## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
The secure-terminal widget.

Design (see https://secure-terminal.github.io):

- DISPLAY is printable-ASCII by default. Program output is passed through
  render_output(): ANSI/OSC escape sequences are removed and, in the default
  'box' mode, every character that is not printable ASCII (plus tab and
  newline) becomes '_', the way sanitize-string/stcat neutralize a log. There is
  no escape parser, so a hostile filename, a forged status line or a Trojan-
  Source comment cannot redraw or reorder what you read. Two optional display
  modes trade some of that for readability, per tab: 'show' renders a non-ASCII
  character as its glyph when it is printable (str.isprintable() excludes the
  invisible, bidi and format characters that make unicode deceptive), so a log
  with legitimate unicode is readable while the dangerous classes still collapse
  to '_'; 'reveal' shows every non-ASCII character as a <U+XXXX> badge so you can
  inspect exactly what is there. Two cursor controls are honored, and both are
  necessary: the interactive shell echoes its line editing with backspace and
  carriage return (readline sends "\b \b" to rub out a character and redraw after
  tab-completion/history; zsh returns to column 0 with a carriage return to draw
  its prompt) regardless of the pty's echo flag, so a terminal that dropped them
  could not display line editing at all. Terminal overwrite semantics apply on
  the current line: backspace moves the cursor one cell left, a bare carriage
  return moves it to column 0, and a printable character overwrites the cell
  under the cursor (never inserting-and-shifting). "\r\n" is collapsed to "\n"
  first, since the pty maps every newline to CRLF and that carriage return is
  only a line ending. BOTH controls are bounded to the current line and can
  never reach an earlier line or the scrollback. The residual is that a program
  which prints its own backspaces or carriage returns can rewrite text WITHIN
  the line it is on (e.g. "bad\b\b\bok" shows "ok"); this is far narrower than
  cursor addressing and cannot touch already-committed lines, but it is the one
  lie this terminal cannot fully refuse without breaking interactive editing.

- PASTE is sanitized the same way before it reaches the shell, so invisible or
  bidi characters copied from a web page never enter your command line.

- INPUT forwards printable characters and the control keys, each sent as its
  control byte exactly as a real terminal does (Ctrl+C -> 0x03, Ctrl+\\ -> 0x1c,
  readline's Ctrl+A/R/U ...): a cooked shell's line discipline turns 0x03 into
  SIGINT, while a raw-mode program reads the byte itself (so an app's own "press
  Ctrl+C again to exit" works). Still one-directional. terminate_foreground() is
  the guaranteed panic button (SIGTERM then SIGKILL) for a program that ignores
  all of the above. An opt-in command hook (apply_hook) can additionally judge a
  typed line before Enter submits it.

This is a deliberately minimal, line-oriented terminal by default: no escape
parser at all -- every escape sequence in the output is stripped in the renderer
(safety does not rest on TERM -- CLI mode advertises the restricted
`secure-terminal` entry, TUI mode xterm-256color -- but on that unconditional
stripping). An opt-in TUI mode (apply_tui) instead interprets
escapes through a pyte screen model so full-screen programs (ssh, vim, htop,
tmux) work; mode is only a rendering choice over the same byte stream, so it
switches without restarting the shell and a running program survives the switch.
Even in TUI mode every cell is still character-filtered and pyte only builds a
screen model, so program output cannot drive it to set the title or touch the
clipboard the way a real terminal's escape handling can (the programs you run
still have your normal user access). The window flags TUI mode with a visible
risk indicator; the strict line mode remains the safe-by-design default.
"""

import os
import pty
import re
import copy
import select
import subprocess
import time
import base64
import urllib.parse
import fcntl
import signal
import codecs
import struct
import termios
import shlex
import unicodedata

try:
    import pyte
except ImportError:  # pragma: no cover - pyte is a hard runtime dependency
    pyte = None                          # (TUI mode is unavailable without it)

if pyte is not None:
    # Per base cell; Unicode UAX #15 stream-safe format allows at most 30
    # combining marks, so any conformant text stays untouched.
    _TUI_COMBINE_CAP = 32

    class _SafeHistoryScreen(pyte.HistoryScreen):
        """pyte 0.8.0's HistoryScreen.select_graphic_rendition() takes only
        *attrs, but pyte's stream dispatches a private ("?"-prefixed) CSI with
        private=True, so a private-marked SGR raises TypeError and _feed_bytes
        drops the whole frame. Programs like vim, htop and tmux emit such
        sequences, which showed up as dropped frames in that render. A private
        SGR is not a standard colour operation, so ignore it (as upstream pyte
        later did) instead of crashing; every other private CSI (set/reset mode)
        already accepts private=. Nothing here weakens the cell filter: this only
        governs how pyte parses, never what is allowed onto the screen."""

        def select_graphic_rendition(self, *attrs, private=False, **kwargs):
            if private:
                return
            super().select_graphic_rendition(*attrs)

        def draw(self, data):
            # Bound a Zalgo flood. pyte merges each zero-width combining mark into
            # the cell before the cursor via unicodedata.normalize("NFC",
            # cell.data + mark) -- O(len) per mark -- so a base plus thousands of
            # marks, OR a cursor that steers many chunks back onto ONE cell, reshapes
            # in O(n^2) and freezes the render for seconds. Drop a mark once its
            # TARGET cell already holds the Unicode stream-safe maximum: cell-accurate,
            # so neither read boundaries nor cursor moves can bypass it. Lossless for
            # real decomposed text (never nears the cap). Fast path: an all-ASCII
            # chunk (the common case) batches through at C speed, since ASCII can
            # never be a combining mark.
            if data.isascii():
                super().draw(data)
                return
            for ch in data:
                if ord(ch) >= 0x0300 and unicodedata.combining(ch):
                    x = self.cursor.x
                    if x:
                        target = self.buffer[self.cursor.y].get(x - 1)
                    elif self.cursor.y:
                        target = self.buffer[self.cursor.y - 1].get(self.columns - 1)
                    else:
                        target = None
                    if target is not None and len(target.data) > _TUI_COMBINE_CAP:
                        continue                  # target cell already at the cap
                super().draw(ch)
else:  # pragma: no cover - pyte is a hard runtime dependency (always present)
    _SafeHistoryScreen = None

from PyQt6.QtCore import (QSocketNotifier, Qt, QTimer, pyqtSignal, QEvent,
                          QMimeData)
from PyQt6.QtGui import (QFont, QTextCursor, QColor, QPalette, QTextCharFormat,
                         QTextFormat, QGuiApplication)
from PyQt6.QtWidgets import (QPlainTextEdit, QToolTip, QDialog, QVBoxLayout,
                             QHBoxLayout, QLabel, QPushButton, QApplication)

# The pure, Qt-free sanitization core (also tested directly by dist-ai). Names
# are re-exported here so terminal.py stays the single import point for the rest
# of the package (main.py, review.py).
from secure_terminal.sanitize import (
    THEMES, BASE_POINT_SIZE, ANSI_PALETTE, DISPLAY_MODES,
    colors_allowed, too_close, luminance, sanitize_paste,
    sanitize_paste_unicode, sanitize_clipboard, sanitize_clipboard_unicode,
    paste_findings, paste_is_multiline, tui_cell, sanitize_title,
    feed_line_edits, cells_to_runs, cells_display_col, MARK_KEY, WRAP_NL, BOX,
    render_output,
    wants_full_screen, leaves_full_screen, wants_screen_repaint, wants_clear,
    wants_line_clears,
    describe_codepoint, marking_class, PROMPT_START,
    split_trailing_escape, feed_chunk_carry, has_bell, OSC_FEATURES,
    _ALT_SCREEN as _ALT_ENTER, _ALT_SCREEN_OFF as _ALT_LEAVE,
)

# Custom char-format property carrying a marked cell's SOURCE code point, so the
# widget can describe the real character on hover/click regardless of how it is
# displayed (the box placeholder, a reveal/detail badge, a control as a box).
# The default terminal font. Hack is a monospace face DESIGNED to disambiguate
# confusable glyphs (dotted zero distinct from O, tailed l, serifed 1 and I,
# rn kept apart from m) and -- crucially for a terminal that promises "what you
# see is the exact bytes" -- it ships NO ligature tables, so it can never merge
# characters (e.g. != into one glyph). Packaged in Debian as fonts-hack; an
# uninstalled family falls back to DejaVu Sans Mono, then the generic monospace.
DEFAULT_FONT_FAMILY = 'Hack'

# Base font point-size bounds (the zoom scales this); a stored or typed value is
# clamped so the glyph can never be made unreadably tiny or huge.
FONT_SIZE_MIN = 6
FONT_SIZE_MAX = 72

_CP_PROP = QTextFormat.Property.UserProperty + 1

# Human-readable gloss for each risk class (marking_class), for the click popup.
_RISK_LABELS = {
    'bidi':       'bidirectional control -- can reorder text (the worst deception)',
    'confusable': 'a look-alike of an ASCII character (homoglyph), e.g. Cyrillic a for Latin a',
    'invisible':  'invisible -- zero-width, BOM or line/paragraph separator',
    'control':    'control character -- C0, DEL or C1',
    'nonascii':   'other non-ASCII -- foreign text, not an ASCII look-alike',
}

# Any numeric-code OSC: ESC ] <code> ; <params> (BEL | ST). The dispatcher acts on
# the codes for enabled OSC features and ignores the rest (still stripped).
_OSC_ANY = re.compile(rb'\x1b\](\d{1,8});([^\x07\x1b]*)(?:\x07|\x1b\\)')
_OSC_CLIP_MAX = 64 * 1024        # cap a clipboard payload; no unbounded writes
# Whether an OSC body (the bytes after its "\x1b]") contains a terminator (BEL or
# ST). Used to decide if a trailing OSC introducer is incomplete and must be held
# back and prepended to the next read, so a sequence split across PTY reads (a
# full-size OSC 52 clipboard payload always spans the 64 KiB read) is not missed.
_OSC_TERMINATED = re.compile(rb'\x07|\x1b\\')
# OSC 8 hyperlink: ESC ] 8 ; <params> ; <URI> BEL <text> ESC ] 8 ; ; BEL. Captures
# the real target URI and the visible text, so the true destination can be shown
# (the display text can differ from the target -- the phishing risk).
_OSC8 = re.compile(rb'\x1b\]8;[^;\x07\x1b]*;([^\x07\x1b]*)(?:\x07|\x1b\\)'
                   rb'(.*?)\x1b\]8;;(?:\x07|\x1b\\)', re.DOTALL)
# OSC numeric code -> feature key, so a CLI-mode notice can name the exact type.
_OSC_CODE_KEY = {}
for _k, _lbl, _codes, *_rest in OSC_FEATURES:
    for _c in _codes.replace(' ', '').split(','):
        _OSC_CODE_KEY.setdefault(int(_c), _k)
# OSC code embedded in text (str, in the CLI display path).
_OSC_CODE_RE = re.compile(r'\x1b\](\d{1,8})')

# Alternate-screen enter/leave, as BYTES: pyte has no alt buffer, so the feed path
# acts on these to snapshot/restore the primary screen at the exact boundary.
_ALT_ENTER_BYTES = (b'\x1b[?1049h', b'\x1b[?1047h', b'\x1b[?47h')
_ALT_LEAVE_BYTES = (b'\x1b[?1049l', b'\x1b[?1047l', b'\x1b[?47l')
# longest alt-screen marker, so a tail of (len-1) carried between reads reunites a
# marker split across an os.read() boundary (F6).
_ALT_MARKER_MAX = max(len(m) for m in _ALT_ENTER + _ALT_LEAVE)
_ALT_MARKER_MAX_BYTES = max(len(m) for m in _ALT_ENTER_BYTES + _ALT_LEAVE_BYTES)


def _alt_partial_tail(data):
    """Length of the tail of `data` that is a PROPER prefix of an alt-screen marker,
    i.e. it may be the START of a marker split across an os.read() boundary. 0 when
    the tail is not a partial marker (so a COMPLETE marker at the end is not held back
    -- that would delay its snapshot/restore, which is the whole point of feeding)."""
    markers = _ALT_ENTER_BYTES + _ALT_LEAVE_BYTES
    for k in range(min(_ALT_MARKER_MAX_BYTES - 1, len(data)), 0, -1):
        tail = data[-k:]
        if any(len(tail) < len(m) and m.startswith(tail) for m in markers):
            return k
    return 0
# Synchronized output (DECSET private mode 2026): a program brackets a screen
# update so the terminal shows the completed frame, never a half-drawn one. It is
# a SET-mode with no reply -- purely a rendering hint -- so it is safe to honour
# unconditionally; a watchdog bounds an update that is never closed.
_SYNC_BEGIN = '\x1b[?2026h'
_SYNC_END = '\x1b[?2026l'
# Bracketed paste is DECSET *private* mode 2004. pyte stores private modes in
# screen.mode shifted left by 5 (so they cannot collide with ANSI modes), so the
# program's `\x1b[?2004h` lands as 2004 << 5 -- test for that, not the bare 2004.
_BRACKETED_PASTE_MODE = 2004 << 5


def tui_available():
    return pyte is not None


# Directories a bell sound file may live in. Restricting to these keeps the
# AppArmor profile enforceable (it grants read only here), so a user cannot point
# the bell at an arbitrary path the sandbox would then have to be widened for.
BELL_SOUND_DIRS = (
    '/usr/share/sounds',
    '/usr/share/secure-terminal/sounds',
    os.path.join(os.path.expanduser('~'), '.local/share/sounds'),
)


_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))


def _terminfo_source():
    """Locate the shipped `secure-terminal.ti` terminfo source (installed tree or
    a source checkout), or None."""
    candidates = (
        os.path.join(_MODULE_DIR, *(['..'] * 4),
                     'share', 'secure-terminal', 'terminfo', 'secure-terminal.ti'),
        '/usr/share/secure-terminal/terminfo/secure-terminal.ti',
    )
    for path in candidates:
        if os.path.isfile(path):
            return os.path.abspath(path)
    return None


def cli_terminfo_dir():
    """Return a terminfo directory containing the compiled `secure-terminal` entry
    (CLI mode's restricted TERM), compiling the shipped source into the user cache
    on demand when it is not already compiled, or None if it cannot be produced
    (caller then falls back to xterm-256color). Pure lookup + at most one `tic`."""
    src = _terminfo_source()
    if src:
        pkg_dir = os.path.dirname(src)
        if os.path.isfile(os.path.join(pkg_dir, 's', 'secure-terminal')):
            return pkg_dir                # compiled at build time next to the source
    cache = os.path.join(
        os.environ.get('XDG_CACHE_HOME') or os.path.join(
            os.path.expanduser('~'), '.cache'),
        'secure-terminal', 'terminfo')
    if os.path.isfile(os.path.join(cache, 's', 'secure-terminal')):
        return cache
    if src:
        try:
            os.makedirs(cache, exist_ok=True)
            subprocess.run(['tic', '-x', '-o', cache, src],
                           check=True, capture_output=True, timeout=15)
            if os.path.isfile(os.path.join(cache, 's', 'secure-terminal')):
                return cache
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def sound_file_allowed(path):
    """True if `path` is a real file inside one of BELL_SOUND_DIRS (symlinks
    resolved), so a bell sound cannot escape the AppArmor-granted directories."""
    if not path:
        return False
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    if not os.path.isfile(real):
        return False
    return any(real == base or real.startswith(base + os.sep)
               for base in (os.path.realpath(p) for p in BELL_SOUND_DIRS))


def _rgb(color):
    return (color.red(), color.green(), color.blue())


# pyte colour name -> ANSI_PALETTE index (bold promotes to the bright variant).
_PYTE_COLOR = {
    'black': 0, 'red': 1, 'green': 2, 'brown': 3,
    'blue': 4, 'magenta': 5, 'cyan': 6, 'white': 7,
}


def _build_tui_keys():
    """Qt.Key -> the VT byte sequence a TUI program expects. Built lazily since
    it references Qt.Key values."""
    k = Qt.Key
    return {
        k.Key_Return: b'\r', k.Key_Enter: b'\r',
        k.Key_Backspace: b'\x7f', k.Key_Tab: b'\t', k.Key_Escape: b'\x1b',
        k.Key_Up: b'\x1b[A', k.Key_Down: b'\x1b[B',
        k.Key_Right: b'\x1b[C', k.Key_Left: b'\x1b[D',
        k.Key_Home: b'\x1b[H', k.Key_End: b'\x1b[F',
        k.Key_PageUp: b'\x1b[5~', k.Key_PageDown: b'\x1b[6~',
        k.Key_Insert: b'\x1b[2~', k.Key_Delete: b'\x1b[3~',
        k.Key_F1: b'\x1bOP', k.Key_F2: b'\x1bOQ', k.Key_F3: b'\x1bOR',
        k.Key_F4: b'\x1bOS', k.Key_F5: b'\x1b[15~', k.Key_F6: b'\x1b[17~',
        k.Key_F7: b'\x1b[18~', k.Key_F8: b'\x1b[19~', k.Key_F9: b'\x1b[20~',
        k.Key_F10: b'\x1b[21~', k.Key_F11: b'\x1b[23~', k.Key_F12: b'\x1b[24~',
    }


def _build_line_edit_keys():
    """Qt.Key -> VT byte sequence for the keys line mode forwards to the shell's
    own line editor: history recall (Up/Down), intra-line movement (Left/Right/
    Home/End) and forward delete. Built lazily (references Qt.Key)."""
    k = Qt.Key
    return {
        k.Key_Up: b'\x1b[A', k.Key_Down: b'\x1b[B',
        k.Key_Right: b'\x1b[C', k.Key_Left: b'\x1b[D',
        k.Key_Home: b'\x1b[H', k.Key_End: b'\x1b[F',
        k.Key_Delete: b'\x1b[3~',
    }


class SecureTerminal(QPlainTextEdit):
    # emitted when the child shell exits, so the window can close its tab
    shell_exited = pyqtSignal()
    # Ctrl+wheel over the widget asks the window to zoom by +1/-1 step
    zoom_step = pyqtSignal(int)
    # Ctrl+PageUp/Down asks the window to switch tabs; Ctrl+Shift+PageUp/Down to
    # move the current tab. Handled at the widget because it owns the keyboard.
    tab_step = pyqtSignal(int)
    tab_move = pyqtSignal(int)
    # the command hook produced an advisory message to surface (status bar)
    hook_notice = pyqtSignal(str)
    # An advisory from the terminal itself (e.g. "turn on TUI mode"). Emitted, NOT
    # injected into the document: injected text is unfaithful -- it could be
    # selected and copied into a transcript as if a program printed it.
    advise_signal = pyqtSignal(str)
    # A pasted text needs review before it may reach the shell: (raw, countdown
    # seconds). The window shows the in-window review bar; the paste is held and
    # input suspended until dispatch_pending_paste resolves it. resolved fires when
    # the choice is made (send or reject), so the window can hide the bar.
    paste_review_requested = pyqtSignal(str, int)
    paste_review_resolved = pyqtSignal()
    # As paste_review_requested, but for text leaving via COPY (the same review bar
    # and preview, configured separately). (raw text, countdown seconds).
    copy_review_requested = pyqtSignal(str, int)
    # Risky text (unicode / control / multi-line) crossed the boundary UNREVIEWED
    # because the user set review to 'never': the content is NOT stripped (that would
    # break deliberately pasting/copying real unicode), but the window lights a red
    # risk lamp so the unreviewed crossing is visible rather than silent.
    unreviewed_risk = pyqtSignal()
    # a program emitted an OSC escape (window title, clipboard, hyperlink, ...)
    # while in line mode, where it is stripped for safety. Carries the FEATURE KEY
    # (see OSC_FEATURES; 'osc_other' for an unrecognized code) so the window can
    # notice each TYPE at most once per tab.
    osc_used = pyqtSignal(str)
    # a program set the title / sent a notification (only when allowed)
    title_changed = pyqtSignal(str)
    notified = pyqtSignal(str)
    # a program reported its working directory via OSC 7 (only when osc_cwd is on)
    cwd_changed = pyqtSignal(str)
    # a bell fired with the 'tray' channel enabled; the window shows a passive
    # system-tray popup (the terminal has no tray icon of its own). Carries a label.
    bell_tray = pyqtSignal(str)
    # a program in this tab asked to READ the clipboard (OSC 52 query) and the tab
    # has not yet decided; the window asks the user ONCE PER TAB (see osc_clipboard_read).
    clipboard_read_requested = pyqtSignal()

    def __init__(self, parent=None, command=None, tui=False, history='',
                 preview=False, cwd=None, mode='detail', colors=False,
                 markings=True):
        super().__init__(parent)
        # working directory to start the shell in (restored session tab); None ->
        # inherit the app's cwd.
        self._cwd = cwd if isinstance(cwd, str) and cwd else None
        # A preview instance renders text through the SAME pipeline (risk-class
        # colouring, the inspect popup, the contrast guard, theme and font) but runs
        # NO child: it spawns no pty and accepts no keyboard input, so the paste
        # review can show the terminal's real rendering without a shell behind it.
        self._preview = bool(preview)
        # A pasted text, or a selection being copied out, held awaiting the user's
        # review choice (see insertFromMimeData / copy). Only one review is active
        # at a time; while active, terminal input is suspended.
        self._pending_paste = None
        self._pending_copy = None
        self._review_active = False
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        # A terminal never scrolls sideways: line mode wraps at the widget width and
        # the TUI grid is sized to fit, so a horizontal scrollbar is always wrong
        # (it only appeared from a rounding overflow and clipped the right edge).
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFrameStyle(0)

        self._base_point_size = BASE_POINT_SIZE
        self._zoom = 100
        self._font_family = DEFAULT_FONT_FAMILY
        self._apply_font(sync=False)

        self._theme = 'dark'
        self.apply_theme(self._theme)

        # display mode for non-ASCII output, and an incremental UTF-8 decoder so
        # a multi-byte character split across two os.read() chunks still decodes.
        # Set from the ctor (a restored tab passes its saved mode) BEFORE any
        # history is rendered below, so restored scrollback is drawn ONCE in its
        # final mode -- never first in the default then re-rendered (the flicker +
        # scrollbar jumps of restoring into the wrong mode).
        self._mode = mode if mode in DISPLAY_MODES else 'detail'
        self._decoder = codecs.getincrementaldecoder('utf-8')('replace')
        # Retain the raw decoded output (line mode) so a display-mode change can
        # re-render the WHOLE buffer, not just new output. Bounded so a flood
        # cannot grow it without limit; the oldest output is dropped first.
        self._raw = ''
        self._RAW_MAX = 1_000_000
        # cap alternate-screen enter/leave snapshots per read (anti-DoS: a flood of
        # alternating ?1049h/?1049l would otherwise deepcopy the screen thousands of
        # times); a real full-screen program toggles it at most a handful of times.
        self._ALT_TRANSITIONS_MAX = 200
        # A mode toggle only re-renders this much of the most-recent raw output,
        # not the whole buffer: rendering the full scrollback (and reveal expands
        # each byte to an 8-char <U+XXXX>) froze the UI on a flood. This tail is
        # far more than a screenful, so what you can see is always re-rendered.
        self._RERENDER_TAIL = 131072

        # optional ANSI colours (off by default); SGR parser state. Also set from
        # the ctor before the history render, for the same render-once reason.
        self._colors = bool(colors)
        self._markings = bool(markings)   # colour the '_' / badge by risk class
        self._sgr_reset()

        # Scrollback limit in lines. Default to a bounded window (like every
        # mainstream terminal) so an endless flood cannot grow the document
        # without bound; a config/apply_scrollback of 0 restores unlimited.
        self._scrollback = 10000
        self.setMaximumBlockCount(self._scrollback)
        # A single logical line is hard-wrapped past this many characters, so a
        # newline-free flood cannot build one pathologically long block (the
        # QPlainTextEdit layout of which is quadratic).
        self._MAX_LINE = 8192
        # Autowrap width: the number of columns we report to the child via the
        # winsize, so output hard-wraps at exactly the width the shell/program
        # formats to. Without this, a shell that pads to the width and relies on
        # the terminal wrapping (zsh's PROMPT_SP / PROMPT_EOL_MARK end-of-line
        # marker) collapses its marker and the next prompt onto one logical line,
        # showing spurious trailing lines after a file with no final newline.
        # Updated by _set_winsize; falls back to _MAX_LINE until first sized.
        self._cols = 0

        # seconds the paste-warning "Allow" button stays disabled.
        self._paste_delay = 3
        self._paste_warn = 'unicode'   # always | unicode (default) | never
        self._copy_warn = 'unicode'    # always | unicode (default) | never

        # TUI mode: interpret escapes through a pyte screen so full-screen
        # programs (ssh, vim, htop, tmux) work. Off by default; the strict, no-parser
        # line mode above is the safe default.
        self._tui = bool(tui) and tui_available()
        if self._tui:
            # a TUI screen is fixed; no scrollback scrollbar (see apply_tui)
            self.setVerticalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._command = command
        self._screen = None
        self._stream = None
        self._fmt_cache = {}
        # TUI grid view state: which pyte history rows are already rendered as
        # permanent scrollback (by id), and how many blocks the live grid occupies
        # at the bottom of the document. Lets each frame re-render only the grid.
        self._top_ids = set()
        self._grid_rows = 0
        self._grid_seeded = False     # has this TUI screen been seeded from _raw
        # snapshot of the primary pyte screen (buffer, history, cursor) saved as a
        # full-screen program takes the alternate screen, and restored on exit --
        # pyte has no separate alt buffer, so without this the program's clear/draw
        # would destroy the primary screen and pollute the scrollback.
        self._alt_saved = None

        # OSC features a program may reach OUT of the grid with (title, notify,
        # clipboard, hyperlink, palette, cwd, iTerm2). Each is honored ONLY when
        # the user enabled it AND only in TUI mode (line mode strips all escapes).
        # Off by default -- every one is a spoofing/exfiltration surface.
        self._osc = {key: False for key, *_rest in OSC_FEATURES}
        # Bell (BEL, 0x07): a set of independent notification channels (audible /
        # visual / tray). Empty = silent, the safe default -- BEL from untrusted
        # output is a nuisance/attention-grab surface. Rate-limited so a program
        # spamming BEL cannot machine-gun it. An optional sound file replaces the
        # system beep for the audible channel (restricted to allowed folders).
        self._bell_channels = set()
        self._bell_sound = ''
        self._sound_effect = None
        self._last_bell = 0.0
        # OSC 52 clipboard-READ decision for THIS tab (ask once per tab): None =
        # not yet asked, 'pending' = the dialog is open, True/False = the user's
        # answer. Rate-limited so a granted tab cannot be flood-exfiltrated.
        self._clipboard_read = None
        # global "always allow clipboard read" default (from settings): auto-answers
        # a tab that has made no explicit decision. An explicit per-tab decision
        # (True/False) always wins over this global default.
        self._clipboard_read_always = False
        self._last_clip_read = 0.0
        self._seeding = False         # True while replaying _raw into pyte (no bell)
        self._last_title = ''
        self._reported_cwd = ''       # OSC 7 working directory, when osc_cwd is on
        # OSC 4/10/11/12 palette overrides (when osc_colors is on): 'fg'/'bg'/
        # 'cursor' -> hex, and int index -> hex for the 16-colour set.
        self._osc_palette = {}
        # persistent output cursor for line mode (see _paint_line)
        self._out_cursor = None
        # the current (editable) line held as LOGICAL cells (source_char, sgr_key)
        # plus a logical cursor column, so the shell's cursor/erase ops act on
        # characters, not on a reveal badge's multi-column rendering.
        self._line_cells = []
        self._line_col = 0
        self._line_fmt_cache = {}     # sgr_key -> QTextCharFormat (line mode)
        # show the "this program wants TUI mode" advisory at most once per
        # full-screen program, so one that redraws every second does not spam it.
        self._tui_hint_shown = False
        # note a whole-screen clear / reset that line mode drops, at most once per
        # tab, so a `clear` / Ctrl+L / `reset` that did nothing is explained.
        self._clear_notice_shown = False
        # True while a full-screen program holds the alternate screen buffer. The
        # pyte screen is then kept fed in the background even in line mode, so
        # flipping to TUI mode shows the program's current frame instantly (no
        # restart). Maintained from the output stream (alt-screen enter/leave).
        self._alt_screen = False
        # True while the grid view is rendering the alternate screen ALONE (grid
        # only, no scrollback above it). Lets _render_tui clear the carried-in
        # scrollback exactly once when a full-screen program takes the alt screen,
        # so its bottom row (e.g. tmux's status bar) is not pushed below the
        # viewport and no spurious scrollbar appears.
        self._alt_view = False
        self._grid_shown = False      # is the fixed pyte grid currently on screen
        # Local caret echoes (^C, ^\) awaiting possible de-duplication against the
        # shell's own echo: [(text, deadline_monotonic), ...]. See _echo_caret.
        self._pending_caret = []
        # An escape sequence split across two os.read() chunks: its incomplete tail
        # is held here and prepended to the next chunk, so a split OSC/CSI never
        # leaks its remainder as literal text (see feed_chunk_carry).
        self._esc_carry = ''
        # When an over-long string sequence (OSC/DCS/Sixel/APC) outgrows the carry
        # cap, this holds its introducer byte and the feed discards bytes until the
        # terminator, so a huge chunk-split escape is stripped in O(1) memory.
        self._esc_drop = ''
        # TUI OSC action path: bytes of an incomplete trailing OSC held from the
        # previous read, so an enabled OSC (clipboard/notify/...) split across PTY
        # reads is still acted on. Bounded a little above the clipboard cap.
        self._osc_carry = b''
        self._OSC_CARRY_MAX = _OSC_CLIP_MAX + 4096
        # emitted whenever a program uses an OSC escape while in pure CLI mode,
        # where it is stripped; the window de-duplicates to a once-per-tab notice
        # (it knows the setting, so the terminal must not consume the state itself).
        # optional command hook (opt-in): config dict or None, plus the current
        # typed input line so it can be judged before Enter submits it.
        self._hook = None
        self._line_buffer = ''
        # set when history recall / cursor editing desyncs _line_buffer from the
        # real shell line, so the hook fails safe (asks) rather than judge a stale
        # line. See keyPressEvent (line-edit keys) and _hook_intercept.
        self._line_dirty = False
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.timeout.connect(self._render_tui)
        # synchronized output (DECSET 2026): while True, hold the paint (pyte is
        # still fed) so a frame is shown whole. Watchdog bounds an unclosed update.
        self._sync_update = False
        self._sync_scan_carry = ''    # tail kept so a split ?2026 marker is seen
        self._alt_scan_carry = ''     # tail kept so a split alt-screen marker is seen (CLI state)
        self._alt_feed_carry = b''    # tail held so a split alt-screen marker is not fed mid-split (TUI)
        self._sync_timer = QTimer(self)
        self._sync_timer.setSingleShot(True)
        self._sync_timer.timeout.connect(self._end_sync_update)

        # restored scrollback from a previous session, shown as history above
        # the fresh shell (line mode; a TUI tab repaints over it on first draw).
        if history:
            restored = history if history.endswith('\n') else history + '\n'
            # bound the retained raw as for live output, so entering TUI does not
            # replay a huge restored scrollback (up to the 100k-line setting)
            # synchronously through pyte on the first switch.
            self._raw = restored[-self._RAW_MAX:]   # so a mode toggle re-renders it too
            self._append(restored)

        self._notifier = None
        self._fd = None
        self._pid = None
        if self._preview:
            # No child, no keyboard: a read-only rendering surface only.
            self.setReadOnly(True)
            return
        self._start(command)
        if self._tui:
            # A tab that STARTS in TUI must enter the grid view properly (seed the
            # pyte screen from any restored scrollback, set _grid_shown and the
            # scrollbar), or the first output would clear the history unseeded and a
            # later switch to CLI would not rebuild the line document.
            self._sync_display()

    def render_preview(self, text, mode='detail', markings=True):
        """Render `text` as a static, read-only preview in the chosen display mode,
        replacing any previous content. Reuses the live rendering pipeline, so the
        preview carries the same risk-class colouring and the same click-to-inspect
        popup as the terminal itself. Preview instances only."""
        self.clear()
        # Retain `text` as the raw source (not ''), so a later apply_mode /
        # apply_markings / apply_colors re-renders the preview instead of blanking
        # it, and reset the per-line state (cursor + SGR) so a previous preview's
        # unfinished formatting cannot bleed into this one.
        self._raw = text
        self._out_cursor = None
        self._line_cells = []
        self._line_col = 0
        self._line_fmt_cache = {}
        self._sgr_reset()
        self._mode = mode if mode in DISPLAY_MODES else 'detail'
        self._markings = bool(markings)
        self._feed_line(text)

    # -- appearance: theme + zoom ---------------------------------------------
    def apply_theme(self, theme):
        base, text = THEMES.get(theme, THEMES['dark'])
        self._theme = theme if theme in THEMES else 'dark'
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Base, QColor(base))
        pal.setColor(QPalette.ColorRole.Text, QColor(text))
        self.setPalette(pal)
        self._fmt_cache = {}          # theme changes the resolved cell colours
        self._line_fmt_cache = {}     # and the line-mode SGR format cache
        if self._grid_mode():         # repaint the grid ONLY while it owns the
            self._render_timer.start(16)   # screen; line-TUI keeps its scrollback

    def _apply_font(self, sync=True):
        """Build the terminal font from the chosen family and current zoom. The
        default family (Hack) is a hard package dependency, so no fallback chain is
        needed; the Monospace style hint still steers Qt's own substitution toward
        a fixed-pitch face if a user picks a family that is not installed. OpenType
        ligature and contextual-alternate features are turned off where the Qt build
        allows it -- ligatures HIDE characters, a deception vector for a WYSIWYG
        terminal; the default family (Hack) ships no ligature tables anyway."""
        size = max(1, round(self._base_point_size * self._zoom / 100.0))
        font = QFont()
        font.setFamily(self._font_family or DEFAULT_FONT_FAMILY)
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setFixedPitch(True)
        for _tag in ('liga', 'clig', 'calt', 'dlig'):
            try:
                font.setFeature(_tag, 0)
            except (AttributeError, TypeError, ValueError):
                pass                 # per-feature control needs Qt >= 6.7; skip
        font.setPointSize(size)
        self.setFont(font)
        if sync:
            self._sync_tui_size()          # a font change resizes the grid
            if self._grid_mode():
                self._render_timer.start(16)   # repaint at the new glyph size

    def apply_zoom(self, percent):
        self._zoom = max(10, min(1000, int(percent)))
        self._apply_font()

    def set_font_family(self, family):
        self._font_family = (family or '').strip() or DEFAULT_FONT_FAMILY
        self._apply_font()

    def current_font_family(self):
        return self._font_family

    def set_font_size(self, points):
        """Set the BASE font point size (the zoom then scales it). Clamped to a
        sane range so a stored/typed value cannot make the glyph unreadable."""
        self._base_point_size = max(FONT_SIZE_MIN, min(FONT_SIZE_MAX, int(points)))
        self._apply_font()

    def current_font_size(self):
        return self._base_point_size

    def current_zoom(self):
        return self._zoom

    def current_theme(self):
        return self._theme

    def apply_mode(self, mode):
        """Set the display mode for non-ASCII output and re-render the existing
        buffer under it -- a mode change affects the whole scrollback, not only
        new output, so toggling box/show/reveal re-reads what is already there."""
        if mode not in DISPLAY_MODES or mode == self._mode:
            return
        self._mode = mode
        self._rerender()

    def _rerender(self):
        """Re-display existing output under the current display mode. While a
        full-screen program owns the grid the pyte screen is simply repainted;
        otherwise (CLI, or TUI at a shell prompt) the retained raw output is
        replayed through the render pipeline from a clean document."""
        if self._grid_mode():
            self._render_tui()
            return
        self.clear()
        self._out_cursor = None
        self._line_cells = []
        self._line_col = 0
        self._sgr_reset()                 # replay SGR colours from a clean slate
        if self._raw:
            # Only the recent tail, so a mode toggle after a flood cannot freeze
            # the UI re-rendering (and reveal-expanding) megabytes of scrollback.
            self._feed_line(self._raw[-self._RERENDER_TAIL:])

    def current_mode(self):
        return self._mode

    def apply_scrollback(self, lines):
        """Limit retained scrollback to `lines` blocks (0 = unlimited)."""
        lines = max(0, int(lines))
        self._scrollback = lines
        self.setMaximumBlockCount(lines)

    def current_scrollback(self):
        return self._scrollback

    def apply_paste_delay(self, seconds):
        self._paste_delay = max(0, int(seconds))

    def current_paste_delay(self):
        return self._paste_delay

    def apply_paste_warn(self, mode):
        self._paste_warn = mode if mode in ('always', 'unicode', 'never') else 'unicode'

    def current_paste_warn(self):
        return self._paste_warn

    def apply_copy_warn(self, mode):
        self._copy_warn = mode if mode in ('always', 'unicode', 'never') else 'unicode'

    def current_copy_warn(self):
        return self._copy_warn

    # -- TUI mode -------------------------------------------------------------
    def apply_tui(self, enabled):
        """Switch between CLI (line) and TUI (grid) mode. The rendering changes over
        the SAME running shell -- history is kept, nothing restarts. In addition,
        when the shell is at a prompt its TERM is re-exported to match the new mode
        (CLI -> restricted `secure-terminal`, so a program lists completions instead
        of drawing an in-place menu line mode cannot show; TUI -> xterm-256color, so
        full-screen programs work). The shell re-reads terminfo live, so no restart
        and no lost shell state.

        If a program (or a nested shell) is running it OWNS the terminal, so the
        re-export cannot reach the shell -- sending it would type `export TERM=...`
        into that program. So the switch is REFUSED with a clear message. Returns
        True if the mode changed (or was already set), False if it was refused."""
        if bool(enabled) and not tui_available():
            return False              # TUI requested but pyte missing: not applied
        enabled = bool(enabled)
        if enabled == self._tui:
            return True
        # Refuse only for the default login shell running a foreground child: the
        # re-export below would type `export TERM=...` into that child. A `-- PROGRAM`
        # tab (self._command set) skips the re-export entirely, so its switch is a
        # safe rendering-only change even though has_foreground_program() is True.
        if (not self._preview and self._pid is not None
                and self._command is None and self.has_foreground_program()):
            self._advise('Switch between CLI and TUI mode at a shell prompt: a '
                         'program is running now and owns the terminal, so its '
                         'terminfo cannot be changed under it. Quit the program '
                         'first, or open a new tab in the other mode.')
            return False
        self._tui = enabled
        # switching modes abandons any half-parsed CLI escape state; a stale carry
        # or discard would corrupt the first bytes rendered after switching back.
        self._esc_carry = ''
        self._esc_drop = ''
        self._osc_carry = b''
        # re-advertise the mode's terminfo to the running shell (no restart). ONLY
        # for the default login shell (self._command is None): a tab launched with
        # `-- PROGRAM` runs that program as _pid, which has_foreground_program cannot
        # tell apart from a bare shell, so injecting `export TERM=...` would type it
        # into that program. Skipping keeps the switch a rendering-only change there.
        if not self._preview and self._pid is not None and self._command is None:
            self._reexport_term()
        self._sync_display()
        return True

    def _reexport_term(self):
        """Tell the running shell to re-export TERM for the current mode, so it and
        the programs it launches advertise what the mode can render -- without a
        restart (the shell re-reads terminfo live). Sent as a plain, VISIBLE command
        so the switch is transparent: you see exactly the `export TERM=...` that
        reconfigured the shell, rather than a hidden change. Terminated with CR
        (\\r, the same byte Enter sends), NOT \\n: an interactive shell's line
        editor (zsh's zle) binds accept-line to CR, so a bare \\n leaves the command
        sitting UNSUBMITTED at the prompt."""
        term, _ = self._child_term()
        self._write(('export TERM=%s\r' % term).encode())

    def _grid_mode(self):
        """True whenever TUI mode is on: the pyte grid owns the screen (with its
        scrollback rendered above it), so a program can position the cursor -- a
        completion menu, a progress display, a full-screen app -- and it renders
        faithfully. CLI mode stays the safe one-dimensional line display."""
        return self.tui_active()

    def _sync_display(self):
        """Match the on-screen view to the current mode. TUI mode shows the pyte
        grid with its scrollback; CLI mode shows the scrolling line document. The
        vertical scrollbar stays available in both (TUI now has scrollback too)."""
        grid = self._grid_mode()
        was_grid = self._grid_shown
        self._grid_shown = grid
        if grid:
            self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            if not was_grid:
                # Entering the grid view. pyte is NOT fed in CLI mode (kept out of
                # the safe path), so rebuild it from the retained raw output: this
                # reconstructs the scrollback AND a running program's current frame,
                # so switching CLI->TUI never loses history (and no ~60% frame).
                self._make_screen()      # fresh HistoryScreen + clean view
                self._seed_grid()
            elif self._screen is None:
                self._make_screen()
            else:
                self._sync_tui_size()
            self._render_tui()
            return
        self._render_timer.stop()
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        if was_grid:
            # Leaving TUI for CLI: rebuild the scrolling line document from the
            # retained raw output (the grid view is discarded).
            self._rerender()

    def _seed_grid(self):
        """Replay the retained raw output into the fresh pyte screen, so entering
        TUI shows the existing scrollback and any running program's frame. Bounded
        by _raw's own cap; feeding is contained like the live stream."""
        if self._screen is None or not self._raw:
            return
        self._seeding = True          # replayed bells already happened; do not ring
        try:
            self._feed_stream(self._raw.encode('utf-8', 'replace'))
        finally:
            self._seeding = False

    def current_tui(self):
        return self._tui

    def apply_osc(self, key, enabled):
        """Enable/disable one OSC feature (see OSC_FEATURES) for this tab."""
        if key in self._osc:
            self._osc[key] = bool(enabled)
            if key == 'osc_colors' and not enabled and self._osc_palette:
                self._osc_palette.clear()
                self.apply_theme(self._theme)  # restore the theme palette + repaint

    def osc_enabled(self, key):
        return self._osc.get(key, False)

    def any_osc_enabled(self):
        return any(self._osc.values())

    # -- bell (BEL 0x07) -------------------------------------------------------
    # Notification channels are INDEPENDENT (not mutually exclusive): a bell may
    # ring any combination. Empty set = silent (the safe default).
    #   audible  a system beep, or a chosen sound file (see apply_bell_sound)
    #   visual   a window-manager urgency hint / taskbar flash
    #   tray     a passive system-tray popup (dispatched by the window)
    BELL_CHANNELS = ('audible', 'visual', 'tray')

    @classmethod
    def _parse_bell(cls, spec):
        """Normalise a bell spec (a comma-separated string, an iterable of strings,
        or the legacy 'off'/'audible'/'visual') to a set of valid channels. Any
        malformed value -- e.g. a corrupt session field like 123 or [None] -- is
        treated as no channels, never raises, so a bad session cannot block start."""
        if isinstance(spec, str):
            items = spec.split(',')
        elif isinstance(spec, (list, tuple, set, frozenset)):
            items = spec
        else:
            return set()
        return {c.strip() for c in items
                if isinstance(c, str) and c.strip() in cls.BELL_CHANNELS}

    def apply_bell(self, spec):
        """Set the enabled notification channels for this tab (see BELL_CHANNELS)."""
        self._bell_channels = self._parse_bell(spec)

    def bell_channels(self):
        return set(self._bell_channels)

    def bell_spec(self):
        """The channel set as a stable comma-separated string, for config/session."""
        return ','.join(sorted(self._bell_channels))

    def bell_enabled(self, channel):
        return channel in self._bell_channels

    def apply_bell_sound(self, path):
        """Set the audible-channel sound file. Accepted only if it resolves inside
        an allowed sound directory (so the AppArmor profile stays enforceable); an
        empty or disallowed path falls back to the plain system beep."""
        self._bell_sound = path if sound_file_allowed(path) else ''
        self._sound_effect = None       # rebuilt lazily on next ring

    def _ring(self):
        """Fire every enabled notification channel, rate-limited to at most once per
        ~200ms so a BEL flood cannot machine-gun the beep/flash/popup."""
        if not self._bell_channels:
            return
        now = time.monotonic()
        if now - self._last_bell < 0.2:
            return
        self._last_bell = now
        app = QApplication.instance()
        if app is None:  # pragma: no cover - a running widget always has a QApplication
            return
        if 'audible' in self._bell_channels:
            if not self._play_sound():
                app.beep()              # no/failed sound file -> system beep
        if 'visual' in self._bell_channels:
            win = self.window()
            if win is not None:
                app.alert(win, 0)       # WM urgency hint on our window
        if 'tray' in self._bell_channels:
            self.bell_tray.emit(self._last_title or 'secure-terminal')

    def _play_sound(self):
        """Play the configured sound file via QtMultimedia (a hard dependency).
        Returns True if playback was started, False if there is no sound set or
        playback fails (a bad/unsupported file, no audio device)."""
        if not self._bell_sound:
            return False
        try:
            if self._sound_effect is None:
                from PyQt6.QtMultimedia import QSoundEffect
                from PyQt6.QtCore import QUrl
                eff = QSoundEffect(self)
                eff.setSource(QUrl.fromLocalFile(self._bell_sound))
                self._sound_effect = eff
            self._sound_effect.play()
            return True
        except Exception:               # noqa: BLE001 -- contain any playback error
            return False

    # -- compatibility: "allow title/notifications" == the title + notify OSCs ---
    def apply_allow_title(self, enabled):
        self.apply_osc('osc_title', enabled)
        self.apply_osc('osc_notify', enabled)

    def allow_title_enabled(self):
        return self._osc['osc_title'] or self._osc['osc_notify']

    def tui_active(self):
        return getattr(self, '_tui', False) and tui_available()

    def _text_area(self):
        """The viewport size MINUS the document margins, i.e. the pixels actually
        available for text. Dividing the raw viewport width instead gave the grid
        one column too many -- it overflowed by the margin and showed a useless
        horizontal scrollbar (and nano-style apps drew past the right edge)."""
        margin = int(self.document().documentMargin())
        vp = self.viewport()
        return (max(1, vp.width() - 2 * margin), max(1, vp.height() - 2 * margin))

    def _grid_size(self):
        """Columns and rows that fit the viewport at the current font. Used for
        the LINE-mode winsize, so it tracks the actual text width (scrollbar
        excluded), matching how the shell wraps and fills the prompt."""
        metrics = self.fontMetrics()
        char_w = metrics.horizontalAdvance('M') or 1
        char_h = metrics.height() or 1
        width, height = self._text_area()
        cols = max(2, width // char_w)
        rows = max(2, height // char_h)
        return cols, rows

    def _tui_grid_size(self):
        """Columns and rows for the pyte grid: the text area (viewport minus the
        document margins) at the current font. TUI mode now keeps the vertical
        scrollbar (the grid has scrollback), so its width is part of the viewport
        and is not reclaimed."""
        metrics = self.fontMetrics()
        char_w = metrics.horizontalAdvance('M') or 1
        char_h = metrics.height() or 1
        width, height = self._text_area()
        cols = max(2, width // char_w)
        rows = max(2, height // char_h)
        return cols, rows

    def _set_winsize(self, cols, rows):
        # Remember the width we tell the child, so line-mode output wraps at the
        # same column the shell formats to (see self._cols / _feed_line).
        self._cols = cols
        if self._fd is None:
            return
        try:
            fcntl.ioctl(self._fd, termios.TIOCSWINSZ,
                        struct.pack('HHHH', rows, cols, 0, 0))
        except OSError:
            pass            # a closed/invalid pty just misses this resize

    def _history_size(self):
        """Depth of the pyte scrollback. Bounded so that entering the grid view
        (which renders the whole history once) does not stall on a huge buffer:
        ~2000 lines rebuild in a few hundred ms, and interactive output only ever
        renders the small per-frame delta after that."""
        cap = self._scrollback or 2000
        return max(200, min(cap, 2000))

    def _make_screen(self):
        cols, rows = self._tui_grid_size()
        self._screen = _SafeHistoryScreen(cols, rows,
                                          history=self._history_size(), ratio=0.5)
        self._stream = pyte.ByteStream(self._screen)
        # Route pyte's BEL to the tab's bell policy. pyte tracks OSC state across
        # feeds, so a BEL that merely terminates a (possibly split) OSC title is
        # consumed as the terminator and never reaches here -- only a real bell does.
        self._screen.bell = self._pyte_bell
        self._set_winsize(cols, rows)
        self._reset_grid_view()

    def _pyte_bell(self):
        """pyte dispatched a BEL in TUI mode. Ring per policy, unless we are
        replaying retained output to seed the grid (those bells already happened)."""
        if not self._seeding:
            self._ring()

    def _reset_grid_view(self):
        """Start the grid view from a clean document: the next render rebuilds the
        whole scrollback + grid (all history rows count as new)."""
        self.clear()
        self._top_ids = set()
        self._grid_rows = 0

    def _sync_tui_size(self):
        if self._screen is None:
            return
        cols, rows = self._tui_grid_size()
        if (cols, rows) == (self._screen.columns, self._screen.lines):
            return                        # no real change -> no destructive resize
        # pyte.resize() clears the alternate screen; the running program redraws
        # on the SIGWINCH from the new winsize, so do not force a render here (that
        # would flash a blank frame). The document keeps the last frame until the
        # program's redraw arrives.
        self._screen.resize(rows, cols)
        self._set_winsize(cols, rows)

    def _pyte_qcolor(self, color, default, bright=False):
        if not color or color == 'default':
            return QColor(default) if default is not None else None
        idx = _PYTE_COLOR.get(color)
        if idx is not None:
            real = idx + 8 if bright else idx
            return QColor(self._osc_palette.get(real, ANSI_PALETTE[real]))
        col = QColor('#' + color)          # 256/truecolor as a 6-hex string
        if col.isValid():
            return col
        return QColor(default) if default is not None else None

    def _pyte_format(self, cell):
        key = (cell.fg, cell.bg, cell.bold, cell.reverse, cell.underscore)
        fmt = self._fmt_cache.get(key)
        if fmt is not None:
            return fmt
        theme_bg, theme_fg = THEMES.get(self._theme, THEMES['dark'])
        base_bg = self._osc_palette.get('bg', theme_bg)   # OSC 11 default bg
        base_fg = self._osc_palette.get('fg', theme_fg)   # OSC 10 default fg
        fg = self._pyte_qcolor(cell.fg, base_fg, bright=cell.bold)
        bg = self._pyte_qcolor(cell.bg, None)
        if cell.reverse:
            fg, bg = (bg if bg is not None else QColor(base_bg)), \
                     (fg if fg is not None else QColor(base_fg))
        if fg is None:  # pragma: no cover - _pyte_qcolor always returns a non-None default here
            fg = QColor(base_fg)
        eff_bg = bg if bg is not None else QColor(base_bg)
        if too_close(_rgb(fg), _rgb(eff_bg)):
            # force a readable foreground for the ACTUAL background, so a program
            # cannot hide text by setting fg == bg -- even by moving the default
            # colours together via OSC 10/11 (the fallback must NOT be a
            # program-set colour, or the guard could be defeated).
            fg = QColor('#000000') if luminance(_rgb(eff_bg)) > 127 \
                else QColor('#e6e6e6')
            if bg is not None and too_close(_rgb(fg), _rgb(bg)):  # pragma: no cover - the forced fg already maximises contrast vs bg
                bg = None
        fmt = QTextCharFormat()
        fmt.setForeground(fg)
        if bg is not None:
            fmt.setBackground(bg)
        if cell.bold:
            fmt.setFontWeight(QFont.Weight.Bold)
        if cell.underscore:
            fmt.setFontUnderline(True)
        self._fmt_cache[key] = fmt
        return fmt

    def _end_sync_update(self):
        """End a synchronized-output hold (its ESC[?2026l arrived, or the watchdog
        fired) and paint the completed frame at once."""
        if not self._sync_update:
            return
        self._sync_update = False
        self._sync_timer.stop()
        if self._grid_mode():
            self._render_tui()

    def _render_tui(self):
        """Repaint the TUI view: the scrolling history ABOVE the live pyte grid.
        A scrolled-off history line never changes, so it is appended to the
        document ONCE; only the live grid (screen.lines rows) is re-rendered each
        frame, so the cost is independent of how deep the scrollback is. Every
        cell is still tui_cell-filtered, so a program can position and colour text
        but cannot smuggle a deceptive glyph."""
        screen = self._screen
        if screen is None:
            return
        # If the user has scrolled up into the history to read it while output is
        # still arriving, do NOT yank the view back to the bottom on every frame
        # (and do not clobber a selection); only auto-follow when already at the end.
        bar = self.verticalScrollBar()
        at_bottom = bar is None or bar.value() >= bar.maximum() - 2
        prev_scroll = bar.value() if bar is not None else 0
        self.setUpdatesEnabled(False)
        if self._alt_screen:
            # A full-screen program holds the alternate screen: it is a fixed
            # canvas with no scrollback, so render ONLY the grid. History above it
            # would push the grid's bottom row (e.g. tmux's status bar) below the
            # viewport and add a spurious scrollbar. Clear the carried-in scrollback
            # exactly once, on the frame the view enters this state.
            if not self._alt_view:
                self._reset_grid_view()
                self._alt_view = True
            self._delete_grid()
            self._append_grid(screen)
        else:
            # Left the alternate screen: rebuild the scrolling view from a clean
            # document so the restored primary scrollback is shown once.
            if self._alt_view:
                self._reset_grid_view()
                self._alt_view = False
            self._delete_grid()
            self._append_scrollback(screen)
            # Trim trailing blank grid rows BELOW the cursor so the document ends at
            # the prompt/last output; without this the full grid pads ~screen.lines
            # empty rows below it and you can scroll down into empty space.
            last = screen.cursor.y
            for y in range(screen.lines):
                if any(cell.data.strip() for cell in screen.buffer[y].values()):
                    last = y
            self._append_grid(screen, last_row=max(last, screen.cursor.y))
        self.setUpdatesEnabled(True)
        if at_bottom:
            self._place_grid_cursor(screen)
            if bar is not None:
                # Follow the tail: setTextCursor alone does not reliably scroll the
                # viewport (the CLI path adds an explicit ensureCursorVisible for the
                # same reason), so pin the view to the newest line when at the bottom.
                bar.setValue(bar.maximum())
        elif bar is not None:
            bar.setValue(min(prev_scroll, bar.maximum()))
        self.viewport().update()

    def _insert_grid_row(self, cursor, row, columns):
        """Insert one pyte row (coalescing same-format runs) at the cursor."""
        run_text = ''
        run_fmt = None
        for x in range(columns):
            cell = row[x]
            fmt = self._pyte_format(cell)
            ch = tui_cell(cell.data, self._mode)
            if run_text and fmt is run_fmt:
                run_text += ch
            else:
                if run_text:
                    cursor.insertText(run_text, run_fmt)
                run_text, run_fmt = ch, fmt
        if run_text:
            cursor.insertText(run_text, run_fmt)

    def _delete_grid(self):
        """Remove the live grid (the last _grid_rows blocks) plus the newline that
        joins it to the scrollback, leaving the document ending at the scrollback."""
        if self._grid_rows <= 0:
            return
        doc = self.document()
        first = doc.blockCount() - self._grid_rows
        cur = QTextCursor(doc.findBlockByNumber(max(0, first)))
        cur.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        if first > 0:                     # also eat the newline before the grid:
            # move the WHOLE cursor (anchor too) back over it, so the End
            # selection below starts before the newline. With KeepAnchor the
            # anchor stayed at the block start and the newline was never
            # selected, leaving scrollback's last row with a trailing newline --
            # a spurious empty block that double-spaced every scrolled row.
            cur.movePosition(QTextCursor.MoveOperation.PreviousCharacter)
        cur.movePosition(QTextCursor.MoveOperation.End,
                         QTextCursor.MoveMode.KeepAnchor)
        cur.removeSelectedText()
        self._grid_rows = 0

    def _append_scrollback(self, screen):
        """Append the newly scrolled-off history rows (identified by object id, so
        only the new tail is rendered) at the end of the document."""
        current = list(screen.history.top)
        new_rows = [r for r in current if id(r) not in self._top_ids]
        if new_rows:
            cur = self.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            have = self.document().characterCount() > 1
            for row in new_rows:
                if have:
                    cur.insertText('\n')
                self._insert_grid_row(cur, row, screen.columns)
                have = True
        self._top_ids = {id(r) for r in current}

    def _append_grid(self, screen, last_row=None):
        """Append the live grid at the end of the document. last_row (the last row
        that carries content or holds the cursor) trims the trailing BLANK grid rows
        below the cursor in the primary/line-TUI view -- otherwise the full
        screen.lines grid pads the document with empty, scrollable rows below the
        last output, so you can scroll into empty space. A full-screen alt-screen
        program passes None and keeps all rows (it owns the whole fixed canvas)."""
        cur = self.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        have = self.document().characterCount() > 1
        rows = screen.lines if last_row is None else last_row + 1
        for y in range(rows):
            if have:
                cur.insertText('\n')
            self._insert_grid_row(cur, screen.buffer[y], screen.columns)
            have = True
        # Actual block count, not rows: if the scrollback block cap is smaller than
        # the grid (a tiny /scrollback on a tall display), Qt prunes blocks as they
        # are inserted, and a stale _grid_rows would make the next _delete_grid
        # compute a negative start and wipe the whole document.
        self._grid_rows = min(rows, self.document().blockCount())

    def _place_grid_cursor(self, screen):
        if screen.cursor.hidden:
            return
        doc = self.document()
        grid_top = doc.blockCount() - self._grid_rows
        block = doc.findBlockByNumber(
            min(grid_top + screen.cursor.y, doc.blockCount() - 1))
        if block.isValid():
            pos = block.position() + min(screen.cursor.x, screen.columns)
            tc = self.textCursor()
            tc.setPosition(min(pos, doc.characterCount() - 1))
            self.setTextCursor(tc)

    # -- optional ANSI colours ------------------------------------------------
    def apply_colors(self, enabled):
        if bool(enabled) == self._colors:
            return
        self._colors = bool(enabled)
        self._sgr_reset()
        self._rerender()      # re-colour (or un-colour) the existing buffer too

    def colors_enabled(self):
        return self._colors

    def _effective_colors(self):
        return self._colors and colors_allowed()

    # -- coloured risk markings (the '_' / <U+XXXX> badge, by risk class) -------
    def apply_markings(self, enabled):
        if bool(enabled) == self._markings:
            return
        self._markings = bool(enabled)
        self._rerender()      # re-colour (or un-colour) the existing markings

    def markings_enabled(self):
        return self._markings

    def _sgr_reset(self):
        # palette indexes (or None for default) + bold; folded by parse_sgr.
        self._sgr = {'fg': None, 'bg': None, 'bold': False}

    def _reset_leftover_sgr(self, text):
        """Guard the shell prompt against a finished command's leftover colour.

        A program can set an SGR colour and exit without resetting it; a normal
        terminal then leaves it "stuck", bleeding into the shell's next prompt
        (here readable, contrast-guarded, but still the attacker's colour). Inject
        an SGR reset at each prompt-start marker so the prompt renders in the
        default palette; the program's own colour, before the marker, is untouched.
        The reset is a no-op when nothing is stuck, and a colour the prompt itself
        (a coloured PS1) sets after the marker still applies. Injected into the
        retained raw too, so a mode re-render stays consistent. Shells that do not
        enable bracketed paste simply keep the old (stuck-but-readable) behaviour."""
        if PROMPT_START in text:
            return text.replace(PROMPT_START, '\x1b[0m' + PROMPT_START)
        return text

    def _sgr_qcolor(self, val, default):
        """A parse_sgr colour value -> QColor: a 16-colour palette INDEX (int,
        honouring an OSC 4 override), a '#rrggbb' 256-colour / truecolor string, or
        None -> the default (or None)."""
        if val is None:
            return QColor(default) if default is not None else None
        if isinstance(val, int):
            return QColor(self._osc_palette.get(val, ANSI_PALETTE[val]))
        return QColor(val)                # '#rrggbb' from color_256 / truecolor

    def _format_for(self, state):
        """Build the QTextCharFormat for an SGR state dict, guarding against an
        unreadable foreground/background combination."""
        fmt = QTextCharFormat()
        fg_i, bg_i, bold = state['fg'], state['bg'], state['bold']
        if fg_i is None and bg_i is None and not bold:
            return fmt
        base_bg, base_fg = THEMES.get(self._theme, THEMES['dark'])
        fg = self._sgr_qcolor(fg_i, base_fg)
        bg = self._sgr_qcolor(bg_i, None)
        eff_bg = bg if bg is not None else QColor(base_bg)
        if too_close(_rgb(fg), _rgb(eff_bg)):
            fg = QColor(base_fg)          # never let the text vanish
            if bg is not None and too_close(_rgb(fg), _rgb(bg)):
                bg = None                 # base text collides with the bg -> drop it
        fmt.setForeground(fg)
        if bg is not None:
            fmt.setBackground(bg)
        if bold:
            fmt.setFontWeight(QFont.Weight.Bold)
        return fmt

    # Foreground colour of a neutralized/revealed marking, by risk class. Chosen
    # to read on both the light and dark themes.
    MARKING_COLORS = {
        'bidi':       '#e5484d',      # red    -- reorders text (worst)
        'confusable': '#ff5c8a',      # rose   -- a homoglyph: poses as an ASCII char
        'invisible':  '#f5a623',      # amber  -- zero-width / BOM / separators
        'control':    '#3b9eff',      # blue   -- C0 / DEL / C1 controls
        'nonascii':   '#a06cff',      # purple -- other non-ASCII (foreign, not a look-alike)
    }

    def _fmt_from_key(self, key):
        """QTextCharFormat for a cell's SGR key (a sorted-items tuple), or the
        default format for None. A (MARK_KEY, colour, codepoint) key colours a
        neutralized / revealed marking -- by its risk class (a class-name string),
        by the program's own SGR (an items-tuple, when colored markings are off but
        ANSI colours are on), or not at all (None) -- and carries the source code
        point so hover/click can describe it. Cached; a theme change clears it."""
        if key is None:
            return QTextCharFormat()
        if isinstance(key, tuple) and len(key) == 3 and key[0] == MARK_KEY:
            fmt = self._line_fmt_cache.get(key)
            if fmt is None:
                color = key[1]
                if isinstance(color, str):
                    fmt = QTextCharFormat()
                    fmt.setForeground(QColor(self.MARKING_COLORS[color]))
                elif color:                   # the program's own SGR items-tuple
                    fmt = self._format_for(dict(color))
                else:
                    fmt = QTextCharFormat()
                fmt.setProperty(_CP_PROP, key[2])
                self._line_fmt_cache[key] = fmt
            return fmt
        fmt = self._line_fmt_cache.get(key)
        if fmt is None:
            fmt = self._format_for(dict(key))
            self._line_fmt_cache[key] = fmt
        return fmt

    def wheelEvent(self, event):
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            if delta:
                self.zoom_step.emit(1 if delta > 0 else -1)
            event.accept()
            return
        super().wheelEvent(event)

    def _child_term(self):
        """The child's TERM and terminfo dir for the CURRENT mode, decided BEFORE
        the fork (so no tic runs in the post-fork child). The shell is told, over
        the normal terminfo protocol, exactly what the mode can show:

        - CLI mode -> the restricted `secure-terminal` entry: no cursor addressing,
          no alternate screen. A program then LISTS completions plainly and never
          draws an in-place menu or full screen that line mode would strip into
          garbage. Falls back to xterm-256color if the entry does not resolve.
        - TUI mode -> xterm-256color, so full-screen programs (and ssh) work.

        The terminfo DIR is returned in BOTH modes (so TERMINFO_DIRS always resolves
        both entries), which lets a mode switch re-export TERM into the running shell
        without a restart (see apply_tui). An installed system also ships the entry
        in the system terminfo db (/usr/share/terminfo), so it resolves without
        TERMINFO_DIRS; this dir covers a source checkout. Safety never rests on TERM
        -- line mode strips every escape regardless."""
        tdir = cli_terminfo_dir()
        if not self._tui and tdir:
            return 'secure-terminal', tdir
        return 'xterm-256color', tdir

    # -- child process over a pseudo-terminal ---------------------------------
    def _start(self, command):
        term, terminfo_dir = self._child_term()
        pid, fd = pty.fork()
        if pid == 0:  # pragma: no cover
            # (no cover: this branch runs in the pty.fork child and immediately
            # execvp()s or os._exit()s, so the parent's coverage tracer never
            # receives its line data; the child setup is exercised end-to-end by
            # the widget tests that spawn a real command and read its output.)
            os.environ['TERM'] = term
            if terminfo_dir:
                # prepend our dir; a trailing empty entry keeps the system defaults
                prev = os.environ.get('TERMINFO_DIRS', '')
                os.environ['TERMINFO_DIRS'] = terminfo_dir + ':' + (prev or '')
            # Scrub terminal-fingerprint vars inherited from whatever terminal
            # launched us, so the child (and any host it ssh's into) cannot learn
            # the host emulator's identity/version or a correlatable session id.
            # LINES/COLUMNS are dropped too: the real size comes from TIOCSWINSZ,
            # and a stale value here would mislead programs.
            for _var in ('TERM_PROGRAM', 'TERM_PROGRAM_VERSION',
                         'VTE_VERSION', 'KONSOLE_VERSION', 'KONSOLE_DBUS_SERVICE',
                         'KONSOLE_DBUS_SESSION', 'WT_SESSION', 'WT_PROFILE_ID',
                         'ITERM_SESSION_ID', 'ITERM_PROFILE', 'KITTY_WINDOW_ID',
                         'KITTY_PID', 'ALACRITTY_WINDOW_ID', 'LINES', 'COLUMNS'):
                os.environ.pop(_var, None)
            # We render 24-bit colour faithfully (with a contrast guard) in both
            # modes, so advertise it -- a fixed value, not inherited, so it is not a
            # fingerprint. Programs then emit truecolor instead of down-mapping.
            os.environ['COLORTERM'] = 'truecolor'
            os.environ.setdefault('PAGER', 'cat')
            # `command` is an optional program to run: a list is used verbatim as
            # argv (the "-- prog args" CLI form, no shell reparse), a string is
            # split like a shell word list ("ssh -p 22 host"); none -> login shell.
            if isinstance(command, (list, tuple)):
                argv = [str(a) for a in command]
            else:
                argv = shlex.split(command) if command else []
            if not argv:
                argv = [os.environ.get('SHELL') or '/bin/bash']
            if self._cwd:
                # restore a session tab's working directory; a vanished dir falls
                # back to the inherited cwd rather than failing the spawn.
                try:
                    os.chdir(self._cwd)
                except OSError:
                    pass
            try:
                os.execvp(argv[0], argv)
            except OSError:
                os._exit(127)
        self._pid = pid
        self._fd = fd
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self._notifier = QSocketNotifier(fd, QSocketNotifier.Type.Read, self)
        self._notifier.activated.connect(self._on_readable)
        if self._tui:
            self._make_screen()

    def _on_readable(self):
        try:
            data = os.read(self._fd, 65536)
        except BlockingIOError:
            return                        # nothing ready yet (non-blocking fd)
        except OSError:
            # After the child exits, reading a pty master raises EIO on Linux
            # rather than returning b''. Treat any read error as end-of-file, or a
            # level-triggered notifier on the errored fd spins a core forever.
            data = b''
        if not data:
            if self._notifier is not None:
                self._notifier.setEnabled(False)
            self.shell_exited.emit()
            return
        text = self._decoder.decode(data)
        # The bell is rung where each mode consumes the stream, NOT here: in TUI via
        # pyte's BEL dispatch (_pyte_bell), in CLI on the carry-aware renderable text
        # (below). Ringing on the raw chunk would false-fire whenever a shell's OSC
        # title -- BEL-terminated -- split across a read, seeing the terminator as a
        # standalone bell.
        # Track whether a full-screen program holds the alternate screen. While it
        # does, keep the pyte screen fed even in line mode, so flipping to TUI mode
        # shows its current frame at once (no restart, the program keeps running).
        # Resolve enter/leave by LAST occurrence in the chunk, so a chunk that
        # carries both (one program quits and another starts) ends in the right
        # state rather than always enter-wins.
        # Scan a tail-carried probe so an alt-screen marker split across an os.read()
        # boundary is still seen (as the sync-2026 scan below does). F6.
        alt_probe = self._alt_scan_carry + text
        self._alt_scan_carry = text[-(_ALT_MARKER_MAX - 1):]
        entered = wants_full_screen(alt_probe)
        left = leaves_full_screen(alt_probe)
        alt_changed = False
        if entered or left:
            last_enter = max((alt_probe.rfind(s) for s in _ALT_ENTER), default=-1)
            last_leave = max((alt_probe.rfind(s) for s in _ALT_LEAVE), default=-1)
            was_alt = self._alt_screen
            self._alt_screen = last_enter > last_leave
            alt_changed = self._alt_screen != was_alt
            if not self._alt_screen:
                self._tui_hint_shown = False   # a later full-screen app re-advises

        # Synchronized output (DECSET 2026): resolve the LAST marker, carrying the
        # tail so a marker split across reads is still seen. Apply BEGIN now (drop a
        # pending partial paint, take the hold); defer END until AFTER pyte is fed
        # the closing chunk, so _end_sync_update paints the COMPLETED frame.
        probe = self._sync_scan_carry + text
        self._sync_scan_carry = text[-(len(_SYNC_BEGIN) - 1):]
        sync_end = False
        if _SYNC_BEGIN in probe or _SYNC_END in probe:
            if probe.rfind(_SYNC_BEGIN) > probe.rfind(_SYNC_END):
                # (Re)arm on ENTER, or when an END preceded this BEGIN in the same
                # read (a NEW frame) -- but NOT on a bare repeated BEGIN while held,
                # which must not extend the watchdog's bound.
                if not self._sync_update or _SYNC_END in probe:
                    self._sync_update = True
                    self._render_timer.stop()  # drop a pending partial paint
                    self._sync_timer.start(150)   # bound an update that never closes
                else:
                    self._sync_update = True
            else:
                sync_end = True

        # Feed pyte ONLY in TUI mode -- never in the safe CLI mode, so the escape
        # interpreter is kept out of the default path. On CLI->TUI the screen is
        # rebuilt from the retained raw output (see _seed_grid), so no CLI-period
        # output is lost. _feed_stream handles the alternate-screen snapshot/restore
        # inline (at the byte boundary), so this works for live output and the seed.
        if self.tui_active() and pyte is not None:
            if self._screen is None:
                self._make_screen()
            # Hold back a possible split alt-screen marker tail so _feed_stream never
            # snapshots/restores on HALF a marker; it is reunited with the next read
            # (flushed at EOF below). F6.
            feed = self._alt_feed_carry + data
            k = _alt_partial_tail(feed)         # hold back ONLY a split-marker tail
            self._alt_feed_carry = feed[len(feed) - k:] if k else b''
            self._feed_stream(feed[:len(feed) - k] if k else feed)
        else:
            self._alt_feed_carry = b''          # CLI mode does not stream-feed; drop any tail
        if sync_end:
            self._end_sync_update()            # closing chunk fed -> paint the frame

        # OSC side-effects (title, notify, clipboard, colours, cwd, iTerm2) are a
        # TUI-mode feature, each honored only when the user enabled it.
        if self.tui_active() and self.any_osc_enabled():
            self._handle_osc(data)

        # Retain the raw output in BOTH modes -- for a mode re-render (TUI->CLI)
        # and for seeding the TUI grid (CLI->TUI) -- so neither switch loses output.
        text = self._absorb_caret(text)         # drop a shell's duplicate ^C echo

        if self._grid_mode():
            self._raw += text
            if len(self._raw) > self._RAW_MAX:
                self._raw = self._raw[-self._RAW_MAX:]
            # hold the paint during a synchronized update (the model keeps updating);
            # _end_sync_update renders the completed frame.
            if not self._sync_update and not self._render_timer.isActive():
                self._render_timer.start(16)     # coalesce bursts into ~60fps
            return

        # CLI line mode: display through the escape-stripping pipeline. Prepend any
        # escape tail held back from the previous chunk and hold back a new
        # incomplete tail, so a sequence split across reads (a long OSC title is the
        # usual victim) is never leaked as literal text. An over-long string
        # sequence (a Sixel image is the worst case) switches to a discard state so
        # it is stripped whatever its length, without buffering it unbounded.
        drop_before = self._esc_drop
        text, self._esc_carry, self._esc_drop = feed_chunk_carry(
            text, self._esc_carry, self._esc_drop)
        # Ring on a standalone BEL (a real bell) in the carry-reassembled text.
        # feed_chunk_carry has rejoined a split sequence, so has_bell() -- which
        # strips complete OSC/DCS sequences before looking for a BEL -- never
        # false-fires on a shell's BEL-terminated title, split across reads or not.
        if self._bell_channels and has_bell(text):
            self._ring()
        # An OSC (ESC ]) is stripped in CLI mode; flag each distinct TYPE seen so
        # the window can notice it at most once per tab (not once per any OSC).
        if '\x1b]' in text:
            emitted = set()
            for m in _OSC_CODE_RE.finditer(text):
                code = int(m.group(1))
                key = _OSC_CODE_KEY.get(code, 'osc_other')
                if code == 52:
                    # osc_clipboard (write) and osc_clipboard_read share code 52;
                    # distinguish by the payload so the per-type notice is right.
                    tail = text[m.end():m.end() + 512]
                    end = min((p for p in (tail.find('\x07'), tail.find('\x1b'))
                               if p >= 0), default=len(tail))
                    key = ('osc_clipboard_read' if tail[:end].rstrip().endswith('?')
                           else 'osc_clipboard')
                if key not in emitted:
                    emitted.add(key)
                    self.osc_used.emit(key)
        # An over-cap OSC that just switched to the discard state had its introducer
        # truncated away before the scan above, so still surface the attempt (as a
        # generic OSC) -- else padding an OSC past the cap would evade the notice.
        if self._esc_drop == ']' and drop_before != ']':
            self.osc_used.emit('osc_other')
        # Reset a finished command's leftover colour before it reaches the shell's
        # next prompt. Injected into the retained raw too, so a later mode
        # re-render reproduces the clean prompt rather than re-sticking the colour.
        text = self._reset_leftover_sgr(text)
        self._raw += text
        if len(self._raw) > self._RAW_MAX:
            self._raw = self._raw[-self._RAW_MAX:]     # drop the oldest output
        self._feed_line(text)
        # A program that draws in place -- a full-screen app (htop, vim, on the
        # alternate screen) OR an in-place vertical repaint without it (the shell's
        # interactive completion menu, a progress grid, a cursor-addressed TUI) --
        # is unusable in line mode, whose append-only renderer strips the redraw and
        # leaves garbage. Point the user at TUI mode once per such program. The
        # repaint case (zsh/readline menu-select especially) uses no alternate
        # screen, so wants_full_screen alone misses it.
        if not self._tui_hint_shown and (
                entered or wants_screen_repaint(text)
                or (wants_line_clears(text) and self.has_foreground_program())):
            self._tui_hint_shown = True
            self._advise('This program is drawing in place -- a full-screen '
                         'interface, or a completion menu or progress display that '
                         'repaints -- which the safe CLI mode cannot show. Turn on '
                         'TUI mode to see it.')
        # A whole-screen clear or reset (from `clear`, Ctrl+L or `reset`) is a
        # no-op here BY DESIGN: line mode is append-only, so nothing -- not a
        # program, not a stray clear -- can erase what you have already seen. Note
        # it once per tab, so a clear that "did nothing" is explained rather than
        # a silent surprise. Skipped when a full-screen or repainting program is on
        # (its own TUI advisory covers it, and there its clear is part of drawing).
        elif (not self._clear_notice_shown and wants_clear(text)
                and not self._alt_screen and not entered
                and not wants_screen_repaint(text)):
            self._clear_notice_shown = True
            self._advise('A program tried to clear the screen. The safe CLI mode '
                         'keeps output append-only, so nothing can erase what you '
                         'have already seen. Turn on TUI mode if you need a program '
                         'to control the screen.')

    def _feed_stream(self, data):
        """Feed bytes to pyte, handling alternate-screen enter/leave INLINE so the
        primary screen is snapshotted/restored at the exact byte boundary. This is
        used for live output AND the seed replay, so bytes after a leave (the
        shell's next prompt) land on the RESTORED primary, and a full-screen
        program's frames never pollute the scrollback -- pyte itself has no alt
        buffer."""
        if self._stream is None:
            return
        pos, n = 0, len(data)
        transitions = 0
        while pos < n:
            nxt, kind, mlen = n, None, 0
            for marker in _ALT_ENTER_BYTES:
                i = data.find(marker, pos)
                if 0 <= i < nxt:
                    nxt, kind, mlen = i, 'enter', len(marker)
            for marker in _ALT_LEAVE_BYTES:
                i = data.find(marker, pos)
                if 0 <= i < nxt:
                    nxt, kind, mlen = i, 'leave', len(marker)
            # Each enter/leave snapshots or clears the whole screen (pyte has no alt
            # buffer). A process flooding alternating ?1049h/?1049l in one read could
            # otherwise force thousands of full-screen deepcopies and freeze the GUI,
            # so bound the snapshot/restore work per read: past the cap, feed the
            # remainder as ordinary bytes (a real program redraws its own frame).
            if transitions >= self._ALT_TRANSITIONS_MAX:
                self._feed_bytes(data[pos:])
                break
            self._feed_bytes(data[pos:nxt + mlen])   # up to and incl. the marker
            if kind == 'enter':
                self._alt_enter()
                transitions += 1
            elif kind == 'leave':
                self._alt_leave()
                transitions += 1
            pos = nxt + mlen if kind else n

    def _feed_bytes(self, chunk):
        """Feed one segment to the pyte parser, containing any error -- pyte parses
        untrusted output and a version quirk (private SGR from htop/vim/tmux) must
        never crash the terminal, worst case a rendering glitch, never a core dump."""
        if not chunk:
            return
        try:
            self._stream.feed(chunk)
        except Exception:  # noqa: BLE001  # pragma: no cover - defensive: the filtered byte stream does not make pyte raise
            pass

    def _alt_enter(self):
        """A full-screen program took the alternate screen: snapshot the primary
        screen so it can be restored intact on exit (pyte has no alt buffer)."""
        if self._alt_saved is not None or self._screen is None:
            return                        # already in the alt screen; do not nest
        s = self._screen
        self._alt_saved = (
            copy.deepcopy(s.buffer),
            s.history._replace(top=copy.copy(s.history.top),
                               bottom=copy.copy(s.history.bottom)),
            copy.copy(s.cursor))

    def _alt_leave(self):
        """A full-screen program left the alternate screen: restore the primary
        screen and rebuild the view, so the pre-program screen is back and the
        scrollback is clean."""
        if self._alt_saved is None or self._screen is None:
            return
        self._screen.buffer, self._screen.history, self._screen.cursor = \
            self._alt_saved
        self._alt_saved = None
        self._reset_grid_view()           # rebuild scrollback from restored history

    def _handle_osc(self, data):
        """Dispatch a program's OSC escapes to the features the user has ENABLED
        (each off by default); every value is validated and sanitized first, so a
        title/notification/path can never carry an escape, control or homoglyph.
        Only ever called in TUI mode. Palette (OSC 4/10/11/12) and hyperlinks
        (OSC 8) are display-affecting and handled in the render path, not here."""
        # Rejoin an OSC split across PTY reads, and hold back a new incomplete tail,
        # so a sequence spanning two reads (a full-size clipboard payload always
        # does) is acted on rather than silently dropped. The tail to carry is the
        # earliest of: the last UNTERMINATED "\x1b]" introducer, or a trailing lone
        # "\x1b" (which may begin an introducer in the next read). Bounded: an
        # unterminated flood past the cap is let go rather than buffered forever.
        data = self._osc_carry + data
        self._osc_carry = b''
        carry_at = len(data) if data.endswith(b'\x1b') else -1
        intro = data.rfind(b'\x1b]')
        if intro != -1 and not _OSC_TERMINATED.search(data[intro + 2:]):
            carry_at = intro
        if carry_at == len(data):
            carry_at = len(data) - 1          # the trailing lone ESC
        if carry_at >= 0 and (len(data) - carry_at) <= self._OSC_CARRY_MAX:
            self._osc_carry = data[carry_at:]
            data = data[:carry_at]
        if self._osc['osc_title']:
            title = sanitize_title(getattr(self._screen, 'title', ''))
            if title and title != self._last_title:
                self._last_title = title
                self.title_changed.emit(title)
        if self._osc['osc_hyperlink']:
            for m in _OSC8.finditer(data):
                uri = sanitize_title(m.group(1).decode('utf-8', 'replace'))
                text = sanitize_title(m.group(2).decode('utf-8', 'replace'))
                if uri:
                    # Surface the REAL target next to the visible text -- the
                    # display text can differ from where the link points, so seeing
                    # both is the whole anti-phishing value. (pyte has no per-cell
                    # hyperlink model, so inline-clickable rendering is future work.)
                    self.notified.emit('link: ' + (text or uri) + ' -> ' + uri)
        for match in _OSC_ANY.finditer(data):
            code = int(match.group(1))
            params = match.group(2)
            if code == 9 and self._osc['osc_notify']:
                text = sanitize_title(params.decode('ascii', 'ignore'))
                if text:
                    self.notified.emit(text)
            elif code == 52:
                if params.rstrip().endswith(b'?'):
                    self._osc_clipboard_read()      # READ query: gated per tab
                elif self._osc['osc_clipboard']:
                    self._osc_clipboard(params)     # WRITE
            elif code == 7 and self._osc['osc_cwd']:
                self._osc_cwd(params)
            elif code in (4, 10, 11, 12) and self._osc['osc_colors']:
                self._osc_color(code, params)
            # every other OSC code (iTerm2's OSC 1337 among them) matches no branch
            # and is dropped -- recognized, never acted on, never leaked.

    def _parse_osc_color(self, spec):
        """An OSC colour spec ('rgb:RR/GG/BB', '#RRGGBB', or a name) -> '#rrggbb',
        or None. Only well-formed colours are accepted (never a raw string)."""
        s = spec.decode('ascii', 'ignore').strip().lower()
        m = re.match(r'rgb:([0-9a-f]{1,4})/([0-9a-f]{1,4})/([0-9a-f]{1,4})$', s)
        if m:
            return '#' + ''.join((g * 2)[:2] for g in m.groups())
        if re.match(r'#[0-9a-f]{6}$', s):
            return s
        col = QColor(s)
        return col.name() if col.isValid() else None

    def _osc_color(self, code, params):
        """OSC 4/10/11/12: override a palette index or the default fg/bg/cursor
        colour. The contrast guard in _pyte_format still applies, so a program
        still cannot paint text the same colour as the background to hide it."""
        if code == 4:
            parts = params.split(b';', 1)
            # cap the digit length: int() of a 4300+-digit run raises (a palette
            # index is 0-255, so 8 is far more than enough) -- untrusted output
            # must not crash the OSC handler.
            if len(parts) != 2 or not parts[0].isdigit() or len(parts[0]) > 8:
                return
            idx = int(parts[0])
            col = self._parse_osc_color(parts[1])
            if col is not None and 0 <= idx < 16:      # only the set we render
                self._osc_palette[idx] = col
        else:
            col = self._parse_osc_color(params)
            if col is None:
                return
            role = {10: 'fg', 11: 'bg', 12: 'cursor'}[code]
            self._osc_palette[role] = col
            if role in ('fg', 'bg'):       # make the default colour actually show
                pal = self.palette()
                pal.setColor(QPalette.ColorRole.Base if role == 'bg'
                             else QPalette.ColorRole.Text, QColor(col))
                self.setPalette(pal)
        # Re-resolve cell colours; the render itself is left to the coalescing
        # timer (started after _handle_osc), so a program flooding OSC 4 palette
        # changes cannot force one full re-render per change.
        self._fmt_cache.clear()

    def _osc_clipboard_read(self):
        """OSC 52 READ query. Answering exfiltrates the clipboard (which may hold
        passwords or keys) onto the program's input, so it is gated TWICE: the
        osc_clipboard_read feature must be on, AND the tab must have been GRANTED
        clipboard-read by the user, asked ONCE PER TAB. An un-granted tab only
        raises the ask dialog; it NEVER replies -- so untrusted output in an
        un-approved tab can never exfiltrate the clipboard."""
        if not self._osc.get('osc_clipboard_read'):
            return
        if self._clipboard_read is True:
            self._reply_clipboard()                 # explicitly approved for this tab
        elif self._clipboard_read is False:
            return                                  # explicitly denied for this tab
        elif self._clipboard_read is None:
            if self._clipboard_read_always:
                self._reply_clipboard()             # global always-allow, no prompt
            else:
                self._clipboard_read = 'pending'    # ask once; ignore repeats
                self.clipboard_read_requested.emit()
        # 'pending' (dialog open) -> no reply

    # the clipboard-read decisions the dialog can return
    CLIP_ALLOW_ONCE = 'allow_once'
    CLIP_ALLOW_ALWAYS = 'allow_always'
    CLIP_DENY_ONCE = 'deny_once'
    CLIP_DENY_ALWAYS = 'deny_always'

    def grant_clipboard_read(self, decision):
        """Record the user's clipboard-read decision from the dialog. Four choices:
        allow/deny, each ONCE (this request only, re-ask next time) or ALWAYS
        (remembered for the tab's life). A bool is accepted for compatibility
        (True -> allow-always, False -> deny-always). When the answer allows, reply
        to the query that opened the dialog now -- it was consumed when the prompt
        went up, so a one-shot client would otherwise wait forever."""
        if decision is True:
            decision = self.CLIP_ALLOW_ALWAYS
        elif decision is False:
            decision = self.CLIP_DENY_ALWAYS
        was_pending = self._clipboard_read == 'pending'
        allow = decision in (self.CLIP_ALLOW_ONCE, self.CLIP_ALLOW_ALWAYS)
        remember = decision in (self.CLIP_ALLOW_ALWAYS, self.CLIP_DENY_ALWAYS)
        # remember -> persist the tab decision; once -> reset to None so the next
        # request asks again.
        self._clipboard_read = allow if remember else None
        if allow and was_pending:
            self._reply_clipboard()

    def set_clipboard_read_always(self, on):
        """Apply the global 'always allow clipboard read' default to this tab. Does
        not override an explicit per-tab decision already made."""
        self._clipboard_read_always = bool(on)

    def _reply_clipboard(self):
        """Write the clipboard back as an OSC 52 reply -- rate-limited (so a granted
        tab cannot be flood-exfiltrated) and size-capped. The payload is base64, so
        it carries no newline or control byte into the program's input."""
        now = time.monotonic()
        if now - self._last_clip_read < 1.0:
            return
        self._last_clip_read = now
        board = QGuiApplication.clipboard()
        if board is None:  # pragma: no cover - clipboard() is non-None under a running QApplication
            return
        raw = (board.text() or '').encode('utf-8', 'replace')[:_OSC_CLIP_MAX]
        # _write handles the whole (~87 KiB) reply incl. partial writes, so the
        # client never sees a truncated, unterminated OSC sequence.
        self._write(b'\x1b]52;c;' + base64.b64encode(raw) + b'\x07')

    def _osc_clipboard(self, params):
        """OSC 52 WRITE: <selection>;<base64>. The decoded text is filtered to
        printable ASCII (plus tab and newline) before it reaches the system
        clipboard, and bounded in size -- so a program cannot smuggle a bidi
        override, a zero-width / invisible character or a C0/C1 control onto the
        clipboard (the same hazard the paste path drops), which a later paste into
        any application would otherwise carry. ASCII-only (not the unicode-keeping
        clipboard filter the USER-initiated copy uses): this write is driven by
        untrusted program output with no review, so a homoglyph must not ride onto
        the system clipboard to deceive a paste into another application. (A read
        query is handled separately in _handle_osc, gated per tab.)"""
        parts = params.split(b';', 1)
        if len(parts) != 2:
            return
        payload = parts[1]
        if payload in (b'?', b'') or len(payload) > _OSC_CLIP_MAX:
            return                        # read/clear query or oversized: decline
        try:
            text = base64.b64decode(payload, validate=True).decode('utf-8', 'replace')
        except (ValueError, base64.binascii.Error):
            return
        QGuiApplication.clipboard().setText(sanitize_clipboard(text))

    def _osc_cwd(self, params):
        """OSC 7: file://HOST/PATH working-directory report. Used for the tab; the
        path is unquoted then stripped to safe, bounded text."""
        url = params.decode('ascii', 'ignore')
        if not url.startswith('file://'):
            return
        path = urllib.parse.unquote(url[7:].split('/', 1)[-1])
        path = '/' + path if not path.startswith('/') else path
        # percent-decoding can reintroduce control/bidi/zero-width characters, so
        # run the decoded path through the same safe-ASCII sanitizer as titles
        # before it is shown as a tooltip (no control, no homoglyph, no bidi).
        path = sanitize_title(path)[:4096]
        if path and path != self._reported_cwd:
            self._reported_cwd = path
            self.cwd_changed.emit(path)

    def shutdown(self):
        """Detach the notifier, close the master fd and hang up the child. Used
        when a tab is closed so the shell does not linger, and on app quit so the
        pty machinery is torn down inside the event loop, not during teardown."""
        self._render_timer.stop()          # no pending paint fires into teardown
        if self._notifier is not None:
            self._notifier.setEnabled(False)
            try:
                self._notifier.activated.disconnect()   # no late readable callback
            except (TypeError, RuntimeError):
                pass                       # already disconnected -> nothing to do
            self._notifier = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass        # already closed -> nothing to do
            self._fd = None
        if self._pid:
            try:
                os.kill(self._pid, signal.SIGHUP)
            except OSError:
                pass        # child already gone -> nothing to hang up
            # SIGHUP is asynchronous, so the child may still be alive here; a
            # one-shot waitpid would return (0, 0) and reap nothing. Reaping is
            # therefore left to the process-wide SIGCHLD=SIG_IGN handler (see
            # main.main), which the kernel honors whenever the child does exit.
            # The WNOHANG call only mops up a child that has already died, e.g.
            # when the widget is used without that handler installed.
            try:
                os.waitpid(self._pid, os.WNOHANG)
            except (OSError, ChildProcessError):
                pass        # not yet dead / already reaped -> nothing to do
            self._pid = None

    def _append(self, text):
        self._feed_line(text)

    def _advise(self, message):
        """Emit a one-line advisory from the terminal itself (not the running
        program). The window shows it as a dismissible banner OUTSIDE the terminal
        document, so it is never mistaken for -- or copied as -- program output."""
        self.advise_signal.emit(message)

    def _echo_caret(self, s):
        """Locally echo a signal key in caret notation (^C, ^\\) so pressing it is
        always visible -- secure-terminal's job is to make the invisible visible,
        and a shell (zsh) may print nothing. To avoid a double under a shell that
        DOES echo (bash's readline prints ^C), remember it briefly so the shell's
        own copy in the next output is absorbed (see _absorb_caret)."""
        self._raw += s
        if len(self._raw) > self._RAW_MAX:
            self._raw = self._raw[-self._RAW_MAX:]
        self._feed_line(s)
        self._pending_caret.append((s, time.monotonic() + 0.4))

    def _absorb_caret(self, text):
        """If we just locally echoed a caret (^C, ^\\) and the shell's own echo of
        it appears at the very start of the next output, drop that one copy so the
        user sees a single caret, not two. Expires quickly (0.4s) so an unrelated
        later '^C' in normal output is never swallowed."""
        if not self._pending_caret:
            return text
        now = time.monotonic()
        self._pending_caret = [p for p in self._pending_caret if p[1] >= now]
        for entry in list(self._pending_caret):
            token = entry[0]
            idx = text.find(token)
            # Only absorb a caret that leads the chunk: at the start, or preceded by
            # nothing but CR/LF/whitespace (a shell may emit "\r\n^C"). A printable
            # char before it means this is real output that merely contains "^C"
            # (e.g. "a^C-note"), which must NOT be corrupted.
            if 0 <= idx <= 2 and not text[:idx].strip():
                text = text[:idx] + text[idx + len(token):]
                self._pending_caret.remove(entry)
        return text

    def _feed_line(self, text):
        """The single line-mode output path: advance the logical cell buffer by
        this raw chunk (feed_line_edits honors \\r, \\b and the line-local CSI
        cursor/erase ops, strips every other escape) and repaint the current line.
        Replaces the old strip-then-QTextCursor path; the cell model is what lets
        a reveal badge edit as one character."""
        # Hard-wrap at the reported terminal width (never below a sane floor, and
        # capped so a pathological newline-free flood still bounds each block).
        wrap = self._cols if 8 <= self._cols <= self._MAX_LINE else self._MAX_LINE
        completed, self._line_cells, self._line_col, self._sgr, wraps = \
            feed_line_edits(self._line_cells, self._line_col, self._sgr, text,
                            wrap)
        self._paint_line(completed, wraps)

    def _paint_line(self, completed, wraps=None):
        """Render the just-finished lines (immutable scrollback) plus the current
        editable line to the document, and place the caret at the display column
        of the logical cursor (a reveal badge is several columns wide)."""
        colors = self._effective_colors()
        runs, prefix = cells_to_runs(completed, self._line_cells,
                                     self._mode, colors, self._markings, wraps)
        cursor = self._out_cursor
        if cursor is None:
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
        blk_start = cursor.block().position()
        edit = QTextCursor(cursor)
        edit.setPosition(blk_start)
        edit.movePosition(QTextCursor.MoveOperation.End,
                          QTextCursor.MoveMode.KeepAnchor)
        edit.removeSelectedText()            # drop the old current line
        for text, key in runs:
            if key == WRAP_NL:
                # a soft-autowrap break: a real newline for display, but the new
                # block is marked a continuation so copy joins the wrapped rows.
                edit.insertText('\n')
                edit.block().setUserState(1)
            else:
                edit.insertText(text, self._fmt_from_key(key))
        disp = cells_display_col(self._line_cells, self._line_col, self._mode)
        target = blk_start + prefix + disp
        cursor.setPosition(min(target, self.document().characterCount() - 1))
        self._out_cursor = cursor
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def _export_ascii(self, text):
        """Map the display box (BOX) back to ASCII '_' for any text that LEAVES the
        widget (copy, command hook, session restore -- a saved transcript instead
        uses transcript_text, which stays lossless), so text leaving in Box mode is
        pure ASCII. Map only in Box mode, where every non-ASCII
        byte is a placeholder. Show mode also draws a box for no-glyph characters
        (invisible / bidi / control), but there a box may equally be a real U+25A1
        the program printed -- both copy safely as the box itself -- and Show mode is
        the opt-in to copy real unicode, so leave its text untouched. Reveal / Detail
        carry <U+XXXX> badges, already ASCII."""
        return text.replace(BOX, '_') if self._mode == 'box' else text

    def toPlainText(self):
        # Overrides QPlainTextEdit.toPlainText so every external text getter
        # (save transcript, _hook_transcript, session cap) yields ASCII, not the
        # display box. Qt's own rendering does not go through this method.
        return self._export_ascii(super().toPlainText())

    def transcript_text(self):
        """The scrollback for SAVING: lossless, and pure ASCII except the real
        glyphs Show mode keeps. In Box mode the display collapses every neutralized
        byte to an inert box, which toPlainText saves as a bare '_' -- losing which
        codepoint it was. A saved transcript is a record, so walk the RENDERED
        document (line edits, wraps and scrollback already applied -- unlike the
        capped raw stream) and expand each box to its source codepoint named inline
        (<U+XXXX NAME>, the Detail rendering). Non-box display passes through
        unchanged: Reveal/Detail already carry <U+XXXX> badges, and Show keeps the
        glyph you opted into. Works the same in CLI and TUI (both render a
        document)."""
        doc = self.document()
        out = []
        block = doc.begin()
        first = True
        while block.isValid():
            if not first:                       # blocks are newline-separated,
                out.append('\n')                # exactly like toPlainText
            first = False
            it = block.begin()
            while not it.atEnd():
                frag = it.fragment()
                if frag.isValid():
                    text = frag.text()
                    if BOX in text:
                        cp = frag.charFormat().property(_CP_PROP)
                        # a neutralized run carries its source codepoint; name it.
                        # A box without one (should not happen) still exports '_'.
                        text = (text.replace(BOX, render_output(chr(cp), 'detail'))
                                if cp is not None else text.replace(BOX, '_'))
                    out.append(text)
                it += 1
            block = block.next()
        return ''.join(out)

    def _selection_text(self):
        """The current selection as it would leave the widget: soft-autowrapped
        rows (blocks _paint_line marked with userState 1) are joined so a line that
        wrapped at the terminal width copies as one line, like a real terminal --
        not with a spurious newline at each wrap -- and the box placeholder is
        mapped back to ASCII in Box mode (_export_ascii). '' if nothing selected."""
        cursor = self.textCursor()
        if not cursor.hasSelection():
            return ''
        doc = self.document()
        start, end = cursor.selectionStart(), cursor.selectionEnd()
        parts = []
        block = doc.findBlock(start)
        while block.isValid() and block.position() <= end:
            base = block.position()
            # extract each block's selected slice with a QTextCursor, whose
            # positions are the same UTF-16 code units as start/end -- Python
            # str slicing would count code points and mis-slice an astral char.
            seg_start = max(start, base)
            seg_end = min(end, base + block.length() - 1)   # exclude block sep
            seg = QTextCursor(doc)
            seg.setPosition(seg_start)
            seg.setPosition(seg_end, QTextCursor.MoveMode.KeepAnchor)
            if parts and block.userState() != 1:      # 1 == wrap continuation
                parts.append('\n')
            parts.append(seg.selectedText())
            block = block.next()
        return self._export_ascii(''.join(parts))

    def createMimeDataFromSelection(self):
        cursor = self.textCursor()
        if not cursor.hasSelection():
            return super().createMimeDataFromSelection()
        data = QMimeData()
        # The X11 PRIMARY selection (mouse-select) and drag-and-drop go through here
        # AUTOMATICALLY, with no review UI possible -- so strip to safe ASCII (as the
        # copy review's 'stripped' action does). Otherwise a Show-mode homoglyph would
        # reach a middle-click-paste / drop target unreviewed, exactly the leak the
        # copy review exists to stop. Ctrl+C still routes through copy()'s review, so
        # keeping a real glyph stays an explicit, reviewed choice.
        data.setText(sanitize_clipboard(self._selection_text()))
        return data

    def copy(self):
        """Copy the selection, reviewing it first when it would carry unicode /
        control characters out to the system clipboard (per the copy_warn setting).
        The display is already sanitized -- Box/Reveal/Detail export pure ASCII --
        so a review only arises in Show mode, where real glyphs (a homoglyph, CJK)
        are kept: e.g. after `cat evil-log`, selecting and copying would otherwise
        put the look-alike straight on the clipboard. Reuses the SAME review bar
        and preview as paste; configured SEPARATELY (copy and paste are opposite
        trust directions)."""
        text = self._selection_text()
        if not text or self._review_active:
            return
        has_unicode, has_control = paste_findings(text)
        warn = self._copy_warn
        if warn == 'always' or (warn == 'unicode' and (has_unicode or has_control)):
            self._pending_copy = text
            self._review_active = True
            # no countdown for copy: it is not executed, so the anti-fat-finger
            # gate the paste review needs does not apply (delay 0).
            self.copy_review_requested.emit(text, 0)
            return
        # Review off ('never'): the selection already keeps its unicode (a deliberate
        # copy is not stripped); if it was risky, it reaches the clipboard unreviewed,
        # so light the risk lamp.
        if warn == 'never' and (has_unicode or has_control):
            self.unreviewed_risk.emit()
        self._set_clipboard(sanitize_clipboard_unicode(text))

    def dispatch_pending_copy(self, action):
        """Resolve a held copy review: 'stripped' copies ASCII only, 'unicode'
        keeps printable non-ASCII, 'reject' copies nothing. Re-enables input and
        tells the window to hide the review bar. A no-op if none pending."""
        if not self._review_active:
            return
        text = self._pending_copy
        self._pending_copy = None
        self._review_active = False
        self.paste_review_resolved.emit()
        if text is None or action == 'reject':
            return
        safe = (sanitize_clipboard_unicode(text) if action == 'unicode'
                else sanitize_clipboard(text))
        self._set_clipboard(safe)

    def _set_clipboard(self, text):
        board = QGuiApplication.clipboard()
        if board is not None:
            board.setText(text)

    def _reviewed_context_menu(self, pos):
        """The standard context menu, but with Copy/Cut rerouted through our
        reviewed copy(): their default targets are Qt's NON-virtual C++ copy()
        slot, which bypasses the copy() override and would put a raw (Show-mode)
        selection straight on the clipboard. (Paste goes through insertFromMimeData,
        which IS virtual and already reviewed.)"""
        menu = self.createStandardContextMenu(pos)
        for act in menu.actions():
            if act.objectName() in ('edit-copy', 'edit-cut'):
                try:
                    act.triggered.disconnect()
                except TypeError:
                    pass
                act.triggered.connect(lambda _checked=False: self.copy())
        return menu

    def contextMenuEvent(self, event):
        self._reviewed_context_menu(event.pos()).exec(event.globalPos())

    def _write(self, data):
        """Write ALL of `data` to the pty. The single point where anything reaches
        the child's input (keystrokes, paste, the one gated clipboard reply), so it
        is the choke point the reflection-oracle test spies. Retries a partial write
        / EAGAIN on the non-blocking fd (a large clipboard reply is ~87 KiB, more
        than one os.write may accept), bounded so a program that never drains its
        input cannot hang us."""
        if self._fd is None:
            return
        view = memoryview(data if isinstance(data, (bytes, bytearray)) else bytes(data))
        deadline = time.monotonic() + 2.0
        while view:
            try:
                view = view[os.write(self._fd, view):]
            except BlockingIOError:
                if time.monotonic() > deadline:
                    return
                select.select([], [self._fd], [], 0.05)
            except OSError:
                return          # child gone / pty closed -> input is dropped

    # -- signalling the foreground program ------------------------------------
    def _foreground_pgrp(self):
        """The terminal's foreground process group, or None. This is the running
        command (e.g. nano), not necessarily the shell."""
        if self._fd is None:
            return None
        try:
            pgrp = os.tcgetpgrp(self._fd)
        except OSError:
            return None
        return pgrp if pgrp > 0 else None

    def cwd_basename(self):
        """The basename of the foreground process's working directory (the shell's
        when nothing else runs), for a useful default tab label -- "~" for home,
        else the directory name. None if it cannot be read. This is a far more
        informative default than a static "shell": it tracks where you are as you
        cd around."""
        pgrp = self._foreground_pgrp()
        pid = pgrp if pgrp is not None else self._pid
        if pid is None:
            return None
        try:
            path = os.readlink('/proc/%d/cwd' % pid)
        except OSError:
            return None
        home = os.path.expanduser('~')
        if path == home:
            return '~'
        return os.path.basename(path.rstrip('/')) or '/'

    def shell_cwd(self):
        """The SHELL's full working directory (where the prompt sits), for saving a
        session tab so it restores in the same place. Always the shell pid (not the
        foreground pgrp): that is the canonical prompt location. '' if unreadable."""
        if self._pid is None:
            return ''
        try:
            return os.readlink('/proc/%d/cwd' % self._pid)
        except OSError:
            return ''

    def has_foreground_program(self):
        """True when a program holds the foreground, i.e. there is something for
        Terminate to act on. The direct child (_pid) in the foreground means the
        shell is at its bare prompt for a LOGIN-shell tab (nothing to terminate) --
        but for a `-- PROGRAM` tab _pid IS that program (nano, htop), so it is
        exactly the foreground program to terminate."""
        pgrp = self._foreground_pgrp()
        if pgrp is None:
            return False
        try:
            child_pgrp = os.getpgid(self._pid) if self._pid is not None else None
        except ProcessLookupError:
            return False                  # child already gone (auto-reaped)
        if child_pgrp is not None and pgrp == child_pgrp:
            return self._command is not None   # a launched program, not a shell prompt
        return True

    def terminate_foreground(self):
        """Guaranteed escape hatch for a program that ignores Ctrl+C / Ctrl+\\
        (a stuck TUI): SIGTERM the foreground process group now, then SIGKILL any
        survivor after a grace period. A no-op when only the shell is in the
        foreground, so the panic button never kills your shell out from under a
        bare prompt. Returns True when a program was actually signalled."""
        pgrp = self._foreground_pgrp()
        if pgrp is None:
            return False
        # Never signal our OWN process group: the panic button must not kill
        # secure-terminal itself. A child always runs in its own pty session, so a
        # match here means the foreground pgrp was misresolved -- refuse it.
        if pgrp == os.getpgrp():
            return False
        # The direct child is in the foreground: a bare LOGIN-shell prompt (nothing
        # to terminate), but for a `-- PROGRAM` tab that child IS the program to kill.
        # getpgid can race the child's death (it may exit between the enable-poll and
        # the click) -- a gone child means nothing to signal (as has_foreground_program).
        if self._pid is not None and self._command is None:
            try:
                child_pgrp = os.getpgid(self._pid)
            except ProcessLookupError:
                return False
            if pgrp == child_pgrp:
                return False
        try:
            os.killpg(pgrp, signal.SIGTERM)
        except OSError:
            return False

        def _kill_survivor(target=pgrp):  # pragma: no cover - fires via QTimer 2s later; the grace-period SIGKILL is not observable in the offscreen test harness
            try:
                os.killpg(target, 0)      # still alive?
            except OSError:
                return                    # already gone
            try:
                os.killpg(target, signal.SIGKILL)
            except OSError:
                pass        # exited between the check and the kill -> fine
        QTimer.singleShot(2000, _kill_survivor)
        return True

    # -- input: printable ASCII + signal-key allowlist ------------------------
    _TUI_KEYS = None      # built lazily below (needs Qt.Key at call time)
    _LINE_KEYS = None     # line-mode cursor/history keys, built lazily

    def keyPressEvent(self, event):
        if self._preview:
            # A preview has no child to type to; defer to the read-only base so
            # selection, copy and scrolling still work, but nothing is ever sent.
            super().keyPressEvent(event)
            return
        if self._review_active:
            # A pasted text is held for review: input is suspended so a stray key
            # can never leak into the shell or fire the paste. Enter or Esc rejects
            # (the safe default); everything else is swallowed until a choice.
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter,
                               Qt.Key.Key_Escape):
                self.dispatch_pending_paste('reject')
            return
        key = event.key()
        mods = event.modifiers()
        ctrl = mods & Qt.KeyboardModifier.ControlModifier
        shift = mods & Qt.KeyboardModifier.ShiftModifier

        # Tab navigation is a window action and must work in both modes (even
        # while a full-screen program owns the keyboard): Ctrl+PageUp/Down switch
        # tabs, Ctrl+Shift+PageUp/Down move the current tab. Handled here, before
        # the TUI dispatch, so the program never receives them.
        if ctrl and key in (Qt.Key.Key_PageUp, Qt.Key.Key_PageDown):
            step = -1 if key == Qt.Key.Key_PageUp else 1
            (self.tab_move if shift else self.tab_step).emit(step)
            return

        # In TUI mode the running program owns the keyboard: Ctrl+Shift+<key>
        # still reaches the window shortcuts, but everything else is encoded as
        # VT input (arrows, function keys, control bytes) and sent raw.
        if self.tui_active() and not (ctrl and shift):
            self._tui_key(event)
            return

        # Ctrl+Shift+<key> is reserved for the window (copy/paste, new/close tab,
        # zoom); let those fall through to the QAction shortcuts.
        if ctrl and not shift:
            # Send the control byte to the pty, exactly as a real terminal does.
            # In cooked mode the line discipline turns 0x03/0x1a/0x1c into
            # SIGINT/SIGTSTP/SIGQUIT for the foreground process group; a raw-mode
            # program (an editor, a pager, Claude Code) instead reads the byte
            # itself -- which is what makes readline's Ctrl+A/W/R/U and an app's
            # own "press Ctrl+C again to exit" work. Sending a real signal here
            # broke that. The Terminate action stays the escape hatch for a raw
            # program that ignores its interrupt. Still one-directional.
            #
            # Caret echo (^C) is the tty/shell's job, not ours -- and we already
            # show it wherever a real terminal does: the tty's ECHOCTL echoes ^C
            # for a cooked program, and bash's readline prints it at the prompt,
            # both arriving here as ordinary printable output. zsh's ZLE chooses
            # not to print it at its prompt (verified: identical in xterm), so we
            # add no local echo -- that would double-print under bash.
            if key == Qt.Key.Key_Backslash:
                self._write(b'\x1c')          # Ctrl+\ -> SIGQUIT (cooked)
                self._echo_caret('^\\')       # make the signal visible
                return
            if Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
                byte = key & 0x1f                  # Ctrl+C -> 0x03, Ctrl+L -> 0x0c
                if byte in (0x0a, 0x0d):
                    # Ctrl+J (LF) and Ctrl+M (CR) are accept-line: readline/zle
                    # submit the line exactly like Enter, so route them through the
                    # hook and reset the line state -- else the command runs unjudged
                    # and a stale dirty flag would poison the next prompt.
                    if self._hook is not None and self._hook_intercept():
                        return
                    self._line_buffer = ''
                    self._line_dirty = False
                    self._write(bytes([byte]))
                    return
                self._write(bytes([byte]))
                if key == Qt.Key.Key_C:
                    self._echo_caret('^C')    # make the interrupt visible
                if key in (Qt.Key.Key_C, Qt.Key.Key_U):
                    self._line_buffer = ''    # SIGINT / kill-line discards the line
                    self._line_dirty = False
                elif self._hook is not None:
                    # any OTHER readline control edit (Ctrl+A/E/B/F move, Ctrl+K/W
                    # kill, Ctrl+Y yank, Ctrl+T transpose, Ctrl+D delete, Ctrl+R
                    # search) rewrites the real line without updating _line_buffer,
                    # so the hook must not judge the stale buffer -- fail safe (ask).
                    self._line_dirty = True
                return
            # The rest of the Ctrl+@..Ctrl+_ range (Ctrl+[ -> 0x1b ESC, Ctrl+] ->
            # 0x1d, Ctrl+^ -> 0x1e, Ctrl+_ / Ctrl+/ -> 0x1f readline-undo, Ctrl+Space
            # / Ctrl+@ -> 0x00 set-mark): forward the control byte Qt already
            # computed for the layout, so the whole range is faithful without a
            # hard-coded keymap. Enter/Tab/Backspace keep their dedicated handling.
            ctl = event.text()
            if len(ctl) == 1 and ord(ctl) < 0x20 and ctl not in '\b\t\n\r':
                if self._hook is not None:
                    self._line_dirty = True   # an unmirrored control edit may desync
                self._write(ctl.encode('latin-1'))
                return

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            # The command hook (if configured) judges the typed line before Enter
            # submits it; it may block, ask, or offer a safer command.
            if self._hook is not None and self._hook_intercept():
                return
            self._line_buffer = ''
            self._line_dirty = False
            self._write(b'\r')
            return
        if key == Qt.Key.Key_Backspace:
            self._line_buffer = self._line_buffer[:-1]
            self._write(b'\x7f')
            return
        if key == Qt.Key.Key_Tab:
            # Tab completion rewrites the shell's line (path/command completion)
            # without updating _line_buffer, so the hook would judge the
            # pre-completion fragment. Fail safe: ask.
            if self._hook is not None:
                self._line_dirty = True
            self._write(b'\t')
            return

        # Line editing and history: forward the cursor/history/delete keys to the
        # shell's own line editor (readline/zle). Up/Down recall previous commands,
        # Left/Right and Home/End move within the line, Delete removes forward.
        # These are input you typed -- sent to the shell, whose redraw returns as
        # ordinary output the renderer sanitizes. Shift+navigation is reserved for
        # scrollback (below), so only the unmodified keys forward here.
        if not shift and not ctrl:
            if SecureTerminal._LINE_KEYS is None:
                SecureTerminal._LINE_KEYS = _build_line_edit_keys()
            seq = SecureTerminal._LINE_KEYS.get(key)
            if seq is not None:
                # History recall / intra-line cursor editing happens inside the
                # shell's line editor, which we do not mirror -- so once one of
                # these is used, _line_buffer no longer reflects the real command.
                # Mark it, so the hook fails safe (asks) instead of judging a
                # stale or empty line. Only matters when a hook is configured.
                if self._hook is not None:
                    self._line_dirty = True
                self._write(seq)
                return

        # Scrollback navigation. In line mode there is no full-screen program to
        # own these keys, so scroll the buffer: Shift+PageUp/Down a page and
        # Shift+Home/End to the ends is the gnome-terminal/konsole convention,
        # and plain PageUp/Down scroll too because "Page Up shows earlier output"
        # is what a user reaches for. (TUI mode returned above; there the running
        # program gets these as VT input.)
        if self._scroll_key(key, bool(shift)):
            return

        text = event.text()
        # Typed input is deliberate -- you pressed the key -- so printable
        # non-ASCII (the euro sign, accents, CJK) is sent UTF-8 encoded. The
        # deceptive classes cannot ride in this way: str.isprintable() is False
        # for control, bidi, zero-width and format characters, and those are not
        # reachable from a keyboard anyway. How it then DISPLAYS is still the
        # display mode's call (box shows a placeholder, show shows the glyph).
        if text and all(ch.isprintable() for ch in text):
            self._line_buffer += text
            self._write(text.encode('utf-8'))
        # non-printable input and arrow/navigation keys are intentionally ignored

    def _scroll_key(self, key, shift):
        """Scroll the scrollback view for a navigation key in line mode. Returns
        True when `key` was a scroll key and was handled. PageUp/PageDown scroll
        a page unmodified (line mode has no program consuming them); Shift+Home/
        End jump to the ends, matching the standard terminal bindings and leaving
        plain Home/End free for line editing later."""
        bar = self.verticalScrollBar()
        if key == Qt.Key.Key_PageUp:
            bar.triggerAction(bar.SliderAction.SliderPageStepSub)
        elif key == Qt.Key.Key_PageDown:
            bar.triggerAction(bar.SliderAction.SliderPageStepAdd)
        elif shift and key == Qt.Key.Key_Home:
            bar.triggerAction(bar.SliderAction.SliderToMinimum)
        elif shift and key == Qt.Key.Key_End:
            bar.triggerAction(bar.SliderAction.SliderToMaximum)
        else:
            return False
        return True

    # -- command hook: judge the typed line before Enter submits it -----------
    def apply_hook(self, config):
        """Enable the command hook (a dict with keys argv, timeout, on_error,
        transcript) or disable it with None."""
        self._hook = config or None

    def hook_enabled(self):
        return self._hook is not None

    def _foreground_cwd(self):
        pgrp = self._foreground_pgrp()
        if pgrp:
            try:
                return os.readlink('/proc/%d/cwd' % pgrp)
            except OSError:
                pass            # gone / not readable -> no cwd
        return ''

    def _hook_transcript(self):
        setting = (self._hook or {}).get('transcript', 'none')
        if setting == 'full':
            return self.toPlainText()
        if setting.startswith('tail:'):
            try:
                count = int(setting.split(':', 1)[1])
            except ValueError:
                count = 0
            if count > 0:
                return '\n'.join(self.toPlainText().split('\n')[-count:])
        return ''

    def _hook_intercept(self):
        """Judge the typed line through the hook before it is submitted. Returns
        True when the hook handled the Enter (blocked, or asked and decided);
        False to let the normal path submit the line unchanged."""
        from secure_terminal import hook
        # If the line was recalled from history or edited with the cursor keys,
        # _line_buffer no longer matches what the shell will run, so judging it
        # would be misleading (it could wave a dangerous recalled command through).
        # Fail safe: ask the user to confirm the line the hook could not read.
        if self._line_dirty:
            action = self._hook_ask('(recalled / edited line)', {
                'verdict': 'ask',
                'message': 'This line was recalled from history or edited in '
                           'place, so the command hook could not read it. Review '
                           'it before it runs.',
                'suggestion': ''})
            self._line_buffer = ''
            self._line_dirty = False
            if action == 'run':
                self._write(b'\r')
            else:
                self._write(b'\x15')          # Ctrl+U: discard the line
            return True
        command = self._line_buffer
        if not command.strip():
            return False
        result = hook.evaluate(
            self._hook['argv'], command,
            timeout=self._hook.get('timeout', 10),
            on_error=self._hook.get('on_error', 'allow'),
            cwd=self._foreground_cwd(),
            transcript_provider=self._hook_transcript)
        if result['message']:
            self.hook_notice.emit(result['message'])
        if result['verdict'] == 'allow':
            return False
        action = self._hook_ask(command, result)     # 'run' | 'suggest' | 'discard'
        if action == 'run':
            self._line_buffer = ''
            self._write(b'\r')
            return True
        self._write(b'\x15')          # Ctrl+U: discard the typed line in the shell
        self._line_buffer = ''
        if action == 'suggest' and result['suggestion']:
            # insert the suggested command for review -- never with a newline, so
            # it never auto-runs; the user presses Enter (and is re-judged). The
            # hook layer already single-lines a suggestion, but strip CR/LF HERE
            # too so the no-auto-run invariant is enforced at the point of the
            # write, not only upstream.
            suggestion = result['suggestion'].replace('\r', ' ').replace('\n', ' ')
            self._write(suggestion.encode('ascii', 'ignore'))
            self._line_buffer = suggestion
        return True

    def _hook_ask(self, command, result):
        """Prompt for a blocked/ask verdict. Returns 'run', 'suggest' or
        'discard'. A 'block' with no suggestion needs no prompt (just discard)."""
        from PyQt6.QtWidgets import QMessageBox
        if result['verdict'] == 'block' and not result['suggestion']:
            return 'discard'
        text = ('The command hook flagged this command:\n\n  ' + command
                + (('\n\n' + result['message']) if result['message'] else ''))
        box = QMessageBox(QMessageBox.Icon.Warning, 'Command hook', text, parent=self)
        run_btn = None
        if result['verdict'] == 'ask':
            run_btn = box.addButton('Run as typed',
                                    QMessageBox.ButtonRole.AcceptRole)
        suggest_btn = None
        if result['suggestion']:
            suggest_btn = box.addButton('Use: ' + result['suggestion'][:40],
                                        QMessageBox.ButtonRole.ActionRole)
        cancel_btn = box.addButton('Cancel', QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(cancel_btn)
        box.exec()
        clicked = box.clickedButton()
        if clicked is run_btn and run_btn is not None:
            return 'run'
        if clicked is suggest_btn and suggest_btn is not None:
            return 'suggest'
        return 'discard'

    def _tui_key(self, event):
        """Encode a keystroke as VT input for the program in TUI mode."""
        key = event.key()
        mods = event.modifiers()
        ctrl = mods & Qt.KeyboardModifier.ControlModifier
        shift = mods & Qt.KeyboardModifier.ShiftModifier
        alt = mods & Qt.KeyboardModifier.AltModifier

        if SecureTerminal._TUI_KEYS is None:
            SecureTerminal._TUI_KEYS = _build_tui_keys()

        if key == Qt.Key.Key_Tab and shift:
            self._write(b'\x1b[Z')                  # back-tab
            return
        seq = SecureTerminal._TUI_KEYS.get(key)
        if seq is not None:
            self._write(seq)
            return
        # Ctrl+letter -> the corresponding control byte (Ctrl+C -> 0x03), which
        # the program receives; the Terminate action stays the escape hatch.
        if ctrl and not shift and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            self._write(bytes([key & 0x1f]))
            return
        text = event.text()
        if text and len(text) == 1 and ord(text) < 0x20:
            self._write(text.encode('latin-1'))     # e.g. Ctrl+[ -> ESC
            return
        if text and all(ch.isprintable() for ch in text):
            self._write((b'\x1b' if alt else b'') + text.encode('utf-8'))
        # non-printable input is still dropped

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.tui_active() or (self._alt_screen and self._screen is not None):
            # TUI mode, or a full-screen program held in the background while in
            # line mode: keep the pyte screen and the pty at the (scrollbar-
            # independent) grid, so a later flip to TUI needs no resize.
            self._sync_tui_size()
        else:
            # Plain line mode still needs the pty's winsize kept in step with the
            # widget: the shell reads COLUMNS from it, and zsh pads its prompt
            # with trailing fill to that width. Left at the fork-time default
            # (80), that fill (and the clickable void it creates) lands in the
            # middle of a wider window instead of at the true right edge.
            self._set_winsize(*self._grid_size())

    def _cp_at(self, pos):
        """The source code point of a neutralized/revealed character under a
        viewport point, or None. First the char format's tagged code point (every
        marked cell carries it, in every mode -- even the box placeholder); then, for a
        readable glyph shown as-is (show mode), the non-ASCII character itself.

        cursorForPosition snaps to the nearest insertion boundary; the glyph under
        the point is the character on one side of it. We navigate by CHARACTER (so
        an astral pair is one step, never split at a surrogate) and pick the side
        whose visual box actually contains the point -- comparing against min/max of
        the two caret rects, so a right-to-left run needs no left-to-right guess."""
        cursor = self.cursorForPosition(pos)
        for step in (QTextCursor.MoveOperation.NextCharacter,
                     QTextCursor.MoveOperation.PreviousCharacter):
            probe = QTextCursor(cursor)
            if not probe.movePosition(step, QTextCursor.MoveMode.KeepAnchor):
                continue
            cp = self._cp_in_box(probe.selectionStart(), probe.selectionEnd(), pos)
            if cp is not None:
                return cp
        return None

    def _cp_in_box(self, a, b, pos):
        """The inspectable code point of the character spanning document positions
        [a, b) if the point falls inside its visual box, else None. The box is the
        span between the two boundary caret rects (min/max, so it is correct in a
        right-to-left run too)."""
        doc = self.document()
        ca, cb = QTextCursor(doc), QTextCursor(doc)
        ca.setPosition(a)
        cb.setPosition(b)
        ra, rb = self.cursorRect(ca), self.cursorRect(cb)
        if not (min(ra.x(), rb.x()) <= pos.x() <= max(ra.x(), rb.x())
                and min(ra.top(), rb.top()) <= pos.y() <= max(ra.bottom(), rb.bottom())):
            return None
        fwd = QTextCursor(doc)
        fwd.setPosition(a)
        fwd.setPosition(b, QTextCursor.MoveMode.KeepAnchor)
        cp = fwd.charFormat().property(_CP_PROP)
        if cp is not None:
            return int(cp)
        text = fwd.selectedText()
        # a readable non-ASCII glyph (show mode) keeps no tag but IS its own code
        # point; skip Qt's block/line separators (U+2028/U+2029). A whole astral
        # char comes back as one Python code point here (grapheme-aware nav).
        if len(text) == 1:
            o = ord(text)
            if o > 0x7F and not 0xD800 <= o <= 0xDFFF and o not in (0x2028, 0x2029):
                return o
        return None

    def event(self, e):
        # Hovering a neutralized/revealed character explains what it actually is --
        # name, category, escape -- because the display ("_", a <U+XXXX> badge, or
        # a look-alike glyph) does not, on its own, reveal its identity.
        if e.type() == QEvent.Type.ToolTip:
            pos = self.viewport().mapFromGlobal(e.globalPos())
            cp = self._cp_at(pos)
            if cp is not None:
                QToolTip.showText(e.globalPos(), describe_codepoint(cp), self)
                return True
            QToolTip.hideText()
            e.ignore()
            return True
        return super().event(e)

    def mouseDoubleClickEvent(self, event):
        # Double-clicking a neutralized/revealed character opens an ACTIVE popup
        # (unlike the passive hover tooltip): its text can be selected and copied,
        # and it stays open while you work. A double-click elsewhere selects a word
        # as usual.
        cp = self._cp_at(event.position().toPoint())
        if cp is not None:
            self._show_char_popup(cp, event.globalPosition().toPoint())
            return
        super().mouseDoubleClickEvent(event)

    def _show_char_popup(self, cp, global_point):
        """A small, dismissible, copyable popup describing a character. Copies the
        \\uXXXX ESCAPE, not the raw glyph -- putting a bidi override or homoglyph
        on the clipboard is the very hazard this terminal guards against."""
        dlg = QDialog(self)
        dlg.setWindowTitle('Character U+%04X' % cp)
        dlg.setMinimumWidth(340)        # roomy enough to read the description
        col = QVBoxLayout(dlg)
        info = QLabel(describe_codepoint(cp) + '\nRisk: '
                      + _RISK_LABELS.get(marking_class(cp), marking_class(cp)), dlg)
        info.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        col.addWidget(info)
        esc = '\\u%04x' % cp if cp <= 0xFFFF else '\\U%08x' % cp
        note = QLabel(
            'Copy places the safe <code>%s</code> escape on the clipboard, not the '
            'raw character: copying an invisible, bidi or homoglyph character as-is '
            'is the exact hazard this terminal guards against.' % esc, dlg)
        note.setTextFormat(Qt.TextFormat.RichText)
        note.setWordWrap(True)
        # readable (palette(text), not the too-faint palette(mid)) and selectable,
        # so the explanation can be marked and copied like the rest.
        note.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        note.setStyleSheet('color: palette(text); font-size: 12px;')
        col.addWidget(note)
        row = QHBoxLayout()
        copy = QPushButton('Copy ' + esc, dlg)
        copy.setToolTip('Copies the %s escape (a safe ASCII representation), '
                        'never the raw character.' % esc)

        def _copy_escape(_checked=False, button=copy, text=esc):
            QGuiApplication.clipboard().setText(text)
            button.setText('Copied ' + text)        # confirm it happened
        copy.clicked.connect(_copy_escape)
        close = QPushButton('Close', dlg)
        close.setDefault(True)
        close.clicked.connect(dlg.close)
        row.addWidget(copy)
        row.addStretch(1)
        row.addWidget(close)
        col.addLayout(row)
        dlg.move(global_point)
        self._char_popup = dlg          # keep a reference so it is not GC'd
        dlg.show()

    def reset_caret(self):
        """Snap the visible caret back to the output cursor (where typed input
        goes), clearing any selection. Used after a search moves the caret to a
        match, so closing the find bar returns the caret to where you can type."""
        if self._out_cursor is not None:
            self.setTextCursor(self._out_cursor)
        else:
            tc = self.textCursor()
            tc.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(tc)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        # A terminal caret is not click-positionable: typed input always goes to
        # the shell at the output cursor, never where you click. A plain click
        # that moved the blinking caret elsewhere -- e.g. into zsh's trailing
        # prompt fill -- would only mislead (a caret blinking where you cannot
        # type). Keep a drag-selection for copy; otherwise snap the caret back.
        if self.textCursor().hasSelection():
            return
        self.reset_caret()

    # -- paste: warn on, then sanitize, anything unusual ----------------------
    def insertFromMimeData(self, source):
        if self._review_active:
            # A copy or paste is already held for review: ignore a second paste
            # rather than clobber the pending one (input is otherwise suspended
            # during a review; copy() guards the same way). Re-paste after choosing.
            return
        raw = source.text()
        # When to review the paste, per the paste_warn setting:
        #   'always'  -- every paste (even plain ASCII);
        #   'unicode' -- only when the clipboard carries unicode or control
        #                characters, the case worth a second look (the default);
        #   'never'   -- never prompt; the paste is still sanitized silently.
        # A review is ASYNCHRONOUS: rather than block on a modal, HOLD the paste,
        # ask the window to show the in-window review bar, and suspend terminal
        # input until a choice dispatches or rejects it (dispatch_pending_paste).
        # The hard gate is preserved -- no byte reaches the shell until you choose.
        has_unicode, has_control = paste_findings(raw)
        # A multi-line paste would run a hidden second command the instant you paste,
        # so hold it for review too -- otherwise a pure-ASCII pastejacking payload
        # bypasses the default 'unicode' review the settings promise covers it (F3).
        risky = has_unicode or has_control or paste_is_multiline(raw)
        # With a command hook configured (line mode), a paste that carries ANY
        # newline/CR -- even a single trailing one that paste_is_multiline does not
        # flag -- auto-submits the command the instant it is sent, with no Enter and
        # so no hook evaluation. Force review so the command is seen first, even when
        # paste review is otherwise off ('never') -- the hook gate must not be
        # bypassable by the paste_warn setting.
        hook_submit = (self._hook is not None and not self.tui_active()
                       and ('\n' in raw or '\r' in raw))
        risky = risky or hook_submit
        warn = self._paste_warn
        if hook_submit or warn == 'always' or (warn == 'unicode' and risky):
            self._pending_paste = raw
            self._review_active = True
            self.paste_review_requested.emit(raw, int(self._paste_delay))
            return
        # Not held. With review OFF ('never'), do NOT strip to ASCII -- that would
        # make deliberately pasting real unicode (CJK, emoji, an accented path)
        # impossible; keep printable unicode instead (control/bidi/invisible are
        # still neutralized, since those are injection, not content, and a hidden
        # newline could auto-run). If the content was risky, it crosses UNREVIEWED,
        # so light the risk lamp -- visible, not silent.
        if warn == 'never' and risky:
            self.unreviewed_risk.emit()
        self._dispatch_paste(raw, 'unicode' if warn == 'never' else 'stripped')

    def dispatch_pending_paste(self, action):
        """Resolve a held paste review: 'stripped' or 'unicode' sends it (sanitized
        accordingly), 'reject' drops it. Re-enables input and tells the window to
        hide the review bar either way. A no-op if no review is pending."""
        if not self._review_active:
            return
        raw = self._pending_paste
        self._pending_paste = None
        self._review_active = False
        self.paste_review_resolved.emit()
        if raw is not None and action != 'reject':
            self._dispatch_paste(raw, action)

    def review_pending(self):
        """True while a pasted text is held awaiting the user's review choice."""
        return self._review_active

    def _dispatch_paste(self, raw, action):
        # 'unicode' keeps printable non-ASCII (still no control/bidi/zero-width);
        # 'stripped' is ASCII only. Both are safe to send as UTF-8.
        safe = (sanitize_paste_unicode(raw) if action == 'unicode'
                else sanitize_paste(raw))
        if not safe:
            return
        # Keep the hook's view of the line honest across a paste (line mode only; a
        # TUI paste does not touch the line-mode command).
        if self._hook is not None and not self.tui_active() and safe:
            if safe.endswith('\r') and not self._line_dirty:
                # A CLEAN line plus a submitting paste: the trailing CR submits the
                # line (approved via review). Reset like Enter so a typed prefix
                # cannot linger and make the hook judge "prefix + next command".
                # Only when clean: on an already-unverifiable line a quoted-insert
                # (Ctrl+V) could make the CR literal rather than accept-line, so we
                # must not ASSUME submission -- the else branch keeps failing safe.
                self._line_buffer = ''
            else:
                # Pending text _line_buffer never saw, or a line we already cannot
                # verify -> the hook must fail safe (ask) on the next Enter.
                self._line_dirty = True
        data = safe.encode('utf-8')
        # Bracketed paste when the TUI program asked for it (DEC mode 2004), so a
        # multi-line paste is delivered as data, not interpreted as keystrokes.
        if self.tui_active() and self._screen is not None \
                and _BRACKETED_PASTE_MODE in getattr(self._screen, 'mode', ()):
            data = b'\x1b[200~' + data + b'\x1b[201~'
        self._write(data)
