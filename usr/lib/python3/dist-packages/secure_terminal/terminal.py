## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
The secure-terminal widget.

Design (see https://secure-terminal.github.io):

- DISPLAY is printable-ASCII by default. Program output is passed through
  render_output(): ANSI/OSC escape sequences are removed and, in the default
  'strip' mode, every character that is not printable ASCII (plus tab and
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
(safety does not rest on TERM, which is a normal xterm-256color, but on that
unconditional stripping). An opt-in TUI mode (apply_tui) instead interprets
escapes through a pyte screen model so full-screen programs (ssh, vim, htop,
tmux) work; mode is only a rendering choice over the same byte stream, so it
switches without restarting the shell and a running program survives the switch.
Even in TUI mode every cell is still character-filtered and pyte only builds a
screen model, so program output cannot drive it to set the title or touch the
clipboard the way a real terminal's escape handling can (the programs you run
still have your normal user access). The window flags TUI mode with a visible
risk indicator; the strict line mode remains the safe-by-construction default.
"""

import os
import pty
import re
import copy
import time
import base64
import urllib.parse
import fcntl
import signal
import codecs
import struct
import termios
import shlex

try:
    import pyte
except ImportError:                      # TUI mode is unavailable without pyte
    pyte = None

from PyQt6.QtCore import (QSocketNotifier, Qt, QTimer, pyqtSignal, QEvent,
                          QMimeData)
from PyQt6.QtGui import (QFont, QTextCursor, QColor, QPalette, QTextCharFormat,
                         QTextFormat, QGuiApplication)
from PyQt6.QtWidgets import (QPlainTextEdit, QToolTip, QDialog, QVBoxLayout,
                             QHBoxLayout, QLabel, QPushButton, QApplication)

# The pure, Qt-free sanitization core (also tested directly by dist-ai). Names
# are re-exported here so terminal.py stays the single import point for the rest
# of the package (main.py, dialog.py).
from secure_terminal.sanitize import (
    THEMES, BASE_POINT_SIZE, ANSI_PALETTE, DISPLAY_MODES,
    colors_allowed, too_close, luminance, sanitize_paste,
    sanitize_paste_unicode,
    paste_findings, tui_cell, sanitize_title,
    feed_line_edits, cells_to_runs, cells_display_col, MARK_KEY, WRAP_NL,
    wants_full_screen, leaves_full_screen, describe_codepoint, marking_class,
    split_trailing_escape, feed_chunk_carry, has_bell, OSC_FEATURES,
    _ALT_SCREEN as _ALT_ENTER, _ALT_SCREEN_OFF as _ALT_LEAVE,
)

# Custom char-format property carrying a marked cell's SOURCE code point, so the
# widget can describe the real character on hover/click regardless of how it is
# displayed (the strip "_", a reveal/detail badge, a control shown as "_").
_CP_PROP = QTextFormat.Property.UserProperty + 1

# Human-readable gloss for each risk class (marking_class), for the click popup.
_RISK_LABELS = {
    'bidi':      'bidirectional control -- can reorder text (the worst deception)',
    'invisible': 'invisible -- zero-width, BOM or line/paragraph separator',
    'control':   'control character -- C0, DEL or C1',
    'nonascii':  'other non-ASCII -- can be a look-alike (homoglyph)',
}

# Any numeric-code OSC: ESC ] <code> ; <params> (BEL | ST). The dispatcher acts on
# the codes for enabled OSC features and ignores the rest (still stripped).
_OSC_ANY = re.compile(rb'\x1b\](\d+);([^\x07\x1b]*)(?:\x07|\x1b\\)')
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
        _OSC_CODE_KEY[int(_c)] = _k
# OSC code embedded in text (str, in the CLI display path).
_OSC_CODE_RE = re.compile(r'\x1b\](\d+)')

# Alternate-screen enter/leave, as BYTES: pyte has no alt buffer, so the feed path
# acts on these to snapshot/restore the primary screen at the exact boundary.
_ALT_ENTER_BYTES = (b'\x1b[?1049h', b'\x1b[?1047h', b'\x1b[?47h')
_ALT_LEAVE_BYTES = (b'\x1b[?1049l', b'\x1b[?1047l', b'\x1b[?47l')


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

    def __init__(self, parent=None, command=None, tui=False, history=''):
        super().__init__(parent)
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        # A terminal never scrolls sideways: line mode wraps at the widget width and
        # the TUI grid is sized to fit, so a horizontal scrollbar is always wrong
        # (it only appeared from a rounding overflow and clipped the right edge).
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setFrameStyle(0)

        self._base_point_size = BASE_POINT_SIZE
        font = QFont('monospace')
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setPointSize(self._base_point_size)
        self.setFont(font)

        self._zoom = 100
        self._theme = 'dark'
        self.apply_theme(self._theme)

        # display mode for non-ASCII output, and an incremental UTF-8 decoder so
        # a multi-byte character split across two os.read() chunks still decodes.
        self._mode = 'strip'
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

        # optional ANSI colours (off by default); SGR parser state.
        self._colors = False
        self._markings = True         # colour the '_' / badge by risk class (on)
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
        # True while a full-screen program holds the alternate screen buffer. The
        # pyte screen is then kept fed in the background even in line mode, so
        # flipping to TUI mode shows the program's current frame instantly (no
        # restart). Maintained from the output stream (alt-screen enter/leave).
        self._alt_screen = False
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
        self._start(command)
        if self._tui:
            # A tab that STARTS in TUI must enter the grid view properly (seed the
            # pyte screen from any restored scrollback, set _grid_shown and the
            # scrollbar), or the first output would clear the history unseeded and a
            # later switch to CLI would not rebuild the line document.
            self._sync_display()

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

    def apply_zoom(self, percent):
        percent = max(10, min(1000, int(percent)))
        self._zoom = percent
        size = max(1, round(self._base_point_size * percent / 100.0))
        font = self.font()
        font.setPointSize(size)
        self.setFont(font)
        self._sync_tui_size()          # font change resizes the grid
        if self._grid_mode():
            self._render_timer.start(16)   # repaint at the new glyph size

    def current_zoom(self):
        return self._zoom

    def current_theme(self):
        return self._theme

    def apply_mode(self, mode):
        """Set the display mode for non-ASCII output and re-render the existing
        buffer under it -- a mode change affects the whole scrollback, not only
        new output, so toggling strip/show/reveal re-reads what is already there."""
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

    # -- TUI mode -------------------------------------------------------------
    def apply_tui(self, enabled):
        """Turn TUI mode on/off without restarting the shell. Mode is only a
        rendering choice over the same byte stream, so a running program (htop,
        an ssh session) keeps running across the switch. A no-op when unchanged or
        pyte is missing.

        Enabling TUI does NOT blank the scrolling history: the fixed pyte grid
        only takes over the screen while a full-screen program is actually on the
        alternate screen (_grid_mode). With just a shell, TUI stays in line
        display with the scrollback intact, so toggling CLI<->TUI back and forth
        never loses history."""
        enabled = bool(enabled) and tui_available()
        if enabled == self._tui:
            return
        self._tui = enabled
        # switching modes abandons any half-parsed CLI escape state; a stale carry
        # or discard would corrupt the first bytes rendered after switching back.
        self._esc_carry = ''
        self._esc_drop = ''
        self._osc_carry = b''
        self._sync_display()

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
        """Normalise a bell spec (a comma-separated string, an iterable, or the
        legacy 'off'/'audible'/'visual') to a set of valid channels."""
        if isinstance(spec, str):
            spec = spec.split(',')
        return {c.strip() for c in spec if c and c.strip() in cls.BELL_CHANNELS}

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
        if app is None:
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
        """Play the configured sound file via QtMultimedia if one is set and the
        module is available. Returns True if playback was started."""
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
        except Exception:               # noqa: BLE001 -- QtMultimedia optional
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
        self._screen = pyte.HistoryScreen(cols, rows,
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
        if fg is None:
            fg = QColor(base_fg)
        eff_bg = bg if bg is not None else QColor(base_bg)
        if too_close(_rgb(fg), _rgb(eff_bg)):
            # force a readable foreground for the ACTUAL background, so a program
            # cannot hide text by setting fg == bg -- even by moving the default
            # colours together via OSC 10/11 (the fallback must NOT be a
            # program-set colour, or the guard could be defeated).
            fg = QColor('#000000') if luminance(_rgb(eff_bg)) > 127 \
                else QColor('#e6e6e6')
            if bg is not None and too_close(_rgb(fg), _rgb(bg)):
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
        self._delete_grid()
        self._append_scrollback(screen)
        self._append_grid(screen)
        self.setUpdatesEnabled(True)
        if at_bottom:
            self._place_grid_cursor(screen)
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
        if first > 0:                     # also eat the newline before the grid
            cur.movePosition(QTextCursor.MoveOperation.PreviousCharacter,
                             QTextCursor.MoveMode.KeepAnchor)
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

    def _append_grid(self, screen):
        """Append the live grid (screen.lines rows) at the end of the document."""
        cur = self.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        have = self.document().characterCount() > 1
        for y in range(screen.lines):
            if have:
                cur.insertText('\n')
            self._insert_grid_row(cur, screen.buffer[y], screen.columns)
            have = True
        # Actual block count, not screen.lines: if the scrollback block cap is
        # smaller than the grid (a tiny /scrollback on a tall display), Qt prunes
        # blocks as they are inserted, and a stale _grid_rows would make the next
        # _delete_grid compute a negative start and wipe the whole document.
        self._grid_rows = min(screen.lines, self.document().blockCount())

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

    def _format_for(self, state):
        """Build the QTextCharFormat for an SGR state dict, guarding against an
        unreadable foreground/background combination."""
        fmt = QTextCharFormat()
        fg_i, bg_i, bold = state['fg'], state['bg'], state['bold']
        if fg_i is None and bg_i is None and not bold:
            return fmt
        base_bg, base_fg = THEMES.get(self._theme, THEMES['dark'])
        fg = QColor(ANSI_PALETTE[fg_i]) if fg_i is not None else QColor(base_fg)
        bg = QColor(ANSI_PALETTE[bg_i]) if bg_i is not None else None
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
        'bidi':      '#e5484d',       # red    -- reorders text (worst)
        'invisible': '#f5a623',       # amber  -- zero-width / BOM / separators
        'control':   '#3b9eff',       # blue   -- C0 / DEL / C1 controls
        'nonascii':  '#a06cff',       # purple -- other non-ASCII (homoglyph)
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

    # -- child process over a pseudo-terminal ---------------------------------
    def _start(self, command):
        pid, fd = pty.fork()
        if pid == 0:
            # child. Always advertise a real terminal: mode (line vs TUI) is now a
            # pure rendering choice over the SAME byte stream, switchable without a
            # restart, so the shell must not be pinned to a dumb terminal it cannot
            # change later. Safety does not rest on TERM: line mode strips every
            # escape in the renderer regardless (fuzz-proven), and a capable TERM
            # is what lets a full-screen program actually run once TUI mode is on.
            os.environ['TERM'] = 'xterm-256color'
            # Scrub terminal-fingerprint vars inherited from whatever terminal
            # launched us, so the child (and any host it ssh's into) cannot learn
            # the host emulator's identity/version or a correlatable session id.
            # LINES/COLUMNS are dropped too: the real size comes from TIOCSWINSZ,
            # and a stale value here would mislead programs.
            for _var in ('TERM_PROGRAM', 'TERM_PROGRAM_VERSION', 'COLORTERM',
                         'VTE_VERSION', 'KONSOLE_VERSION', 'KONSOLE_DBUS_SERVICE',
                         'KONSOLE_DBUS_SESSION', 'WT_SESSION', 'WT_PROFILE_ID',
                         'ITERM_SESSION_ID', 'ITERM_PROFILE', 'KITTY_WINDOW_ID',
                         'KITTY_PID', 'ALACRITTY_WINDOW_ID', 'LINES', 'COLUMNS'):
                os.environ.pop(_var, None)
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
        entered = wants_full_screen(text)
        left = leaves_full_screen(text)
        alt_changed = False
        if entered or left:
            last_enter = max((text.rfind(s) for s in _ALT_ENTER), default=-1)
            last_leave = max((text.rfind(s) for s in _ALT_LEAVE), default=-1)
            was_alt = self._alt_screen
            self._alt_screen = last_enter > last_leave
            alt_changed = self._alt_screen != was_alt
            if not self._alt_screen:
                self._tui_hint_shown = False   # a later full-screen app re-advises

        # Feed pyte ONLY in TUI mode -- never in the safe CLI mode, so the escape
        # interpreter is kept out of the default path. On CLI->TUI the screen is
        # rebuilt from the retained raw output (see _seed_grid), so no CLI-period
        # output is lost. _feed_stream handles the alternate-screen snapshot/restore
        # inline (at the byte boundary), so this works for live output and the seed.
        if self.tui_active() and pyte is not None:
            if self._screen is None:
                self._make_screen()
            self._feed_stream(data)

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
            if not self._render_timer.isActive():
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
                key = _OSC_CODE_KEY.get(int(m.group(1)), 'osc_other')
                if key not in emitted:
                    emitted.add(key)
                    self.osc_used.emit(key)
        # An over-cap OSC that just switched to the discard state had its introducer
        # truncated away before the scan above, so still surface the attempt (as a
        # generic OSC) -- else padding an OSC past the cap would evade the notice.
        if self._esc_drop == ']' and drop_before != ']':
            self.osc_used.emit('osc_other')
        self._raw += text
        if len(self._raw) > self._RAW_MAX:
            self._raw = self._raw[-self._RAW_MAX:]     # drop the oldest output
        self._feed_line(text)
        # A full-screen program (htop, vim) is unusable in line mode -- its
        # escapes are stripped, leaving garbage. Point the user at TUI mode once.
        if not self._tui_hint_shown and entered:
            self._tui_hint_shown = True
            self._advise('This program wants a full-screen interface, which the '
                         'safe CLI mode cannot draw. Turn on TUI mode to run it '
                         'here.')

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
        except Exception:            # noqa: BLE001 -- third-party parser, any error
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
            elif code == 52 and self._osc['osc_clipboard']:
                self._osc_clipboard(params)
            elif code == 7 and self._osc['osc_cwd']:
                self._osc_cwd(params)
            elif code in (4, 10, 11, 12) and self._osc['osc_colors']:
                self._osc_color(code, params)
            elif code == 1337 and self._osc['osc_iterm2']:
                self._osc_iterm2(params)

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
            if len(parts) != 2 or not parts[0].isdigit():
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

    def _osc_clipboard(self, params):
        """OSC 52: <selection>;<base64|'?'>. WRITE only; a read query ('?') is
        DECLINED -- answering would exfiltrate your clipboard to the program AND
        write onto its input. The decoded text is stripped of control/escape bytes
        before it reaches the clipboard, and bounded in size."""
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
        text = ''.join(ch for ch in text
                       if ch in '\n\t' or 0x20 <= ord(ch) and ch != '\x7f')
        QGuiApplication.clipboard().setText(text)

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

    def _osc_iterm2(self, params):
        """OSC 1337: iTerm2 proprietary. File upload/download from untrusted output
        is indefensible, so it is DECLINED even when enabled -- this handler makes
        the escape recognized (not leaked) but performs no iTerm2 action."""
        return

    def shutdown(self):
        """Detach the notifier, close the master fd and hang up the child. Used
        when a tab is closed so the shell does not linger."""
        if self._notifier is not None:
            self._notifier.setEnabled(False)
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
            if 0 <= idx <= 2:                 # only near the very start of output
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

    def createMimeDataFromSelection(self):
        """On copy, join soft-autowrapped rows (blocks _paint_line marked with
        userState 1) so a line that wrapped at the terminal width copies as one
        line, like a real terminal -- not with a spurious newline at each wrap."""
        cursor = self.textCursor()
        if not cursor.hasSelection():
            return super().createMimeDataFromSelection()
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
        data = QMimeData()
        data.setText(''.join(parts))
        return data

    def _write(self, data):
        if self._fd is None:
            return
        try:
            os.write(self._fd, data)
        except OSError:
            pass            # child gone / pty closed -> input is dropped

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

    def has_foreground_program(self):
        """True when a program other than the shell holds the foreground, i.e.
        there is something for Terminate to act on."""
        pgrp = self._foreground_pgrp()
        if pgrp is None:
            return False
        try:
            shell_pgrp = os.getpgid(self._pid) if self._pid is not None else None
        except ProcessLookupError:
            return False                  # shell already gone (auto-reaped)
        if shell_pgrp is not None and pgrp == shell_pgrp:
            return False
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
        # Only the shell is running (nothing to terminate).
        if self._pid is not None and pgrp == os.getpgid(self._pid):
            return False
        try:
            os.killpg(pgrp, signal.SIGTERM)
        except OSError:
            return False

        def _kill_survivor(target=pgrp):
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
                self._write(bytes([key & 0x1f]))   # Ctrl+C -> 0x03, Ctrl+L -> 0x0c
                if key == Qt.Key.Key_C:
                    self._echo_caret('^C')    # make the interrupt visible
                if key in (Qt.Key.Key_C, Qt.Key.Key_U):
                    self._line_buffer = ''    # SIGINT / kill-line discards the line
                    self._line_dirty = False
                return
            # The rest of the Ctrl+@..Ctrl+_ range (Ctrl+[ -> 0x1b ESC, Ctrl+] ->
            # 0x1d, Ctrl+^ -> 0x1e, Ctrl+_ / Ctrl+/ -> 0x1f readline-undo, Ctrl+Space
            # / Ctrl+@ -> 0x00 set-mark): forward the control byte Qt already
            # computed for the layout, so the whole range is faithful without a
            # hard-coded keymap. Enter/Tab/Backspace keep their dedicated handling.
            ctl = event.text()
            if len(ctl) == 1 and ord(ctl) < 0x20 and ctl not in '\b\t\n\r':
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
        # display mode's call (strip shows '_', show shows the glyph).
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
            # it never auto-runs; the user presses Enter (and is re-judged).
            self._write(result['suggestion'].encode('ascii', 'ignore'))
            self._line_buffer = result['suggestion']
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
        marked cell carries it, in every mode -- even the strip "_"); then, for a
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
        col = QVBoxLayout(dlg)
        info = QLabel(describe_codepoint(cp) + '\nRisk: '
                      + _RISK_LABELS.get(marking_class(cp), marking_class(cp)), dlg)
        info.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        col.addWidget(info)
        esc = '\\u%04x' % cp if cp <= 0xFFFF else '\\U%08x' % cp
        row = QHBoxLayout()
        copy = QPushButton('Copy ' + esc, dlg)
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(esc))
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

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        # A terminal caret is not click-positionable: typed input always goes to
        # the shell at the output cursor, never where you click. A plain click
        # that moved the blinking caret elsewhere -- e.g. into zsh's trailing
        # prompt fill -- would only mislead (a caret blinking where you cannot
        # type). Keep a drag-selection for copy; otherwise snap the caret back.
        if self.textCursor().hasSelection():
            return
        if self._out_cursor is not None:
            self.setTextCursor(self._out_cursor)
        else:
            tc = self.textCursor()
            tc.movePosition(QTextCursor.MoveOperation.End)
            self.setTextCursor(tc)

    # -- paste: warn on, then sanitize, anything unusual ----------------------
    def insertFromMimeData(self, source):
        raw = source.text()
        # A plain-ASCII paste goes straight through; only warn when the clipboard
        # carries unicode or control characters -- the case worth a second look.
        has_unicode, has_control = paste_findings(raw)
        action = 'stripped'
        if has_unicode or has_control:
            from secure_terminal.dialog import PasteWarningDialog
            action = PasteWarningDialog.confirm(raw, self._paste_delay, self)
            if action == 'reject':
                return
        # 'unicode' keeps printable non-ASCII (still no control/bidi/zero-width);
        # 'stripped' is ASCII only. Both are safe to send as UTF-8.
        safe = (sanitize_paste_unicode(raw) if action == 'unicode'
                else sanitize_paste(raw))
        if not safe:
            return
        data = safe.encode('utf-8')
        # Bracketed paste when the TUI program asked for it (DEC mode 2004), so a
        # multi-line paste is delivered as data, not interpreted as keystrokes.
        if self.tui_active() and self._screen is not None \
                and 2004 in getattr(self._screen, 'mode', ()):
            data = b'\x1b[200~' + data + b'\x1b[201~'
        self._write(data)
