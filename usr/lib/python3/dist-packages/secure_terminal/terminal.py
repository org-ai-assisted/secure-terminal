#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
The secure-terminal widget.

Design (see https://secure-terminal.github.io):

- DISPLAY is printable-ASCII by default. Program output is passed through
  render_output(): ANSI/OSC escape sequences are removed and, in the default
  'box' mode, every character that is not printable ASCII (plus tab and
  newline) becomes a box placeholder (the U+25A1 white square, exported as ASCII
  '_' on copy), the way sanitize-string/stcat neutralize a log. There is
  no escape parser, so a hostile filename, a forged status line or a Trojan-
  Source comment cannot redraw or reorder what you read. Two optional display
  modes trade some of that for readability, per tab: 'show' renders a non-ASCII
  character as its glyph when it is printable (str.isprintable() excludes the
  invisible, bidi and format characters that make unicode deceptive), so a log
  with legitimate unicode is readable while the dangerous classes still collapse
  to the box; 'reveal' shows every non-ASCII character as a <U+XXXX> badge so you can
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

import pyte
# pyte's own hard dependency, so no new package: it is what pyte's draw() uses to
# decide a character's cell width, and _SafeHistoryScreen.draw has to agree with
# that decision to know which characters pyte would silently drop.
from wcwidth import wcwidth

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

    def linefeed(self):
        # A line that fills the EXACT width leaves the cursor "past" the last column (pyte's
        # deferred-wrap / last-column-flag state, cursor.x == columns); pyte then performs the
        # wrap only on the NEXT printable char, with its own CR+LF. A bare LF here would advance
        # a SECOND line, leaving a blank row between every full-width line (a full-screen `cat`
        # of a width-filling board rendered as row, blank, row, blank ...). The usual ONLCR
        # \r\n already reset the column with its CR, so this only fires for a BARE LF at full
        # width: consume the deferred wrap. Purely a cursor fix -- no cell and no filtering change.
        #
        # Match a real terminal exactly: xterm clears the last-column flag on a line feed but
        # KEEPS the column, so the next char lands at the LAST column of the new line (a
        # staircase), NOT column 0 -- proven with an ESC[6n (DSR) cursor probe. A truth-telling
        # terminal must render what a real one does, so drop the cursor onto the last real column
        # rather than normalising to column 0. Distribution pyte (which we pin) lacks this; the
        # fork fixes it in every cursor-move primitive, matching what cursor_back already did.
        #
        # pyte last-column-flag bug -- fork fix: https://github.com/org-ai-assisted/pyte/pull/7 ;
        # report: https://github.com/org-ai-assisted/pyte-audit/blob/master/reports/bug-H-linefeed-pending-wrap.md
        if self.cursor.x == self.columns:
            self.cursor.x -= 1
        super().linefeed()

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
            combining = ord(ch) >= 0x0300 and unicodedata.combining(ch)
            if combining or wcwidth(ch) < 1:
                x = self.cursor.x
                if x:
                    target = self.buffer[self.cursor.y].get(x - 1)
                elif self.cursor.y:
                    target = self.buffer[self.cursor.y - 1].get(self.columns - 1)
                else:
                    target = None
                if target is not None and len(target.data) > _TUI_COMBINE_CAP:
                    continue                  # target cell already at the cap
                if not combining:
                    # pyte's draw() takes `else: break` for a character that is
                    # zero-width but NOT a combining mark -- U+200D, U+FE0F, the
                    # emoji modifiers -- so it writes no cell and the character
                    # VANISHES: nothing shown, nothing marked. CLI mode names the
                    # same byte inline, so TUI mode was the one place an invisible
                    # reached the user unmarked, which is the guarantee every mode
                    # is supposed to keep. Merge it into the preceding cell the way
                    # pyte does for a combining mark, so tui_cell sees a cell whose
                    # data is not purely printable and renders the placeholder.
                    if target is not None:
                        self._merge_invisible(target, ch)
                    else:
                        # Nothing precedes it (cursor at the very start of the
                        # screen), so there is no cell to attach to. Occupy THIS
                        # cell instead: a leading invisible is exactly the
                        # spoofing position that must not go unmarked.
                        self._mark_own_cell(ch)
                    continue
            super().draw(ch)

    def _mark_own_cell(self, ch):
        """Store a zero-width character in the cell AT the cursor and step past it.
        Used only when nothing precedes it, so there is no cell to merge into.
        tui_cell renders any cell whose data is not purely printable as the
        placeholder, so the character is marked rather than silently dropped."""
        row = self.buffer[self.cursor.y]
        row[self.cursor.x] = self.cursor.attrs._replace(data=ch)
        self.dirty.add(self.cursor.y)
        self.cursor.x = min(self.cursor.x + 1, self.columns)

    def _merge_invisible(self, target, ch):
        """Append a zero-width character to `target`'s data so the cell is marked.
        No NFC normalization: this is not a combining mark and must not compose
        with the base -- the point is that the cell stops being purely printable,
        which is what tui_cell keys the placeholder on."""
        x = self.cursor.x
        if x:
            row, col = self.cursor.y, x - 1
        else:
            row, col = self.cursor.y - 1, self.columns - 1
        self.buffer[row][col] = target._replace(data=target.data + ch)
        self.dirty.add(row)


class _Utf8CharsetByteStream(pyte.ByteStream):
    """A pyte ByteStream that decodes UTF-8 itself yet still honours ISO-2022
    charset designation -- so DEC line-drawing (``ESC ( 0``, and SI/SO) renders as
    real box-drawing glyphs.

    pyte's stock ByteStream ties both behaviours to one flag: with ``use_utf8``
    True (its default) it UTF-8-decodes the bytes, but the parser then treats every
    ``ESC ( <F>`` designation as a no-op (``if self.use_utf8: continue``), so an
    ncurses/vt100 program's line-drawing borders arrive as literal ``lqqqk`` text.
    Turning use_utf8 off re-enables the designation but drops UTF-8 decoding to
    latin-1, corrupting every multi-byte character.

    We want both, so decode UTF-8 unconditionally in feed() (the terminal already
    knows its child speaks UTF-8) and keep use_utf8 False purely to arm the parser's
    charset path. The Screen still character-filters every resulting cell via
    tui_cell, so a translated glyph is subject to the same neutralization as any
    other output; this only lets a benign box-drawing designation reach the grid."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_utf8 = False              # arm the parser's charset designation

    def feed(self, data):
        # Always UTF-8 (via the inherited incremental decoder, so a multi-byte
        # character split across reads still decodes), then parse the str directly
        # -- bypassing ByteStream.feed's use_utf8-gated latin-1 pass-through.
        pyte.Stream.feed(self, self.utf8_decoder.decode(data))


from PyQt6.QtCore import (QSocketNotifier, Qt, QTimer, pyqtSignal, QEvent,
                          QMimeData)
from PyQt6.QtGui import (QFont, QTextCursor, QColor, QPalette, QTextCharFormat,
                         QTextFormat, QGuiApplication, QSyntaxHighlighter,
                         QTextBlockUserData)
from PyQt6.QtWidgets import (QPlainTextEdit, QToolTip, QDialog, QVBoxLayout,
                             QHBoxLayout, QLabel, QPushButton, QApplication)

# The pure, Qt-free sanitization core (also tested directly by dist-ai). Names
# are re-exported here so terminal.py stays the single import point for the rest
# of the package (main.py, review.py).
from secure_terminal.sanitize import (
    THEMES, BASE_POINT_SIZE, ANSI_PALETTE, DISPLAY_MODES,
    colors_allowed, too_close, luminance, sanitize_paste,
    sanitize_paste_unicode, sanitize_clipboard, sanitize_clipboard_unicode,
    sanitize_clipboard_display,
    paste_findings, paste_is_multiline, paste_no_autosubmit, tui_cell,
    sanitize_title,
    feed_line_edits, cells_to_runs, cells_display_col, MARK_KEY, WRAP_NL, BOX,
    SPACE_MARK,
    render_output,
    wants_full_screen, leaves_full_screen, wants_screen_repaint, wants_clear,
    wants_line_clears,
    describe_codepoint, marking_class, marking_cp_for_cell, is_structural,
    PROMPT_START,
    feed_chunk_carry, has_bell, OSC_FEATURES,
    tail_from_escape_boundary, split_trailing_escape, scan_mouse_modes,
    sgr_mouse_report,
    _MOUSE_BUTTON_MODES, _MOUSE_DRAG_MODE, _MOUSE_MOTION_MODE,
    _MOUSE_FOCUS_MODE, _MOUSE_SGR_MODE,
    _ALT_SCREEN as _ALT_ENTER, _ALT_SCREEN_OFF as _ALT_LEAVE,
)

# Custom char-format property carrying a marked cell's SOURCE code point, so the
# widget can describe the real character on hover/click regardless of how it is
# displayed (the box placeholder, a reveal/detail badge, a control as a box).
# The default terminal font. Hack is a monospace face DESIGNED to disambiguate
# confusable glyphs (dotted zero distinct from O, tailed l, serifed 1 and I,
# rn kept apart from m) and -- crucially for a terminal that promises "what you
# see is the exact bytes" -- it ships NO ligature tables, so it can never merge
# characters (e.g. != into one glyph). Packaged in Debian as fonts-hack, a hard
# dependency; main._require_default_font fails loud at startup if it is absent
# rather than let Qt silently substitute a fallback that may reintroduce them.
DEFAULT_FONT_FAMILY = 'Hack'

# Base font point-size bounds (the zoom scales this); a stored or typed value is
# clamped so the glyph can never be made unreadably tiny or huge.
FONT_SIZE_MIN = 6
FONT_SIZE_MAX = 72

_CP_PROP = QTextFormat.Property.UserProperty + 1


class _GridRow(QTextBlockUserData):
    """The render model for one TUI-grid block, attached to the block so it
    survives scrollback promotion and relayout. `runs` is a list of
    (offset, length, fmt, cp): UTF-16 offset+length within the block, the
    QTextCharFormat to paint, and the SOURCE code point that region stands for
    (None for a plain cell). The grid stores its formats HERE rather than in the
    document's char formats -- inserting plain text once per row and letting a
    QSyntaxHighlighter paint the runs is dramatically cheaper than a per-cell
    cursor.insertText(text, fmt) on a full-viewport distinct-colour board. Layout
    formats are not readable via charFormat(), so the code point that hover / copy
    / transcript need is kept here too (see _run_cp_at / _block_runs)."""

    def __init__(self, runs):
        super().__init__()
        self.runs = runs


class _GridHighlighter(QSyntaxHighlighter):
    """Re-applies each grid block's stored formats. Qt drops layout formats on
    every relayout (resize, font change, wrap), and calls highlightBlock to
    rebuild them; painting from the block's own _GridRow makes the formats
    durable with no invalidation bookkeeping. A non-grid block (CLI line mode,
    whose formats live in the document via insertText) carries no _GridRow and is
    left untouched."""

    def highlightBlock(self, _text):
        data = self.currentBlockUserData()
        if isinstance(data, _GridRow):
            for offset, length, fmt, _cp in data.runs:
                self.setFormat(offset, length, fmt)


# Human-readable gloss for each risk class (marking_class), for the click popup.
_RISK_LABELS = {
    'bidi':       'bidirectional control -- can reorder text (the worst deception)',
    'confusable': 'a look-alike of an ASCII character (homoglyph), e.g. Cyrillic a for Latin a',
    'invisible':  'invisible or blank -- zero-width, BOM, line/paragraph separator, or a non-ASCII space',
    'control':    'control character -- C0, DEL or C1',
    'combining':  'a combining mark -- stacks onto the preceding character (Zalgo)',
    'nonascii':   'other non-ASCII -- foreign text, not an ASCII look-alike',
}

# Both marking-format caches (line mode's _line_fmt_cache, the TUI grid's
# _grid_mark_cache) are keyed by SOURCE code point, so untrusted output cycling
# through distinct non-ASCII code points would grow them toward the whole ~1.1M
# code-point space for the life of the tab. Cap admission -- the same bound
# sanitize._is_mark uses -- so a flood cannot leak formats without limit; an
# over-cap format is still built and returned, just not retained.
_MARK_CACHE_MAX = 4096


def _cache_bounded(cache, key, fmt):
    """Store fmt under key only while cache is below the admission cap, then return
    it, so a code-point-keyed format cache cannot grow without bound."""
    if len(cache) < _MARK_CACHE_MAX:
        cache[key] = fmt
    return fmt


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
    # python3-pyte is a hard dependency (see debian/control), so TUI mode is
    # always available. Retained as a stable capability query for callers/tests.
    return True


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

    def _fresh(directory):
        """True when `directory` holds BOTH compiled entries and neither is OLDER
        than the shipped source.

        Both, because _child_term hands the child `secure-terminal-noedit` purely
        on the strength of this probe: a directory carrying only the older single
        entry gave the shell a TERM with no compiled entry at all ("unknown
        terminal type" -- ncurses programs refuse to start).

        Not older, because the cache otherwise outlived every .ti change: an
        upgrade that cancelled a capability left existing users on the stale
        compilation, so the terminal kept advertising what the renderer no longer
        matched -- the source-vs-artifact drift these entries exist to prevent."""
        compiled = [os.path.join(directory, 's', name)
                    for name in ('secure-terminal', 'secure-terminal-noedit')]
        if not all(os.path.isfile(path) for path in compiled):
            return False
        if not src:
            return True
        try:
            return min(os.path.getmtime(p) for p in compiled) >= os.path.getmtime(src)
        except OSError:
            return False

    if src and _fresh(os.path.dirname(src)):
        return os.path.dirname(src)       # compiled at build time next to the source
    cache = os.path.join(
        os.environ.get('XDG_CACHE_HOME') or os.path.join(
            os.path.expanduser('~'), '.cache'),
        'secure-terminal', 'terminfo')
    if _fresh(cache):
        return cache
    if src:
        try:
            os.makedirs(cache, exist_ok=True)
            subprocess.run(['tic', '-x', '-o', cache, src],
                           check=True, capture_output=True, timeout=15)
            # the same both-entries test: a tic that produced only one of them is
            # not a usable result, because _child_term may ask for either.
            if _fresh(cache):
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


def _build_non_content_keys():
    """Qt.Key values that, at a shell prompt, only move the cursor or delete --
    they CANNOT introduce new submittable text. In TUI mode (where the line is not
    mirrored) these must NOT flag the line pending: any real content always arrives
    via a content-introducing key first (printable text, history recall, Tab
    completion), which does the flagging, so a later navigation/deletion keystroke
    need not re-flag. Flagging one of these at an EMPTY prompt would defer the
    mode-switch re-export for no reason (a no-op Backspace/Left leaving TERM stale).
    History recall (Up/Down) is deliberately ABSENT -- it recalls a command, which
    is exactly the invisible content the flag must catch. Built lazily (Qt.Key)."""
    k = Qt.Key
    return frozenset((
        k.Key_Left, k.Key_Right, k.Key_Home, k.Key_End,
        k.Key_PageUp, k.Key_PageDown, k.Key_Insert, k.Key_Delete,
        k.Key_Backspace,
        k.Key_F1, k.Key_F2, k.Key_F3, k.Key_F4, k.Key_F5, k.Key_F6,
        k.Key_F7, k.Key_F8, k.Key_F9, k.Key_F10, k.Key_F11, k.Key_F12,
    ))


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
    # an unterminated / over-long string sequence (OSC/DCS/...) has silently
    # suppressed a lot of CLI-mode output (the escape_limit threshold). The
    # suppression is NOT lifted (no escape byte is rendered); the window shows a
    # one-time notice so a frozen-looking terminal is explained, not mysterious.
    escape_suppressed = pyqtSignal()
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
                 markings=True, line_edits=True, theme='light'):
        super().__init__(parent)
        # Deterministic screenshot mode (SECURE_TERMINAL_SHOT=1, a startup capture
        # MODE -- never a persisted per-tab setting): hide the caret and render the
        # document SYNCHRONOUSLY, so a capture of unchanged content is byte-identical
        # run to run (the comparison shots jitter otherwise -- an async paint race
        # lands the prompt +/-1 row, plus the blinking caret). Gates ONLY the
        # shot-mode branches below; the normal render path and every security
        # guarantee are unchanged when it is off.
        self._shot = os.environ.get('SECURE_TERMINAL_SHOT') == '1'
        if self._shot:
            self.setCursorWidth(0)     # no caret drawn -> no frame depends on blink phase
        # Optional live transcript file: when SECURE_TERMINAL_TRANSCRIPT_FILE names a path,
        # this tab's transcript is written there whenever output SETTLES, kept current. A
        # generic, mode-agnostic configuration -- set it on the command line
        # (SECURE_TERMINAL_TRANSCRIPT_FILE=/path secure-terminal ...) to keep a live plain
        # transcript on disk. A capture harness uses it to VERIFY a shot rendered its
        # payload -- a screenshot alone cannot tell an empty terminal from a full one, the
        # window chrome paints either way. Off (None) unless the path is set.
        self._transcript_file = os.environ.get('SECURE_TERMINAL_TRANSCRIPT_FILE') or None
        if self._transcript_file:
            # Debounce the write to the TRAILING EDGE of an output burst: a busy stream fires
            # _on_readable continuously, and serialising the whole (capped) document on every
            # read is O(reads x document). Coalesce to one write when output pauses -- which is
            # also AFTER the (possibly debounced) render, so the file reflects the painted frame.
            self._transcript_timer = QTimer(self)
            self._transcript_timer.setSingleShot(True)
            self._transcript_timer.setInterval(30)     # > the 16ms render debounce
            self._transcript_timer.timeout.connect(self._write_transcript_file)
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
        # Line-wrap is per display mode (_sync_wrap_mode, set once _mode/_tui are
        # known below); NoWrap is the pre-render default. Box/Show stay NoWrap so a
        # glyph keeps its line/column across a box<->show toggle (a pixel-width wrap
        # made a wide CJK/emoji glyph, ~1.7 char advances vs a box's ~1, jump lines
        # on the toggle). Detail/Reveal expand each cell to a wide <U+XXXX> badge and
        # wrap to the width instead -- a real terminal has no horizontal scroll, and
        # an auto-scroll to reach that overflow would hide the start of every row.
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        # A residual Box/Show line of wide glyphs can still exceed the width (it is
        # left NoWrap for cross-mode stability), so keep the horizontal scrollbar
        # available-as-needed for MANUAL inspection of that overflow -- never as an
        # auto-follow (see _paint_line's home-pin) and never for Detail/Reveal, which
        # wrap. It stays hidden for ordinary output (the child hard-wraps at
        # self._cols; the TUI grid is sized to fit).
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setFrameStyle(0)

        self._base_point_size = BASE_POINT_SIZE
        self._zoom = 100
        self._font_family = DEFAULT_FONT_FAMILY
        self._apply_font(sync=False)

        # Render the (restored) history ONCE in the final theme: setting it before
        # apply_theme keeps the CTOR's own apply_theme idempotent, and the saved
        # scrollback below is coloured for this theme with no post-hoc re-render
        # (mirrors the mode/colours/markings ctor kwargs -- #78 render-once).
        self._theme = theme if theme in THEMES else 'light'
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
        self._markings = bool(markings)   # colour the box / badge by risk class
        # Whether the line-local cursor/erase escapes a shell's line editor emits
        # are honored (see the `line_edits` entry in 30_defaults.conf). Set from the
        # ctor before the history render, for the same render-once reason as
        # colours -- and, unlike an apply_line_edits() call after construction, in
        # time for the fork, so the child gets the matching terminfo entry.
        self._line_edits = bool(line_edits)
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
        # Rows we report to the child (winsize height). Kept so a mouse report can
        # clamp its row to the child's actual screen, symmetric with _cols -- a click
        # in the sub-row strip below the last row must not name a row past the grid.
        self._rows = 0

        # seconds the paste-warning "Allow" button stays disabled.
        self._paste_delay = 3
        self._paste_warn = 'unicode'   # always | unicode (default) | never
        self._copy_warn = 'unicode'    # always | unicode (default) | never

        # TUI mode: interpret escapes through a pyte screen so full-screen
        # programs (ssh, vim, htop, tmux) work. Off by default; the strict, no-parser
        # line mode above is the safe default.
        self._tui = bool(tui)
        if self._tui:
            # a TUI screen is fixed; no scrollback scrollbar (see apply_tui)
            self.setVerticalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        # _mode and _tui are now known: pick the per-mode wrap before any history
        # render, so restored scrollback is drawn once under the final wrap mode.
        self._sync_wrap_mode()
        self._command = command
        self._screen = None
        self._stream = None
        self._fmt_cache = {}
        # sgr-format cache for the grid, plus a codepoint-keyed cache of the
        # risk-class marking format a neutralized grid cell wears (see
        # _grid_cell_format), so the TUI grid names WHY a byte was boxed, exactly
        # as the CLI box mode does.
        self._grid_mark_cache = {}
        # TUI grid view state: the pyte history rows already rendered as permanent
        # scrollback, held BY REFERENCE (not by id()) so an evicted row's id cannot
        # be recycled for a new row and make it look already-rendered (which would
        # drop it); plus how many blocks the live grid occupies at the bottom of
        # the document. Lets each frame re-render only the grid.
        self._top_rows = []
        self._grid_rows = 0
        # Per-row incremental grid model: the row objects (by id) currently
        # rendered as the live grid's blocks, and the (text, format) runs each
        # one rendered to. A frame re-renders only the rows whose runs changed
        # and keeps every unchanged block, so a full-viewport truecolour board
        # (every cell a distinct colour, so runs never coalesce) is not rewritten
        # cell-by-cell each PTY read. The runs ARE the signature, so any theme /
        # mode / marking / colour change makes them differ and forces a correct
        # re-render -- a stale cell can never survive a format change.
        self._grid_row_ids = []
        self._grid_row_sig = []
        # Repaints each grid block's cached formats from its _GridRow on relayout
        # (a non-grid line-mode block carries none and is left as inserted).
        self._grid_hl = _GridHighlighter(self.document())
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
        self._wheel_accum = 0         # accumulated wheel delta for alt-screen scroll
        # The set of mouse DEC modes the child has enabled (1000/1002/1003 tracking,
        # 1004 focus, 1006 SGR), tracked off the output stream. When it requests
        # tracking + SGR, the mouse/wheel handlers REPORT to it (konsole/xterm
        # parity); Shift is the local override. See wheelEvent / mousePressEvent.
        self._mouse_modes = set()
        self._mouse_scan_carry = ''   # incomplete escape carried across a read split
        self._wheel_accum_x = 0       # horizontal wheel delta (vertical: _wheel_accum)
        self._mouse_report_btns = set()  # Qt buttons whose reported press awaits release
        self._mouse_report_cell = None  # last cell reported for motion (coalesce 1003)
        # True while the grid view is rendering the alternate screen ALONE (grid
        # only, no scrollback above it). Lets _render_tui clear the carried-in
        # scrollback exactly once when a full-screen program takes the alt screen,
        # so its bottom row (e.g. tmux's status bar) is not pushed below the
        # viewport and no spurious scrollbar appears.
        self._alt_view = False
        # TUI auto-follow intent: pin the view to the newest output ONLY while the user is at
        # the very bottom. A per-frame value-vs-maximum test (with a 2-line tolerance) mistook a
        # 1-2 line wheel scroll for "still at bottom" and yanked the view back every frame (the
        # reported scroll flicker). This sticky flag is cleared the instant the user scrolls up
        # and restored when they return to the bottom; _programmatic_scroll suppresses the signal
        # handler while _render_tui does its OWN follow/rebuild writes, so only genuine user
        # scrolling changes the intent.
        self._tui_follow = True
        self._programmatic_scroll = False
        self.verticalScrollBar().valueChanged.connect(self._on_scroll_value)
        # True while the user is dragging a text selection. The TUI grid is rebuilt
        # (_delete_grid + _append_grid) every ~16ms frame; doing that under an active
        # selection re-anchors it and drags it to the document bottom (the reported
        # "selects to the bottom" bug). While a selection is active the rebuild is frozen,
        # exactly as a traditional terminal holds the view still while you select.
        self._mouse_selecting = False
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
        # Characters swallowed so far in the current discard run (a long unterminated
        # string sequence). Watched against self._escape_limit to fire a one-time
        # notice; the suppression itself is never lifted.
        self._esc_dropped = 0
        self._esc_notified = False   # the suppression notice fired for this run
        # Characters an unterminated string sequence may silently suppress before a
        # one-time notice (0 = never notify). Output stays suppressed regardless.
        # Set from the escape_limit config.
        self._escape_limit = 4096
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
        # a mode change wanted to re-export TERM but the prompt held a pending
        # line, so the CR-terminated re-export would have submitted it. Held here
        # until the line is clear again. See _reexport_term / _flush_reexport.
        self._reexport_pending = False
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.timeout.connect(self._render_tui)
        # CLI line-mode paint debounce: the model (_line_cells) is fed every read
        # for correctness, but the document REBUILD (_paint_line) is coalesced to
        # ~60fps by this single-shot timer, mirroring the grid path's _render_timer.
        # Completed lines finished between paints are held here and flushed together.
        # _flush_paint() is called synchronously wherever the document must be
        # current (teardown, and any transcript/copy/save getter).
        self._paint_timer = QTimer(self)
        self._paint_timer.setSingleShot(True)
        self._paint_timer.timeout.connect(self._flush_paint)
        self._paint_pending = []          # completed cell-lines awaiting a paint
        self._paint_pending_wraps = []    # parallel autowrap flags
        self._paint_dirty = False         # a feed changed the line since last paint
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
            # cut at an escape boundary: a raw slice can start mid-sequence, and
            # the headless remainder then renders as literal escape garbage.
            self._raw = tail_from_escape_boundary(restored, self._RAW_MAX)
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
        self._sync_wrap_mode()            # preview feeds the line path directly
        self._feed_line(text)

    # -- appearance: theme + zoom ---------------------------------------------
    def apply_theme(self, theme):
        theme = theme if theme in THEMES else 'dark'
        changed = theme != getattr(self, '_theme', None)
        base, text = THEMES[theme]
        self._theme = theme
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Base, QColor(base))
        pal.setColor(QPalette.ColorRole.Text, QColor(text))
        self.setPalette(pal)
        self._fmt_cache = {}          # theme changes the resolved cell colours
        self._line_fmt_cache = {}     # and the line-mode SGR format cache
        self._grid_mark_cache = {}    # and the grid risk-class marking formats
        if self._grid_mode():         # repaint the grid ONLY while it owns the
            self._render_timer.start(16)   # screen; line-TUI keeps its scrollback
        elif changed and getattr(self, '_paint_timer', None) is not None:
            # CLI (line) view: existing markings hold the OLD theme's colours in
            # their stored QTextCharFormats -- clearing the caches does not touch a
            # format already in the document. Replay the retained output so they are
            # rebuilt in the new theme (mirrors apply_mode / apply_colors). Only on a
            # REAL change: an idempotent re-apply (the restore path sets the current
            # theme) must not re-render, or restore draws the scrollback twice (#78).
            # Guarded: apply_theme also runs in __init__ before the line model exists.
            self._rerender()

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

    def _cap_raw(self):
        """Bound the retained raw output, cutting at an escape BOUNDARY. A plain
        tail slice can land inside a sequence; the remainder then has no
        introducer, so the line renderer prints it as literal text and pyte
        mis-parses it when the grid is seeded -- the cap would itself leak an
        escape."""
        if len(self._raw) > self._RAW_MAX:
            self._raw = tail_from_escape_boundary(self._raw, self._RAW_MAX)

    def _rerender(self):
        """Re-display existing output under the current display mode. While a
        full-screen program owns the grid the pyte screen is simply repainted;
        otherwise (CLI, or TUI at a shell prompt) the retained raw output is
        replayed through the render pipeline from a clean document."""
        # A re-render follows a mode / grid change: repick the per-mode wrap first,
        # so the rebuilt document lays out under the correct wrap (Detail/Reveal wrap
        # to the width; Box/Show and the grid do not).
        self._sync_wrap_mode()
        # Drop the format caches: a re-render follows a mode / colour / marking change,
        # any of which alters how a cell is formatted (the structural-glyph contrast
        # bypass is Show-only), yet the caches are keyed by source codepoint + SGR, not
        # by that state. Stale would let a Show-mode structural bypass persist into a
        # strict mode and hide a neutralized placeholder.
        self._fmt_cache = {}
        self._grid_mark_cache = {}
        self._line_fmt_cache = {}
        # A debounced CLI paint must NOT survive the reset: its stale pending lines
        # would be replayed on top of the freshly-rebuilt document (duplicating
        # completed output), or painted over a TUI grid by the still-armed timer.
        # Drop the pending paint before any document/line-model reset, both paths.
        self._paint_timer.stop()
        self._paint_pending = []
        self._paint_pending_wraps = []
        self._paint_dirty = False
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
            self._feed_line(tail_from_escape_boundary(self._raw,
                                                      self._RERENDER_TAIL))

    def current_mode(self):
        return self._mode

    def apply_scrollback(self, lines):
        """Limit retained scrollback to `lines` blocks (0 = unlimited)."""
        lines = max(0, int(lines))
        # No change: the cap is already this value, so setMaximumBlockCount would
        # prune nothing and the grid model stays in sync -- there is nothing to
        # rebuild. This is the COMMON path: _apply_global re-applies the SAME
        # scrollback on EVERY global-settings change (theme, font, zoom, ...), and
        # the rebuild below reconstructs the TUI scrollback from pyte's bounded
        # history, so an unconditional rebuild here erased every promoted row above
        # pyte's history cap on any unrelated setting change.
        if lines == self._scrollback:
            return
        before = self.blockCount()
        self._scrollback = lines
        self.setMaximumBlockCount(lines)
        # Only a cap REDUCTION that actually prunes leading blocks desyncs the
        # incremental grid model (grid_rows / row ids / sigs / scrollback tracking)
        # from the surviving document -- a stale grid_rows would make the next
        # _delete_grid compute a wrong (or negative) start and wipe the document,
        # and _place_grid_cursor a wrong grid top. Rebuild the grid view from the
        # live pyte state ONLY then. A raise (or 0 = unlimited) prunes nothing, so
        # the model stays in sync and the document -- including promoted scrollback
        # above pyte's cap -- must be preserved untouched.
        # NB: the rebuild reconstructs scrollback from pyte's bounded history, so a
        # reduction still cannot retain document rows older than that cap.
        if (self._grid_mode() and self._screen is not None
                and self.blockCount() < before):
            self._reset_grid_view()
            self._render_tui()

    def current_scrollback(self):
        return self._scrollback

    def apply_paste_delay(self, seconds):
        self._paste_delay = max(0, int(seconds))

    def current_paste_delay(self):
        return self._paste_delay

    def apply_escape_limit(self, limit):
        # Only the notice THRESHOLD; changing it cannot alter what is on screen, so
        # no _rerender. Suppression is unaffected -- this only tunes when the
        # one-time "output suppressed" notice fires.
        self._escape_limit = max(0, int(limit))

    def current_escape_limit(self):
        return self._escape_limit

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
        self._esc_dropped = 0
        self._esc_notified = False
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

    def _line_pending(self):
        """True when the shell's line editor may hold text at the prompt. Either we
        mirrored it (_line_buffer) or we know we CANNOT mirror it (_line_dirty: a
        history recall or an in-place cursor edit). Both mean "do not type a
        CR-terminated command in here"; the dirty case is the dangerous one, since
        the recalled line is invisible to us but very much present to the shell."""
        return bool(self._line_buffer) or self._line_dirty

    def _reexport_term(self):
        """Tell the running shell to re-export TERM for the current mode, so it and
        the programs it launches advertise what the mode can render -- without a
        restart (the shell re-reads terminfo live). Sent as a plain, VISIBLE command
        so the switch is transparent: you see exactly the `export TERM=...` that
        reconfigured the shell, rather than a hidden change. Terminated with CR
        (\\r, the same byte Enter sends), NOT \\n: an interactive shell's line
        editor (zsh's zle) binds accept-line to CR, so a bare \\n leaves the command
        sitting UNSUBMITTED at the prompt.

        That CR is why a pending line DEFERS the re-export instead of racing it.
        This is typed input: with a half-typed line at the prompt the shell would
        receive `<pending>export TERM=...` and RUN it -- an Enter the user never
        pressed, submitting their unfinished text. Worse, that submission is
        generated here rather than by the Enter handler, so it never passes
        command_hook: the one control that judges what reaches the shell would be
        routed around by the terminal itself. So the line is left untouched (never
        killed -- discarding what someone typed to satisfy our own housekeeping is
        not ours to do) and the re-export waits for a clear prompt."""
        if self._line_pending():
            self._reexport_pending = True
            self._advise('Display switched now; the shell will be told once the '
                         'line you are typing is submitted or cleared.')
            return
        self._send_reexport()

    def _send_reexport(self):
        """Type the re-export into the shell. Only ever called with a clear prompt,
        so nothing of the user's concatenates with it."""
        self._reexport_pending = False
        term, _ = self._child_term()
        self._write(('export TERM=%s\r' % term).encode())

    def _flush_reexport(self):
        """Send a deferred re-export once the prompt is clear again. Driven from
        _on_readable -- output arriving is what a returning prompt looks like from
        here -- and gated on the pending flag, so a terminal with nothing deferred
        pays nothing for it. Re-checks EVERY precondition rather than trusting the
        ones that held when the switch was made: by now a program may have been
        started, in which case the re-export would be typed into that program."""
        if not self._reexport_pending:
            return
        if (self._preview or self._fd is None or self._pid is None
                or self._command is not None):
            self._reexport_pending = False      # no longer a re-exportable tab
            return
        if self._line_pending() or self.has_foreground_program():
            return                              # still not a clear prompt; keep waiting
        self._send_reexport()

    def _grid_mode(self):
        """True whenever TUI mode is on: the pyte grid owns the screen (with its
        scrollback rendered above it), so a program can position the cursor -- a
        completion menu, a progress display, a full-screen app -- and it renders
        faithfully. CLI mode stays the safe one-dimensional line display."""
        return self.tui_active()

    def _sync_wrap_mode(self):
        """Pick the line-wrap mode for the current display mode, so the widget
        behaves like a real terminal: content wraps to the width, it never scrolls
        off the right edge.

        - Box / Show: each cell is ~1 column, so NoWrap -- this keeps a glyph's
          line/column STABLE across a box<->show toggle (a pixel-width wrap made a
          wide glyph jump lines on the toggle; see the ctor). The child already
          hard-wraps at self._cols, so ordinary output does not overflow; a residual
          run of wide Show-mode glyphs is left-anchored by _paint_line's home-pin
          when that keeps the caret visible (else the caret is followed).
        - Detail / Reveal: each cell expands to a wide <U+XXXX> badge that overflows
          the width the child was told, so wrap the DISPLAY to the viewport --
          otherwise the overflow is reachable only by a horizontal scroll that hides
          the start of every row. This is a SOFT (visual) wrap: it inserts no
          document newline, so copy/transcript are unchanged.
        - TUI grid: sized to fit and its Detail/Reveal cells fall back to the box, so
          it never overflows; NoWrap.
        """
        wrap = (not self._grid_mode()
                and self._mode in ('detail', 'reveal'))
        self.setLineWrapMode(
            QPlainTextEdit.LineWrapMode.WidgetWidth if wrap
            else QPlainTextEdit.LineWrapMode.NoWrap)

    def _sync_display(self):
        """Match the on-screen view to the current mode. TUI mode shows the pyte
        grid with its scrollback; CLI mode shows the scrolling line document. The
        vertical scrollbar stays available in both (TUI now has scrollback too)."""
        grid = self._grid_mode()
        was_grid = self._grid_shown
        self._grid_shown = grid
        self._sync_wrap_mode()            # grid never wraps; CLI wraps per mode
        if grid:
            # A debounced CLI paint must not survive the switch into the grid:
            # apply_tui reaches here directly (not via _rerender), so a still-armed
            # _paint_timer would later call _flush_paint and write stale CLI content
            # into the grid document, corrupting it. Drop the pending paint first.
            self._paint_timer.stop()
            self._paint_pending = []
            self._paint_pending_wraps = []
            self._paint_dirty = False
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
        return getattr(self, '_tui', False)

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
        # Remember the size we tell the child: the width so line-mode output wraps
        # at the same column the shell formats to (see self._cols / _feed_line), and
        # the height so a mouse report clamps its row to the child's screen.
        self._cols = cols
        self._rows = rows
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
        self._stream = _Utf8CharsetByteStream(self._screen)
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
        self._top_rows = []
        self._grid_rows = 0
        self._grid_row_ids = []
        self._grid_row_sig = []
        self._tui_follow = True       # a fresh grid view follows the tail until the user scrolls

    def _on_scroll_value(self, value):
        """Update the TUI auto-follow intent from USER scrolling. _render_tui's own
        follow/rebuild writes set _programmatic_scroll so they do not clear the intent; a user
        wheel/drag/key that lands anywhere but the very bottom stops the auto-follow, and
        returning to the bottom resumes it."""
        if self._programmatic_scroll:
            return
        # Connected to the bar's OWN valueChanged, so the bar exists here.
        self._tui_follow = value >= self.verticalScrollBar().maximum()

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

    def _pyte_format(self, cell, structural=None):
        # A structural block/half-block glyph IS its own pixels: skip the fg-vs-bg
        # readability guard so its truecolor background is filled verbatim (a
        # half-block colour ramp sets fg near bg on purpose; clamping bands it). That
        # bypass is valid ONLY where the glyph is DISPLAYED as itself (Show mode). A
        # caller rendering a MARKING passes the effective (display-context) value, so a
        # structural source char NEUTRALIZED to a placeholder in a strict mode keeps the
        # guard -- else a program could set fg==bg to hide the placeholder. Default
        # (None): judge by the source glyph, for the direct non-marking render path.
        if structural is None:
            structural = len(cell.data) == 1 and is_structural(ord(cell.data))
        key = (cell.fg, cell.bg, cell.bold, cell.reverse, cell.underscore, structural)
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
        if not structural and too_close(_rgb(fg), _rgb(eff_bg)):
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
        # Freeze the rebuild while a text selection is active (being dragged, or held after
        # release): _delete_grid + _append_grid rewrites the document each frame, which
        # re-anchors an in-progress selection and drags it to the bottom (the reported bug),
        # and setTextCursor in the follow path would collapse a completed one. Output keeps
        # feeding the pyte model; clearing the selection (a click / keypress) re-arms a render
        # that catches up. This holds the view still during selection, as a real terminal does.
        if self._mouse_selecting or self.textCursor().hasSelection():
            return
        # If the user has scrolled up into the history to read it while output is
        # still arriving, do NOT yank the view back to the bottom on every frame
        # (and do not clobber a selection); only auto-follow when the user is at the
        # end. _tui_follow tracks that intent (set by _on_scroll_value on real user
        # scrolling), so a 1-2 line wheel scroll is no longer mistaken for "at bottom".
        bar = self.verticalScrollBar()
        at_bottom = self._tui_follow
        prev_scroll = bar.value() if bar is not None else 0
        # Everything below is OUR write: guard it so the scrollbar changes the rebuild and the
        # follow cause do not fire _on_scroll_value and clobber the user's follow intent.
        self._programmatic_scroll = True
        try:
            self._render_tui_body(screen, bar, at_bottom, prev_scroll)
        finally:
            self._programmatic_scroll = False
        self.viewport().update()

    def _render_tui_body(self, screen, bar, at_bottom, prev_scroll):
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
            # A fixed canvas never scrolls to history, so there is nothing to
            # promote: reconcile the whole grid in place, re-rendering only the
            # rows whose runs changed (htop / a full-screen colour app repaints a
            # small region, not every cell).
            columns = screen.columns
            target = [screen.buffer[y] for y in range(screen.lines)]
            tsig = [self._grid_row_runs(r, columns) for r in target]
            self._reconcile_grid_tail(target, tsig, columns)
        else:
            # Left the alternate screen: rebuild the scrolling view from a clean
            # document so the restored primary scrollback is shown once.
            if self._alt_view:
                self._reset_grid_view()
                self._alt_view = False
            self._render_primary_grid(screen)
        self.setUpdatesEnabled(True)
        if self._alt_screen:
            # The alternate screen is a fixed canvas with NO scrollback: its row 0 is the
            # TOP of the program's screen and must always be visible, exactly as a real
            # terminal shows it (a real terminal never scrolls the alt screen). Any
            # off-by-one between the pyte grid and the viewport height leaves a 1-row
            # scroll range, and following the TAIL there scrolls row 0 off the top -- so a
            # SHORT full-screen frame (a one-line status program, or the alt-screen demo
            # shot whose payload draws a single line at row 0) renders as an empty
            # viewport even though the document holds the content. Pin to the top instead.
            self._place_grid_cursor(screen)
            if bar is not None:
                bar.setValue(bar.minimum())
        elif at_bottom:
            self._place_grid_cursor(screen)
            if bar is not None:
                # Follow the tail: setTextCursor alone does not reliably scroll the
                # viewport (the CLI path adds an explicit ensureCursorVisible for the
                # same reason), so pin the view to the newest line when at the bottom.
                bar.setValue(bar.maximum())
        elif bar is not None:
            bar.setValue(min(prev_scroll, bar.maximum()))

    def _grid_cell_format(self, cell, disp):
        """Format for one grid cell. A cell that is NOT a marking takes the
        program's own SGR (_pyte_format). A MARKING -- a cell neutralized to the box
        placeholder (box / detail / reveal, or an invisible/bidi/control in show
        mode), OR a non-ASCII glyph SHOWN as itself in show mode (a line-drawing
        border, a homoglyph, foreign text) -- ALWAYS carries its source code point
        (_CP_PROP), so hover/click names the real character in EVERY mode and
        whether or not markings are on, at parity with the CLI line renderer
        (cells_to_runs tags the code point even with markings off). Before, hover on
        a neutralized cell reported the box glyph itself (U+25A1).

        When markings are ON the cell is also coloured by risk class
        (MARKING_COLORS, keyed by code point since the colour follows the class);
        when OFF it keeps the program's SGR (keyed by code point + the SGR attrs, so
        two cells sharing a code point but not a colour do not collide). The cache
        is admission-capped (_cache_bounded), and cleared wherever _fmt_cache is.

        The one exception is a SHOW-mode box-drawing / block-element glyph
        (is_structural): it is shown as its real glyph in the program's OWN SGR, never
        a risk tint, because a line or a bar cannot pose as ASCII, hide, or reorder --
        it is honest structure, not a deception. It is still tagged with its code
        point so hover/click can name it. Strict modes keep risk-colouring it."""
        cp = marking_cp_for_cell(cell.data)
        if cp is None or not (disp == BOX or self._mode == 'show'):
            return self._pyte_format(cell)
        # box-drawing / block elements shown as their real glyph in SHOW mode are
        # purely structural, not a deception: they wear the program's OWN SGR like a
        # real terminal, never a risk-class tint -- yet still carry their source code
        # point so hover/click can name them. Strict modes (box/detail/reveal) keep
        # neutralizing and risk-colouring them, so the ASCII-only guarantee is intact.
        structural = self._mode == 'show' and is_structural(cp)
        risk = self._markings and not structural
        if risk:
            key = cp                          # colour depends only on the risk class
        else:
            key = (cp, cell.fg, cell.bg, cell.bold, cell.reverse, cell.underscore)
        fmt = self._grid_mark_cache.get(key)
        if fmt is None:
            if risk:
                fmt = QTextCharFormat()
                spec = self.MARKING_COLORS[self._theme][marking_class(cp)]
                fmt.setForeground(QColor(spec['fg']))
                if spec['bg'] is not None:
                    fmt.setBackground(QColor(spec['bg']))
            else:
                # Pass the EFFECTIVE structural (Show-only): a strict-mode placeholder is
                # not displayed as its glyph, so it must keep the contrast guard.
                fmt = QTextCharFormat(self._pyte_format(cell, structural))   # program SGR
            fmt.setProperty(_CP_PROP, cp)
            return _cache_bounded(self._grid_mark_cache, key, fmt)
        return fmt

    def _grid_row_runs(self, row, columns):
        """The (text, format) runs one pyte row renders to, same-format cells
        coalesced. This IS both the row's render and its incremental signature:
        two rows with equal runs render to an identical block, so a block whose
        stored runs equal the freshly computed runs is reused as-is. Format
        objects are cached and shared, so an unchanged row's runs hold the SAME
        format objects and compare equal by identity (fast); a theme / mode /
        marking / colour change rebuilds the cached formats, so the runs differ
        and the row is correctly re-rendered."""
        runs = []
        run_text = ''
        run_fmt = None
        for x in range(columns):
            cell = row[x]
            ch = tui_cell(cell.data, self._mode)
            fmt = self._grid_cell_format(cell, ch)
            if run_text and fmt is run_fmt:
                run_text += ch
            else:
                if run_text:
                    runs.append((run_text, run_fmt))
                run_text, run_fmt = ch, fmt
        if run_text:
            runs.append((run_text, run_fmt))
        return runs

    def _insert_grid_row(self, cursor, row, columns):
        """Insert one pyte row at the cursor as PLAIN text, recording its format
        runs on the block for the grid highlighter to paint. This is far cheaper
        than a per-cell cursor.insertText(text, fmt) on a distinct-colour board,
        and keeps each region's SOURCE code point (which layout formats do not
        expose via charFormat) for hover / copy / transcript. Offsets are UTF-16
        code units, to match Qt document positions and QSyntaxHighlighter.setFormat."""
        block_pos = cursor.position()
        runs = []
        parts = []
        offset = 0
        for text, fmt in self._grid_row_runs(row, columns):
            length = len(text) + sum(ord(ch) > 0xFFFF for ch in text)   # UTF-16 units
            cp = fmt.property(_CP_PROP)
            runs.append((offset, length, fmt, None if cp is None else int(cp)))
            parts.append(text)
            offset += length
        cursor.insertText(''.join(parts))
        block = self.document().findBlock(block_pos)
        block.setUserData(_GridRow(runs))
        self._grid_hl.rehighlightBlock(block)

    def _delete_grid(self, keep=0):
        """Remove the live grid down to its first `keep` blocks (default: all of
        it), plus the newline that joins the removed span to what precedes it, so
        the document ends at the kept block (or the scrollback) with no trailing
        empty block."""
        n = self._grid_rows - keep
        if n <= 0:
            return
        doc = self.document()
        first = doc.blockCount() - n
        cur = QTextCursor(doc.findBlockByNumber(max(0, first)))
        cur.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        if first > 0:                     # also eat the newline before the span:
            # move the WHOLE cursor (anchor too) back over it, so the End
            # selection below starts before the newline. With KeepAnchor the
            # anchor stayed at the block start and the newline was never
            # selected, leaving the preceding row with a trailing newline --
            # a spurious empty block that double-spaced every scrolled row.
            cur.movePosition(QTextCursor.MoveOperation.PreviousCharacter)
        cur.movePosition(QTextCursor.MoveOperation.End,
                         QTextCursor.MoveMode.KeepAnchor)
        cur.removeSelectedText()
        self._grid_rows = keep

    def _render_primary_grid(self, screen):
        """Incrementally reconcile the scrolling (primary-screen) grid.

        Two properties keep this linear in output, not quadratic per PTY read:
        a row that has scrolled off the top of the live grid into pyte's history
        is IDENTICAL (same object) to the block already rendered for it, so its
        block is kept and reclassified as permanent scrollback (promotion)
        instead of deleted and re-appended; and the still-live grid rows are
        reconciled by a positional signature diff, so only the changed tail is
        re-rendered. A distinct-truecolour board therefore renders each row about
        once as it is drawn, not once per read."""
        columns = screen.columns
        # Trim trailing blank rows BELOW the cursor so the document ends at the
        # prompt/last output; without this the full grid pads ~screen.lines empty
        # rows below it and you can scroll down into empty space (Bug #64). A row
        # counts as blank only if it RENDERS as empty: test tui_cell, not
        # cell.data.strip() -- str.strip() drops U+00A0 / tab / ideographic space,
        # which tui_cell marks as a visible placeholder, so a lone marked space
        # below the cursor must keep its row rather than be trimmed away and hidden.
        last = screen.cursor.y
        for y in range(screen.lines):
            if any(tui_cell(cell.data, self._mode) != ' '
                   for cell in screen.buffer[y].values()):
                last = y
        last = max(last, screen.cursor.y)
        target = [screen.buffer[y] for y in range(last + 1)]
        tsig = [self._grid_row_runs(r, columns) for r in target]

        hist = list(screen.history.top)
        new_hist = self._new_history_rows(hist)
        # Promote the leading grid rows that have scrolled into history: their
        # blocks are already in the document, in order, so keep them as permanent
        # scrollback rather than re-render. Verify BOTH identity and that the
        # row's rendered runs still match what we stored -- a row mutated between
        # its last render and the scroll (all within one un-rendered read) is
        # then NOT promoted, so it can never be kept stale.
        promote = 0
        while (promote < len(self._grid_row_ids)
               and promote < len(new_hist)
               and self._grid_row_ids[promote] == id(new_hist[promote])
               and self._grid_row_runs(new_hist[promote], columns)
                   == self._grid_row_sig[promote]):
            promote += 1
        if promote != len(new_hist):
            # A scrolled-off row is not a promotable leading grid block -- a
            # screen clear, a cursor-addressed rewrite, or the first render of a
            # seeded view. Fall back to the correct full rebuild.
            self._delete_grid()
            self._append_scrollback(screen)
            self._append_grid(screen, last_row=last)
            self._set_grid_model(target, tsig)
            return
        self._grid_rows -= promote
        # The promoted rows are now permanent scrollback. Hold the current history
        # top by reference (which contains them), as _append_scrollback does, so an
        # evicted row's id cannot be recycled and its objects do not leak.
        self._top_rows = list(hist)
        self._reconcile_grid_tail(target, tsig, columns,
                                  self._grid_row_sig[promote:])

    def _reconcile_grid_tail(self, target, tsig, columns, cur_sig=None):
        """Bring the live grid to `target` by keeping the longest unchanged
        leading run of blocks and re-rendering only the divergent tail. `cur_sig`
        is the signatures of the blocks currently in the grid region (defaults to
        the whole recorded grid; the primary path passes the post-promotion
        slice)."""
        if cur_sig is None:
            cur_sig = self._grid_row_sig
        d = 0
        while d < len(cur_sig) and d < len(tsig) and cur_sig[d] == tsig[d]:
            d += 1
        self._delete_grid(keep=d)
        self._append_grid_rows(target[d:], columns)
        self._set_grid_model(target, tsig)

    def _append_grid_rows(self, rows, columns):
        """Append `rows` as new grid blocks at the end of the document."""
        if not rows:
            return
        cur = self.textCursor()
        cur.movePosition(QTextCursor.MoveOperation.End)
        have = self.document().characterCount() > 1
        for row in rows:
            if have:
                cur.insertText('\n')
            self._insert_grid_row(cur, row, columns)
            have = True
        # Actual block count, not the row count: a scrollback cap smaller than the
        # grid makes Qt prune blocks as they are inserted, and an over-counted
        # _grid_rows would make the next _delete_grid compute a negative start.
        self._grid_rows = min(self._grid_rows + len(rows),
                              self.document().blockCount())

    def _set_grid_model(self, target, tsig):
        """Record which rows now occupy the grid blocks. If the scrollback cap
        pruned the oldest grid blocks (a scrollback smaller than one screen),
        only the trailing _grid_rows survive, so keep the model's tail in step."""
        ids = [id(r) for r in target]
        n = self._grid_rows
        if n < len(target):
            ids = ids[len(ids) - n:]
            tsig = tsig[len(tsig) - n:]
        self._grid_row_ids = ids
        self._grid_row_sig = tsig

    def _new_history_rows(self, current):
        """The history-top rows not yet rendered as scrollback, by IDENTITY.
        `_top_rows` holds references to the already-rendered set, so those objects
        stay alive and their id() cannot be recycled for a NEW row -- an id()-only
        set would risk dropping a new row whose id was reused after pyte evicted an
        old one (two LIVE objects always have distinct ids, so comparing a live
        `current` row's id against the held set is exact)."""
        seen = {id(r) for r in self._top_rows}
        return [r for r in current if id(r) not in seen]

    def _append_scrollback(self, screen):
        """Append the newly scrolled-off history rows (identified by object, so
        only the new tail is rendered) at the end of the document."""
        current = list(screen.history.top)
        new_rows = self._new_history_rows(current)
        if new_rows:
            cur = self.textCursor()
            cur.movePosition(QTextCursor.MoveOperation.End)
            have = self.document().characterCount() > 1
            for row in new_rows:
                if have:
                    cur.insertText('\n')
                self._insert_grid_row(cur, row, screen.columns)
                have = True
        self._top_rows = list(current)

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

    # -- line-local editing escapes ------------------------------------------
    def apply_line_edits(self, enabled):
        """Honour (or drop) the four line-local editing escapes. See the
        `line_edits` entry in `30_defaults.conf` for what they are for.

        The RENDERER change alone is not the whole setting: the child shell must
        also stop EMITTING redraws the renderer would now drop on the floor, or a
        completion reprints mangled instead of degrading to a plain append. So the
        matching terminfo entry is re-advertised to the running shell, exactly as a
        CLI/TUI switch does -- same reachability guard: only a login-shell CLI tab
        sitting at its prompt can be re-exported into, since the `export TERM=...`
        is typed input and any other target would receive it as data."""
        if bool(enabled) == self._line_edits:
            return
        self._line_edits = bool(enabled)
        self._rerender()      # replay the retained output under the new rule
        if self._preview or self._tui or self._pid is None or self._command is not None:
            return
        if self.has_foreground_program():
            self._advise('Line editing changed for the display only: a program is '
                         'running and owns the terminal, so the shell was not told '
                         'about it. Toggle it again at a shell prompt (or open a '
                         'new tab) to update the shell too.')
            return
        self._reexport_term()

    def line_edits_enabled(self):
        return self._line_edits

    def _effective_colors(self):
        return self._colors and colors_allowed()

    # -- coloured risk markings (the box / <U+XXXX> badge, by risk class) -------
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

    def _format_for(self, state, structural=False):
        """Build the QTextCharFormat for an SGR state dict, guarding against an
        unreadable foreground/background combination.

        A STRUCTURAL block/half-block glyph (U+2500-U+259F) IS its own pixels --
        there is no hidden text behind it to protect, so the fg-vs-bg readability
        guard must NOT run for it: a half-block colour ramp deliberately sets a
        cell's fg (its top pixel) and bg (its bottom pixel) near-equal, and clamping
        them would drop the truecolor background and band the gradient. For a
        structural glyph, fill both colours verbatim."""
        fmt = QTextCharFormat()
        fg_i, bg_i, bold = state['fg'], state['bg'], state['bold']
        if fg_i is None and bg_i is None and not bold:
            return fmt
        base_bg, base_fg = THEMES.get(self._theme, THEMES['dark'])
        fg = self._sgr_qcolor(fg_i, base_fg)
        bg = self._sgr_qcolor(bg_i, None)
        if not structural:
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

    # Colours of a neutralized/revealed marking, by THEME then risk class: a
    # foreground tint plus an optional background BAND (bg None = no band). BOTH
    # themes give the genuinely-dangerous classes (bidi/control/invisible/
    # confusable/combining) a band, because a foreground-only tint was optically
    # swallowed by the base and vanished. Honest foreign text ('nonascii') stays a
    # subtle fg-only tint in both, so it is not mistaken for an attack. Light is the
    # shipped default, so its bands are the primary case (dark bands kept for users
    # who switch).
    MARKING_COLORS = {
        'light': {
            'bidi':       {'fg': '#b3261e', 'bg': '#ffb3ab'},   # red    -- reorders text (worst)
            'control':    {'fg': '#0842a0', 'bg': '#aecbff'},   # blue   -- C0 / DEL / C1 controls
            'invisible':  {'fg': '#8a5000', 'bg': '#ffcf8f'},   # amber  -- zero-width / BOM / separators
            'confusable': {'fg': '#a4113f', 'bg': '#ffb3ca'},   # rose   -- a homoglyph posing as ASCII
            'combining':  {'fg': '#5b21b6', 'bg': '#cdb0ff'},   # violet -- a stacked combining mark (Zalgo)
            'nonascii':   {'fg': '#6d28d9', 'bg': None},        # purple -- honest foreign: subtle, no band
        },
        'dark': {
            'bidi':       {'fg': '#ff5a60', 'bg': '#5c1820'},   # red    -- reorders text (worst)
            'control':    {'fg': '#5cb0ff', 'bg': '#143a5c'},   # blue   -- C0 / DEL / C1 controls
            'invisible':  {'fg': '#ffb340', 'bg': '#4d3a0e'},   # amber  -- zero-width / BOM / separators
            'confusable': {'fg': '#ff6f9d', 'bg': '#551d35'},   # rose   -- a homoglyph posing as ASCII
            'combining':  {'fg': '#c9a3ff', 'bg': '#46306b'},   # violet -- a stacked combining mark (Zalgo)
            'nonascii':   {'fg': '#a06cff', 'bg': None},        # purple -- honest foreign: subtle, no band
        },
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
                    spec = self.MARKING_COLORS[self._theme][color]
                    fmt.setForeground(QColor(spec['fg']))
                    if spec['bg'] is not None:
                        fmt.setBackground(QColor(spec['bg']))
                elif color:                   # the program's own SGR items-tuple
                    # a structural block/half-block glyph SHOWN in its own SGR keeps its
                    # truecolor bg -- the contrast guard must not band the gradient. Gate
                    # on Show: in a strict mode the same source glyph is a neutralized
                    # placeholder that MUST keep the guard (else fg==bg hides it).
                    fmt = self._format_for(
                        dict(color),
                        structural=(self._mode == 'show' and is_structural(key[2])))
                else:
                    fmt = QTextCharFormat()
                fmt.setProperty(_CP_PROP, key[2])
                return _cache_bounded(self._line_fmt_cache, key, fmt)
            return fmt
        fmt = self._line_fmt_cache.get(key)
        if fmt is None:
            fmt = self._format_for(dict(key))
            return _cache_bounded(self._line_fmt_cache, key, fmt)
        return fmt

    # -- mouse reporting (konsole/xterm parity) -------------------------------
    # A child that enables mouse tracking (1000/1002/1003) + SGR encoding (1006) has
    # its mouse and wheel events REPORTED to it, at the cell under the pointer, so a
    # mouse-aware UI (Claude Code, vim, htop, tmux) behaves as in konsole. Shift is
    # the LOCAL override throughout: Shift+wheel scrolls this terminal's scrollback,
    # Shift+click/drag selects text, Shift+middle pastes -- none of those are
    # forwarded. Only genuine user events are ever reported; there is no path from
    # program output to a report except the modes it explicitly set.
    _SGR_BUTTON = {
        Qt.MouseButton.LeftButton: 0,
        Qt.MouseButton.MiddleButton: 1,
        Qt.MouseButton.RightButton: 2,
    }

    # Cancel a line of UNKNOWN content (recalled from history / cursor-edited, so
    # neither its text nor the cursor column is mirrored). Ctrl+C (SIGINT), NOT a
    # kill-line key sequence: any End/Ctrl+E/Ctrl+U combination depends on the
    # shell's keymap and SILENTLY LEAVES the command in some of them (bash vi-insert
    # needed End-then-U; zsh vi-insert has ESC[F unbound; xterm's End is ESC O F).
    # The hook only fires at a bare prompt (no foreground child -- enforced by the
    # has_foreground_program() guard at every _hook_intercept call site), so SIGINT
    # there cancels the line editor and gives a fresh prompt in EVERY shell and
    # editing mode. It is best-effort: a user who ran `stty intr undef` disarms it,
    # so the caller marks _line_dirty afterward to FAIL SAFE (re-ask, never submit
    # a line the cancel may have left behind). A line whose content IS mirrored is
    # cleared deterministically by _clear_typed_line instead (no signal, no tcflush).
    _CANCEL_UNKNOWN_LINE = b'\x03'

    def _clear_typed_line(self, command):
        """Erase a line whose exact content is mirrored (cursor at end, not dirty)
        with one Backspace per character. Unlike SIGINT this sends no signal (so it
        never kills a foreground program) and triggers no tcflush TCIFLUSH (so a
        suggestion written immediately after is not swallowed), and unlike a
        kill-line key it needs no shell keymap. len() counts the logical characters
        readline/zle delete one-per-Backspace. The caller only reaches here with a
        non-empty command (the empty line returns earlier)."""
        self._write(b'\x7f' * len(command))

    def _mouse_report_on(self):
        """True when the child has enabled mouse tracking WITH SGR encoding, so its
        mouse/wheel events are reported. Shift (the local override) is checked per
        handler, not here."""
        return (bool(self._mouse_modes & _MOUSE_BUTTON_MODES)
                and _MOUSE_SGR_MODE in self._mouse_modes)

    def _event_cell(self, event):
        """1-based (col, row) of the terminal cell under a mouse/wheel event, for an
        SGR report -- the on-screen cell coordinate a real terminal sends. Clamped to
        the grid so a report never names a cell off the left/top edge or past the
        column count."""
        metrics = self.fontMetrics()
        char_w = metrics.horizontalAdvance('M') or 1
        char_h = metrics.height() or 1
        off = self.contentOffset()
        margin = self.document().documentMargin()
        pos = event.position()
        col = int((pos.x() - margin - off.x()) // char_w) + 1
        row = int((pos.y() - margin - off.y()) // char_h) + 1
        cols = self._cols if self._cols and self._cols > 0 else self._MAX_LINE
        rows = self._rows if self._rows and self._rows > 0 else self._MAX_LINE
        col = min(col, cols) if col > 1 else 1
        row = min(row, rows) if row > 1 else 1
        return col, row

    def _button_code(self, base, mods, motion=False):
        """The SGR button byte: `base` (0/1/2 button, 3 none, 64+ wheel) plus the
        motion flag (+32) and the Ctrl (+16) / Alt (+8) modifier bits. Shift is NEVER
        encoded -- it is the local-selection override and never reaches a report."""
        if motion:
            base += 32
        if mods & Qt.KeyboardModifier.ControlModifier:
            base += 16
        if mods & Qt.KeyboardModifier.AltModifier:
            base += 8
        return base

    def _report_mouse(self, base, event, pressed, motion=False):
        col, row = self._event_cell(event)
        code = self._button_code(base, event.modifiers(), motion)
        self._write(sgr_mouse_report(code, col, row, pressed).encode('ascii'))

    def _mouse_reporting(self):
        """True when a press/motion/wheel must be REPORTED to the child: tracking +
        SGR are on AND no paste/copy review is up. Input to the child is suspended
        during a review (as keyPressEvent refuses keys), so the report paths -- which
        also TRACK the pressed button -- must not fire, or a press reported (or a
        button tracked) mid-review leaves the child an unmatched event."""
        return self._mouse_report_on() and not self._review_active

    def wheelEvent(self, event):
        mods = event.modifiers()
        if mods & Qt.KeyboardModifier.ControlModifier:
            delta = event.angleDelta().y()
            if delta:
                self.zoom_step.emit(1 if delta > 0 else -1)
            event.accept()
            return
        # Shift+wheel is the LOCAL override: it scrolls this terminal's own Qt
        # document instead of reporting to / scrolling the child, and so must precede
        # the reporting/application branches below. In CLI/normal mode that is the
        # scrollback. In the alt screen the document holds only the pinned grid
        # (primary scrollback behind a full-screen app is not yet exposed -- a konsole-
        # parity follow-up), so there it is a no-op rather than reaching history.
        if mods & Qt.KeyboardModifier.ShiftModifier:
            super().wheelEvent(event)
            return
        # ACCUMULATE the delta and act only past a notch (~120 units), carrying the
        # remainder -- a high-resolution trackpad streams many tiny deltas, so acting
        # on EACH would fire per micro-event (uncontrollable hyperscroll).
        self._wheel_accum += event.angleDelta().y()
        self._wheel_accum_x += event.angleDelta().x()
        if self._mouse_reporting():
            # Report the wheel as a real SGR wheel event at the cell under the pointer
            # (konsole/xterm): 64 up / 65 down, 66 left / 67 right. One event per notch
            # so the program scrolls line-by-line at its own granularity.
            for accum_attr, pos_btn, neg_btn in (
                    ('_wheel_accum', 64, 65), ('_wheel_accum_x', 67, 66)):
                accum = getattr(self, accum_attr)
                events = int(accum / 120)
                if events:
                    setattr(self, accum_attr, accum - events * 120)
                    base = pos_btn if events > 0 else neg_btn
                    for _ in range(min(abs(events), 8)):   # cap a single huge jump
                        self._report_mouse(base, event, pressed=True)
            event.accept()
            return
        # A full-screen program that did NOT request the mouse (a plain pager in the
        # alt screen): translate the wheel to arrow-key line scrolls, like xterm's
        # alternateScroll -- the surrogate it understands. ~3 lines per notch.
        if self._alt_screen:
            lines = int(self._wheel_accum / 40)
            if lines:
                self._wheel_accum -= lines * 40
                # input suspended during a paste/copy review (as in _report_mouse):
                # drain the accumulator but do not write the arrow surrogate.
                if not self._review_active:
                    seq = b'\x1b[A' if lines > 0 else b'\x1b[B'
                    self._write(seq * min(abs(lines), 8))    # cap a single huge jump
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
        - CLI mode with line_edits off -> `secure-terminal-noedit`, which also
          cancels el/el1/cuf/cuf1/cub/hpa. Those four ops are STRIPPED in that
          setting, so advertising them would have the shell emit redraws we drop on
          the floor. cub1 (\b) stays advertised: it is a raw control byte, honoured
          either way.
        - TUI mode -> xterm-256color, so full-screen programs (and ssh) work.

        The terminfo DIR is returned in BOTH modes (so TERMINFO_DIRS always resolves
        both entries), which lets a mode switch re-export TERM into the running shell
        without a restart (see apply_tui). An installed system also ships the entry
        in the system terminfo db (/usr/share/terminfo), so it resolves without
        TERMINFO_DIRS; this dir covers a source checkout. Safety never rests on TERM
        -- line mode strips every escape regardless."""
        tdir = cli_terminfo_dir()
        if not self._tui and tdir:
            if self._line_edits:
                return 'secure-terminal', tdir
            return 'secure-terminal-noedit', tdir
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
        self._read_and_render()
        # Refresh the live transcript file after output settles (debounced). No-op unless
        # SECURE_TERMINAL_TRANSCRIPT_FILE is configured.
        if self._transcript_file:
            self._transcript_timer.start()

    def _read_and_render(self):
        fd = self._fd
        if fd is None:
            # teardown race: the fd was closed before a queued notifier event
            # drained; os.read(None) would TypeError (uncaught below).
            return
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            return                        # nothing ready yet (non-blocking fd)
        except OSError:
            # After the child exits, reading a pty master raises EIO on Linux
            # rather than returning b''. Treat any read error as end-of-file, or a
            # level-triggered notifier on the errored fd spins a core forever.
            data = b''
        if not data:
            # The child exited. feed_chunk_carry may be holding a trailing run in
            # _esc_carry that MIGHT have been an incomplete escape awaiting more bytes
            # (CLI mode). No bytes are coming now, so flush it as the program's final
            # output rather than drop it silently: the line renderer strips a genuine
            # dangling control intro and shows the rest (e.g. 'ESC' + text -> the
            # text). An over-cap discard (_esc_drop) is intentionally-stripped and not
            # recovered. Empty in TUI mode, so this is a no-op there.
            if self._esc_carry:
                tail, self._esc_carry = self._esc_carry, ''
                self._raw += tail
                self._cap_raw()
                self._feed_line(tail, defer=False)
            if self._notifier is not None:
                self._notifier.setEnabled(False)
            self.shell_exited.emit()
            return
        # output arriving is how a returning prompt looks from here, so it is the
        # cue to retry a re-export deferred by a pending line. No-ops (one flag
        # test) unless a mode switch is actually waiting.
        self._flush_reexport()
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
        # Carry the tail of the JOINED probe, not of this chunk: a marker split
        # across three or more reads otherwise loses its introducer. Reads
        # "\x1b[?1", "04", "9h" leave carry "\x1b[?1", then carry "04" -- the ESC
        # dropped -- so the final probe "049h" matches nothing and the alt screen
        # goes unnoticed. (The TUI feed carry, _alt_partial_tail, already slices
        # the joined buffer; the two must not disagree.)
        self._alt_scan_carry = alt_probe[-(_ALT_MARKER_MAX - 1):]
        entered = wants_full_screen(alt_probe)
        left = leaves_full_screen(alt_probe)
        if entered or left:
            last_enter = max((alt_probe.rfind(s) for s in _ALT_ENTER), default=-1)
            last_leave = max((alt_probe.rfind(s) for s in _ALT_LEAVE), default=-1)
            self._alt_screen = last_enter > last_leave
            # Drop any stale wheel-scroll remainder at an alt-screen transition:
            # a leftover sub-line delta must not carry into the next full-screen
            # session, where the first small wheel event could cross the per-line
            # threshold and emit a spurious arrow key.
            self._wheel_accum = 0
            if not self._alt_screen:
                self._tui_hint_shown = False   # a later full-screen app re-advises

        # Track the child's mouse-reporting request (button/motion tracking + SGR
        # encoding), carrying an escape split across this read boundary so a divided
        # DECSET is not missed. Mode-agnostic: a full-screen program requests the
        # mouse whether or not this terminal is showing its frame. Only the wheel is
        # ever acted on (wheelEvent), never clicks/motion.
        mouse_body = self._mouse_scan_carry + text
        mouse_body, self._mouse_scan_carry = split_trailing_escape(mouse_body)
        self._mouse_modes = scan_mouse_modes(mouse_body, self._mouse_modes)
        # Any-event tracking (1003) needs button-less pointer motion, which Qt only
        # delivers when the widget has mouse tracking on. Enable it exactly while the
        # child asks, so no motion is watched otherwise.
        self.setMouseTracking(_MOUSE_MOTION_MODE in self._mouse_modes)

        # Synchronized output (DECSET 2026): resolve the LAST marker, carrying the
        # tail so a marker split across reads is still seen. Apply BEGIN now (drop a
        # pending partial paint, take the hold); defer END until AFTER pyte is fed
        # the closing chunk, so _end_sync_update paints the COMPLETED frame.
        probe = self._sync_scan_carry + text
        # Same as the alt-screen carry above: slice the joined probe, so a marker
        # spanning three or more reads keeps its introducer.
        self._sync_scan_carry = probe[-(len(_SYNC_BEGIN) - 1):]
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
        if self.tui_active():
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
            self._cap_raw()
            # hold the paint during a synchronized update (the model keeps updating);
            # _end_sync_update renders the completed frame.
            if not self._sync_update and not self._render_timer.isActive():
                if self._shot:
                    self._render_tui()           # shot mode: render NOW (byte-stable capture)
                else:
                    self._render_timer.start(16)     # coalesce bursts into ~60fps
            return

        # CLI line mode: display through the escape-stripping pipeline. Prepend any
        # escape tail held back from the previous chunk and hold back a new
        # incomplete tail, so a sequence split across reads (a long OSC title is the
        # usual victim) is never leaked as literal text. An over-long string
        # sequence (a Sixel image is the worst case) switches to a discard state so
        # it is stripped whatever its length, without buffering it unbounded.
        drop_before = self._esc_drop
        text, self._esc_carry, self._esc_drop, self._esc_dropped = feed_chunk_carry(
            text, self._esc_carry, self._esc_drop, self._esc_dropped)
        # A long unterminated string sequence keeps suppressing output (nothing is
        # rendered, so no escape byte leaks). That is safe but LOOKS like a freeze,
        # so once the suppressed run passes the configured threshold, fire a one-time
        # notice (the window de-dups per tab). Re-arm when the run ends.
        if not self._esc_drop:
            self._esc_notified = False
        elif (self._escape_limit and not self._esc_notified
              and self._esc_dropped >= self._escape_limit):
            self._esc_notified = True
            self.escape_suppressed.emit()
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
        self._cap_raw()                     # drop the oldest output
        self._feed_line(text, defer=True)   # coalesce the paint to ~60fps
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
        # With line editing OFF the child runs under `secure-terminal-noedit`,
        # which cancels el/el1 on top of the base entry's cup/cuu/smcup -- so
        # every escape-based detector above is structurally dead: a curses program
        # emits no alternate screen, no cursor motion and no EL burst, and the
        # advisory would never fire at all. Fall back to a terminfo-independent
        # signal: the pty in raw mode with a program (not the shell's own line
        # editor) in the foreground means that program is driving the screen
        # itself. Used only in that setting, so an ordinary readline REPL in the
        # normal CLI mode -- which line editing renders fine -- is not nagged.
        elif (not self._tui_hint_shown and not self._line_edits
                and self.has_foreground_program() and self._child_raw_mode()):
            self._tui_hint_shown = True
            self._advise('This program has taken over the keyboard and is drawing '
                         'its own screen. With line editing off the safe CLI mode '
                         'shows almost nothing it draws. Turn on TUI mode to see '
                         'it.')
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
        if not chunk or self._stream is None:
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
            if code in (0, 2) and self._osc['osc_title']:
                # Read the title out of the bytes arriving NOW, never out of
                # pyte's screen.title: pyte LATCHES the last title it ever saw, so
                # a title set while osc_title was off would be adopted by the next
                # unrelated OSC once the user enables it, and re-seeding the grid
                # on a CLI->TUI switch replays every historical title out of the
                # retained scrollback -- both adopt a title from output the tab was
                # not showing titles for.
                title = sanitize_title(params.decode('utf-8', 'replace'))
                if title and title != self._last_title:
                    self._last_title = title
                    self.title_changed.emit(title)
            elif code == 9 and self._osc['osc_notify']:
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
        self._grid_mark_cache.clear()   # markings-off grid formats clone _pyte_format

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
        # binascii.Error subclasses ValueError, so ValueError alone covers a bad
        # payload. Reaching through base64.binascii relied on a private re-export
        # (base64 imports binascii for its own use and does not export it), which
        # would raise AttributeError -- inside the handler -- if that ever changed.
        except ValueError:
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
        self._flush_paint()                # paint the last CLI line before we go
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
        self._cap_raw()
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

    def _feed_line(self, text, defer=False):
        """The single line-mode output path: advance the logical cell buffer by
        this raw chunk (feed_line_edits honors \\r, \\b and the line-local CSI
        cursor/erase ops, strips every other escape) and repaint the current line.
        Replaces the old strip-then-QTextCursor path; the cell model is what lets
        a reveal badge edit as one character.

        The model is ALWAYS advanced synchronously (feed_line_edits must see every
        byte). The document REBUILD is painted now by default; the live streaming
        read path passes defer=True to coalesce the rebuild to ~60fps via the paint
        timer (mirroring the grid path). A deferred paint is flushed synchronously
        wherever the document must be current (teardown, transcript, copy, save)."""
        # Hard-wrap at the reported terminal width (never below a sane floor, and
        # capped so a pathological newline-free flood still bounds each block).
        if self._shot:
            defer = False        # shot mode: paint NOW so the capture is byte-stable
        wrap = self._cols if 8 <= self._cols <= self._MAX_LINE else self._MAX_LINE
        completed, self._line_cells, self._line_col, self._sgr, wraps = \
            feed_line_edits(self._line_cells, self._line_col, self._sgr, text,
                            wrap, self._line_edits)
        self._paint_pending.extend(completed)
        self._paint_pending_wraps.extend(wraps)
        self._paint_dirty = True          # the current line changed too, not just
        if not defer:                     # any completed lines above
            self._flush_paint()
        elif not self._paint_timer.isActive():
            self._paint_timer.start(16)

    def _flush_paint(self):
        """Paint any debounced line output now: the scrollback lines finished since
        the last paint plus the current editable line, then clear the pending
        buffers. Idempotent -- a no-op flush still repaints the current line, which
        is harmless. Called on the 16ms timer, and synchronously wherever the
        document must be current (teardown, transcript, copy, save)."""
        if not self._paint_dirty:
            return                        # nothing fed since last paint -> no-op
        self._paint_timer.stop()
        completed = self._paint_pending
        wraps = self._paint_pending_wraps
        self._paint_pending = []
        self._paint_pending_wraps = []
        self._paint_dirty = False
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
        # A terminal does not auto-scroll horizontally: anchor the view at the left
        # so the START of every row stays on screen instead of being clipped off the
        # left edge. Left alone, ensureCursorVisible follows the caret's DISPLAY
        # column -- far to the right in Detail/Reveal, where each cell expands to a
        # wide <U+XXXX> badge -- and parks the viewport mid-line, silently hiding the
        # codepoint prefix that names the character. Detail/Reveal wrap to the width
        # (see _sync_wrap_mode) so their caret is always within the viewport and this
        # simply keeps home. Box/Show are NoWrap (glyph line/column stable across a
        # box<->show toggle), so a long INTERACTIVE line of wide glyphs can carry the
        # caret past the right edge -- there the caret must stay visible, so home only
        # when doing so keeps it on screen (else follow it, as ensureCursorVisible
        # did). Vertical tail-follow is preserved either way.
        hbar = self.horizontalScrollBar()
        if hbar is not None:
            # Home only when the WHOLE caret fits at the left, so pinning never clips
            # it against the right edge -- include the caret WIDTH, not just its left
            # edge (a caret exactly on the boundary would else be pinned and shaved).
            # cursorWidth() is reliable even in shot mode, where cursorRect() reports
            # zero width; cursorRect().x() gives the caret's current viewport x and
            # the scroll terms map it to where it would sit once homed.
            caret_right = (self.cursorRect().x() + self.cursorWidth()
                           + hbar.value() - hbar.minimum())
            if caret_right <= self.viewport().width():
                hbar.setValue(hbar.minimum())

    def _export_ascii(self, text):
        """Map the display box (BOX) back to ASCII '_' for any text that LEAVES the
        widget (copy, command hook, session restore -- a saved transcript instead
        uses transcript_text, which stays lossless), so neutralized text leaves as
        pure ASCII. Map in every mode EXCEPT Show: Box neutralizes every non-ASCII
        byte to a box, and in a TUI grid Reveal/Detail also fall back to the box
        (a <U+XXXX> badge cannot fit one cell), so both must export '_'. In CLI
        Reveal/Detail the document carries <U+XXXX> badges with no box, so the
        replace is a harmless no-op. Only Show mode keeps the box: there it may be
        a real U+25A1 the program printed, and Show is the opt-in to copy real
        unicode, so its text is left untouched. SPACE_MARK is the ONE exception in
        Show mode: it is our synthetic marker for a neutralized non-ASCII space, not
        a glyph the program printed, so it must never round-trip as its glyph or as a
        plain space -- map it to '_' in every mode, Show included."""
        if self._mode == 'show':
            return text.replace(SPACE_MARK, '_')
        return text.replace(BOX, '_').replace(SPACE_MARK, '_')

    def toPlainText(self):
        # Overrides QPlainTextEdit.toPlainText so every external text getter
        # (save transcript, _hook_transcript, session cap) yields ASCII, not the
        # display box. Qt's own rendering does not go through this method.
        self._flush_paint()          # never read a stale (debounced) document
        return self._export_ascii(super().toPlainText())

    def _write_transcript_file(self):
        """Write this tab's transcript to the configured SECURE_TERMINAL_TRANSCRIPT_FILE,
        atomically. transcript_text() is the lossless plain-ASCII record and walks the
        RENDERED document, so it reflects CLI and TUI (incl. the alternate screen) alike.
        Best-effort: a write failure must never disturb the terminal."""
        path = self._transcript_file
        if path is None:  # pragma: no cover - the debounce timer only fires when a path is set
            return
        # Force any pending debounced GRID render first, so the transcript reflects the
        # LATEST frame regardless of timer ordering (under load the render debounce can slip
        # past this one). CLI mode needs no equivalent: transcript_text() flushes its paint.
        if self._grid_mode() and self._render_timer.isActive():
            self._render_timer.stop()
            self._render_tui()
        try:
            text = self.transcript_text()
            tmp = path + '.tmp'
            # O_NOFOLLOW + owner-only: the target may be a user-chosen path in a shared dir,
            # so never write THROUGH a pre-planted symlink at <path>.tmp (would let a local
            # attacker redirect the write); a symlink there raises and is ignored below.
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
            with os.fdopen(os.open(tmp, flags, 0o600), 'w', encoding='utf-8') as handle:
                handle.write(text)
            os.replace(tmp, path)          # atomic: a reader never sees a half-write
        except OSError:  # pragma: no cover - defensive: a transcript write failure is ignored
            pass

    def _doc_runs(self, block):
        """Yield (doc_start, doc_end, cp) for each run of a block in document
        (UTF-16) positions: from the block's _GridRow in TUI grid mode (where the
        formats and the source code point live in the layout / block model, not the
        char format), else from the document fragments in CLI line mode (cp on the
        fragment's char format). The single seam the code-point readers -- hover
        (_run_cp_at), copy (_selection_text) and save (transcript_text) -- share, so
        both render paths stay lossless with one implementation."""
        data = block.userData()
        base = block.position()
        if isinstance(data, _GridRow):
            for start, length, _fmt, cp in data.runs:
                yield base + start, base + start + length, cp
        else:
            it = block.begin()
            while not it.atEnd():
                frag = it.fragment()
                if frag.isValid():
                    cp = frag.charFormat().property(_CP_PROP)
                    yield (frag.position(), frag.position() + frag.length(),
                           None if cp is None else int(cp))
                it += 1

    def _run_cp_at(self, docpos):
        """The source code point of the character at document position `docpos`
        (grid model or line fragment), or None for a plain cell. Replaces reading
        _CP_PROP off the char format, which a layout-format grid cell does not
        expose."""
        block = self.document().findBlock(docpos)
        for a, b, cp in self._doc_runs(block):
            if a <= docpos < b:
                return cp
        return None

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
        self._flush_paint()          # a save must include the last unpainted line
        doc = self.document()
        out = []
        cur = QTextCursor(doc)
        block = doc.begin()
        first = True
        while block.isValid():
            if not first:                       # blocks are newline-separated,
                out.append('\n')                # exactly like toPlainText
            first = False
            # Walk the per-run code points via the shared seam: in TUI grid mode
            # the source cp is in the block's _GridRow (layout formats are not
            # queryable), in CLI line mode it is on the fragment's char format.
            for a, b, cp in self._doc_runs(block):
                cur.setPosition(a)
                cur.setPosition(b, QTextCursor.MoveMode.KeepAnchor)
                text = cur.selectedText()
                if BOX in text:
                    # A real U+25A1 the program printed is kept as its glyph in Show
                    # mode (cp is its own codepoint) -- it is NOT a neutralization
                    # placeholder, so it is left untouched, matching _export_ascii's
                    # Show invariant. Otherwise the box stands in for a neutralized
                    # byte: name its source codepoint inline, or (untagged, e.g. past
                    # the marking cap) the ASCII placeholder.
                    if not (cp == 0x25a1 and self._mode == 'show'):
                        text = (text.replace(BOX, render_output(chr(cp), 'detail'))
                                if cp is not None else text.replace(BOX, '_'))
                if SPACE_MARK in text:
                    # SPACE_MARK stands in for a neutralized non-ASCII space: name its
                    # source codepoint inline (<U+00A0 NO-BREAK SPACE>, the Detail
                    # rendering), so the record stays lossless and a non-breaking space
                    # is unmistakable. A real U+2423 the program printed in Show mode
                    # (cp is its own, non-space code point) is kept as its glyph,
                    # matching the BOX branch; untagged falls back to '_'.
                    if not (cp == 0x2423 and self._mode == 'show'):
                        text = (text.replace(SPACE_MARK, render_output(chr(cp), 'detail'))
                                if cp is not None else text.replace(SPACE_MARK, '_'))
                out.append(text)
            block = block.next()
        return ''.join(out)

    def _export_selection_fragment(self, text, cp):
        """Map ONE selected run's display text to what leaves the widget, using its
        recorded SOURCE code point to tell a synthetic marker from a real glyph the
        program printed -- the distinction _export_ascii, a pure string map with no
        code-point context, cannot make.

        Outside Show mode _export_ascii is exact (every non-ASCII byte is a marker),
        so defer to it. In Show mode a real U+2423 the child printed is kept as its
        glyph (its cp IS 0x2423, matching transcript_text's guard); only the
        SYNTHETIC SPACE_MARK -- our stand-in for a neutralized non-ASCII space, whose
        cp is the SOURCE byte, not 0x2423 -- is mapped to '_'. BOX is left as-is in
        Show, exactly as _export_ascii does, so a real U+25A1 is preserved too."""
        if self._mode != 'show':
            return self._export_ascii(text)
        if SPACE_MARK in text and cp != 0x2423:
            return text.replace(SPACE_MARK, '_')
        return text

    def _selection_text(self):
        """The current selection as it would leave the widget: soft-autowrapped
        rows (blocks _paint_line marked with userState 1) are joined so a line that
        wrapped at the terminal width copies as one line, like a real terminal --
        not with a spurious newline at each wrap -- and each neutralized placeholder
        is mapped back to ASCII per _export_selection_fragment. '' if nothing
        selected. Walks FRAGMENTS (not whole blocks) so each carries its own source
        code point, the only way to keep a real Show-mode U+2423/U+25A1 the program
        printed while still collapsing the synthetic markers."""
        cursor = self.textCursor()
        if not cursor.hasSelection():
            return ''
        doc = self.document()
        start, end = cursor.selectionStart(), cursor.selectionEnd()
        parts = []
        block = doc.findBlock(start)
        while block.isValid() and block.position() <= end:
            if parts and block.userState() != 1:      # 1 == wrap continuation
                parts.append('\n')
            # Walk per-run (grid _GridRow or line fragments) so each carries its own
            # source code point -- the only way to keep a real Show-mode U+2423/U+25A1
            # the program printed while still collapsing the synthetic markers.
            for a, b, cp in self._doc_runs(block):
                lo, hi = max(start, a), min(end, b)
                if lo < hi:
                    # slice with a QTextCursor, whose positions are the same UTF-16
                    # code units as start/end -- Python str slicing counts code points
                    # and mis-slices an astral char.
                    seg = QTextCursor(doc)
                    seg.setPosition(lo)
                    seg.setPosition(hi, QTextCursor.MoveMode.KeepAnchor)
                    parts.append(self._export_selection_fragment(seg.selectedText(), cp))
            block = block.next()
        return ''.join(parts)

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
        # keeping a real glyph stays an explicit, reviewed choice. The display-aware
        # strip maps a Show-mode box / box-drawing glyph to an ASCII stand-in first, so
        # a selected box copies as '_' instead of collapsing to the surrounding spaces.
        data.setText(sanitize_clipboard_display(self._selection_text()))
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
                else sanitize_clipboard_display(text))
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
        # Let the owning window append its app-level toggles (system tray, clipboard
        # sanitizer), so they are reachable from the right-click menu too. A preview
        # pane's window() is not a MainWindow and has no such method -> nothing added.
        add = getattr(self.window(), 'add_terminal_context_actions', None)
        if add is not None:
            add(menu)
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

    def _child_raw_mode(self):
        """True when the pty is in NON-CANONICAL (raw) mode, i.e. a program has
        taken the keyboard over character-by-character instead of letting the
        kernel cook a line -- what every full-screen and cursor-addressing program
        does. TIOCGETS on the master reports the pty's line discipline, so this
        needs no cooperation from the child and, unlike every escape-based
        detector, does not depend on what the terminfo entry advertises."""
        if self._fd is None:
            return False
        try:
            attrs = termios.tcgetattr(self._fd)
        except (OSError, termios.error):
            return False
        return not attrs[3] & termios.ICANON        # attrs[3] == c_lflag

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
        if pgrp == os.getpgrp():
            # The tty is still owned by OUR process group: between pty.fork() and
            # the child's execvp the shell has not yet taken the terminal, so
            # "some other pgrp holds it" is us, not a program worth terminating.
            # Without this, a tab closed within milliseconds of opening asked "A
            # program is still running in this tab", and the test harness -- which
            # cannot answer a modal -- blocked forever on that dialog.
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
    _NON_CONTENT_KEYS = None   # keys that cannot leave prompt text, built lazily

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
            # Typing resumes input: clear a held selection so the grid rebuild (frozen by
            # _render_tui while a selection is active) resumes -- TUI keys go straight to the
            # child, never through Qt's editor, so the selection would otherwise persist and
            # freeze the view until a mouse click.
            if self.textCursor().hasSelection():
                cur = self.textCursor()
                cur.clearSelection()
                self.setTextCursor(cur)
                self._render_timer.start(16)
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
                    # and a stale dirty flag would poison the next prompt. Judge only
                    # at a bare prompt: with a foreground program the keystrokes are
                    # ITS input (a password at sudo/ssh, text in cat), not a shell
                    # command -- feeding them to the hook would leak them and the
                    # discard would signal/disrupt that program (matches the TUI path).
                    if (self._hook is not None and not self.has_foreground_program()
                            and self._hook_intercept()):
                        return
                    self._line_buffer = ''
                    self._line_dirty = False
                    self._write(bytes([byte]))
                    return
                self._write(bytes([byte]))
                if key == Qt.Key.Key_C:
                    self._echo_caret('^C')    # make the interrupt visible
                if key == Qt.Key.Key_C:
                    self._line_buffer = ''    # SIGINT discards the whole line
                    self._line_dirty = False
                elif key == Qt.Key.Key_U:
                    # Ctrl+U (kill-line) reaches cursor-to-start (bash unix-line-discard)
                    # or the whole line (zsh kill-whole-line) -- its extent depends on
                    # the cursor position, which we do not track. So clear the mirror but
                    # PRESERVE _line_dirty: only a clean mirror (cursor at end, not dirty)
                    # truly killed the whole line. If the cursor had already moved, the
                    # survivor is unknown and the next Enter must fail safe (ask), not
                    # submit it unjudged. Regression: resetting the flag let Home then
                    # Ctrl+U bypass the command hook.
                    self._line_buffer = ''
                else:
                    # any OTHER readline control edit (Ctrl+A/E/B/F move, Ctrl+K/W
                    # kill, Ctrl+Y yank, Ctrl+T transpose, Ctrl+D delete, Ctrl+R
                    # search) rewrites the real line without updating _line_buffer,
                    # so the hook must not judge the stale buffer -- fail safe (ask).
                    # Flagged whether or not a hook is configured: _line_pending
                    # reads it too, and a line we cannot see is exactly the line a
                    # CR-terminated re-export must not be typed into.
                    self._line_dirty = True
                return
            # The rest of the Ctrl+@..Ctrl+_ range (Ctrl+[ -> 0x1b ESC, Ctrl+] ->
            # 0x1d, Ctrl+^ -> 0x1e, Ctrl+_ / Ctrl+/ -> 0x1f readline-undo, Ctrl+Space
            # / Ctrl+@ -> 0x00 set-mark): forward the control byte Qt already
            # computed for the layout, so the whole range is faithful without a
            # hard-coded keymap. Enter/Tab/Backspace keep their dedicated handling.
            ctl = event.text()
            if len(ctl) == 1 and ord(ctl) < 0x20 and ctl not in '\b\t\n\r':
                self._line_dirty = True       # an unmirrored control edit may desync
                self._write(ctl.encode('latin-1'))
                return

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            # The command hook (if configured) judges the typed line before Enter
            # submits it; it may block, ask, or offer a safer command. Only at a
            # bare prompt: with a foreground program in place the line is ITS input
            # (a sudo/ssh password), not a shell command (matches the TUI path).
            if (self._hook is not None and not self.has_foreground_program()
                    and self._hook_intercept()):
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
                # stale or empty line -- and so _line_pending knows a recalled
                # command is sitting at the prompt even though we never saw it.
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
            if action == 'run':
                self._line_dirty = False
                self._write(b'\r')
            else:
                # Best-effort cancel of a line we cannot see. Its content is unknown
                # so a counted erase is impossible; SIGINT is the only keymap-free
                # cancel. It can be disarmed (`stty intr undef`), so KEEP _line_dirty
                # set -- the next Enter re-asks instead of submitting a retained line.
                self._write(self._CANCEL_UNKNOWN_LINE)
            return True
        command = self._line_buffer
        if not command.strip():
            return False
        cfg = self._hook or {}            # never None here (the caller guards), and
        result = hook.evaluate(           # the `or {}` mirrors _hook_transcript
            cfg['argv'], command,
            timeout=cfg.get('timeout', 10),
            on_error=cfg.get('on_error', 'allow'),
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
        # Content is mirrored (not dirty), so erase it deterministically: no SIGINT
        # (would kill nothing here but flush the tty input queue via tcflush and
        # swallow the suggestion written next) and no keymap dependence.
        self._clear_typed_line(command)
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
        if SecureTerminal._NON_CONTENT_KEYS is None:
            SecureTerminal._NON_CONTENT_KEYS = _build_non_content_keys()

        # TUI mode does not mirror the shell's line -- a full-screen program may own
        # the keys entirely -- so the CLI line model is not maintained here. Two
        # jobs still keep _line_pending honest (it gates the mode-switch re-export;
        # see _reexport_term):
        #   RELEASE a line a re-export is waiting on. A re-export deferred by a
        #   pending line at a CLI->TUI switch would otherwise wait forever, because
        #   nothing else here clears the flags. Accept-line and the two discard
        #   keys are exactly the keystrokes that empty the prompt. The discard keys
        #   need `not shift` to match the control-byte branch below (Ctrl+Shift+C is
        #   a copy shortcut, not a discard): the window filters Ctrl+Shift before
        #   _tui_key, so this only keeps the two branches self-consistent.
        #   MARK a line a re-export must wait FOR. With no foreground program the
        #   keys reach the shell's line editor, so a content-introducing key (typed
        #   text, a history recall, a completion) leaves text at the bare prompt --
        #   which TUI cannot mirror. Flag it dirty: otherwise a later TUI->CLI
        #   switch fires an immediate CR-terminated re-export that concatenates onto
        #   and SUBMITS that line, an Enter the user never pressed that also bypasses
        #   command_hook. Pure navigation/deletion keys (_NON_CONTENT_KEYS) never
        #   introduce content, so they do NOT flag -- else a no-op Backspace/Left at
        #   an empty prompt would needlessly defer the re-export. Unlike the CLI path
        #   the flag here feeds ONLY the re-export (the hook is not consulted in TUI),
        #   so this precision is safe. Gated on "no foreground program" so a program's
        #   own keys never strand the flag (a `less` quit with `q` leaves no prompt
        #   line, yet marking would defer the re-export forever).
        accept_line = (key in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                or (ctrl and not shift and key in (Qt.Key.Key_J, Qt.Key.Key_M)))
        submit_or_discard = accept_line or (
                ctrl and not shift and key in (Qt.Key.Key_C, Qt.Key.Key_U))
        # A bare shell prompt in TUI mode still submits real commands, so the command
        # hook must judge an accept-line here too -- otherwise switching to TUI is a
        # SILENT BYPASS of it. Only a bare prompt routes through (a foreground program
        # owns its own keys), and only when a hook is configured. TUI does not mirror
        # the line, so _hook_intercept sees _line_dirty (set above for typed content)
        # and falls through to a human review rather than judging an empty buffer -- a
        # prompted override, never a silent pass. It performs the submit/discard itself
        # when it fires, so return without also writing the accept byte; an empty prompt
        # (nothing typed, not dirty) returns False and submits normally with no prompt.
        if (accept_line and not self.has_foreground_program()
                and self._hook is not None and self._hook_intercept()):
            return
        if submit_or_discard:
            self._line_buffer = ''
            # accept-line and Ctrl+C settle the line (judged, or SIGINT-discarded), so
            # the flag clears. Ctrl+U does NOT: its reach is cursor-dependent (untracked),
            # so a survivor must keep the next accept-line failing safe -- same reason as
            # the CLI path. Regression: clearing it let Home then Ctrl+U bypass the hook.
            if not (ctrl and key == Qt.Key.Key_U):
                self._line_dirty = False

        seq = SecureTerminal._TUI_KEYS.get(key)
        text = event.text()
        if key == Qt.Key.Key_Tab and shift:
            out = b'\x1b[Z'                          # back-tab
        elif (seq is not None and (ctrl or shift or alt)
              and len(seq) == 3 and seq[:2] == b'\x1b[' and 0x41 <= seq[2] <= 0x5a):
            # A MODIFIED cursor / Home / End key (bare form ESC[<final>): encode the
            # modifier in the xterm CSI form ESC[1;<p><final>, p = 1 + shift + 2*alt +
            # 4*ctrl, so the child program actually sees it -- e.g. Ctrl+End -> ESC[1;5F,
            # which claude-code's "jump to bottom" binding expects. The bare table drops
            # the modifier. Ctrl+PageUp/Down never reach here (intercepted for tab
            # switching), so the tilde-form keys need no modifier handling.
            p = 1 + (1 if shift else 0) + (2 if alt else 0) + (4 if ctrl else 0)
            out = b'\x1b[1;%d%c' % (p, seq[2])
        elif seq is not None:
            out = seq
        elif ctrl and not shift and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            # Ctrl+letter -> the control byte (Ctrl+C -> 0x03) the program
            # receives; the Terminate action stays the escape hatch.
            out = bytes([key & 0x1f])
        elif text and len(text) == 1 and ord(text) < 0x20:
            out = text.encode('latin-1')            # e.g. Ctrl+[ -> ESC
        elif text and all(ch.isprintable() for ch in text):
            out = (b'\x1b' if alt else b'') + text.encode('utf-8')
        else:
            return                                  # non-input key: nothing sent

        # A content key marks the line pending. So does a navigation/deletion key
        # (_NON_CONTENT_KEYS) WHEN a CLI-typed line was carried into TUI (_line_buffer
        # still populated): TUI cannot mirror the edit, so a Home/Delete/Backspace
        # there desyncs that buffer from the real shell line -- and command_hook must
        # not judge the stale buffer while the shell runs the edited command. Marking
        # it dirty forces the hook to fail safe (ask). At an EMPTY prompt (no carried
        # buffer) a no-op key still does not mark, so the re-export is not deferred
        # needlessly.
        if (not submit_or_discard and not self.has_foreground_program()
                and (key not in SecureTerminal._NON_CONTENT_KEYS
                     or self._line_buffer)):
            self._line_dirty = True
        self._write(out)

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
        cp = self._run_cp_at(a)
        if cp is not None:
            return int(cp)
        fwd = QTextCursor(doc)
        fwd.setPosition(a)
        fwd.setPosition(b, QTextCursor.MoveMode.KeepAnchor)
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
        # name, category, escape -- because the display (a box, a <U+XXXX> badge, or
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
        # When the child grabs the mouse, a double-click is REPORTED as another press
        # (its release follows via mouseReleaseEvent), not used for a local word-select
        # or the character popup; Shift is the local override.
        if self._mouse_reporting() and not self._shift(event):
            base = self._SGR_BUTTON.get(event.button())
            if base is not None:
                self._report_mouse(base, event, pressed=True)
                self._mouse_report_btns.add(event.button())
                event.accept()
                return
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
        # box-drawing / block elements are benign structure, not a risk class: name
        # them honestly rather than as generic "foreign text" (marking_class, kept in
        # step with the paste review, still reports them 'nonascii').
        risk = ('box-drawing / block element -- structural, not deceptive'
                if is_structural(cp)
                else _RISK_LABELS.get(marking_class(cp), marking_class(cp)))
        info = QLabel(describe_codepoint(cp) + '\nRisk: ' + risk, dlg)
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

    def _shift(self, event):
        return bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)

    def mousePressEvent(self, event):
        # When the child grabs the mouse (tracking + SGR), a plain press is REPORTED
        # to it rather than starting a local selection; Shift is the local override.
        if self._mouse_reporting() and not self._shift(event):
            base = self._SGR_BUTTON.get(event.button())
            if base is not None:
                self._report_mouse(base, event, pressed=True)
                self._mouse_report_btns.add(event.button())
                event.accept()
                return
        # Mark a drag-selection in progress so _render_tui freezes the grid rebuild while
        # the user selects (a left-button press begins a possible drag).
        if event.button() == Qt.MouseButton.LeftButton:
            self._mouse_selecting = True
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):
        # Balance EACH reported press with the release of THAT button (report it even if
        # Shift toggled mid-drag, so the child never sees an unmatched press). A set,
        # not one button: a left+right chord reports two presses, so each release must
        # match its own button -- tracking a single button left the first one logically
        # stuck in the child (no protocol release).
        btn = event.button()
        if btn in self._mouse_report_btns:
            base = self._SGR_BUTTON.get(btn, 0)
            self._report_mouse(base, event, pressed=False)
            self._mouse_report_btns.discard(btn)
            if not self._mouse_report_btns:
                self._mouse_report_cell = None
            event.accept()
            return
        super().mouseReleaseEvent(event)
        self._mouse_selecting = False
        # The drag is over: re-arm a grid render so the view catches up once the selection
        # is gone (if a selection is still held, _render_tui stays frozen and does not
        # clobber it; clearing it later re-arms another render).
        if self._grid_mode():
            self._render_timer.start(16)
        # A terminal caret is not click-positionable: typed input always goes to
        # the shell at the output cursor, never where you click. A plain click
        # that moved the blinking caret elsewhere -- e.g. into zsh's trailing
        # prompt fill -- would only mislead (a caret blinking where you cannot
        # type). Keep a drag-selection for copy; otherwise snap the caret back.
        if self.textCursor().hasSelection():
            return
        self.reset_caret()

    def mouseMoveEvent(self, event):
        # Report motion to a child that asked: a drag (button held) under 1002/1003,
        # or button-less motion under 1003. Coalesce to one report per CELL so any-
        # motion (1003) does not flood. Shift keeps motion local (text selection).
        if self._mouse_reporting() and not self._shift(event):
            buttons = event.buttons()
            held = buttons != Qt.MouseButton.NoButton
            report = ((held and (_MOUSE_DRAG_MODE in self._mouse_modes
                                 or _MOUSE_MOTION_MODE in self._mouse_modes))
                      or (not held and _MOUSE_MOTION_MODE in self._mouse_modes))
            if report:
                cell = self._event_cell(event)
                if cell != self._mouse_report_cell:
                    self._mouse_report_cell = cell
                    if buttons & Qt.MouseButton.LeftButton:
                        base = 0
                    elif buttons & Qt.MouseButton.MiddleButton:
                        base = 1
                    elif buttons & Qt.MouseButton.RightButton:
                        base = 2
                    else:
                        base = 3            # motion with no button
                    self._report_mouse(base, event, pressed=True, motion=True)
                event.accept()
                return
        super().mouseMoveEvent(event)

    def focusInEvent(self, event):
        # not while a paste/copy review is up: input to the child is suspended (as in
        # _report_mouse / keyPressEvent), so a focus report must not leak either.
        if _MOUSE_FOCUS_MODE in self._mouse_modes and not self._review_active:
            self._write(b'\x1b[I')          # DEC 1004 focus-in report
        super().focusInEvent(event)

    def focusOutEvent(self, event):
        if _MOUSE_FOCUS_MODE in self._mouse_modes and not self._review_active:
            self._write(b'\x1b[O')          # DEC 1004 focus-out report
        super().focusOutEvent(event)

    # -- paste: warn on, then sanitize, anything unusual ----------------------
    def _bracketed_paste_active(self):
        """True when a TUI child has enabled bracketed paste (DEC mode 2004): it
        then BUFFERS a pasted payload as inert data rather than interpreting the
        bytes as keystrokes, so an embedded newline cannot auto-run a command. This
        is the ONLY condition under which a multiline paste is safe to deliver
        without a forced review, and the ONLY one that gets the 200~/201~ framing."""
        return (self.tui_active() and self._screen is not None
                and _BRACKETED_PASTE_MODE in getattr(self._screen, 'mode', ()))

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
        # A paste with an EMBEDDED newline carries MORE than one command: its first
        # newline would auto-run a command the instant the paste lands, before it
        # can be read (a pure-ASCII pastejacking payload). HOLD such a paste for
        # review WHATEVER the warn setting -- a security terminal must never auto-run
        # a hidden second command, so this gate is not bypassable by paste_warn=
        # 'never'. A SINGLE-line paste (with or without a trailing newline) is
        # instead made safe in _dispatch_paste, which strips the trailing submit so
        # the command waits at the prompt for the user's Enter; it needs no forced
        # hold. The ONE exemption is a TUI child with bracketed paste (DEC 2004)
        # active: it BUFFERS the payload as inert data, so an embedded newline cannot
        # execute -- there the ordinary warn-based gate applies. A TUI WITHOUT
        # bracketed paste is no safer than line mode (its embedded \r would run), so
        # it is NOT exempt: tui_active() alone is the wrong test.
        multiline = paste_is_multiline(raw)
        risky = has_unicode or has_control or multiline
        force_review = multiline and not self._bracketed_paste_active()
        warn = self._paste_warn
        if force_review or warn == 'always' or (warn == 'unicode' and risky):
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
        # Bracketed paste when a TUI program asked for it (DEC mode 2004): the child
        # BUFFERS the payload as data rather than interpreting it as keystrokes, so
        # it cannot auto-execute -- deliver it verbatim between the markers.
        bracketed = self._bracketed_paste_active()
        if not bracketed:
            # No bracketed framing to make the child buffer it, so a trailing submit
            # byte ('\r', which sanitize_paste maps every newline to) would auto-run
            # the pasted command with no explicit Enter -- exactly what a security
            # terminal must never do. Strip the trailing submit so the command waits
            # at the prompt for the user's own Enter. An embedded newline in a
            # reviewed multi-command paste is preserved (only the final auto-run is
            # dropped); a single-line paste then reaches the shell with no submit.
            safe = paste_no_autosubmit(safe)
            if not safe:
                return
        # Keep our view of the line honest across a paste. A paste that lands at a
        # bare SHELL prompt (CLI, or TUI with no foreground program) sits there as a
        # command the next Enter submits -- _line_buffer never saw it, so mark the
        # line unverifiable. _line_dirty has TWO consumers, both of which must catch
        # a pasted command: the hook (which then FAILS SAFE, asking on the next
        # Enter, including in TUI where accept-line now routes through it) AND
        # _line_pending(), the guard that stops _send_reexport from typing
        # "export TERM=...\r" onto a line that already holds text. Only a paste
        # delivered to a FOREGROUND PROGRAM (a TUI app that asked for it) is its
        # data, not a shell line, so it is the sole case left unmarked.
        if not self.tui_active() or not self.has_foreground_program():
            self._line_dirty = True
        data = safe.encode('utf-8')
        if bracketed:
            data = b'\x1b[200~' + data + b'\x1b[201~'
        self._write(data)
