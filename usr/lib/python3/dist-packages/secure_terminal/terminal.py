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

from PyQt6.QtCore import QSocketNotifier, Qt, QTimer, pyqtSignal, QEvent
from PyQt6.QtGui import QFont, QTextCursor, QColor, QPalette, QTextCharFormat
from PyQt6.QtWidgets import QPlainTextEdit, QToolTip

# The pure, Qt-free sanitization core (also tested directly by dist-ai). Names
# are re-exported here so terminal.py stays the single import point for the rest
# of the package (main.py, dialog.py).
from secure_terminal.sanitize import (
    THEMES, BASE_POINT_SIZE, ANSI_PALETTE, DISPLAY_MODES,
    ANSI_RE as _ANSI, SGR_RE as _SGR,
    colors_allowed, too_close, render_output, sanitize_paste,
    sanitize_paste_unicode,
    paste_findings, parse_sgr, tui_cell, sanitize_title, apply_line_edits,
    wants_full_screen, leaves_full_screen, describe_codepoint,
    _ALT_SCREEN as _ALT_ENTER, _ALT_SCREEN_OFF as _ALT_LEAVE,
)

# a revealed non-ASCII character, e.g. "<U+20AC>"; hovering one shows what it is.
_BADGE_RE = re.compile(r'<U\+([0-9A-Fa-f]+)>')

# OSC 9 ";<text>" (BEL or ST terminated): the iTerm2-style desktop notification.
_OSC9 = re.compile(rb'\x1b\]9;([^\x07\x1b]*)(?:\x07|\x1b\\)')


def tui_available():
    return pyte is not None


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
    # a program set the title / sent a notification (only when allowed)
    title_changed = pyqtSignal(str)
    notified = pyqtSignal(str)

    def __init__(self, parent=None, command=None, tui=False, history=''):
        super().__init__(parent)
        self.setUndoRedoEnabled(False)
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
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
        # A mode toggle only re-renders this much of the most-recent raw output,
        # not the whole buffer: rendering the full scrollback (and reveal expands
        # each byte to an 8-char <U+XXXX>) froze the UI on a flood. This tail is
        # far more than a screenful, so what you can see is always re-rendered.
        self._RERENDER_TAIL = 131072

        # optional ANSI colours (off by default); SGR parser state.
        self._colors = False
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

        # "modern terminal protocol": let a program set the title / notify.
        # Off by default; only has an effect in TUI mode (line mode strips
        # escapes). OSC 52 clipboard and OSC 8 hyperlinks stay blocked regardless.
        self._allow_title = False
        self._last_title = ''
        # persistent output cursor for line mode (see _append_runs)
        self._out_cursor = None
        # show the "this program wants TUI mode" advisory at most once per
        # full-screen program, so one that redraws every second does not spam it.
        self._tui_hint_shown = False
        # True while a full-screen program holds the alternate screen buffer. The
        # pyte screen is then kept fed in the background even in line mode, so
        # flipping to TUI mode shows the program's current frame instantly (no
        # restart). Maintained from the output stream (alt-screen enter/leave).
        self._alt_screen = False
        # optional command hook (opt-in): config dict or None, plus the current
        # typed input line so it can be judged before Enter submits it.
        self._hook = None
        self._line_buffer = ''
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.timeout.connect(self._render_tui)

        # restored scrollback from a previous session, shown as history above
        # the fresh shell (line mode; a TUI tab repaints over it on first draw).
        if history:
            restored = history if history.endswith('\n') else history + '\n'
            self._raw = restored          # so a mode toggle re-renders it too
            self._append(restored)

        self._notifier = None
        self._fd = None
        self._pid = None
        self._start(command)

    # -- appearance: theme + zoom ---------------------------------------------
    def apply_theme(self, theme):
        base, text = THEMES.get(theme, THEMES['dark'])
        self._theme = theme if theme in THEMES else 'dark'
        pal = self.palette()
        pal.setColor(QPalette.ColorRole.Base, QColor(base))
        pal.setColor(QPalette.ColorRole.Text, QColor(text))
        self.setPalette(pal)
        self._fmt_cache = {}          # theme changes the resolved cell colours
        if self.tui_active():
            self._render_timer.start(16)

    def apply_zoom(self, percent):
        percent = max(10, min(1000, int(percent)))
        self._zoom = percent
        size = max(1, round(self._base_point_size * percent / 100.0))
        font = self.font()
        font.setPointSize(size)
        self.setFont(font)
        self._sync_tui_size()          # font change resizes the grid
        if self.tui_active():
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
        """Re-display existing output under the current display mode. In TUI mode
        the pyte screen is simply repainted; in line mode the retained raw output
        is replayed through the render pipeline from a clean document."""
        if self.tui_active():
            self._render_tui()
            return
        self.clear()
        self._out_cursor = None
        self._sgr_reset()                 # replay SGR colours from a clean slate
        if self._raw:
            # Only the recent tail, so a mode toggle after a flood cannot freeze
            # the UI re-rendering (and reveal-expanding) megabytes of scrollback.
            self._append_runs(self._render_runs(self._raw[-self._RERENDER_TAIL:]))

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
        pyte is missing."""
        enabled = bool(enabled) and tui_available()
        if enabled == self._tui:
            return
        self._tui = enabled
        if enabled:
            # A TUI screen is fixed (no scrollback), so hide the vertical
            # scrollbar. Because the pyte grid is scrollbar-independent
            # (_tui_grid_size), toggling it does not change the grid, so no
            # pyte.resize() fires -- which is what preserves the running program's
            # frame across the switch.
            self.setVerticalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
            # Show the current screen at once. If a full-screen program is already
            # running (_alt_screen) its frames were fed in the background, so the
            # screen is up to date. Otherwise start from a FRESH blank screen: a
            # leftover screen from an earlier TUI session holds a stale frame (it
            # is not fed in plain line mode), which must not be shown as if live.
            if self._screen is None or not self._alt_screen:
                self._make_screen()
            self._render_tui()
        else:
            self.setVerticalScrollBarPolicy(
                Qt.ScrollBarPolicy.ScrollBarAsNeeded)
            # Back to line mode: stop the TUI repaint and rebuild the scrolling
            # document from the retained raw output. A full-screen program that is
            # still running keeps drawing into the background pyte screen (so
            # re-enabling is instant) while its stripped output also appends here.
            self._render_timer.stop()
            self._rerender()

    def current_tui(self):
        return self._tui

    def apply_allow_title(self, enabled):
        self._allow_title = bool(enabled)

    def allow_title_enabled(self):
        return self._allow_title

    def tui_active(self):
        return getattr(self, '_tui', False) and tui_available()

    def _grid_size(self):
        """Columns and rows that fit the viewport at the current font. Used for
        the LINE-mode winsize, so it tracks the actual text width (scrollbar
        excluded), matching how the shell wraps and fills the prompt."""
        metrics = self.fontMetrics()
        char_w = metrics.horizontalAdvance('M') or 1
        char_h = metrics.height() or 1
        vp = self.viewport()
        cols = max(2, vp.width() // char_w)
        rows = max(2, vp.height() // char_h)
        return cols, rows

    def _tui_grid_size(self):
        """The grid for the pyte screen: scrollbar-INDEPENDENT, because TUI mode
        hides the vertical scrollbar. Computing it the same whether or not the
        line-mode scrollbar is currently shown means flipping into TUI mode (which
        toggles that scrollbar) does not change the grid, so it triggers no
        pyte.resize() -- and pyte.resize() clears the alternate screen, which would
        wipe the running program's frame we are switching in to see."""
        metrics = self.fontMetrics()
        char_w = metrics.horizontalAdvance('M') or 1
        char_h = metrics.height() or 1
        vp = self.viewport()
        width = vp.width()
        bar = self.verticalScrollBar()
        if bar is not None and bar.isVisible():
            width += bar.width()          # reclaim the space TUI mode will not use
        cols = max(2, width // char_w)
        rows = max(2, vp.height() // char_h)
        return cols, rows

    def _set_winsize(self, cols, rows):
        if self._fd is None:
            return
        try:
            fcntl.ioctl(self._fd, termios.TIOCSWINSZ,
                        struct.pack('HHHH', rows, cols, 0, 0))
        except OSError:
            pass            # a closed/invalid pty just misses this resize

    def _make_screen(self):
        cols, rows = self._tui_grid_size()
        self._screen = pyte.Screen(cols, rows)
        self._stream = pyte.ByteStream(self._screen)
        self._set_winsize(cols, rows)

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
            return QColor(ANSI_PALETTE[idx + 8 if bright else idx])
        col = QColor('#' + color)          # 256/truecolor as a 6-hex string
        if col.isValid():
            return col
        return QColor(default) if default is not None else None

    def _pyte_format(self, cell):
        key = (cell.fg, cell.bg, cell.bold, cell.reverse, cell.underscore)
        fmt = self._fmt_cache.get(key)
        if fmt is not None:
            return fmt
        base_bg, base_fg = THEMES.get(self._theme, THEMES['dark'])
        fg = self._pyte_qcolor(cell.fg, base_fg, bright=cell.bold)
        bg = self._pyte_qcolor(cell.bg, None)
        if cell.reverse:
            fg, bg = (bg if bg is not None else QColor(base_bg)), \
                     (fg if fg is not None else QColor(base_fg))
        if fg is None:
            fg = QColor(base_fg)
        eff_bg = bg if bg is not None else QColor(base_bg)
        if too_close(_rgb(fg), _rgb(eff_bg)):   # same contrast guard as colours
            fg = QColor(base_fg)
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
        """Repaint the whole pyte screen grid into the widget. Every cell's
        character is still ASCII/unicode-filtered (tui_cell), so a program can
        position and colour text but cannot smuggle a deceptive glyph."""
        screen = self._screen
        if screen is None:
            return
        self.setUpdatesEnabled(False)
        self.clear()
        cursor = self.textCursor()
        last = screen.lines - 1
        for y in range(screen.lines):
            row = screen.buffer[y]
            run_text = ''
            run_fmt = None
            for x in range(screen.columns):
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
            if y != last:
                cursor.insertText('\n')
        self.setUpdatesEnabled(True)
        if not screen.cursor.hidden:
            block = self.document().findBlockByNumber(
                min(screen.cursor.y, last))
            if block.isValid():
                pos = block.position() + min(screen.cursor.x, screen.columns)
                tc = self.textCursor()
                tc.setPosition(min(pos, self.document().characterCount() - 1))
                self.setTextCursor(tc)
        self.viewport().update()

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

    def _sgr_reset(self):
        # palette indexes (or None for default) + bold; folded by parse_sgr.
        self._sgr = {'fg': None, 'bg': None, 'bold': False}

    def _apply_sgr(self, param_str):
        parse_sgr(param_str, self._sgr)

    def _current_format(self):
        """Build the QTextCharFormat for the current SGR state, guarding against
        an unreadable foreground/background combination."""
        fmt = QTextCharFormat()
        fg_i, bg_i, bold = self._sgr['fg'], self._sgr['bg'], self._sgr['bold']
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

    def _render_runs(self, text):
        """Turn decoded output into a list of (display_text, format) runs. With
        colours off there is a single default-format run; with colours on the
        text is split at each SGR sequence and each run carries its colour."""
        if not self._effective_colors():
            return [(render_output(text, self._mode), None)]
        runs = []
        pos = 0
        for m in _ANSI.finditer(text):
            seg = text[pos:m.start()]
            if seg:
                runs.append((render_output(seg, self._mode),
                             self._current_format()))
            sgr = _SGR.fullmatch(m.group())
            if sgr:
                self._apply_sgr(sgr.group(1))
            pos = m.end()
        seg = text[pos:]
        if seg:
            runs.append((render_output(seg, self._mode), self._current_format()))
        return runs

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
            os.environ.setdefault('PAGER', 'cat')
            # `command` is an optional program to run (split like a shell word
            # list, e.g. "ssh -p 22 host"); with none we run the login shell.
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
        # Track whether a full-screen program holds the alternate screen. While it
        # does, keep the pyte screen fed even in line mode, so flipping to TUI mode
        # shows its current frame at once (no restart, the program keeps running).
        # Resolve enter/leave by LAST occurrence in the chunk, so a chunk that
        # carries both (one program quits and another starts) ends in the right
        # state rather than always enter-wins.
        entered = wants_full_screen(text)
        left = leaves_full_screen(text)
        if entered or left:
            last_enter = max((text.rfind(s) for s in _ALT_ENTER), default=-1)
            last_leave = max((text.rfind(s) for s in _ALT_LEAVE), default=-1)
            self._alt_screen = last_enter > last_leave
            if not self._alt_screen:
                self._tui_hint_shown = False   # a later full-screen app re-advises

        # Feed the background pyte screen only when pyte is actually available; on
        # a box without python3-pyte, _alt_screen can still be set (detection is
        # pure) but pyte.Screen() would crash and wedge the tab.
        if (self.tui_active() or self._alt_screen) and pyte is not None:
            if self._screen is None:
                self._make_screen()
            self._feed_stream(data)

        if self.tui_active():
            if not self._render_timer.isActive():
                self._render_timer.start(16)     # coalesce bursts into ~60fps
            if self._allow_title:
                self._handle_title_and_notify(data)
            return

        # line mode: retain the raw output (for a mode re-render) and display it
        # through the escape-stripping pipeline.
        self._raw += text
        if len(self._raw) > self._RAW_MAX:
            self._raw = self._raw[-self._RAW_MAX:]     # drop the oldest output
        self._append_runs(self._render_runs(text))
        # A full-screen program (htop, vim) is unusable in line mode -- its
        # escapes are stripped, leaving garbage. Point the user at TUI mode once.
        if not self._tui_hint_shown and entered:
            self._tui_hint_shown = True
            self._advise('This program wants a full-screen interface, which the '
                         'safe line mode cannot draw. Turn on TUI mode to run it '
                         'here.')

    def _feed_stream(self, data):
        """Feed bytes to the pyte parser, containing any error. pyte parses
        untrusted program output, and a version quirk or an odd sequence (real
        htop/vim/tmux emit private SGR that some pyte builds mishandle) must never
        crash the terminal -- worst case a rendering glitch, never a core dump."""
        try:
            self._stream.feed(data)
        except Exception:            # noqa: BLE001 -- third-party parser, any error
            pass

    def _handle_title_and_notify(self, data):
        """When the "modern protocol" setting is on, surface the program's title
        (OSC 0/2, captured by pyte) and notifications (OSC 9). Everything is
        sanitized to plain ASCII first, so a title or notification cannot carry
        an escape, control or homoglyph."""
        title = sanitize_title(getattr(self._screen, 'title', ''))
        if title and title != self._last_title:
            self._last_title = title
            self.title_changed.emit(title)
        for match in _OSC9.finditer(data):
            text = sanitize_title(match.group(1).decode('ascii', 'ignore'))
            if text:
                self.notified.emit(text)

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
        self._append_runs([(text, None)])

    def _advise(self, message):
        """Append a one-line advisory from the terminal itself (not the running
        program), styled distinctly (yellow, italic) and clearly marked so it
        cannot be mistaken for program output."""
        fmt = QTextCharFormat()
        fmt.setForeground(QColor('#e5a50a'))
        fmt.setFontItalic(True)
        self._append_runs([('\n[secure-terminal] ' + message + '\n', fmt)])

    def _append_plain(self, text):
        """Bulk line-mode append for uncolored output: resolve the line-editing
        controls in Python (apply_line_edits) and write the result in a couple of
        insertText calls, instead of walking a QTextCursor per character. This is
        the path a flood takes, so it stays O(n) where the per-char path crawled;
        _MAX_LINE hard-wraps a runaway line so a newline-free flood cannot build
        one unbounded block."""
        text = text.replace('\r\n', '\n')
        cursor = self._out_cursor
        if cursor is None:
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
        blk = cursor.block()
        col = cursor.position() - blk.position()
        completed, line, col = apply_line_edits(blk.text(), col, text, self._MAX_LINE)
        edit = QTextCursor(cursor)
        edit.setPosition(blk.position())
        edit.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                          QTextCursor.MoveMode.KeepAnchor)
        edit.removeSelectedText()            # clear the current (incomplete) line
        edit.insertText('\n'.join(completed + [line]))
        final_start = edit.position() - len(line)   # start of the new current line
        cursor.setPosition(final_start + col)
        self._out_cursor = cursor
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def _append_runs(self, runs):
        runs = [(text, fmt) for text, fmt in runs if text]
        if not runs:
            return
        # Fast, bulk path for uncolored output -- the common case, and the one a
        # flood arrives on (colours are opt-in). Resolve the line edits in Python
        # and bulk-insert; only genuinely coloured runs fall through to the
        # per-character overwrite path below.
        if all(fmt is None for _, fmt in runs):
            self._append_plain(''.join(text for text, _ in runs))
            return
        # The output cursor persists across writes, like a real terminal cursor.
        # A program may leave it mid-line -- zsh, for one, redraws its prompt with
        # a carriage return and leaves trailing fill spaces beyond the cursor --
        # and the next write (the echo of what you type) must land there, not at
        # the end of the document. Resetting to End each time is what put a wall
        # of spaces before your input.
        cursor = self._out_cursor
        if cursor is None:
            cursor = self.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
        move = QTextCursor.MoveOperation
        keep = QTextCursor.MoveMode.KeepAnchor
        sep = 0x2029
        default_fmt = QTextCharFormat()
        for text, fmt in runs:
            if not text:
                continue
            if fmt is None:
                fmt = default_fmt
            # CRLF is just a line ending: the pty maps every "\n" to "\r\n" on
            # output, so a carriage return glued to a newline carries no cursor
            # meaning and must NOT redraw the line -- collapse it first.
            text = text.replace('\r\n', '\n')
            # Fast path: plain output appended at the end of the document. When
            # the cursor is mid-line, fall through to overwrite semantics.
            if cursor.atEnd() and '\x08' not in text and '\r' not in text:
                cursor.insertText(text, fmt)
                continue
            # Slow path: honor the two line-local cursor controls the shell's
            # line editor emits, with terminal overwrite semantics. Backspace
            # (0x08) moves the cursor one cell left; a bare carriage return
            # (0x0D) moves it to column 0; a printable character OVERWRITES the
            # cell under the cursor (a real terminal never inserts-and-shifts)
            # and only appends at the end of the line. All of it is bounded to
            # the current line -- a program can never reach an earlier line or
            # the scrollback -- and there is still no vertical or absolute cursor
            # movement, because those arrive as escapes, which are stripped.
            # U+2029 is Qt's block (newline) separator.
            for ch in text:
                if ch == '\n':
                    cursor.movePosition(move.EndOfBlock)
                    cursor.insertText('\n', fmt)
                elif ch == '\r':
                    cursor.movePosition(move.StartOfBlock)
                elif ch == '\x08':
                    probe = QTextCursor(cursor)
                    probe.movePosition(move.Left, keep)
                    sel = probe.selectedText()
                    if sel and ord(sel[0]) != sep:
                        cursor.movePosition(move.Left)
                else:
                    probe = QTextCursor(cursor)
                    probe.movePosition(move.Right, keep)
                    sel = probe.selectedText()
                    if sel and ord(sel[0]) != sep:
                        cursor.movePosition(move.Right, keep)
                        cursor.insertText(ch, fmt)   # overwrite the cell
                    else:
                        cursor.insertText(ch, fmt)   # end of line -> append
        self._out_cursor = cursor
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

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
            if key == Qt.Key.Key_Backslash:
                self._write(b'\x1c')          # Ctrl+\ -> SIGQUIT (cooked)
                return
            if Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
                self._write(bytes([key & 0x1f]))   # Ctrl+C -> 0x03, Ctrl+L -> 0x0c
                if key in (Qt.Key.Key_C, Qt.Key.Key_U):
                    self._line_buffer = ''    # SIGINT / kill-line discards the line
                return

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            # The command hook (if configured) judges the typed line before Enter
            # submits it; it may block, ask, or offer a safer command.
            if self._hook is not None and self._hook_intercept():
                return
            self._line_buffer = ''
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

    def event(self, e):
        # Hovering a reveal badge (<U+XXXX>) explains what the character actually
        # is -- name, category and escape -- because the bare codepoint means
        # nothing to most people. Nothing else needs a tooltip.
        if e.type() == QEvent.Type.ToolTip:
            pos = self.viewport().mapFromGlobal(e.globalPos())
            cursor = self.cursorForPosition(pos)
            col = cursor.positionInBlock()
            text = cursor.block().text()
            for m in _BADGE_RE.finditer(text):
                if m.start() <= col <= m.end():
                    QToolTip.showText(
                        e.globalPos(), describe_codepoint(int(m.group(1), 16)),
                        self)
                    return True
            QToolTip.hideText()
            e.ignore()
            return True
        return super().event(e)

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
