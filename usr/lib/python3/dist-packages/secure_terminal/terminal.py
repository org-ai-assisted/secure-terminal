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

- INPUT forwards printable ASCII and a tiny allowlist of control keys. The
  signal keys deliver a real signal to the foreground process group
  (Ctrl+C -> SIGINT, Ctrl+Z -> SIGTSTP, Ctrl+\\ -> SIGQUIT) so they work even
  against a raw-mode program that would swallow the control byte; Ctrl+D (EOF)
  and Ctrl+L (clear) are written as line-discipline bytes. Still one-directional.
  terminate_foreground() is the guaranteed panic button (SIGTERM then SIGKILL)
  for a program that ignores all of the above.

This is a deliberately minimal, line-oriented terminal by default: TERM is
"dumb" and no escapes are parsed. An opt-in TUI mode (apply_tui) interprets
escapes through a pyte screen model so full-screen programs (ssh, an editor, the
Claude Code CLI) work; even then every cell is still character-filtered and pyte
has no OS reach (it cannot set the title or touch the clipboard). The window
flags TUI mode with a visible risk indicator; the strict line mode remains the
safe-by-construction default.
"""

import os
import pty
import re
import fcntl
import signal
import codecs
import struct
import termios

try:
    import pyte
except ImportError:                      # TUI mode is unavailable without pyte
    pyte = None

from PyQt6.QtCore import QSocketNotifier, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QColor, QPalette, QTextCharFormat
from PyQt6.QtWidgets import QPlainTextEdit

# The pure, Qt-free sanitization core (also tested directly by dist-ai). Names
# are re-exported here so terminal.py stays the single import point for the rest
# of the package (main.py, dialog.py).
from secure_terminal.sanitize import (
    THEMES, BASE_POINT_SIZE, ANSI_PALETTE, DISPLAY_MODES,
    ANSI_RE as _ANSI, SGR_RE as _SGR,
    colors_allowed, too_close, render_output, sanitize_bytes, sanitize_paste,
    paste_findings, parse_sgr, tui_cell,
)


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


class SecureTerminal(QPlainTextEdit):
    # emitted when the child shell exits, so the window can close its tab
    shell_exited = pyqtSignal()
    # Ctrl+wheel over the widget asks the window to zoom by +1/-1 step
    zoom_step = pyqtSignal(int)

    def __init__(self, parent=None, command=None, tui=False):
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

        # optional ANSI colours (off by default); SGR parser state.
        self._colors = False
        self._sgr_reset()

        # scrollback limit in lines (0 = unlimited, the QPlainTextEdit default).
        self._scrollback = 0

        # seconds the paste-warning "Allow" button stays disabled.
        self._paste_delay = 3

        # TUI mode: interpret escapes through a pyte screen so full-screen
        # programs (ssh, Claude Code) work. Off by default; the strict, no-parser
        # line mode above is the safe default.
        self._tui = bool(tui) and tui_available()
        self._command = command
        self._screen = None
        self._stream = None
        self._fmt_cache = {}
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.timeout.connect(self._render_tui)

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

    def current_zoom(self):
        return self._zoom

    def current_theme(self):
        return self._theme

    def apply_mode(self, mode):
        """Set the display mode for non-ASCII output. Affects future output only;
        already-rendered text is left as it was shown."""
        if mode in DISPLAY_MODES:
            self._mode = mode

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
        """Turn TUI mode on/off. Because TERM is fixed at fork time, the shell is
        re-started; a no-op when the state is unchanged or pyte is missing."""
        enabled = bool(enabled) and tui_available()
        if enabled == self._tui:
            return
        self._tui = enabled
        self._restart()

    def current_tui(self):
        return self._tui

    def tui_active(self):
        return getattr(self, '_tui', False) and tui_available()

    def _grid_size(self):
        """Columns and rows that fit the viewport at the current font."""
        metrics = self.fontMetrics()
        char_w = metrics.horizontalAdvance('M') or 1
        char_h = metrics.height() or 1
        vp = self.viewport()
        cols = max(2, vp.width() // char_w)
        rows = max(2, vp.height() // char_h)
        return cols, rows

    def _set_winsize(self, cols, rows):
        if self._fd is None:
            return
        try:
            fcntl.ioctl(self._fd, termios.TIOCSWINSZ,
                        struct.pack('HHHH', rows, cols, 0, 0))
        except OSError:
            pass

    def _make_screen(self):
        cols, rows = self._grid_size()
        self._screen = pyte.Screen(cols, rows)
        self._stream = pyte.ByteStream(self._screen)
        self._set_winsize(cols, rows)

    def _restart(self):
        """Tear down the child and start a fresh one. Used when TUI mode toggles,
        which changes TERM (fixed at fork time)."""
        self.shutdown()
        self.clear()
        self._screen = None
        self._stream = None
        self._fmt_cache = {}
        self._decoder = codecs.getincrementaldecoder('utf-8')('replace')
        self._sgr_reset()
        self._start(self._command)

    def _sync_tui_size(self):
        if not (self.tui_active() and self._screen is not None):
            return
        cols, rows = self._grid_size()
        if (cols, rows) != (self._screen.columns, self._screen.lines):
            self._screen.resize(rows, cols)
        self._set_winsize(cols, rows)
        self._render_timer.start(16)

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
        self._colors = bool(enabled)
        self._sgr_reset()

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
            # child. In line mode advertise a dumb terminal so programs do not
            # emit escape-heavy output; in TUI mode advertise a real terminal so
            # ncurses / Claude Code / a remote shell over ssh drive it properly.
            os.environ['TERM'] = 'xterm-256color' if self._tui else 'dumb'
            os.environ.setdefault('PAGER', 'cat')
            shell = command or os.environ.get('SHELL') or '/bin/bash'
            try:
                os.execvp(shell, [shell])
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
        except (OSError, BlockingIOError):
            return
        if not data:
            if self._notifier is not None:
                self._notifier.setEnabled(False)
            self.shell_exited.emit()
            return
        if self.tui_active() and self._stream is not None:
            self._stream.feed(data)
            if not self._render_timer.isActive():
                self._render_timer.start(16)     # coalesce bursts into ~60fps
            return
        self._append_runs(self._render_runs(self._decoder.decode(data)))

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
                pass
            self._fd = None
        if self._pid:
            try:
                os.kill(self._pid, signal.SIGHUP)
            except OSError:
                pass
            # SIGHUP is asynchronous, so the child may still be alive here; a
            # one-shot waitpid would return (0, 0) and reap nothing. Reaping is
            # therefore left to the process-wide SIGCHLD=SIG_IGN handler (see
            # main.main), which the kernel honors whenever the child does exit.
            # The WNOHANG call only mops up a child that has already died, e.g.
            # when the widget is used without that handler installed.
            try:
                os.waitpid(self._pid, os.WNOHANG)
            except (OSError, ChildProcessError):
                pass
            self._pid = None

    def _append(self, text):
        self._append_runs([(text, None)])

    def _append_runs(self, runs):
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
            # Fast path: ordinary output carries no cursor controls -> append.
            if '\x08' not in text and '\r' not in text:
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
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def _write(self, data):
        if self._fd is None:
            return
        try:
            os.write(self._fd, data)
        except OSError:
            pass

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

    def has_foreground_program(self):
        """True when a program other than the shell holds the foreground, i.e.
        there is something for Terminate to act on."""
        pgrp = self._foreground_pgrp()
        if pgrp is None:
            return False
        if self._pid is not None and pgrp == os.getpgid(self._pid):
            return False
        return True

    def signal_foreground(self, sig):
        """Send a signal to the foreground process group so it takes effect even
        against a raw-mode program that would ignore the control byte."""
        pgrp = self._foreground_pgrp()
        if pgrp is None:
            return
        try:
            os.killpg(pgrp, sig)
        except OSError:
            pass

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
                pass
        QTimer.singleShot(2000, _kill_survivor)
        return True

    # -- input: printable ASCII + signal-key allowlist ------------------------
    _TUI_KEYS = None      # built lazily below (needs Qt.Key at call time)

    def keyPressEvent(self, event):
        key = event.key()
        mods = event.modifiers()
        ctrl = mods & Qt.KeyboardModifier.ControlModifier
        shift = mods & Qt.KeyboardModifier.ShiftModifier

        # In TUI mode the running program owns the keyboard: Ctrl+Shift+<key>
        # still reaches the window shortcuts, but everything else is encoded as
        # VT input (arrows, function keys, control bytes) and sent raw.
        if self.tui_active() and not (ctrl and shift):
            self._tui_key(event)
            return

        # Ctrl+Shift+<key> is reserved for the window (copy/paste, new/close tab,
        # zoom); let those fall through to the QAction shortcuts.
        if ctrl and not shift:
            # The signal keys deliver a REAL signal to the terminal's foreground
            # process group, not just the control byte. In cooked mode the effect
            # is the same, but a program in raw mode (nano, less, a pager) reads
            # the byte as an ordinary keystroke and would never be interrupted;
            # the signal reaches it regardless. Still one-directional.
            sig_map = {
                Qt.Key.Key_C: signal.SIGINT,
                Qt.Key.Key_Z: signal.SIGTSTP,
                Qt.Key.Key_Backslash: signal.SIGQUIT,
            }
            # EOF and clear are line-discipline bytes, not signals.
            byte_map = {
                Qt.Key.Key_D: b'\x04',        # EOF
                Qt.Key.Key_L: b'\x0c',        # form feed (clear)
            }
            if key in sig_map:
                self.signal_foreground(sig_map[key])
                return
            if key in byte_map:
                self._write(byte_map[key])
                return

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._write(b'\r')
            return
        if key == Qt.Key.Key_Backspace:
            self._write(b'\x7f')
            return
        if key == Qt.Key.Key_Tab:
            self._write(b'\t')
            return

        text = event.text()
        if text and all(0x20 <= ord(c) <= 0x7E for c in text):
            self._write(text.encode('ascii'))
        # non-ASCII input and arrow/navigation keys are intentionally ignored

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
        if text and all(0x20 <= ord(c) <= 0x7E for c in text):
            self._write((b'\x1b' if alt else b'') + text.encode('ascii'))
        # non-ASCII input is still dropped

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_tui_size()

    # -- paste: warn on, then sanitize, anything unusual ----------------------
    def insertFromMimeData(self, source):
        raw = source.text()
        # A plain-ASCII paste goes straight through; only warn when the clipboard
        # carries unicode or control characters -- the case worth a second look.
        has_unicode, has_control = paste_findings(raw)
        if has_unicode or has_control:
            from secure_terminal.dialog import PasteWarningDialog
            if not PasteWarningDialog.confirm(raw, self._paste_delay, self):
                return
        safe = sanitize_paste(raw)
        if not safe:
            return
        data = safe.encode('ascii')
        # Bracketed paste when the TUI program asked for it (DEC mode 2004), so a
        # multi-line paste is delivered as data, not interpreted as keystrokes.
        if self.tui_active() and self._screen is not None \
                and 2004 in getattr(self._screen, 'mode', ()):
            data = b'\x1b[200~' + data + b'\x1b[201~'
        self._write(data)
