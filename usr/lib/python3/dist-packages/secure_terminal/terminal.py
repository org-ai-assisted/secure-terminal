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

This is a deliberately minimal, line-oriented terminal. It is not a curses host:
TERM is advertised as "dumb", and full-screen TUIs (nano, vim, emacs) are out of
scope by design, because supporting them means parsing exactly the escape
sequences this terminal exists to refuse.
"""

import os
import pty
import re
import fcntl
import signal
import codecs

from PyQt6.QtCore import QSocketNotifier, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QColor, QPalette, QTextCharFormat
from PyQt6.QtWidgets import QPlainTextEdit

# Standard 16-colour ANSI palette (xterm-ish); indexes 0-7 normal, 8-15 bright.
ANSI_PALETTE = [
    '#000000', '#cd0000', '#00cd00', '#cdcd00',
    '#0000ee', '#cd00cd', '#00cdcd', '#e5e5e5',
    '#7f7f7f', '#ff0000', '#00ff00', '#ffff00',
    '#5c5cff', '#ff00ff', '#00ffff', '#ffffff',
]


def colors_allowed():
    """False when the environment says never colour -- NO_COLOR is set (per the
    no-color.org spec: presence, any value) or the outer TERM is 'dumb'. Colours
    are opt-in per tab anyway; this lets the environment force them off."""
    if os.environ.get('NO_COLOR'):
        return False
    if os.environ.get('TERM', '') == 'dumb':
        return False
    return True


def _luminance(color):
    return 0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()


def _too_close(a, b):
    """True when two colours are so close that text would be near-invisible --
    the guard that stops a program painting black-on-black. Kept low so ordinary
    colours (e.g. red on a near-black background) are still allowed; it only
    catches genuinely unreadable, deceptive combinations."""
    return abs(_luminance(a) - _luminance(b)) < 30

# name -> (background, foreground). "dark" is white-on-black, "light" is the
# reverse; both are plain, high-contrast, no syntax coloring.
THEMES = {
    'dark':  ('#14161b', '#e6e6e6'),
    'light': ('#ffffff', '#1a1a1a'),
}
BASE_POINT_SIZE = 11

# How non-ASCII / unsafe content in program OUTPUT is shown:
#   'strip'  -- replace with '_' (default, safe), as sanitize-string/stcat do.
#   'show'   -- render a non-ASCII character as its glyph when it is printable
#               (str.isprintable() excludes the invisible, bidi and format
#               characters that make unicode deceptive), so a log with useful
#               unicode is readable; control still becomes '_'.
#   'reveal' -- replace with a visible <U+XXXX> codepoint badge, to inspect.
DISPLAY_MODES = ('strip', 'show', 'reveal')

# CSI (ESC [ ...), OSC (ESC ] ... BEL/ST) and other two-byte escapes.
_ANSI = re.compile(
    r'\x1b\[[0-9;?]*[ -/]*[@-~]'
    r'|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?'
    r'|\x1b[@-Z\\-_]'
)

# SGR: ESC [ <params> m -- the only escape sequence honored, and only when
# colours are enabled. Everything else is still stripped.
_SGR = re.compile(r'\x1b\[([0-9;]*)m')


def render_output(text, mode='strip'):
    """Turn decoded child output into safe display text under one display mode.
    Escape sequences are always removed (there is no ANSI parser). Printable
    ASCII, tab and newline, and the two interactive cursor controls backspace
    (0x08) and carriage return (0x0D) always pass through -- _append() honors the
    latter two as line-local edits. Everything else is handled per `mode`
    (see DISPLAY_MODES)."""
    text = _ANSI.sub('', text)
    out = []
    for ch in text:
        cp = ord(ch)
        if cp in (0x08, 0x09, 0x0A, 0x0D) or 0x20 <= cp <= 0x7E:
            out.append(ch)
        elif mode == 'reveal':
            out.append('<U+%04X>' % cp)
        elif mode == 'show' and cp >= 0x80 and ch.isprintable():
            out.append(ch)
        else:
            out.append('_')
    return ''.join(out)


def sanitize_bytes(data, mode='strip'):
    """Convenience wrapper: decode raw bytes 1:1 (latin-1) and render. Used by
    tests and any all-ASCII path; the live output stream in _on_readable uses an
    incremental UTF-8 decoder so multi-byte characters survive read boundaries."""
    return render_output(data.decode('latin-1'), mode)


def sanitize_paste(text):
    """Strip a pasted string to printable ASCII; newlines become carriage returns."""
    out = []
    for ch in text:
        cp = ord(ch)
        if ch == '\n' or ch == '\r':
            out.append('\r')
        elif ch == '\t' or 0x20 <= cp <= 0x7E:
            out.append(ch)
        # everything else (invisible, bidi, homoglyph, control) is dropped
    return ''.join(out)


class SecureTerminal(QPlainTextEdit):
    # emitted when the child shell exits, so the window can close its tab
    shell_exited = pyqtSignal()
    # Ctrl+wheel over the widget asks the window to zoom by +1/-1 step
    zoom_step = pyqtSignal(int)

    def __init__(self, parent=None, command=None):
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

    def apply_zoom(self, percent):
        percent = max(10, min(1000, int(percent)))
        self._zoom = percent
        size = max(1, round(self._base_point_size * percent / 100.0))
        font = self.font()
        font.setPointSize(size)
        self.setFont(font)

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

    # -- optional ANSI colours ------------------------------------------------
    def apply_colors(self, enabled):
        self._colors = bool(enabled)
        self._sgr_reset()

    def colors_enabled(self):
        return self._colors

    def _effective_colors(self):
        return self._colors and colors_allowed()

    def _sgr_reset(self):
        self._sgr_fg = None      # palette index, or None for the default
        self._sgr_bg = None
        self._sgr_bold = False

    def _apply_sgr(self, param_str):
        nums = [int(p) if p.isdigit() else 0
                for p in (param_str.split(';') if param_str else ['0'])]
        i = 0
        while i < len(nums):
            n = nums[i]
            if n == 0:
                self._sgr_reset()
            elif n == 1:
                self._sgr_bold = True
            elif n == 22:
                self._sgr_bold = False
            elif 30 <= n <= 37:
                self._sgr_fg = n - 30
            elif 90 <= n <= 97:
                self._sgr_fg = n - 90 + 8
            elif n == 39:
                self._sgr_fg = None
            elif 40 <= n <= 47:
                self._sgr_bg = n - 40
            elif 100 <= n <= 107:
                self._sgr_bg = n - 100 + 8
            elif n == 49:
                self._sgr_bg = None
            elif n in (38, 48):
                # 8-bit (5;n) and 24-bit (2;r;g;b) colours: consume the extra
                # parameters and fall back to the default (not in the safe set).
                if i + 1 < len(nums) and nums[i + 1] == 5:
                    i += 2
                elif i + 1 < len(nums) and nums[i + 1] == 2:
                    i += 4
            i += 1

    def _current_format(self):
        """Build the QTextCharFormat for the current SGR state, guarding against
        an unreadable foreground/background combination."""
        fmt = QTextCharFormat()
        if self._sgr_fg is None and self._sgr_bg is None and not self._sgr_bold:
            return fmt
        base_bg, base_fg = THEMES.get(self._theme, THEMES['dark'])
        fg = QColor(ANSI_PALETTE[self._sgr_fg]) if self._sgr_fg is not None \
            else QColor(base_fg)
        bg = QColor(ANSI_PALETTE[self._sgr_bg]) if self._sgr_bg is not None \
            else None
        eff_bg = bg if bg is not None else QColor(base_bg)
        if _too_close(fg, eff_bg):
            fg = QColor(base_fg)          # never let the text vanish
            if bg is not None and _too_close(fg, bg):
                bg = None                 # base text collides with the bg -> drop it
        fmt.setForeground(fg)
        if bg is not None:
            fmt.setBackground(bg)
        if self._sgr_bold:
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
            # child
            os.environ['TERM'] = 'dumb'          # discourage escape-heavy output
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
    def keyPressEvent(self, event):
        key = event.key()
        mods = event.modifiers()
        ctrl = mods & Qt.KeyboardModifier.ControlModifier
        shift = mods & Qt.KeyboardModifier.ShiftModifier

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

    # -- paste: sanitize before it reaches the shell --------------------------
    def insertFromMimeData(self, source):
        safe = sanitize_paste(source.text())
        if safe:
            self._write(safe.encode('ascii'))
