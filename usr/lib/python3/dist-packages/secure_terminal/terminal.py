## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
The secure-terminal widget.

Design (see https://secure-terminal.github.io):

- DISPLAY is printable-ASCII only. Program output is passed through sanitize():
  ANSI/OSC escape sequences are removed and every byte that is not printable
  ASCII (plus tab, newline and backspace) is dropped. There is no escape parser,
  so a hostile filename, a forged status line or a Trojan-Source comment cannot
  redraw or reorder what you read. Backspace is the single exception, and a
  necessary one: the interactive shell echoes its line editing as backspaces
  (readline sends "\b \b" to rub out a character, and uses backspaces to redraw
  after tab-completion and history recall) regardless of the pty's echo flag, so
  a terminal that dropped them could not display line editing at all. We honor a
  backspace as a destructive cursor-left, bounded to the current line: it can
  never reach an earlier line or the scrollback. The residual is that a program
  which prints its own backspaces can rewrite text WITHIN the line it is on
  (e.g. "bad\b\b\bok" shows "ok"); this is far narrower than cursor addressing
  and cannot touch already-committed lines, but it is the one lie this terminal
  cannot fully refuse without breaking interactive editing.

- PASTE is sanitized the same way before it reaches the shell, so invisible or
  bidi characters copied from a web page never enter your command line.

- INPUT forwards printable ASCII and a tiny allowlist of control keys that the
  pseudo-terminal line discipline turns into signals:
    Ctrl+C -> SIGINT, Ctrl+Z -> SIGTSTP, Ctrl+\\ -> SIGQUIT, Ctrl+D -> EOF.
  We only write the control byte; the kernel does the rest. One-directional.

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

from PyQt6.QtCore import QSocketNotifier, Qt, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor, QColor, QPalette
from PyQt6.QtWidgets import QPlainTextEdit

# name -> (background, foreground). "dark" is white-on-black, "light" is the
# reverse; both are plain, high-contrast, no syntax coloring.
THEMES = {
    'dark':  ('#14161b', '#e6e6e6'),
    'light': ('#ffffff', '#1a1a1a'),
}
BASE_POINT_SIZE = 11

# CSI (ESC [ ...), OSC (ESC ] ... BEL/ST) and other two-byte escapes.
_ANSI = re.compile(
    rb'\x1b\[[0-9;?]*[ -/]*[@-~]'
    rb'|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?'
    rb'|\x1b[@-Z\\-_]'
)


def sanitize_bytes(data):
    """Return printable-ASCII text (plus tab/newline/backspace) from raw terminal
    bytes. Backspace (0x08) is kept because the shell's line editor emits it to
    erase a character; _append() honors it as a destructive cursor-left. It is
    the one control effect we interpret, and it stays inside the current line."""
    data = _ANSI.sub(b'', data)
    kept = bytes(b for b in data if b in (0x08, 0x09, 0x0A) or 0x20 <= b <= 0x7E)
    return kept.decode('ascii', 'ignore')


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
        self._append(sanitize_bytes(data))

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
        if not text:
            return
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        # Honor backspace (0x08) as a destructive cursor-left so the shell's line
        # editor can rub out a character (readline echoes "\b \b" to erase one).
        # We never cross a line boundary, so it cannot rewrite earlier output the
        # way an escape sequence could; U+2029 is Qt's block/newline separator.
        parts = text.split('\x08')
        cursor.insertText(parts[0])
        for part in parts[1:]:
            probe = QTextCursor(cursor)
            probe.movePosition(QTextCursor.MoveOperation.Left,
                               QTextCursor.MoveMode.KeepAnchor)
            sel = probe.selectedText()
            if sel and ord(sel[0]) not in (0x0A, 0x2029):
                probe.removeSelectedText()
                cursor = probe
            cursor.insertText(part)
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

    def _write(self, data):
        if self._fd is None:
            return
        try:
            os.write(self._fd, data)
        except OSError:
            pass

    # -- input: printable ASCII + signal-key allowlist ------------------------
    def keyPressEvent(self, event):
        key = event.key()
        mods = event.modifiers()
        ctrl = mods & Qt.KeyboardModifier.ControlModifier
        shift = mods & Qt.KeyboardModifier.ShiftModifier

        # Ctrl+Shift+<key> is reserved for the window (copy/paste, new/close tab,
        # zoom); let those fall through to the QAction shortcuts.
        if ctrl and not shift:
            mapping = {
                Qt.Key.Key_C: b'\x03',        # SIGINT
                Qt.Key.Key_Z: b'\x1a',        # SIGTSTP
                Qt.Key.Key_Backslash: b'\x1c',  # SIGQUIT
                Qt.Key.Key_D: b'\x04',        # EOF
                Qt.Key.Key_L: b'\x0c',        # form feed (clear)
            }
            if key in mapping:
                self._write(mapping[key])
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
