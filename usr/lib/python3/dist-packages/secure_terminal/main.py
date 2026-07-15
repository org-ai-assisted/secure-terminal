## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Application entry point and main window for secure-terminal."""

import signal
import sys

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QAction, QActionGroup, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QToolBar, QSpinBox, QLabel,
    QWidget, QSizePolicy,
)

from secure_terminal.terminal import SecureTerminal

ZOOM_MIN = 25
ZOOM_MAX = 400
ZOOM_STEP = 10

# menu label -> theme key in terminal.THEMES
THEME_LABELS = [
    ('Dark (white on black)', 'dark'),
    ('Light (black on white)', 'light'),
]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('secure-terminal')
        self.resize(820, 520)

        self._zoom = 100
        self._theme = 'dark'

        self.tabs = QTabWidget(self)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.setCentralWidget(self.tabs)

        self._build_menu()
        self._build_toolbar()
        self.new_tab()

    # -- tabs, each its own shell over its own pseudo-terminal -----------------
    def new_tab(self):
        term = SecureTerminal()
        term.apply_theme(self._theme)
        term.apply_zoom(self._zoom)
        term.zoom_step.connect(self._on_zoom_step)
        term.shell_exited.connect(lambda t=term: self._on_shell_exited(t))
        index = self.tabs.addTab(term, 'shell')
        self.tabs.setCurrentIndex(index)
        term.setFocus()

    def close_tab(self, index):
        term = self.tabs.widget(index)
        if term is None:
            return
        term.shutdown()
        self.tabs.removeTab(index)
        term.deleteLater()
        if self.tabs.count() == 0:
            self.close()

    def _on_shell_exited(self, term):
        index = self.tabs.indexOf(term)
        if index != -1:
            self.close_tab(index)

    def current(self):
        return self.tabs.currentWidget()

    # -- copy / paste route through the current tab (paste stays sanitized) ----
    def copy_selection(self):
        term = self.current()
        if term is not None:
            term.copy()

    def paste_clipboard(self):
        term = self.current()
        if term is not None:
            term.paste()
            term.setFocus()

    # -- zoom -----------------------------------------------------------------
    def set_zoom(self, percent):
        percent = max(ZOOM_MIN, min(ZOOM_MAX, int(percent)))
        self._zoom = percent
        for i in range(self.tabs.count()):
            self.tabs.widget(i).apply_zoom(percent)
        self.zoom_box.blockSignals(True)
        self.zoom_box.setValue(percent)
        self.zoom_box.blockSignals(False)

    def _on_zoom_step(self, direction):
        self.set_zoom(self._zoom + direction * ZOOM_STEP)

    def zoom_in(self):
        self.set_zoom(self._zoom + ZOOM_STEP)

    def zoom_out(self):
        self.set_zoom(self._zoom - ZOOM_STEP)

    def zoom_reset(self):
        self.set_zoom(100)

    # -- theme ----------------------------------------------------------------
    def set_theme(self, theme):
        self._theme = theme
        for i in range(self.tabs.count()):
            self.tabs.widget(i).apply_theme(theme)

    # -- chrome ---------------------------------------------------------------
    def _build_menu(self):
        bar = self.menuBar()

        file_menu = bar.addMenu('&File')
        act_new = QAction('New &Tab', self)
        act_new.setShortcut(QKeySequence('Ctrl+Shift+T'))
        act_new.triggered.connect(self.new_tab)
        file_menu.addAction(act_new)

        act_close = QAction('&Close Tab', self)
        act_close.setShortcut(QKeySequence('Ctrl+Shift+W'))
        act_close.triggered.connect(
            lambda: self.close_tab(self.tabs.currentIndex()))
        file_menu.addAction(act_close)

        file_menu.addSeparator()
        act_quit = QAction('&Quit', self)
        act_quit.setShortcut(QKeySequence('Ctrl+Q'))
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        edit_menu = bar.addMenu('&Edit')
        self.act_copy = QAction('&Copy', self)
        self.act_copy.setShortcut(QKeySequence('Ctrl+Shift+C'))
        self.act_copy.triggered.connect(self.copy_selection)
        edit_menu.addAction(self.act_copy)

        self.act_paste = QAction('&Paste', self)
        self.act_paste.setShortcut(QKeySequence('Ctrl+Shift+V'))
        self.act_paste.triggered.connect(self.paste_clipboard)
        edit_menu.addAction(self.act_paste)

        view_menu = bar.addMenu('&View')
        act_zin = QAction('Zoom &In', self)
        act_zin.setShortcut(QKeySequence.StandardKey.ZoomIn)
        act_zin.triggered.connect(self.zoom_in)
        view_menu.addAction(act_zin)

        act_zout = QAction('Zoom &Out', self)
        act_zout.setShortcut(QKeySequence.StandardKey.ZoomOut)
        act_zout.triggered.connect(self.zoom_out)
        view_menu.addAction(act_zout)

        act_zreset = QAction('&Reset Zoom', self)
        act_zreset.setShortcut(QKeySequence('Ctrl+0'))
        act_zreset.triggered.connect(self.zoom_reset)
        view_menu.addAction(act_zreset)

        view_menu.addSeparator()
        theme_menu = view_menu.addMenu('&Theme')
        group = QActionGroup(self)
        group.setExclusive(True)
        for label, key in THEME_LABELS:
            act = QAction(label, self, checkable=True)
            act.setChecked(key == self._theme)
            act.triggered.connect(lambda _checked, k=key: self.set_theme(k))
            group.addAction(act)
            theme_menu.addAction(act)

    def _build_toolbar(self):
        bar = QToolBar('Main', self)
        bar.setMovable(False)
        self.addToolBar(bar)

        bar.addAction(self.act_copy)
        bar.addAction(self.act_paste)

        spacer = QWidget(bar)
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding,
                             QSizePolicy.Policy.Preferred)
        bar.addWidget(spacer)

        bar.addWidget(QLabel('Zoom ', bar))
        self.zoom_box = QSpinBox(bar)
        self.zoom_box.setRange(ZOOM_MIN, ZOOM_MAX)
        self.zoom_box.setSingleStep(ZOOM_STEP)
        self.zoom_box.setSuffix('%')
        self.zoom_box.setValue(self._zoom)
        self.zoom_box.setToolTip('Text size (Up/Down or type a value; '
                                 'Ctrl+wheel over the terminal)')
        self.zoom_box.valueChanged.connect(self.set_zoom)
        bar.addWidget(self.zoom_box)

    # -- lifecycle ------------------------------------------------------------
    def closeEvent(self, event):
        for i in range(self.tabs.count()):
            self.tabs.widget(i).shutdown()
        super().closeEvent(event)


def _install_signal_quit(app):
    """Terminate on the usual signals from the launching terminal: Ctrl+C
    (SIGINT), plus SIGTERM and SIGHUP. Qt's C++ event loop does not deliver
    Python signal handlers on its own, so a periodic no-op timer wakes it often
    enough for the handler to run."""
    def handler(_signum, _frame):
        app.quit()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, handler)
        except (OSError, ValueError, AttributeError):
            pass
    wake = QTimer(app)
    wake.timeout.connect(lambda: None)
    wake.start(200)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('secure-terminal')
    _install_signal_quit(app)

    # Auto-reap exited shells so closing a tab (which hangs up the child
    # asynchronously) cannot leave a defunct process behind: on Linux, ignoring
    # SIGCHLD makes the kernel reap children itself. We never wait() on a child
    # for its status; a tab notices its shell ended from EOF on the pty, not a
    # wait, so this does not race with anything.
    try:
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    except (OSError, ValueError, AttributeError):
        pass

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
