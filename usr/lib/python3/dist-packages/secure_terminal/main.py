## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Application entry point and main window for secure-terminal."""

import signal
import sys

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtGui import QAction, QActionGroup, QKeySequence, QIcon
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

        # Global defaults inherited by every NEW tab; each tab then carries its
        # own theme and zoom, which the chrome below reflects and edits.
        self._default_theme = 'dark'
        self._default_zoom = 100

        self.tabs = QTabWidget(self)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._sync_chrome_to_tab)
        self.setCentralWidget(self.tabs)

        self._theme_actions = {}
        self._build_menu()
        self._build_toolbar()
        self.new_tab()

        # Enable Terminate only while a program (not just the shell) is running.
        # There is no event for a foreground-pgrp change, so poll cheaply.
        self._fg_poll = QTimer(self)
        self._fg_poll.timeout.connect(self._update_terminate_enabled)
        self._fg_poll.start(400)
        self._update_terminate_enabled()

    # -- tabs, each its own shell over its own pseudo-terminal -----------------
    def new_tab(self):
        term = SecureTerminal()
        term.apply_theme(self._default_theme)
        term.apply_zoom(self._default_zoom)
        term.zoom_step.connect(self._on_zoom_step)
        term.shell_exited.connect(lambda t=term: self._on_shell_exited(t))
        index = self.tabs.addTab(term, 'shell')
        self.tabs.setCurrentIndex(index)
        self._sync_chrome_to_tab()
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

    def terminate_foreground(self):
        term = self.current()
        if term is not None:
            term.terminate_foreground()

    def _update_terminate_enabled(self):
        term = self.current()
        self.act_terminate.setEnabled(
            term is not None and term.has_foreground_program())

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

    # -- keep the toolbar/menu showing the CURRENT tab's theme and zoom -------
    def _sync_chrome_to_tab(self, *_args):
        term = self.current()
        if term is None:
            return
        self.zoom_box.blockSignals(True)
        self.zoom_box.setValue(term.current_zoom())
        self.zoom_box.blockSignals(False)
        active = term.current_theme()
        for key, action in self._theme_actions.items():
            action.setChecked(key == active)
        self._update_terminate_enabled()

    # -- zoom: per current tab ------------------------------------------------
    def set_zoom(self, percent):
        percent = max(ZOOM_MIN, min(ZOOM_MAX, int(percent)))
        term = self.current()
        if term is not None:
            term.apply_zoom(percent)
        self.zoom_box.blockSignals(True)
        self.zoom_box.setValue(percent)
        self.zoom_box.blockSignals(False)

    def _on_zoom_step(self, direction):
        term = self.current()
        if term is not None:
            self.set_zoom(term.current_zoom() + direction * ZOOM_STEP)

    def zoom_in(self):
        term = self.current()
        if term is not None:
            self.set_zoom(term.current_zoom() + ZOOM_STEP)

    def zoom_out(self):
        term = self.current()
        if term is not None:
            self.set_zoom(term.current_zoom() - ZOOM_STEP)

    def zoom_reset(self):
        self.set_zoom(100)

    # -- theme: per current tab -----------------------------------------------
    def set_theme(self, theme):
        term = self.current()
        if term is not None:
            term.apply_theme(theme)

    # -- chrome ---------------------------------------------------------------
    def _build_menu(self):
        bar = self.menuBar()

        file_menu = bar.addMenu('&File')
        self.act_new = QAction(QIcon.fromTheme('tab-new'), 'New &Tab', self)
        self.act_new.setShortcut(QKeySequence('Ctrl+Shift+T'))
        self.act_new.triggered.connect(self.new_tab)
        file_menu.addAction(self.act_new)

        self.act_close = QAction(QIcon.fromTheme('window-close'),
                                 '&Close Tab', self)
        self.act_close.setShortcut(QKeySequence('Ctrl+Shift+W'))
        self.act_close.triggered.connect(
            lambda: self.close_tab(self.tabs.currentIndex()))
        file_menu.addAction(self.act_close)

        file_menu.addSeparator()
        self.act_terminate = QAction(QIcon.fromTheme('process-stop'),
                                     '&Terminate Program', self)
        self.act_terminate.setShortcut(QKeySequence('Ctrl+Shift+K'))
        self.act_terminate.setToolTip(
            'Force-terminate the running program (SIGTERM, then SIGKILL). '
            'Use when Ctrl+C and Ctrl+\\ are ignored, e.g. a stuck full-screen '
            'program.')
        self.act_terminate.triggered.connect(self.terminate_foreground)
        file_menu.addAction(self.act_terminate)

        file_menu.addSeparator()
        act_quit = QAction(QIcon.fromTheme('application-exit'), '&Quit', self)
        act_quit.setShortcut(QKeySequence('Ctrl+Q'))
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        edit_menu = bar.addMenu('&Edit')
        self.act_copy = QAction(QIcon.fromTheme('edit-copy'), '&Copy', self)
        self.act_copy.setShortcut(QKeySequence('Ctrl+Shift+C'))
        self.act_copy.triggered.connect(self.copy_selection)
        edit_menu.addAction(self.act_copy)

        self.act_paste = QAction(QIcon.fromTheme('edit-paste'), '&Paste', self)
        self.act_paste.setShortcut(QKeySequence('Ctrl+Shift+V'))
        self.act_paste.triggered.connect(self.paste_clipboard)
        edit_menu.addAction(self.act_paste)

        view_menu = bar.addMenu('&View')
        act_zin = QAction(QIcon.fromTheme('zoom-in'), 'Zoom &In', self)
        act_zin.setShortcut(QKeySequence.StandardKey.ZoomIn)
        act_zin.triggered.connect(self.zoom_in)
        view_menu.addAction(act_zin)

        act_zout = QAction(QIcon.fromTheme('zoom-out'), 'Zoom &Out', self)
        act_zout.setShortcut(QKeySequence.StandardKey.ZoomOut)
        act_zout.triggered.connect(self.zoom_out)
        view_menu.addAction(act_zout)

        act_zreset = QAction(QIcon.fromTheme('zoom-original'),
                             '&Reset Zoom', self)
        act_zreset.setShortcut(QKeySequence('Ctrl+0'))
        act_zreset.triggered.connect(self.zoom_reset)
        view_menu.addAction(act_zreset)

        view_menu.addSeparator()
        theme_menu = view_menu.addMenu('&Theme')
        group = QActionGroup(self)
        group.setExclusive(True)
        for label, key in THEME_LABELS:
            act = QAction(label, self, checkable=True)
            act.setChecked(key == self._default_theme)
            act.triggered.connect(lambda _checked, k=key: self.set_theme(k))
            group.addAction(act)
            theme_menu.addAction(act)
            self._theme_actions[key] = act

    def _build_toolbar(self):
        bar = QToolBar('Main', self)
        bar.setMovable(False)
        bar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.addToolBar(bar)

        bar.addAction(self.act_new)
        bar.addSeparator()
        bar.addAction(self.act_copy)
        bar.addAction(self.act_paste)
        bar.addSeparator()
        bar.addAction(self.act_terminate)

        spacer = QWidget(bar)
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding,
                             QSizePolicy.Policy.Preferred)
        bar.addWidget(spacer)

        bar.addWidget(QLabel('Zoom ', bar))
        self.zoom_box = QSpinBox(bar)
        self.zoom_box.setRange(ZOOM_MIN, ZOOM_MAX)
        self.zoom_box.setSingleStep(ZOOM_STEP)
        self.zoom_box.setSuffix('%')
        self.zoom_box.setValue(self._default_zoom)
        self.zoom_box.setToolTip('Text size of the current tab (Up/Down or type '
                                 'a value; Ctrl+wheel over the terminal)')
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
