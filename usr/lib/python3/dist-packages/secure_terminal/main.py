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
    QWidget, QSizePolicy, QComboBox, QFileDialog,
)

from secure_terminal import settings
from secure_terminal.terminal import SecureTerminal, THEMES, DISPLAY_MODES

ZOOM_MIN = 25
ZOOM_MAX = 400
ZOOM_STEP = 10

# menu label -> theme key in terminal.THEMES
THEME_LABELS = [
    ('Dark (white on black)', 'dark'),
    ('Light (black on white)', 'light'),
]

# menu / combo label -> display-mode key in terminal.DISPLAY_MODES
MODE_LABELS = [
    ('Strip unicode (safe)', 'strip'),
    ('Show unicode', 'show'),
    ('Reveal unicode', 'reveal'),
]

# menu label -> scrollback limit in lines (0 = unlimited)
SCROLLBACK_CHOICES = [
    ('1,000 lines', 1000),
    ('10,000 lines', 10000),
    ('100,000 lines', 100000),
    ('Unlimited', 0),
]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('secure-terminal')
        self.resize(820, 520)

        # Global defaults inherited by every NEW tab; each tab then carries its
        # own theme and zoom, which the chrome below reflects and edits.
        # Global defaults, loaded from ~/.config; each is validated so a hand-
        # edited or stale config can never crash or set a bogus value. Changing
        # any of them (below) updates the default and re-persists.
        cfg = settings.load()
        self._default_theme = cfg.get('theme') if cfg.get('theme') in THEMES \
            else 'dark'
        self._default_mode = cfg.get('unicode_mode') \
            if cfg.get('unicode_mode') in DISPLAY_MODES else 'strip'
        self._default_colors = cfg.get('colors') == 'true'
        try:
            self._default_zoom = max(ZOOM_MIN, min(ZOOM_MAX, int(cfg['zoom'])))
        except (KeyError, ValueError):
            self._default_zoom = 100
        valid_scrollback = {lines for _, lines in SCROLLBACK_CHOICES}
        try:
            self._scrollback = int(cfg['scrollback'])
            if self._scrollback not in valid_scrollback:
                self._scrollback = 0
        except (KeyError, ValueError):
            self._scrollback = 0

        self.tabs = QTabWidget(self)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._sync_chrome_to_tab)
        self.setCentralWidget(self.tabs)

        self._theme_actions = {}
        self._mode_actions = {}
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
        term.apply_mode(self._default_mode)
        term.apply_colors(self._default_colors)
        term.apply_scrollback(self._scrollback)
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
        mode = term.current_mode()
        for key, action in self._mode_actions.items():
            action.setChecked(key == mode)
        self.mode_box.blockSignals(True)
        self.mode_box.setCurrentIndex(self.mode_box.findData(mode))
        self.mode_box.blockSignals(False)
        self.act_colors.setChecked(term.colors_enabled())
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
        self._default_zoom = percent
        self._persist()

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
        self._default_theme = theme
        self._persist()

    # -- unicode display mode: per current tab --------------------------------
    def set_mode(self, mode):
        term = self.current()
        if term is not None:
            term.apply_mode(mode)
        # keep menu + combo in agreement whichever was used
        for key, action in self._mode_actions.items():
            action.setChecked(key == mode)
        self.mode_box.blockSignals(True)
        self.mode_box.setCurrentIndex(self.mode_box.findData(mode))
        self.mode_box.blockSignals(False)
        self._default_mode = mode
        self._persist()

    def _on_mode_box(self, index):
        self.set_mode(self.mode_box.itemData(index))

    def set_colors(self, enabled):
        term = self.current()
        if term is not None:
            term.apply_colors(enabled)
        self.act_colors.setChecked(enabled)
        self._default_colors = bool(enabled)
        self._persist()

    def set_scrollback(self, lines):
        self._scrollback = int(lines)
        for i in range(self.tabs.count()):
            self.tabs.widget(i).apply_scrollback(lines)
        self._persist()

    def save_transcript(self):
        term = self.current()
        if term is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, 'Save Transcript', 'secure-terminal-transcript.txt',
            'Text files (*.txt);;All files (*)')
        if not path:
            return
        # The buffer is already sanitized plain ASCII, so the saved file is safe
        # to open anywhere -- unlike a normal terminal's raw log.
        try:
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(term.toPlainText())
        except OSError:
            pass

    def _persist(self):
        settings.save({
            'theme': self._default_theme,
            'zoom': str(self._default_zoom),
            'unicode_mode': self._default_mode,
            'colors': 'true' if self._default_colors else 'false',
            'scrollback': str(self._scrollback),
        })

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

        self.act_save = QAction(QIcon.fromTheme('document-save'),
                                '&Save Transcript...', self)
        self.act_save.setShortcut(QKeySequence('Ctrl+Shift+S'))
        self.act_save.setToolTip(
            'Save this tab\'s scrollback to a file. It is already sanitized '
            'plain ASCII, so the saved file is safe to open anywhere.')
        self.act_save.triggered.connect(self.save_transcript)
        file_menu.addAction(self.act_save)

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

        mode_menu = view_menu.addMenu('&Unicode')
        mode_group = QActionGroup(self)
        mode_group.setExclusive(True)
        for label, key in MODE_LABELS:
            act = QAction(label, self, checkable=True)
            act.setChecked(key == self._default_mode)
            act.triggered.connect(lambda _checked, k=key: self.set_mode(k))
            mode_group.addAction(act)
            mode_menu.addAction(act)
            self._mode_actions[key] = act

        view_menu.addSeparator()
        self.act_colors = QAction('Ansi &Colors', self, checkable=True)
        self.act_colors.setChecked(self._default_colors)
        self.act_colors.setToolTip(
            'Render a safe subset of ANSI colors (16-color SGR) in the current '
            'tab. Off by default; contrast-guarded so text can never be painted '
            'invisibly, and forced off by NO_COLOR or TERM=dumb.')
        self.act_colors.toggled.connect(self.set_colors)
        view_menu.addAction(self.act_colors)

        view_menu.addSeparator()
        sb_menu = view_menu.addMenu('&Scrollback')
        sb_group = QActionGroup(self)
        sb_group.setExclusive(True)
        for label, lines in SCROLLBACK_CHOICES:
            act = QAction(label, self, checkable=True)
            act.setChecked(lines == self._scrollback)
            act.triggered.connect(lambda _checked, n=lines: self.set_scrollback(n))
            sb_group.addAction(act)
            sb_menu.addAction(act)

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

        bar.addWidget(QLabel('Unicode ', bar))
        self.mode_box = QComboBox(bar)
        for label, key in MODE_LABELS:
            self.mode_box.addItem(label, key)
        self.mode_box.setCurrentIndex(self.mode_box.findData(self._default_mode))
        self.mode_box.setToolTip(
            'How the current tab shows non-ASCII output: Strip (safe, default), '
            'Show (render legitimate unicode), or Reveal (as <U+XXXX> to inspect)')
        self.mode_box.currentIndexChanged.connect(self._on_mode_box)
        bar.addWidget(self.mode_box)
        bar.addAction(self.act_colors)
        bar.addSeparator()

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
