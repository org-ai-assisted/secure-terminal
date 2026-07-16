## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Application entry point and main window for secure-terminal."""

import os
import signal
import sys
import shlex

from PyQt6.QtCore import QTimer, Qt, QUrl, QRect, qInstallMessageHandler
from PyQt6.QtGui import (
    QAction, QActionGroup, QKeySequence, QIcon, QColor, QPixmap,
    QPainter, QBrush, QFont, QDesktopServices,
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QToolBar, QSpinBox, QLabel,
    QWidget, QSizePolicy, QFileDialog, QInputDialog, QColorDialog,
    QMenu, QDialog, QGridLayout, QPushButton, QLineEdit,
    QVBoxLayout, QHBoxLayout, QPlainTextEdit,
    QComboBox, QCheckBox, QFormLayout, QMessageBox,
)

from secure_terminal import settings, session
from secure_terminal.terminal import (
    SecureTerminal, THEMES, DISPLAY_MODES, tui_available,
)

TUI_TOOLTIP = (
    'TUI mode runs full-screen programs (ssh, vim, htop, tmux) by '
    'interpreting the terminal escape sequences the strict default mode refuses. '
    'It stays confined to an isolated screen model: the window title and system '
    'clipboard cannot be touched, and every character is still '
    'ASCII/unicode-filtered, so invisible or homoglyph text cannot hide. But a '
    'program CAN draw a misleading interface within its screen, so only run '
    'programs you trust. The default line mode remains safe by construction.')

ZOOM_MIN = 25
ZOOM_MAX = 400
ZOOM_STEP = 10

# menu label -> theme key in terminal.THEMES
THEME_LABELS = [
    ('Dark (white on black)', 'dark'),
    ('Light (black on white)', 'light'),
]

# menu / combo label -> display-mode key in terminal.DISPLAY_MODES
def _read_version(paths=None):
    """The version is baked from debian/changelog into a file at build time (see
    debian/rules) and read here. Fail open: a missing or unreadable file yields
    'unknown' so a source checkout or a partial install still starts."""
    if paths is None:
        base = os.path.abspath(__file__)
        for _ in range(6):        # .../usr/lib/python3/dist-packages/secure_terminal/main.py -> repo root
            base = os.path.dirname(base)
        paths = ['/usr/share/secure-terminal/version',
                 os.path.join(base, 'usr', 'share', 'secure-terminal', 'version')]
    for path in paths:
        try:
            with open(path, encoding='utf-8') as handle:
                version = handle.read().strip()
        except OSError:
            continue
        if version:
            return version
    return 'unknown'


# Shown in the About dialog.
APP_VERSION = _read_version()

# menu label -> scrollback limit in lines (0 = unlimited)
SCROLLBACK_CHOICES = [
    ('1,000 lines', 1000),
    ('10,000 lines', 10000),
    ('100,000 lines', 100000),
    ('Unlimited', 0),
]

# menu label -> paste-warning "Allow" delay in seconds
PASTE_DELAY_CHOICES = [
    ('No delay', 0),
    ('1 second', 1),
    ('3 seconds', 3),
    ('5 seconds', 5),
]


def _letter_icon(letter, color):
    """A small rounded-square icon with a single ASCII letter, used as the drawn
    fallback when the desktop icon theme has no fitting symbol. ASCII-only and
    always available, so a toolbar toggle is never left iconless."""
    pixmap = QPixmap(16, 16)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(1, 1, 14, 14, 3, 3)
    painter.setPen(QColor('#ffffff'))
    font = QFont()
    font.setPixelSize(11)
    font.setBold(True)
    painter.setFont(font)
    painter.drawText(QRect(0, 0, 16, 16), Qt.AlignmentFlag.AlignCenter, letter)
    painter.end()
    return QIcon(pixmap)


def _toggle_icon(theme_name, letter, color):
    """Prefer the desktop theme's symbol for a toolbar toggle; fall back to a
    drawn letter chip when the theme lacks it, so the button always has a mark."""
    icon = QIcon.fromTheme(theme_name)
    if not icon.isNull():
        return icon
    return _letter_icon(letter, color)


def _read_hook_config(cfg):
    """Build the opt-in command-hook config from a settings drop-in, or None when
    no handler is configured. Keys: command_hook (the handler command line, empty
    = off) plus optional command_hook_transcript (none|tail:N|full),
    command_hook_timeout (seconds), command_hook_on_error (allow|block)."""
    raw = (cfg.get('command_hook') or '').strip()
    if not raw:
        return None
    try:
        argv = shlex.split(raw)
    except ValueError:
        return None
    if not argv:
        return None
    try:
        timeout = int(cfg.get('command_hook_timeout') or 10)
    except ValueError:
        timeout = 10
    return {
        'argv': argv,
        'transcript': cfg.get('command_hook_transcript') or 'none',
        'timeout': timeout,
        'on_error': 'block' if cfg.get('command_hook_on_error') == 'block'
                    else 'allow',
    }


def _dot_icon(color):
    """A filled circle in `color` -- the traffic-light lamp of the security
    indicator (green safe / yellow TUI / red unicode-shown)."""
    pixmap = QPixmap(14, 14)
    pixmap.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QBrush(QColor(color)))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(1, 1, 12, 12)
    painter.end()
    return QIcon(pixmap)


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
        # Colours on by default: with a capable TERM the shell prompt, ls, git
        # and friends emit SGR colour, and a terminal that silently dropped it
        # looks broken. Parsing is bounded (16 palette colours) and the renderer's
        # contrast guard keeps text readable. An explicit saved 'false' still wins.
        self._default_colors = cfg.get('colors', 'true') == 'true'
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
        try:
            self._paste_delay = max(0, min(60, int(cfg['paste_delay'])))
        except (KeyError, ValueError):
            self._paste_delay = 3
        self._default_tui = cfg.get('tui') == 'true'
        self._default_allow_title = cfg.get('allow_title') == 'true'
        # session persistence is on unless explicitly disabled
        self._persist_session = cfg.get('persist_session') != 'false'
        # optional opt-in command hook, configured only via a settings drop-in
        self._hook_config = _read_hook_config(cfg)

        self.tabs = QTabWidget(self)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._sync_chrome_to_tab)
        # double-click a tab to rename it; right-click for rename/colour/close.
        self.tabs.tabBarDoubleClicked.connect(self.rename_tab)
        bar = self.tabs.tabBar()
        bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        bar.customContextMenuRequested.connect(self._tab_context_menu)
        self.setCentralWidget(self.tabs)

        self._theme_actions = {}
        self._user_titles = {}       # term -> user-set tab name
        self._prog_titles = {}       # term -> program (OSC) title
        self._tab_colors = {}        # term -> tab colour name (for persistence)
        self._build_menu()
        self._build_toolbar()
        self._build_security_indicator()

        # restore the previous session (tabs + scrollback) if enabled
        restored = session.load() if self._persist_session else []
        for info in restored:
            if isinstance(info, dict):
                self._restore_tab(info)
        if self.tabs.count() == 0:
            self.new_tab()

        # Enable Terminate only while a program (not just the shell) is running.
        # There is no event for a foreground-pgrp change, so poll cheaply.
        self._fg_poll = QTimer(self)
        self._fg_poll.timeout.connect(self._update_terminate_enabled)
        self._fg_poll.start(400)
        self._update_terminate_enabled()

    # -- tabs, each its own shell over its own pseudo-terminal -----------------
    def _add_tab(self, term):
        term.zoom_step.connect(self._on_zoom_step)
        term.tab_step.connect(self._on_tab_step)
        term.tab_move.connect(self._on_tab_move)
        term.apply_hook(self._hook_config)
        term.hook_notice.connect(self._on_hook_notice)
        term.shell_exited.connect(lambda t=term: self._on_shell_exited(t))
        term.title_changed.connect(
            lambda title, t=term: self._on_tab_title(t, title))
        term.notified.connect(self._on_notify)
        index = self.tabs.addTab(term, 'shell')
        self.tabs.setCurrentIndex(index)
        self._sync_chrome_to_tab()
        term.setFocus()
        return index

    def _on_tab_step(self, step):
        """Ctrl+PageUp/Down: move to the previous/next tab, wrapping around."""
        count = self.tabs.count()
        if count > 1:
            self.tabs.setCurrentIndex((self.tabs.currentIndex() + step) % count)

    def _on_tab_move(self, step):
        """Ctrl+Shift+PageUp/Down: move the current tab left/right, wrapping."""
        count = self.tabs.count()
        if count > 1:
            i = self.tabs.currentIndex()
            self.tabs.tabBar().moveTab(i, (i + step) % count)

    def _goto_tab(self, index):
        """Alt+1..9: jump straight to a tab by position (Alt+9 = last)."""
        if index == 8 or index >= self.tabs.count():
            index = self.tabs.count() - 1
        if 0 <= index < self.tabs.count():
            self.tabs.setCurrentIndex(index)

    def new_tab(self, command=None):
        term = SecureTerminal(tui=self._default_tui, command=command or None)
        term.apply_theme(self._default_theme)
        term.apply_zoom(self._default_zoom)
        term.apply_mode(self._default_mode)
        term.apply_colors(self._default_colors)
        term.apply_scrollback(self._scrollback)
        term.apply_paste_delay(self._paste_delay)
        term.apply_allow_title(self._default_allow_title)
        self._add_tab(term)

    def _restore_tab(self, info):
        """Recreate a tab from saved session state: its settings, name, colour
        and scrollback history, under a fresh shell."""
        history = info.get('text') if isinstance(info.get('text'), str) else ''
        term = SecureTerminal(tui=bool(info.get('tui')), history=history)
        theme = info.get('theme')
        term.apply_theme(theme if theme in THEMES else self._default_theme)
        try:
            term.apply_zoom(int(info.get('zoom', self._default_zoom)))
        except (TypeError, ValueError):
            term.apply_zoom(self._default_zoom)
        mode = info.get('mode')
        term.apply_mode(mode if mode in DISPLAY_MODES else self._default_mode)
        term.apply_colors(bool(info.get('colors')))
        try:
            term.apply_scrollback(int(info.get('scrollback', self._scrollback)))
        except (TypeError, ValueError):
            term.apply_scrollback(self._scrollback)
        term.apply_paste_delay(self._paste_delay)
        term.apply_allow_title(bool(info.get('allow_title')))
        index = self._add_tab(term)
        name = info.get('name')
        if isinstance(name, str) and name:
            self._user_titles[term] = name
        color = info.get('color')
        if isinstance(color, str) and color:
            self.set_tab_color(index, QColor(color))
        self._refresh_tab_label(term)

    def new_tab_running(self):
        command, ok = QInputDialog.getText(
            self, 'New Tab Running', 'Command (e.g. ssh host, tmux, claude):')
        if ok and command.strip():
            self.new_tab(command.strip())

    def close_tab(self, index):
        term = self.tabs.widget(index)
        if term is None:
            return
        term.shutdown()
        self._user_titles.pop(term, None)
        self._prog_titles.pop(term, None)
        self._tab_colors.pop(term, None)
        self.tabs.removeTab(index)
        term.deleteLater()
        if self.tabs.count() == 0:
            self.close()

    def _on_shell_exited(self, term):
        index = self.tabs.indexOf(term)
        if index != -1:
            self.close_tab(index)

    # -- tab label: user name + program title kept separately -----------------
    def rename_tab(self, index):
        if index < 0:
            return
        term = self.tabs.widget(index)
        current = self._user_titles.get(term, '')
        name, ok = QInputDialog.getText(
            self, 'Rename Tab', 'Tab name:',
            text=current or self.tabs.tabText(index))
        if ok:
            # a user name takes precedence over any program-set title, and is
            # not lost when a program later sets its own title.
            self._user_titles[term] = name.strip()
            self._refresh_tab_label(term)

    def _refresh_tab_label(self, term):
        index = self.tabs.indexOf(term)
        if index < 0:
            return
        user = self._user_titles.get(term)
        program = self._prog_titles.get(term)
        # plain text only; setTabText does not interpret markup
        self.tabs.setTabText(index, user or program or 'shell')
        parts = []
        if user:
            parts.append('name: ' + user)
        if program:
            parts.append('program: ' + program)
        self.tabs.setTabToolTip(index, '\n'.join(parts))

    def set_tab_color(self, index, color):
        if index < 0:
            return
        term = self.tabs.widget(index)
        if color is None or not color.isValid():
            self.tabs.setTabIcon(index, QIcon())
            self._tab_colors.pop(term, None)
            return
        pixmap = QPixmap(12, 12)
        pixmap.fill(color)
        self.tabs.setTabIcon(index, QIcon(pixmap))
        self._tab_colors[term] = color.name()

    def _tab_context_menu(self, point):
        index = self.tabs.tabBar().tabAt(point)
        if index < 0:
            return
        menu = QMenu(self)
        menu.addAction('Rename...', lambda: self.rename_tab(index))
        color_menu = menu.addMenu('Colour')
        for name, value in (('Red', '#d83933'), ('Green', '#1f8a54'),
                            ('Blue', '#3b82f6'), ('Yellow', '#e5a50a'),
                            ('Purple', '#8b5cf6')):
            color_menu.addAction(
                name, lambda v=value: self.set_tab_color(index, QColor(v)))
        color_menu.addAction(
            'Custom...',
            lambda: self.set_tab_color(index, QColorDialog.getColor(parent=self)))
        color_menu.addAction('Clear', lambda: self.set_tab_color(index, None))
        menu.addSeparator()
        menu.addAction('Close Tab', lambda: self.close_tab(index))
        menu.exec(self.tabs.tabBar().mapToGlobal(point))

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

    def select_all(self):
        term = self.current()
        if term is not None:
            term.selectAll()

    def toggle_fullscreen(self, on):
        if on:
            self.showFullScreen()
        else:
            self.showNormal()

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
        self._sync_mode_toggles(term.current_mode())
        self.act_colors.setChecked(term.colors_enabled())
        self.act_tui.setChecked(term.current_tui())
        self.act_title.setChecked(term.allow_title_enabled())
        self._update_tui_indicator()
        self._update_security_indicator()
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
        self._sync_mode_toggles(mode)
        self._update_security_indicator()
        self._default_mode = mode
        self._persist()

    def _sync_mode_toggles(self, mode):
        """Check the button for the active display mode in the exclusive group.
        setChecked() does not fire triggered, so this cannot loop back into
        set_mode."""
        action = self._mode_actions.get(mode)
        if action is not None and not action.isChecked():
            action.setChecked(True)

    def set_colors(self, enabled):
        term = self.current()
        if term is not None:
            term.apply_colors(enabled)
        self.act_colors.setChecked(enabled)
        self._default_colors = bool(enabled)
        self._persist()

    def set_tui(self, enabled):
        term = self.current()
        if term is not None:
            term.apply_tui(enabled)
            # a strict-stripped screen makes a TUI unreadable, so lean to 'show'
            if enabled and term.current_mode() == 'strip':
                self.set_mode('show')
        self._default_tui = bool(enabled)
        self.act_tui.setChecked(enabled)
        self._update_tui_indicator()
        self._update_security_indicator()
        self._persist()

    def _update_tui_indicator(self):
        term = self.current()
        active = term is not None and term.tui_active()
        self.tui_dot_action.setVisible(active)

    # -- security indicator: two lamps, one per independent risk axis ---------
    def _build_security_indicator(self):
        self.sec_display = QPushButton(self)
        self.sec_mode = QPushButton(self)
        for lamp in (self.sec_display, self.sec_mode):
            lamp.setFlat(True)
            lamp.setCursor(Qt.CursorShape.PointingHandCursor)
            lamp.clicked.connect(self._show_security_details)
            self.statusBar().addPermanentWidget(lamp)
        self._update_security_indicator()

    def _display_level(self):
        """The display (unicode) risk axis as (colour, short, detail). Show
        renders deceptive glyphs (red). Reveal is safe AND lossless -- the exact
        <U+XXXX> codepoint is shown (green). Strip is safe but LOSSY -- non-ASCII
        collapses to a single "_" that is easy to overlook (yellow)."""
        term = self.current()
        mode = term.current_mode() if term is not None else 'strip'
        if mode == 'show':
            return ('#d83933', 'Show',
                    'Display: SHOW (red).\n\n'
                    'Non-ASCII output is drawn as its glyph, so a look-alike '
                    '(homoglyph) can pose as an ASCII character and text can read '
                    'as something it is not. The invisible, bidi and control '
                    'classes are still neutralized and pasting is still sanitized, '
                    'but a rendered glyph can deceive the eye. This is the highest '
                    'risk, above TUI mode, because the deception is in what you '
                    'read.\n\nSwitch to Strip or Reveal to remove it.')
        if mode == 'reveal':
            return ('#1f8a54', 'Reveal',
                    'Display: REVEAL (green, safe).\n\n'
                    'Every non-ASCII character is shown as a <U+XXXX> badge: you '
                    'see the exact codepoint, so nothing can pose as a look-alike '
                    'and nothing is silently dropped. Escape sequences are removed '
                    'and pasting is sanitized.')
        return ('#e5a50a', 'Strip',
                'Display: STRIP (yellow).\n\n'
                'Non-ASCII output becomes "_": safe -- nothing deceptive is drawn '
                '-- but lossy. A single "_" is easy to overlook (far less visible '
                'than a revealed <U+XXXX> badge), so you may not notice that '
                'hidden characters were there at all. Switch to Reveal to see the '
                'exact codepoints. Escape sequences are removed and pasting is '
                'sanitized either way.')

    def _mode_level(self):
        """The interpretation (mode) risk axis: TUI interprets escapes in a
        confined screen (yellow); the strict line mode is green."""
        term = self.current()
        if term is not None and term.tui_active():
            return ('#e5a50a', 'TUI',
                    'Mode: TUI (yellow).\n\n'
                    'Escape sequences are interpreted through a confined screen '
                    'model so full-screen programs (ssh, vim, htop, tmux) work. '
                    'Every cell is still character-filtered, and a program\'s '
                    'output cannot drive that interpreter to act on the OS: it '
                    'cannot set the clipboard, or the window title unless you '
                    'allow it -- unlike terminals where an escape sequence can. '
                    'This constrains escape sequences, not the programs: a '
                    'program you run (nano, bash) has your normal user access, as '
                    'in any terminal, and can still draw a misleading interface '
                    'within its own screen, so only run programs you trust.\n\n'
                    'Turn TUI mode off to return to the safe line mode.')
        return ('#1f8a54', 'Line',
                'Mode: LINE (green, the safe default).\n\n'
                'No escape parser (TERM=dumb): program output is reduced to '
                'printable ASCII and every escape sequence is removed. There is '
                'nothing on screen a program can use to deceive you.')

    def _update_security_indicator(self):
        for lamp, level, axis in (
                (self.sec_display, self._display_level(), 'Display'),
                (self.sec_mode, self._mode_level(), 'Mode')):
            colour, short, _detail = level
            lamp.setIcon(_dot_icon(colour))
            lamp.setText(' ' + short)
            lamp.setToolTip(axis + ': ' + short + ' -- click for details')

    def _show_security_details(self):
        detail = self._display_level()[2] + '\n\n' + self._mode_level()[2]
        dialog = QDialog(self)
        dialog.setWindowTitle('Security level')
        layout = QVBoxLayout(dialog)
        # read-only, selectable so the explanation can be copied and discussed
        body = QPlainTextEdit(detail)
        body.setReadOnly(True)
        body.setMinimumSize(480, 300)
        layout.addWidget(body)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        copy = QPushButton('Copy')
        copy.clicked.connect(lambda: QApplication.clipboard().setText(detail))
        buttons.addWidget(copy)
        close = QPushButton('Close')
        close.clicked.connect(dialog.accept)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        dialog.exec()

    def set_allow_title(self, enabled):
        term = self.current()
        if term is not None:
            term.apply_allow_title(enabled)
        self._default_allow_title = bool(enabled)
        self.act_title.setChecked(enabled)
        self._persist()

    def _on_tab_title(self, term, title):
        if title:
            self._prog_titles[term] = title
            self._refresh_tab_label(term)

    def _on_notify(self, text):
        # passive, non-intrusive: a timed status-bar message, already ASCII-safe
        self.statusBar().showMessage('Notification: ' + text, 6000)

    def _on_hook_notice(self, message):
        # the command hook's advisory (already sanitized in hook.evaluate)
        self.statusBar().showMessage('Command hook: ' + message, 8000)

    def set_scrollback(self, lines):
        self._scrollback = int(lines)
        for i in range(self.tabs.count()):
            self.tabs.widget(i).apply_scrollback(lines)
        self._persist()

    def set_paste_delay(self, seconds):
        self._paste_delay = int(seconds)
        for i in range(self.tabs.count()):
            self.tabs.widget(i).apply_paste_delay(seconds)
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
            pass            # a failed save (bad path, no space) is not fatal

    def _persist(self):
        settings.save({
            'theme': self._default_theme,
            'zoom': str(self._default_zoom),
            'unicode_mode': self._default_mode,
            'colors': 'true' if self._default_colors else 'false',
            'scrollback': str(self._scrollback),
            'paste_delay': str(self._paste_delay),
            'tui': 'true' if self._default_tui else 'false',
            'allow_title': 'true' if self._default_allow_title else 'false',
            'persist_session': 'true' if self._persist_session else 'false',
        })

    # -- chrome ---------------------------------------------------------------
    def _build_menu(self):
        bar = self.menuBar()

        file_menu = bar.addMenu('&File')
        self.act_new = QAction(QIcon.fromTheme('tab-new'), 'New &Tab', self)
        self.act_new.setShortcut(QKeySequence('Ctrl+Shift+T'))
        self.act_new.triggered.connect(lambda: self.new_tab())
        file_menu.addAction(self.act_new)

        self.act_new_cmd = QAction('New Tab &Running...', self)
        self.act_new_cmd.setShortcut(QKeySequence('Ctrl+Shift+R'))
        self.act_new_cmd.setToolTip(
            'Open a tab running a specific program (e.g. ssh host, tmux, claude) '
            'instead of the login shell.')
        self.act_new_cmd.triggered.connect(self.new_tab_running)
        file_menu.addAction(self.act_new_cmd)

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
        self.act_persist = QAction('Restore &session on start', self,
                                   checkable=True)
        self.act_persist.setChecked(self._persist_session)
        self.act_persist.setToolTip(
            'Save the open tabs and their scrollback on exit and restore them '
            'next time. The running programs are not resurrected; a fresh shell '
            'starts under the restored history. Stored under ~/.local/state.')
        self.act_persist.toggled.connect(self.set_persist_session)
        file_menu.addAction(self.act_persist)

        act_clear_session = QAction('&Clear Saved Session', self)
        act_clear_session.triggered.connect(self.clear_saved_session)
        file_menu.addAction(act_clear_session)

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

        self.act_select_all = QAction(QIcon.fromTheme('edit-select-all'),
                                      'Select &All', self)
        self.act_select_all.setShortcut(QKeySequence('Ctrl+Shift+A'))
        self.act_select_all.triggered.connect(self.select_all)
        edit_menu.addAction(self.act_select_all)

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
        self.act_full = QAction(QIcon.fromTheme('view-fullscreen'),
                                '&Full Screen', self, checkable=True)
        self.act_full.setShortcut(QKeySequence('F11'))
        self.act_full.triggered.connect(self.toggle_fullscreen)
        view_menu.addAction(self.act_full)

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

        # Three mutually-exclusive display modes as a colour-coded segmented
        # control. Ordered Strip, Reveal, Show so Strip and Show are never
        # adjacent. Reveal is green (safe AND lossless -- the exact codepoint is
        # shown); Strip is yellow (safe but lossy -- non-ASCII collapses to a "_"
        # that is easy to overlook); Show is red (a rendered glyph can deceive).
        mode_menu = view_menu.addMenu('&Unicode')
        self._mode_group = QActionGroup(self)
        self._mode_group.setExclusive(True)
        self._mode_actions = {}
        for label, key, colour, tip in (
            ('&Strip', 'strip', '#e5a50a',
             'Non-ASCII output becomes "_": safe, but lossy -- a single "_" is '
             'easy to overlook, so you may not notice hidden characters were '
             'there. Reveal is more informative.'),
            ('&Reveal', 'reveal', '#1f8a54',
             'Show every non-ASCII character as a <U+XXXX> badge: safe and '
             'lossless, you see the exact codepoint, nothing can pose as a '
             'look-alike.'),
            ('S&how', 'show', '#d83933',
             'Render non-ASCII output as its glyph. Least safe: a look-alike '
             '(homoglyph) can pose as an ASCII character. The invisible, bidi and '
             'control classes are still neutralized.'),
        ):
            act = QAction(_dot_icon(colour), label, self, checkable=True)
            act.setToolTip(tip)
            act.triggered.connect(lambda _checked, k=key: self.set_mode(k))
            self._mode_group.addAction(act)
            mode_menu.addAction(act)
            self._mode_actions[key] = act
        self.act_strip = self._mode_actions['strip']
        self.act_reveal = self._mode_actions['reveal']
        self.act_show = self._mode_actions['show']
        self._sync_mode_toggles(self._default_mode)

        view_menu.addSeparator()
        self.act_colors = QAction(
            _toggle_icon('format-text-color', 'C', '#0969da'),
            '&Colors', self, checkable=True)
        self.act_colors.setChecked(self._default_colors)
        self.act_colors.setToolTip(
            'Render a safe subset of ANSI colors (16-color SGR) in the current '
            'tab. Off by default; contrast-guarded so text can never be painted '
            'invisibly, and forced off only by NO_COLOR.')
        self.act_colors.toggled.connect(self.set_colors)
        view_menu.addAction(self.act_colors)

        self.act_tui = QAction(_toggle_icon('utilities-terminal', 'T', '#e5a50a'),
                               '&TUI mode', self, checkable=True)
        self.act_tui.setChecked(self._default_tui)
        self.act_tui.setEnabled(tui_available())
        self.act_tui.setToolTip(TUI_TOOLTIP)
        if not tui_available():
            self.act_tui.setText('TUI mode (needs python3-pyte)')
        self.act_tui.toggled.connect(self.set_tui)
        view_menu.addAction(self.act_tui)

        self.act_title = QAction(
            _toggle_icon('preferences-desktop-notification', 'N', '#bf3989'),
            'Allow program &title / notifications', self, checkable=True)
        self.act_title.setChecked(self._default_allow_title)
        self.act_title.setToolTip(
            'Let a program set the tab title (OSC 0/2) and send notifications '
            '(OSC 9), the modern terminal protocol. Off by default; only takes '
            'effect in TUI mode. Titles and notifications are sanitized to plain '
            'ASCII. Clipboard-write and hyperlink escapes stay blocked.')
        self.act_title.toggled.connect(self.set_allow_title)
        view_menu.addAction(self.act_title)

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

        pd_menu = view_menu.addMenu('&Paste delay')
        pd_group = QActionGroup(self)
        pd_group.setExclusive(True)
        for label, secs in PASTE_DELAY_CHOICES:
            act = QAction(label, self, checkable=True)
            act.setChecked(secs == self._paste_delay)
            act.triggered.connect(lambda _checked, n=secs: self.set_paste_delay(n))
            pd_group.addAction(act)
            pd_menu.addAction(act)

        tabs_menu = bar.addMenu('Ta&bs')
        act_next_tab = QAction('&Next Tab', self)
        act_next_tab.triggered.connect(lambda: self._on_tab_step(1))
        tabs_menu.addAction(act_next_tab)
        act_prev_tab = QAction('&Previous Tab', self)
        act_prev_tab.triggered.connect(lambda: self._on_tab_step(-1))
        tabs_menu.addAction(act_prev_tab)
        # Ctrl+PageUp/Down (switch) and Ctrl+Shift+PageUp/Down (move) are handled
        # in the terminal widget so they win over a full-screen program; the menu
        # entries above stay unbound to avoid firing them twice.
        tabs_menu.addSeparator()
        for _n in range(1, 10):
            act = QAction('Tab &%d' % _n, self)
            act.setShortcut(QKeySequence('Alt+%d' % _n))
            act.triggered.connect(lambda _c=False, i=_n - 1: self._goto_tab(i))
            tabs_menu.addAction(act)

        settings_menu = bar.addMenu('&Settings')
        act_global = QAction('&Global Settings...', self)
        act_global.setToolTip(
            'Set the defaults for every tab in one place; changes apply to all '
            'open tabs and to new ones.')
        act_global.triggered.connect(self.show_global_settings)
        settings_menu.addAction(act_global)
        act_command = QAction('&Command...', self)
        act_command.setShortcut(QKeySequence('Ctrl+Shift+P'))
        act_command.setToolTip('Type a slash command to change a setting, e.g. '
                               '/mode reveal or /help.')
        act_command.triggered.connect(self.show_command_palette)
        settings_menu.addAction(act_command)
        settings_menu.addSeparator()
        act_locations = QAction('&Folders & Files...', self)
        act_locations.setToolTip(
            'Show where settings and session state are stored, with buttons to '
            'copy the path or open the folder.')
        act_locations.triggered.connect(self.show_locations)
        settings_menu.addAction(act_locations)

        help_menu = bar.addMenu('&Help')
        act_about = QAction(QIcon.fromTheme('help-about'), '&About', self)
        act_about.triggered.connect(self.show_about)
        help_menu.addAction(act_about)

    def show_about(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('About secure-terminal')
        layout = QVBoxLayout(dialog)
        title = QLabel('secure-terminal ' + APP_VERSION)
        title.setStyleSheet('font-weight:bold; font-size:16px;')
        layout.addWidget(title)
        body = QLabel(
            'A terminal where paste is safe by construction.<br><br>'
            'Program output is reduced to printable ASCII with no escape parser, '
            'so a printed or pasted lie cannot redraw, reorder or hide what you '
            'see. Pasting is sanitized and warned on. It is written in a '
            'memory-safe language.<br><br>'
            '<a href="https://secure-terminal.github.io">secure-terminal.github.io</a>'
            '<br><a href="https://output-lies.github.io">output-lies.github.io</a>'
            ' &ndash; the problem it removes<br><br>'
            'Licensed under the GNU Affero General Public License v3 or later.')
        body.setTextFormat(Qt.TextFormat.RichText)
        body.setWordWrap(True)
        body.setOpenExternalLinks(True)
        body.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction)
        layout.addWidget(body)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        close = QPushButton('Close')
        close.clicked.connect(dialog.accept)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        dialog.exec()

    _COMMAND_HELP = (
        'Slash commands (the leading / is optional):\n\n'
        '  /theme dark|light\n'
        '  /mode strip|show|reveal\n'
        '  /colors on|off\n'
        '  /tui on|off\n'
        '  /title on|off\n'
        '  /zoom <25-400>\n'
        '  /scrollback <lines, 0 = unlimited>\n'
        '  /paste-delay <seconds>\n'
        '  /help')

    def show_command_palette(self):
        text, ok = QInputDialog.getText(self, 'Command', 'Command (try /help):')
        if ok and text.strip():
            self.run_command(text)

    def run_command(self, line):
        """Apply a slash command to the current tab. Returns True when the command
        was recognized and valid. A separate palette (not the shell line), so a
        leading / never collides with an absolute-path program."""
        parts = line.strip().lstrip('/').split()
        if not parts:
            return False
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ''
        low = arg.lower()
        on = low in ('on', 'true', '1', 'yes')
        off = low in ('off', 'false', '0', 'no')
        if cmd == 'help':
            QMessageBox.information(self, 'Commands', self._COMMAND_HELP)
        elif cmd == 'theme' and low in THEMES:
            self.set_theme(low)
        elif cmd == 'mode' and low in DISPLAY_MODES:
            self.set_mode(low)
        elif cmd == 'colors' and (on or off):
            self.set_colors(on)
        elif cmd == 'tui' and (on or off):
            self.set_tui(on)
        elif cmd == 'title' and (on or off):
            self.set_allow_title(on)
        elif cmd == 'zoom' and arg.isdigit():
            self.set_zoom(int(arg))
        elif cmd == 'scrollback' and arg.isdigit():
            self.set_scrollback(int(arg))
        elif cmd in ('paste-delay', 'pastedelay') and arg.isdigit():
            self.set_paste_delay(int(arg))
        else:
            self.statusBar().showMessage(
                'Unknown or invalid command: ' + line.strip() + '  (try /help)',
                5000)
            return False
        return True

    def show_global_settings(self):
        """One dialog for the defaults that otherwise live scattered across the
        View menu. On accept the choices apply to every open tab and become the
        default for new ones."""
        dialog = QDialog(self)
        dialog.setWindowTitle('Global settings')
        form = QFormLayout(dialog)

        theme = QComboBox()
        for label, key in THEME_LABELS:
            theme.addItem(label, key)
        theme.setCurrentIndex(theme.findData(self._default_theme))
        form.addRow('Theme', theme)

        zoom = QSpinBox()
        zoom.setRange(ZOOM_MIN, ZOOM_MAX)
        zoom.setSingleStep(ZOOM_STEP)
        zoom.setSuffix('%')
        zoom.setValue(self._default_zoom)
        form.addRow('Zoom', zoom)

        mode = QComboBox()
        for label, key in (('Strip (safe)', 'strip'), ('Show unicode', 'show'),
                           ('Reveal unicode', 'reveal')):
            mode.addItem(label, key)
        mode.setCurrentIndex(mode.findData(self._default_mode))
        form.addRow('Unicode', mode)

        colors = QCheckBox()
        colors.setChecked(self._default_colors)
        form.addRow('Colors', colors)

        tui = QCheckBox()
        tui.setChecked(self._default_tui)
        tui.setEnabled(tui_available())
        form.addRow('TUI mode (new tabs)', tui)

        title = QCheckBox()
        title.setChecked(self._default_allow_title)
        form.addRow('Allow program title / notifications', title)

        scrollback = QComboBox()
        for label, lines in SCROLLBACK_CHOICES:
            scrollback.addItem(label, lines)
        scrollback.setCurrentIndex(scrollback.findData(self._scrollback))
        form.addRow('Scrollback', scrollback)

        pdelay = QComboBox()
        for label, secs in PASTE_DELAY_CHOICES:
            pdelay.addItem(label, secs)
        pdelay.setCurrentIndex(pdelay.findData(self._paste_delay))
        form.addRow('Paste delay', pdelay)

        persist = QCheckBox()
        persist.setChecked(self._persist_session)
        form.addRow('Restore session on start', persist)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton('Cancel')
        cancel.clicked.connect(dialog.reject)
        apply_all = QPushButton('Apply to all tabs')
        apply_all.setDefault(True)
        apply_all.clicked.connect(dialog.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(apply_all)
        form.addRow(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._apply_global({
            'theme': theme.currentData(), 'zoom': zoom.value(),
            'mode': mode.currentData(), 'colors': colors.isChecked(),
            'tui': tui.isChecked(), 'allow_title': title.isChecked(),
            'scrollback': scrollback.currentData(), 'paste_delay': pdelay.currentData(),
            'persist': persist.isChecked(),
        })

    def _apply_global(self, opts):
        """Apply the global-settings choices to every open tab and store the new
        defaults. TUI mode changes only the default for new tabs -- switching it
        would restart the shell in each existing tab, throwing away running work,
        which a settings dialog must not do."""
        self._default_theme = opts['theme']
        self._default_zoom = opts['zoom']
        self._default_mode = opts['mode']
        self._default_colors = opts['colors']
        self._default_tui = opts['tui']
        self._default_allow_title = opts['allow_title']
        self._scrollback = opts['scrollback']
        self._paste_delay = opts['paste_delay']
        for index in range(self.tabs.count()):
            term = self.tabs.widget(index)
            term.apply_theme(opts['theme'])
            term.apply_zoom(opts['zoom'])
            term.apply_mode(opts['mode'])
            term.apply_colors(opts['colors'])
            term.apply_allow_title(opts['allow_title'])
            term.apply_scrollback(opts['scrollback'])
            term.apply_paste_delay(opts['paste_delay'])
        self.set_persist_session(opts['persist'])
        self._sync_chrome_to_tab()
        self._persist()

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

        bar.addAction(self.act_strip)
        bar.addAction(self.act_reveal)
        bar.addAction(self.act_show)
        bar.addAction(self.act_colors)
        bar.addSeparator()

        bar.addAction(self.act_tui)
        # yellow risk indicator, shown only while TUI mode is active. A toolbar
        # widget is shown/hidden through the QAction addWidget() returns.
        self.tui_dot = QLabel(bar)
        self.tui_dot.setFixedSize(14, 14)
        self.tui_dot.setStyleSheet('background-color:#e5a50a; border-radius:7px;')
        self.tui_dot.setToolTip(TUI_TOOLTIP)
        self.tui_dot_action = bar.addWidget(self.tui_dot)
        self.tui_dot_action.setVisible(False)
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

    # -- session persistence --------------------------------------------------
    def _session_tabs(self):
        tabs = []
        for i in range(self.tabs.count()):
            term = self.tabs.widget(i)
            text = session.cap_text(term.toPlainText(), term.current_scrollback())
            tabs.append({
                'name': self._user_titles.get(term, ''),
                'color': self._tab_colors.get(term, ''),
                'theme': term.current_theme(),
                'zoom': term.current_zoom(),
                'mode': term.current_mode(),
                'colors': term.colors_enabled(),
                'tui': term.current_tui(),
                'allow_title': term.allow_title_enabled(),
                'scrollback': term.current_scrollback(),
                'text': text,
            })
        return tabs

    def set_persist_session(self, enabled):
        self._persist_session = bool(enabled)
        self.act_persist.setChecked(enabled)
        if not enabled:
            session.clear()
        self._persist()

    def clear_saved_session(self):
        session.clear()

    # -- settings / state locations -------------------------------------------
    def _open_path(self, path):
        # open the folder in the file manager; fall back to its parent when the
        # path itself does not exist yet (e.g. an unused drop-in dir).
        target = path if os.path.exists(path) else os.path.dirname(path)
        QDesktopServices.openUrl(QUrl.fromLocalFile(target))

    def show_locations(self):
        rows = [('Settings (written here)', settings.user_config_file())]
        labels = ['System drop-in', 'Local drop-in', 'User drop-in']
        for label, directory in zip(labels, settings.config_dirs()):
            rows.append((label, directory))
        rows.append(('Saved session', session.session_path()))

        dialog = QDialog(self)
        dialog.setWindowTitle('Folders & Files')
        grid = QGridLayout(dialog)
        grid.addWidget(QLabel(
            'Settings are read from these .conf drop-in directories (later '
            'overrides earlier); the app writes to the first file. Session state '
            'is separate.'), 0, 0, 1, 4)
        for row, (label, path) in enumerate(rows, start=1):
            grid.addWidget(QLabel(label), row, 0)
            field = QLineEdit(path)
            field.setReadOnly(True)
            field.setMinimumWidth(380)
            grid.addWidget(field, row, 1)
            copy = QPushButton('Copy')
            copy.clicked.connect(
                lambda _checked, p=path: QApplication.clipboard().setText(p))
            grid.addWidget(copy, row, 2)
            open_button = QPushButton('Open')
            open_button.clicked.connect(
                lambda _checked, p=path: self._open_path(p))
            grid.addWidget(open_button, row, 3)
        close = QPushButton('Close')
        close.clicked.connect(dialog.accept)
        grid.addWidget(close, len(rows) + 1, 3)
        dialog.exec()

    # -- lifecycle ------------------------------------------------------------
    def closeEvent(self, event):
        if self._persist_session:
            session.save(self._session_tabs())
        else:
            session.clear()
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
            pass        # a signal not settable here stays at its default
    wake = QTimer(app)
    wake.timeout.connect(lambda: None)
    wake.start(200)


def _is_font_noise(category, message):
    """True for the harmless 'qt.text.font.db: OpenType support missing for ...'
    warnings Qt logs when show mode renders a codepoint from a complex script
    whose installed monospace font lacks shaping tables. A flood of decoded
    random bytes ("cat /dev/random" in show mode) emits thousands of these."""
    return category == 'qt.text.font.db' or 'OpenType support missing' in message


def _quiet_font_warnings():
    """Drop the font-shaping warnings (see _is_font_noise) and pass everything
    else through. They are emitted straight to the message handler and ignore
    QT_LOGGING_RULES, so a handler is the only thing that catches them."""
    def handler(_mode, context, message):
        if _is_font_noise(getattr(context, 'category', '') or '', message):
            return
        sys.stderr.write(message + '\n')
    qInstallMessageHandler(handler)


def main():
    _quiet_font_warnings()
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
        pass            # if we cannot auto-reap, tabs simply reap on exit

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
