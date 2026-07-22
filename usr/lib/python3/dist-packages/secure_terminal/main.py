## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Application entry point and main window for secure-terminal."""

import os
import signal
import sys
import shlex
import argparse
import json

from PyQt6.QtCore import (
    QTimer, Qt, QUrl, QRect, QPoint, QObject, QEvent, qInstallMessageHandler)
from PyQt6.QtGui import (
    QAction, QActionGroup, QKeySequence, QIcon, QColor, QPixmap,
    QPainter, QBrush, QFont, QDesktopServices, QCursor,
    QTextCharFormat, QTextCursor, QTextDocument,
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QToolBar, QSpinBox, QLabel,
    QWidget, QSizePolicy, QFileDialog, QInputDialog, QColorDialog,
    QMenu, QDialog, QGridLayout, QPushButton, QLineEdit,
    QVBoxLayout, QHBoxLayout, QPlainTextEdit, QButtonGroup, QFrame,
    QComboBox, QCheckBox, QFormLayout, QMessageBox, QKeySequenceEdit,
    QTextEdit, QFontDialog, QGroupBox,
)

from PyQt6.QtNetwork import QLocalServer
from secure_terminal import settings, session, ipc
from secure_terminal.sanitize import (
    sanitize_paste, OSC_FEATURES, OSC_FEATURE_BY_KEY, luminance)
from secure_terminal.terminal import (
    SecureTerminal, THEMES, DISPLAY_MODES, tui_available,
    sound_file_allowed, BELL_SOUND_DIRS, DEFAULT_FONT_FAMILY,
)
from secure_terminal.review import ReviewBar

TUI_TOOLTIP = (
    'TUI mode runs full-screen programs (ssh, vim, htop, tmux) by '
    'interpreting the terminal escape sequences the strict default mode refuses. '
    'It stays confined to an isolated screen model: the window title and system '
    'clipboard cannot be touched, and every character is still '
    'ASCII/unicode-filtered, so invisible or homoglyph text cannot hide. But a '
    'program CAN draw a misleading interface within its screen, so only run '
    'programs you trust. The default CLI mode remains safe by design.')

# Plain-language threat model for the OSC controls, shown in the security lamp so
# a lay user does not over-trust the feature. Safe example only (no destructive
# commands): the point is that a passive action can trigger a real side-effect.
_OSC_THREAT_MODEL = (
    'Threat model: secure-terminal does NOT make the programs you run safer -- if '
    'you choose to run something harmful it still runs, as in any terminal. What '
    'it guards is VIEWING untrusted output: a crafted file you open, a program\'s '
    'output, an SSH login banner or even a filename can carry these escapes, so a '
    'harmless-looking action (reading a log) would otherwise cause a real '
    'side-effect -- for example quietly changing your clipboard so a later paste '
    'inserts text you never copied. Keeping these off means untrusted output can '
    'only be read, never act.')

ZOOM_MIN = 25
ZOOM_MAX = 400

# Cycled to auto-colour new tabs so a tab differs from its neighbour; distinct,
# theme-readable hues. A user-set tab colour overrides the auto one.
TAB_PALETTE = ('#e5484d', '#e5a50a', '#1f8a54', '#3b9eff',
               '#a06cff', '#e06c9f', '#2ab0a0', '#c07a3a')
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


def _app_icon():
    """The secure-terminal application icon. Prefer the installed hicolor theme
    icon; fall back to the shipped SVG by path so the About dialog and window
    icon still show it from a source checkout, before `update-icon-caches` has
    run, or on a bare-bones desktop with no icon theme. Returns a null QIcon if
    nothing is found -- callers treat that as "no logo", never an error."""
    themed = QIcon.fromTheme('secure-terminal')
    if not themed.isNull():
        return themed
    base = os.path.abspath(__file__)
    for _ in range(6):            # .../dist-packages/secure_terminal/main.py -> repo root
        base = os.path.dirname(base)
    rel = os.path.join('usr', 'share', 'icons', 'hicolor', 'scalable',
                       'apps', 'secure-terminal.svg')
    for path in ('/usr/share/icons/hicolor/scalable/apps/secure-terminal.svg',
                 os.path.join(base, rel)):
        if os.path.exists(path):
            return QIcon(path)
    return QIcon()


# cap on a `ctl dump-tab` reply so it stays under the IPC frame limit.
_DUMP_MAX = 512 * 1024

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
    if not argv:  # pragma: no cover - a non-empty non-whitespace command always yields a token
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


def _select_labels(widget):
    """Make every QLabel under `widget` selectable, so a dialog's descriptive
    text can be marked and copied by hand, not just its input fields. Preserves
    any flags a label already has (e.g. link handling)."""
    for label in widget.findChildren(QLabel):
        label.setTextInteractionFlags(
            label.textInteractionFlags()
            | Qt.TextInteractionFlag.TextSelectableByMouse
            | Qt.TextInteractionFlag.TextSelectableByKeyboard)


class InfoTip(QLabel):
    """A persistent, selectable, zoom-aware replacement for the plain tooltip.
    Unlike QToolTip you can move the pointer INTO it to select and copy the text,
    and its font follows the current zoom, so a long risk explanation is readable
    and quotable. It hides on Esc, or when the pointer leaves both it and the
    widget it describes (polled, so no fragile enter/leave bookkeeping)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        # a non-activating tool window: shows without stealing focus from the
        # terminal, stays on top, and (unlike a QToolTip) accepts mouse events so
        # its text can be selected. Parented to the window for clean teardown.
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Tool
                            | Qt.WindowType.WindowStaysOnTopHint)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating, True)
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse
                                     | Qt.TextInteractionFlag.TextSelectableByKeyboard)
        self.setWordWrap(True)
        self.setMargin(7)
        self.setMaximumWidth(460)
        self.setStyleSheet('QLabel{background:#fdf6d8;color:#1a1a1a;'
                           'border:1px solid #b9a24a;border-radius:5px}')
        self._source = None
        self._poll = QTimer(self)
        self._poll.setInterval(150)
        self._poll.timeout.connect(self._check_pointer)

    def show_for(self, widget, text, global_pos, zoom):
        self._source = widget
        self.setText(text)
        font = QFont()
        base = font.pointSizeF() if font.pointSizeF() > 0 else 10.0
        font.setPointSizeF(base * max(50, min(400, zoom)) / 100.0)
        self.setFont(font)
        self.adjustSize()
        self.move(global_pos + QPoint(12, 18))
        self.show()
        self._poll.start()

    def _check_pointer(self):
        pos = QCursor.pos()
        over_tip = self.isVisible() and self.geometry().contains(pos)
        over_src = False
        if self._source is not None:
            try:
                top_left = self._source.mapToGlobal(QPoint(0, 0))
                over_src = QRect(top_left, self._source.size()).contains(pos)
            except RuntimeError:                       # the source was destroyed
                self._source = None
        if not over_tip and not over_src:
            self.hide()
            self._poll.stop()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.hide()
            self._poll.stop()
            return
        super().keyPressEvent(event)


class _ToolTipFilter(QObject):
    """Application event filter that renders every tooltip as an interactive,
    zoom-aware InfoTip instead of the plain QToolTip."""

    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self._tip = InfoTip(window)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.ToolTip and isinstance(obj, QWidget):
            text = obj.toolTip()
            if text:
                self._tip.show_for(obj, text, event.globalPos(),
                                   self._window.current_zoom_percent())
                return True                            # suppress the plain tooltip
        return super().eventFilter(obj, event)


class FindBar(QWidget):
    """A dismissible find bar shown below the tabs. It searches only the
    already-neutralized display text of the terminal (never raw bytes), so a
    search can surface nothing a program did not already render. The bar drives
    the search; the window owns the tabs and does the actual finding."""

    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self.setObjectName('findbar')
        self.setVisible(False)
        row = QHBoxLayout(self)
        row.setContentsMargins(8, 4, 8, 4)
        row.setSpacing(6)
        self.input = QLineEdit(self)
        self.input.setPlaceholderText('Find in scrollback')
        self.input.setClearButtonEnabled(True)
        self.input.textChanged.connect(lambda _t: window._find_update())
        self.input.returnPressed.connect(lambda: window._find_step(False))
        self.count = QLabel('', self)
        self.count.setStyleSheet('color: palette(mid)')
        prev_btn = QPushButton('Prev', self)
        prev_btn.setToolTip('Previous match (Shift+Enter)')
        prev_btn.clicked.connect(lambda: window._find_step(True))
        next_btn = QPushButton('Next', self)
        next_btn.setToolTip('Next match (Enter)')
        next_btn.clicked.connect(lambda: window._find_step(False))
        self.case = QCheckBox('Case', self)
        self.case.setToolTip('Case sensitive')
        self.case.toggled.connect(lambda _c: window._find_update())
        self.all_tabs = QCheckBox('All tabs', self)
        self.all_tabs.setToolTip('Search every tab, not just this one')
        self.all_tabs.toggled.connect(lambda _c: window._find_update())
        close_btn = QPushButton('x', self)
        close_btn.setToolTip('Close (Esc)')
        close_btn.setFixedWidth(24)
        close_btn.clicked.connect(window.hide_find)
        row.addWidget(QLabel('Find:', self))
        row.addWidget(self.input, 1)
        row.addWidget(self.count)
        row.addWidget(prev_btn)
        row.addWidget(next_btn)
        row.addWidget(self.case)
        row.addWidget(self.all_tabs)
        row.addWidget(close_btn)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self._window.hide_find()
            return
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            backward = bool(event.modifiers() & Qt.KeyboardModifier.ShiftModifier)
            self._window._find_step(backward)
            return
        super().keyPressEvent(event)


class MainWindow(QMainWindow):
    def __init__(self, launch=None):
        super().__init__()
        self.setWindowTitle('secure-terminal')
        # Set the icon on the WINDOW too, not only the QApplication default: some
        # window managers read _NET_WM_ICON off the individual window for the title
        # bar / taskbar, so app.setWindowIcon() alone can leave a generic icon.
        _icon = _app_icon()
        if not _icon.isNull():
            self.setWindowIcon(_icon)
        self.resize(820, 520)
        self._launch = launch

        # Global defaults inherited by every NEW tab; each tab then carries its
        # own theme and zoom, which the chrome below reflects and edits.
        # Global defaults, loaded from ~/.config; each is validated so a hand-
        # edited or stale config can never crash or set a bogus value. Changing
        # any of them (below) updates the default and re-persists.
        cfg = settings.load()
        # Keys an admin locked via a privileged drop-in (/etc, /usr/local/etc).
        # A locked setting cannot be changed by the user: its control is disabled,
        # set_* refuses it, and it is never written back to the user config.
        self._locked = cfg.locked
        self._locked_violations = cfg.violations
        self._default_theme = cfg.get('theme') if cfg.get('theme') in THEMES \
            else 'dark'
        self._default_mode = cfg.get('unicode_mode') \
            if cfg.get('unicode_mode') in DISPLAY_MODES else 'detail'
        # Default terminal font family (global). Hack disambiguates confusables and
        # has no ligature tables; an uninstalled family falls back in the widget.
        self._default_font_family = (cfg.get('font_family') or '').strip() \
            or DEFAULT_FONT_FAMILY
        # Colours on by default: with a capable TERM the shell prompt, ls, git
        # and friends emit SGR colour, and a terminal that silently dropped it
        # looks broken. Parsing is bounded (16 palette colours) and the renderer's
        # contrast guard keeps text readable. An explicit saved 'false' still wins.
        self._default_colors = cfg.get('colors', 'true') == 'true'
        self._default_markings = cfg.get('colored_markings', 'true') == 'true'
        self._auto_tab_colors = cfg.get('auto_tab_colors', 'true') == 'true'
        self._auto_color_idx = 0      # cycles TAB_PALETTE so neighbours differ
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
        self._paste_warn = cfg.get('paste_warn') \
            if cfg.get('paste_warn') in ('always', 'unicode', 'never') else 'unicode'
        self._copy_warn = cfg.get('copy_warn') \
            if cfg.get('copy_warn') in ('always', 'unicode', 'never') else 'unicode'
        self._default_tui = cfg.get('tui') == 'true'
        # opt-in: advertise the restricted `secure-terminal` terminfo (CLI-mode)
        # instead of xterm-256color for new tabs. Off by default (xterm-256color
        # keeps ssh + TUI working); TERM is fixed at shell start, so this applies
        # to NEW tabs only.
        self._default_cli_terminfo = cfg.get('cli_terminfo') == 'true'
        self._default_allow_title = cfg.get('allow_title') == 'true'
        # granular per-OSC-feature defaults (each off = neutralized).
        self._osc_defaults = {}
        for _key, _lbl, _codes, _dflt, _risk, _hint in OSC_FEATURES:
            self._osc_defaults[_key] = cfg.get(_key) == 'true'
        # legacy allow_title seeds title + notify ONLY as a migration fallback --
        # when the granular key is absent. It must not clobber an explicit granular
        # value (a user enabling osc_title but disabling osc_notify would otherwise
        # find osc_notify forced back on every restart).
        if self._default_allow_title:
            if cfg.get('osc_title') is None:
                self._osc_defaults['osc_title'] = True
            if cfg.get('osc_notify') is None:
                self._osc_defaults['osc_notify'] = True
        # a locked legacy allow_title enforces BOTH granular title settings, in
        # either direction (an admin can require or forbid the capability).
        if 'allow_title' in self._locked:
            self._osc_defaults['osc_title'] = self._default_allow_title
            self._osc_defaults['osc_notify'] = self._default_allow_title
        # notice (a dismissible banner) when a program uses an OSC escape that line
        # mode strips; on by default, a global toggle turns it off
        self._osc_notice = cfg.get('osc_notice') != 'false'
        # OSC types the user has muted individually (still neutralized, just no
        # notice): a set of feature keys, comma-separated in config.
        self._osc_notice_off = set(
            k.strip() for k in cfg.get('osc_notice_off', '').split(',') if k.strip())
        # global "always allow clipboard read": auto-answers OSC 52 read in any tab
        # that has made no explicit decision, WITHOUT prompting. Off by default and
        # security-relevant (any untrusted output could then exfiltrate the
        # clipboard), so it is opt-in and lockable like the other high-risk toggles.
        self._osc_clipboard_read_always = cfg.get('osc_clipboard_read_always') == 'true'
        # bell (BEL 0x07) policy: off (default, silent), audible (system beep) or
        # visual (window/taskbar urgency flash). BEL from untrusted output is a
        # nuisance surface, so silence is the safe default.
        # bell notification channels (comma-separated: audible, visual, tray;
        # empty = silent). Legacy single 'audible'/'visual' still parse. An optional
        # sound file (restricted to allowed dirs) replaces the beep for 'audible'.
        self._default_bell = SecureTerminal._parse_bell(cfg.get('bell', ''))
        self._default_bell_sound = cfg.get('bell_sound', '')
        # system tray: opt-in, OFF by default. When on, a tray icon offers a few
        # fixed, safe actions (Show/Hide, New Tab, Quit) and the 'tray' bell
        # channel works; when off, no tray icon is ever created.
        self._systray = cfg.get('systray') == 'true'
        self._tray = None             # shared system-tray icon, created on first use
        # user overrides for window keyboard shortcuts: "ident=Seq ident=Seq ...".
        # Only overrides (bindings differing from the built-in default) are stored;
        # _bind() applies them as each action is created, and the Keyboard
        # Shortcuts dialog edits them. An empty Seq unbinds an action.
        self._keybindings = {}
        for _entry in cfg.get('keybindings', '').split():
            if '=' in _entry:
                _kid, _kseq = _entry.split('=', 1)
                self._keybindings[_kid.strip()] = _kseq.strip()
        self._shortcuts = {}          # ident -> (action, default_seq_str, label)
        # session persistence is on unless explicitly disabled
        self._persist_session = cfg.get('persist_session') != 'false'
        # confirm before closing a tab/window that still runs a foreground program
        self._confirm_close = cfg.get('confirm_close') != 'false'
        # optional opt-in command hook, configured only via a settings drop-in
        self._hook_config = _read_hook_config(cfg)
        # remote control (the ctl inject-into-tab surface) is OFF unless an admin
        # turned it on in a privileged directory (remote_control is privileged-
        # only, so a home config cannot enable it).
        self._remote_control = cfg.get('remote_control') == 'true'
        self._tab_ids = {}            # term -> stable id (for `ctl --tab id:N`)
        self._next_tab_id = 0

        self.tabs = QTabWidget(self)
        self.tabs.setTabsClosable(True)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._sync_chrome_to_tab)
        # double-click a tab to rename it; right-click for rename/colour/close.
        self.tabs.tabBarDoubleClicked.connect(self.rename_tab)
        bar = self.tabs.tabBar()
        # keep the 1..N tab numbers correct after a drag-reorder
        bar.tabMoved.connect(lambda *_: self._renumber_tabs())
        bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        bar.customContextMenuRequested.connect(self._tab_context_menu)
        # a pointing-hand cursor over the tab bar hints that a tab is interactive
        # (double-click to rename the title, right-click for rename/colour/close).
        bar.setCursor(Qt.CursorShape.PointingHandCursor)
        bar.setToolTip('Double-click to rename this tab; right-click for more.')
        # a dismissible advisory banner BELOW the tab bar and terminal (not
        # injected into any terminal, so an advisory can never be copied as
        # program output). Placing it under the tabs, rather than above, keeps
        # the tab bar at a fixed position: showing or hiding the banner no longer
        # shifts the tab strip, so switching tabs does not make them jump.
        central = QWidget(self)
        col = QVBoxLayout(central)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)
        self._banner = self._make_banner()
        self._find_bar = FindBar(self)
        self._review_bar = ReviewBar(self)
        col.addWidget(self.tabs)
        col.addWidget(self._review_bar)
        col.addWidget(self._find_bar)
        col.addWidget(self._banner)
        self.setCentralWidget(central)
        # render tooltips as interactive, zoom-aware popups (selectable + copyable)
        self._tip_filter = _ToolTipFilter(self)
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self._tip_filter)

        self._theme_actions = {}
        self._osc_actions = {}       # osc feature key -> its checkable menu action
        self._osc_notice_actions = {}  # osc feature key -> its notice-toggle action
        self._user_titles = {}       # term -> user-set tab name
        self._prog_titles = {}       # term -> program (OSC) title
        self._pre_tui_mode = {}      # term -> display mode to restore after TUI
        self._tab_colors = {}        # term -> tab colour name (for persistence)
        self._advisories = {}        # term -> (kind, banner text); kind tui|osc
        self._osc_notified = set()   # (term, key) pairs already shown the OSC notice
        self._syncing = False        # guard: programmatic chip sync vs user click
        # toolbar chip buttons, populated by _build_toolbar; empty here so a
        # _sync during _build_menu (which runs first) is a harmless no-op.
        self._mode_buttons = {}
        self._colors_buttons = {}
        self._tui_buttons = {}
        self._build_menu()
        self._build_toolbar()
        self._build_security_indicator()
        self._apply_locks()

        # Launch-CLI tabs take precedence over a restored session: opening
        # `secure-terminal --title x -- htop` should give you exactly that.
        if launch is not None and launch.tabs:
            for spec in launch.tabs:
                self._open_launch_tab(spec)
        else:
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
        self._tab_ids[term] = self._next_tab_id       # stable id for ctl matching
        self._next_tab_id += 1
        term.zoom_step.connect(self._on_zoom_step)
        term.tab_step.connect(self._on_tab_step)
        term.tab_move.connect(self._on_tab_move)
        term.apply_hook(self._hook_config)
        term.hook_notice.connect(self._on_hook_notice)
        term.shell_exited.connect(lambda t=term: self._on_shell_exited(t))
        term.title_changed.connect(
            lambda title, t=term: self._on_tab_title(t, title))
        term.notified.connect(self._on_notify)
        term.cwd_changed.connect(lambda path, t=term: self._on_cwd_changed(t, path))
        term.clipboard_read_requested.connect(
            lambda t=term: self._on_clipboard_read_requested(t))
        term.advise_signal.connect(lambda msg, t=term: self._on_advise(t, msg))
        term.osc_used.connect(lambda key, t=term: self._on_osc_used(t, key))
        term.paste_review_requested.connect(
            lambda raw, delay, t=term: self._show_review(t, raw, delay, 'paste'))
        term.copy_review_requested.connect(
            lambda raw, delay, t=term: self._show_review(t, raw, delay, 'copy'))
        term.paste_review_resolved.connect(
            lambda t=term: self._hide_paste_review(t))
        index = self.tabs.addTab(term, term.cwd_basename() or 'shell')
        self.tabs.setCurrentIndex(index)
        # auto-colour the new tab so it differs from its neighbour, unless one is
        # already set (a restored or user-chosen colour wins). Advance past a
        # palette colour that matches the adjacent tab's actual colour, so the
        # distinction holds even after a neighbour was recoloured or moved.
        if self._auto_tab_colors and term not in self._tab_colors:
            prev = None
            if index > 0:
                prev = self._tab_colors.get(self.tabs.widget(index - 1))
            color = TAB_PALETTE[self._auto_color_idx % len(TAB_PALETTE)]
            for _ in range(len(TAB_PALETTE)):
                color = TAB_PALETTE[self._auto_color_idx % len(TAB_PALETTE)]
                self._auto_color_idx += 1
                if color != prev:
                    break
            self.set_tab_color(index, QColor(color))
        self._renumber_tabs()          # number a tab that got no auto-colour too
        self._sync_chrome_to_tab()
        term.setFocus()
        return index

    def _make_banner(self):
        """A dismissible, yellowish advisory banner shown above the tabs. Its text
        is selectable/copyable but lives OUTSIDE any terminal document, so it is
        never mistaken for -- or copied as -- program output."""
        frame = QFrame(self)
        frame.setObjectName('advisory')
        frame.setVisible(False)
        frame.setStyleSheet(
            '#advisory{background:#fdf3d0;border-bottom:1px solid #e5c975}'
            '#advisory QLabel{color:#6b5510;font-size:13px}'
            '#advisory QPushButton{border:none;background:transparent;'
            'color:#6b5510;font-size:15px;font-weight:700}'
            '#advisory QPushButton:hover{color:#3a2e08}')
        row = QHBoxLayout(frame)
        row.setContentsMargins(14, 8, 8, 8)
        row.setSpacing(10)
        row.addWidget(QLabel('\u26a0', frame))          # warning sign
        self._banner_label = QLabel(frame)
        self._banner_label.setWordWrap(True)
        self._banner_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self._banner_label, 1)
        close = QPushButton('\u2715', frame)            # X
        close.setFixedSize(24, 24)
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setFocusPolicy(Qt.FocusPolicy.NoFocus)    # do not steal the caret
        close.setToolTip('Dismiss')
        close.clicked.connect(self._dismiss_advisory)
        row.addWidget(close)
        return frame

    def _on_advise(self, term, message, kind='tui'):
        """A terminal raised an advisory. It belongs to THAT tab, so remember it
        per-tab (with its kind) and only show the banner while its tab is current --
        otherwise the hint would hang over an unrelated terminal. kind is 'tui' for
        a full-screen hint (auto-dismissed when TUI is enabled) or 'osc'."""
        self._advisories[term] = (kind, message)
        if term is self.current():
            self._refresh_banner()

    def _on_osc_used(self, term, key):
        """A program used an OSC escape of TYPE `key` that pure CLI mode strips.
        Surface a dismissible notice at most once per TYPE per tab, unless notices
        are off globally or for that type. De-duplicating here (not in the terminal)
        means re-enabling a notice re-arms a tab that was never actually shown it."""
        if not self._osc_notice or key in self._osc_notice_off:
            return
        if (term, key) in self._osc_notified:
            return
        self._osc_notified.add((term, key))
        entry = OSC_FEATURE_BY_KEY.get(key)
        label = entry[0].lower() if entry else 'an escape'
        self._on_advise(term, 'An application used an OSC escape (' + label + '), '
                        'which the safe CLI mode neutralized. Enable it under '
                        'View > OSC features if you trust the source; turn this '
                        'notice off (all or per type) in View > Notify on OSC use.',
                        'osc')

    def _dismiss_advisory(self):
        """The X button: clear the current tab's advisory and hide the banner."""
        self._advisories.pop(self.current(), None)
        self._refresh_banner()

    def _clear_advisories(self, kind):
        """Drop every tab's advisory of a given kind (e.g. all 'osc' notices once
        OSC handling is enabled, or the notice is switched off) and refresh."""
        for term in [t for t, entry in self._advisories.items() if entry[0] == kind]:
            self._advisories.pop(term, None)
        self._refresh_banner()

    def _refresh_banner(self):
        """Show the current tab's pending advisory, or hide the banner if it has
        none. Called on every tab switch so the banner always matches the tab."""
        entry = self._advisories.get(self.current())
        if entry:
            self._banner_label.setText(entry[1])
            self._banner.setVisible(True)
        else:
            self._banner.setVisible(False)

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
        term = SecureTerminal(tui=self._default_tui, command=command or None,
                              cli_terminfo=self._default_cli_terminfo)
        term.apply_theme(self._default_theme)
        term.apply_zoom(self._default_zoom)
        term.set_font_family(self._default_font_family)
        term.apply_mode(self._default_mode)
        term.apply_colors(self._default_colors)
        term.apply_markings(self._default_markings)
        term.apply_scrollback(self._scrollback)
        term.apply_paste_delay(self._paste_delay)
        term.apply_paste_warn(self._paste_warn)
        term.apply_copy_warn(self._copy_warn)
        term.apply_bell(self._default_bell)
        term.apply_bell_sound(self._default_bell_sound)
        self._connect_bell_tray(term)
        self._apply_osc_defaults(term)
        self._add_tab(term)

    def _osc_locked(self, feat):
        """An OSC feature is admin-locked directly by its own key, or (for the title
        / notify pair) via the legacy allow_title lock."""
        return feat in self._locked or (
            feat in ('osc_title', 'osc_notify') and 'allow_title' in self._locked)

    def _open_launch_tab(self, spec):
        """Open a tab from a parsed launch spec. Besides --title/--tui/--mode/command,
        a tab may override the window defaults for colours, cli-terminfo, bell and
        individual OSC features. Admin locks still win: a locked setting is NEVER
        overridable from the command line."""
        def _tab(key, default):
            val = spec.get(key)
            return default if val is None or key in self._locked else val

        tui = self._default_tui if (spec.get('tui') is None
                                    or 'tui' in self._locked) else spec['tui']
        cli_terminfo = _tab('cli_terminfo', self._default_cli_terminfo)
        term = SecureTerminal(tui=tui, command=spec.get('command') or None,
                              cli_terminfo=cli_terminfo)
        term.apply_theme(self._default_theme)
        term.apply_zoom(self._default_zoom)
        term.set_font_family(spec.get('font_family') or self._default_font_family)
        mode = spec.get('mode')
        if mode not in DISPLAY_MODES or 'unicode_mode' in self._locked:
            mode = self._default_mode
        term.apply_mode(mode)
        term.apply_colors(_tab('colors', self._default_colors))
        term.apply_markings(self._default_markings)
        term.apply_scrollback(self._scrollback)
        term.apply_paste_delay(self._paste_delay)
        term.apply_paste_warn(self._paste_warn)
        term.apply_copy_warn(self._copy_warn)
        bell = self._default_bell
        if spec.get('bell') is not None and 'bell' not in self._locked:
            bell = SecureTerminal._parse_bell(spec['bell'])
        term.apply_bell(bell)
        term.apply_bell_sound(self._default_bell_sound)
        self._connect_bell_tray(term)
        self._apply_osc_defaults(term)
        # per-tab OSC feature overrides: enable each named, valid, unlocked feature.
        valid = {feature[0] for feature in OSC_FEATURES}
        for feat in (spec.get('osc') or []):
            if feat in valid and not self._osc_locked(feat):
                term.apply_osc(feat, True)
        self._add_tab(term)
        if spec.get('title'):
            self._user_titles[term] = spec['title']
            self._refresh_tab_label(term)

    # -- single-instance IPC server (owner-only socket) -----------------------
    def start_instance_server(self, group='default'):
        """Listen on the group's owner-only socket so later launches reuse this
        process. A stale socket from a crashed instance is cleared first."""
        self._instance_group = group
        try:
            ipc.ensure_socket_dir()
        except OSError:
            return                          # no runtime dir -> no single instance
        path = ipc.socket_path(group)
        QLocalServer.removeServer(path)     # clear a stale socket, if any
        self._server = QLocalServer(self)
        self._server.setSocketOptions(
            QLocalServer.SocketOption.UserAccessOption)   # 0700, same-UID only
        if not self._server.listen(path):  # pragma: no cover - a fresh same-UID socket path listens; a listen failure is a rare OS-level fault
            self._server = None
            return
        self._server.newConnection.connect(self._on_instance_connection)

    def _on_instance_connection(self):
        conn = self._server.nextPendingConnection()
        if conn is None:
            return
        framer = ipc.Framer()

        def on_ready():
            try:
                payload = framer.feed(bytes(conn.readAll()))
            except ValueError:
                conn.abort()
                return
            if payload is None:
                return                      # frame not complete yet
            reply = self._dispatch_request(payload)
            conn.write(ipc.frame(json.dumps(reply).encode('utf-8')))
            conn.flush()
            conn.disconnectFromServer()

        conn.readyRead.connect(on_ready)

    def _dispatch_request(self, payload):
        """Handle one IPC request; return a reply dict. Every request is same-UID
        (owner-only socket) but is still type-validated. Only 'open'/'ping' are
        handled here; remote-control ops are added (and gated) separately."""
        try:
            request = json.loads(payload.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return {'ok': False, 'error': 'malformed request'}
        if not isinstance(request, dict):
            return {'ok': False, 'error': 'malformed request'}
        op = request.get('op')
        # 'open'/'ping' are the single-instance mechanism, always allowed. The
        # remote-control ops (ctl-*) are the inject/list surface and are refused
        # unless an admin enabled remote_control in a privileged directory.
        if op == 'ping':
            return {'ok': True, 'pid': os.getpid()}
        if op == 'open':
            return self._ipc_open(request)
        if isinstance(op, str) and op.startswith('ctl-'):
            if not self._remote_control:
                return {'ok': False, 'error': 'remote control is disabled; an '
                        'administrator must set remote_control=true in '
                        '/etc/secure-terminal.d'}
            return self._ipc_ctl(op, request)
        return {'ok': False, 'error': 'unknown op: %r' % (op,)}

    def _find_tab(self, match):
        """Resolve a `ctl --tab` matcher ('id:N', 'title:NAME', or a bare title)
        to a terminal, or None. The first title match wins."""
        if not isinstance(match, str):
            return None
        kind, _, value = match.partition(':')
        if not value:
            kind, value = 'title', match
        for term, tid in self._tab_ids.items():
            index = self.tabs.indexOf(term)
            if index < 0:
                continue
            if kind == 'id' and str(tid) == value:
                return term
            if kind == 'title' and self.tabs.tabText(index) == value:
                return term
        return None

    def _ipc_ctl(self, op, request):
        if op == 'ctl-ls':
            tabs = []
            for term, tid in sorted(self._tab_ids.items(), key=lambda kv: kv[1]):
                index = self.tabs.indexOf(term)
                if index < 0:
                    continue
                tabs.append({'id': tid, 'title': self.tabs.tabText(index),
                             'mode': term.current_mode(),
                             'tui': term.tui_active()})
            return {'ok': True, 'tabs': tabs}
        if op in ('ctl-send-text', 'ctl-set-tab-title', 'ctl-dump-tab'):
            term = self._find_tab(request.get('tab'))
            if term is None:
                return {'ok': False, 'error': 'no tab matched %r'
                        % (request.get('tab'),)}
            if op == 'ctl-send-text':
                text = request.get('text')
                if not isinstance(text, str):
                    return {'ok': False, 'error': 'text must be a string'}
                # route through the paste sanitizer: injected text can no more
                # smuggle an escape/control than a paste can.
                term._write(sanitize_paste(text).encode('utf-8'))
                return {'ok': True}
            if op == 'ctl-dump-tab':
                # read back the tab's CURRENT rendered text (already sanitized --
                # it is exactly what is on screen), for drive-and-assert E2E tests.
                text = term.toPlainText()
                lines = request.get('lines')
                if isinstance(lines, int) and lines > 0:
                    text = '\n'.join(text.split('\n')[-lines:])
                if len(text) > _DUMP_MAX:
                    text = text[-_DUMP_MAX:]     # tail-cap to stay under the frame
                return {'ok': True, 'text': text}
            title = request.get('title')
            if not isinstance(title, str):
                return {'ok': False, 'error': 'title must be a string'}
            self._user_titles[term] = title
            self._refresh_tab_label(term)
            return {'ok': True}
        return {'ok': False, 'error': 'unknown ctl op: %r' % (op,)}

    def _ipc_open(self, request):
        tabs = request.get('tabs')
        opened = 0
        for spec in (tabs if isinstance(tabs, list) else []):
            if isinstance(spec, dict):
                self._open_launch_tab(_sanitize_tab_spec(spec))
                opened += 1
        if opened == 0 and self.tabs.count() == 0:
            self.new_tab()                  # a bare reuse: ensure a usable tab
        self.show()
        self.raise_()
        self.activateWindow()
        return {'ok': True, 'opened': opened}

    def _restore_tab(self, info):
        """Recreate a tab from saved session state: its settings, name, colour
        and scrollback history, under a fresh shell."""
        history = info.get('text') if isinstance(info.get('text'), str) else ''
        cwd = info.get('cwd')
        term = SecureTerminal(tui=bool(info.get('tui')), history=history,
                              cli_terminfo=self._default_cli_terminfo,
                              cwd=cwd if isinstance(cwd, str) and cwd else None)
        theme = info.get('theme')
        term.apply_theme(theme if theme in THEMES else self._default_theme)
        try:
            term.apply_zoom(int(info.get('zoom', self._default_zoom)))
        except (TypeError, ValueError):
            term.apply_zoom(self._default_zoom)
        term.set_font_family(info.get('font_family') or self._default_font_family)
        mode = info.get('mode')
        term.apply_mode(mode if mode in DISPLAY_MODES else self._default_mode)
        term.apply_colors(bool(info.get('colors')))
        term.apply_markings(bool(info.get('markings', True)))
        try:
            term.apply_scrollback(int(info.get('scrollback', self._scrollback)))
        except (TypeError, ValueError):
            term.apply_scrollback(self._scrollback)
        term.apply_paste_delay(self._paste_delay)
        term.apply_paste_warn(self._paste_warn)
        term.apply_copy_warn(self._copy_warn)
        # restore the full per-feature OSC map when present; fall back to the legacy
        # allow_title boolean for sessions saved before the granular controls (which
        # collapsed hyperlink/clipboard/colour/cwd/iTerm2 into title+notify).
        osc_state = info.get('osc')
        if isinstance(osc_state, dict):
            for _f in OSC_FEATURES:
                locked = _f[0] in self._locked or (
                    _f[0] in ('osc_title', 'osc_notify') and 'allow_title' in self._locked)
                term.apply_osc(_f[0], self._osc_defaults.get(_f[0], False) if locked
                               else bool(osc_state.get(_f[0], False)))
        else:
            term.apply_allow_title(bool(info.get('allow_title')))
        # an admin-locked bell must win over whatever the saved session carried
        term.apply_bell(self._default_bell if 'bell' in self._locked
                        else info.get('bell', self._default_bell))
        term.apply_bell_sound(self._default_bell_sound)
        self._connect_bell_tray(term)
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
        if not self._confirm_running_close(
                'Close tab?',
                'A program is still running in this tab. Close it anyway?',
                [term]):
            return
        term.shutdown()
        self._user_titles.pop(term, None)
        self._prog_titles.pop(term, None)
        self._tab_colors.pop(term, None)
        self._advisories.pop(term, None)
        self._osc_notified = {p for p in self._osc_notified if p[0] is not term}
        self._tab_ids.pop(term, None)
        self.tabs.removeTab(index)
        term.deleteLater()
        self._renumber_tabs()          # numbers shift left after a close
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
        # plain text only; setTabText does not interpret markup. The default is
        # the working-directory name (tracked live by the fg poll), which says far
        # more than a static "shell"; fall back to "shell" only if it is unreadable.
        default = term.cwd_basename() or 'shell'
        self.tabs.setTabText(index, user or program or default)
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
            self._tab_colors.pop(term, None)
        else:
            self._tab_colors[term] = color.name()
        # the colour swatch also carries the tab's number, so refresh every tab
        # (a colour change does not move tabs, but this keeps one code path).
        self._renumber_tabs()

    # -- find in scrollback: per-tab and across all tabs ----------------------
    _FIND_FMT = None

    def _find_format(self):
        if MainWindow._FIND_FMT is None:
            fmt = QTextCharFormat()
            fmt.setBackground(QColor('#ffd54a'))     # amber highlight
            fmt.setForeground(QColor('#1a1a1a'))     # readable on amber
            MainWindow._FIND_FMT = fmt
        return MainWindow._FIND_FMT

    def show_find(self):
        term = self.current()
        if term is None:
            return
        # seed with the current selection, if any, for a quick "find this"
        sel = term.textCursor().selectedText()
        if sel and '\u2029' not in sel:      # not a multi-line selection (Qt joins rows with U+2029)
            self._find_bar.input.setText(sel)
        self._find_bar.setVisible(True)
        self._find_bar.input.setFocus()
        self._find_bar.input.selectAll()
        self._find_update()

    def hide_find(self):
        self._find_bar.setVisible(False)
        for i in range(self.tabs.count()):
            self.tabs.widget(i).setExtraSelections([])
        term = self.current()
        if term is not None:
            term.reset_caret()
            term.setFocus()

    # -- paste / copy review (the in-window bar) ------------------------------
    def _show_review(self, term, raw, delay, kind):
        """A tab is holding risky text crossing the boundary (a paste coming in or
        a copy going out): show the review bar for it. Only the active tab can be
        the target, so a background tab's request is ignored (its text stays held
        until the tab is focused and resolved)."""
        if term is not self.current():
            return
        self._review_bar.show_review(term, raw, delay, kind)

    def _hide_paste_review(self, term):
        """The text was resolved (crossed or rejected): hide the bar and return
        focus to the terminal so typing resumes."""
        self._review_bar.hide_review()
        if term is self.current():
            term.setFocus()

    def _find_flags(self):
        flags = QTextDocument.FindFlag(0)
        if self._find_bar.case.isChecked():
            flags |= QTextDocument.FindFlag.FindCaseSensitively
        return flags

    def _highlight_matches(self, term, query, flags):
        """Highlight every match of `query` in `term`; return the match count."""
        if not query:
            term.setExtraSelections([])
            return 0
        selections = []
        doc = term.document()
        cursor = QTextCursor(doc)
        fmt = self._find_format()
        while True:
            cursor = doc.find(query, cursor, flags)
            if cursor.isNull():
                break
            sel = QTextEdit.ExtraSelection()
            sel.cursor = cursor
            sel.format = fmt
            selections.append(sel)
        term.setExtraSelections(selections)
        return len(selections)

    def _find_update(self):
        """Re-run after the query, case or scope changed: highlight matches and
        move to the first one from the top of the current tab."""
        query = self._find_bar.input.text()
        flags = self._find_flags()
        all_tabs = self._find_bar.all_tabs.isChecked()
        term = self.current()
        total = 0
        if all_tabs:
            tabs_hit = 0
            for i in range(self.tabs.count()):
                n = self._highlight_matches(self.tabs.widget(i), query, flags)
                total += n
                tabs_hit += 1 if n else 0
            if query:
                self._find_bar.count.setText(
                    '%d in %d tab%s' % (total, tabs_hit,
                                        '' if tabs_hit == 1 else 's')
                    if total else 'no matches')
            else:
                self._find_bar.count.setText('')
        else:
            for i in range(self.tabs.count()):
                if self.tabs.widget(i) is not term:
                    self.tabs.widget(i).setExtraSelections([])
            total = self._highlight_matches(term, query, flags)
            if not query:
                self._find_bar.count.setText('')
            elif total == 0:
                self._find_bar.count.setText('no matches')
            else:
                self._find_bar.count.setText(
                    '%d match%s' % (total, '' if total == 1 else 'es'))
        # jump to the first match from the top of the current tab
        if query and term is not None:
            cursor = term.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            term.setTextCursor(cursor)
            self._find_step(False, from_update=True)

    def _find_step(self, backward, from_update=False):
        """Move to the next (or previous) match. In all-tabs mode, roll over into
        the neighbouring tab that has a match when the current tab is exhausted."""
        query = self._find_bar.input.text()
        if not query:
            return
        flags = self._find_flags()
        if backward:
            flags |= QTextDocument.FindFlag.FindBackward
        term = self.current()
        if term is not None and term.find(query, flags):
            term.ensureCursorVisible()
            return
        if not self._find_bar.all_tabs.isChecked():
            # wrap within this tab
            if term is None:
                return
            cursor = term.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End if backward
                                else QTextCursor.MoveOperation.Start)
            term.setTextCursor(cursor)
            if term.find(query, flags):
                term.ensureCursorVisible()
            return
        if from_update:
            return                        # the first-match seed found nothing here
        # all-tabs: hop to the next/prev tab that has a match
        count = self.tabs.count()
        start = self.tabs.currentIndex()
        order = range(1, count + 1)
        for off in order:
            idx = (start + (-off if backward else off)) % count
            other = self.tabs.widget(idx)
            cursor = other.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End if backward
                                else QTextCursor.MoveOperation.Start)
            other.setTextCursor(cursor)
            if other.find(query, flags):
                self.tabs.setCurrentIndex(idx)
                other.ensureCursorVisible()
                other.setFocus()
                self._find_bar.input.setFocus()
                return

    def _number_icon(self, n, color):
        """The tab's position number drawn inside its colour swatch (a neutral
        grey dot when the tab has no colour), so tabs are quickly addressable by
        number. Text colour follows the swatch luminance so the digit stays
        readable. Drawn, ASCII-only, always available."""
        pixmap = QPixmap(18, 18)
        pixmap.fill(QColor(0, 0, 0, 0))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        dot = QColor(color) if color is not None else QColor('#9aa0a6')
        painter.setBrush(QBrush(dot))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(1, 1, 16, 16, 4, 4)
        label = str(n)
        # pick the digit colour by relative luminance, the same rule the contrast
        # guard uses -- HSL lightness misjudges saturated swatches (bright yellow
        # would wrongly take white text), luminance does not.
        painter.setPen(QColor('#000000')
                       if luminance((dot.red(), dot.green(), dot.blue())) > 127
                       else QColor('#ffffff'))
        font = QFont()
        font.setPixelSize(11 if len(label) == 1 else 9)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(QRect(0, 0, 18, 18),
                         Qt.AlignmentFlag.AlignCenter, label)
        painter.end()
        return QIcon(pixmap)

    def _renumber_tabs(self):
        """Redraw every tab's number swatch to match its current position, so the
        numbers stay 1..N left to right after a tab is added, closed or moved."""
        for i in range(self.tabs.count()):
            term = self.tabs.widget(i)
            cname = self._tab_colors.get(term)
            color = QColor(cname) if cname else None
            self.tabs.setTabIcon(i, self._number_icon(i + 1, color))

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
        # Keep the current tab's default label in step with its working directory
        # (only when it is not overridden by a user or program title).
        if term is not None and not self._user_titles.get(term) \
                and not self._prog_titles.get(term):
            self._refresh_tab_label(term)

    def current(self):
        return self.tabs.currentWidget()

    def current_zoom_percent(self):
        """The active tab's zoom (percent), so tooltip text scales with it. Falls
        back to the window default when there is no tab yet."""
        term = self.current()
        if term is not None:
            return term.current_zoom()
        return getattr(self, '_default_zoom', 100)

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
        self._refresh_banner()          # the banner follows the current tab
        self.zoom_box.blockSignals(True)
        self.zoom_box.setValue(term.current_zoom())
        self.zoom_box.blockSignals(False)
        active = term.current_theme()
        for key, action in self._theme_actions.items():
            action.setChecked(key == active)
        self._sync_mode_toggles(term.current_mode())
        # These are connected via `toggled`, which fires on a programmatic
        # setChecked too -- so reflecting the current tab's state here would call
        # set_colors/set_tui/set_title and rewrite the persisted defaults on every
        # tab switch (and set_tui would even force the tab's mode). Block signals
        # so a tab switch only DISPLAYS state, never mutates it.
        _sync = [
            (self.act_colors, term.colors_enabled()),
            (self.act_markings, term.markings_enabled()),
            (self.act_tui, term.current_tui()),
            (self.act_title, term.allow_title_enabled()),
        ] + [(self._osc_actions[k], term.osc_enabled(k)) for k in self._osc_actions]
        for action, value in _sync:
            action.blockSignals(True)
            action.setChecked(value)
            action.blockSignals(False)
        # the Bell channels use `triggered` (fires only on a user click), so a
        # programmatic setChecked here just reflects the current tab, no mutation
        for channel, action in self._bell_actions.items():
            action.setChecked(term.bell_enabled(channel))
        self._set_chip(self._colors_buttons,
                       'on' if term.colors_enabled() else 'off')
        self._set_chip(self._tui_buttons,
                       'tui' if term.current_tui() else 'cli')
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
        if 'unicode_mode' in self._locked:
            return                        # admin-locked; not user-changeable
        term = self.current()
        if term is not None:
            term.apply_mode(mode)
        self._sync_mode_toggles(mode)
        self._update_security_indicator()
        self._default_mode = mode
        self._persist()

    def set_font_family(self, family):
        """Set the current tab's font family and make it the default for new tabs
        (existing tabs keep their own, mirroring how mode/theme are sticky). An
        empty or admin-locked value is ignored; the widget falls back on a family
        that is not installed."""
        if 'font_family' in self._locked:
            return                        # admin-locked; not user-changeable
        family = (family or '').strip() or DEFAULT_FONT_FAMILY
        term = self.current()
        if term is not None:
            term.set_font_family(family)
        self._default_font_family = family
        self._persist()

    def choose_font(self):
        """Per-tab font picker: a monospaced-only font dialog seeded with the
        current tab's family. Only the family is taken (size is the zoom control);
        a proportional pick is prevented by the dialog's monospaced filter and, as
        a backstop, the widget's fixed-pitch fallback chain."""
        term = self.current()
        if term is None:
            return
        current = QFont(term.current_font_family())
        try:
            opts = QFontDialog.FontDialogOption.MonospacedFonts
        except AttributeError:
            opts = QFontDialog.FontDialogOption(0)
        font, ok = QFontDialog.getFont(current, self, 'Terminal font', opts)
        if ok:
            self.set_font_family(font.family())

    def _sync_mode_toggles(self, mode):
        """Check the button for the active display mode in the exclusive group.
        setChecked() does not fire triggered, so this cannot loop back into
        set_mode."""
        action = self._mode_actions.get(mode)
        if action is not None and not action.isChecked():
            action.setChecked(True)
        self._set_chip(self._mode_buttons, mode)

    def set_colors(self, enabled):
        if 'colors' in self._locked:
            return                        # admin-locked; not user-changeable
        term = self.current()
        if term is not None:
            term.apply_colors(enabled)
        self.act_colors.setChecked(enabled)
        self._set_chip(self._colors_buttons, 'on' if enabled else 'off')
        self._default_colors = bool(enabled)
        self._persist()

    def set_auto_tab_colors(self, enabled):
        if 'auto_tab_colors' in self._locked:
            return                        # admin-locked; not user-changeable
        self._auto_tab_colors = bool(enabled)
        self.act_auto_tab_colors.setChecked(enabled)
        self._persist()               # affects new tabs; existing keep their colour

    def set_osc_notice(self, enabled):
        if 'osc_notice' in self._locked:
            return                        # admin-locked; not user-changeable
        self._osc_notice = bool(enabled)
        self.act_osc_notice.setChecked(enabled)
        if not self._osc_notice:
            self._clear_advisories('osc')   # a switched-off notice must not linger
        self._persist()

    def set_osc_notice_type(self, key, notify):
        """Mute or un-mute the OSC notice for one type (the feature is unaffected;
        this only controls whether its neutralized use raises a banner)."""
        if notify:
            self._osc_notice_off.discard(key)
        else:
            self._osc_notice_off.add(key)
            self._clear_advisories('osc')   # drop a showing notice for a muted type
        self._persist()

    def set_markings(self, enabled):
        if 'colored_markings' in self._locked:
            return                        # admin-locked; not user-changeable
        term = self.current()
        if term is not None:
            term.apply_markings(enabled)
        self.act_markings.setChecked(enabled)
        self._default_markings = bool(enabled)
        self._persist()

    def set_tui(self, enabled):
        if 'tui' in self._locked:
            return                        # admin-locked; not user-changeable
        term = self.current()
        if term is not None:
            term.apply_tui(enabled)
            if enabled:
                # Turning TUI on answers a "this program needs a full-screen
                # interface -- turn on TUI mode" advisory, so that hint is no longer
                # valid: clear it. Only the TUI hint -- an unrelated OSC notice on
                # the same tab must stay.
                if self._advisories.get(term, (None,))[0] == 'tui':
                    self._advisories.pop(term, None)
                    self._refresh_banner()
                # Any non-'show' mode makes a TUI unreadable (box-drawing becomes
                # a box in Box mode, or a badge in reveal/detail that breaks the grid),
                # so lean this TAB to 'show'. Do it on the term only -- NOT via
                # set_mode, which would persist 'show' as the global default for
                # every future tab -- and remember the prior mode so turning TUI
                # off restores it. Skip when the mode is admin-locked (a forced
                # mode is a deliberate hardening choice to respect).
                if term.current_mode() != 'show' \
                        and 'unicode_mode' not in self._locked:
                    self._pre_tui_mode[term] = term.current_mode()
                    term.apply_mode('show')
            else:
                prior = self._pre_tui_mode.pop(term, None)
                if prior is not None:
                    term.apply_mode(prior)
            self._sync_mode_toggles(term.current_mode())
        self._default_tui = bool(enabled)
        self.act_tui.setChecked(enabled)
        self._set_chip(self._tui_buttons, 'tui' if enabled else 'cli')
        self._update_tui_indicator()
        self._update_security_indicator()
        self._persist()

    def set_cli_terminfo(self, enabled):
        """Set the restricted-terminfo default for new tabs. TERM is fixed when a
        shell starts, so this cannot change a running tab -- only new ones."""
        if 'cli_terminfo' in self._locked:
            return
        self._default_cli_terminfo = bool(enabled)
        self.act_cli_terminfo.setChecked(bool(enabled))
        self._persist()

    def _update_tui_indicator(self):
        term = self.current()
        active = term is not None and term.tui_active()
        self.tui_dot_action.setVisible(active)

    # -- security indicator: three lamps, one per independent risk axis -------
    def _build_security_indicator(self):
        self.sec_display = QPushButton(self)
        self.sec_mode = QPushButton(self)
        self.sec_osc = QPushButton(self)
        for lamp in (self.sec_display, self.sec_mode, self.sec_osc):
            lamp.setFlat(True)
            lamp.setCursor(Qt.CursorShape.PointingHandCursor)
            lamp.clicked.connect(self._show_security_details)
            self.statusBar().addPermanentWidget(lamp)
        self._update_security_indicator()

    def _osc_level(self):
        """The OSC risk axis as (colour, short, detail): green when every OSC
        feature is neutralized (the default); yellow when a low/medium one is
        enabled; red when a high-risk one (clipboard) is enabled."""
        term = self.current()
        enabled = [k for k in self._osc_defaults if self._osc_defaults[k]]
        if term is not None:
            enabled = [k for k in self._osc_actions if term.osc_enabled(k)]
        if not enabled:
            return ('#1f8a54', 'OSC off',
                    'OSC: all neutralized (green).\n\n'
                    'Every way OUTPUT can reach out of the terminal (set the window '
                    'title, write your clipboard, make hyperlinks, change colours, '
                    '...) is turned off, so viewing untrusted output cannot trigger '
                    'those side-effects. Enable individual ones under View > OSC '
                    'features, at your own risk.\n\n' + _OSC_THREAT_MODEL)
        risks = [OSC_FEATURE_BY_KEY[k][3] for k in enabled]
        labels = ', '.join(OSC_FEATURE_BY_KEY[k][0] for k in enabled)
        if 'high' in risks:
            colour, word = '#e5484d', 'OSC red'
        else:
            colour, word = '#e5a50a', 'OSC on'
        return (colour, word,
                'OSC: enabled features (%s).\n\n' % ('high risk' if 'high' in risks
                                                     else 'elevated') +
                'You have enabled: ' + labels + '.\n\n'
                'Untrusted output can now trigger these side-effects (not only a '
                'program you chose to run -- any output, including a file you view '
                'or a server banner). Turn them off under View > OSC features to '
                'return to green.\n\n' + _OSC_THREAT_MODEL)

    def _display_level(self):
        """The display (unicode) risk axis as (colour, short, detail). Show
        renders deceptive glyphs (red). Reveal is safe AND lossless -- the exact
        <U+XXXX> codepoint is shown (green). Box is safe too -- non-ASCII becomes
        a coloured box, hard to miss (green); lossy, but nothing deceptive."""
        term = self.current()
        mode = term.current_mode() if term is not None else 'detail'
        if mode == 'show':
            return ('#d83933', 'Show',
                    'Display: SHOW (red).\n\n'
                    'Non-ASCII output is drawn as its glyph. With colour markings on '
                    '(the default) each glyph is tinted by its risk class -- a '
                    'homoglyph in rose -- so a look-alike is flagged rather than '
                    'posing cleanly as ASCII; but you still have to NOTICE the '
                    'colour, so this stays the highest risk, above TUI mode. The '
                    'invisible, bidi and control classes are neutralized to a box '
                    'and pasting is still sanitized.\n\nSwitch to Box or Reveal to '
                    'remove the risk entirely.')
        if mode == 'reveal':
            return ('#1f8a54', 'Reveal',
                    'Display: REVEAL (green, safe).\n\n'
                    'Every non-ASCII character is shown as a <U+XXXX> badge: you '
                    'see the exact codepoint, so nothing can pose as a look-alike '
                    'and nothing is silently dropped. Escape sequences are removed '
                    'and pasting is sanitized.')
        if mode == 'detail':
            return ('#1f8a54', 'Detail',
                    'Display: DETAIL (green, safe).\n\n'
                    'Like Reveal but verbose: every non-ASCII character is shown '
                    'as a <U+XXXX NAME> badge -- the exact codepoint plus its '
                    'official Unicode name -- so a homoglyph reads as its '
                    'identity, not just a number (the annotation unicode-show '
                    'prints). Escape sequences are removed and pasting is '
                    'sanitized.')
        return ('#1f8a54', 'Box',
                'Display: BOX (green, safe).\n\n'
                'Non-ASCII output is drawn as a coloured box -- one per character, '
                'coloured by risk class -- so nothing deceptive is drawn and a '
                'neutralized character is hard to miss. Still lossy: you see that '
                'something was there, not which codepoint; switch to Reveal for '
                'the exact <U+XXXX>. Escape sequences are removed and pasting is '
                'sanitized either way.\n\nThis is a DISPLAY setting: it never alters '
                'the bytes a program pipes or redirects elsewhere, so "cat file | '
                'bash" runs the file regardless of the mode.')

    def _mode_level(self):
        """The interpretation (mode) risk axis: TUI interprets escapes in a
        confined screen (yellow); the strict CLI mode is green."""
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
                    'Turn TUI mode off to return to the safe CLI mode.')
        return ('#1f8a54', 'CLI',
                'Mode: CLI (green, the safe default).\n\n'
                'No escape parser: every escape sequence in program output is '
                'removed in the renderer, in every unicode display mode, '
                'regardless of TERM (which stays a normal xterm-256color so the '
                'opt-in TUI mode can run full-screen programs). So merely '
                'viewing a file or log (the "cat a crafted file and it runs a '
                'command" risk) cannot execute anything here, whatever the '
                'unicode setting.\n\n'
                'How non-ASCII characters themselves are shown is the separate '
                'unicode setting (Box / Reveal / Show); none of those re-enable '
                'escapes, so none can be used to deceive you into running code.')

    def _update_security_indicator(self):
        for lamp, level, axis in (
                (self.sec_display, self._display_level(), 'Display'),
                (self.sec_mode, self._mode_level(), 'Mode'),
                (self.sec_osc, self._osc_level(), 'OSC')):
            colour, short, _detail = level
            lamp.setIcon(_dot_icon(colour))
            lamp.setText(' ' + short)
            lamp.setToolTip(axis + ': ' + short + ' -- click for details')

    def _show_security_details(self):
        detail = (self._display_level()[2] + '\n\n' + self._mode_level()[2]
                  + '\n\n' + self._osc_level()[2])
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
        _select_labels(dialog)
        dialog.exec()

    def set_allow_title(self, enabled):
        if 'allow_title' in self._locked:
            return                        # admin-locked; not user-changeable
        term = self.current()
        if term is not None:
            term.apply_allow_title(enabled)
        self._default_allow_title = bool(enabled)
        self.act_title.setChecked(enabled)
        if enabled:
            # letting titles/notifications through answers the OSC "was ignored"
            # notice, so it is no longer valid.
            self._clear_advisories('osc')
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

    # -- granular OSC features ------------------------------------------------
    def _apply_osc_defaults(self, term):
        for key, enabled in self._osc_defaults.items():
            term.apply_osc(key, enabled)
        term.set_clipboard_read_always(self._osc_clipboard_read_always)

    def set_clipboard_read_always(self, on):
        """Global 'always allow clipboard read' default. Applies to every tab (an
        explicit per-tab decision still wins) and to new tabs."""
        if 'osc_clipboard_read_always' in self._locked:
            return
        self._osc_clipboard_read_always = bool(on)
        self.act_clip_read_always.setChecked(bool(on))
        for i in range(self.tabs.count()):
            self.tabs.widget(i).set_clipboard_read_always(bool(on))
        self._persist()

    def set_osc(self, key, enabled):
        """Enable/disable one OSC feature: apply it to the current tab, remember it
        as the default for new tabs, persist, and refresh the security lamp (an
        enabled feature dims it by its risk class)."""
        if key in self._locked:
            return                        # admin-locked; not user-changeable
        # a legacy lock=allow_title locks the title + notify granular controls too,
        # or the lock would be bypassable through the new per-feature menu.
        if key in ('osc_title', 'osc_notify') and 'allow_title' in self._locked:
            return
        term = self.current()
        if term is not None:
            term.apply_osc(key, enabled)
        self._osc_defaults[key] = bool(enabled)
        if key in self._osc_actions:
            self._osc_actions[key].setChecked(bool(enabled))
        # title/notify keep the legacy allow_title default in sync
        self._default_allow_title = (self._osc_defaults.get('osc_title')
                                     or self._osc_defaults.get('osc_notify'))
        if enabled:
            self._clear_advisories('osc')   # the "was ignored" notice is now stale
        self._update_security_indicator()
        self._persist()

    def set_bell_channel(self, channel, enabled):
        """Enable/disable one notification channel (audible/visual/tray) on the
        current tab, remember it as the default for new tabs, and persist. The
        channels are independent -- any combination may be on."""
        if 'bell' in self._locked:
            return
        if enabled:
            self._default_bell.add(channel)
        else:
            self._default_bell.discard(channel)
        # toggle only THIS channel on the current tab, preserving its other
        # channels (a restored tab may differ from the global default)
        term = self.current()
        if term is not None:
            chans = term.bell_channels()
            chans.add(channel) if enabled else chans.discard(channel)
            term.apply_bell(chans)
        if channel in self._bell_actions:
            self._bell_actions[channel].setChecked(enabled)
        self._persist()

    def _bell_sound_locked(self):
        return 'bell' in self._locked or 'bell_sound' in self._locked

    def set_bell_sound(self, path):
        """Set the audible-channel sound file (accepted only inside an allowed
        directory), apply it to every tab, and persist."""
        if self._bell_sound_locked():
            return
        self._default_bell_sound = path if sound_file_allowed(path) else ''
        for i in range(self.tabs.count()):
            self.tabs.widget(i).apply_bell_sound(self._default_bell_sound)
        if hasattr(self, 'act_bell_sound'):
            self.act_bell_sound.setText(self._bell_sound_label())
        self._persist()

    def _bell_sound_label(self):
        if self._default_bell_sound:
            return 'Sound file: ' + os.path.basename(self._default_bell_sound) + '...'
        return 'Sound file (beep)...'

    def _pick_bell_sound(self):
        if self._bell_sound_locked():
            return
        start = next((d for d in BELL_SOUND_DIRS if os.path.isdir(d)),
                     BELL_SOUND_DIRS[0])
        path, _ = QFileDialog.getOpenFileName(
            self, 'Choose bell sound', start, 'Sound files (*.wav *.ogg)')
        if not path:
            return
        if not sound_file_allowed(path):
            QMessageBox.warning(
                self, 'Sound file not allowed',
                'The bell sound must be a file inside an allowed folder:\n\n  '
                + '\n  '.join(BELL_SOUND_DIRS)
                + '\n\nCopy the file into one of these and try again.')
            return
        self.set_bell_sound(path)

    def _tray_icon(self):
        """The shared system-tray icon. Created lazily on first use, but ONLY when
        the tray is enabled in settings (opt-in, default off). Returns None if the
        tray is disabled or the platform has no tray."""
        if not self._systray:
            return None
        if self._tray is None:
            from PyQt6.QtWidgets import QSystemTrayIcon
            if not QSystemTrayIcon.isSystemTrayAvailable():
                return None
            self._tray = QSystemTrayIcon(self.windowIcon(), self)
            self._tray.setToolTip('secure-terminal')   # a fixed string, never output
            self._tray.setContextMenu(self._build_tray_menu())
            self._tray.activated.connect(self._on_tray_activated)
            self._tray.show()
        return self._tray

    def _build_tray_menu(self):
        """The tray context menu: SAFE, fixed actions only. Nothing here is derived
        from program output -- a tray surface is out-of-grid and trusted-looking, so
        untrusted text on it could phish. Show/Hide, New Tab, Quit."""
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        menu.addAction('Show / Hide window').triggered.connect(
            self._toggle_window_visibility)
        menu.addAction('New Tab').triggered.connect(
            lambda: (self._restore_window(), self.new_tab()))
        menu.addSeparator()
        menu.addAction('Quit').triggered.connect(self.close)
        return menu

    def _on_tray_activated(self, reason):
        from PyQt6.QtWidgets import QSystemTrayIcon
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            self._toggle_window_visibility()

    def _toggle_window_visibility(self):
        if self.isVisible() and not self.isMinimized():
            self.hide()
        else:
            self._restore_window()

    def _restore_window(self):
        # Clear only the minimized bit, preserving maximized / full-screen state --
        # showNormal() would shrink a maximized or full-screen window on restore.
        self.setWindowState(self.windowState() & ~Qt.WindowState.WindowMinimized)
        self.show()
        self.raise_()
        self.activateWindow()

    def _connect_bell_tray(self, term):
        term.bell_tray.connect(lambda label: self._on_bell_tray(term, label))

    def _on_bell_tray(self, term, _label):
        from PyQt6.QtWidgets import QSystemTrayIcon
        tray = self._tray_icon()
        if tray is None:
            return
        # Only TRUSTED text in the notification: the user-set tab name, else a
        # generic locator. NEVER the program-set title (_label) -- untrusted output
        # must not reach this out-of-grid, trusted-looking surface (the whole threat
        # model is "output lies"; a "Bell: <arbitrary text>" popup is a phish vector).
        name = self._user_titles.get(term)
        if not name:
            index = self.tabs.indexOf(term)
            name = 'tab %d' % (index + 1) if index != -1 else 'a background tab'
        tray.showMessage('secure-terminal', 'Bell in ' + name,
                         QSystemTrayIcon.MessageIcon.Information, 3000)

    def set_systray(self, enabled):
        """Enable/disable the opt-in system-tray icon (default off). Turning it off
        removes any existing icon; the 'tray' bell channel follows suit."""
        if 'systray' in self._locked:
            return
        enabled = bool(enabled)
        if enabled:
            from PyQt6.QtWidgets import QSystemTrayIcon
            if not QSystemTrayIcon.isSystemTrayAvailable():
                # Don't present the feature as active where the desktop has no tray:
                # the icon can't show and popups would be silently discarded.
                self._systray = False
                self.act_systray.setChecked(False)
                self._update_bell_tray_action()
                self.statusBar().showMessage(
                    'No system tray is available on this desktop.', 8000)
                return
        self._systray = enabled
        self.act_systray.setChecked(enabled)
        if not enabled and self._tray is not None:
            self._tray.hide()
            self._tray = None
        elif enabled:
            self._tray_icon()          # create now, so the effect is immediate
        self._update_bell_tray_action()
        self._persist()

    def _update_bell_tray_action(self):
        """The 'Tray popup' bell channel needs the tray enabled; grey it out (with a
        hint) when the tray is off, so it is never a silent dead setting. An admin
        'bell' lock, if present, already governs it and wins."""
        act = self._bell_actions.get('tray')
        if act is None or 'bell' in self._locked:
            return
        act.setEnabled(self._systray)
        tip = self._bell_tray_base_tip
        if not self._systray:
            tip += ('\n\nEnable the system tray (View > System tray icon) to use '
                    'this channel.')
        act.setToolTip(tip)

    def _on_cwd_changed(self, term, path):
        # OSC 7 working directory (only when osc_cwd is enabled): show it as the
        # tab's tooltip (non-intrusive; the path is already sanitized).
        index = self.tabs.indexOf(term)
        if index != -1:
            self.tabs.setTabToolTip(index, path)

    def _on_clipboard_read_requested(self, term):
        """A program in `term` asked to READ the clipboard (OSC 52). Ask the user
        for this tab; the two Allow buttons are disabled for the paste delay so a
        stray Enter cannot wave them through, and the default is Deny-once. Four
        choices -- allow or deny, ONCE (this request) or ALWAYS (remembered for the
        tab). Closing the dialog denies once. The choice is recorded on the tab."""
        index = self.tabs.indexOf(term)
        name = self._user_titles.get(term) or (
            self.tabs.tabText(index) if index != -1 else 'this tab')
        name = name.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        dialog = QDialog(self)
        dialog.setWindowTitle('Clipboard read request')
        layout = QVBoxLayout(dialog)
        msg = QLabel(
            'A program in <b>%s</b> is asking to READ your system clipboard '
            '(OSC&nbsp;52).<br><br>Your clipboard may hold passwords, keys or other '
            'secrets, and the contents would be sent to that program.<br><br>'
            '<b>Once</b> answers only this request; <b>Always</b> remembers your '
            'choice for this tab. Only allow if you trust everything running here: '
            'any output, including a log you merely view, could then read your '
            'clipboard.' % name)
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setWordWrap(True)
        layout.addWidget(msg)

        # Closing the dialog (Esc / window close) is the safe default: deny once.
        result = {'decision': SecureTerminal.CLIP_DENY_ONCE}

        def _choose(decision):
            result['decision'] = decision
            dialog.accept()

        buttons = QHBoxLayout()
        deny_once = QPushButton('Deny once')
        deny_once.setDefault(True)                 # the safe default
        deny_once.clicked.connect(lambda: _choose(SecureTerminal.CLIP_DENY_ONCE))
        deny_always = QPushButton('Always deny (this tab)')
        deny_always.clicked.connect(lambda: _choose(SecureTerminal.CLIP_DENY_ALWAYS))
        buttons.addWidget(deny_once)
        buttons.addWidget(deny_always)
        buttons.addStretch(1)
        allow_once = QPushButton()
        allow_once.setEnabled(False)
        allow_once.clicked.connect(lambda: _choose(SecureTerminal.CLIP_ALLOW_ONCE))
        allow_always = QPushButton()
        allow_always.setEnabled(False)
        allow_always.clicked.connect(lambda: _choose(SecureTerminal.CLIP_ALLOW_ALWAYS))
        buttons.addWidget(allow_once)
        buttons.addWidget(allow_always)
        layout.addLayout(buttons)

        secs = max(1, int(self._paste_delay))
        state = {'left': secs}

        def _sync():
            suffix = '' if state['left'] <= 0 else ' (%d)' % state['left']
            allow_once.setText('Allow once' + suffix)
            allow_always.setText('Always allow (this tab)' + suffix)

        def _tick():
            state['left'] -= 1
            if state['left'] <= 0:
                allow_once.setEnabled(True)
                allow_always.setEnabled(True)
                countdown.stop()
            _sync()
        _sync()
        countdown = QTimer(dialog)
        countdown.timeout.connect(_tick)
        countdown.start(1000)
        _select_labels(dialog)
        dialog.exec()
        term.grant_clipboard_read(result['decision'])

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

    def set_paste_warn(self, mode):
        """When to review a paste: always / unicode (default) / never. Applies to
        every tab and becomes the default for new ones."""
        if mode not in ('always', 'unicode', 'never') or 'paste_warn' in self._locked:
            return
        self._paste_warn = mode
        for i in range(self.tabs.count()):
            self.tabs.widget(i).apply_paste_warn(mode)
        if hasattr(self, '_paste_warn_actions'):
            act = self._paste_warn_actions.get(mode)
            if act is not None and not act.isChecked():
                act.setChecked(True)
        self._persist()

    def set_copy_warn(self, mode):
        """When to review a copy leaving for the clipboard: always / unicode
        (default) / never. Separate from the paste warning (copy and paste are
        opposite trust directions). Applies to every tab and new ones."""
        if mode not in ('always', 'unicode', 'never') or 'copy_warn' in self._locked:
            return
        self._copy_warn = mode
        for i in range(self.tabs.count()):
            self.tabs.widget(i).apply_copy_warn(mode)
        if hasattr(self, '_copy_warn_actions'):
            act = self._copy_warn_actions.get(mode)
            if act is not None and not act.isChecked():
                act.setChecked(True)
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
        # transcript_text() is lossless -- Box mode names each neutralized
        # character inline (<U+XXXX NAME>) rather than collapsing it to '_' -- and
        # pure ASCII except the real glyphs Show mode keeps. So the saved file is
        # safe to open anywhere (unlike a normal terminal's raw log) and still
        # records exactly which characters were there.
        try:
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(term.transcript_text())
        except OSError:
            pass            # a failed save (bad path, no space) is not fatal

    def _apply_locks(self):
        """Reflect admin-locked settings in the UI: disable the controls the user
        cannot change (greyed out with a note), and warn once if the user's own
        config tried to override a lock (that override was ignored)."""
        note = '\n\nLocked by the system administrator (a privileged drop-in in ' \
               '/etc/secure-terminal.d).'
        gated = [
            ('unicode_mode', list(self._mode_actions.values())),
            ('colors', [self.act_colors]),
            ('colored_markings', [self.act_markings]),
            ('auto_tab_colors', [self.act_auto_tab_colors]),
            ('osc_notice', [self.act_osc_notice]),
            ('osc_clipboard_read_always', [self.act_clip_read_always]),
            ('tui', [self.act_tui]),
            ('cli_terminfo', [self.act_cli_terminfo]),
            ('allow_title', [self.act_title]),
            ('bell', list(self._bell_actions.values())
             + [self.act_bell_sound, self.act_bell_sound_clear]),
            ('bell_sound', [self.act_bell_sound, self.act_bell_sound_clear]),
            ('systray', [self.act_systray]),
            ('paste_warn', list(self._paste_warn_actions.values())),
            ('copy_warn', list(self._copy_warn_actions.values())),
        ] + [(k, [self._osc_actions[k]]) for k in self._osc_actions]
        # a legacy allow_title lock also greys the granular title + notify controls
        if 'allow_title' in self._locked:
            gated += [('allow_title', [self._osc_actions[k]])
                      for k in ('osc_title', 'osc_notify') if k in self._osc_actions]
        for key, actions in gated:
            if key in self._locked:
                for act in actions:
                    act.setEnabled(False)
                    act.setToolTip(act.toolTip() + note)
        # disable the matching toolbar chip groups too, so a locked setting is
        # visibly un-clickable in both the menu and the toolbar.
        for key, buttons in (('unicode_mode', self._mode_buttons),
                             ('colors', self._colors_buttons),
                             ('tui', self._tui_buttons)):
            if key in self._locked:
                for btn in buttons.values():
                    btn.setEnabled(False)
                    btn.setToolTip(btn.toolTip() + note)
        if self._locked_violations:
            keys = ', '.join(self._locked_violations)
            msg = ('These settings are locked by the administrator; your home '
                   'config for them was ignored: ' + keys)
            self.statusBar().showMessage(msg, 15000)
            sys.stderr.write('secure-terminal: ' + msg + '\n')

    def _persist(self):
        # admin-locked keys are dropped by settings.save, so a locked setting is
        # never written to (dead) user config.
        settings.save({
            'theme': self._default_theme,
            'zoom': str(self._default_zoom),
            'unicode_mode': self._default_mode,
            'font_family': self._default_font_family,
            'colors': 'true' if self._default_colors else 'false',
            'colored_markings': 'true' if self._default_markings else 'false',
            'auto_tab_colors': 'true' if self._auto_tab_colors else 'false',
            'scrollback': str(self._scrollback),
            'paste_delay': str(self._paste_delay),
            'paste_warn': self._paste_warn,
            'copy_warn': self._copy_warn,
            'tui': 'true' if self._default_tui else 'false',
            'cli_terminfo': 'true' if self._default_cli_terminfo else 'false',
            'allow_title': 'true' if self._default_allow_title else 'false',
            'bell': ','.join(sorted(self._default_bell)),
            'bell_sound': self._default_bell_sound,
            'systray': 'true' if self._systray else 'false',
            'keybindings': ' '.join('%s=%s' % (i, self._keybindings[i])
                                    for i in sorted(self._keybindings)),
            'osc_notice': 'true' if self._osc_notice else 'false',
            'osc_clipboard_read_always': ('true' if self._osc_clipboard_read_always
                                          else 'false'),
            'osc_notice_off': ','.join(sorted(self._osc_notice_off)),
            'persist_session': 'true' if self._persist_session else 'false',
            'confirm_close': 'true' if self._confirm_close else 'false',
            **{k: 'true' if v else 'false' for k, v in self._osc_defaults.items()},
        }, locked=self._locked)

    # -- chrome ---------------------------------------------------------------
    def _build_menu(self):
        bar = self.menuBar()

        file_menu = bar.addMenu('&File')
        self.act_new = QAction(QIcon.fromTheme('tab-new'), 'New &Tab', self)
        self._bind(self.act_new, 'new_tab', 'Ctrl+Shift+T')
        self.act_new.triggered.connect(lambda: self.new_tab())
        file_menu.addAction(self.act_new)

        self.act_new_cmd = QAction('New Tab &Running...', self)
        self._bind(self.act_new_cmd, 'new_command_tab', 'Ctrl+Shift+R')
        self.act_new_cmd.setToolTip(
            'Open a tab running a specific program (e.g. ssh host, tmux, claude) '
            'instead of the login shell.')
        self.act_new_cmd.triggered.connect(self.new_tab_running)
        file_menu.addAction(self.act_new_cmd)

        self.act_close = QAction(QIcon.fromTheme('window-close'),
                                 '&Close Tab', self)
        self._bind(self.act_close, 'close_tab', 'Ctrl+Shift+W')
        self.act_close.triggered.connect(
            lambda: self.close_tab(self.tabs.currentIndex()))
        file_menu.addAction(self.act_close)

        self.act_save = QAction(QIcon.fromTheme('document-save'),
                                '&Save Transcript...', self)
        self._bind(self.act_save, 'save_transcript', 'Ctrl+Shift+S')
        self.act_save.setToolTip(
            'Save this tab\'s scrollback to a file. It is already sanitized '
            'plain ASCII, so the saved file is safe to open anywhere.')
        self.act_save.triggered.connect(self.save_transcript)
        file_menu.addAction(self.act_save)

        file_menu.addSeparator()
        self.act_terminate = QAction(QIcon.fromTheme('process-stop'),
                                     '&Terminate Program', self)
        self._bind(self.act_terminate, 'terminate', 'Ctrl+Shift+K')
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

        self.act_confirm_close = QAction('&Confirm close if a program is running',
                                         self, checkable=True)
        self.act_confirm_close.setChecked(self._confirm_close)
        self.act_confirm_close.setToolTip(
            'Ask before closing a tab -- or the whole window -- while a program '
            'other than the shell is still running in it, so a long job or an '
            'editor is not lost to a stray click. On by default.')
        self.act_confirm_close.toggled.connect(self.set_confirm_close)
        file_menu.addAction(self.act_confirm_close)

        act_clear_session = QAction('&Clear Saved Session', self)
        act_clear_session.triggered.connect(self.clear_saved_session)
        file_menu.addAction(act_clear_session)

        file_menu.addSeparator()
        act_quit = QAction(QIcon.fromTheme('application-exit'), '&Quit', self)
        self._bind(act_quit, 'quit', 'Ctrl+Q')
        act_quit.triggered.connect(self.close)
        file_menu.addAction(act_quit)

        edit_menu = bar.addMenu('&Edit')
        self.act_copy = QAction(QIcon.fromTheme('edit-copy'), '&Copy', self)
        self._bind(self.act_copy, 'copy', 'Ctrl+Shift+C')
        self.act_copy.triggered.connect(self.copy_selection)
        edit_menu.addAction(self.act_copy)

        self.act_paste = QAction(QIcon.fromTheme('edit-paste'), '&Paste', self)
        self._bind(self.act_paste, 'paste', 'Ctrl+Shift+V')
        self.act_paste.triggered.connect(self.paste_clipboard)
        edit_menu.addAction(self.act_paste)

        self.act_select_all = QAction(QIcon.fromTheme('edit-select-all'),
                                      'Select &All', self)
        self._bind(self.act_select_all, 'select_all', 'Ctrl+Shift+A')
        self.act_select_all.triggered.connect(self.select_all)
        edit_menu.addAction(self.act_select_all)
        edit_menu.addSeparator()
        self.act_find = QAction(QIcon.fromTheme('edit-find'), '&Find...', self)
        # Ctrl+Shift+F, not Ctrl+F: a bare Ctrl+<letter> is forwarded to the
        # running program (^F), so the search shortcut uses the Shift variant.
        self._bind(self.act_find, 'find', 'Ctrl+Shift+F')
        self.act_find.triggered.connect(self.show_find)
        edit_menu.addAction(self.act_find)

        view_menu = bar.addMenu('&View')
        act_zin = QAction(QIcon.fromTheme('zoom-in'), 'Zoom &In', self)
        self._bind(act_zin, 'zoom_in', QKeySequence.StandardKey.ZoomIn)
        act_zin.triggered.connect(self.zoom_in)
        view_menu.addAction(act_zin)

        act_zout = QAction(QIcon.fromTheme('zoom-out'), 'Zoom &Out', self)
        self._bind(act_zout, 'zoom_out', QKeySequence.StandardKey.ZoomOut)
        act_zout.triggered.connect(self.zoom_out)
        view_menu.addAction(act_zout)

        act_zreset = QAction(QIcon.fromTheme('zoom-original'),
                             '&Reset Zoom', self)
        self._bind(act_zreset, 'zoom_reset', 'Ctrl+0')
        act_zreset.triggered.connect(self.zoom_reset)
        view_menu.addAction(act_zreset)

        view_menu.addSeparator()
        self.act_full = QAction(QIcon.fromTheme('view-fullscreen'),
                                '&Full Screen', self, checkable=True)
        self._bind(self.act_full, 'fullscreen', 'F11')
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

        # Mutually-exclusive display modes as a colour-coded segmented control.
        # Ordered Box, Reveal, Detail, Show so Box and Show are never
        # adjacent. Box, Reveal and Detail are green (all safe): Box replaces
        # non-ASCII with a coloured box, hard to miss though lossy; Reveal/Detail
        # show the exact codepoint. Show is red (a rendered glyph can deceive).
        mode_menu = view_menu.addMenu('&Unicode')
        mode_menu.addSection('Changes DISPLAY, not bytes piped elsewhere')
        self._mode_group = QActionGroup(self)
        self._mode_group.setExclusive(True)
        self._mode_actions = {}
        for label, key, colour, tip in (
            ('&Box', 'box', '#1f8a54',
             'Non-ASCII OUTPUT is drawn as a coloured box (by risk class): safe and '
             'hard to miss, though lossy -- you see something was there, not which '
             'codepoint (Reveal shows the exact <U+XXXX>). A DISPLAY setting only: it '
             'does not change bytes a program pipes elsewhere, so "cat file | bash" '
             'still runs the file.'),
            ('&Reveal', 'reveal', '#1f8a54',
             'Show every non-ASCII character as a <U+XXXX> badge: safe and '
             'lossless, you see the exact codepoint, nothing can pose as a '
             'look-alike.'),
            ('De&tail', 'detail', '#1f8a54',
             'Like Reveal but verbose: <U+XXXX NAME>, the codepoint plus its '
             'official Unicode name inline (what unicode-show annotates), so a '
             'homoglyph reads as its identity, not just a number.'),
            ('S&how', 'show', '#d83933',
             'Render printable non-ASCII output as its glyph -- and, with colour '
             'markings on, tint each by its risk class (a homoglyph in rose), so a '
             'look-alike is flagged instead of blending in as ASCII. Still the least '
             'safe mode: you have to NOTICE the colour. The invisible, bidi and '
             'control classes are neutralized to a box either way.'),
        ):
            act = QAction(_dot_icon(colour), label, self, checkable=True)
            act.setToolTip(tip)
            act.triggered.connect(lambda _checked, k=key: self.set_mode(k))
            self._mode_group.addAction(act)
            mode_menu.addAction(act)
            self._mode_actions[key] = act
        self.act_box = self._mode_actions['box']
        self.act_reveal = self._mode_actions['reveal']
        self.act_detail = self._mode_actions['detail']
        self.act_show = self._mode_actions['show']
        self._sync_mode_toggles(self._default_mode)

        self.act_font = QAction('&Font...', self)
        self.act_font.setToolTip(
            'Choose the terminal font for this tab, and the default for new tabs. '
            'The default, Hack, is designed to disambiguate look-alike glyphs '
            '(dotted zero, distinct 1/l/I) and ships no ligatures, which could '
            'otherwise hide characters.')
        self.act_font.triggered.connect(self.choose_font)
        view_menu.addAction(self.act_font)

        view_menu.addSeparator()
        self.act_colors = QAction(
            _toggle_icon('format-text-color', 'C', '#0969da'),
            '&Colors', self, checkable=True)
        self.act_colors.setChecked(self._default_colors)
        self.act_colors.setToolTip(
            'Render a safe subset of ANSI colors (16-color SGR) in the current '
            'tab. Off by default; contrast-guarded so text can never be painted '
            'invisibly. Honors the NO_COLOR convention (no-color.org): if the '
            'NO_COLOR environment variable is set, colors stay off even when this '
            'is on.')
        self.act_colors.toggled.connect(self.set_colors)
        view_menu.addAction(self.act_colors)

        self.act_markings = QAction('Colored &markings', self, checkable=True)
        self.act_markings.setChecked(self._default_markings)
        self.act_markings.setToolTip(
            'Colour each neutralized or revealed character -- the box placeholder '
            'and the <U+XXXX> badge -- by its risk class: red for bidi controls '
            'that reorder text, amber for zero-width and invisible characters, '
            'blue for control bytes, purple for other non-ASCII (homoglyph-prone). '
            'The colour comes from the risk class, never from the program, so '
            'output cannot recolour a marking to blend in, and the contrast guard '
            'keeps it readable, so it cannot be hidden. On by default; independent '
            'of the ANSI Colors setting.')
        self.act_markings.toggled.connect(self.set_markings)
        view_menu.addAction(self.act_markings)

        self.act_auto_tab_colors = QAction('&Automatic tab colours', self,
                                           checkable=True)
        self.act_auto_tab_colors.setChecked(self._auto_tab_colors)
        self.act_auto_tab_colors.setToolTip(
            'Give each new tab a colour that differs from its neighbour, so tabs '
            'are easy to tell apart at a glance. On by default; a colour you set '
            'on a tab (right-click) overrides the automatic one.')
        self.act_auto_tab_colors.toggled.connect(self.set_auto_tab_colors)
        view_menu.addAction(self.act_auto_tab_colors)

        osc_notice_menu = view_menu.addMenu('Notify on &OSC use')
        self.act_osc_notice = QAction('&All OSC notices', self, checkable=True)
        self.act_osc_notice.setChecked(self._osc_notice)
        self.act_osc_notice.setToolTip(
            'Show a dismissible banner (at most once per TYPE per tab) when a '
            'program uses an OSC escape the safe CLI mode neutralized. On by '
            'default. Untick a specific type below to mute just that one.')
        self.act_osc_notice.toggled.connect(self.set_osc_notice)
        osc_notice_menu.addAction(self.act_osc_notice)
        osc_notice_menu.addSeparator()
        for key, label, codes, _d, _r, _h in OSC_FEATURES:
            act = QAction(label + '  (OSC ' + codes + ')', self, checkable=True)
            act.setChecked(key not in self._osc_notice_off)   # ticked == notify
            act.setToolTip('Notify when untrusted output uses this OSC escape.')
            act.toggled.connect(lambda on, k=key: self.set_osc_notice_type(k, on))
            osc_notice_menu.addAction(act)
            self._osc_notice_actions[key] = act

        bell_menu = view_menu.addMenu('&Bell')
        # Independent channels (not mutually exclusive): a BEL may ring any
        # combination. None ticked = silent, the safe default (a bell rung by
        # untrusted output is a nuisance/attention-grab surface).
        self._bell_actions = {}
        for label, channel, tip in (
            ('&Audible', 'audible',
             'Ring a short system beep (or a chosen sound file). Rate-limited, so '
             'a program spamming BEL cannot machine-gun it.'),
            ('&Visual', 'visual',
             'Flag the window for attention (a window-manager urgency hint / '
             'taskbar flash). Rate-limited.'),
            ('&Tray popup', 'tray',
             'Show a passive system-tray popup. A subtle, non-focus-stealing '
             'notification. Rate-limited.'),
        ):
            act = QAction(label, self, checkable=True)
            act.setToolTip(tip)
            act.setChecked(channel in self._default_bell)
            act.triggered.connect(
                lambda checked, c=channel: self.set_bell_channel(c, checked))
            bell_menu.addAction(act)
            self._bell_actions[channel] = act
        # base tooltip for the tray channel, so _update_bell_tray_action can append
        # / remove the "needs the tray enabled" hint without mangling the text.
        self._bell_tray_base_tip = self._bell_actions['tray'].toolTip()
        bell_menu.addSeparator()
        self.act_bell_sound = QAction(self._bell_sound_label(), self)
        self.act_bell_sound.setToolTip(
            'Choose the sound file for the audible bell. Restricted to the allowed '
            'sound folders (' + ', '.join(BELL_SOUND_DIRS) + ') so the AppArmor '
            'profile stays enforceable. Clear it to use the plain system beep.')
        self.act_bell_sound.triggered.connect(self._pick_bell_sound)
        bell_menu.addAction(self.act_bell_sound)
        self.act_bell_sound_clear = QAction('Use system beep (clear sound)', self)
        self.act_bell_sound_clear.setToolTip(
            'Clear the chosen sound file so the audible bell is the plain system beep.')
        self.act_bell_sound_clear.triggered.connect(lambda: self.set_bell_sound(''))
        bell_menu.addAction(self.act_bell_sound_clear)

        self.act_tui = QAction(_toggle_icon('utilities-terminal', 'T', '#e5a50a'),
                               '&TUI mode', self, checkable=True)
        self.act_tui.setChecked(self._default_tui)
        self.act_tui.setEnabled(tui_available())
        self.act_tui.setToolTip(TUI_TOOLTIP)
        if not tui_available():
            self.act_tui.setText('TUI mode (needs python3-pyte)')
        self.act_tui.toggled.connect(self.set_tui)
        view_menu.addAction(self.act_tui)

        self.act_cli_terminfo = QAction('&Restricted terminfo (CLI)', self,
                                        checkable=True)
        self.act_cli_terminfo.setChecked(self._default_cli_terminfo)
        self.act_cli_terminfo.setToolTip(
            'Advertise the restricted "secure-terminal" terminfo instead of '
            'xterm-256color, so CLI-mode programs emit only what this terminal '
            'renders and never probe it (no cursor addressing, alternate screen, '
            'or capability queries). Off by default. TERM is fixed when a shell '
            'starts, so this applies to NEW tabs; keep it off if you ssh or use '
            'TUI mode, since a remote host / full-screen program needs the fuller '
            'xterm-256color entry.')
        self.act_cli_terminfo.toggled.connect(self.set_cli_terminfo)
        view_menu.addAction(self.act_cli_terminfo)

        self.act_systray = QAction('S&ystem tray icon', self, checkable=True)
        self.act_systray.setChecked(self._systray)
        self.act_systray.setToolTip(
            'Show a system-tray icon with a few fixed actions (Show/Hide window, '
            'New Tab, Quit) and enable the Tray-popup bell channel. Off by default. '
            'The tray shows only fixed text -- never a program-set title or other '
            'output -- so untrusted output cannot deceive you through it.')
        self.act_systray.toggled.connect(self.set_systray)
        view_menu.addAction(self.act_systray)
        # reflect the tray state onto the 'Tray popup' bell channel (grey it out when
        # the tray is off) now that both actions exist.
        self._update_bell_tray_action()
        if self._systray:
            self._tray_icon()          # show the icon at startup when enabled

        # act_title stays as a compatibility action (the combined title+notify
        # toggle used by the settings dialog / session), but is NOT shown in the
        # menu: the granular OSC submenu below supersedes it.
        self.act_title = QAction('Allow program title / notifications', self,
                                 checkable=True)
        self.act_title.setChecked(self._default_allow_title)
        self.act_title.toggled.connect(self.set_allow_title)

        # Granular OSC control: every way a program can reach OUT of the terminal,
        # each individually toggleable with its layman attack-surface hint. All off
        # by default; enabling one only has effect in TUI mode and dims the OSC
        # security lamp by its risk class.
        osc_menu = view_menu.addMenu('&OSC features')
        osc_menu.setToolTip('Each is a way a program can act on your system '
                            '(title, clipboard, ...). All neutralized by default; '
                            'enable at your own risk (only in TUI mode). iTerm2 '
                            'file-transfer escapes (OSC 1337) are always '
                            'neutralized and have no toggle -- they can never be '
                            'safely enabled.')
        _risk_tag = {'low': '', 'medium': '   [risk: medium]',
                     'high': '   [RISK: HIGH]'}
        for key, label, codes, _dflt, risk, hint in OSC_FEATURES:
            act = QAction(label + '  (OSC ' + codes + ')', self, checkable=True)
            act.setChecked(self._osc_defaults.get(key, False))
            act.setToolTip(hint + _risk_tag[risk])
            act.toggled.connect(lambda on, k=key: self.set_osc(k, on))
            osc_menu.addAction(act)
            self._osc_actions[key] = act
        osc_menu.addSeparator()
        self.act_clip_read_always = QAction(
            'Always allow clipboard READ (all tabs, no prompt)', self, checkable=True)
        self.act_clip_read_always.setChecked(self._osc_clipboard_read_always)
        self.act_clip_read_always.setToolTip(
            'Auto-answer OSC 52 clipboard-read requests in every tab WITHOUT the '
            'once-per-tab prompt. HIGH RISK: any untrusted output could then read '
            'your clipboard (passwords, keys). Off by default; only has effect where '
            'the "System clipboard (read)" OSC feature is also enabled. A per-tab '
            'Deny still wins over this.')
        self.act_clip_read_always.toggled.connect(self.set_clipboard_read_always)
        osc_menu.addAction(self.act_clip_read_always)

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

        pw_menu = view_menu.addMenu('Paste &warning')
        pw_group = QActionGroup(self)
        pw_group.setExclusive(True)
        self._paste_warn_actions = {}
        for label, key, tip in (
            ('&Always', 'always', 'Show the paste-warning dialog on every paste.'),
            ('If &unicode', 'unicode',
             'Show it only when the paste carries unicode or control characters '
             '(the default). Plain-ASCII pastes go straight through.'),
            ('&Never', 'never',
             'Never prompt. The paste is still sanitized (escapes and hidden '
             'bytes removed) before it reaches the shell.'),
        ):
            act = QAction(label, self, checkable=True)
            act.setToolTip(tip)
            act.setChecked(key == self._paste_warn)
            act.triggered.connect(lambda _checked, k=key: self.set_paste_warn(k))
            pw_group.addAction(act)
            pw_menu.addAction(act)
            self._paste_warn_actions[key] = act

        cw_menu = view_menu.addMenu('&Copy warning')
        cw_group = QActionGroup(self)
        cw_group.setExclusive(True)
        self._copy_warn_actions = {}
        for label, key, tip in (
            ('&Always', 'always', 'Review every copy before it reaches the clipboard.'),
            ('If &unicode', 'unicode',
             'Review a copy only when the selection carries unicode or control '
             'characters (the default) -- e.g. a homoglyph shown in Show mode. A '
             'plain-ASCII copy goes straight through.'),
            ('&Never', 'never',
             'Never prompt on copy. The displayed text is copied as-is (already '
             'sanitized: hidden characters are shown as boxes).'),
        ):
            act = QAction(label, self, checkable=True)
            act.setToolTip(tip)
            act.setChecked(key == self._copy_warn)
            act.triggered.connect(lambda _checked, k=key: self.set_copy_warn(k))
            cw_group.addAction(act)
            cw_menu.addAction(act)
            self._copy_warn_actions[key] = act

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
        self._bind(act_command, 'command_palette', 'Ctrl+Shift+P')
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
        act_keys = QAction(QIcon.fromTheme('preferences-desktop-keyboard'),
                           '&Keyboard Shortcuts...', self)
        act_keys.setToolTip('List every window shortcut and rebind it.')
        act_keys.triggered.connect(self.show_shortcuts)
        self._bind(act_keys, 'shortcuts_help', 'F1')
        help_menu.addAction(act_keys)
        help_menu.addSeparator()
        act_about = QAction(QIcon.fromTheme('help-about'), '&About', self)
        act_about.triggered.connect(self.show_about)
        help_menu.addAction(act_about)

    # -- window keyboard shortcuts: documented + configurable -----------------
    def _bind(self, action, ident, default_seq):
        """Give `action` a documented, user-configurable window shortcut. Applies
        the config/user override for `ident` when present, else `default_seq` (a
        QKeySequence string or a QKeySequence.StandardKey), and registers it so the
        Keyboard Shortcuts dialog can list and rebind it."""
        if isinstance(default_seq, QKeySequence.StandardKey):
            default = QKeySequence(default_seq).toString()
        else:
            default = default_seq
        seq = self._keybindings.get(ident, default)
        action.setShortcut(QKeySequence(seq))
        label = action.text().replace('&', '').replace('...', '').strip()
        self._shortcuts[ident] = (action, default, label)

    def _is_reserved_shortcut(self, seq):
        """A window shortcut must not shadow a key the terminal forwards to the
        running program, or the dialog's promise (Ctrl+C/U/R reach the program) is
        broken -- QAction shortcut processing would fire first. Reserved: a bare
        Ctrl+<letter> (the tty/readline control keys) and a bare printable key
        (which would eat ordinary typing). Ctrl+Shift/Ctrl+Alt combos and function
        keys are fine."""
        qks = QKeySequence(seq)
        if qks.isEmpty():
            return False
        combo = qks[0]
        mods = combo.keyboardModifiers()
        key = combo.key()
        ctrl = Qt.KeyboardModifier.ControlModifier
        if mods == ctrl and Qt.Key.Key_A <= key <= Qt.Key.Key_Z:
            return True
        if mods == Qt.KeyboardModifier.NoModifier and 0x20 <= key <= 0x7E:
            return True
        return False

    def _set_shortcuts(self, mapping):
        """Apply a {ident: seq_string} mapping to the registered actions. Returns a
        list of human-readable PROBLEM strings (admin lock, a key reserved for the
        terminal, or the same combination on two actions); when non-empty NOTHING is
        applied. Otherwise applies, records only the non-default overrides, and
        persists."""
        if 'keybindings' in self._locked:
            return ['Keyboard shortcuts are locked by the system administrator.']
        problems = []
        for ident, seq in mapping.items():
            entry = self._shortcuts.get(ident)
            default = entry[1] if entry else ''
            norm = QKeySequence(seq).toString()
            # a built-in default (e.g. quit = Ctrl+Q) is allowed to stand; only
            # reject a user NEWLY assigning a key the terminal forwards
            if (norm and norm != QKeySequence(default).toString()
                    and self._is_reserved_shortcut(seq)):
                label = entry[2] if entry else ident
                problems.append('%s: %s is reserved for the terminal (always sent '
                                'to the running program).' % (label, norm))
        seen = {}
        for ident, seq in mapping.items():
            norm = QKeySequence(seq).toString()   # canonicalise ("ctrl+t" -> "Ctrl+T")
            if norm:
                seen.setdefault(norm, []).append(ident)
        for norm, ids in seen.items():
            if len(ids) > 1:
                problems.append('%s is assigned to more than one action: %s.'
                                % (norm, ', '.join(self._shortcuts[i][2] for i in ids)))
        if problems:
            return problems
        for ident, seq in mapping.items():
            entry = self._shortcuts.get(ident)
            if entry is None:
                continue
            action, default, label = entry
            norm = QKeySequence(seq).toString()
            action.setShortcut(QKeySequence(norm))
            self._shortcuts[ident] = (action, default, label)
            if norm == QKeySequence(default).toString():
                self._keybindings.pop(ident, None)     # back to default -> no override
            else:
                self._keybindings[ident] = norm
        self._persist()
        return []

    def show_shortcuts(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Keyboard Shortcuts')
        layout = QVBoxLayout(dialog)
        intro = QLabel(
            'Window shortcuts. Click a field and press a new combination to '
            'rebind it, or clear it to unbind. Terminal control keys (Ctrl+C, '
            'Ctrl+U, Ctrl+R and the rest) are always sent to the running program '
            'and are not remappable here.')
        intro.setWordWrap(True)
        layout.addWidget(intro)
        locked = 'keybindings' in self._locked
        if locked:
            note = QLabel('These are locked by the system administrator and shown '
                          'for reference only.')
            note.setWordWrap(True)
            layout.addWidget(note)
        grid = QGridLayout()
        edits = {}
        for row, ident in enumerate(sorted(self._shortcuts,
                                            key=lambda i: self._shortcuts[i][2])):
            action, _default, label = self._shortcuts[ident]
            grid.addWidget(QLabel(label), row, 0)
            edit = QKeySequenceEdit(action.shortcut())
            # one combination only: a multi-stroke sequence's toString() carries a
            # space, which the space-separated `keybindings` config cannot round-trip
            if hasattr(edit, 'setMaximumSequenceLength'):
                edit.setMaximumSequenceLength(1)
            edit.setEnabled(not locked)
            edits[ident] = edit
            grid.addWidget(edit, row, 1)
        layout.addLayout(grid)
        buttons = QHBoxLayout()
        reset = QPushButton('Reset to defaults')

        def _do_reset():
            for ident, edit in edits.items():
                edit.setKeySequence(QKeySequence(self._shortcuts[ident][1]))
        reset.clicked.connect(_do_reset)
        reset.setEnabled(not locked)
        buttons.addWidget(reset)
        buttons.addStretch(1)
        cancel = QPushButton('Close' if locked else 'Cancel')
        cancel.clicked.connect(dialog.reject)
        buttons.addWidget(cancel)
        save = QPushButton('Save')
        save.setDefault(True)
        save.setEnabled(not locked)

        def _do_save():
            mapping = {i: e.keySequence().toString() for i, e in edits.items()}
            problems = self._set_shortcuts(mapping)
            if problems:
                QMessageBox.warning(
                    dialog, 'Cannot save shortcuts',
                    'Fix these before saving:\n\n  ' + '\n  '.join(problems))
                return
            dialog.accept()
        save.clicked.connect(_do_save)
        buttons.addWidget(save)
        layout.addLayout(buttons)
        _select_labels(dialog)
        dialog.exec()

    def show_about(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('About secure-terminal')
        layout = QVBoxLayout(dialog)
        icon = _app_icon()
        if not icon.isNull():
            logo = QLabel()
            logo.setPixmap(icon.pixmap(64, 64))
            logo.setAlignment(Qt.AlignmentFlag.AlignHCenter)
            layout.addWidget(logo)
        title = QLabel('secure-terminal ' + APP_VERSION)
        title.setStyleSheet('font-weight:bold; font-size:16px;')
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        layout.addWidget(title)
        body = QLabel(
            'A terminal where paste is safe by design.<br><br>'
            'There is no escape parser, so every escape sequence in program '
            'output is removed and a printed or pasted lie cannot redraw, '
            'reorder or hide what you see -- and merely viewing a file cannot run '
            'code. Non-ASCII characters are stripped, revealed or shown as you '
            'choose. Pasting is sanitized and warned on. It is written in a '
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
        _select_labels(dialog)
        dialog.exec()

    _COMMAND_HELP = (
        'Slash commands (the leading / is optional):\n\n'
        '  /theme dark|light\n'
        '  /mode box|show|reveal\n'
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
        outer = QVBoxLayout(dialog)
        outer.setSpacing(12)

        # Grouped sections instead of one long flat list: each QGroupBox holds a
        # right-aligned form so related settings read as a unit.
        def _section(title):
            box = QGroupBox(title)
            sub = QFormLayout(box)
            sub.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
            sub.setContentsMargins(12, 8, 12, 10)
            sub.setSpacing(8)
            outer.addWidget(box)
            return sub

        appearance = _section('Appearance')
        theme = QComboBox()
        for label, key in THEME_LABELS:
            theme.addItem(label, key)
        theme.setCurrentIndex(theme.findData(self._default_theme))
        appearance.addRow('Theme', theme)

        zoom = QSpinBox()
        zoom.setRange(ZOOM_MIN, ZOOM_MAX)
        zoom.setSingleStep(ZOOM_STEP)
        zoom.setSuffix('%')
        zoom.setValue(self._default_zoom)
        appearance.addRow('Zoom', zoom)

        scrollback = QComboBox()
        for label, lines in SCROLLBACK_CHOICES:
            scrollback.addItem(label, lines)
        scrollback.setCurrentIndex(scrollback.findData(self._scrollback))
        appearance.addRow('Scrollback', scrollback)

        rendering = _section('Text rendering')
        mode = QComboBox()
        for label, key in (('Box (safe)', 'box'), ('Reveal unicode', 'reveal'),
                           ('Detail (named)', 'detail'), ('Show unicode', 'show')):
            mode.addItem(label, key)
        mode.setCurrentIndex(mode.findData(self._default_mode))
        rendering.addRow('Unicode', mode)

        colors = QCheckBox()
        colors.setChecked(self._default_colors)
        rendering.addRow('Colours', colors)

        tui = QCheckBox()
        tui.setChecked(self._default_tui)
        tui.setEnabled(tui_available())
        rendering.addRow('TUI mode (new tabs)', tui)

        # granular OSC feature toggles: each off by default, its risk coloured in
        # the label and its layman attack-surface hint as the tooltip.
        osc_section = _section('OSC escape features (all off by default)')
        osc_checks = {}
        _risk_html = {
            'low': '',
            'medium': ' <span style="color:#b06f00">[medium risk]</span>',
            'high': ' <span style="color:#d83933">[HIGH risk]</span>',
        }
        for _key, _label, _codes, _dflt, _risk, _hint in OSC_FEATURES:
            _cb = QCheckBox()
            _cb.setChecked(self._osc_defaults.get(_key, False))
            _cb.setToolTip(_hint)
            _lbl = QLabel('OSC ' + _label + _risk_html[_risk])
            _lbl.setTextFormat(Qt.TextFormat.RichText)
            _lbl.setToolTip(_hint)
            osc_section.addRow(_lbl, _cb)
            osc_checks[_key] = _cb

        osc = QCheckBox()
        osc.setChecked(self._osc_notice)
        osc_section.addRow('Notify on OSC use', osc)

        session_box = _section('Paste and session')
        pdelay = QComboBox()
        for label, secs in PASTE_DELAY_CHOICES:
            pdelay.addItem(label, secs)
        pidx = pdelay.findData(self._paste_delay)
        if pidx < 0:
            # the stored delay (config allows any 0-60) is not one of the presets;
            # add it as its own item so the combo shows the REAL current value
            # instead of a blank selection.
            pdelay.addItem('%d second%s' % (self._paste_delay,
                                            '' if self._paste_delay == 1 else 's'),
                           self._paste_delay)
            pidx = pdelay.count() - 1
        pdelay.setCurrentIndex(pidx)
        session_box.addRow('Paste delay', pdelay)

        persist = QCheckBox()
        persist.setChecked(self._persist_session)
        session_box.addRow('Restore session on start', persist)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton('Cancel')
        cancel.clicked.connect(dialog.reject)
        apply_all = QPushButton('Apply to all tabs')
        apply_all.setDefault(True)
        apply_all.clicked.connect(dialog.accept)
        buttons.addWidget(cancel)
        buttons.addWidget(apply_all)
        outer.addLayout(buttons)

        _select_labels(dialog)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._apply_global({
            'theme': theme.currentData(), 'zoom': zoom.value(),
            'mode': mode.currentData(), 'colors': colors.isChecked(),
            'tui': tui.isChecked(),
            'osc': {k: cb.isChecked() for k, cb in osc_checks.items()},
            'osc_notice': osc.isChecked(),
            'scrollback': scrollback.currentData(), 'paste_delay': pdelay.currentData(),
            'persist': persist.isChecked(),
        })

    def _apply_global(self, opts):
        """Apply the global-settings choices to every open tab and store the new
        defaults. TUI mode changes only the default for new tabs -- switching it
        would restart the shell in each existing tab, throwing away running work,
        which a settings dialog must not do."""
        # A locked key keeps its admin value regardless of what the dialog returns.
        for key, field, current in (
                ('unicode_mode', 'mode', self._default_mode),
                ('colors', 'colors', self._default_colors),
                ('tui', 'tui', self._default_tui),
                ('osc_notice', 'osc_notice', self._osc_notice)):
            if key in self._locked:
                opts[field] = current
        # granular OSC defaults: a locked feature keeps its current value.
        osc = dict(opts.get('osc', {}))
        for key in osc:
            if key in self._locked:
                osc[key] = self._osc_defaults.get(key, False)
        if 'osc_notice' in opts:
            self._osc_notice = opts['osc_notice']
            self.act_osc_notice.setChecked(self._osc_notice)
        self._default_theme = opts['theme']
        self._default_zoom = opts['zoom']
        self._default_mode = opts['mode']
        self._default_colors = opts['colors']
        self._default_tui = opts['tui']
        for key, value in osc.items():
            self._osc_defaults[key] = value
            if key in self._osc_actions:
                self._osc_actions[key].setChecked(value)
        self._default_allow_title = (self._osc_defaults.get('osc_title')
                                     or self._osc_defaults.get('osc_notify'))
        self._scrollback = opts['scrollback']
        self._paste_delay = opts['paste_delay']
        for index in range(self.tabs.count()):
            term = self.tabs.widget(index)
            term.apply_theme(opts['theme'])
            term.apply_zoom(opts['zoom'])
            term.apply_mode(opts['mode'])
            term.apply_colors(opts['colors'])
            for key, value in osc.items():
                term.apply_osc(key, value)
            term.apply_scrollback(opts['scrollback'])
            term.apply_paste_delay(opts['paste_delay'])
            # NB: bell is intentionally NOT applied here. This global-settings
            # dialog has no bell field, so touching it would silently reset each
            # tab's per-tab bell choice; the bell is managed via the View menu only.
        self.set_persist_session(opts['persist'])
        self._sync_chrome_to_tab()
        self._persist()

    # A labelled, bordered group of mutually-exclusive chip buttons -- the
    # visible, self-explaining form of a setting (e.g. "unicode: Box Reveal
    # Show"). Makes the setting's NAME and its options obvious to a new user,
    # where a bare row of toggle icons did not. Returns (frame, {key: button}).
    _CHIP_CSS = (
        'QFrame#chip{border:1px solid palette(mid);border-radius:6px;'
        'background:palette(base)}'
        'QFrame#chip > QLabel{color:palette(mid);font-size:11px;'
        'padding:0 3px 0 5px;background:transparent}'
        'QFrame#chip QPushButton{border:none;background:transparent;'
        'padding:2px 9px;border-radius:4px;color:palette(text)}'
        'QFrame#chip QPushButton:hover{background:palette(midlight)}'
    )

    def _chip_group(self, caption, specs, on_select):
        frame = QFrame(self)
        frame.setObjectName('chip')
        row = QHBoxLayout(frame)
        row.setContentsMargins(2, 1, 3, 1)
        row.setSpacing(1)
        row.addWidget(QLabel(caption, frame))
        group = QButtonGroup(frame)
        group.setExclusive(True)
        buttons = {}
        # Style the FRAME (so its border and every descendant chip is covered);
        # per-chip checked colour is an object-name rule in the same sheet, so a
        # mode chip keeps its safety colour code (Box green, Reveal green,
        # Show red).
        css = self._CHIP_CSS
        for key, label, colour, tip in specs:
            btn = QPushButton(label, frame)
            btn.setObjectName('chip_' + key)
            btn.setCheckable(True)
            btn.setToolTip(tip)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            # A toolbar chip must not steal keyboard focus from the terminal:
            # otherwise clicking it to change the mode stops the terminal's caret
            # from blinking (it looks like the cursor vanished).
            btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
            # A safety-coloured dot (the old toolbar symbol) on the risk-bearing
            # chips: green Box, green Reveal, red Show, yellow TUI. It shows the
            # risk colour at a glance even when the chip is not the selected one.
            if colour:
                btn.setIcon(_dot_icon(colour))
            checked = colour or '#3b7ddd'
            css += ('QFrame#chip QPushButton#chip_%s:checked'
                    '{background:%s;color:#fff;font-weight:600}' % (key, checked))
            if colour:
                # hover previews the option's safety colour (a light tint), so a
                # user sees that Show / TUI are the less-safe, red/yellow choices
                # before committing the click.
                h = colour.lstrip('#')
                tint = 'rgba(%d,%d,%d,0.22)' % (
                    int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
                css += ('QFrame#chip QPushButton#chip_%s:hover:!checked'
                        '{background:%s}' % (key, tint))
            btn.toggled.connect(
                lambda on, k=key: (on and not self._syncing) and on_select(k))
            group.addButton(btn)
            row.addWidget(btn)
            buttons[key] = btn
        frame.setStyleSheet(css)
        return frame, buttons

    def _set_chip(self, buttons, key):
        """Programmatically select a chip WITHOUT firing its handler (guarded by
        self._syncing), so reflecting state never loops back into a setter."""
        btn = buttons.get(key)
        if btn is None or btn.isChecked():
            return
        self._syncing = True
        try:
            btn.setChecked(True)
        finally:
            self._syncing = False

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

        # unicode display mode: Box (green, lossy) / Reveal (green, lossless) /
        # Show (red, a glyph can deceive). Grouped and labelled so it is obvious
        # these three are one unicode setting.
        uni_frame, self._mode_buttons = self._chip_group('unicode:', (
            ('box', 'Box', '#1f8a54', self.act_box.toolTip()),
            ('reveal', 'Reveal', '#1f8a54', self.act_reveal.toolTip()),
            ('detail', 'Detail', '#1f8a54', self.act_detail.toolTip()),
            ('show', 'Show', '#d83933', self.act_show.toolTip()),
        ), self.set_mode)
        bar.addWidget(uni_frame)

        # rendering mode: CLI (line mode, the safe default) vs TUI (opt-in
        # full-screen). TUI is the riskier choice, so its chip is yellow.
        mode_frame, self._tui_buttons = self._chip_group('mode:', (
            ('cli', 'CLI', None,
             'CLI mode: program output is shown as safe display, the default.'),
            ('tui', 'TUI', '#e5a50a', TUI_TOOLTIP),
        ), lambda k: self.set_tui(k == 'tui'))
        self._tui_frame = mode_frame
        bar.addWidget(mode_frame)

        # ANSI colours on/off.
        col_frame, self._colors_buttons = self._chip_group('colours:', (
            ('on', 'On', None, self.act_colors.toolTip()),
            ('off', 'Off', None, 'Show program output without ANSI colours.'),
        ), lambda k: self.set_colors(k == 'on'))
        bar.addWidget(col_frame)

        if not tui_available():
            for btn in self._tui_buttons.values():
                btn.setEnabled(False)
            self._tui_buttons['tui'].setToolTip('TUI mode needs python3-pyte.')

        # reflect the current defaults on the freshly-built chips
        self._set_chip(self._mode_buttons, self._default_mode)
        self._set_chip(self._colors_buttons,
                       'on' if self._default_colors else 'off')
        self._set_chip(self._tui_buttons, 'tui' if self._default_tui else 'cli')

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
                'font_family': term.current_font_family(),
                'colors': term.colors_enabled(),
                'markings': term.markings_enabled(),
                'tui': term.current_tui(),
                'allow_title': term.allow_title_enabled(),
                'osc': {_f[0]: term.osc_enabled(_f[0]) for _f in OSC_FEATURES},
                'bell': term.bell_spec(),
                'scrollback': term.current_scrollback(),
                'cwd': term.shell_cwd(),      # restore the tab in the same directory
                'text': text,
            })
        return tabs

    def set_persist_session(self, enabled):
        self._persist_session = bool(enabled)
        self.act_persist.setChecked(enabled)
        if not enabled:
            session.clear()

    def set_confirm_close(self, enabled):
        self._confirm_close = bool(enabled)
        self.act_confirm_close.setChecked(enabled)

    def _confirm_running_close(self, title, question, terms):
        """True if it is OK to proceed with a close. When the confirm-on-close
        setting is on and any terminal in `terms` still runs a foreground program
        (something other than its shell), ask first; return False if the user
        declines. A no-op (returns True) when the setting is off or nothing is
        running, so the normal close path is untouched."""
        if not self._confirm_close:
            return True
        if not any(t is not None and t.has_foreground_program() for t in terms):
            return True
        reply = QMessageBox.question(
            self, title, question,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No)
        return reply == QMessageBox.StandardButton.Yes

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
        labels = ['Built-in defaults', 'System drop-in', 'Local drop-in',
                  'User drop-in']
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
        _select_labels(dialog)
        dialog.exec()

    # -- lifecycle ------------------------------------------------------------
    def closeEvent(self, event):
        running = sum(1 for i in range(self.tabs.count())
                      if self.tabs.widget(i).has_foreground_program())
        if running and not self._confirm_running_close(
                'Quit?',
                ('A program is still running in %d tab%s. Quit anyway?'
                 % (running, '' if running == 1 else 's')),
                [self.tabs.widget(i) for i in range(self.tabs.count())]):
            event.ignore()
            return
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
    enough for the handler to run. quit() emits aboutToQuit, which tears every
    tab's pty down inside the event loop (see main), so nothing fires into a
    half-destroyed object during the XCB teardown that follows."""
    wake = QTimer(app)
    wake.timeout.connect(lambda: None)

    def handler(_signum, _frame):
        wake.stop()                     # no more wake ticks racing teardown
        app.quit()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, handler)
        except (OSError, ValueError, AttributeError):
            pass        # a signal not settable here stays at its default
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


class _Launch:
    """The parsed launch command line: window identity, an optional session file,
    Qt pass-through args, and a list of tab specs to open."""

    def __init__(self):
        self.wm_class = None       # --class  -> WM_CLASS class / Wayland app-id
        self.wm_name = None        # --name   -> WM_CLASS instance (X11)
        self.new_instance = False  # --new-instance -> never reuse a running one
        self.instance_group = 'default'   # --instance-group NAME
        self.qt_args = []          # unrecognized args, handed to Qt
        self.tabs = []             # [{title, tui, mode, command}]


def _launch_parser(with_globals):
    """The per-tab option parser; the first group also carries the global options
    (window identity, session, --version)."""
    p = argparse.ArgumentParser(
        prog='secure-terminal', add_help=with_globals,
        description='A terminal that shows untrusted output safely.',
        epilog="Run a command with '-- PROGRAM ARGS' (a real argv, no shell "
               "reparse). Open several tabs by repeating --tab.")
    if with_globals:
        p.add_argument('--version', action='version',
                       version='secure-terminal ' + APP_VERSION)
        p.add_argument('--class', dest='wm_class', metavar='CLASS',
                       help='window WM_CLASS / Wayland app-id (for WM rules)')
        p.add_argument('--name', dest='wm_name', metavar='NAME',
                       help='window WM_CLASS instance name (X11)')
        p.add_argument('--new-instance', dest='new_instance', action='store_true',
                       help='force a fresh process instead of reusing a running one')
        p.add_argument('--instance-group', dest='instance_group',
                       metavar='NAME', default='default',
                       help='which running instance to reuse (default: "default")')
        # Handled by an early headless dispatch in main() (before Qt); listed here
        # only so --help documents it. See CANARY_TOKEN / _test_canary.
        p.add_argument('--test-canary', action='store_true',
                       help='fire the safe EICAR-style test canary and exit '
                            '(positive control for security-test harnesses)')
    p.add_argument('--title', help='initial tab title')
    p.add_argument('--tui', action='store_true', default=None,
                   help='start this tab in TUI mode')
    p.add_argument('--no-tui', dest='tui', action='store_false',
                   help='start this tab in CLI mode')
    p.add_argument('--mode', choices=list(DISPLAY_MODES),
                   help='initial unicode display mode')
    p.add_argument('-e', '--command', dest='cmd_string', metavar='STRING',
                   help='run STRING (shell-split, no shell); prefer -- for a real argv')
    # per-tab overrides of the window defaults (an admin lock still wins). None is
    # the "not passed" sentinel that inherits the window default, so the store_true
    # / store_false pairs deliberately default to None rather than False.
    p.add_argument('--colors', action='store_true', default=None,
                   help='enable ANSI colours for this tab')
    p.add_argument('--no-colors', dest='colors', action='store_false',
                   help='disable ANSI colours for this tab')
    p.add_argument('--cli-terminfo', dest='cli_terminfo', action='store_true',
                   default=None,
                   help='advertise the restricted terminfo for this tab')
    p.add_argument('--no-cli-terminfo', dest='cli_terminfo', action='store_false',
                   help='advertise xterm-256color for this tab')
    p.add_argument('--bell', metavar='CHANNELS',
                   help='bell channels for this tab, e.g. "audible,visual" (empty = silent)')
    p.add_argument('--osc', dest='osc', metavar='FEATURE', action='append',
                   help='enable an OSC feature for this tab (repeatable), e.g. '
                        '--osc osc_clipboard_read --osc osc_title')
    return p


def _parse_launch_args(argv):
    """Parse the launch CLI into a _Launch. Grammar:
        secure-terminal [GLOBAL] [TABOPTS] [--tab [TABOPTS]]... [-- PROGRAM ARGS]
    Everything after the first '--' is a real argv command for the LAST tab;
    '--tab' before that starts an additional tab. argparse handles --help/--version
    and errors (exit) itself, which is correct for a CLI (before Qt starts)."""
    launch = _Launch()
    command = None
    if '--' in argv:
        cut = argv.index('--')
        command = list(argv[cut + 1:])       # verbatim argv, no shell reparse
        argv = argv[:cut]
    groups, current = [], []
    for token in argv:
        if token == '--tab':
            groups.append(current)
            current = []
        else:
            current.append(token)
    groups.append(current)
    for index, group in enumerate(groups):
        parser = _launch_parser(index == 0)
        if index == 0:
            namespace, leftover = parser.parse_known_args(group)
            launch.qt_args = leftover         # e.g. Qt's -platform / -style
            launch.wm_class = namespace.wm_class
            launch.wm_name = namespace.wm_name
            launch.new_instance = namespace.new_instance
            launch.instance_group = namespace.instance_group
        else:
            namespace = parser.parse_args(group)
        launch.tabs.append({
            'title': namespace.title, 'tui': namespace.tui,
            'mode': namespace.mode, 'command': namespace.cmd_string,
            'colors': namespace.colors, 'cli_terminfo': namespace.cli_terminfo,
            'bell': namespace.bell, 'osc': namespace.osc})
    if command is not None:
        launch.tabs[-1]['command'] = command

    def _empty(spec):
        return not any(spec.get(k) is not None
                       for k in ('title', 'tui', 'mode', 'command',
                                 'colors', 'cli_terminfo', 'bell', 'osc'))

    # A leading '--tab' means the first tab IS that group; drop the empty
    # placeholder for tokens before it (its globals were already read).
    if len(launch.tabs) > 1 and _empty(launch.tabs[0]):
        launch.tabs.pop(0)
    # A bare "secure-terminal" (one empty group, no command/session) specifies no
    # tabs -> normal startup (restore session or a default tab).
    if len(launch.tabs) == 1 and _empty(launch.tabs[0]):
        launch.tabs = []
    return launch


def _launch_to_request(launch):
    """Serialize a launch spec into an IPC 'open' request for a running instance."""
    return {'op': 'open', 'wm_class': launch.wm_class, 'tabs': launch.tabs}


def _sanitize_tab_spec(spec):
    """Type-validate a tab spec received over IPC (owner-only, but defensive)."""
    title, tui = spec.get('title'), spec.get('tui')
    mode, command = spec.get('mode'), spec.get('command')
    colors, cli_terminfo = spec.get('colors'), spec.get('cli_terminfo')
    bell, osc = spec.get('bell'), spec.get('osc')
    return {
        'title': title if isinstance(title, str) else None,
        'tui': tui if isinstance(tui, bool) else None,
        'mode': mode if mode in DISPLAY_MODES else None,
        'command': command if isinstance(command, (str, list)) else None,
        'colors': colors if isinstance(colors, bool) else None,
        'cli_terminfo': cli_terminfo if isinstance(cli_terminfo, bool) else None,
        'bell': bell if isinstance(bell, str) else None,
        'osc': [f for f in osc if isinstance(f, str)] if isinstance(osc, list) else None,
    }


def _ctl_main(argv):
    """The `secure-terminal ctl ...` client: send a remote-control request to a
    running instance and print the reply. Pure Python (no Qt). Remote control must
    be enabled by an admin on the running instance, or it refuses."""
    parser = argparse.ArgumentParser(
        prog='secure-terminal ctl',
        description='Remote-control a running secure-terminal instance. Requires '
                    'remote_control=true set by an admin in /etc/secure-terminal.d.')
    parser.add_argument('--instance-group', default='default',
                        help='which running instance (default: "default")')
    sub = parser.add_subparsers(dest='cmd', required=True)
    sub.add_parser('ls', help='list tabs (id and title)')
    send = sub.add_parser('send-text', help='send text to a tab (as if typed, '
                                            'sanitized)')
    send.add_argument('--tab', required=True, metavar='MATCH',
                      help='target tab: id:N or title:NAME')
    send.add_argument('text', help="text to send (include a newline to submit)")
    title = sub.add_parser('set-tab-title', help='rename a tab')
    title.add_argument('--tab', required=True, metavar='MATCH')
    title.add_argument('title')
    dump = sub.add_parser('dump-tab',
                          help="print a tab's current rendered text (for tests)")
    dump.add_argument('--tab', required=True, metavar='MATCH')
    dump.add_argument('--lines', type=int, metavar='N',
                      help='only the last N lines')
    args = parser.parse_args(argv)

    request = {'op': 'ctl-' + args.cmd}
    if args.cmd in ('send-text', 'set-tab-title', 'dump-tab'):
        request['tab'] = args.tab
    if args.cmd == 'send-text':
        request['text'] = args.text
    if args.cmd == 'set-tab-title':
        request['title'] = args.title
    if args.cmd == 'dump-tab' and args.lines:
        request['lines'] = args.lines

    reply = ipc.send_request(args.instance_group, request)
    if reply is None:
        sys.stderr.write('secure-terminal ctl: no running instance in group %r\n'
                         % (args.instance_group,))
        return 1
    if not reply.get('ok'):
        sys.stderr.write('secure-terminal ctl: ' + reply.get('error', 'failed')
                         + '\n')
        return 1
    if args.cmd == 'ls':
        for tab in reply.get('tabs', []):
            sys.stdout.write('%s\t%s%s\n' % (
                tab.get('id'), tab.get('title', ''),
                '  [tui]' if tab.get('tui') else ''))
    elif args.cmd == 'dump-tab':
        sys.stdout.write(reply.get('text', ''))
    return 0


# EICAR-style positive control for adversarial security-test harnesses.
#
# secure-terminal is secure by design: nothing on the output path can write
# to the pty, so an attack payload fed as output can never inject a command. An
# adversarial corpus test therefore EXPECTS the canary to never fire against us.
# That creates a dangerous failure mode -- if the harness itself is broken (never
# feeds the payload, watches the wrong marker, cannot write its temp dir), EVERY
# payload silently "passes" and a genuinely vulnerable terminal would look just as
# clean as we do. A green run would then mean nothing.
#
# `--test-canary` closes that gap: it makes secure-terminal DELIBERATELY perform
# the exact safe action a successful injection would (drop a marker file + emit a
# token), so the harness can confirm end to end that it can actually SEE a fired
# canary. The harness must run this positive control first and FAIL LOUD if the
# canary is not observed, before trusting any "not vulnerable" verdict.
#
# Two properties keep the control itself harmless and confinable:
#  - The action is benign -- a fixed ASCII token, never a real command -- so it
#    cannot hurt a tester.
#  - The marker goes to a single PREDEFINED, owner-only location
#    (<runtime>/secure-terminal/canary/canary), NOT an arbitrary caller-supplied
#    path, so the write can never be aimed elsewhere and the AppArmor profile
#    grants write to exactly that subtree and nothing else.
# The token is a stable protocol constant shared with the harness.
CANARY_TOKEN = 'SECURE-TERMINAL-TEST-CANARY-POSITIVE-CONTROL-V1'


def canary_marker_path():
    """The single PREDEFINED path the --test-canary positive control writes:
    <runtime>/secure-terminal/canary/canary. Fixed (never a caller-supplied path)
    so the action cannot be aimed elsewhere, owner-only, and confinable -- the
    AppArmor profile grants write to exactly this subtree. Reuses the same runtime
    base as the single-instance IPC socket, so (like the socket) it follows
    XDG_RUNTIME_DIR; the profile authorizes the standard /run/user/<uid> location,
    which is what an enforcing host uses. Test harnesses run in CI without the
    profile enforcing, so they may redirect the runtime dir freely."""
    return os.path.join(ipc.socket_dir(), 'canary', 'canary')


def _test_canary():
    """Perform the safe canary action and exit (see CANARY_TOKEN). Writes the fixed
    token to the predefined, owner-only marker and echoes it on stdout. Headless:
    no Qt, no shell, no window. Fails LOUD (exit 1) if the marker cannot be written,
    so a harness can tell a real machinery fault from a clean run."""
    marker = canary_marker_path()
    try:
        os.makedirs(os.path.dirname(marker), mode=0o700, exist_ok=True)
        with open(marker, 'w', encoding='ascii') as handle:
            handle.write(CANARY_TOKEN + '\n')
    except OSError as exc:
        sys.stderr.write('secure-terminal: --test-canary: cannot write the canary '
                         'marker %s: %s\n' % (marker, exc))
        return 1
    sys.stdout.write(CANARY_TOKEN + '\n')
    sys.stdout.flush()
    return 0


def main():
    _quiet_font_warnings()
    if sys.argv[1:2] == ['ctl']:
        return _ctl_main(sys.argv[2:])
    # Headless positive control for security-test harnesses; handled before Qt so
    # it needs no display. It is a global option, so fire whenever --test-canary
    # appears anywhere among the global args (before any child-command '--'), not
    # only as the very first token -- a wrapper may prefix another global such as
    # --new-instance. A '--test-canary' after '--' belongs to the child command
    # and is left alone. See CANARY_TOKEN.
    _head = sys.argv[1:]
    if '--' in _head:
        _head = _head[:_head.index('--')]
    if '--test-canary' in _head:
        return _test_canary()
    launch = _parse_launch_args(sys.argv[1:])

    # Single instance by default: try to hand this launch to a running instance in
    # the same group; if one answers, it opens the tabs and we exit. --new-instance
    # skips this and always starts a fresh process.
    if not launch.new_instance:
        reply = ipc.send_request(launch.instance_group, _launch_to_request(launch))
        if reply is not None:
            if not reply.get('ok'):
                sys.stderr.write('secure-terminal: %s\n'
                                 % reply.get('error', 'the running instance '
                                             'refused the request'))
                return 1
            return 0

    qt_argv = [sys.argv[0]] + launch.qt_args
    if launch.wm_name:
        qt_argv += ['-name', launch.wm_name]     # Qt X11 resource/instance name
    app = QApplication(qt_argv)
    app.setApplicationName('secure-terminal')
    _icon = _app_icon()
    if not _icon.isNull():
        app.setWindowIcon(_icon)
    if launch.wm_class:
        # Wayland app-id and, on Qt6/XCB, the WM_CLASS class part.
        app.setDesktopFileName(launch.wm_class)
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

    window = MainWindow(launch=launch)
    # Become the single-instance server so later launches reuse this process
    # (unless the user asked for a standalone --new-instance).
    if not launch.new_instance:
        window.start_instance_server(launch.instance_group)
    window.show()

    # On ANY quit -- a SIGTERM/SIGHUP from the launching terminal (via
    # _install_signal_quit -> app.quit()), an explicit app.quit(), or the last
    # window closing -- detach every tab's pty notifier, close its fd and hang up
    # its child WHILE the Qt event loop is still up. Without this, a
    # SIGTERM->app.quit() leaves app.exec() and the pty QSocketNotifiers are then
    # destroyed uncontrolled during interpreter teardown, which segfaults under
    # XCB. shutdown() is idempotent, so a normal window close (whose closeEvent
    # already shut its tabs down) re-running here is harmless.
    def _shutdown_all_tabs():
        for widget in app.topLevelWidgets():
            if isinstance(widget, MainWindow):
                for i in range(widget.tabs.count()):
                    try:
                        widget.tabs.widget(i).shutdown()
                    except Exception:      # pylint: disable=broad-except
                        pass               # best-effort teardown; never block quit
    app.aboutToQuit.connect(_shutdown_all_tabs)

    return app.exec()


if __name__ == '__main__':  # pragma: no cover - module entry guard
    sys.exit(main())
