#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Tray-only clipboard sanitizer (`secure-terminal --clipboard-watch`).

Watches the SYSTEM clipboard and, when copied text carries deceptive Unicode --
an invisible / bidi / control character, or a homoglyph posing as ASCII -- offers
to replace it with a safe version, so text later pasted into an editor or any
program that does not neutralize Unicode is safe. No terminal window is opened.

PRINCIPLE -- flag-and-offer, never auto-swap. The tool NEVER rewrites the
clipboard on its own: it raises the review bar and the user chooses Keep original
(the default), Replace (ASCII), or Replace (keep unicode). It stores no clipboard
history; it inspects the current text transiently and forgets it.

SCOPE -- this sanitizes the LOCAL (in-VM) clipboard via Qt, which auto-selects the
X11 or Wayland backend. It does NOT touch the Qubes inter-VM global clipboard
(Ctrl+Shift+C / Ctrl+Shift+V) -- that stays Qubes' own mechanism; run this (or the
sclip CLI) after pasting into the target VM.

Reuses the terminal's own ReviewBar (same look, risk-class colouring and
click-to-inspect preview) and the Qt-free sanitize core; the only new logic here
is the clipboard watch and the standalone popup that hosts the bar.
"""

import os
import signal
import sys

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QMenu, QSystemTrayIcon, QVBoxLayout, QWidget,
)

from secure_terminal import settings
from secure_terminal.review import ReviewBar
from secure_terminal.sanitize import (
    THEMES, classify_paste, sanitize_clipboard, sanitize_clipboard_unicode,
)
from secure_terminal.unicode_tag import tag_text

_AUTOSTART_BASENAME = 'sclip-clipboard-watch.desktop'


def _deceptive(text):
    """True when text carries an ACTIVE deception -- an invisible / bidi / control
    character, or a homoglyph posing as ASCII. Reuses tag_text, which replaces
    exactly those classes and passes honest text (accents, CJK, emoji) through
    unchanged, so 'tag_text changed something' == 'deceptive'. The DEFAULT trigger:
    it does not fire on innocent accented or non-Latin text, only on a real hazard,
    so the user is not trained to dismiss reflexively."""
    return bool(text) and tag_text(text) != text


def _any_nonascii(text):
    """True when text carries ANY non-plain-ASCII character -- the broader, noisier
    trigger the tray menu can opt into (fires on accents / CJK / emoji too)."""
    return bool(classify_paste(text))


def _user_autostart_path():
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return os.path.join(base, 'autostart', _AUTOSTART_BASENAME)


def autostart_enabled():
    """Whether the tray watcher is set to start on login. The package ships an
    ENABLED system entry (etc/xdg/autostart), so 'on' is the default; a per-user
    override file that disables it (X-GNOME-Autostart-enabled=false / Hidden=true)
    is the only way it is off. No override -> enabled."""
    path = _user_autostart_path()
    if not os.path.isfile(path):
        return True
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            body = handle.read().lower()
    except OSError:
        return True
    return ('x-gnome-autostart-enabled=false' not in body
            and 'hidden=true' not in body)


def set_autostart(enabled):
    """Enable/disable start-on-login WITHOUT editing the shipped system entry.
    Enable = remove any per-user disabling override (the system entry, enabled,
    applies again). Disable = write a per-user override that hides it."""
    path = _user_autostart_path()
    if enabled:
        try:
            os.remove(path)
        except OSError:
            pass                 # already absent (or unwritable) -> nothing to undo
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = ('[Desktop Entry]\n'
               'Type=Application\n'
               'Name=secure-terminal clipboard sanitizer\n'
               'Exec=secure-terminal --clipboard-watch\n'
               'X-GNOME-Autostart-enabled=false\n'
               'Hidden=true\n')
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        handle.write(content)
    os.replace(tmp, path)        # atomic, so a reader never sees a half-written file


class _ClipboardReview:
    """The object ReviewBar dispatches a clipboard choice back to -- not a terminal,
    just the holder of the reviewed text that performs the chosen replacement (the
    clipboard analogue of a tab's dispatch_pending_copy). Exposes _theme so
    ReviewBar.show_review can theme its preview panes."""

    def __init__(self, controller, raw, theme):
        self._controller = controller
        self._raw = raw
        self._theme = theme

    def dispatch_pending_clipboard(self, action):
        self._controller.resolve(self._raw, action)


class _ReviewPopup(QWidget):
    """A small top-level window hosting the reused ReviewBar. A docked bar lives in
    the terminal window; there is none here, so the bar gets its own frame, shown
    only when deceptive clipboard text appears."""

    def __init__(self):
        super().__init__(None)
        # Fixed title -- never program-supplied text on this out-of-grid surface.
        self.setWindowTitle('secure-terminal: clipboard')
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.bar = ReviewBar(self)
        self.bar.setVisible(True)          # the popup governs visibility, not the bar
        layout.addWidget(self.bar)


class ClipboardWatchApp:
    """Owns the tray icon, the review popup and the clipboard watch. Runs its own Qt
    event loop with no terminal window."""

    def __init__(self, app):
        self._app = app
        self._clipboard = app.clipboard()
        self._enabled = True
        self._any_mode = False             # default trigger: deceptive-only
        self._last_written = None          # feedback-loop guard (our own write)
        self._dismissed = None             # exact text the user chose to keep
        self._theme = self._load_theme()
        self._popup = _ReviewPopup()
        self._tray = None
        self._clipboard.dataChanged.connect(self._on_change)

    @staticmethod
    def _load_theme():
        cfg = settings.load()
        theme = cfg.get('theme')
        return theme if theme in THEMES else 'light'

    # -- clipboard watch ------------------------------------------------------
    def _on_change(self):
        if not self._enabled:
            return
        text = self._clipboard.text()
        if not text:
            return
        if text == self._last_written:     # our sanitized write echoing back
            return
        if text == self._dismissed:        # the user already chose to keep this
            return
        trigger = _any_nonascii if self._any_mode else _deceptive
        if not trigger(text):
            return                         # clean (or innocent) -> stay silent
        self._show_review(text)

    def _show_review(self, text):
        term = _ClipboardReview(self, text, self._theme)
        # delay 0: nothing is EXECUTED (unlike a paste), so the buttons need no
        # countdown -- the copy direction passes 0 for the same reason.
        self._popup.bar.show_review(term, text, 0, kind='clipboard')
        self._popup.adjustSize()
        self._popup.show()
        self._popup.raise_()
        self._popup.activateWindow()

    def resolve(self, raw, action):
        """Apply the user's choice (called from _ClipboardReview.dispatch)."""
        if action == 'reject':
            self._dismissed = raw          # keep it; do not nag about the same text
        else:
            safe = (sanitize_clipboard_unicode if action == 'unicode'
                    else sanitize_clipboard)(raw)
            self._last_written = safe      # so the resulting dataChanged is ignored
            self._clipboard.setText(safe)
        self._popup.bar.hide_review()
        self._popup.hide()

    # -- tray -----------------------------------------------------------------
    def _build_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return None
        tray = QSystemTrayIcon(self._app.windowIcon())
        tray.setToolTip('secure-terminal clipboard sanitizer')   # fixed string
        tray.setContextMenu(self._build_menu())
        tray.show()
        return tray

    def _build_menu(self):
        """SAFE, fixed actions only -- like the terminal tray, nothing here is derived
        from clipboard/program text (an out-of-grid surface must not carry a phish)."""
        menu = QMenu()
        act_watch = menu.addAction('Watch clipboard')
        act_watch.setCheckable(True)
        act_watch.setChecked(self._enabled)
        act_watch.toggled.connect(self._set_enabled)

        act_any = menu.addAction('Warn on any non-ASCII')
        act_any.setCheckable(True)
        act_any.setChecked(self._any_mode)
        act_any.setToolTip('Off: warn only on hidden/deceptive characters. '
                           'On: warn on any non-ASCII (accents, CJK, emoji) too.')
        act_any.toggled.connect(self._set_any_mode)

        act_autostart = menu.addAction('Start on login')
        act_autostart.setCheckable(True)
        act_autostart.setChecked(autostart_enabled())
        act_autostart.toggled.connect(self._set_autostart)

        menu.addSeparator()
        menu.addAction('Review clipboard now').triggered.connect(self._review_now)
        menu.addSeparator()
        menu.addAction('Quit').triggered.connect(self._app.quit)
        return menu

    def _set_enabled(self, on):
        self._enabled = bool(on)

    def _set_any_mode(self, on):
        self._any_mode = bool(on)

    @staticmethod
    def _set_autostart(on):
        set_autostart(bool(on))

    def _review_now(self):
        """Force the review for whatever is on the clipboard right now (even clean
        text), so a user can sanitize on demand."""
        text = self._clipboard.text()
        if text:
            self._show_review(text)

    # -- lifecycle ------------------------------------------------------------
    def run(self):
        self._app.setQuitOnLastWindowClosed(False)   # tray-only: no window closes it
        self._tray = self._build_tray()
        if self._tray is None:
            sys.stderr.write('secure-terminal: no system tray is available; '
                             '--clipboard-watch needs one.\n')
            return 1
        _install_sigterm(self._app)
        return self._app.exec()


def _install_sigterm(app):
    """Quit cleanly on SIGTERM/SIGINT (a logout or a `kill` from the launcher). A
    periodic no-op timer lets the interpreter run the Python signal handler while
    the otherwise-idle Qt loop waits (Qt does not wake for a Python signal on its
    own)."""
    try:
        signal.signal(signal.SIGTERM, lambda *_: app.quit())
        signal.signal(signal.SIGINT, lambda *_: app.quit())
    except (OSError, ValueError):   # pragma: no cover - only off the main thread; run() is main-thread only
        pass
    timer = QTimer(app)
    timer.start(400)
    timer.timeout.connect(lambda: None)
