#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Clipboard sanitizer watcher.

Watches the SYSTEM clipboard and, when copied text carries deceptive Unicode --
an invisible / bidi / control character, or a homoglyph posing as ASCII -- offers
to replace it with a safe version, so text later pasted into an editor or any
program that does not neutralize Unicode is safe.

PRINCIPLE -- flag-and-offer, never auto-swap. It NEVER rewrites the clipboard on
its own: it raises the review bar and the user chooses Keep original (the
default), Replace (ASCII), or Replace (keep unicode). It stores no clipboard
history; it inspects the current text transiently and forgets it.

SCOPE -- sanitizes the LOCAL (in-VM) clipboard via Qt (X11 or Wayland). It does
NOT touch the Qubes inter-VM global clipboard (Ctrl+Shift+C / Ctrl+Shift+V).

Two consumers of the same core:
  * ClipboardWatcher -- the reusable core: watch + review, no tray/IPC. The
    TERMINAL embeds one (watch=False) for its "Review clipboard now" action.
  * ClipboardWatchApp -- the standalone tray daemon (`--clipboard-watch`): a
    continuous ClipboardWatcher + a tray icon + a SINGLETON IPC server, so only
    one clipboard watcher runs and the terminal can start / stop / query it
    (the 'clipboard-watch' instance group).

Reuses the terminal's own ReviewBar and the Qt-free sanitize core.
"""

import fcntl
import json
import os
import signal
import sys

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QMenu, QSystemTrayIcon, QVBoxLayout, QWidget,
)

from secure_terminal import ipc, settings
from secure_terminal.review import ReviewBar
from secure_terminal.sanitize import (
    THEMES, classify_paste, sanitize_clipboard, sanitize_clipboard_unicode,
)
from secure_terminal.unicode_tag import tag_text

_AUTOSTART_BASENAME = 'sclip-clipboard-watch.desktop'
## The fixed instance group whose owner-only socket makes the watcher a singleton
## and lets the terminal ping / start / stop it. See ipc.socket_path.
INSTANCE_GROUP = 'clipboard-watch'


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


def _load_theme():
    cfg = settings.load()
    theme = cfg.get('theme')
    return theme if theme in THEMES else 'light'


def warn_any_default():
    """The persisted 'warn on any non-ASCII' preference (settings key
    `clip_warn_any`, default off). The terminal persists it; the daemon reads it at
    startup so an autostarted watcher honours the user's choice."""
    return settings.load().get('clip_warn_any') == 'true'


def _user_autostart_path():
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return os.path.join(base, 'autostart', _AUTOSTART_BASENAME)


def autostart_enabled():
    """Whether the watcher is set to start on login. The package ships an ENABLED
    system entry (etc/xdg/autostart), so 'on' is the default; a per-user override
    file that disables it (X-GNOME-Autostart-enabled=false / Hidden=true) is the
    only way it is off. No override -> enabled."""
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


def is_running():
    """True if a clipboard-watch daemon already owns the singleton socket -- a raw
    CONNECT probe that succeeds the instant it binds (see ipc.socket_is_live)."""
    return ipc.socket_is_live(INSTANCE_GROUP)


def stop_running():
    """Ask a running daemon to quit; returns True if one answered. `None` (no
    server) means it was already not running."""
    return ipc.send_request(INSTANCE_GROUP, {'op': 'quit'}) is not None


def push_warn_any(value):
    """Live-update a running daemon's trigger mode; no-op if none runs."""
    ipc.send_request(INSTANCE_GROUP, {'op': 'set-warn-any', 'value': bool(value)})


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


class ClipboardWatcher:
    """The reusable clipboard-review core: optionally watch the clipboard, and/or
    review its current contents once, hosting the shared ReviewBar in a popup. No
    tray, no IPC, no event loop of its own -- embeddable by the tray daemon
    (watch=True) and by the terminal's "Review clipboard now" (watch=False)."""

    def __init__(self, app, theme=None, any_mode=False, watch=False):
        self._clipboard = app.clipboard()
        self._enabled = True
        self._any_mode = bool(any_mode)
        self._last_written = None          # feedback-loop guard (our own write)
        self._dismissed = None             # exact text the user chose to keep
        self._theme = theme if theme in THEMES else _load_theme()
        self._popup = _ReviewPopup()
        if watch:
            self._clipboard.dataChanged.connect(self._on_change)

    def set_enabled(self, on):
        self._enabled = bool(on)

    def set_any_mode(self, on):
        self._any_mode = bool(on)

    def review_now(self):
        """Review whatever is on the clipboard right now (even clean text), so a
        user can sanitize on demand."""
        text = self._clipboard.text()
        if text:
            self._show_review(text)

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
        elif self._clipboard.text() == raw:
            # Replace ONLY while the flagged text is still on the clipboard. If the
            # user copied something else after the popup opened, that newer content
            # must not be silently clobbered by the stale review (a TOCTOU write).
            safe = (sanitize_clipboard_unicode if action == 'unicode'
                    else sanitize_clipboard)(raw)
            self._last_written = safe      # so the resulting dataChanged is ignored
            self._clipboard.setText(safe)
        self._popup.bar.hide_review()
        self._popup.hide()


class ClipboardWatchApp:
    """The standalone tray daemon (`--clipboard-watch`): a continuous
    ClipboardWatcher + a tray icon + a SINGLETON IPC server. Only one runs; the
    terminal starts / stops / pings it over the 'clipboard-watch' group."""

    def __init__(self, app):
        self._app = app
        self._watcher = ClipboardWatcher(app, any_mode=warn_any_default(), watch=True)
        self._tray = None
        self._server = None
        self._lock_fd = None

    # -- singleton IPC server -------------------------------------------------
    def _claim_singleton(self):
        """Claim the 'clipboard-watch' singleton ATOMICALLY. Returns False if another
        live watcher already holds it (the caller should exit).

        The gate is an flock(LOCK_EX|LOCK_NB) on a lock file: the kernel grants it to
        exactly one process and releases it automatically when that process dies, so a
        crashed watcher never wedges the next one. A socket_is_live()+removeServer()+
        listen() sequence could NOT be the gate -- that check-then-act leaves a window
        where two watchers both see 'not live' and both bind, each removeServer()
        unlinking the other's just-bound socket, so BOTH run and race duplicate review
        bars. Here the QLocalServer socket is bound by the SOLE lock holder, so clearing
        a crashed predecessor's stale socket cannot race a live peer.

        (MainWindow.start_instance_server keeps the lighter socket_is_live gate on
        purpose: terminals are meant to coexist, so its residual bind race only orphans
        a ctl target -- benign. A clipboard watcher must be a true singleton.)"""
        try:
            ipc.ensure_socket_dir()
        except OSError:
            return True                     # no runtime dir -> cannot singleton; proceed
        path = ipc.socket_path(INSTANCE_GROUP)
        try:
            lock_fd = os.open(
                path + '.lock', os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o600)
        except OSError:
            return True                     # cannot open the lock file -> best effort, proceed
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock_fd)
            return False                    # another live watcher holds the lock -> exit
        except OSError:
            os.close(lock_fd)               # flock unsupported on this fs -> best effort, proceed
            return True
        self._lock_fd = lock_fd             # held for process lifetime (releases on exit)
        from PyQt6.QtNetwork import QLocalServer   # noqa: PLC0415
        # A watcher still running the PRE-flock code holds no lock, so the flock above
        # cannot see it. Defer to any live incumbent socket (e.g. mid package upgrade)
        # instead of stealing it; only clear a confirmed-stale socket.
        if ipc.socket_is_live(INSTANCE_GROUP):
            os.close(self._lock_fd)
            self._lock_fd = None
            return False
        QLocalServer.removeServer(path)     # stale socket from a crashed predecessor
        self._server = QLocalServer(self._app)
        self._server.setSocketOptions(
            QLocalServer.SocketOption.UserAccessOption)   # 0700, same-UID only
        if not self._server.listen(path):   # pragma: no cover - sole lock holder; a failure is a rare OS fault
            self._server = None
            return True
        self._server.newConnection.connect(self._on_ipc_connection)
        return True

    def _on_ipc_connection(self):
        conn = self._server.nextPendingConnection()
        if conn is None:                    # pragma: no cover - Qt only signals with one pending
            return
        conn.disconnected.connect(conn.deleteLater)
        framer = ipc.Framer()

        def on_ready():
            try:
                payload = framer.feed(bytes(conn.readAll()))
            except ValueError:
                conn.abort()
                return
            if payload is None:             # pragma: no cover - one-shot frame arrives whole locally
                return
            reply = self._dispatch(payload)
            conn.write(ipc.frame(json.dumps(reply).encode('utf-8')))
            conn.flush()
            conn.disconnectFromServer()

        conn.readyRead.connect(on_ready)

    def _dispatch(self, payload):
        """Handle one IPC request; return a reply dict. Owner-only socket, but still
        type-validated. Ops: ping (running probe), quit, set-warn-any (live trigger)."""
        try:
            request = json.loads(payload.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            return {'ok': False, 'error': 'malformed request'}
        if not isinstance(request, dict):
            return {'ok': False, 'error': 'malformed request'}
        op = request.get('op')
        if op == 'ping':
            return {'ok': True, 'pid': os.getpid()}
        if op == 'quit':
            # Reply first, then quit, so the caller gets its acknowledgement.
            QTimer.singleShot(0, self._app.quit)
            return {'ok': True}
        if op == 'set-warn-any':
            self._watcher.set_any_mode(bool(request.get('value')))
            return {'ok': True}
        return {'ok': False, 'error': 'unknown op: %r' % (op,)}

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
        act_watch.setChecked(True)
        act_watch.toggled.connect(self._watcher.set_enabled)

        act_any = menu.addAction('Warn on any non-ASCII')
        act_any.setCheckable(True)
        act_any.setChecked(warn_any_default())
        act_any.setToolTip('Off: warn only on hidden/deceptive characters. '
                           'On: warn on any non-ASCII (accents, CJK, emoji) too.')
        act_any.toggled.connect(self._watcher.set_any_mode)

        act_autostart = menu.addAction('Start on login')
        act_autostart.setCheckable(True)
        act_autostart.setChecked(autostart_enabled())
        act_autostart.toggled.connect(lambda on: set_autostart(bool(on)))

        menu.addSeparator()
        menu.addAction('Review clipboard now').triggered.connect(
            self._watcher.review_now)
        menu.addSeparator()
        menu.addAction('Quit').triggered.connect(self._app.quit)
        return menu

    # -- lifecycle ------------------------------------------------------------
    def run(self):
        self._app.setQuitOnLastWindowClosed(False)   # tray-only: no window closes it
        if not self._claim_singleton():
            # Another clipboard watcher already runs -- not an error.
            return 0
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
