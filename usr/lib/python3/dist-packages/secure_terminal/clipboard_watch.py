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

The reusable core is ClipboardWatcher: watch + review, no tray/IPC. The MAIN
WINDOW embeds it in-process -- a continuous one for "Run in the background" (and
the `--tray` hidden-to-tray login autostart) and a one-shot one (watch=False) for
"Review clipboard now" -- so the sanitizer shares the app's single tray icon
rather than running as a separate daemon process with a second icon.

Reuses the terminal's own ReviewBar and the Qt-free sanitize core.
"""

import configparser
import os

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal
from PyQt6.QtWidgets import QVBoxLayout, QWidget

from secure_terminal import settings
from secure_terminal.review import ReviewBar
from secure_terminal.sanitize import (
    THEMES, has_paste_finding, sanitize_clipboard, sanitize_clipboard_unicode,
)
from secure_terminal.unicode_tag import has_deceptive


_AUTOSTART_BASENAME = 'sclip-clipboard-watch.desktop'


def _deceptive(text):
    """True when text carries an ACTIVE deception -- an invisible / bidi / control
    character, or a homoglyph posing as ASCII. The DEFAULT trigger: it does not fire on
    innocent accented or non-Latin text, only on a real hazard, so the user is not
    trained to dismiss reflexively. has_deceptive is the allocation-free, early-exit
    boolean behind tag_text, so the whole clipboard is scanned at any size with no cap."""
    return has_deceptive(text)


def _any_nonascii(text):
    """True when text carries ANY non-plain-ASCII character -- the broader, noisier
    trigger the tray menu can opt into (fires on accents / CJK / emoji too)."""
    return has_paste_finding(text)


def _load_theme():
    cfg = settings.load()
    theme = cfg.get('theme')
    return theme if theme in THEMES else 'light'


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
            body = handle.read()
    except (OSError, UnicodeDecodeError):
        # Unreadable, or not valid UTF-8 (a hand edit / a Latin-1 tool / a crash
        # mid-write): treat an unparseable override as ENABLED -- the same fallback as
        # an unreadable file, and it must never crash the callers (the clipboard menu,
        # set_systray, the settings dialog) that ask on every open.
        return True
    # Parse the actual Key=Value in the [Desktop Entry] section. A raw whole-file
    # substring match false-reports 'disabled' when a Comment=/Name= VALUE merely
    # CONTAINS the literal 'Hidden=true', or when a [Desktop Action ...] section (not
    # [Desktop Entry]) carries the key. interpolation=None: an Exec= line with a % field
    # code must not raise; strict=False: tolerate a lenient hand-edited file.
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(body)
        entry = parser['Desktop Entry']
    except (configparser.Error, KeyError):
        return True                      # malformed / no [Desktop Entry] -> fail-safe enabled
    return not (entry.get('X-GNOME-Autostart-enabled', '').strip().lower() == 'false'
                or entry.get('Hidden', '').strip().lower() == 'true')


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
               'Exec=secure-terminal --tray\n'
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

    def dispatch_pending_clipboard(self, action, text=None):
        # Thread the ORIGINAL reviewed text (the clipboard-still-holds-it TOCTOU check)
        # and the DELIVERED text (the user's edit, or the original) SEPARATELY: resolve
        # compares the clipboard against the original but WRITES the edited value.
        # Conflating them made an edited Replace silently no-op (edited != the original
        # still on the clipboard -> the write was skipped, leaving the unsafe text).
        self._controller.resolve(self._raw, action,
                                 self._raw if text is None else text)


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


class _ScanTask(QRunnable):
    """Run the (uncapped, potentially multi-second) deceptive / non-ASCII scan OFF the
    GUI thread and report the result back through the watcher's _scan_done signal --
    emitted cross-thread, so Qt delivers _on_scan_done on the GUI thread. `trigger` is a
    module-level pure function (_deceptive / _any_nonascii); it touches no Qt state, so
    running it on a pool thread is safe."""

    def __init__(self, watcher, generation, text, trigger):
        super().__init__()
        self._watcher = watcher
        self._generation = generation
        self._text = text
        self._trigger = trigger

    def run(self):
        self._watcher._scan_done.emit(
            self._generation, self._text, bool(self._trigger(self._text)))


class ClipboardWatcher(QObject):
    """The reusable clipboard-review core: optionally watch the clipboard, and/or
    review its current contents once, hosting the shared ReviewBar in a popup. No
    tray, no IPC, no event loop of its own -- embedded in-process by the main window
    for "Run in the background" (watch=True) and "Review clipboard now" (watch=False)."""

    # Carries a worker scan's result (generation, scanned text, trigger bool) back to the
    # GUI thread. A QObject signal so a cross-thread emit is delivered queued on this
    # thread, where _show_review's Qt widget work is legal.
    _scan_done = pyqtSignal(int, str, bool)

    def __init__(self, app, theme=None, any_mode=False, watch=False):
        super().__init__()
        self._clipboard = app.clipboard()
        self._enabled = True
        self._any_mode = bool(any_mode)
        self._last_written = None          # feedback-loop guard (our own write)
        self._dismissed = None             # exact text the user chose to keep
        self._theme = theme if theme in THEMES else _load_theme()
        self._popup = _ReviewPopup()
        # A monotonically increasing scan id: a newer clipboard change bumps it, so an
        # in-flight worker's result is recognised as stale and dropped (see _on_scan_done).
        self._scan_gen = 0
        self._scan_done.connect(self._on_scan_done)
        if watch:
            self._clipboard.dataChanged.connect(self._on_change)

    def set_enabled(self, on):
        self._enabled = bool(on)

    def set_any_mode(self, on):
        self._any_mode = bool(on)

    def stop(self):
        """Stop watching and close any open review, so the watcher can be dropped.
        The QClipboard.dataChanged connection holds a reference to this watcher, so
        merely dropping the last Python reference would leave it alive and still
        reacting -- disconnect explicitly. Idempotent (a watch=False reviewer, or a
        second stop, disconnects nothing)."""
        self._scan_gen += 1                # invalidate any in-flight worker scan result
        try:
            self._clipboard.dataChanged.disconnect(self._on_change)
        except (TypeError, RuntimeError):
            pass                 # not connected (watch=False) or already stopped
        self._popup.bar.hide_review()
        self._popup.hide()

    def review_now(self):
        """Review whatever is on the clipboard right now (even clean text), so a
        user can sanitize on demand."""
        text = self._clipboard.text()
        if text:
            self._show_review(text)

    def review_is_open(self):
        """True while a review popup is showing and UNRESOLVED (resolve() hides it).
        Lets a second 'Review clipboard now' re-raise the existing popup instead of
        reassigning the holder and silently GC'ing the first, unresolved one."""
        return self._popup.isVisible()

    def raise_popup(self):
        """Bring an already-open review popup to the front (used when a second review
        is requested while the first is still unresolved)."""
        self._popup.raise_()
        self._popup.activateWindow()

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
        # Offload the scan: _deceptive / _any_nonascii are O(n) per character and run with
        # NO cap, so on a large or space-free CJK clipboard they take seconds -- and this
        # slot fires on dataChanged on the GUI thread, so a synchronous scan froze the whole
        # app. Hand it to a worker; a newer change bumps _scan_gen so this scan's result is
        # dropped as stale when it lands (see _on_scan_done). No cap is lost.
        self._scan_gen += 1
        trigger = _any_nonascii if self._any_mode else _deceptive
        QThreadPool.globalInstance().start(
            _ScanTask(self, self._scan_gen, text, trigger))

    def _on_scan_done(self, generation, text, flagged):
        """GUI-thread continuation of _on_change once the worker scan finishes. Drop a
        result that a newer clipboard change has superseded, that came back clean, or
        whose text is no longer what the clipboard currently holds (it changed while the
        scan ran -- the review/reply must act on the CURRENT clipboard, the same TOCTOU
        discipline resolve() uses). A stop() while a scan was in flight bumps _scan_gen and
        clears _enabled, so a late result is dropped here too."""
        if generation != self._scan_gen:
            return                         # a newer clipboard change superseded this scan
        if not flagged:
            return                         # clean (or innocent) -> stay silent
        if not self._enabled:
            return                         # disabled / stopped since the scan started
        if self._clipboard.text() != text:
            return                         # clipboard changed under us -> do not review stale text
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

    def resolve(self, original, action, edited=None):
        """Apply the user's choice (called from _ClipboardReview.dispatch). `original`
        is the reviewed text expected to still be on the clipboard (the TOCTOU guard);
        `edited` is what to WRITE when Replacing -- the user's edit, defaulting to the
        original when the field was left untouched."""
        if edited is None:
            edited = original
        if action == 'reject':
            self._dismissed = original     # keep it; do not nag about the same text
        elif self._clipboard.text() == original:
            # Replace ONLY while the flagged text is still on the clipboard. If the
            # user copied something else after the popup opened, that newer content
            # must not be silently clobbered by the stale review (a TOCTOU write).
            # Compare against the ORIGINAL but sanitize + write the EDITED value.
            safe = (sanitize_clipboard_unicode if action == 'unicode'
                    else sanitize_clipboard)(edited)
            self._last_written = safe      # so the resulting dataChanged is ignored
            self._clipboard.setText(safe)
        self._popup.bar.hide_review()
        self._popup.hide()
