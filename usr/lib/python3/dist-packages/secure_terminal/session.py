#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Session persistence: the open tabs and their scrollback, so they survive a
restart or reboot.

Stored under the XDG state directory (~/.local/state/secure-terminal/). Each
tab's scrollback -- the bulky part -- lives in its own file keyed by the tab's
durable id, tab-<id>.log, and a small session.json holds only the index: the tab
order and each tab's id/name/colour/settings. Keying the log by the durable tab
id (not by position) keeps a tab's scrollback file stable across a restart and
lets the on-demand scratch exports (transcript-<id>.txt, ...) share that identity.
Splitting the logs out keeps the index tiny and
readable, lets one tab's scrollback be inspected or removed on its own, and
avoids rewriting one large blob for every tab. JSON is used for the index because
json.load runs no code, so it stays safe to parse; the .log files are plain
already-sanitized ASCII text. Loading is defensive: a missing or malformed file
yields an empty session and never crashes.

A running program (bash, nano, ...) cannot be resurrected -- only the tab list,
each tab's name/colour/settings and its scrollback are saved, and a fresh shell
starts under the restored history.
"""

import os
import re
import json

from secure_terminal.ipc import _makedirs_private   # 0o700 private-dir creator (reused)

# A hard cap on the persisted scrollback of an "unlimited" tab, so a log file
# cannot grow without bound on disk even when no line limit is set.
UNLIMITED_PERSIST_LINES = 5000

# tab-<id>.log -- one scrollback file per tab, keyed by the tab's durable id.
_LOG_RE = re.compile(r'^tab-(\d+)\.log$')

# The on-demand scratch exports a tab writes into the state dir (Copy-path / Open /
# Save-into actions), keyed by the same durable id. Named here so the writer in
# main.py and the cleanup below cannot drift on the naming. The Save-dialog DEFAULT
# names (secure-terminal-*.txt) are NOT here: the user picks their final path, so
# those are user documents, not app-managed state to purge.
_TAB_SCRATCH_STEMS = ('transcript', 'screen', 'state-dump')
_SCRATCH_RE = re.compile(r'^(?:transcript|screen|state-dump)-(\d+)\.txt$')


def _state_dir():
    base = os.environ.get('XDG_STATE_HOME') or os.path.join(
        os.path.expanduser('~'), '.local', 'state')
    return os.path.join(base, 'secure-terminal')


def ensure_state_dir():
    """Create the state dir owner-only (0o700) and enforce that mode even on a
    PRE-EXISTING dir. It holds sensitive terminal history (transcripts, scrollback,
    session state); under a typical 022 umask a bare os.makedirs would leave it
    world-readable. Mirrors ipc.ensure_socket_dir's hardening. Best-effort chmod --
    a failure must not crash a save. Returns the path."""
    directory = _state_dir()
    _makedirs_private(directory)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    return directory


def session_path():
    return os.path.join(_state_dir(), 'session.json')


def _log_path(uid):
    return os.path.join(_state_dir(), 'tab-%d.log' % uid)


def tab_file(stem, uid):
    """A per-tab on-demand scratch export path (transcript/screen/state-dump),
    keyed by the tab's durable id so two tabs never clobber each other's file.
    One source of truth shared by the writer (main.py) and the cleanup here."""
    return os.path.join(_state_dir(), '%s-%d.txt' % (stem, uid))


def _log_indices():
    """Tab ids of the tab-<id>.log files currently on disk."""
    try:
        names = os.listdir(_state_dir())
    except OSError:
        return []
    found = []
    for name in names:
        match = _LOG_RE.match(name)
        if match:
            found.append(int(match.group(1)))
    return sorted(found)


def cap_text(text, scrollback):
    """Trim scrollback text to the tab's line limit (or the hard cap when the
    tab is unlimited), keeping the most recent lines."""
    limit = scrollback if scrollback > 0 else UNLIMITED_PERSIST_LINES
    lines = text.split('\n')
    if len(lines) > limit:
        lines = lines[-limit:]
    return '\n'.join(lines)


def _write_atomic(path, text):
    # Per-process temp name: two instances saving the same file concurrently must not
    # share one '.tmp' inode, or their writes interleave into a corrupt file before the
    # os.replace. os.replace is atomic, so the last writer wins cleanly.
    tmp = '%s.tmp.%d' % (path, os.getpid())
    # 0o600: session logs and state are sensitive terminal history; never create them
    # world-readable (a bare open() would land at 0644 under a typical umask).
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(text)
    os.replace(tmp, path)


def save(tabs, window=None, active=None):
    """Write the list of tab dicts: each tab's 'text' scrollback to its own
    tab-<n>.log, the rest as the index in session.json. `window` is an opaque
    base64 window-geometry blob (Qt saveGeometry, size + maximized state); `active`
    is the index of the focused tab, so the next start reopens it. Never raises."""
    path = session_path()
    try:
        ensure_state_dir()
        index = []
        current = set()
        for tab in tabs:
            entry = {key: value for key, value in tab.items() if key != 'text'}
            uid = tab['uid']
            current.add(uid)
            _write_atomic(_log_path(uid), tab.get('text', ''))
            index.append(entry)
        # Drop log files whose tab is no longer part of the session (a closed tab,
        # or leftovers from a previous, larger session).
        for stale in _log_indices():
            if stale not in current:
                _remove(_log_path(stale))
        payload: dict[str, object] = {'tabs': index}
        if isinstance(window, str) and window:
            payload['window'] = window
        if isinstance(active, int) and 0 <= active < len(index):
            payload['active'] = active
        _write_atomic(path, json.dumps(payload))
    except OSError:
        pass                    # a failed session save is never fatal


def load_active():
    """Return the saved focused-tab index, or None. Never raises."""
    try:
        with open(session_path(), encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    active = data.get('active')
    return active if isinstance(active, int) and active >= 0 else None


def load_window():
    """Return the saved base64 window-geometry blob, or None. Never raises."""
    try:
        with open(session_path(), encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    window = data.get('window')
    return window if isinstance(window, str) and window else None


def load():
    """Return the list of saved tab dicts (each with its 'text' scrollback read
    back from its log file), or []. Never raises."""
    try:
        with open(session_path(), encoding='utf-8') as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []               # no/corrupt session -> start fresh
    index = data.get('tabs') if isinstance(data, dict) else None
    if not isinstance(index, list):
        return []
    tabs = []
    for entry in index:
        if not isinstance(entry, dict):
            continue
        uid = entry.get('uid')
        if isinstance(uid, int) and uid >= 0:
            try:
                # errors='replace': a log truncated mid-UTF-8, or corrupted on disk,
                # must not break startup. Strict decoding raises UnicodeDecodeError
                # (a ValueError, not an OSError), which would escape "Never raises"
                # and leave the user with no window at all. The replacement chars
                # are then sanitized like any other output on the restore path.
                with open(_log_path(uid), encoding='utf-8',
                          errors='replace') as handle:
                    entry['text'] = handle.read()
            except OSError:
                entry['text'] = ''  # a missing log just restores an empty tab
        else:
            # No/invalid id (e.g. a session.json written before the durable-id
            # migration): restore an empty tab; _restore_tab assigns a fresh id.
            entry['text'] = ''
        tabs.append(entry)
    return tabs


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass                    # nothing there -> nothing to remove


def clear():
    """Remove the saved session: the index and every per-tab log. Never raises."""
    _remove(session_path())
    for uid in _log_indices():
        _remove(_log_path(uid))


def purge_tab_files(uid):
    """Best-effort remove a closed tab's app-managed files: its on-demand scratch
    exports (transcript/screen/state-dump-<id>.txt) and its scrollback log
    (tab-<id>.log). Terminal scrollback is sensitive -- a closed tab must not leave
    it recoverable on disk (the VTE scrollback-on-disk disclosure class). Best-effort
    and non-fatal: a missing file, or one held open by an external viewer, is ignored;
    never raises, so a tab close is never blocked by a failed unlink."""
    for stem in _TAB_SCRATCH_STEMS:
        _remove(tab_file(stem, uid))
    _remove(_log_path(uid))


def _state_uids_on_disk():
    """Every tab id that has any per-tab file (log or scratch) in the state dir."""
    uids = set()
    try:
        names = os.listdir(_state_dir())
    except OSError:
        return uids
    for name in names:
        match = _LOG_RE.match(name) or _SCRATCH_RE.match(name)
        if match:
            uids.add(int(match.group(1)))
    return uids


def purge_orphans(live_uids):
    """Remove every per-tab state file whose tab is not currently live, so no state
    file outlives its tab -- e.g. a crash between a tab close and its unlink, or a
    previous session's leftovers on a fresh start. Never raises."""
    live = set(live_uids)
    for uid in _state_uids_on_disk():
        if uid not in live:
            purge_tab_files(uid)
