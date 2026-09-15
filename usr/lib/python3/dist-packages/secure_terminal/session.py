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
import time
import shutil
from typing import TypeGuard

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


def _valid_uid(value) -> TypeGuard[int]:
    """A durable tab id is a non-negative int. Reject bool (a JSON true/false is an
    int subclass) and any non-int a hand-edited/corrupt session.json could carry, so
    such a value is never used to KEY a log file (which would alias another tab's
    scrollback, or crash). Mirrors main._valid_uid; kept here so session stands
    alone (the GUI is not imported to load a session)."""
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


# The per-instance state namespace: each independent instance owns a SUBTREE of the
# state dir keyed by its group, so two instances (a primary + a --new-instance, or two
# --instance-group launches) never share tab-<n>.log / transcript-<n>.txt and can never
# delete each other's files -- the tab ordinal is unique only WITHIN one instance, so it
# must be namespaced by the instance to be a valid on-disk key across processes (the
# idiom used by iTerm2 / VTE / tmux-resurrect). Set once at window startup.
_INSTANCE_GROUP = 'default'
# The unnamed-throwaway group prefix (a bare --new-instance): isolated, not restored
# across restart, and self-removed on close. A named --instance-group persists.
_THROWAWAY_PREFIX = 'new-'
_GROUP_SAFE_RE = re.compile(r'[^A-Za-z0-9._-]')


def _safe_group(name):
    """A filesystem-safe single path component for the instance subtree. Rejects path
    separators / traversal (a crafted --instance-group must never escape the state dir)
    by mapping unsafe characters to '_'; '', '.' and '..' fall back to 'default'."""
    safe = _GROUP_SAFE_RE.sub('_', name) if isinstance(name, str) else ''
    return safe if safe and safe not in ('.', '..') else 'default'


def set_instance_group(name):
    """Point every session read/write at this instance's own subtree. Called once at
    window startup, before any restore/save, so the whole module namespaces to it."""
    global _INSTANCE_GROUP
    _INSTANCE_GROUP = _safe_group(name)


def instance_group():
    """The sanitized instance group currently in effect (the state subtree name)."""
    return _INSTANCE_GROUP


def _instances_root():
    base = os.environ.get('XDG_STATE_HOME') or os.path.join(
        os.path.expanduser('~'), '.local', 'state')
    return os.path.join(base, 'secure-terminal')


def _state_dir():
    return os.path.join(_instances_root(), _INSTANCE_GROUP)


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
        for position, tab in enumerate(tabs):
            entry = {key: value for key, value in tab.items() if key != 'text'}
            # The app always supplies a valid uid (_session_tabs); fall back to the
            # list position for any other caller so save() keeps its "Never raises"
            # contract (a bare tab dict must not KeyError on quit).
            uid = tab.get('uid')
            uid = uid if _valid_uid(uid) else position
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
    seen: set[int] = set()
    for entry in index:
        if not isinstance(entry, dict):
            continue
        uid = entry.get('uid')
        # A VALID, not-yet-seen id keys this tab's log. Reject a bool (True==1 would
        # read tab-1.log) and a DUPLICATE id (two entries claiming one log would both
        # restore that one tab's scrollback -- a history-aliasing leak from a crafted
        # or corrupt session.json); such an entry restores empty and _restore_tab
        # assigns it a fresh id.
        if _valid_uid(uid) and uid not in seen:
            seen.add(uid)
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
            # No/invalid/bool/duplicate id (a pre-durable-id session.json, or a
            # crafted one): restore an empty tab; _restore_tab assigns a fresh id.
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


def remove_instance():
    """Remove this instance's whole state subtree (its session.json + every per-tab
    log/scratch file + the group dir). Used when an unnamed --new-instance closes: it
    is not restorable across a restart (a fresh id each launch), so leaving its subtree
    behind is pure orphan. Best-effort (ignore_errors swallows a partial tree); confined
    to this instance's own dir, so it can never touch another instance's files."""
    shutil.rmtree(_state_dir(), ignore_errors=True)


def gc_instances(max_age_days=30):
    """Backstop for CRASHED unnamed instances: remove throwaway (`new-<id>`) subtrees
    left behind (a clean close self-removes via remove_instance). Age-gated well beyond
    any plausible session so a still-running instance is never swept; named/default
    groups are NEVER touched. Best-effort; never raises."""
    cutoff = time.time() - max_age_days * 86400
    try:
        names = os.listdir(_instances_root())
    except OSError:
        return
    for name in names:
        if not name.startswith(_THROWAWAY_PREFIX):
            continue
        path = os.path.join(_instances_root(), name)
        try:
            if os.path.isdir(path) and os.path.getmtime(path) < cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:  # pragma: no cover - a TOCTOU race (dir vanished under us)
            pass


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
    uids: set[int] = set()
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
