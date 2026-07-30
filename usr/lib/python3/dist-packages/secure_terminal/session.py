#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Session persistence: the open tabs and their scrollback, so they survive a
restart or reboot.

Stored under the XDG state directory (~/.local/state/secure-terminal/). Each
tab's scrollback -- the bulky part -- lives in its own file, tab-0.log,
tab-1.log, ..., and a small session.json holds only the index: the tab order and
each tab's name/colour/settings. Splitting the logs out keeps the index tiny and
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

# A hard cap on the persisted scrollback of an "unlimited" tab, so a log file
# cannot grow without bound on disk even when no line limit is set.
UNLIMITED_PERSIST_LINES = 5000

# tab-<n>.log -- one scrollback file per tab, numbered by position.
_LOG_RE = re.compile(r'^tab-(\d+)\.log$')


def _state_dir():
    base = os.environ.get('XDG_STATE_HOME') or os.path.join(
        os.path.expanduser('~'), '.local', 'state')
    return os.path.join(base, 'secure-terminal')


def session_path():
    return os.path.join(_state_dir(), 'session.json')


def _log_path(index):
    return os.path.join(_state_dir(), 'tab-%d.log' % index)


def _log_indices():
    """Positions of the tab-<n>.log files currently on disk."""
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
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as handle:
        handle.write(text)
    os.replace(tmp, path)


def save(tabs, window=None, active=None):
    """Write the list of tab dicts: each tab's 'text' scrollback to its own
    tab-<n>.log, the rest as the index in session.json. `window` is an opaque
    base64 window-geometry blob (Qt saveGeometry, size + maximized state); `active`
    is the index of the focused tab, so the next start reopens it. Never raises."""
    path = session_path()
    try:
        os.makedirs(_state_dir(), exist_ok=True)
        index = []
        for position, tab in enumerate(tabs):
            entry = {key: value for key, value in tab.items() if key != 'text'}
            _write_atomic(_log_path(position), tab.get('text', ''))
            index.append(entry)
        # Drop log files left over from a previous, larger session.
        for stale in _log_indices():
            if stale >= len(tabs):
                _remove(_log_path(stale))
        payload = {'tabs': index}
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
    for position, entry in enumerate(index):
        if not isinstance(entry, dict):
            continue
        try:
            with open(_log_path(position), encoding='utf-8') as handle:
                entry['text'] = handle.read()
        except OSError:
            entry['text'] = ''  # a missing log just restores an empty tab
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
    for index in _log_indices():
        _remove(_log_path(index))
