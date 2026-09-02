#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Drop-in settings, the systemd .d way.

Settings are KEY=value plain text spread over *.conf files in drop-in
directories, so a distro or an admin can seed defaults and the user can override
them:

    /usr/lib/secure-terminal.d/*.conf          (built-in vendor defaults, lowest)
    /etc/secure-terminal.d/*.conf              (distro / system administrator)
    /usr/local/etc/secure-terminal.d/*.conf    (local administrator)
    ~/.config/secure-terminal.d/*.conf         (user, highest)

Only files ending in .conf are read. Within each directory files are applied in
lexical order of filename (so 10-*.conf before 90-*.conf), and the directories
are applied lowest to highest, so a later KEY overrides an earlier one and the
user always wins over a system seed. The application writes its own settings to a
mid-numbered user file (50_user.conf): it beats the system seeds, and a user can
still drop a higher-numbered .conf to override even the app's own choices.

Hardening / corporate lockdown: a PRIVILEGED directory (/usr/lib, /etc,
/usr/local/etc) may declare `lock=key1,key2,...`. A locked key is enforced from the system layer
and the user config CANNOT override it -- such an attempt is ignored and reported
in Config.violations, and the application greys out the matching control. `lock`
is honored only from the privileged directories; a user config can neither lock
nor unlock. load() returns a Config (a dict plus .locked and .violations).

Loading is fully defensive: a missing/unreadable file, a malformed line or an
unknown key never raises and never crashes; the value falls back to its default.
Only these drop-in .conf files are read -- there is no legacy single-file config.
"""

import os
import glob
import fcntl

_APP = 'secure-terminal'
# where the app writes its own settings. 50 leaves room for a user to drop a
# higher-numbered .conf that overrides even the app's choices.
_USER_FILE = '50_user.conf'

# Keys that are ALWAYS privileged: honored only from a system directory, never
# from the user's home config (even without an explicit `lock=`). remote_control
# is the injection surface, so only an admin may enable it.
PRIVILEGED_ONLY = frozenset({'remote_control'})


def _user_config_dir():
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(
        os.path.expanduser('~'), '.config')
    return os.path.join(base, _APP + '.d')


def _system_dirs():
    """The PRIVILEGED drop-in directories (root-writable), lowest precedence first:

        /usr/lib/secure-terminal.d   built-in vendor defaults (the shipped package)
        /etc/secure-terminal.d       distro / system administrator
        /usr/local/etc/secure-terminal.d  local administrator

    Any of them may LOCK a key so the unprivileged user config cannot override it
    (corporate / hardened deployments). Vendor defaults live in /usr/lib so a user
    or admin overrides them in a higher tier without editing a packaged file.

    These paths are fixed: a locked key can be set ONLY from a root-writable
    privileged directory, so it cannot be overridden without root. There is no env
    relocation hook (that would let an unprivileged user re-point the trusted layer
    and bypass a lock); a test exercises the lock path by monkeypatching this
    function in-process, which ships nothing."""
    return [
        os.path.join('/usr/lib', _APP + '.d'),
        os.path.join('/etc', _APP + '.d'),
        os.path.join('/usr/local/etc', _APP + '.d'),
    ]


def config_dirs():
    """The drop-in search directories, lowest precedence first."""
    return _system_dirs() + [_user_config_dir()]


def user_config_file():
    """The file the application writes its own settings to."""
    return os.path.join(_user_config_dir(), _USER_FILE)


def config_path():
    """Backward-compatible alias: the file the app writes to."""
    return user_config_file()


def _parse_lines(lines, out):
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, _, value = line.partition('=')
        key = key.strip()
        if key:
            out[key] = value.strip()


def _parse_into(path, out):
    # Parse into a temp then merge on FULL success: text is decoded in buffers, so a
    # bad byte after the first ~8 KiB would otherwise leave the lines already read
    # applied -- a partial drop-in, not the documented "ignored".
    parsed: dict[str, str] = {}
    try:
        with open(path, encoding='utf-8') as handle:
            _parse_lines(handle, parsed)
    except (OSError, ValueError):
        return                  # missing / unreadable / non-UTF-8 drop-in -> ignored
    out.update(parsed)


def _read_user_base():
    """Parse the user file as the base for a REWRITE (set_user_key / update_user).
    Returns the dict, or None if the file EXISTS but cannot be read as UTF-8 -- the
    caller then SKIPS the write instead of clobbering unreadable keys: a lossy
    re-parse of a corrupt file (a single bad byte yields no keys) followed by a
    rewrite would delete every other setting. A missing file is an empty base (the
    write creates it). Never raises."""
    out: dict[str, str] = {}
    try:
        with open(user_config_file(), encoding='utf-8') as handle:
            _parse_lines(handle, out)
    except FileNotFoundError:
        return out              # no file yet -> empty base, the write creates it
    except (OSError, ValueError):
        return None             # unreadable / non-UTF-8 -> do NOT clobber
    return out


def _load_dir(directory):
    """Merge every *.conf in one directory (lexical order) into a fresh dict."""
    out: dict[str, str] = {}
    try:
        files = sorted(glob.glob(os.path.join(directory, '*.conf')))
    except OSError:
        files = []
    for path in files:
        _parse_into(path, out)
    return out


class Config(dict):
    """The merged settings, plus which keys an admin has LOCKED (a user drop-in
    cannot override these) and which user overrides were ignored because of a
    lock. It is a plain dict for reads (.get()); the extra state drives the UI."""

    def __init__(self, values, locked=(), violations=()):
        super().__init__(values)
        self.locked = frozenset(locked)
        self.violations = tuple(violations)

    def is_locked(self, key):
        return key in self.locked


def load():
    """Merge the drop-ins into a Config. The two PRIVILEGED directories are applied
    first and may declare `lock=key1,key2,...` to lock keys; the user directory is
    applied last and wins for every key EXCEPT a locked one -- a user attempt to
    set a locked key is ignored and recorded in .violations. `lock` itself is only
    honored from the privileged directories (a user cannot lock or unlock). Never
    raises."""
    system = {}
    locked = set(PRIVILEGED_ONLY)          # always admin-only, no lock= needed
    for directory in _system_dirs():
        layer = _load_dir(directory)
        for key in layer.pop('lock', '').replace(',', ' ').split():
            locked.add(key)
        system.update(layer)
    user = _load_dir(_user_config_dir())
    user.pop('lock', None)                 # locking is privileged-only
    merged = dict(system)
    violations = []
    for key, value in user.items():
        if key in locked:
            violations.append(key)         # override an admin lock -> ignored
            continue
        merged[key] = value
    return Config(merged, locked, sorted(set(violations)))


def save(values, locked=()):
    """Write the application's settings to the user drop-in file. Locked keys are
    NOT written -- the user cannot control them, so persisting them would be dead,
    ignored config. Never raises."""
    locked = frozenset(locked)
    path = user_config_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines = [
            '## secure-terminal settings, written by the application.',
            '## One KEY=value per line. Additional .conf drop-ins in',
            '## /usr/lib, /etc and /usr/local/etc secure-terminal.d and this',
            '## directory are also read, in lexical then directory order.',
            '## Admin-locked keys (via `lock=` in a system directory) are not',
            '## written here; they cannot be overridden from your home config.',
        ]
        for key in sorted(values):
            if key in locked:
                continue
            lines.append('%s=%s' % (key, values[key]))
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
        os.replace(tmp, path)
    except OSError:
        pass                    # a settings write is best-effort, never fatal


def _user_write_lock():
    """Acquire an exclusive advisory lock (flock) on a sidecar of the user file,
    serializing the read-modify-write in set_user_key / update_user across the
    terminal and the SEPARATE clipboard-watch daemon (both write clip_warn_any) so
    a concurrent single-key write is not lost. Returns an open fd -- hold it across
    the read+save, close it to release -- or None if the lock cannot be taken
    (best-effort: the write still proceeds, just unserialized). Never raises."""
    path = user_config_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        handle = os.open(path + '.lock', os.O_CREAT | os.O_RDWR, 0o600)
    except OSError:
        return None
    try:
        fcntl.flock(handle, fcntl.LOCK_EX)
    except OSError:
        os.close(handle)        # flock failed (e.g. EOPNOTSUPP on NFS) -> no fd leak
        return None
    return handle


def set_user_key(key, value):
    """Set ONE key in the app's OWN user config file, preserving the other keys it
    already holds. Reads only that file, never the merged system/admin config, so it
    cannot pin a system/admin value into user config (which would then outrank a
    later admin change). An admin-locked key is dropped by save (never written). The
    read-modify-write is serialized against the other writer (_user_write_lock); a
    non-UTF-8 user file is left untouched (never clobbered). Never raises."""
    cfg = load()
    handle = _user_write_lock()
    try:
        current = _read_user_base()
        if current is None:
            return              # unreadable base -> skip rather than clobber
        current[key] = value
        save(current, locked=cfg.locked)
    finally:
        if handle is not None:
            os.close(handle)


def update_user(values, locked=()):
    """Merge-preserving multi-key update of the app's OWN user file: set each key in
    `values`, keeping the other keys the file already holds -- e.g. a key ANOTHER
    process persisted via set_user_key (clip_warn_any, from the clipboard-watch
    tray) must not be clobbered by a bulk write here. `locked` (the caller's STARTUP
    snapshot) is UNIONed with the CURRENT load() locks, so a key locked at launch OR
    now is never written back as a user override -- neither a lock removed nor a lock
    added while the app is open can pin a stale value. The read-modify-write is
    serialized against the other writer (_user_write_lock); a non-UTF-8 user file is
    left untouched (never clobbered). Never raises."""
    all_locked = load().locked | frozenset(locked or ())   # tolerate None: never raises
    handle = _user_write_lock()
    try:
        current = _read_user_base()
        if current is None:
            return              # unreadable base -> skip rather than clobber
        current.update(values)
        save(current, locked=all_locked)
    finally:
        if handle is not None:
            os.close(handle)
