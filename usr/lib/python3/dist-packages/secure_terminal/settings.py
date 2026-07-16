## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Drop-in settings, the systemd .d way.

Settings are KEY=value plain text spread over *.conf files in drop-in
directories, so a distro or an admin can seed defaults and the user can override
them:

    /etc/secure-terminal.d/*.conf              (distro / system seed, lowest)
    /usr/local/etc/secure-terminal.d/*.conf    (local admin)
    ~/.config/secure-terminal.d/*.conf         (user, highest)

Only files ending in .conf are read. Within each directory files are applied in
lexical order of filename (so 10-*.conf before 90-*.conf), and the directories
are applied lowest to highest, so a later KEY overrides an earlier one and the
user always wins over a system seed. The application writes its own settings to a
mid-numbered user file (50_user.conf): it beats the system seeds, and a user can
still drop a higher-numbered .conf to override even the app's own choices.

Hardening / corporate lockdown: a PRIVILEGED directory (/etc, /usr/local/etc)
may declare `lock=key1,key2,...`. A locked key is enforced from the system layer
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
    """The PRIVILEGED drop-in directories (root-writable), lowest first. Settings
    here can LOCK a key so the unprivileged user config cannot override it -- for
    corporate / hardened deployments."""
    return [
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


def _parse_into(path, out):
    try:
        with open(path, encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                if key:
                    out[key] = value.strip()
    except OSError:
        pass                    # missing/unreadable drop-in -> ignored


def _load_dir(directory):
    """Merge every *.conf in one directory (lexical order) into a fresh dict."""
    out = {}
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
            '## /etc/secure-terminal.d, /usr/local/etc/secure-terminal.d and',
            '## this directory are also read, in lexical then directory order.',
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
