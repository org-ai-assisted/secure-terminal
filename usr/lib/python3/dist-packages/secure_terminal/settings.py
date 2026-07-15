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
high-numbered user file (99-user.conf) so its changes override the seeds.

Loading is fully defensive: a missing/unreadable file, a malformed line or an
unknown key never raises and never crashes; the value falls back to its default.
"""

import os
import glob

_APP = 'secure-terminal'
_USER_FILE = '99-user.conf'       # where the app writes; sorts last -> wins


def _user_config_dir():
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(
        os.path.expanduser('~'), '.config')
    return os.path.join(base, _APP + '.d')


def config_dirs():
    """The drop-in search directories, lowest precedence first."""
    return [
        os.path.join('/etc', _APP + '.d'),
        os.path.join('/usr/local/etc', _APP + '.d'),
        _user_config_dir(),
    ]


def user_config_file():
    """The file the application writes its own settings to."""
    return os.path.join(_user_config_dir(), _USER_FILE)


def _legacy_config_file():
    # the pre-drop-in single file, still read for backward compatibility
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(
        os.path.expanduser('~'), '.config')
    return os.path.join(base, _APP, 'config')


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


def load():
    """Merge every *.conf drop-in into a dict of str -> str. Never raises."""
    out = {}
    # legacy single file first, so a user drop-in or the app file overrides it
    _parse_into(_legacy_config_file(), out)
    for directory in config_dirs():        # lowest -> highest precedence
        try:
            files = sorted(glob.glob(os.path.join(directory, '*.conf')))
        except OSError:
            files = []
        for path in files:                 # lexical order within the dir
            _parse_into(path, out)
    return out


def save(values):
    """Write the application's settings to the user drop-in file. Never raises."""
    path = user_config_file()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines = [
            '## secure-terminal settings, written by the application.',
            '## One KEY=value per line. Additional .conf drop-ins in',
            '## /etc/secure-terminal.d, /usr/local/etc/secure-terminal.d and',
            '## this directory are also read, in lexical then directory order.',
        ]
        for key in sorted(values):
            lines.append('%s=%s' % (key, values[key]))
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
        os.replace(tmp, path)
    except OSError:
        pass                    # a settings write is best-effort, never fatal
