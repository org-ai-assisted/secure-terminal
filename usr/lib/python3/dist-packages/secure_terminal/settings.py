## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Plain-text settings, stored under the XDG config directory.

The format is deliberately dumb: one KEY=value per line, so it is trivial to
read and hand-edit and there is no parser to attack. Loading is defensive --
a missing file, an unreadable file, a bad line or an unknown key never raises
and never crashes the terminal; the value simply falls back to the default.
"""

import os

_APP = 'secure-terminal'


def config_path():
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(
        os.path.expanduser('~'), '.config')
    return os.path.join(base, _APP, 'config')


def load():
    """Return the settings as a dict of str -> str. Never raises."""
    out = {}
    try:
        with open(config_path(), encoding='utf-8') as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                key, _, value = line.partition('=')
                key = key.strip()
                if key:
                    out[key] = value.strip()
    except OSError:
        pass
    return out


def save(values):
    """Write the settings dict as KEY=value lines. Never raises."""
    path = config_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines = ['## secure-terminal settings -- one KEY=value per line, '
                 'edit freely.']
        for key in sorted(values):
            lines.append('%s=%s' % (key, values[key]))
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')
        os.replace(tmp, path)
    except OSError:
        pass
