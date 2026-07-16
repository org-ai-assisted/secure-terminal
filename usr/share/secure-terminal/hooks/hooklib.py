## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Shared configuration loading for the example command hooks.

The AI prompt and the allow/block/ask command rules are CONFIGURATION, not code:
they live in files under the secure-terminal drop-in directories, so an admin (or
a user, if allowed) can edit them without touching the shipped handler. Files are
read in tier order, highest precedence last:

    /usr/lib/secure-terminal.d/<name>          built-in vendor default (lowest)
    /etc/secure-terminal.d/<name>              system administrator
    /usr/local/etc/secure-terminal.d/<name>    local administrator
    ~/.config/secure-terminal.d/<name>         user -- ONLY if an admin allows it

The user (home) tier is honored ONLY when a PRIVILEGED tier sets
`hook_config_allow_user=true` in hooks.conf (default no): the AI prompt and the
rules are security-relevant, so a user cannot weaken the judge unless the admin
opts in. The gate itself is read from the privileged tiers only, so home cannot
flip it. Self-contained (no secure_terminal import), so a hook stays copyable."""

import os

_APP = 'secure-terminal'
_PRIVILEGED = ('/usr/lib', '/etc', '/usr/local/etc')


def _tiers(allow_user):
    dirs = [os.path.join(base, _APP + '.d') for base in _PRIVILEGED]
    if allow_user:
        home = os.environ.get('XDG_CONFIG_HOME') \
            or os.path.join(os.path.expanduser('~'), '.config')
        dirs.append(os.path.join(home, _APP + '.d'))
    return dirs


def _privileged_conf_value(key):
    """Read a KEY=value from hooks.conf in the PRIVILEGED tiers only (highest tier
    wins). Never raises."""
    value = None
    for directory in _tiers(allow_user=False):
        try:
            with open(os.path.join(directory, 'hooks.conf'),
                      encoding='utf-8') as handle:
                for line in handle:
                    line = line.strip()
                    if line.startswith('#') or '=' not in line:
                        continue
                    name, _, raw = line.partition('=')
                    if name.strip() == key:
                        value = raw.strip()
        except OSError:
            pass
    return value


def allow_user_config():
    """Whether the home tier may override the hook config (admin opt-in)."""
    return _privileged_conf_value('hook_config_allow_user') == 'true'


def read_file(name):
    """Return the content of the highest-precedence <tier>/<name>, or None. The
    home tier is consulted only when an admin has allowed it. Never raises."""
    content = None
    for directory in _tiers(allow_user_config()):
        try:
            with open(os.path.join(directory, name), encoding='utf-8') as handle:
                content = handle.read()
        except OSError:
            pass
    return content


def read_rules(name):
    """Parse a rules file into a list of (verdict, pattern, message, suggestion).
    Lines are `verdict | regex | message | suggestion?` (pipe-separated); blank
    lines and #-comments are ignored. Returns None if the file is absent, so the
    caller keeps its built-in default."""
    text = read_file(name)
    if text is None:
        return None
    rules = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = [p.strip() for p in line.split('|')]
        if len(parts) < 2 or parts[0] not in ('allow', 'block', 'ask'):
            continue
        verdict, pattern = parts[0], parts[1]
        message = parts[2] if len(parts) > 2 else ''
        suggestion = parts[3] if len(parts) > 3 else ''
        rules.append((verdict, pattern, message, suggestion))
    return rules
