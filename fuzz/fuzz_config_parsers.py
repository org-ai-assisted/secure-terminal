#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for the drop-in settings + session-index parsers.

settings._parse_into() reads a KEY=value .conf drop-in, and session.load() reads
the JSON tab index -- both parse untrusted on-disk content that a hostile or
corrupt file could carry, and both must NEVER raise and must yield a well-typed
result (a str->str dict; a list of tab dicts). A crash here would brick startup.

Run locally:
    python3 -m atheris fuzz/fuzz_config_parsers.py -max_total_time=300
"""

import os
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    from secure_terminal import settings as SET
    from secure_terminal import session as SESS

_STATE_DIR = tempfile.mkdtemp(prefix='st-fuzz-cfg-')
SESS._state_dir = lambda: _STATE_DIR
_CONF = os.path.join(_STATE_DIR, 'x.conf')
_SESSION = os.path.join(_STATE_DIR, 'session.json')


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # settings: arbitrary .conf text -> a str->str dict, never raises
    with open(_CONF, 'w', encoding='utf-8', errors='surrogatepass') as handle:
        handle.write(fdp.ConsumeUnicodeNoSurrogates(4096))
    out = {}
    SET._parse_into(_CONF, out)
    for key, value in out.items():
        if not (isinstance(key, str) and isinstance(value, str)):
            raise RuntimeError("settings parsed a non-str entry: {0!r}={1!r}"
                               .format(key, value))

    # session: arbitrary bytes in session.json -> a list, never raises
    with open(_SESSION, 'wb') as handle:
        handle.write(fdp.ConsumeBytes(4096))
    tabs = SESS.load()
    if not isinstance(tabs, list):
        raise RuntimeError("session.load did not return a list: {0!r}".format(tabs))
    for tab in tabs:
        if not isinstance(tab, dict):
            raise RuntimeError("session.load tab is not a dict: {0!r}".format(tab))


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
