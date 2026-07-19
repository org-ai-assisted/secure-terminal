#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for the safe-colour SGR parser.

parse_sgr() folds a program's `ESC[...m` parameters into a colour/bold state,
and color_256() maps a 256-colour index to a palette index or '#rrggbb'. For any
parameters they must never raise and a stored colour must be ONE of: None, a
0..15 palette index, or a valid '#rrggbb' -- never a raw or out-of-range value a
later renderer could mishandle. The parameters are drawn from a small grammar
(basic / bright / 256 / truecolour, plus junk) so every colour branch is reached.

Run locally:
    python3 -m atheris fuzz/fuzz_parse_sgr.py -max_total_time=300
"""

import re
import sys

import atheris

with atheris.instrument_imports():
    from secure_terminal.sanitize import parse_sgr, color_256

_HEX = re.compile(r'#[0-9a-f]{6}')


def _ok_colour(chan):
    return (chan is None
            or (isinstance(chan, int) and 0 <= chan <= 15)
            or (isinstance(chan, str) and _HEX.fullmatch(chan) is not None))


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    atoms = []
    for _ in range(fdp.ConsumeIntInRange(0, 8)):
        kind = fdp.ConsumeIntInRange(0, 4)
        if kind == 0:
            atoms.append(str(fdp.ConsumeIntInRange(0, 130)))       # basic/bright/reset
        elif kind == 1:
            atoms.append('38;5;%d' % fdp.ConsumeIntInRange(0, 300))  # 256 fg (+ OOR)
        elif kind == 2:
            atoms.append('48;5;%d' % fdp.ConsumeIntInRange(0, 300))  # 256 bg
        elif kind == 3:
            atoms.append('38;2;%d;%d;%d' % (fdp.ConsumeIntInRange(0, 300),
                                            fdp.ConsumeIntInRange(0, 300),
                                            fdp.ConsumeIntInRange(0, 300)))  # truecolour
        else:
            atoms.append(fdp.ConsumeUnicodeNoSurrogates(6))         # arbitrary junk
    param = ';'.join(atoms)
    state = {'fg': None, 'bg': None, 'bold': False}
    parse_sgr(param, state)
    for chan in (state['fg'], state['bg']):
        if not _ok_colour(chan):
            raise RuntimeError(
                "parse_sgr stored a bad colour {0!r}: params={1!r}".format(chan, param))
    if not isinstance(state['bold'], bool):
        raise RuntimeError("parse_sgr bold not a bool: params={0!r}".format(param))

    c = color_256(fdp.ConsumeIntInRange(-16, 300))
    if not _ok_colour(c):
        raise RuntimeError("color_256 returned a bad value: {0!r}".format(c))


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
