#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for the line-mode logical-cell editor.

feed_line_edits() replays a program's output into a logical line model that
honors \\r, \\b and line-local CSI ops while bounding the cursor to the current
line. On any input it must:
  - never raise;
  - never smuggle a raw ESC into a cell (an escape in a cell is an escape that
    reaches the widget);
  - keep the logical cursor within the current line;
  - render (via cells_to_runs) to only the safe alphabet in strip mode.
The resulting state, fed again, must still not raise. This is the editor whose
mishandling once froze the GUI on `cat /dev/random`.

Run locally:
    python3 -m atheris fuzz/fuzz_feed_line_edits.py -max_total_time=300
"""

import sys

import atheris

with atheris.instrument_imports():
    from secure_terminal.sanitize import (feed_line_edits, cells_to_runs,
                                          cells_display_col)

_HONORED = {0x08, 0x09, 0x0A, 0x0D}
_SAFE = frozenset(_HONORED | set(range(0x20, 0x7F)))


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(2 ** 18)

    comp, cells, col, sgr = feed_line_edits([], 0, {}, text)
    if not 0 <= col <= len(cells):
        raise RuntimeError(
            "feed_line_edits cursor {0} out of [0,{1}]: input={2!r}".format(
                col, len(cells), text))
    for ch, _key in cells:
        if ch == '\x1b':
            raise RuntimeError(
                "ESC smuggled into a cell: input={0!r}".format(text))

    runs, prefix = cells_to_runs(comp, cells, 'strip', False)
    if not (isinstance(prefix, int) and prefix >= 0):
        raise RuntimeError(
            "cells_to_runs bad prefix {0!r}: input={1!r}".format(prefix, text))
    for run_text, _key in runs:
        if not all(ord(ch) in _SAFE or ch == '\n' for ch in run_text):
            raise RuntimeError(
                "cells_to_runs strip run not safe: input={0!r} run={1!r}".format(
                    text, run_text))

    if cells_display_col(cells, col, 'strip') < 0:
        raise RuntimeError(
            "cells_display_col negative: input={0!r}".format(text))

    ## Feeding the resulting state again must not raise.
    feed_line_edits(cells, col, sgr, text)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
