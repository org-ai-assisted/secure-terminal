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
  - render (via cells_to_runs) to only the safe alphabet in box mode.
The resulting state, fed again, must still not raise. This is the editor whose
mishandling once froze the GUI on `cat /dev/random`.

Run locally:
    python3 -m atheris fuzz/fuzz_feed_line_edits.py -max_total_time=300
"""

import sys

import atheris

with atheris.instrument_imports():
    from secure_terminal.sanitize import (feed_line_edits, cells_to_runs,
                                          cells_display_col, BOX)

_HONORED = {0x08, 0x09, 0x0A, 0x0D}
_SAFE = frozenset(_HONORED | set(range(0x20, 0x7F)))


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    max_line = fdp.ConsumeIntInRange(0, 256)   # 0 = unbounded; >0 = width bound
    # Both settings share every invariant below: with line editing off the CSI ops
    # are consumed but inert (append-only), which must not weaken any of them.
    line_edits = bool(fdp.ConsumeIntInRange(0, 1))
    text = fdp.ConsumeUnicodeNoSurrogates(2 ** 18)

    comp, cells, col, sgr, _wraps = feed_line_edits([], 0, {}, text, max_line,
                                                    line_edits)
    if not 0 <= col <= len(cells):
        raise RuntimeError(
            "feed_line_edits cursor {0} out of [0,{1}]: input={2!r}".format(
                col, len(cells), text))
    if max_line and (col > max_line or len(cells) > max_line):
        raise RuntimeError(
            "feed_line_edits exceeded width {0}: col={1} len={2} input={3!r}".format(
                max_line, col, len(cells), text))
    for ch, _key in cells:
        if ch == '\x1b':
            raise RuntimeError(
                "ESC smuggled into a cell: input={0!r}".format(text))

    runs, prefix = cells_to_runs(comp, cells, 'box', False)
    if not (isinstance(prefix, int) and prefix >= 0):
        raise RuntimeError(
            "cells_to_runs bad prefix {0!r}: input={1!r}".format(prefix, text))
    for run_text, _key in runs:
        # BOX (U+25A1) is cells_to_runs' intentional box-mode placeholder for a
        # neutralized cell (the widget maps it back to '_' on export) -- safe by
        # design, so allow it alongside the ASCII set.
        if not all(ord(ch) in _SAFE or ch in ('\n', BOX) for ch in run_text):
            raise RuntimeError(
                "cells_to_runs box run not safe: input={0!r} run={1!r}".format(
                    text, run_text))

    if cells_display_col(cells, col, 'box') < 0:
        raise RuntimeError(
            "cells_display_col negative: input={0!r}".format(text))

    ## Feeding the resulting state again must not raise.
    feed_line_edits(cells, col, sgr, text, max_line, line_edits)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
