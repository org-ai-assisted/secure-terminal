#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for secure_terminal.sanitize.render_output.

render_output() is the boundary that renders a program's raw output to the
widget. For any input, in every display mode, it must:
  - never raise;
  - never let a DANGEROUS code point (C0/C1 controls incl. ESC, DEL, bidi
    overrides, zero-width joiners, BOM, line/paragraph separators) survive;
  - in strip / reveal mode, emit ONLY the safe display alphabet
    (printable ASCII + the four honored editing controls);
  - be idempotent in strip mode (re-stripping stripped text is a no-op).
A failure here is a dangerous escape reaching the real terminal.

Run locally:
    python3 -m atheris fuzz/fuzz_render_output.py -max_total_time=300
"""

import sys

import atheris

with atheris.instrument_imports():
    from secure_terminal.sanitize import render_output, DISPLAY_MODES

_HONORED = {0x08, 0x09, 0x0A, 0x0D}
_SAFE = frozenset(_HONORED | set(range(0x20, 0x7F)))
_DANGEROUS = frozenset(
    [c for c in range(0x00, 0x20) if c not in _HONORED]
    + [0x7F]
    + list(range(0x80, 0xA0))
    + [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060, 0xFEFF]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A))
    + [0x2028, 0x2029])


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(2 ** 20)
    for mode in DISPLAY_MODES:
        out = render_output(text, mode)
        leaked = [ch for ch in out if ord(ch) in _DANGEROUS]
        if leaked:
            raise RuntimeError(
                "render_output leaked dangerous cp in mode {0}: input={1!r} "
                "leaked={2!r}".format(mode, text, leaked))
        if mode in ('strip', 'reveal'):
            unsafe = [ch for ch in out if ord(ch) not in _SAFE]
            if unsafe:
                raise RuntimeError(
                    "render_output left non-SAFE in mode {0}: input={1!r} "
                    "unsafe={2!r}".format(mode, text, unsafe))
    strip = render_output(text, 'strip')
    again = render_output(strip, 'strip')
    if strip != again:
        raise RuntimeError(
            "render_output strip not idempotent: input={0!r} once={1!r} "
            "twice={2!r}".format(text, strip, again))


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
