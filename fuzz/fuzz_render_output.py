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
import unicodedata

import atheris

with atheris.instrument_imports():
    from secure_terminal.sanitize import (
        render_output, is_default_ignorable, DISPLAY_MODES)

_HONORED = {0x08, 0x09, 0x0A, 0x0D}
_SAFE = frozenset(_HONORED | set(range(0x20, 0x7F)))
# DERIVED from the Unicode general categories, never enumerated -- the same
# derivation as test_corpus.py and fuzz_secure_terminal.py. An enumerated ORACLE
# cannot report its own holes: a member nobody listed weakens the leak check below
# instead of failing it, which is why this copy went on missing U+061C,
# U+2061..2064 and U+180E. Cc control, Cf format (bidi controls, zero-widths,
# invisible math operators, BOM, soft hyphen), Zl/Zp separators -- plus the
# default-ignorables, printable to str.isprintable() yet rendering as nothing.
_DANGEROUS_CATEGORIES = frozenset(('Cc', 'Cf', 'Zl', 'Zp'))
_DANGEROUS = frozenset(
    cp for cp in range(0x110000)
    if cp not in _HONORED
    and (unicodedata.category(chr(cp)) in _DANGEROUS_CATEGORIES
         or is_default_ignorable(chr(cp))))
# Canary: the default-ignorable arm borrows a PRODUCT predicate, so gutting it
# would shrink this oracle silently. Fail at import, before any fuzz iteration.
for _cp in (0x00, 0x1B, 0x7F, 0x9B, 0x061C, 0x180E, 0x200B, 0x200D, 0x200E,
            0x202E, 0x2066, 0x2028, 0x2029, 0xFEFF, 0x2061, 0x2062, 0x2063,
            0x2064, 0xFE0F, 0x3164, 0x115F, 0x034F):
    assert _cp in _DANGEROUS, '_DANGEROUS lost U+%04X' % _cp
assert not (_DANGEROUS & _SAFE), '_SAFE and _DANGEROUS must be disjoint'


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
        if mode in ('box', 'reveal'):
            unsafe = [ch for ch in out if ord(ch) not in _SAFE]
            if unsafe:
                raise RuntimeError(
                    "render_output left non-SAFE in mode {0}: input={1!r} "
                    "unsafe={2!r}".format(mode, text, unsafe))
    strip = render_output(text, 'box')
    again = render_output(strip, 'box')
    if strip != again:
        raise RuntimeError(
            "render_output strip not idempotent: input={0!r} once={1!r} "
            "twice={2!r}".format(text, strip, again))


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
