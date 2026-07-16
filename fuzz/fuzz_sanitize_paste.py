#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for the clipboard/title sanitizers.

Pasted text and program-set titles are attacker-controlled. For any input:
  - sanitize_paste keeps ONLY printable ASCII plus tab and carriage return;
  - sanitize_paste_unicode keeps printable code points (incl. non-ASCII) plus
    the two submit controls, but NO invisible/deceptive one (control, bidi,
    zero-width) that could inject or spoof;
  - sanitize_title is bounded plain ASCII with no newline or tab;
  - all three are idempotent (re-sanitizing sanitized text is a no-op).
None may raise.

Run locally:
    python3 -m atheris fuzz/fuzz_sanitize_paste.py -max_total_time=300
"""

import sys

import atheris

with atheris.instrument_imports():
    from secure_terminal.sanitize import (sanitize_paste,
                                          sanitize_paste_unicode,
                                          sanitize_title)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(2 ** 20)

    pa = sanitize_paste(text)
    if not all(ch in ('\t', '\r') or 0x20 <= ord(ch) <= 0x7E for ch in pa):
        raise RuntimeError(
            "sanitize_paste leaked: input={0!r} out={1!r}".format(text, pa))
    if sanitize_paste(pa) != pa:
        raise RuntimeError(
            "sanitize_paste not idempotent: input={0!r}".format(text))

    pu = sanitize_paste_unicode(text)
    if not all(ch in ('\r', '\t') or ch.isprintable() for ch in pu):
        raise RuntimeError(
            "sanitize_paste_unicode leaked: input={0!r} out={1!r}".format(
                text, pu))
    if sanitize_paste_unicode(pu) != pu:
        raise RuntimeError(
            "sanitize_paste_unicode not idempotent: input={0!r}".format(text))

    ti = sanitize_title(text)
    if len(ti) > 80 or not all(0x20 <= ord(ch) <= 0x7E for ch in ti) \
            or '\n' in ti or '\t' in ti:
        raise RuntimeError(
            "sanitize_title leaked: input={0!r} out={1!r}".format(text, ti))
    if sanitize_title(ti) != ti:
        raise RuntimeError(
            "sanitize_title not idempotent: input={0!r}".format(text))


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
