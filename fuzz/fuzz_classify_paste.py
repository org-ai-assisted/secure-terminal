#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for the paste classifiers + the title sanitizer.

classify_paste() / paste_findings() describe why a paste is risky (bidi, control,
invisible, non-ASCII), and sanitize_title() reduces a hostile OSC title to safe
plain ASCII. For any text they must never raise and must uphold their contracts:
  - classify_paste -> a list of (label:str, count:int>0);
  - paste_findings -> a 2-tuple of bools;
  - sanitize_title -> printable ASCII only, <= 80 chars, no newline/tab, and
    idempotent (re-sanitizing a sanitized title is a no-op).

Run locally:
    python3 -m atheris fuzz/fuzz_classify_paste.py -max_total_time=300
"""

import sys

import atheris

with atheris.instrument_imports():
    from secure_terminal.sanitize import (classify_paste, paste_findings,
                                          sanitize_title)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(2 ** 16)

    findings = classify_paste(text)
    if not isinstance(findings, list):
        raise RuntimeError("classify_paste not a list: input={0!r}".format(text))
    for item in findings:
        if not (isinstance(item, tuple) and len(item) == 2
                and isinstance(item[0], str) and isinstance(item[1], int)
                and item[1] > 0):
            raise RuntimeError(
                "classify_paste bad item {0!r}: input={1!r}".format(item, text))

    flags = paste_findings(text)
    if not (isinstance(flags, tuple) and len(flags) == 2
            and all(isinstance(f, bool) for f in flags)):
        raise RuntimeError("paste_findings bad shape {0!r}: input={1!r}"
                           .format(flags, text))

    title = sanitize_title(text)
    if len(title) > 80:
        raise RuntimeError("sanitize_title too long: input={0!r}".format(text))
    if any(not (0x20 <= ord(ch) <= 0x7E) for ch in title):
        raise RuntimeError("sanitize_title not printable ASCII: input={0!r}"
                           .format(text))
    if '\n' in title or '\t' in title:
        raise RuntimeError("sanitize_title kept newline/tab: input={0!r}"
                           .format(text))
    if sanitize_title(title) != title:
        raise RuntimeError("sanitize_title not idempotent: input={0!r}"
                           .format(text))


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
