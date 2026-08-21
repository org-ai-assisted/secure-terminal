#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
sclip: sanitize clipboard-bound text to safe characters, on stdin/stdout.

A pure filter -- no display, no Qt, no clipboard access -- so it composes with
the system clipboard tools and confines tightly under AppArmor (the same design
as unicode-tag-stdin):

    wl-paste | sclip | wl-copy               # Wayland, ASCII-strict
    xclip -o | sclip --unicode | xclip -i    # X11, keep printable unicode

The st-wl-paste / st-wl-copy / st-xclip drop-ins wrap those pipelines so a user
need not remember them.

Default is the STRICTEST strip (sanitize_clipboard): printable ASCII plus tab
and newline, so a homoglyph cannot ride out either. --unicode keeps printable
non-ASCII (accents, CJK) via sanitize_clipboard_unicode. Note the honest limit:
a homoglyph IS printable unicode, so --unicode does NOT de-confusable -- it only
removes the invisible / bidi / control / zero-width classes; the review GUI is
where a human judges look-alikes. All Unicode logic is reused from the Qt-free
core in secure_terminal.sanitize; none is duplicated here.
"""

import sys

from secure_terminal.sanitize import (
    classify_paste, sanitize_clipboard, sanitize_clipboard_unicode,
)

_USAGE = (
    'usage: sclip [--unicode] [--summary]\n'
    '  Filter stdin to clipboard-safe text on stdout.\n'
    '  --unicode  keep printable non-ASCII (default: ASCII-only, strictest)\n'
    '  --summary  write a one-line report of what was removed to stderr\n'
)


def _summary_line(text, keep_unicode):
    """A one-line, MODE-ACCURATE report for --summary. In --unicode mode printable
    non-ASCII is KEPT, so it is reported as kept (with the look-alike caveat), never
    as removed -- the summary must not claim a strip it did not do."""
    removed = []
    kept_nonascii = 0
    for label, count in classify_paste(text):
        if keep_unicode and label == 'non-ASCII character':
            kept_nonascii = count
        else:
            removed.append((label, count))
    if not removed and not kept_nonascii:
        return 'sclip: nothing removed\n'
    parts = []
    if removed:
        named = ', '.join('%d %s%s' % (n, label, '' if n == 1 else 's')
                          for label, n in removed)
        parts.append('removed ' + named)
    if kept_nonascii:
        parts.append('kept %d non-ASCII character%s (printable, may include '
                     'look-alikes)' % (kept_nonascii,
                                        '' if kept_nonascii == 1 else 's'))
    return 'sclip: %s\n' % '; '.join(parts)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    keep_unicode = False
    summary = False
    for arg in argv:
        if arg == '--unicode':
            keep_unicode = True
        elif arg == '--summary':
            summary = True
        elif arg in ('-h', '--help'):
            sys.stdout.write(_USAGE)
            return 0
        else:
            sys.stderr.write('sclip: unknown option: %s\n%s' % (arg, _USAGE))
            return 2
    try:
        data = sys.stdin.buffer.read()
    except OSError as exc:
        # e.g. stdin is a directory (`sclip < /etc`): report cleanly, no traceback.
        sys.stderr.write('sclip: %s\n' % exc)
        return 1
    # surrogateescape so an undecodable byte cannot crash the filter; it is not
    # printable ASCII nor str.isprintable(), so both sanitizers drop it either way.
    text = data.decode('utf-8', 'surrogateescape')
    if summary:
        sys.stderr.write(_summary_line(text, keep_unicode))
    clean = (sanitize_clipboard_unicode if keep_unicode
             else sanitize_clipboard)(text)
    try:
        sys.stdout.buffer.write(clean.encode('utf-8'))
    except BrokenPipeError:
        # a downstream pipe closed early (e.g. `... | head`): exit 1, no traceback.
        return 1
    return 0
