#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
unicode-tag: byte-faithful Unicode neutralizer for MACHINE (LLM) consumption.

Unlike the terminal display path (cli.py / render_output, which mark EVERY
non-ASCII byte because a terminal cannot know intent), this passes honest text
-- ASCII, accented Latin, CJK, emoji, whole-script foreign words -- through
UNCHANGED, and replaces only the code points that DECEIVE a reader:

  * bidi controls (reorder the surrounding text),
  * C0/C1/DEL controls incl. CARRIAGE RETURN and ESC (overwrite / escape tricks),
  * invisible / zero-width / BOM / separators (hide content),
  * cross-script homoglyphs POSING AS ASCII, scoped to a mixed-script token so a
    legitimate foreign word is never touched.

Each deception becomes an inline, self-describing `[U+XXXX NAME]` token AT its
position, so the true byte order is preserved and the hazard is unmissable with
no sidecar to parse. Square brackets (not the display path's <U+XXXX> badge) so
the marker cannot be mistaken for markup.

Reuses the classifier in `secure_terminal.sanitize` and the mixed-script data in
`confusable_homoglyphs` -- no duplicated Unicode logic. It operates on the code
point STREAM, not lines, so there is no end-of-file concept and thus no "missing
newline" notice; `\\n` and `\\t` pass verbatim and the trailing newline is kept
exactly as the input had it.

What it does NOT claim: an all-ASCII look-alike (`rnicrosoft`, `paypa1`) carries
no cross-script signal, so no tool can flag it -- that residue is inherent to
readable Latin, not a gap here. Stacked combining marks (Zalgo) pass through as
honest, visible code points (they neither hide, reorder, nor execute).
"""

import sys
import unicodedata

# python3-regex: Unicode-aware \\w for the homoglyph-scope token split (stdlib
# re's \\w is ASCII-narrow under the default flags); the sanitize core takes the
# same hard dependency.
import regex

from secure_terminal.sanitize import marking_class

# confusable_homoglyphs (a hard dependency, also used by sanitize) decides at the
# TOKEN level whether a word mixes scripts / poses as ASCII -- the scoping that
# keeps 'cafe', CJK and whole-script Greek/Cyrillic untouched.
from confusable_homoglyphs.confusables import is_dangerous

# C0 / DEL controls have no unicodedata.name; the Unicode name aliases keep a tag
# readable as `[U+001B ESCAPE]` rather than a bare code point.
_C0_NAMES = {
    0x00: 'NULL', 0x01: 'START OF HEADING', 0x02: 'START OF TEXT',
    0x03: 'END OF TEXT', 0x04: 'END OF TRANSMISSION', 0x05: 'ENQUIRY',
    0x06: 'ACKNOWLEDGE', 0x07: 'BELL', 0x08: 'BACKSPACE',
    0x09: 'CHARACTER TABULATION', 0x0A: 'LINE FEED', 0x0B: 'LINE TABULATION',
    0x0C: 'FORM FEED', 0x0D: 'CARRIAGE RETURN', 0x0E: 'SHIFT OUT',
    0x0F: 'SHIFT IN', 0x10: 'DATA LINK ESCAPE', 0x11: 'DEVICE CONTROL ONE',
    0x12: 'DEVICE CONTROL TWO', 0x13: 'DEVICE CONTROL THREE',
    0x14: 'DEVICE CONTROL FOUR', 0x15: 'NEGATIVE ACKNOWLEDGE',
    0x16: 'SYNCHRONOUS IDLE', 0x17: 'END OF TRANSMISSION BLOCK',
    0x18: 'CANCEL', 0x19: 'END OF MEDIUM', 0x1A: 'SUBSTITUTE',
    0x1B: 'ESCAPE', 0x1C: 'INFORMATION SEPARATOR FOUR',
    0x1D: 'INFORMATION SEPARATOR THREE', 0x1E: 'INFORMATION SEPARATOR TWO',
    0x1F: 'INFORMATION SEPARATOR ONE', 0x7F: 'DELETE',
}

# The deception classes marking_class names that are NEVER legitimate in text and
# so are always tagged. 'confusable' is handled separately (token-scoped);
# 'combining' and 'nonascii' are honest code points and pass through.
_ALWAYS_TAG = frozenset(('bidi', 'control', 'invisible'))

_WORD = regex.compile(r'\w+')


def _name(cp):
    try:
        return unicodedata.name(chr(cp))
    except ValueError:
        if cp in _C0_NAMES:
            return _C0_NAMES[cp]
        if 0x80 <= cp <= 0x9F:
            return 'C1 CONTROL'
        return 'UNNAMED'


def _tag(cp):
    return '[U+%04X %s]' % (cp, _name(cp))


def _confusable_positions(text):
    """Character indices to tag as homoglyphs. Only code points inside a token
    that mixes scripts / poses as ASCII (is_dangerous) qualify, so an honest
    foreign word stays untouched and an all-ASCII look-alike -- which no
    cross-script check can catch -- is left as-is."""
    marked = set()
    for match in _WORD.finditer(text):
        token = match.group()
        if not any(ord(ch) > 0x7F for ch in token):
            continue                       # pure-ASCII token cannot be mixed-script
        try:
            dangerous = bool(is_dangerous(token))
        except Exception:                  # pylint: disable=broad-except
            dangerous = False              # data hiccup: skip the refinement, never crash
        if not dangerous:
            continue
        for offset, ch in enumerate(token):
            if marking_class(ord(ch)) == 'confusable':
                marked.add(match.start() + offset)
    return marked


def tag_text(text):
    """Return text with every deceptive code point replaced by an inline
    `[U+XXXX NAME]` token; everything else is byte-for-byte identical."""
    confusable = _confusable_positions(text)
    out = []
    for index, ch in enumerate(text):
        cp = ord(ch)
        if 0xDC80 <= cp <= 0xDCFF:         # surrogateescape: a raw undecodable byte
            out.append('[INVALID-BYTE 0x%02X]' % (cp & 0xFF))
        elif ch in ('\n', '\t') or 0x20 <= cp <= 0x7E:
            out.append(ch)                 # allowlisted whitespace / printable ASCII
        elif marking_class(cp) in _ALWAYS_TAG:
            out.append(_tag(cp))           # never-legitimate active deception
        elif index in confusable:
            out.append(_tag(cp))           # homoglyph inside a mixed-script token
        else:
            out.append(ch)                 # honest foreign / combining / scoped-out
    return ''.join(out)


def tag_bytes(data):
    """Decode UTF-8 with surrogateescape so an undecodable byte survives as
    U+DCxx and is tagged rather than silently dropped (an encoding trick cannot
    hide a byte), then tag."""
    return tag_text(data.decode('utf-8', 'surrogateescape'))


def _write_tagged(data):
    # Shared emit path for both entry points. tag_text removed every surrogate,
    # so the UTF-8 re-encode cannot raise; only a downstream pipe closing early
    # (e.g. `... | head`) can, and that exits 1 without a traceback.
    try:
        sys.stdout.buffer.write(tag_bytes(data).encode('utf-8'))
    except BrokenPipeError:
        return 1
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        if argv:
            chunks = []
            for path in argv:
                with open(path, 'rb') as handle:
                    chunks.append(handle.read())
            data = b''.join(chunks)
        else:
            data = sys.stdin.buffer.read()
    except OSError as exc:
        # An unreadable file: report cleanly and exit non-zero, no traceback.
        sys.stderr.write('unicode-tag: %s\n' % exc)
        return 1
    return _write_tagged(data)


def main_stdin(argv=None):
    # Stdin-only entry point: reads NO files, so a confining AppArmor profile can
    # deny all data-file access. argv is accepted and ignored for a uniform
    # signature. Drives the AppArmor-confined `unicode-tag-stdin` (the hook path).
    return _write_tagged(sys.stdin.buffer.read())
