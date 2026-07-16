## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Pure, Qt-free sanitization core for secure-terminal.

Everything here is a plain function on strings/bytes with no GUI dependency, so
it runs identically under the terminal widget and under a bare Python test
(dist-ai), the way output-lies keeps its analyzer DOM-free. It decides what is
safe to display and names the class of anything that is not; the widget layer
(terminal.py) adds only the interactive cursor handling and, optionally, colour.
"""

import os
import re
import unicodedata

# two-letter Unicode general categories -> a readable name, so the reveal-badge
# tooltip can say "Currency Symbol" rather than only "Sc".
_CATEGORY_NAMES = {
    'Cc': 'Control', 'Cf': 'Format', 'Co': 'Private Use', 'Cs': 'Surrogate',
    'Cn': 'Unassigned',
    'Ll': 'Lowercase Letter', 'Lm': 'Modifier Letter', 'Lo': 'Other Letter',
    'Lt': 'Titlecase Letter', 'Lu': 'Uppercase Letter',
    'Mc': 'Spacing Mark', 'Me': 'Enclosing Mark', 'Mn': 'Nonspacing Mark',
    'Nd': 'Decimal Number', 'Nl': 'Letter Number', 'No': 'Other Number',
    'Pc': 'Connector Punctuation', 'Pd': 'Dash Punctuation',
    'Pe': 'Close Punctuation', 'Pf': 'Final Punctuation',
    'Pi': 'Initial Punctuation', 'Po': 'Other Punctuation',
    'Ps': 'Open Punctuation', 'Sc': 'Currency Symbol', 'Sk': 'Modifier Symbol',
    'Sm': 'Math Symbol', 'So': 'Other Symbol', 'Zl': 'Line Separator',
    'Zp': 'Paragraph Separator', 'Zs': 'Space Separator',
}


def describe_codepoint(cp):
    """Human description of a Unicode code point for the reveal-badge tooltip:
    its name, general category (long and short) and the \\u escape -- the same
    detail `unicode-show` prints, because "<U+20AC>" alone means nothing to most
    people. Pure, so it is unit-tested; the widget only positions the popup."""
    if not isinstance(cp, int) or cp < 0 or cp > 0x10FFFF:
        return 'U+???? (not a code point)'
    ch = chr(cp)
    try:
        name = unicodedata.name(ch)
    except ValueError:
        name = 'unnamed code point'
    cat = unicodedata.category(ch)
    cat_long = _CATEGORY_NAMES.get(cat, cat)
    esc = '\\u%04x' % cp if cp <= 0xFFFF else '\\U%08x' % cp
    return 'U+%04X  %s\n%s (%s)   %s' % (cp, name, cat_long, cat, esc)

# name -> (background, foreground). "dark" is white-on-black, "light" is the
# reverse; both are plain, high-contrast, no syntax coloring.
THEMES = {
    'dark':  ('#14161b', '#e6e6e6'),
    'light': ('#ffffff', '#1a1a1a'),
}
BASE_POINT_SIZE = 11

# Standard 16-colour ANSI palette (xterm-ish); indexes 0-7 normal, 8-15 bright.
ANSI_PALETTE = [
    '#000000', '#cd0000', '#00cd00', '#cdcd00',
    '#0000ee', '#cd00cd', '#00cdcd', '#e5e5e5',
    '#7f7f7f', '#ff0000', '#00ff00', '#ffff00',
    '#5c5cff', '#ff00ff', '#00ffff', '#ffffff',
]

# How non-ASCII / unsafe content in program OUTPUT is shown:
#   'strip'  -- replace with '_' (default, safe), as sanitize-string/stcat do.
#   'show'   -- render a non-ASCII character as its glyph when it is printable
#               (str.isprintable() excludes the invisible, bidi and format
#               characters that make unicode deceptive), so a log with useful
#               unicode is readable; control still becomes '_'.
#   'reveal' -- replace with a visible <U+XXXX> codepoint badge, to inspect.
DISPLAY_MODES = ('strip', 'show', 'reveal')

# CSI (ESC [ ...), OSC (ESC ] ... BEL/ST) and other two-byte escapes.
ANSI_RE = re.compile(
    # CSI: ESC [ , parameter bytes 0x30-0x3F (0-9 : ; < = > ?), intermediate
    # bytes 0x20-0x2F, a final byte 0x40-0x7E. The parameter class must span the
    # whole 0x30-0x3F range, or a private-prefix sequence a capable-TERM program
    # emits (e.g. modifyOtherKeys "\x1b[>4;2m", "\x1b[?25l") is left unstripped.
    r'\x1b\[[0-?]*[ -/]*[@-~]'
    r'|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?'
    r'|\x1b[@-Z\\-_]'
)

# SGR: ESC [ <params> m -- the only escape sequence honored, and only when
# colours are enabled. Everything else is still stripped.
SGR_RE = re.compile(r'\x1b\[([0-9;]*)m')


def colors_allowed():
    """False only when NO_COLOR is set (per no-color.org: presence, any value),
    a legitimate user-wide opt-out. Colours are opt-in per tab anyway. The
    terminal's OWN launch TERM is deliberately NOT consulted: it renders to a
    screen, not to its parent, so being started from a dumb context -- e.g. from
    another terminal running in line mode -- must not silently disable the
    Colors toggle (that was a real "why don't my ls/zsh colours show" bug)."""
    return not os.environ.get('NO_COLOR')


def luminance(color):
    """Perceptual-ish luminance of an (r, g, b) tuple, 0..255."""
    r, g, b = color
    return 0.299 * r + 0.587 * g + 0.114 * b


def too_close(a, b):
    """True when two (r, g, b) colours are so close that text would be near-
    invisible -- the guard that stops a program painting black-on-black. Kept low
    so ordinary colours (e.g. red on a near-black background) are still allowed;
    it only catches genuinely unreadable, deceptive combinations."""
    return abs(luminance(a) - luminance(b)) < 30


def render_output(text, mode='strip'):
    """Turn decoded child output into safe display text under one display mode.
    Escape sequences are always removed (there is no ANSI parser). Printable
    ASCII, tab and newline, and the two interactive cursor controls backspace
    (0x08) and carriage return (0x0D) always pass through -- the widget honors the
    latter two as line-local edits. Everything else is handled per `mode`
    (see DISPLAY_MODES)."""
    text = ANSI_RE.sub('', text)
    out = []
    for ch in text:
        cp = ord(ch)
        if cp in (0x08, 0x09, 0x0A, 0x0D) or 0x20 <= cp <= 0x7E:
            out.append(ch)
        elif mode == 'reveal':
            out.append('<U+%04X>' % cp)
        elif mode == 'show' and cp >= 0x80 and ch.isprintable():
            out.append(ch)
        else:
            out.append('_')
    return ''.join(out)


# The alternate-screen enable sequences (private DEC modes). A program that
# switches to the alternate screen buffer is a full-screen (TUI) app -- htop,
# vim, less -- which line mode, having no escape parser, cannot draw. Detecting
# this lets the widget hint that TUI mode is needed, rather than showing garbage.
_ALT_SCREEN = ('\x1b[?1049h', '\x1b[?1047h', '\x1b[?47h')
_ALT_SCREEN_OFF = ('\x1b[?1049l', '\x1b[?1047l', '\x1b[?47l')


def wants_full_screen(text):
    """True when the output tries to switch to the alternate screen buffer, the
    tell of a full-screen (TUI) program that cannot render in line mode."""
    return any(seq in text for seq in _ALT_SCREEN)


def leaves_full_screen(text):
    """True when the output leaves the alternate screen buffer -- the full-screen
    program (htop, vim) has exited and the shell's primary screen is back."""
    return any(seq in text for seq in _ALT_SCREEN_OFF)


def sanitize_bytes(data, mode='strip'):
    """Convenience wrapper: decode raw bytes 1:1 (latin-1) and render. Used by
    tests and any all-ASCII path; the live output stream uses an incremental
    UTF-8 decoder so multi-byte characters survive read boundaries."""
    return render_output(data.decode('latin-1'), mode)


def apply_line_edits(line, col, text, max_line=0):
    r"""Resolve the interactive line-editing controls the shell's line editor
    emits, against one logical line held as a Python string with a cursor column.
    Pure and O(len(text)), so a flood of control-laden bytes ("cat /dev/random")
    never reaches the per-character QTextCursor path that crawls.

    Backspace (0x08) moves the cursor one cell left; a bare carriage return
    (0x0D) moves it to column 0; a printable character OVERWRITES the cell under
    the cursor (a terminal never inserts-and-shifts) or appends at end of line;
    '\n' ends the line. `line`/`col` are the current incomplete line and cursor
    column carried across writes. Returns (completed_lines, line, col): the lines
    finished by a newline plus the new current line and column. max_line (> 0)
    hard-wraps an over-long line into its own completed line, so a flood with no
    newline cannot build one unbounded block. CRLF must already be collapsed."""
    completed = []
    buf = list(line)
    for ch in text:
        if ch == '\n':
            completed.append(''.join(buf))
            buf = []
            col = 0
        elif ch == '\r':
            col = 0
        elif ch == '\x08':
            if col > 0:
                col -= 1
        else:
            if col < len(buf):
                buf[col] = ch
            else:
                buf.append(ch)
            col += 1
            if max_line and len(buf) >= max_line:
                completed.append(''.join(buf))
                buf = []
                col = 0
    return completed, ''.join(buf), col


def sanitize_paste(text):
    """Strip a pasted string to printable ASCII; newlines become carriage
    returns (what the shell expects for a submitted line)."""
    out = []
    for ch in text:
        cp = ord(ch)
        if ch == '\n' or ch == '\r':
            out.append('\r')
        elif ch == '\t' or 0x20 <= cp <= 0x7E:
            out.append(ch)
        # everything else (invisible, bidi, homoglyph, control) is dropped
    return ''.join(out)


def sanitize_paste_unicode(text):
    """Like sanitize_paste but KEEP printable non-ASCII (the euro sign, accents,
    CJK) instead of dropping it, for a deliberate "paste with unicode". The
    deceptive and injection classes are still removed: control characters, bidi
    overrides, zero-width and other invisibles are all non-printable, so
    str.isprintable() excludes them, and a paste can never smuggle a hidden
    newline or an escape sequence this way either. Newlines still become the
    carriage return the shell expects for a submitted line."""
    out = []
    for ch in text:
        if ch == '\n' or ch == '\r':
            out.append('\r')
        elif ch == '\t' or ch.isprintable():
            out.append(ch)
        # control, bidi, zero-width, other invisibles -> dropped
    return ''.join(out)


def sanitize_title(text, limit=80):
    """Reduce a program-supplied window title or notification to safe plain
    ASCII: keep only printable ASCII (so no control, escape, bidi or homoglyph
    can ride in through a title), collapse whitespace to single spaces, cap the
    length."""
    kept = []
    for ch in (text or ''):
        if 0x20 <= ord(ch) <= 0x7E:
            kept.append(ch)
        elif ch in '\t\n\r\f\v':
            kept.append(' ')          # keep word boundaries, drop the control
    return ' '.join(''.join(kept).split())[:limit]


def _cell_cp_safe(cp, mode):
    # Only 'show' renders a non-ASCII glyph in a TUI cell. 'reveal' cannot: a
    # <U+XXXX> badge is many columns wide and would break the fixed grid, so
    # reveal falls back to the safe '_' here (same as strip). This keeps the
    # display honest -- a homoglyph never renders as its glyph under the green
    # "reveal is safe/lossless" lamp; to read the exact codepoint, use line mode.
    if 0x20 <= cp <= 0x7E:
        return True
    return mode == 'show' and cp >= 0x80


def tui_cell(ch, mode):
    """Sanitize one screen cell for TUI-mode display. A pyte cell can hold more
    than one codepoint (a base character plus combining marks form one grapheme,
    one column), so this accepts a string of any length -- never assume length 1.
    The whole grapheme is kept only when every codepoint is safe: printable ASCII,
    or, in 'show'/'reveal', printable non-ASCII (str.isprintable() excludes the
    invisible, bidi and format classes). Otherwise the cell becomes '_'. The
    result is a single display unit, so the grid and the neutralization hold."""
    if not ch:
        return ' '
    if all(_cell_cp_safe(ord(c), mode) and c.isprintable() for c in ch):
        return ch
    return '_'


def paste_findings(text):
    """Classify a to-be-pasted string as (has_unicode, has_control), so a paste
    of anything but plain ASCII + tab/newline can be flagged before it is sent to
    the shell."""
    has_unicode = has_control = False
    for ch in text:
        cp = ord(ch)
        if ch in ('\n', '\r', '\t') or 0x20 <= cp <= 0x7E:
            continue
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            has_control = True
        else:
            has_unicode = True
    return has_unicode, has_control


def classify_paste(text):
    """Name and count the classes of non-plain-ASCII characters in a paste, so a
    warning can say exactly what is hidden in it ("2 bidirectional controls, 1
    invisible character") instead of a bare "contains unicode" -- the user has a
    right to know what a copied string really carries. Returns an ordered list of
    (label, count) for the classes present, most alarming first; label is a
    singular noun the caller pluralizes."""
    counts = {}
    for ch in text:
        cp = ord(ch)
        if ch in ('\n', '\r', '\t') or 0x20 <= cp <= 0x7E:
            continue
        if cp in (0x200E, 0x200F) or 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
            key = 'bidirectional control'
        elif cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            key = 'control character'
        elif not ch.isprintable():
            key = 'invisible character'
        else:
            key = 'non-ASCII character'   # homoglyphs and other printable non-ASCII
        counts[key] = counts.get(key, 0) + 1
    order = ('bidirectional control', 'control character',
             'invisible character', 'non-ASCII character')
    return [(label, counts[label]) for label in order if label in counts]


def parse_sgr(param_str, state):
    """Fold one SGR parameter string into `state` -- a dict with keys 'fg', 'bg'
    (palette index or None) and 'bold' (bool). Pure so the colour logic can be
    tested without Qt; terminal.py turns the resulting state into a format."""
    nums = [int(p) if p.isdigit() else 0
            for p in (param_str.split(';') if param_str else ['0'])]
    i = 0
    while i < len(nums):
        n = nums[i]
        if n == 0:
            state['fg'] = state['bg'] = None
            state['bold'] = False
        elif n == 1:
            state['bold'] = True
        elif n == 22:
            state['bold'] = False
        elif 30 <= n <= 37:
            state['fg'] = n - 30
        elif 90 <= n <= 97:
            state['fg'] = n - 90 + 8
        elif n == 39:
            state['fg'] = None
        elif 40 <= n <= 47:
            state['bg'] = n - 40
        elif 100 <= n <= 107:
            state['bg'] = n - 100 + 8
        elif n == 49:
            state['bg'] = None
        elif n in (38, 48):
            # 8-bit (5;n) and 24-bit (2;r;g;b): consume the extra parameters and
            # fall back to the default (not part of the safe set).
            if i + 1 < len(nums) and nums[i + 1] == 5:
                i += 2
            elif i + 1 < len(nums) and nums[i + 1] == 2:
                i += 4
        i += 1
    return state
