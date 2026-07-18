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
#   'detail' -- like reveal but verbose: <U+XXXX NAME>, the codepoint plus its
#               official Unicode name inline (what `unicode-show` annotates), so
#               a homoglyph reads as its identity, not just a number.
DISPLAY_MODES = ('strip', 'show', 'reveal', 'detail')


def _detail_badge(cp):
    """A verbose reveal badge: <U+XXXX NAME>, all printable ASCII (Unicode names
    are ASCII), so it is safe in every display and never re-enables an escape."""
    try:
        name = unicodedata.name(chr(cp))
    except (ValueError, TypeError):
        name = 'UNNAMED'
    return '<U+%04X %s>' % (cp, name)

# CSI (ESC [ ...), OSC (ESC ] ... BEL/ST), the DCS/SOS/PM/APC string sequences
# (ESC P/X/^/_ ... ST) and other two-byte escapes.
ANSI_RE = re.compile(
    # CSI: ESC [ , parameter bytes 0x30-0x3F (0-9 : ; < = > ?), intermediate
    # bytes 0x20-0x2F, a final byte 0x40-0x7E. The parameter class must span the
    # whole 0x30-0x3F range, or a private-prefix sequence a capable-TERM program
    # emits (e.g. modifyOtherKeys "\x1b[>4;2m", "\x1b[?25l") is left unstripped.
    r'\x1b\[[0-?]*[ -/]*[@-~]'
    r'|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?'
    # DCS (ESC P), SOS (ESC X), PM (ESC ^), APC (ESC _): a string sequence whose
    # BODY runs to an ST (ESC \) terminator. Unlike OSC, BEL does NOT terminate
    # these -- a BEL byte is part of the (often binary) body -- so the body is
    # "anything but ESC" up to the ST. Consume the whole body: matching only the
    # two-byte opener (the generic arm below) would leak the body as text, so a
    # cat'd DECRQSS/XTGETTCAP/Sixel/APC payload ("\x1bP$qm\x1b\\") would show "$qm".
    r'|\x1b[PX^_][^\x1b]*(?:\x1b\\)?'
    r'|\x1b[@-Z\\-_]'
)

# SGR: ESC [ <params> m -- the only escape sequence honored, and only when
# colours are enabled. Everything else is still stripped.
SGR_RE = re.compile(r'\x1b\[([0-9;]*)m')

# An escape sequence can be split across two os.read() chunks. The line renderer
# is stateless per chunk, so a split OSC/CSI would leak its TAIL as literal text:
# a long OSC title (which a shell sets on every prompt) is the usual victim -- its
# head is stripped, then the next chunk's remainder ("...] (cd ~) [pts/11]\x07")
# renders as text, BEL and all. This matches an INCOMPLETE escape at end-of-text
# so the caller can hold it back and prepend it to the next chunk.
_TRAILING_ESCAPE = re.compile(
    r'\x1b(?:'
    r'\][^\x07\x1b]*'        # OSC: ESC ] ... still awaiting its BEL or ST
    r'|[PX^_][^\x1b]*'       # DCS/SOS/PM/APC: ESC P/X/^/_ ... awaiting ST (BEL is body)
    r'|\[[0-?]*[ -/]*'       # CSI: ESC [ params/intermediates, no final byte yet
    r'|[ -/]*'               # ESC + intermediate bytes, awaiting a final (charsets)
    r')?$'
)


def has_bell(text):
    """True if `text` contains a standalone BEL (0x07) -- a program ringing the
    bell -- as opposed to a BEL that merely terminates an OSC sequence (a shell
    ends a title with one). ANSI_RE removes the OSC/escape matches, so only a
    standalone BEL survives."""
    return '\x07' in ANSI_RE.sub('', text)


def split_trailing_escape(text, cap=4096):
    """Split off an INCOMPLETE escape sequence at the end of `text`, if any, so a
    caller feeding one read()-chunk at a time can carry it to the next chunk rather
    than leak its tail. Returns (complete_text, carry). A carry longer than `cap`
    is NOT held (a genuine split sequence is short; an unterminated flood -- or a
    program that simply never terminates its OSC -- is let through, bounded)."""
    m = _TRAILING_ESCAPE.search(text)
    if m and m.group() and len(m.group()) <= cap:
        return text[:m.start()], m.group()
    return text, ''


# A string sequence -- OSC (ESC ]), DCS (ESC P), SOS (ESC X), PM (ESC ^), APC
# (ESC _) -- can be arbitrarily long (a Sixel image is a large DCS) and can split
# across read() chunks. Holding an unbounded carry would let hostile output
# balloon memory; but simply DROPPING an over-cap carry leaks the sequence's
# continuation (the later chunks carry no introducer) as visible text. So once an
# incomplete string sequence outgrows the carry cap we switch to a DISCARD state:
# subsequent bytes are swallowed until the terminator, then rendering resumes.
# This keeps "strip every escape" true for a sequence of ANY length in O(1) memory.
_STRING_INTRO = ']PX^_'                 # 2nd byte of ESC-<x> string introducers
_STRING_TERMINATOR = {
    ']': re.compile(r'\x07|\x1b\\'),    # OSC ends on BEL or ST
    'P': re.compile(r'\x1b\\'),         # DCS ends on ST only (BEL is body)
    'X': re.compile(r'\x1b\\'),         # SOS
    '^': re.compile(r'\x1b\\'),         # PM
    '_': re.compile(r'\x1b\\'),         # APC
}


def feed_chunk_carry(text, carry, drop, cap=4096):
    """CLI-mode incremental escape handling across read() chunks. Given the new
    `text`, the short `carry` held from the previous chunk (str), and `drop` (the
    introducer byte of an over-long string sequence being discarded, or ''),
    return (renderable_text, new_carry, new_drop). Guarantees every escape --
    including an arbitrarily long, chunk-split string sequence -- is fully removed
    with O(1) memory: an incomplete string sequence past `cap` switches to a
    discard state that swallows bytes until its terminator (handling a terminator
    itself split across the boundary via a one-byte ESC carry)."""
    text = carry + text
    carry = ''
    if drop:
        m = _STRING_TERMINATOR[drop].search(text)
        if not m:
            # still inside the sequence; a lone trailing ESC may be a split ST
            return '', ('\x1b' if text.endswith('\x1b') else ''), drop
        text = text[m.end():]
        drop = ''
    m = _TRAILING_ESCAPE.search(text)
    if m and m.group():
        g = m.group()
        if len(g) >= 2 and g[1] in _STRING_INTRO and len(g) > cap:
            drop = g[1]                 # too long to hold -> swallow to terminator
            text = text[:m.start()]
        elif len(g) <= cap:
            carry = g                   # short incomplete escape -> hold for next chunk
            text = text[:m.start()]
        # else: an over-cap NON-string tail (a pathological unterminated CSI, which
        # a real program never emits) is let through, bounded -- as before.
    return text, carry, drop


# --- OSC features -------------------------------------------------------------
# Every OSC (Operating System Command) capability a program may try. Each is
# NEUTRALIZED by default (secure by construction) and can be individually enabled
# at the user's own risk. This registry is the single source of truth for the
# config keys, the settings/menu UI, the security lamp and the layman
# attack-surface hints, so the list never drifts across those places.
#
# Fields: key, label, codes (human), default (always False = neutralized),
# risk ('low' | 'medium' | 'high'; drives the security lamp), hint (laymen).
#
# The hints describe the risk from UNTRUSTED OUTPUT: bytes you did not author
# reaching the terminal (a file you view, a program's output, a server banner)
# can carry these escapes, so a passive action like viewing a log triggers the
# side-effect. This is NOT about a program you deliberately run -- secure-terminal
# does not sandbox programs; see the threat-model note in the security lamp.
OSC_FEATURES = (
    ('osc_title', 'Window / tab title', '0, 2', False, 'medium',
     'Untrusted output can rename the window or tab; a spoofed title can mislead '
     'you, and a "report title" query can put text onto your input line.'),
    ('osc_notify', 'Desktop notifications', '9', False, 'medium',
     'Untrusted output can raise a desktop notification whose text is faked '
     '(for example a bogus "your session expired" prompt).'),
    ('osc_hyperlink', 'Hyperlinks', '8', False, 'medium',
     'Untrusted output can present a link whose visible text differs from where '
     'it really points (phishing). When enabled, the true target is surfaced next '
     'to the text so you can see where a link really goes.'),
    ('osc_clipboard', 'System clipboard', '52', False, 'high',
     'Untrusted output could silently overwrite your system clipboard, so a later '
     'paste inserts text you did not copy, or read your clipboard back to itself. '
     'The most dangerous terminal escape.'),
    ('osc_colors', 'Palette / colours', '4, 10, 11, 12', False, 'medium',
     'Untrusted output can change the terminal colours -- for example paint text '
     'the same colour as the background to hide it, or leave your palette altered '
     'after it exits.'),
    ('osc_cwd', 'Working-directory report', '7', False, 'low',
     'Untrusted output can set the tab\'s reported directory. Minor: it discloses '
     'a path and some shells act on it.'),
    ('osc_color_query', 'Colour query reply', '10, 11, 4', False, 'medium',
     'Lets programs read the terminal\'s own background / foreground colour '
     '(editors use it to match a dark or light theme). This is the one case the '
     'terminal writes a reply back, so to stay safe it answers ONLY while a '
     'full-screen program is running -- never at a shell prompt, where a reply '
     'could be injected as input -- and only the non-secret colour.'),
    ('osc_iterm2', 'iTerm2 extensions', '1337', False, 'high',
     'Untrusted output could use iTerm2 proprietary escapes (file upload / '
     'download, set variables) -- a very large surface.'),
)

# key -> (label, codes, default, risk, hint), for quick lookup.
OSC_FEATURE_BY_KEY = {f[0]: f[1:] for f in OSC_FEATURES}


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
        elif mode == 'detail':
            out.append(_detail_badge(cp))
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


# Line-LOCAL cursor/erase escapes the shell's line editor emits, honored in line
# mode so the display tracks the real command buffer (readline/zle redraw with
# these under a capable TERM). ONLY these, and only within the current line:
#   CSI n C  cursor forward      CSI n D  cursor back
#   CSI n G  cursor to column n   CSI n K  erase in line (0 EOL, 1 BOL, 2 all)
# Vertical/absolute movement (A/B/H/d/...) is NOT honored -- those are stripped,
# so a program can never reach another line or the scrollback. The worst these
# allow is redrawing the CURRENT line, exactly like the \r/\b already honored.
_LINE_CSI_RE = re.compile(r'\x1b\[([0-9]*)([CDGK])')
_SGR_ONLY_RE = re.compile(r'\x1b\[([0-9;]*)m')


def feed_line_edits(cells, col, sgr, raw, max_line=0):
    """Advance the current line's LOGICAL cell buffer by one raw output chunk.

    A cell is (source_char, sgr_state) -- one SOURCE character, whatever its later
    display width (a reveal <U+XXXX> badge is one cell but eight columns), so the
    shell's cursor/erase ops act on characters, not on the rendering. This is what
    makes backspacing over a badge delete the whole badge. Pure and testable.

    Honors \r, \b, \n and the line-local CSI ops (see _LINE_CSI_RE); folds SGR into
    `sgr` (so colour survives a redraw); strips every other escape and treats a
    stray control byte as an overwrite cell (rendered '_' later). Returns
    (completed, cells, col, sgr, wraps): cell-lists finished by a newline or an
    autowrap, plus the new current buffer, cursor column, SGR state, and a bool
    per completed line -- True where the line ended by a soft autowrap (so the
    widget can join the wrapped rows on copy). max_line (>0) autowraps."""
    completed = []
    wraps = []                            # parallel to completed: True == autowrap
    cells = list(cells)
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == '\x1b':
            m = _LINE_CSI_RE.match(raw, i)
            if m:
                num = int(m.group(1)) if m.group(1) else None
                op = m.group(2)
                if op == 'C':
                    # cursor forward: like a real VT, moving past end-of-line
                    # leaves BLANKS in the gap (a right-prompt jumps here, e.g.
                    # "\x1b[43C[pts/N]"). Pad up to the target column, bounded by
                    # the width, instead of collapsing the gap onto the last cell.
                    col = col + (num or 1)
                    col = min(col, max_line - 1) if max_line else min(col, len(cells))
                    while len(cells) < col:
                        cells.append((' ', tuple(sorted(sgr.items()))))
                elif op == 'D':
                    col = max(0, col - (num or 1))
                elif op == 'G':
                    col = max(0, (num or 1) - 1)          # absolute column (1-based)
                    col = min(col, max_line - 1) if max_line else min(col, len(cells))
                    while len(cells) < col:
                        cells.append((' ', tuple(sorted(sgr.items()))))
                else:                                   # K: erase in line
                    if num in (None, 0):
                        del cells[col:]                 # cursor -> end of line
                    elif num == 1:
                        for j in range(0, min(col + 1, len(cells))):
                            cells[j] = (' ', cells[j][1])
                    elif num == 2:
                        cells = []
                        col = 0
                # A cursor/erase op clears the pending autowrap (the implicit
                # col == max_line "phantom" past the last column), so a following
                # printable overwrites the last cell instead of wrapping a row.
                if max_line and col >= max_line:
                    col = max_line - 1
                i = m.end()
                continue
            m = _SGR_ONLY_RE.match(raw, i)
            if m:
                sgr = dict(sgr)
                parse_sgr(m.group(1), sgr)
                i = m.end()
                continue
            m = ANSI_RE.match(raw, i)
            if m:                                       # any other escape: strip
                i = m.end()
                continue
            i += 1                                      # lone/unknown ESC: drop
            continue
        if ch == '\n':
            completed.append(cells)
            wraps.append(False)                     # a real line break, not a wrap
            cells, col = [], 0
        elif ch == '\r':
            col = 0
        elif ch == '\x08':
            if col > 0:
                col -= 1
        else:
            # DEFERRED autowrap (VT "last column" behaviour): filling the last
            # column leaves the cursor there; the NEXT printable char wraps to a
            # fresh row. A \r or backspace before it moves off the margin and
            # cancels the pending wrap, so width-sized output + a \n or \r is not
            # split with a spurious blank line.
            if max_line and col >= max_line:
                completed.append(cells)
                wraps.append(True)                  # a soft autowrap continuation
                cells, col = [], 0
            state = tuple(sorted(sgr.items()))
            if col < len(cells):
                cells[col] = (ch, state)
            else:
                cells.append((ch, state))
            col += 1
        i += 1
    return completed, cells, col, sgr, wraps


# Risk class of a neutralized/revealed character, so its marking (the '_' or the
# <U+XXXX> badge) can be coloured by WHY the character is dangerous, not just that
# it is. Ordered worst-first.
def marking_class(cp):
    if (0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069
            or cp in (0x200E, 0x200F, 0x061C)):
        return 'bidi'                 # reorders text -- the worst deception
    if (cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF)
            or 0x2028 <= cp <= 0x2029):
        return 'invisible'            # zero-width / BOM / line-paragraph separator
    if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
        return 'control'              # C0 / DEL / C1 control bytes
    return 'nonascii'                 # any other non-ASCII (homoglyph-prone)


# sentinel head of a run key that colours a marking by its risk class, kept
# distinct from an SGR-state key (a sorted-items tuple) or None.
MARK_KEY = '\x00mark'

# sentinel key for a newline that is a SOFT autowrap (the line filled the width),
# not a real line break -- the widget marks the following block a continuation so
# copy joins the wrapped rows, like a real terminal. A completed cell-line of
# exactly `wrap` cells is a wrap: a \n-ended line always has fewer, because
# reaching `wrap` cells wraps before any later \n.
WRAP_NL = '\x00wrap'

# Beyond this many runs, stop per-character marking colour so a flood of
# alternating safe/marking characters re-coalesces into a few plain runs instead
# of one Qt insert per character -- preserving the flood-coalescing guard. A
# screenful of alternating chars is far below this, so real display is unaffected.
_RUN_CAP = 2000


def cells_to_runs(lines, current, mode, colors, markings=True, wraps=None):
    r"""Render finished cell-lines plus the current cell-line to a coalesced list
    of (display_text, sgr_key) runs, with '\n' between the finished lines and
    before the current one. Each cell's char is rendered via render_output (so the
    escape-stripping / mode rules still hold); adjacent cells of the same SGR key
    (or all of them when colours are off) are merged into one run, so an uncolored
    flood is one insert, not one per character. Returns (runs, prefix_len) where
    prefix_len is the display-character offset at which the current line begins,
    for placing the caret."""
    runs = []                             # list of [ [text_parts], sgr_key ]

    def add(disp, key):
        if runs and runs[-1][1] == key:
            runs[-1][0].append(disp)
        else:
            runs.append([[disp], key])

    def emit(ch, key):
        disp = render_output(ch, mode)
        # a neutralized/revealed char (its display differs from the source) is a
        # "marking": tag it with a COLOUR SOURCE -- its risk class when colored
        # markings are on; otherwise the program's own SGR key, so allowed ANSI
        # colour is still honoured (None only when colours are off too) -- and
        # ALWAYS with its source CODEPOINT, so the widget can describe the real
        # character on hover/click in every mode (even the strip "_", which keeps
        # no other trace). Past _RUN_CAP runs (a flood) stop tagging so the runs
        # re-coalesce and the UI cannot wedge; distinct codepoints no longer merge,
        # but the cap still bounds it.
        if disp != ch and len(runs) < _RUN_CAP:
            if markings:
                color = marking_class(ord(ch))
            elif colors:
                color = key
            else:
                color = None
            add(disp, (MARK_KEY, color, ord(ch)))
        else:
            add(disp, key if colors else None)

    for idx, cellline in enumerate(lines):
        for ch, key in cellline:
            emit(ch, key)
        # a newline that ended a soft autowrap is tagged so the widget can join
        # the wrapped rows on copy (see WRAP_NL); a real line break stays None.
        soft = wraps is not None and idx < len(wraps) and wraps[idx]
        add('\n', WRAP_NL if soft else None)
    prefix_len = sum(len(p) for parts, _ in runs for p in parts)
    for ch, key in current:
        emit(ch, key)
    return [(''.join(parts), key) for parts, key in runs], prefix_len


def cells_display_col(cells, col, mode):
    """The DISPLAY column (character offset) of logical cursor position `col`,
    i.e. the width of rendering cells[0:col] under `mode` -- needed to place the
    caret, since a reveal badge is many columns wide."""
    return sum(len(render_output(c, mode)) for c, _ in cells[:col])


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
    # Collapse whitespace, then cap. Truncation can land on a space and leave a
    # trailing one; strip it so the result is idempotent (re-sanitizing an
    # already-sanitized title is a no-op, not a one-character-shorter string).
    return ' '.join(''.join(kept).split())[:limit].strip()


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
