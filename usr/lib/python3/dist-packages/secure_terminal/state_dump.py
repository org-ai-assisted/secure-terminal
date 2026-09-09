#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Deterministic terminal-state dump.

Serializes the CURRENT terminal state -- the pyte grid (TUI mode) or the line
document plus SGR pen (CLI mode), together with the wrapper-level flags that pyte
does not model (alternate screen, mouse-reporting modes, OSC 4/10/11/12 palette
overrides) -- into a form a human can read and diff, and a machine can round-trip. Two dumps taken while the terminal is
idle are byte-identical: only pyte MODEL state is read (cell fg/bg colour names,
bold, ...), never the theme/contrast-guarded display colours, and no volatile field
(a pid/pgrp, a timer, an object address, a cache) is ever included.

Pure: no Qt. `collect()` reads a pyte Screen (or a CLI snapshot) into a plain dict;
`dump_text()` / `dump_json()` render that dict. The text form elides blank cells and
fully-blank rows (a row's surviving index shows the gap) so the file stays small and
diffs stay minimal; a cell is "blank" only when it equals the screen's default cell,
so a coloured space (bg set, data == ' ') is kept.

Format is versioned (FORMAT_VERSION) and designed to be round-trippable; a loader is
a deliberate follow-up, not shipped here.
"""

import json

import pyte.modes
import pyte.charsets as _charsets

FORMAT_VERSION = 2

# pyte private modes are stored in Screen.mode shifted left 5 (see pyte.modes); the
# widget stores bracketed paste (DEC private 2004) the same way but pyte has no name
# for it. Build a value -> stable-name map from pyte.modes' public constants plus that
# one, so a dumped mode reads as e.g. "DECAWM" not the raw int.
_MODE_NAMES = {
    value: name
    for name, value in vars(pyte.modes).items()
    if name.isupper() and isinstance(value, int)
}
_MODE_NAMES[2004 << 5] = 'BRACKETED_PASTE'

# ANSI (non-private) modes are NOT shifted; pyte's two are small ints. Everything else
# a program can set via DECSET is a private mode (shifted). Split on that so the dump
# lists them under the right heading.
_ANSI_MODE_VALUES = frozenset((pyte.modes.LNM, pyte.modes.IRM))

# Mouse-reporting DEC private mode numbers -> short names (mirrors sanitize._MOUSE_*).
_MOUSE_NAMES = {
    1000: 'button-track',
    1002: 'drag-track',
    1003: 'any-motion',
    1004: 'focus',
    1006: 'sgr-ext',
}

# The eight pyte Char attribute fields, in namedtuple order; `data` is handled
# separately (it is the glyph, not a rendition attribute).
_ATTR_FIELDS = ('fg', 'bg', 'bold', 'italics', 'underscore', 'strikethrough',
                'reverse')


def _mode_name(value):
    return _MODE_NAMES.get(value, 'mode:%d' % value)


def _palette_dict(palette):
    """Normalize the wrapper's OSC 4/10/11/12 overrides -- {int palette index or the
    'fg'/'bg'/'cursor' role -> '#rrggbb'} -- to a str-keyed dict so the JSON dump is
    deterministic (sort_keys orders the string keys). These are PROGRAM-set overrides
    that outlive nothing but the child; they leak into the next prompt unless reset,
    so the dump must expose them to make that measurable. The values are already the
    ASCII hex strings sanitize/_parse_osc_color produced -- no display colour here."""
    if not palette:
        return {}
    return {str(key): value for key, value in palette.items()}


# The canonical clean prompt baseline, expressed against the DUMP schema: a fresh
# screen's DEC mode set and charset, no mouse reporting, no scroll region, a visible
# cursor carrying the default pen, and no palette override. terminal.py's
# _reset_vt_to_prompt_baseline() drives the terminal here on a program exit / restart.
_BASELINE_DEC_MODES = frozenset(('DECAWM', 'DECTCEM'))
_BASELINE_CHARSET = {'active': 0, 'g0': 'LAT1', 'g1': 'VT100'}


def is_baseline(snap):
    """True when a collect() snapshot carries NO leaked VT state -- i.e. it is at the
    clean prompt baseline -- IGNORING the scrollback (the document / grid rows), the
    alternate-screen flag (owned by the fg-exit alt-leave, not the VT reset) and the grid
    GEOMETRY (columns/lines are widget-determined, with no fixed baseline value -- a
    DECCOLM width leak is checked directly, not here). Covers modes, scroll region,
    charset, tab stops, cursor visibility/pen, mouse reporting and palette overrides. The
    single oracle shared by the reset regression sweep, the INV-7 Hypothesis property and
    the T10 formal check, so 'clean' cannot drift between the fix and its proofs; keying it
    to the dump schema means a newly-dumped leak field also has to be cleared to stay
    baseline. `snap` is the dict collect() returns (either mode)."""
    if snap.get('mouse_modes') or snap.get('palette_overrides'):
        return False
    if snap['mode'] != 'tui':
        return not snap.get('pen')
    cursor = snap['cursor']
    return (frozenset(snap['dec_modes']) == _BASELINE_DEC_MODES
            and not snap['ansi_modes']
            and snap['scroll_region'] is None
            and snap['charset'] == _BASELINE_CHARSET
            and snap['tabstops'] == 'default'
            and cursor['visible'] is True
            and not cursor['pen'])


def _charset_id(table):
    """A stable identity for a pyte G0/G1 charset table (a 256-char translation
    string), so a dump names the DESIGNATION (LAT1 / VT100 special-graphics / ...)
    rather than emitting 256 characters. Unknown tables read as 'custom'."""
    for name in ('LAT1_MAP', 'VT100_MAP', 'IBM_PC_MAP', 'VAX42_MAP'):
        if table is getattr(_charsets, name, None):
            return name[:-4]              # strip the '_MAP' suffix
    return 'custom'


def _attrs_dict(cell, default):
    """The non-default rendition attributes of `cell` vs the screen's `default` cell,
    as a plain dict (empty when the cell carries default rendition). Colours are the
    pyte MODEL names/hex ('default', 'red', 'ff0000'), never display colours."""
    out = {}
    for field in _ATTR_FIELDS:
        value = getattr(cell, field)
        if value != getattr(default, field):
            out[field] = value
    return out


def _row_runs(row, columns, default):
    """(text, runs, blank) for one grid row. `text` is the row glyphs up to the last
    SIGNIFICANT cell (one that differs from `default`), trailing default cells dropped.
    `runs` is the list of maximal column spans that share one non-default attribute set:
    {'start', 'end' (exclusive), 'attrs'}. `blank` is True when every cell equals the
    default cell (data and rendition) -- such a row is elided by the caller."""
    last = -1
    for x in range(columns):
        if row[x] != default:
            last = x
    if last < 0:
        return '', [], True
    text = ''.join(row[x].data for x in range(last + 1))
    runs = []
    cur = None
    for x in range(last + 1):
        attrs = _attrs_dict(row[x], default)
        if attrs:
            if cur is not None and cur['attrs'] == attrs and cur['end'] == x:
                cur['end'] = x + 1
            else:
                cur = {'start': x, 'end': x + 1, 'attrs': attrs}
                runs.append(cur)
        else:
            cur = None
    return text, runs, False


def collect(screen, *, mode, columns, alt_screen, saved_primary, mouse_modes,
            title, palette=None, cli_pen=None, document=None):
    """Read a terminal into a plain, deterministic snapshot dict.

    - `screen`: the pyte Screen in TUI mode; None in CLI mode.
    - `mode`: 'tui' or 'cli'.
    - `columns`: the child's column count (self._cols) -- used in CLI mode where there
      is no pyte grid.
    - `alt_screen`: bool, whether a full-screen program holds the alternate screen.
    - `saved_primary`: None, or (columns, lines) of the frozen primary while in alt.
    - `mouse_modes`: iterable of active mouse-reporting mode ints.
    - `title`: the (already sanitized) window title string.
    - `palette`: the wrapper's OSC 4/10/11/12 overrides (index/role -> '#rrggbb'); a
      program-set field that leaks into the next prompt unless reset, so it is dumped
      in BOTH modes.
    - `cli_pen`: the CLI-mode SGR pen dict {'fg','bg','bold'} (fg/bg None == default).
    - `document`: CLI-mode rendered line-document text.
    """
    snap = {
        'version': FORMAT_VERSION,
        'mode': mode,
        'alt_screen': bool(alt_screen),
        'saved_primary': (None if saved_primary is None
                          else {'columns': saved_primary[0],
                                'lines': saved_primary[1]}),
        'mouse_modes': sorted(int(m) for m in mouse_modes),
        'palette_overrides': _palette_dict(palette),
        'title': title or '',
    }
    if mode == 'cli' or screen is None:
        snap['columns'] = int(columns)
        snap['pen'] = _cli_pen(cli_pen)
        snap['document'] = document or ''
        return snap

    default = screen.default_char
    snap['columns'] = screen.columns
    snap['lines'] = screen.lines
    cursor_y = min(screen.cursor.y, screen.lines - 1)
    snap['cursor'] = {
        'x': screen.cursor.x,
        'y': cursor_y,
        'visible': not screen.cursor.hidden,
        'pen': _attrs_dict(screen.cursor.attrs, default),
    }
    dec: list[str] = []
    ansi: list[str] = []
    for value in sorted(screen.mode):
        (ansi if value in _ANSI_MODE_VALUES else dec).append(_mode_name(value))
    snap['dec_modes'] = dec
    snap['ansi_modes'] = ansi
    margins = screen.margins
    snap['scroll_region'] = (None if margins is None
                             else {'top': margins.top, 'bottom': margins.bottom})
    snap['charset'] = {
        'active': screen.charset,
        'g0': _charset_id(screen.g0_charset),
        'g1': _charset_id(screen.g1_charset),
    }
    default_tabs = set(range(8, screen.columns, 8))
    tabs = set(screen.tabstops)
    snap['tabstops'] = ('default' if tabs == default_tabs
                        else sorted(tabs))
    rows = []
    for y in range(screen.lines):
        text, runs, blank = _row_runs(screen.buffer[y], screen.columns, default)
        if not blank:
            rows.append({'y': y, 'text': text, 'runs': runs})
    snap['rows'] = rows
    return snap


def _cli_pen(pen):
    """Normalize the CLI-mode SGR pen ({'fg','bg','bold'}, fg/bg None == default) to
    the same non-default-only attr dict shape the TUI pen uses."""
    if not pen:
        return {}
    out = {}
    if pen.get('fg') is not None:
        out['fg'] = pen['fg']
    if pen.get('bg') is not None:
        out['bg'] = pen['bg']
    if pen.get('bold'):
        out['bold'] = True
    return out


def _encoded_len(snap):
    return len(json.dumps(snap, sort_keys=True, ensure_ascii=True, indent=1)) + 1


def _fit_snapshot(snap, max_bytes):
    """Shrink `snap` (a shallow copy) so its JSON stays UNDER max_bytes while remaining
    VALID JSON -- by dropping whole trailing grid rows (TUI) and/or truncating the line
    document (CLI), never by byte-slicing the serialized text (which would emit a broken
    fragment). Truncation is recorded so a consumer sees the dump is partial."""
    if _encoded_len(snap) <= max_bytes:
        return snap
    snap = dict(snap)
    rows = list(snap.get('rows') or [])
    if rows:
        dropped = 0
        # Drop from the END (keep the top of the screen); geometric step so a huge grid
        # converges in a few re-encodes, not one row at a time.
        while rows and _encoded_len({**snap, 'rows': rows,
                                     'truncated_rows': dropped}) > max_bytes:
            step = max(1, len(rows) // 8)
            dropped += step
            rows = rows[:-step]
        snap['rows'] = rows
        snap['truncated_rows'] = dropped
    if 'document' in snap and _encoded_len(snap) > max_bytes:
        doc = snap['document']
        _orig_doc_len = len(doc)
        # Keep the TAIL (the current screen / most recent output), dropping from the
        # front -- consistent with the text path's _fit_dump_reply, and because the live
        # screen is what a debugger wants, not the oldest scrollback.
        while doc and _encoded_len({**snap, 'document': doc,
                                    'document_truncated': True}) > max_bytes:
            doc = doc[len(doc) // 8 + 1:]
        # Flag ONLY when the document was actually shortened: an empty (or already-fitting)
        # document, with the overflow coming from another field, must not be mislabelled
        # document-truncated.
        if len(doc) < _orig_doc_len:
            snap['document'] = doc
            snap['document_truncated'] = True
    # An explicit tab-stop list can itself blow the budget (a program can HTS every column
    # of a 65535-wide screen), and rows/document shrinking never touches it -- collapse it
    # to a count so the bound holds.
    if (isinstance(snap.get('tabstops'), list)
            and _encoded_len(snap) > max_bytes):
        snap['tabstops'] = 'truncated(%d)' % len(snap['tabstops'])
    # Final guarantee: if some other field still overflows (a pathological title, a flood
    # of named modes), fall back to a minimal VALID JSON that names the overflow rather
    # than emit an over-budget document the transport frame would silently drop.
    if _encoded_len(snap) > max_bytes:
        minimal = {'version': snap.get('version', FORMAT_VERSION),
                   'mode': snap.get('mode'),
                   'truncated': True,
                   'note': 'state exceeds the dump budget; fields dropped'}
        # Bound the fallback ITSELF: shed its own optional fields until it fits, so even a
        # tiny budget yields valid JSON UNDER it -- never an over-budget frame the transport
        # would silently drop (the bare {version, truncated} is the irreducible minimum).
        for _drop in ('note', 'mode'):
            if _encoded_len(minimal) <= max_bytes:
                break
            minimal.pop(_drop, None)
        return minimal
    return snap


def dump_json(snap, max_bytes=None):
    """Machine round-trip form: sorted keys, ASCII-safe, deterministic byte output.
    When max_bytes is given, the snapshot is shrunk (whole rows / document truncated,
    recorded via truncated_rows / document_truncated) so the result stays VALID JSON
    under the budget -- an oversized dump must never become an unparseable fragment."""
    if max_bytes is not None:
        snap = _fit_snapshot(snap, max_bytes)
    return json.dumps(snap, sort_keys=True, ensure_ascii=True, indent=1) + '\n'


def _fmt_attrs(attrs):
    """Render a non-default attr dict as `fg=red bold reverse`: a boolean flag prints
    as the bare field name, a colour (str name/hex, or a CLI-pen int palette index)
    as field=value. Field order stable."""
    parts = []
    for field in _ATTR_FIELDS:
        if field not in attrs:
            continue
        value = attrs[field]
        # bool is an int subclass -> test it first, so a True flag is bare and a
        # numeric palette index still prints its value.
        parts.append(field if isinstance(value, bool)
                     else '%s=%s' % (field, value))
    return ' '.join(parts)


def _fmt_pen(pen):
    return _fmt_attrs(pen) if pen else 'default'


def dump_text(snap):
    """Human + technical, diffable form (see module docstring / the plan format)."""
    out = []
    out.append('# secure-terminal state dump v%d' % snap['version'])
    if snap['mode'] == 'cli':
        out.append('mode: cli            width: %d' % snap['columns'])
        out.append('pen: %s' % _fmt_pen(snap['pen']))
        out.append('alt-screen: %s' % ('yes' if snap['alt_screen'] else 'no'))
        out.append('mouse: %s' % _fmt_mouse(snap['mouse_modes']))
        out.append('palette: %s' % _fmt_palette(snap['palette_overrides']))
        out.append('title: %r' % snap['title'])
        out.append('--- document (line mode; no cell grid) ---')
        out.append(snap['document'])
        return '\n'.join(out) + '\n'

    cur = snap['cursor']
    out.append('mode: tui            size: %dx%d'
               % (snap['columns'], snap['lines']))
    out.append('cursor: x=%d y=%d visible=%s'
               % (cur['x'], cur['y'], 'yes' if cur['visible'] else 'no'))
    out.append('pen: %s' % _fmt_pen(cur['pen']))
    out.append('dec-modes: %s' % (' '.join(snap['dec_modes']) or '(none)'))
    out.append('ansi-modes: %s' % (' '.join(snap['ansi_modes']) or '(none)'))
    saved = snap['saved_primary']
    out.append('alt-screen: %s    saved-primary: %s'
               % ('yes' if snap['alt_screen'] else 'no',
                  'none' if saved is None
                  else '%dx%d' % (saved['columns'], saved['lines'])))
    region = snap['scroll_region']
    out.append('scroll-region: %s'
               % ('full' if region is None
                  else 'top=%d bottom=%d' % (region['top'], region['bottom'])))
    cs = snap['charset']
    out.append('charset: active=G%d G0=%s G1=%s'
               % (cs['active'], cs['g0'], cs['g1']))
    out.append('mouse: %s' % _fmt_mouse(snap['mouse_modes']))
    out.append('palette: %s' % _fmt_palette(snap['palette_overrides']))
    out.append('title: %r' % snap['title'])
    tabs = snap['tabstops']
    out.append('tabstops: %s'
               % ('default(8)' if tabs == 'default'
                  else ' '.join(str(t) for t in tabs) or '(none)'))
    out.append('--- grid ---  (blank cells and fully-blank rows elided; '
               'row index shows gaps)')
    for row in snap['rows']:
        line = '%4d: %s' % (row['y'], row['text'])
        ann = '  '.join('@%d-%d %s' % (r['start'], r['end'] - 1, _fmt_attrs(r['attrs']))
                        for r in row['runs'])
        if ann:
            line = '%s   %s' % (line, ann)
        out.append(line)
    return '\n'.join(out) + '\n'


def _fmt_mouse(modes):
    if not modes:
        return '(none)'
    names = ' '.join(_MOUSE_NAMES.get(m, str(m)) for m in modes)
    return '%s (%s)' % (' '.join(str(m) for m in modes), names)


def _fmt_palette(overrides):
    """`1=#ff0000 fg=#00ff00` (sorted, stable), or `(none)` when the program set no
    OSC 4/10/11/12 override."""
    if not overrides:
        return '(none)'
    return ' '.join('%s=%s' % (key, overrides[key]) for key in sorted(overrides))
