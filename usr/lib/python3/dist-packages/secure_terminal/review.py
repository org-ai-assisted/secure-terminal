#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""The in-window review bar for text crossing the terminal boundary.

The same bar reviews text in BOTH trust directions: a paste coming IN (before it
reaches the shell) and a selection being copied OUT (before it reaches the system
clipboard). When such text carries unicode or control characters, the terminal
HOLDS it and asks the window to show this bar (docked at the bottom, like the find
bar).

ONE BOX, revealed and editable: the bar shows a one-line summary of what is hidden,
a single RevealedEditor box that IS the exact preview of what will cross (every
character rendered through the terminal's detail pipeline -- a homoglyph tinted, a
bidi override named, an invisible boxed -- and editable in place), a status line
naming the active transform, four action buttons, and a live per-class breakdown
that recomputes from the box on every edit and every button (the "is it clean yet"
readout). There is NO separate hidden edit box and NO separate read-only mirror: the
box the user edits and the preview of what crosses are the same surface, so a
"works live, wrong in the review box" divergence cannot recur.

The box OPENS in the default "Keep printable unicode" state -- every invisible /
bidi / control character dropped, visible glyphs (INCLUDING look-alikes) kept,
revealed and editable. The four actions each carry a house-style hover tooltip:

  [Strip unicode]  delete ALL non-ASCII, NO mapping (Cyrillic a is REMOVED, never
                   mapped to Latin a), so a homoglyph-spoofed domain reads visibly
                   broken and is noticed.
  [ASCII-fold]     fold each look-alike to the ASCII it imitates (Cyrillic a ->
                   Latin a), then clean -- reveals the ASCII the disguise imitates.
  [Restore original paste]  revert the box to the original paste's keep-printable
                   form (confirm: edits lost) -- the escape hatch to re-inspect.
  Deliver (Paste / Copy / Replace)  send EXACTLY the box's bytes (re-sanitized on
                   the way out: the printable-unicode drop is re-applied as
                   defense-in-depth, so a re-paste into the box cannot smuggle an
                   invisible past review).

Only Reject is coloured safe-green: the one unconditionally-safe choice (nothing
crosses), never gated -- Esc rejects from anywhere. The Deliver button stays gated
by the anti-fat-finger countdown for a PASTE (re-armed on every edit and transform,
so the currently-shown buffer always gets the full delay); a copy has no countdown.
Delivery is dispatched back to the tab that held the text, the only path that lets
it cross.
"""

from typing import NotRequired, TypedDict, cast

from PyQt6.QtCore import Qt
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout, QPushButton,
)

from secure_terminal.sanitize import (
    classify_paste, classify_paste_detail,
    sanitize_clipboard, sanitize_clipboard_unicode, ascii_fold_display,
)
from secure_terminal.terminal import SecureTerminal
from secure_terminal.revealed_editor import RevealedEditor

# Semantic colours -- the app's green=safe traffic light, matching the main window
# (which labels DETAIL/CLI "green, safe" and the review lamp red). All three clear the
# contrast guard (sanitize.too_close) against BOTH theme backgrounds, so they stay
# readable whatever the desktop palette. Pinned so test_review.py can assert the
# contrast. Used on: Reject (green), the transform buttons (green = result is safe
# ASCII, amber = result keeps printable unicode), and Deliver (red blocked / amber
# unicode / no colour ASCII -- so a button's colour predicts what Deliver becomes).
SAFE_FG = '#1f8a54'      # green -- a safe outcome (pure ASCII), and Reject
CAUTION_FG = '#9a6a00'   # amber -- printable unicode kept (look-alikes survive)
RISK_FG = '#d83933'      # red  -- the risk dot, and a Deliver blocked by hidden chars

# The box loads (and edits) at most this many SOURCE characters of the paste. Well
# beyond any human-reviewable paste, but bounded so the per-keystroke cell rebuild
# stays snappy and a multi-megabyte paste cannot freeze the mandatory review. A
# longer paste keeps its beyond-cap tail OUT of the box (self._tail) -- the tail
# still DELIVERS (so the full paste crosses) and the truncation notice discloses it,
# so the un-reviewed tail is never silently dropped nor silently crossed.
_BOX_MAX = 20000

# key -> (code point, plain-language label), most-alarming first (box-drawing last).
# The glyph is built with chr() so the SOURCE stays ASCII (house convention, like
# sanitize.BOX = chr 0x25A1); the text label is ALWAYS shown beside it, so a missing
# glyph font degrades to readable text rather than a blank.
_CLASS_ROWS = tuple(
    (key, chr(cp), label) for key, cp, label in (
        ('bidi',       0x2194, 'Bidirectional control'),   # left-right arrow: reorders
        ('control',    0x2400, 'Control character'),        # symbol for NULL
        ('invisible',  0x2423, 'Invisible / zero-width'),   # open box (blank)
        ('confusable', 0x2248, 'Look-alike (homoglyph)'),   # almost-equal: looks like ASCII
        ('combining',  0x25CC, 'Combining (Zalgo)'),        # dotted circle: combining base
        # an accented Latin letter: itself non-ASCII and in every common font (a CJK
        # sample would tofu without a CJK font the app does not require).
        ('nonascii',   0x00C0, 'Other non-ASCII'),
        ('structural', 0x253C, 'Box-drawing / blocks'),     # box-drawing cross
    )
)
# Absent classes, the box-drawing row, and the informational Length row: no risk, muted.
_MUTED_FG = '#888888'
_LINES_GLYPH = chr(0x00B6)   # pilcrow, for the Lines row
_SAFE_GLYPH = chr(0x2713)    # check: the never-auto-run guarantee is met
_CAUTION_GLYPH = chr(0x25B2)  # up-triangle: accepted, but delivery is not a waiting command line
# Shown (safe-green) when a reviewed paste hides nothing -- a positive all-clear so an
# ASCII-only paste held for another reason (a multi-line paste) reads as safe.
_CLEAN_MSG = 'ASCII-only -- nothing hidden.'


# Everything that differs between the two directions. `dispatch` is the tab method the
# choice is routed to. `paste_newline` maps the shell's carriage return to a newline
# for the never-auto-run wording and marks the direction that runs commands.
class _Kind(TypedDict):
    """One trust direction's wording. Typed so the text keys read as str (mypy)."""
    summary: str
    summary_empty: str
    full_note: str
    subject: str
    noun: str
    reject: str
    reject_tip: str
    deliver: str
    deliver_tip: str
    dispatch: str
    paste_newline: NotRequired[bool]


_KINDS: dict[str, _Kind] = {
    'paste': {
        'summary': 'This paste hides %s.',
        # shown in "always" mode for a clean paste: no hidden characters to name.
        'summary_empty': 'Review this paste before it reaches the shell.',
        'full_note': 'the FULL paste still delivers',
        'subject': 'this paste',
        'noun': 'paste',
        'reject': 'Reject',
        'reject_tip': 'Do not paste (Enter or Esc)',
        'deliver': 'Paste',
        'deliver_tip': 'Paste exactly the box above into the shell',
        'dispatch': 'dispatch_pending_paste',
        'paste_newline': True,
    },
    'copy': {
        'summary': 'This copy would carry %s onto the clipboard.',
        'summary_empty': 'Review this copy before it reaches the clipboard.',
        'full_note': 'the FULL copy still reaches the clipboard',
        'subject': 'this copy',
        'noun': 'copy',
        'reject': "Don't copy",
        'reject_tip': 'Do not copy (Enter or Esc)',
        'deliver': 'Copy',
        'deliver_tip': 'Copy exactly the box above to the clipboard',
        'dispatch': 'dispatch_pending_copy',
    },
    # The standalone clipboard sanitizer (clipboard_watch.py): text already ON the
    # system clipboard, reviewed before it is pasted elsewhere. Not a terminal
    # direction -- dispatch_pending_clipboard lives on a small holder object, not a
    # tab -- but the bar is identical.
    'clipboard': {
        'summary': 'This clipboard text hides %s.',
        'summary_empty': 'Review the clipboard text.',
        'full_note': 'the FULL clipboard text is still used',
        'subject': 'this clipboard text',
        'noun': 'clipboard text',
        'reject': 'Leave it',
        'reject_tip': 'Leave the clipboard unchanged (Enter or Esc)',
        'deliver': 'Replace',
        'deliver_tip': 'Replace the clipboard with exactly the box above',
        'dispatch': 'dispatch_pending_clipboard',
    },
}


class ReviewBar(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self._term = None
        # The FULL original text held for review (the box may load only a bounded
        # prefix of it -- see _BOX_MAX / self._tail).
        self._raw = ''
        # The beyond-cap tail: raw[_BOX_MAX:], held OUT of the editable box but still
        # delivered so the whole paste crosses; the truncation notice discloses it.
        self._tail = ''
        # The active transform tier the tail is neutralized to on deliver -- 'keep'
        # (printable unicode), 'strip' (ASCII only) or 'fold' (look-alikes folded).
        # The box carries the user's choice for its visible prefix; the tail is not
        # editable, so it must be neutralized to the SAME tier, or a [Strip unicode]
        # would silently leave a homoglyph in the un-shown tail (a paste past the box
        # cap could then smuggle a look-alike past a strip). Set by the transform
        # buttons + open/restore; a manual box edit leaves it (the chosen tier stands).
        self._active_mode = 'keep'
        self._kind = _KINDS['paste']
        # The anti-fat-finger countdown gating Deliver for a PASTE (seconds). Re-armed
        # on every edit and transform; a copy passes delay 0 (no countdown).
        self._remaining = 0
        self._delay = 0
        self._countdown = QTimer(self)
        self._countdown.timeout.connect(self._tick)
        self.setObjectName('reviewbar')
        self.setVisible(False)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(6)

        # summary row: risk dot, the "what is hidden" headline, then the three DECISIONS
        # -- Show original (reset to the revealed trap), Reject (safe backout), Deliver
        # (content-driven). The transforms live in their own group below.
        row = QHBoxLayout()
        row.setSpacing(8)
        # The risk dot recolours per review: RISK_FG when something is hidden, SAFE_FG
        # for an all-clear (set in _refresh_review), so the dot never contradicts the
        # summary.
        self._dot = QLabel(self)
        self._dot.setFixedSize(14, 14)
        self._dot.setStyleSheet('background-color:%s; border-radius:7px;' % RISK_FG)
        row.addWidget(self._dot)
        # Selectable so the user can copy the summary text to ask about it.
        self._summary = QLabel('', self)
        self._summary.setStyleSheet('font-weight:bold;')
        self._summary.setWordWrap(True)
        self._summary.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self._summary, 1)
        # Restore original: revert the box to the original paste, fully revealed
        # (discards edits + transforms, re-blocks Deliver) -- the evidence escape hatch,
        # one click, no confirm, so re-inspecting the trap is never gated. Named for what
        # it does (reverts the content); "show" would wrongly read as a display toggle.
        self._restore = QPushButton('Restore original', self)
        self._restore.setToolTip('Revert the box to the original paste with every hidden '
                                 'character revealed again (discards your edits and any '
                                 'transformation). Re-blocks sending until you remove them.')
        self._restore.clicked.connect(self._do_restore)
        row.addWidget(self._restore)
        # Only Reject is fixed green: the one unconditionally-safe choice (nothing
        # crosses), never gated -- Enter/Esc always back out.
        self._reject = QPushButton('Reject', self)
        self._reject.setStyleSheet('color:%s; font-weight:600;' % SAFE_FG)
        self._reject.clicked.connect(lambda: self._choose('reject'))
        row.addWidget(self._reject)
        # Deliver is CONTENT-DRIVEN (see _update_deliver): red + disabled while any hidden
        # (invisible/bidi/control) character remains -- a trap literally cannot be sent
        # while it is visible -- amber when only printable unicode (look-alikes) remains,
        # no colour when pure ASCII. The paste countdown gates it on top.
        self._deliver = QPushButton('Paste', self)
        self._deliver.clicked.connect(self._deliver_clicked)
        row.addWidget(self._deliver)
        outer.addLayout(row)

        # THE box: editable, revealed, multi-line -- opens showing the WHOLE paste
        # (invisibles/bidi as named badges, look-alikes tinted), nothing pre-dropped, so
        # the trap is EVIDENCE you see before choosing. What is shown is what a Deliver
        # sends (re-sanitized); an edit can never bypass the neutralization, and a typed
        # or re-pasted character is cleaned so it cannot ADD a hidden one.
        self._editor = RevealedEditor(self)
        self._editor.setMaximumHeight(140)
        self._editor.changed.connect(self._on_edit)
        outer.addWidget(self._editor)

        # Status line: names the CURRENT box state and which classes a transform removed
        # (never a bare ambiguous count). The badges in the box name each exact character.
        self._status = QLabel('', self)
        self._status.setStyleSheet('color:%s;' % _MUTED_FG)
        self._status.setWordWrap(True)
        outer.addWidget(self._status)

        # The in-place transforms, under a NEUTRAL header (they change the text; they
        # promise nothing). Each: a technical label + a plain gloss beneath, and a
        # green/amber tint in the app's green=safe language -- Strip + ASCII-fold give a
        # safe ASCII result (green), Keep printable leaves the look-alikes (amber). So the
        # button colour predicts what Deliver becomes if you click it.
        header = QLabel('Text transformations:', self)
        header.setStyleSheet('color:%s; font-weight:600;' % _MUTED_FG)
        outer.addWidget(header)
        trow = QHBoxLayout()
        trow.setSpacing(14)
        self._strip = self._transform_button(
            trow, 'Strip unicode', SAFE_FG, 'remove every non-ASCII character',
            'Delete every non-ASCII character, with NO mapping -- a look-alike is removed, '
            'not turned into the letter it imitates, so a spoofed word reads visibly '
            'broken. Result is plain ASCII (safe to send).', self._do_strip)
        self._fold = self._transform_button(
            trow, 'ASCII-fold', SAFE_FG,
            'replace look-alikes with the plain letter they imitate',
            'Replace each look-alike with the ASCII character it imitates (Cyrillic a '
            'becomes Latin a), then clean -- reveals the plain ASCII the disguise was '
            'pretending to be. Result is plain ASCII (safe to send).', self._do_fold)
        self._keep = self._transform_button(
            trow, 'Keep printable unicode', CAUTION_FG,
            'remove invisible/reordering characters, keep the rest',
            'Remove the invisible / reordering / control characters, but KEEP every visible '
            'letter including any look-alikes. The visible deception survives, so this '
            'result is caution (amber), not fully safe.', self._do_keep)
        trow.addStretch(1)
        outer.addLayout(trow)

        # The breakdown beneath the box: a Structure section (lines, the never-auto-run
        # guarantee, length) and a per-class hidden-character table, recomputed from the
        # box on every change. Rich text so a glyph can carry its risk colour; selectable
        # so the user can copy it.
        self._detail = QLabel('', self)
        self._detail.setTextFormat(Qt.TextFormat.RichText)
        self._detail.setWordWrap(True)
        self._detail.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(self._detail)

    def _transform_button(self, row, label, colour, gloss, tip, slot):
        """One transform: a tinted technical button (colour = its result's safety, in the
        app's green=safe language) with a plain-language gloss beneath it, and the house
        tooltip on hover. Added as its own column to `row`; returns the button."""
        col = QVBoxLayout()
        col.setSpacing(1)
        btn = QPushButton(label, self)
        btn.setStyleSheet('color:%s; font-weight:600;' % colour)
        btn.setToolTip(tip)
        btn.clicked.connect(slot)
        col.addWidget(btn)
        cap = QLabel(gloss, self)
        cap.setStyleSheet('color:%s; font-size:11px;' % _MUTED_FG)
        cap.setWordWrap(True)
        col.addWidget(cap)
        row.addLayout(col)
        return btn

    # -- lifecycle ------------------------------------------------------------
    def show_review(self, term, raw, delay, kind='paste'):
        """Show the bar for `term`'s held text `raw`, in the given direction ('paste',
        'copy' or 'clipboard'). The box opens in the default keep-printable form. The
        anti-fat-finger countdown gates Deliver for a paste (`delay` seconds, 0 for a
        copy); it is re-armed on every edit. Focus lands on the box so the held text
        can be reviewed and trimmed at once; Esc rejects from anywhere."""
        self._term = term
        self._raw = raw
        self._tail = raw[_BOX_MAX:]
        self._active_mode = 'reveal'        # opens fully revealed; the tail follows
        self._kind = _KINDS.get(kind, _KINDS['paste'])
        self._reject.setText(self._kind['reject'])
        self._reject.setToolTip(self._kind['reject_tip'])
        self._deliver.setText(self._kind['deliver'])
        self._deliver.setToolTip(self._kind['deliver_tip'])
        self._delay = max(0, int(delay))
        self._remaining = 0
        self._countdown.stop()
        # Follow the reviewed tab's theme + display mode, so the box reveals risk on
        # the same background and in the same mode as the console.
        self._sync_appearance()
        # Open FULLY REVEALED -- the whole trap is shown (invisibles/bidi as badges),
        # nothing pre-dropped. set_source_revealed emits `changed`, which runs _on_edit
        # -> refresh + arm-countdown, so the table + the content-driven Deliver state
        # populate without a separate call.
        self._editor.set_source_revealed(raw[:_BOX_MAX])
        self._set_status_reveal()
        self.setVisible(True)
        self._editor.setFocus()

    def _sync_appearance(self):
        term = self._term
        if term is None:
            return
        self._editor.apply_theme(getattr(term, '_theme', 'dark'))
        if hasattr(term, 'current_mode'):
            self._editor.set_mode(term.current_mode())
        if hasattr(term, 'current_font_family'):
            self._editor.set_font_family(term.current_font_family())
        if hasattr(term, 'current_zoom'):
            self._editor.apply_zoom(term.current_zoom())

    def _on_edit(self):
        """The box changed (a manual edit or a transform button): refresh the summary
        + breakdown from it, and RE-ARM the countdown so the currently-shown buffer
        gets the full delay -- editing to new content must never inherit the original
        text's already-elapsed countdown."""
        self._refresh_review()
        self._arm_countdown()

    def _refresh_review(self):
        """Recompute the summary, risk dot and breakdown from the CURRENT box content,
        so the bar always reflects exactly what delivery will send (the box IS the
        buffer that crosses). A beyond-cap tail (raw longer than _BOX_MAX) is disclosed
        as un-reviewed: it still delivers, so the count is of the reviewed box and the
        notice tells the user to Reject if they cannot verify the rest."""
        term = self._term
        if term is None:
            return
        text = self._editor.source()
        detail = classify_paste_detail(text)
        parts = ['%d %s%s' % (n, label, '' if n == 1 else 's')
                 for label, n in classify_paste(text)]
        truncated = bool(self._tail)
        hidden = sum(detail['counts'].values())
        if hidden == 0 and not truncated:
            summary = _CLEAN_MSG
            dot_fg = SAFE_FG
        else:
            summary = (self._kind['summary'] % ', '.join(parts)
                       if parts else self._kind['summary_empty'])
            dot_fg = RISK_FG
        self._dot.setStyleSheet('background-color:%s; border-radius:7px;' % dot_fg)
        if truncated:
            summary += ('  [truncated: only the first {:,} characters are shown and '
                        'editable here; the rest is not shown but is neutralized to the '
                        'SAME choice (keep / strip / fold) and still delivers -- {}; '
                        'Reject if you cannot verify the rest]'
                        .format(_BOX_MAX, self._kind['full_note']))
        self._summary.setText(summary)
        self._set_detail(detail, term, truncated)

    def _set_detail(self, detail, term, truncated):
        """Populate the breakdown label from a classify_paste_detail result: a Structure
        section (lines, the never-auto-run guarantee for a paste, length) and a per-class
        hidden-character table. Each present class's glyph carries its ON-SCREEN marking
        colour (SecureTerminal.MARKING_COLORS) so the table and the terminal never
        disagree; absent classes stay muted, so what is NOT present is explicit."""
        theme = getattr(term, '_theme', 'dark')
        # MARKING_COLORS is an untyped nested class attribute -> its values read as object;
        # name the concrete shape here so palette[class]['fg'] indexes cleanly (mypy).
        palette = cast('dict[str, dict[str, str]]', SecureTerminal.MARKING_COLORS.get(
            theme, SecureTerminal.MARKING_COLORS['dark']))

        def _row(glyph, color, name, value):
            return ('<tr><td><font color="%s">%s</font></td>'
                    '<td>&nbsp;%s&nbsp;&nbsp;</td><td>%s</td></tr>'
                    % (color, glyph, name, value))

        # A beyond-cap tail means the counts are of the SHOWN box, not the whole paste
        # (which still delivers), so mark them ">= N" rather than present them as a total.
        multiline = detail['multiline']
        plus = '+' if truncated else ''
        # Only the PASTE direction executes the lines; a copy/clipboard review runs
        # nothing, so reserve the "runs more than one command" wording for paste.
        if not multiline:
            note = ''
        elif self._kind.get('paste_newline'):
            note = ' &nbsp;(multi-line -- runs more than one command)'
        else:
            note = ' &nbsp;(multi-line)'
        lines_val = '%d%s%s' % (detail['lines'], plus, note)
        struct = [_row(_LINES_GLYPH,
                       palette['invisible']['fg'] if multiline else _MUTED_FG,
                       'Lines', lines_val)]
        if self._kind.get('paste_newline'):
            # never-auto-run always holds -- we never inject a submit: a bracketed program
            # buffers the paste as inert text; every non-bracketed delivery has its trailing
            # submit CR stripped (paste_no_autosubmit). But WHERE the bytes land differs, and
            # the row must not over-promise a waiting command line that isn't there:
            #  - bracketed: the foreground program receives it as inert text.
            #  - a bare shell prompt (canonical line discipline): the line is cooked and held,
            #    so it truly waits for the user's own Enter.
            #  - a foreground program in RAW mode (ICANON off) with no bracketed framing: the
            #    program consumes the bytes AS KEYSTROKES the instant they arrive -- there is
            #    no command line and no Enter to press. Still never auto-runs a shell command
            #    (the trailing CR is gone), but it is not "waiting", so say so and tint amber.
            bracketed = (hasattr(term, '_bracketed_paste_active')
                         and term._bracketed_paste_active())
            raw_fg = (not bracketed
                      and hasattr(term, '_child_raw_mode')
                      and hasattr(term, 'has_foreground_program')
                      and term.has_foreground_program()
                      and term._child_raw_mode())
            if bracketed:
                glyph, colour, note = (_SAFE_GLYPH, SAFE_FG,
                                       'your program receives it as text')
            elif raw_fg:
                glyph, colour, note = (_CAUTION_GLYPH, CAUTION_FG,
                                       'your program receives it immediately as keystrokes')
            else:
                glyph, colour, note = (_SAFE_GLYPH, SAFE_FG,
                                       'waits on the command line -- press Enter to run')
            struct.append(_row(glyph, colour, 'If accepted', note))
        length = ('%d+ characters (shown box; the full text is larger)'
                  % detail['chars'] if truncated
                  else '%d characters (%d bytes)'
                  % (detail['chars'], detail['bytes']))
        struct.append(_row('', _MUTED_FG, 'Length', length))

        counts = detail['counts']
        if sum(counts.values()) == 0 and not truncated:
            chars_html = '<font color="%s">(none)</font>' % _MUTED_FG
        else:
            crows = []
            for key, glyph, label in _CLASS_ROWS:
                n = counts.get(key, 0)
                present = n > 0
                color = (palette[key]['fg'] if present and key != 'structural'
                         else _MUTED_FG)
                count_txt = ('<b>%d</b>' % n) if present else str(n)
                crows.append(_row(glyph, color, label, count_txt))
            chars_html = ('<table cellspacing="0" cellpadding="1">%s</table>'
                          % ''.join(crows))
        self._detail.setText(
            '<b>Structure</b>'
            '<table cellspacing="0" cellpadding="1">%s</table>'
            '<b>Hidden characters</b>%s' % (''.join(struct), chars_html))

    # -- the transforms -------------------------------------------------------
    # The display sanitizer (newline-preserving) for each tier -- ONE source of truth,
    # applied to the box AND to the un-shown tail on deliver, so a transform can never
    # neutralize the visible prefix but leave the tail at a weaker tier. 'reveal' (the
    # open default, look-alikes + invisibles shown) neutralizes the un-shown tail to
    # keep-printable: a revealed box can only reach Deliver once its OWN invisibles are
    # gone, so the tail follows the same printable-unicode floor.
    # dict VALUES are not descriptors, so these stay plain callables (no self binding).
    _TIER = {
        'reveal': sanitize_clipboard_unicode,
        'keep': sanitize_clipboard_unicode,
        'strip': sanitize_clipboard,
        'fold': ascii_fold_display,
    }

    def _do_keep(self):
        """[Keep printable unicode]: remove the invisible / reordering / control
        characters, KEEP the visible letters (incl. look-alikes) -> box becomes
        deliverable at the amber 'unicode' tier."""
        self._active_mode = 'keep'
        before = self._editor.source()
        removed = self._blocked_count(before)
        self._editor.set_source(sanitize_clipboard_unicode(before))
        self._status.setText('Removed %d hidden character%s (invisible / reordering / '
                             'control)%s; kept the visible letters, including any '
                             'look-alikes.'
                             % (removed, '' if removed == 1 else 's', self._tail_note()))

    def _do_strip(self):
        """[Strip unicode]: delete every non-ASCII character, NO mapping. Applies to the
        box AND (on deliver) the tail; newlines are preserved (display form)."""
        self._active_mode = 'strip'
        before = self._editor.source()
        after = sanitize_clipboard(before)
        removed = len(before) - len(after)
        self._editor.set_source(after)        # emits changed -> _on_edit refresh
        self._status.setText('Removed all %d non-ASCII character%s%s -- plain ASCII only.'
                             % (removed, '' if removed == 1 else 's', self._tail_note()))

    def _do_fold(self):
        """[ASCII-fold]: replace each look-alike with the ASCII it imitates, then clean to
        ASCII. Applies to the box AND (on deliver) the tail; newlines preserved."""
        self._active_mode = 'fold'
        before = self._editor.source()
        after = ascii_fold_display(before)
        self._editor.set_source(after)
        self._status.setText('Replaced look-alikes with the plain ASCII they imitate, then '
                             'removed any remaining non-ASCII%s.' % self._tail_note())

    def _do_restore(self):
        """[Restore original]: revert the box to the FULLY REVEALED original paste,
        discarding edits/transforms and re-showing every hidden character (re-blocks
        Deliver). The evidence escape hatch -- one click, no confirm, so re-inspecting
        the trap is never gated."""
        if self._term is None:
            return
        self._active_mode = 'reveal'
        self._editor.set_source_revealed(self._raw[:_BOX_MAX])
        self._set_status_reveal()

    def _blocked_count(self, text):
        """How many characters in `text` are the truly-hidden kind Keep-printable drops
        (invisible / bidi / control) -- the classes that BLOCK Deliver. Length diff
        against keep-printable, so it never disagrees with what a keep would remove."""
        return len(text) - len(sanitize_clipboard_unicode(text))

    def _set_status_reveal(self):
        """Status for the reveal state (open + Restore original): the full text is shown;
        name how many hidden characters block sending (the badges name each exact one).
        Uses the direction's noun so a copy/clipboard review does not read 'paste'."""
        noun = self._kind['noun']
        n = self._blocked_count(self._editor.source())
        if n:
            self._status.setText('Showing the full %s -- %d hidden character%s '
                                 '(invisible / reordering / control) block sending; each '
                                 'is named in the box. Remove them (a Text transformation, '
                                 'or delete the badges) to continue.'
                                 % (noun, n, '' if n == 1 else 's'))
        else:
            self._status.setText('Showing the full %s -- nothing hidden.' % noun)

    def _tail_note(self):
        """A status suffix disclosing that the un-shown tail is neutralized to the SAME
        tier -- empty when there is no tail, so the common (fully-shown) case is silent."""
        return ' (the un-shown tail too)' if self._tail else ''

    def _tail_delivered(self):
        """The un-shown tail neutralized to the ACTIVE tier -- the same display
        transform the box got, so the tail can never deliver at a weaker tier than the
        button the user pressed. '' when the whole paste fits in the box."""
        if not self._tail:
            return ''
        return self._TIER[self._active_mode](self._tail)

    # -- appearance follow (main.py calls this on tab mode/theme/font/zoom change) --
    def rerender_mirror(self):
        """Re-apply the reviewed tab's theme + display mode to the box, so an open
        review follows a live change on the tab. No-op when no review is open
        (_term is None iff a review is showing), so the window can call it
        unconditionally. (Named for the mirror it replaced; the box now IS the
        preview.)"""
        if self._term is None:
            return
        self._sync_appearance()

    def hide_review(self):
        """Hide the bar and stop the countdown; called when the text is resolved."""
        self._countdown.stop()
        self._term = None
        self.setVisible(False)

    def reviewed_term(self):
        """The terminal whose held text this bar is reviewing, or None -- so a
        closing tab can hide its own review before the terminal is destroyed."""
        return self._term

    # -- countdown + delivery -------------------------------------------------
    def _arm_countdown(self):
        """(Re)start the anti-fat-finger countdown that gates Deliver. Called on every
        edit and transform, so the CURRENTLY-shown buffer always gets the full delay
        before it can be delivered. A copy (delay 0) enables Deliver at once."""
        self._remaining = self._delay
        if self._remaining > 0:
            self._countdown.start(1000)
        else:
            self._countdown.stop()
        self._update_deliver()

    def _update_deliver(self):
        """Sync the Deliver button to the box CONTENT (recomputed on every edit/transform)
        and the countdown, in the app's green=safe language:
          - any hidden (invisible/bidi/control) char left  -> RED, disabled,
            '<verb> blocked - N hidden' -- a trap cannot be sent while it is visible;
          - only printable unicode (look-alikes) left       -> amber, '<verb> unicode';
          - pure ASCII                                       -> no colour, '<verb> ASCII'.
        The paste countdown gates it ON TOP (disabled + a (N) suffix while it runs)."""
        verb = self._kind['deliver']
        box = self._editor.source()
        blocked = self._blocked_count(box)
        if blocked > 0:
            self._deliver.setText('%s blocked - %d hidden' % (verb, blocked))
            self._deliver.setEnabled(False)
            self._deliver.setStyleSheet('color:%s; font-weight:600;' % RISK_FG)
            self._deliver.setToolTip('Remove the %d hidden character%s first -- a Text '
                                     'transformation, or delete the badges in the box.'
                                     % (blocked, '' if blocked == 1 else 's'))
            return
        # not blocked: the OUTCOME is safe (ASCII) or caution (printable unicode kept).
        if any(ord(c) > 0x7F for c in box):
            base, colour = '%s unicode' % verb, CAUTION_FG
        else:
            base, colour = '%s ASCII' % verb, None
        self._deliver.setStyleSheet('color:%s; font-weight:600;' % colour if colour else '')
        if self._remaining > 0:
            self._deliver.setText('%s (%d)' % (base, self._remaining))
            self._deliver.setEnabled(False)
            self._deliver.setToolTip('Review the box -- ready in %d s' % self._remaining)
        else:
            self._deliver.setText(base)
            self._deliver.setEnabled(True)
            self._deliver.setToolTip(self._kind['deliver_tip'])

    def _tick(self):
        if self._remaining > 0:
            self._remaining -= 1
        self._update_deliver()
        if self._remaining <= 0:
            self._countdown.stop()

    def _deliver_clicked(self):
        """The Deliver button: send the box. Disabled while any hidden character remains
        or the countdown runs, but re-check both in case a click races the state."""
        if self._remaining <= 0 and self._blocked_count(self._editor.source()) == 0:
            self._choose('deliver')

    def _choose(self, choice):
        # Single-shot: clear _term before dispatching so a second click (a double-click,
        # or Esc right after) is a no-op.
        term = self._term
        if term is None:
            return
        self._term = None
        self._countdown.stop()
        if choice == 'reject':
            getattr(term, self._kind['dispatch'])('reject')
        else:
            # Deliver EXACTLY the box (what is shown IS what crosses) plus the un-shown
            # tail NEUTRALIZED TO THE SAME TIER the box got (_tail_delivered) -- so a
            # [Strip unicode] cannot leave a homoglyph in the tail past the box cap. The
            # dispatch's 'unicode' action re-applies the printable-unicode drop as a final
            # defense-in-depth (a re-paste into the box cannot smuggle an invisible past
            # review) and, for a paste, maps newlines to the shell's submit CR. The box's
            # Keep / Strip / Fold choice IS the sanitization; this just re-neutralizes.
            getattr(term, self._kind['dispatch'])(
                'unicode', self._editor.source() + self._tail_delivered())
        # HIDE the bar directly: this bar made a definitive choice on the term it was
        # showing, so it must close. We cannot rely on the paste_review_resolved ->
        # _hide_paste_review path here, because that path guards on reviewed_term()
        # (to avoid a cross-tab resolution tearing down another tab's re-shown bar)
        # and we just cleared _term above -- so the guarded hide would be skipped and
        # the bar would stay open after the click.
        self.hide_review()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self._choose('reject')
            return
        super().keyPressEvent(event)
