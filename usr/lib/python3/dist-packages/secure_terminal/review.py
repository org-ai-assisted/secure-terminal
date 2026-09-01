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

The bar shows a one-line summary of what is hidden, a per-class breakdown table and a
Structure section (line count, the never-auto-run guarantee, length), an EDITABLE
held-text field (trim the risky part before delivery), and a SINGLE mirror pane: a
read-only terminal view that renders through the SAME pipeline as the tab it came
from, so a homoglyph is tinted and each character is click-to-inspect exactly as in
the terminal. The pane FOLLOWS the reviewed tab live -- its display mode
(box/show/reveal/detail), theme, font and zoom (rerender_mirror). There is no
preview-only render branch, so a "works live, wrong in the review box" divergence
cannot recur. Risk-class colouring stays ON regardless of the tab's markings setting:
revealing risk is the pane's whole job.

The delivery choice is RADIO-FIRST, no default: pick "Strip to ASCII" or "Keep
unicode". Until a mode is picked the mirror shows only a hint, so it is never mistaken
for the outcome; picking a mode renders that mode's exact DELIVERED form (_delivered)
-- so "Strip to ASCII" reveals `rm -rf /` when the raw looked like a harmless `ram`:
the de-obfuscation a strip performs cannot hide behind a label. A single deliver button
(Paste / Copy / Replace) stays DISABLED, and carries NO colour (neither delivery is
unconditionally safe -- a strip de-obfuscates, a keep preserves deception), until a
mode is picked AND its anti-fat-finger countdown elapses -- so the delivered form is
ALWAYS seen before delivery is possible, and editing the held text re-arms the
countdown. ONLY Reject is coloured (safe-green): the one unconditionally-safe choice,
never gated (Esc rejects from anywhere). A copy (not executed) has no countdown. The
choice is dispatched back to the tab that held the text, the only path that lets it
cross.
"""

from typing import Callable, NotRequired, TypedDict, cast

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout, QPushButton, QPlainTextEdit,
    QRadioButton, QButtonGroup,
)

from secure_terminal.sanitize import (
    classify_paste, classify_paste_detail,
    sanitize_paste, sanitize_paste_unicode,
    sanitize_clipboard, sanitize_clipboard_display, sanitize_clipboard_unicode,
    paste_no_autosubmit,
)
from secure_terminal.terminal import SecureTerminal

# Semantic colours: the app's canonical safe-green and caution-red (the same values
# the mode lamps and risk dots use). SAFE_FG tints ONLY the Reject button (the one
# safe choice); RISK_FG is the risk dot. Chosen to clear the contrast guard
# (sanitize.too_close) against BOTH the light and the dark theme background, so they
# stay readable whatever the desktop palette -- unlike a foreground-only tint tuned
# for one theme. Pinned as constants so test_review.py can assert the contrast.
SAFE_FG = '#1f8a54'
RISK_FG = '#d83933'

# The seven hidden-character classes for the review table, most-alarming first
# (box-drawing last). Each row: (marking-class key, a monochrome technical glyph, a
# plain-language label). The glyph is coloured by the class's ON-SCREEN marking colour
# (SecureTerminal.MARKING_COLORS) so the table and the terminal never disagree, and the
# text label is ALWAYS shown, so a missing glyph font degrades to readable text rather
# than a blank. 'structural' (box-drawing) carries no risk tint on screen, so its glyph
# and count use the muted colour.
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
# Shown (safe-green) when a reviewed paste hides nothing -- a positive all-clear so an
# ASCII-only paste held for another reason (a multi-line paste) reads as safe.
_CLEAN_MSG = 'ASCII-only -- nothing hidden.'
# Radio-first choice: the two delivery MODES, shown as radios with NO default. Picking
# one previews its delivered form in the mirror and arms the single deliver button, so
# the delivered form is ALWAYS seen before delivery is possible.
_RADIO_STRIP = 'Strip to ASCII'
_RADIO_KEEP = 'Keep unicode'
# Shown in the mirror before a mode is picked, so the pane is never mistaken for the
# outcome (the old default-raw preview was read as "what will happen").
_MIRROR_HINT = 'Choose how to deliver above to preview exactly what it sends.'

# Everything that differs between the two directions. `dispatch` is the tab method
# the choice is routed to; `strip`/`keep` are the sanitizers the mirror uses to
# render EXACTLY what each action button would deliver (focusing a delivery button
# shows its outcome in the mirror), closing the "the delivered form is unseen" gap
# a homoglyph-obfuscated command could hide behind. `paste_newline` maps the shell's
# carriage return to a newline for display and drops the trailing auto-submit CR at a
# bare prompt, so the paste preview matches what actually reaches the pty.
class _Kind(TypedDict):
    """One trust direction's wording + sanitizers. Typed so self._kind['strip'] reads as a
    callable and the text keys as str (mypy) instead of a heterogeneous dict[str, object]."""
    summary: str
    summary_empty: str
    full_note: str
    subject: str
    reject: str
    reject_tip: str
    deliver: str
    stripped: str
    unicode: str
    dispatch: str
    strip: Callable[[str], str]
    keep: Callable[[str], str]
    paste_newline: NotRequired[bool]


_KINDS: dict[str, _Kind] = {
    'paste': {
        'summary': 'This paste hides %s.',
        # shown in "always" mode for a clean paste: no hidden characters to name.
        'summary_empty': 'Review this paste before it reaches the shell.',
        'full_note': 'the FULL paste still delivers',
        'subject': 'this paste',
        'reject': 'Reject',
        'reject_tip': 'Do not paste (Enter or Esc)',
        'deliver': 'Paste',
        'stripped': 'Paste (ASCII)',
        'unicode': 'Paste (unicode)',
        'dispatch': 'dispatch_pending_paste',
        'strip': sanitize_paste,
        'keep': sanitize_paste_unicode,
        'paste_newline': True,
    },
    'copy': {
        'summary': 'This copy would carry %s onto the clipboard.',
        'summary_empty': 'Review this copy before it reaches the clipboard.',
        'full_note': 'the FULL copy still reaches the clipboard',
        'subject': 'this copy',
        'reject': "Don't copy",
        'reject_tip': 'Do not copy (Enter or Esc)',
        'deliver': 'Copy',
        'stripped': 'Copy (ASCII)',
        'unicode': 'Copy (unicode)',
        'dispatch': 'dispatch_pending_copy',
        # the display-aware strip, so the mirror's stripped form matches what
        # dispatch_pending_copy('stripped') places (a box -> '_', never gone).
        'strip': sanitize_clipboard_display,
        'keep': sanitize_clipboard_unicode,
    },
    # The standalone clipboard sanitizer (clipboard_watch.py): text already ON the
    # system clipboard, reviewed before it is pasted elsewhere. Not a terminal
    # direction -- dispatch_pending_clipboard lives on a small holder object, not a
    # tab -- but the bar and mirror are identical.
    'clipboard': {
        'summary': 'This clipboard text hides %s.',
        'summary_empty': 'Review the clipboard text.',
        'full_note': 'the FULL clipboard text is still used',
        'subject': 'this clipboard text',
        'reject': 'Leave it',
        'reject_tip': 'Leave the clipboard unchanged (Enter or Esc)',
        'deliver': 'Replace',
        'stripped': 'Replace (ASCII)',
        'unicode': 'Replace (unicode)',
        'dispatch': 'dispatch_pending_clipboard',
        # plain ASCII strip -- raw clipboard content, not lifted from the display,
        # so the display-aware box->'_' rewrite does not apply.
        'strip': sanitize_clipboard,
        'keep': sanitize_clipboard_unicode,
    },
}


class ReviewBar(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self._term = None
        self._raw = ''
        # The beyond-cap tail: raw[_RAW_MAX:] held OUT of the edit widget (which loads only
        # the visible prefix), so an edit re-adopts prefix+tail and self._raw stays FULL --
        # the tail keeps delivering and scan_truncated stays honest (see _on_edit).
        self._raw_tail = ''
        # The chosen delivery MODE ('stripped'/'unicode'), or None until a radio is
        # picked. Picking one previews its delivered form in the mirror and ARMS the
        # single deliver button (disabled until then), so the delivered form is always
        # seen before delivery is possible. _delay is the anti-fat-finger countdown
        # (seconds) started on each mode pick; the deliver button stays disabled while it
        # runs. Reject is never gated.
        self._selected_action = None
        self._kind = _KINDS['paste']
        self._remaining = 0
        self._delay = 0
        self._countdown = QTimer(self)
        self._countdown.timeout.connect(self._tick)
        self.setObjectName('reviewbar')
        self.setVisible(False)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(6)

        # summary row: a red dot, the "what is hidden" headline, and the choices
        row = QHBoxLayout()
        row.setSpacing(8)
        # The risk dot recolours per review: RISK_FG when something is hidden, SAFE_FG
        # for an ASCII-only all-clear (set in show_review), so the dot never contradicts
        # the summary.
        self._dot = QLabel(self)
        self._dot.setFixedSize(14, 14)
        self._dot.setStyleSheet('background-color:%s; border-radius:7px;' % RISK_FG)
        row.addWidget(self._dot)
        # Selectable so the user can copy the summary + table text to ask about it.
        self._summary = QLabel('', self)
        self._summary.setStyleSheet('font-weight:bold;')
        self._summary.setWordWrap(True)
        self._summary.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self._summary, 1)
        # Only Reject is coloured (safe-green): it is the one unconditionally-safe choice
        # (nothing crosses) and is never gated -- Enter/Esc always back out. The single
        # DELIVER button carries NO colour (neither delivery is safe in general -- a strip
        # DE-OBFUSCATES a homoglyph command, a keep preserves the deception) and stays
        # DISABLED until a mode radio is picked and the countdown elapses; the mirror is
        # where the truth (the delivered form) is shown.
        self._reject = QPushButton('Reject', self)
        self._reject.setStyleSheet('color:%s; font-weight:600;' % SAFE_FG)
        self._reject.clicked.connect(lambda: self._choose('reject'))
        row.addWidget(self._reject)
        self._deliver = QPushButton('Paste', self)
        self._deliver.setEnabled(False)
        self._deliver.clicked.connect(self._deliver_clicked)
        row.addWidget(self._deliver)
        outer.addLayout(row)

        # The held text, EDITABLE before delivery: the user can trim the risky part.
        # Every edit re-runs the classifier (summary + breakdown) and re-renders the
        # mirror, and delivery sends EXACTLY this buffer (re-sanitized per the chosen
        # action), so what is shown is what crosses -- an edit cannot bypass the
        # neutralization. NoWrap so a long line is not visually re-flowed under the eye.
        self._edit = QPlainTextEdit(self)
        self._edit.setMaximumHeight(70)
        self._edit.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        # Tab moves focus OUT of the field (to the radios / buttons) instead of inserting
        # a tab, so a keyboard-only user can reach the delivery radios -- a QPlainTextEdit
        # otherwise swallows Tab. (Enter still inserts a newline here, as any text editor;
        # Esc rejects from anywhere -- keyPressEvent.)
        self._edit.setTabChangesFocus(True)
        self._edit.textChanged.connect(self._on_edit)
        outer.addWidget(self._edit)

        # The breakdown beneath the summary: a Structure section (lines, the never-auto-
        # run guarantee, length) and a per-class hidden-character table. Rich text so a
        # glyph can carry its risk colour; selectable so the user can copy any of it.
        # Populated per review in _set_detail (empty text collapses it to nothing).
        self._detail = QLabel('', self)
        self._detail.setTextFormat(Qt.TextFormat.RichText)
        self._detail.setWordWrap(True)
        self._detail.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        outer.addWidget(self._detail)

        # The delivery MODE, chosen by radio with NO default: picking one previews its
        # delivered form in the mirror (below) and arms the deliver button. Exclusive.
        radio_row = QHBoxLayout()
        radio_row.setSpacing(12)
        radio_row.addWidget(QLabel('Deliver as:', self))
        self._radio_strip = QRadioButton(_RADIO_STRIP, self)
        self._radio_keep = QRadioButton(_RADIO_KEEP, self)
        self._radio_group = QButtonGroup(self)
        self._radio_group.setExclusive(True)
        self._radio_group.addButton(self._radio_strip)
        self._radio_group.addButton(self._radio_keep)
        self._radio_strip.clicked.connect(lambda: self._on_radio('stripped'))
        self._radio_keep.clicked.connect(lambda: self._on_radio('unicode'))
        radio_row.addWidget(self._radio_strip)
        radio_row.addWidget(self._radio_keep)
        radio_row.addStretch(1)
        outer.addLayout(radio_row)

        # The single mirror pane: a read-only terminal view that renders the held
        # text through the SAME pipeline as the tab, so risk-class colouring and
        # click-to-inspect come for free. Always visible while the bar is open (a
        # fast visual review, no toggle); it follows the tab's mode/theme/font via
        # rerender_mirror.
        self._mirror = SecureTerminal(preview=True)
        self._mirror.setMinimumHeight(120)
        outer.addWidget(self._mirror)

    # -- lifecycle ------------------------------------------------------------
    def show_review(self, term, raw, delay, kind='paste'):
        """Show the bar for `term`'s held text `raw`, in the given direction
        ('paste' or 'copy'). No mode is picked yet, so the deliver button is disabled; the
        anti-fat-finger countdown starts on the first mode pick (`delay` seconds). Focus
        lands on Reject; Esc rejects from anywhere, and Enter rejects from a button (the
        default button) -- but inserts a newline while focus is in the editable held-text
        field, as in any text editor. Nothing crosses until a delivery is chosen."""
        self._term = term
        self._raw = raw
        self._kind = _KINDS.get(kind, _KINDS['paste'])
        self._reject.setText(self._kind['reject'])
        self._reject.setToolTip(self._kind['reject_tip'])
        # each review opens with NO mode picked: the mirror shows the hint and the
        # deliver button is disabled until a radio is chosen.
        self._selected_action = None
        self._delay = max(0, int(delay))
        self._remaining = 0
        self._countdown.stop()
        # Clear both radios. An exclusive group will not let setChecked(False) uncheck
        # the checked one, so drop exclusivity to clear, then restore it.
        self._radio_group.setExclusive(False)
        self._radio_strip.setChecked(False)
        self._radio_keep.setChecked(False)
        self._radio_group.setExclusive(True)
        # Show the held text in the editable field; block the change signal so
        # populating it here does not recurse into _on_edit. Cap what the QPlainTextEdit
        # loads to the mirror's budget: the paste/copy path pre-caps _raw at the terminal
        # source, but the CLIPBOARD path passes the whole clipboard, so an unbounded
        # setPlainText (a 20M-char clipboard) freezes the UI / balloons memory. self._raw
        # stays FULL so an un-edited Replace still sanitizes the entire clipboard; the
        # over-cap truncation is already DISCLOSED by _refresh_review's notice. The
        # beyond-cap tail is stashed in self._raw_tail so an edit of the visible prefix
        # re-adopts prefix+tail (keeping self._raw FULL) instead of silently DROPPING the
        # tail -- which would flip scan_truncated to a false-green "nothing hidden".
        self._raw_tail = raw[self._mirror._RAW_MAX:]
        self._edit.blockSignals(True)
        self._edit.setPlainText(raw[:self._mirror._RAW_MAX])
        self._edit.blockSignals(False)
        self._refresh_review()
        self._update_deliver()
        self.setVisible(True)
        self._reject.setDefault(True)
        self._reject.setFocus()

    def _on_edit(self):
        """The user edited the held text: adopt it and refresh everything from it, so
        the summary, breakdown, mirror -- and what delivery sends -- all track the
        edited buffer. The edit widget holds only the visible prefix (capped at _RAW_MAX);
        re-append the stashed beyond-cap tail so self._raw stays FULL -- otherwise the
        first edit truncates it, flipping scan_truncated to a false-green 'nothing hidden'
        that hides a beyond-cap char, and silently dropping the tail from delivery."""
        self._raw = self._edit.toPlainText() + self._raw_tail
        self._refresh_review()          # keeps the selected mode; re-previews its outcome
        # Editing changes what would be delivered, so RE-ARM the countdown when a mode is
        # picked: the edited content must be reviewed for the delay too, never delivered
        # instantly on the original text's already-elapsed countdown.
        if self._selected_action in ('stripped', 'unicode'):
            self._arm_countdown()
        else:
            self._update_deliver()

    def _refresh_review(self):
        """Recompute the summary, breakdown and mirror from the CURRENT held text
        (self._raw). Called on show and on every edit, so the bar always reflects
        exactly what delivery will send.

        classify_paste[_detail] cap their input to the mirror's budget: on a 50-100MB
        clipboard a full scan would run for tens of seconds on the Qt thread while
        terminal input is already suspended -- a hung window the user cannot even reject
        from. A hidden char beyond the cap is then uncounted, but the truncation notice
        fires (raw > _RAW_MAX), so the partial count is DISCLOSED, not silent."""
        term = self._term
        if term is None:
            return
        capped = self._raw[:self._mirror._RAW_MAX]
        detail = classify_paste_detail(capped)
        parts = ['%d %s%s' % (n, label, '' if n == 1 else 's')
                 for label, n in classify_paste(capped)]
        # TWO different truncations, not one. The classifier caps by SOURCE character count
        # (scan_truncated -> the hidden-char count and the length are PARTIAL). The mirror
        # render caps by RENDERED size (render_truncated -> the pane shows only a prefix;
        # detail badges expand ~30x, so this trips far earlier). A non-ASCII paste well
        # under the char cap trips ONLY the render cap -- its counts are COMPLETE and must
        # never read as a partial scan.
        scan_truncated = len(self._raw) > self._mirror._RAW_MAX
        # Paint what the pane SHOWS -- the selected mode's delivered form, or the hint until a
        # mode is picked -- and read render-truncation from THAT, never a throwaway raw render:
        # the delivered form (e.g. a stripped 'hello') or the hint is usually far shorter, so a
        # raw-based flag would falsely claim the VISIBLE pane is clipped. (grok)
        if self._selected_action in ('stripped', 'unicode'):
            self._render_mirror(term, self._delivered(self._selected_action))
            render_truncated = bool(getattr(self._mirror, '_preview_truncated', False))
        else:
            self._render_mirror(term, _MIRROR_HINT, markings=False)
            render_truncated = False        # the hint is fixed text -- never truncated
        hidden = sum(detail['counts'].values())
        # A confident ASCII-only all-clear needs the whole paste SCANNED; render truncation
        # does not undercount (the scan already covered it), so it does not block the claim.
        if hidden == 0 and not scan_truncated:
            summary = _CLEAN_MSG
            dot_fg = SAFE_FG
        else:
            summary = (self._kind['summary'] % ', '.join(parts)
                       if parts else self._kind['summary_empty'])
            dot_fg = RISK_FG
        self._dot.setStyleSheet('background-color:%s; border-radius:7px;' % dot_fg)
        # Disclose each truncation for what it is (unspoofable chrome, not the pane a paste
        # could forge). SCAN truncation understates the count -- Reject if you cannot verify
        # the rest. RENDER truncation only shortens the PANE; the scan is complete, so it is
        # a milder note. full_note names the real action (paste delivers / copy reaches the
        # clipboard).
        if scan_truncated:
            summary += ('  [truncated: only the first {:,} characters were scanned for '
                        'hidden characters, so the count may be partial -- {}; Reject if '
                        'you cannot verify the rest]'.format(self._mirror._RAW_MAX,
                                                             self._kind['full_note']))
        elif render_truncated:
            summary += ('  [the preview below shows only the first part of {}, but the whole '
                        'of it WAS scanned for hidden characters -- {}]'
                        .format(self._kind['subject'], self._kind['full_note']))
        self._summary.setText(summary)
        self._set_detail(detail, term, scan_truncated)

    def _set_detail(self, detail, term, truncated):
        """Populate the breakdown label from a classify_paste_detail result: a Structure
        section (lines, the never-auto-run guarantee for a paste, length) and a per-class
        hidden-character table. Each present class's glyph carries its ON-SCREEN marking
        colour (SecureTerminal.MARKING_COLORS) so the table and the terminal never
        disagree; absent classes stay muted, so what is NOT present is explicit. Rich
        text via <font> tags, which Qt's QLabel renders reliably."""
        theme = getattr(term, '_theme', 'dark')
        # MARKING_COLORS is an untyped nested class attribute -> its values read as object;
        # name the concrete shape here so palette[class]['fg'] indexes cleanly (mypy).
        palette = cast('dict[str, dict[str, str]]', SecureTerminal.MARKING_COLORS.get(
            theme, SecureTerminal.MARKING_COLORS['dark']))

        def _row(glyph, color, name, value):
            return ('<tr><td><font color="%s">%s</font></td>'
                    '<td>&nbsp;%s&nbsp;&nbsp;</td><td>%s</td></tr>'
                    % (color, glyph, name, value))

        # On a truncated review the counts are of the SCANNED PREFIX, not the full
        # paste (which still delivers whole), so mark them ">= N" rather than present
        # the cap as a definite total.
        multiline = detail['multiline']
        plus = '+' if truncated else ''
        # Only the PASTE direction executes the lines; a copy/clipboard review runs
        # nothing, so reserve the "runs more than one command" wording for paste (gated
        # like the "If accepted" row below) and use neutral wording elsewhere.
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
            # never-auto-run is UNCONDITIONAL for a reviewed paste: at a shell prompt the
            # trailing submit CR is stripped (paste_no_autosubmit); a bracketed program
            # receives the paste as inert text. Either way it cannot run on its own, so
            # this row always states the safe guarantee (only the wording varies).
            bracketed = (hasattr(term, '_bracketed_paste_active')
                         and term._bracketed_paste_active())
            note = ('your program receives it as text' if bracketed
                    else 'waits on the command line -- press Enter to run')
            struct.append(_row(_SAFE_GLYPH, SAFE_FG, 'If accepted', note))
        length = ('%d+ characters (scanned prefix; full paste is larger)'
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

    def _delivered(self, action):
        """The full sanitized text `action` would deliver, formatted for display -- so
        the mirror shows what actually crosses: a stripped homoglyph revealed as its
        ASCII, the trailing auto-submit CR dropped at a bare prompt, embedded carriage
        returns shown as newlines.

        It shows the WHOLE delivered content, which is a SUPERSET of any single click:
        for a non-bracketed MULTI-line paste _dispatch_paste delivers only line 1 on
        the click and holds the rest for later paste gestures (see _insert_next_staged),
        so the mirror lists every line that will run rather than modelling that
        line-by-line staging. This never UNDERSTATES/hides what crosses (the point) --
        the de-obfuscated, dangerous lines are all shown; it just does not imply one
        atomic delivery."""
        sanitizer = self._kind['strip'] if action == 'stripped' else self._kind['keep']
        # Bound the materialization: sanitizing an UNBOUNDED paste here (a 50MB clipboard
        # -> ~8.6s / ~0.5GB) would freeze or OOM the UI on a mere button hover, BEFORE the
        # mirror's render cap ever runs. Sanitize only a bounded source prefix -- the
        # sanitizers are per-character and length-non-increasing, so this stays a true
        # prefix of the delivered form, and render_preview caps the render further; the
        # truncation notice already fires from _refresh_review.
        raw = self._raw[:self._mirror._RAW_MAX]
        # Whole-paste check BEFORE the collapse (which shrinks len): the trailing-submit
        # strip below applies only when the preview is the FULL paste.
        whole = len(raw) >= len(self._raw)
        # Collapse a Windows CRLF PAIR to one newline BEFORE sanitizing, exactly as
        # _dispatch_paste does: sanitize maps EACH of \r and \n to '\r', so an uncollapsed
        # '\r\n' becomes '\r\r' -- a phantom blank line the mirror would show but delivery
        # never sends, contradicting the Lines count (which also collapses). (claude)
        raw = raw.replace('\r\n', '\n')
        sent = sanitizer(raw)
        if self._kind.get('paste_newline'):
            term = self._term
            if term is not None and hasattr(term, '_bracketed_paste_active') \
                    and not term._bracketed_paste_active() \
                    and whole:
                # Strip the trailing submit CR ONLY when the preview shows the WHOLE
                # paste. On a TRUNCATED preview the trailing byte is mid-paste content
                # -- an embedded newline that WILL auto-run the lines before it -- not
                # the final submit; stripping it would deceptively show a safe prompt
                # wait while delivery auto-executes. Left in, it renders as \n below so
                # the user sees the embedded run.
                # Deliberate SAFE-direction limit: if everything after the cap sanitizes
                # to nothing (e.g. a trailing NUL run), delivery WOULD strip the boundary
                # newline, so showing it OVER-states the run. Determining that needs
                # unbounded tail sanitization (the DoS this cap exists to stop), so we
                # err toward showing it -- a false alarm, never a hidden auto-run -- and
                # the truncation notice tells the user to reject what they cannot verify.
                sent = paste_no_autosubmit(sent)
            sent = sent.replace('\r', '\n')
        return sent

    def _render_mirror(self, term, content, markings=True):
        """Render `content` into the mirror the way the reviewed tab would -- its CURRENT
        display mode, theme, font and zoom. Risk-class colouring is forced ON (markings)
        even if the tab has it off -- the review pane exists to REVEAL risk. The line path
        is used deliberately: a review surface must SHOW control/hidden characters (named,
        tinted, click-to-inspect), not run them through a pyte grid that would consume
        them. Also sets self._mirror._preview_truncated for the caller."""
        theme = getattr(term, '_theme', 'dark')
        family = term.current_font_family() \
            if hasattr(term, 'current_font_family') else None
        mode = term.current_mode() if hasattr(term, 'current_mode') else 'detail'
        self._mirror.apply_theme(theme)
        if family:
            self._mirror.set_font_family(family)
        if hasattr(term, 'current_zoom'):
            self._mirror.apply_zoom(term.current_zoom())   # follow the tab's zoom
        self._mirror.render_preview(content, mode=mode, markings=markings)

    def rerender_mirror(self):
        """Re-render the mirror to follow a live change (mode/theme/font/zoom) on
        the reviewed tab. No-op when no review is open (_term is None iff a review
        is showing), so the window can call it unconditionally from its
        mode/theme/font setters."""
        if self._term is None:
            return
        self._refresh_review()

    def hide_review(self):
        """Hide the bar and stop the countdown; called when the text is resolved."""
        self._countdown.stop()
        self._term = None
        self.setVisible(False)

    def reviewed_term(self):
        """The terminal whose held text this bar is reviewing, or None -- so a
        closing tab can hide its own review before the terminal is destroyed."""
        return self._term

    # -- internals ------------------------------------------------------------
    def _arm_countdown(self):
        """(Re)start the anti-fat-finger countdown that gates the deliver button. Called on
        every mode pick AND every edit, so the CURRENTLY-shown outcome always gets the full
        delay before it can be delivered -- editing to new content after the button already
        enabled must NOT inherit the elapsed countdown of the original held text."""
        self._remaining = self._delay
        if self._remaining > 0:
            self._countdown.start(1000)
        else:
            self._countdown.stop()
        self._update_deliver()

    def _on_radio(self, action):
        """A delivery MODE was picked: preview its delivered form in the mirror and start
        the countdown that arms the deliver button. Switching modes re-previews and
        restarts the countdown, so the shown outcome and the armed button always match."""
        self._selected_action = action
        self._refresh_review()          # mirror now shows this mode's delivered form
        self._arm_countdown()

    def _update_deliver(self):
        """Sync the deliver button to the current state: disabled with a hint until a
        mode is picked, then a countdown, then enabled. Its label names the chosen mode
        so the button and the previewed outcome cannot disagree."""
        if self._selected_action not in ('stripped', 'unicode'):
            self._deliver.setText(self._kind['deliver'])
            self._deliver.setEnabled(False)
            self._deliver.setToolTip('Choose "%s" or "%s" first'
                                     % (_RADIO_STRIP, _RADIO_KEEP))
            return
        # literal keys: _selected_action is 'stripped'/'unicode' here, but a TypedDict
        # index needs a literal, not the variable.
        base = (self._kind['stripped'] if self._selected_action == 'stripped'
                else self._kind['unicode'])
        if self._remaining > 0:
            self._deliver.setText('%s (%d)' % (base, self._remaining))
            self._deliver.setEnabled(False)
            self._deliver.setToolTip('Review the preview -- ready in %d s'
                                     % self._remaining)
        else:
            self._deliver.setText(base)
            self._deliver.setEnabled(True)
            self._deliver.setToolTip('')

    def _deliver_clicked(self):
        """The deliver button: send the selected mode. The button is disabled until a
        mode is picked and the countdown elapses, but re-check in case a click races the
        timer."""
        if self._selected_action in ('stripped', 'unicode') and self._remaining <= 0:
            self._choose(self._selected_action)

    def _choose(self, action):
        # Single-shot: clear _term before dispatching so a second click (a
        # double-click, or Esc right after) is a no-op.
        term = self._term
        if term is None:
            return
        self._term = None
        self._countdown.stop()
        # Deliver the CURRENT (possibly edited) buffer, not the originally held text --
        # still sanitized on the way out, so an edit cannot bypass the neutralization.
        getattr(term, self._kind['dispatch'])(action, self._raw)
        # HIDE the bar directly: this bar made a definitive choice on the term it was
        # showing, so it must close. We cannot rely on the paste_review_resolved ->
        # _hide_paste_review path here, because that path guards on reviewed_term()
        # (to avoid a cross-tab resolution tearing down another tab's re-shown bar)
        # and we just cleared _term above -- so the guarded hide would be skipped and
        # the bar would stay open after the click.
        self.hide_review()

    def _tick(self):
        if self._remaining > 0:
            self._remaining -= 1
        self._update_deliver()
        if self._remaining <= 0:
            self._countdown.stop()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self._choose('reject')
            return
        super().keyPressEvent(event)
