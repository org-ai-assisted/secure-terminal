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

The bar shows a one-line summary of what is hidden plus a SINGLE mirror pane: a
read-only terminal view that renders through the SAME pipeline as the tab it came
from, so a homoglyph is tinted and each character is click-to-inspect exactly as in
the terminal. The pane FOLLOWS the reviewed tab live -- its display mode
(box/show/reveal/detail), theme, font and zoom -- so flipping the tab's mode with
the normal shortcut re-renders it (rerender_mirror). There is no preview-only render
branch, so a "works live, wrong in the review box" divergence cannot recur.
Risk-class colouring stays ON regardless of the tab's markings setting: revealing
risk is the pane's whole job.

Crucially the pane shows what each choice DELIVERS, not just the raw text: by
default it shows the held text, but FOCUSING or HOVERING a delivery button
re-renders it to that button's exact delivered form (_delivered). So focusing
"Paste (ASCII)" reveals `rm -rf /` when the raw looked like a harmless `ram` --
the de-obfuscation a strip performs cannot hide behind a label. Three choices:
Reject / Don't copy / Leave it (default, and what Enter/Esc do while the text is
held), the ASCII action (stripped), and the unicode action (printable unicode
kept). ONLY Reject is coloured (safe-green): it is the one unconditionally-safe
choice. The two delivery buttons are UNCOLOURED on purpose -- neither is safe in
general (stripping de-obfuscates, keeping preserves deception), so a green there
would mislead; the mirror shows the truth. For a paste both action buttons are
countdown-gated so a stray click cannot run it; a copy (not executed) has no
countdown. The choice is dispatched back to the tab that held the text, the only
path that lets it cross.
"""

from PyQt6.QtCore import Qt, QTimer, QEvent
from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout, QPushButton,
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
        ('nonascii',   0x6587, 'Other non-ASCII'),          # a CJK sample: honest foreign
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

# Everything that differs between the two directions. `dispatch` is the tab method
# the choice is routed to; `strip`/`keep` are the sanitizers the mirror uses to
# render EXACTLY what each action button would deliver (focusing a delivery button
# shows its outcome in the mirror), closing the "the delivered form is unseen" gap
# a homoglyph-obfuscated command could hide behind. `paste_newline` maps the shell's
# carriage return to a newline for display and drops the trailing auto-submit CR at a
# bare prompt, so the paste preview matches what actually reaches the pty.
_KINDS = {
    'paste': {
        'summary': 'This paste hides %s.',
        # shown in "always" mode for a clean paste: no hidden characters to name.
        'summary_empty': 'Review this paste before it reaches the shell.',
        'full_note': 'the FULL paste still delivers',
        'reject': 'Reject',
        'reject_tip': 'Do not paste (Enter or Esc)',
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
        'reject': "Don't copy",
        'reject_tip': 'Do not copy (Enter or Esc)',
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
        'reject': 'Leave it',
        'reject_tip': 'Leave the clipboard unchanged (Enter or Esc)',
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
        # which delivery action's OUTCOME the mirror is previewing (None = the raw
        # held text). Focusing/hovering a delivery button shows exactly what it would
        # send, so an obfuscated command's de-obfuscated, auto-submitting form cannot
        # stay hidden behind the button label. _focused/_hovered track the delivery
        # buttons' keyboard-focus and mouse-hover so the preview is derived
        # focus-first (see eventFilter) and never goes stale.
        self._preview_action = None
        self._focused = None
        self._hovered = None
        self._kind = _KINDS['paste']
        self._remaining = 0
        # True while the anti-fat-finger countdown is up: the delivery buttons stay
        # ENABLED (so focusing/hovering one previews its delivered form -- the whole
        # point of the countdown window), but a delivery CLICK is ignored until it
        # elapses. Reject is never gated.
        self._gated = False
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
        # Only Reject is coloured (green): it is the one unconditionally-safe choice
        # (nothing crosses). The two DELIVERY buttons carry NO colour on purpose --
        # neither delivery is safe in general (stripping DE-OBFUSCATES a homoglyph
        # command, keeping preserves the deception), so a "safe" tint on either would
        # mislead. The mirror (delivered-form-on-focus) is where the truth is shown.
        self._reject = QPushButton('Reject', self)
        self._reject.setStyleSheet('color:%s; font-weight:600;' % SAFE_FG)
        self._reject.clicked.connect(lambda: self._choose('reject'))
        row.addWidget(self._reject)
        self._stripped = QPushButton('Paste (ASCII)', self)
        self._stripped.clicked.connect(lambda: self._choose('stripped'))
        row.addWidget(self._stripped)
        self._unicode = QPushButton('Paste (unicode)', self)
        self._unicode.clicked.connect(lambda: self._choose('unicode'))
        row.addWidget(self._unicode)
        outer.addLayout(row)

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

        # Focusing or hovering a delivery button previews its OUTCOME in the mirror.
        # The action buttons are countdown-gated, so the user has time to focus one
        # and SEE what it delivers before it becomes clickable.
        self._stripped.installEventFilter(self)
        self._unicode.installEventFilter(self)

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
        ('paste' or 'copy'), gating the action buttons for `delay` seconds. Focus
        lands on Reject so Enter/Esc reject and nothing crosses until a choice."""
        self._term = term
        self._raw = raw
        self._kind = _KINDS.get(kind, _KINDS['paste'])

        # classify_paste[_detail] are the uncapped materializations in show_review: on a
        # 50-100MB clipboard a full scan runs for tens of seconds on the Qt thread BEFORE
        # the bar (and its Reject button) can appear, while terminal input is already
        # suspended -- a hung window the user cannot even reject from. Cap the input to
        # the same budget the mirror uses; a hidden char beyond the cap is then uncounted,
        # but the truncation notice below fires (raw > _RAW_MAX), so the partial count is
        # disclosed, not silent.
        capped = raw[:self._mirror._RAW_MAX]
        detail = classify_paste_detail(capped)
        parts = ['%d %s%s' % (n, label, '' if n == 1 else 's')
                 for label, n in classify_paste(capped)]
        self._reject.setText(self._kind['reject'])
        self._reject.setToolTip(self._kind['reject_tip'])
        # each review opens on the raw text, with no button focused or hovered
        self._preview_action = None
        self._focused = None
        self._hovered = None
        self._render_mirror(term)         # caps a huge render; sets _preview_truncated
        truncated = bool(getattr(self._mirror, '_preview_truncated', False))
        hidden = sum(detail['counts'].values())
        # A confident ASCII-only all-clear (green dot + positive summary) ONLY when the
        # WHOLE paste was scanned: a truncated scan cannot promise nothing hides past the
        # cap, so it keeps the cautious summary and the truncation notice below.
        if hidden == 0 and not truncated:
            summary = _CLEAN_MSG
            dot_fg = SAFE_FG
        else:
            summary = (self._kind['summary'] % ', '.join(parts)
                       if parts else self._kind['summary_empty'])
            dot_fg = RISK_FG
        self._dot.setStyleSheet('background-color:%s; border-radius:7px;' % dot_fg)
        # The mirror bounds its RENDER (render_preview) so a multi-MB paste cannot hang
        # the pane, and the scan above reads only the same first _RAW_MAX chars. Delivery
        # still sends the WHOLE text, so a truncated review must SAY that both the shown
        # text AND the hidden-char count are partial, in unspoofable chrome (this label,
        # not the terminal pane a paste could forge). full_note names the real action
        # per direction (paste delivers / copy reaches the clipboard).
        if truncated:
            summary += ('  [truncated: only the first {:,} characters are shown and '
                        'scanned for hidden characters -- {}; Reject if you cannot '
                        'verify the rest]'.format(self._mirror._RAW_MAX,
                                                  self._kind['full_note']))
        self._summary.setText(summary)
        self._set_detail(detail, term, truncated)

        self._remaining = max(0, int(delay))
        self._gate(self._remaining > 0)
        self._tick_labels()
        if self._remaining > 0:
            self._countdown.start(1000)
        self.setVisible(True)
        self._reject.setDefault(True)
        self._reject.setFocus()

    def _set_detail(self, detail, term, truncated):
        """Populate the breakdown label from a classify_paste_detail result: a Structure
        section (lines, the never-auto-run guarantee for a paste, length) and a per-class
        hidden-character table. Each present class's glyph carries its ON-SCREEN marking
        colour (SecureTerminal.MARKING_COLORS) so the table and the terminal never
        disagree; absent classes stay muted, so what is NOT present is explicit. Rich
        text via <font> tags, which Qt's QLabel renders reliably."""
        theme = getattr(term, '_theme', 'dark')
        palette = SecureTerminal.MARKING_COLORS.get(
            theme, SecureTerminal.MARKING_COLORS['dark'])

        def _row(glyph, color, name, value):
            return ('<tr><td><font color="%s">%s</font></td>'
                    '<td>&nbsp;%s&nbsp;&nbsp;</td><td>%s</td></tr>'
                    % (color, glyph, name, value))

        multiline = detail['multiline']
        lines_val = ('%d &nbsp;(multi-line -- runs more than one command)'
                     % detail['lines'] if multiline else '%d' % detail['lines'])
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
        struct.append(_row('', _MUTED_FG, 'Length', '%d characters (%d bytes)'
                           % (detail['chars'], detail['bytes'])))

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
        # truncation notice already fires from the raw-path render in show_review.
        raw = self._raw[:self._mirror._RAW_MAX]
        sent = sanitizer(raw)
        if self._kind.get('paste_newline'):
            term = self._term
            if term is not None and hasattr(term, '_bracketed_paste_active') \
                    and not term._bracketed_paste_active() \
                    and len(raw) >= len(self._raw):
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

    def _render_mirror(self, term):
        """Render into the mirror pane the way the reviewed tab would -- its CURRENT
        display mode, theme, font and zoom. When a delivery action is being previewed
        (_preview_action set by focusing/hovering its button) the mirror shows that
        action's DELIVERED form; otherwise the RAW held text. Risk-class colouring is
        forced ON (markings=True) even if the tab has it off -- the review pane exists
        to REVEAL risk. The line path is used deliberately: a review surface must SHOW
        control/hidden characters (named, tinted, click-to-inspect), not run them
        through a pyte grid that would consume them."""
        theme = getattr(term, '_theme', 'dark')
        family = term.current_font_family() \
            if hasattr(term, 'current_font_family') else None
        mode = term.current_mode() if hasattr(term, 'current_mode') else 'detail'
        self._mirror.apply_theme(theme)
        if family:
            self._mirror.set_font_family(family)
        if hasattr(term, 'current_zoom'):
            self._mirror.apply_zoom(term.current_zoom())   # follow the tab's zoom
        text = self._delivered(self._preview_action) \
            if self._preview_action in ('stripped', 'unicode') else self._raw
        self._mirror.render_preview(text, mode=mode, markings=True)

    def _set_preview(self, action):
        """Switch the mirror between the raw held text (action=None) and a delivery
        action's outcome, re-rendering only on a real change."""
        if action == self._preview_action or self._term is None:
            return
        self._preview_action = action
        self._render_mirror(self._term)

    def eventFilter(self, obj, event):
        # Track focus and hover on the two delivery buttons from their events, then
        # derive the previewed action FOCUS-FIRST. Keyboard Enter/Space commits the
        # FOCUSED button, so the mirror must show that button's outcome whenever one
        # is focused -- otherwise un-hovering a button while its sibling keeps focus
        # would leave the mirror stale on the un-hovered outcome, letting Enter
        # dispatch a payload the mirror is not showing. Re-derived on EVERY event so
        # the preview can never go stale.
        action = ('stripped' if obj is self._stripped
                  else 'unicode' if obj is self._unicode else None)
        if action is not None:
            et = event.type()
            if et == QEvent.Type.FocusIn:
                self._focused = action
            elif et == QEvent.Type.FocusOut and self._focused == action:
                self._focused = None
            elif et == QEvent.Type.Enter:
                self._hovered = action
            elif et == QEvent.Type.Leave and self._hovered == action:
                self._hovered = None
            self._set_preview(self._focused or self._hovered)
        return super().eventFilter(obj, event)

    def rerender_mirror(self):
        """Re-render the mirror to follow a live change (mode/theme/font/zoom) on
        the reviewed tab. No-op when no review is open (_term is None iff a review
        is showing), so the window can call it unconditionally from its
        mode/theme/font setters."""
        if self._term is None:
            return
        self._render_mirror(self._term)

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
    def _choose(self, action):
        # Single-shot: clear _term before dispatching so a second click (a
        # double-click, or Esc right after) is a no-op.
        term = self._term
        if term is None:
            return
        # Anti-fat-finger: while the countdown is up, a DELIVERY choice is ignored (the
        # buttons stay enabled only so the preview works). Reject is never gated -- it
        # is the safe choice, and Esc/Enter must always be able to back out.
        if self._gated and action in ('stripped', 'unicode'):
            return
        self._term = None
        self._countdown.stop()
        getattr(term, self._kind['dispatch'])(action)
        # HIDE the bar directly: this bar made a definitive choice on the term it was
        # showing, so it must close. We cannot rely on the paste_review_resolved ->
        # _hide_paste_review path here, because that path guards on reviewed_term()
        # (to avoid a cross-tab resolution tearing down another tab's re-shown bar)
        # and we just cleared _term above -- so the guarded hide would be skipped and
        # the bar would stay open after the click.
        self.hide_review()

    def _gate(self, disabled):
        # Do NOT setEnabled(False): a DISABLED Qt button cannot take keyboard focus and
        # does not reliably receive hover, so the delivered-form preview (focus/hover a
        # delivery button) would be dead during the very countdown it exists for. Keep
        # the buttons enabled -- so the preview works -- and gate the CLICK in _choose.
        # The "(N)" countdown suffix on the labels is the visible not-yet cue.
        self._gated = disabled

    def _tick_labels(self):
        suffix = ' (%d)' % self._remaining if self._remaining > 0 else ''
        self._stripped.setText(self._kind['stripped'] + suffix)
        self._unicode.setText(self._kind['unicode'] + suffix)

    def _tick(self):
        if self._remaining > 0:
            self._remaining -= 1
        self._tick_labels()
        if self._remaining <= 0:
            self._gate(False)
            self._countdown.stop()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self._choose('reject')
            return
        super().keyPressEvent(event)
