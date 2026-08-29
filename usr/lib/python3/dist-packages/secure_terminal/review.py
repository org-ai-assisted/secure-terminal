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
read-only terminal view that renders the held text through the SAME pipeline as
the tab it came from, so a homoglyph is tinted and each character is
click-to-inspect exactly as in the terminal. The pane FOLLOWS the reviewed tab
live -- its display mode (box/show/reveal/detail), theme and font -- so flipping
the tab's mode with the normal shortcut re-renders the pane (rerender_mirror).
There is no preview-only render branch, so a "works live, wrong in the review box"
divergence cannot recur. Risk-class colouring stays ON in the pane regardless of
the tab's markings setting: revealing risk is the pane's whole job.

Three choices carry the "what is delivered" distinction in their LABELS (the
side-by-side strip-vs-keep panes are intentionally dropped): Reject / Don't copy
(default, and what Enter/Esc do while the text is held), the stripped action
(ASCII only), and the with-unicode action (printable unicode kept). For a paste
both action buttons are countdown-gated so a stray click cannot run it; a copy
(not executed) has no countdown. The choice is dispatched back to the tab that
held the text, the only path that lets it cross.
"""

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QLabel, QHBoxLayout, QVBoxLayout, QPushButton,
)

from secure_terminal.sanitize import classify_paste
from secure_terminal.terminal import SecureTerminal

# Semantic button/dot colours: the app's canonical safe-green and caution-red (the
# same values the mode lamps and risk dots use). Chosen to clear the contrast guard
# (sanitize.too_close) against BOTH the light and the dark theme background, so the
# send buttons and the risk dot stay readable whatever the desktop palette -- unlike
# a foreground-only tint tuned for one theme. Pinned as constants so test_review.py
# can assert the contrast directly.
SAFE_FG = '#1f8a54'
RISK_FG = '#d83933'

# Everything that differs between the two directions. `dispatch` is the tab method
# the choice is routed to; the two action-button LABELS carry the strip-vs-keep
# "what is delivered" distinction (there are no per-outcome preview panes).
_KINDS = {
    'paste': {
        'summary': 'This paste hides %s.',
        # shown in "always" mode for a clean paste: no hidden characters to name.
        'summary_empty': 'Review this paste before it reaches the shell.',
        'reject': 'Reject',
        'reject_tip': 'Do not paste (Enter or Esc)',
        'stripped': 'Paste stripped',
        'unicode': 'Paste with unicode',
        'dispatch': 'dispatch_pending_paste',
    },
    'copy': {
        'summary': 'This copy would carry %s onto the clipboard.',
        'summary_empty': 'Review this copy before it reaches the clipboard.',
        'reject': "Don't copy",
        'reject_tip': 'Do not copy (Enter or Esc)',
        'stripped': 'Copy stripped',
        'unicode': 'Copy with unicode',
        'dispatch': 'dispatch_pending_copy',
    },
    # The standalone clipboard sanitizer (clipboard_watch.py): text already ON the
    # system clipboard, reviewed before it is pasted elsewhere. Not a terminal
    # direction -- dispatch_pending_clipboard lives on a small holder object, not a
    # tab -- but the bar and mirror are identical.
    'clipboard': {
        'summary': 'This clipboard text hides %s.',
        'summary_empty': 'Review the clipboard text.',
        'reject': 'Keep original',
        'reject_tip': 'Leave the clipboard unchanged (Enter or Esc)',
        'stripped': 'Replace (ASCII)',
        'unicode': 'Replace (keep unicode)',
        'dispatch': 'dispatch_pending_clipboard',
    },
}


class ReviewBar(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self._term = None
        self._raw = ''
        self._kind = _KINDS['paste']
        self._remaining = 0
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
        dot = QLabel(self)
        dot.setFixedSize(14, 14)
        dot.setStyleSheet('background-color:%s; border-radius:7px;' % RISK_FG)
        row.addWidget(dot)
        self._summary = QLabel('', self)
        self._summary.setStyleSheet('font-weight:bold;')
        self._summary.setWordWrap(True)
        row.addWidget(self._summary, 1)
        self._reject = QPushButton('Reject', self)
        self._reject.clicked.connect(lambda: self._choose('reject'))
        row.addWidget(self._reject)
        self._stripped = QPushButton('Paste stripped', self)
        self._stripped.setStyleSheet('color:%s; font-weight:600;' % SAFE_FG)
        self._stripped.clicked.connect(lambda: self._choose('stripped'))
        row.addWidget(self._stripped)
        self._unicode = QPushButton('Paste with unicode', self)
        self._unicode.setStyleSheet('color:%s; font-weight:600;' % RISK_FG)
        self._unicode.clicked.connect(lambda: self._choose('unicode'))
        row.addWidget(self._unicode)
        outer.addLayout(row)

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

        parts = ['%d %s%s' % (n, label, '' if n == 1 else 's')
                 for label, n in classify_paste(raw)]
        self._summary.setText(self._kind['summary'] % ', '.join(parts)
                              if parts else self._kind['summary_empty'])
        self._reject.setText(self._kind['reject'])
        self._reject.setToolTip(self._kind['reject_tip'])
        self._render_mirror(term)

        self._remaining = max(0, int(delay))
        self._gate(self._remaining > 0)
        self._tick_labels()
        if self._remaining > 0:
            self._countdown.start(1000)
        self.setVisible(True)
        self._reject.setDefault(True)
        self._reject.setFocus()

    def _render_mirror(self, term):
        """Render the held text into the mirror pane the way the reviewed tab
        would: its CURRENT display mode, theme and font. Risk-class colouring is
        forced ON (markings=True) even if the tab has it off -- the review pane
        exists to REVEAL risk. The line path is used deliberately: a review surface
        must SHOW control/hidden characters (named, tinted, click-to-inspect), not
        run them through a pyte grid that would consume them."""
        theme = getattr(term, '_theme', 'dark')
        family = term.current_font_family() \
            if hasattr(term, 'current_font_family') else None
        mode = term.current_mode() if hasattr(term, 'current_mode') else 'detail'
        self._mirror.apply_theme(theme)
        if family:
            self._mirror.set_font_family(family)
        self._mirror.render_preview(self._raw, mode=mode, markings=True)

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
        # double-click, or Esc right after) is a no-op, independent of when the
        # resolved signal hides the bar.
        term = self._term
        if term is None:
            return
        self._term = None
        self._countdown.stop()
        # dispatch emits paste_review_resolved, which the window routes back to
        # hide_review -- so the bar always closes, however the choice was made.
        getattr(term, self._kind['dispatch'])(action)

    def _gate(self, disabled):
        self._stripped.setEnabled(not disabled)
        self._unicode.setEnabled(not disabled)

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
