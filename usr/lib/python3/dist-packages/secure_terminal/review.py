#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""The in-window review bar for text crossing the terminal boundary.

The same bar reviews text in BOTH trust directions: a paste coming IN (before it
reaches the shell) and a selection being copied OUT (before it reaches the system
clipboard). When such text carries unicode or control characters, the terminal
HOLDS it and asks the window to show this bar (docked at the bottom, like the find
bar). The preview reuses the terminal's own renderer, so risk-class colouring and
click-to-inspect come for free.

The bar shows a one-line summary of what is hidden and, on the Detail toggle, four
read-only preview panes -- Original (how it looks), Detail (each hidden character
named inline), and exactly what each action button would deliver (stripped to
ASCII, or with printable unicode kept). Three choices: Reject / Don't copy
(default, and what Enter/Esc do while the text is held), the stripped action, and
the with-unicode action. For a paste both action buttons are countdown-gated so a
stray click cannot run it; a copy (not executed) has no countdown. The choice is
dispatched back to the tab that held the text, the only path that lets it cross.
"""

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QLabel, QGridLayout, QHBoxLayout, QVBoxLayout, QPushButton,
    QToolButton,
)

from secure_terminal.sanitize import (
    classify_paste, sanitize_paste, sanitize_paste_unicode,
    sanitize_clipboard, sanitize_clipboard_display, sanitize_clipboard_unicode,
    paste_no_autosubmit,
)
from secure_terminal.terminal import SecureTerminal

# Semantic button/dot colours: the app's canonical safe-green and caution-red (the
# same values the mode lamps and risk dots use). Chosen to clear the contrast guard
# (sanitize.too_close) against BOTH the light and the dark theme background, so the
# send buttons and the risk dot stay readable whatever the desktop palette -- unlike
# a foreground-only tint tuned for one theme. Pinned as constants so test_review.py
# can assert the contrast directly.
SAFE_FG = '#1f8a54'
RISK_FG = '#d83933'

# (display mode, risk-class colouring?) for the four preview panes, in order.
_PANE_RENDER = (
    ('show', False),      # Original -- how it looks, deceptive, untinted
    ('detail', True),     # Detail -- named + tinted + click-to-inspect
    ('show', False),      # the stripped (ASCII) result
    ('show', True),       # the printable-unicode-kept result, tinted
)

# Everything that differs between the two directions. `dispatch` is the tab method
# the choice is routed to; `panes` are the four column titles; `strip`/`keep` are
# the sanitizers used to build the last two preview panes (paste maps newlines to
# the shell's carriage return, copy preserves them for the clipboard).
_KINDS = {
    'paste': {
        'summary': 'This paste hides %s.',
        # shown in "always" mode for a clean paste: no hidden characters to name.
        'summary_empty': 'Review this paste before it reaches the shell.',
        'reject': 'Reject',
        'reject_tip': 'Do not paste (Enter or Esc)',
        'stripped': 'Paste stripped',
        'unicode': 'Paste with unicode',
        'titles': ('Original (as it looks)', 'Detail (what is really there)',
                   'Paste stripped sends', 'Paste with unicode sends'),
        'dispatch': 'dispatch_pending_paste',
        # Sanitizers return the \r-form; show_review then applies paste_no_autosubmit
        # (only when the target is NOT bracketed-paste, matching _dispatch_paste) and maps
        # \r -> \n for display, so the "sends" panes show EXACTLY what reaches the pty --
        # at a bare prompt the trailing auto-submit CR is dropped, so the preview no longer
        # implies a submit that will not happen. Keyed by 'paste_newline'.
        'strip': sanitize_paste,
        'keep': sanitize_paste_unicode,
        'paste_newline': True,
    },
    'copy': {
        'summary': 'This copy would carry %s onto the clipboard.',
        'summary_empty': 'Review this copy before it reaches the clipboard.',
        'reject': "Don't copy",
        'reject_tip': 'Do not copy (Enter or Esc)',
        'stripped': 'Copy stripped',
        'unicode': 'Copy with unicode',
        'titles': ('Original (as it looks)', 'Detail (what is really there)',
                   'Copy stripped puts', 'Copy with unicode puts'),
        'dispatch': 'dispatch_pending_copy',
        # the display-aware strip, so the "Copy stripped puts" preview matches what
        # dispatch_pending_copy('stripped') actually places (a box -> '_', never gone).
        'strip': sanitize_clipboard_display,
        'keep': sanitize_clipboard_unicode,
    },
    # The standalone clipboard sanitizer (clipboard_watch.py): text already ON the
    # system clipboard, reviewed before it is pasted elsewhere. Not a terminal
    # direction -- dispatch_pending_clipboard lives on a small holder object, not a
    # tab -- but the bar and previews are identical.
    'clipboard': {
        'summary': 'This clipboard text hides %s.',
        'summary_empty': 'Review the clipboard text.',
        'reject': 'Keep original',
        'reject_tip': 'Leave the clipboard unchanged (Enter or Esc)',
        'stripped': 'Replace (ASCII)',
        'unicode': 'Replace (keep unicode)',
        'titles': ('Original (as it looks)', 'Detail (what is really there)',
                   'Replace (ASCII) puts', 'Replace (keep unicode) puts'),
        'dispatch': 'dispatch_pending_clipboard',
        # plain ASCII strip -- the text is raw clipboard content, NOT lifted from the
        # rendered display, so the display-aware strip's box->'_' rewrite does not
        # apply; this matches what dispatch_pending_clipboard writes back.
        'strip': sanitize_clipboard,
        'keep': sanitize_clipboard_unicode,
    },
}


class ReviewBar(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self._term = None
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
        self._detail_btn = QToolButton(self)
        self._detail_btn.setText('Detail')
        self._detail_btn.setCheckable(True)
        self._detail_btn.setToolTip('Show what the text really contains, and what '
                                    'each button would deliver')
        self._detail_btn.toggled.connect(self._toggle_detail)
        row.addWidget(self._detail_btn)
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

        # preview panes (hidden until Detail is toggled): read-only terminal views
        # that render through the SAME pipeline, so a homoglyph is tinted and each
        # character is click-to-inspect, exactly as in the terminal.
        self._panes_host = QWidget(self)
        grid = QGridLayout(self._panes_host)
        grid.setContentsMargins(0, 0, 0, 0)
        self._views = []
        self._pane_labels = []
        for column in range(len(_PANE_RENDER)):
            label = QLabel('', self._panes_host)
            grid.addWidget(label, 0, column)
            self._pane_labels.append(label)
            view = SecureTerminal(preview=True)
            view.setMinimumSize(200, 130)
            grid.addWidget(view, 1, column)
            self._views.append(view)
        self._panes_host.setVisible(False)
        outer.addWidget(self._panes_host)

    # -- lifecycle ------------------------------------------------------------
    def show_review(self, term, raw, delay, kind='paste'):
        """Show the bar for `term`'s held text `raw`, in the given direction
        ('paste' or 'copy'), gating the action buttons for `delay` seconds. Focus
        lands on Reject so Enter/Esc reject and nothing crosses until a choice."""
        self._term = term
        self._kind = _KINDS.get(kind, _KINDS['paste'])
        # Each review opens collapsed: a prior review's expanded Detail must not
        # reveal the next text's previews without an explicit toggle.
        self._detail_btn.setChecked(False)

        parts = ['%d %s%s' % (n, label, '' if n == 1 else 's')
                 for label, n in classify_paste(raw)]
        self._summary.setText(self._kind['summary'] % ', '.join(parts)
                              if parts else self._kind['summary_empty'])
        self._reject.setText(self._kind['reject'])
        self._reject.setToolTip(self._kind['reject_tip'])
        for label, title in zip(self._pane_labels, self._kind['titles']):
            label.setText(title)

        theme = getattr(term, '_theme', 'dark')
        family = term.current_font_family() if hasattr(term, 'current_font_family') \
            else None
        def preview_send(sanitizer):
            sent = sanitizer(raw)
            if self._kind.get('paste_newline'):
                # Match _dispatch_paste: at a non-bracketed target the trailing auto-submit
                # CR is stripped (so a pasted command waits for the user's own Enter), then
                # \r -> \n for a readable preview. A bracketed-paste TUI keeps the CR, so its
                # preview keeps the newline -- the pane tracks the real delivery either way.
                if not term._bracketed_paste_active():
                    sent = paste_no_autosubmit(sent)
                sent = sent.replace('\r', '\n')
            return sent
        texts = (raw, raw, preview_send(self._kind['strip']),
                 preview_send(self._kind['keep']))
        for view, text, (mode, mark) in zip(self._views, texts, _PANE_RENDER):
            view.apply_theme(theme)
            if family:
                view.set_font_family(family)
            view.render_preview(text, mode=mode, markings=mark)

        self._remaining = max(0, int(delay))
        self._gate(self._remaining > 0)
        self._tick_labels()
        if self._remaining > 0:
            self._countdown.start(1000)
        self.setVisible(True)
        self._reject.setDefault(True)
        self._reject.setFocus()

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

    def _toggle_detail(self, on):
        self._panes_host.setVisible(bool(on))

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
