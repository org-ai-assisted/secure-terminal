## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""The in-window paste-review bar.

When a paste carries unicode or control characters, the terminal HOLDS it and asks
the window to show this bar (docked at the bottom, like the find bar). The preview
reuses the terminal's own renderer, so risk-class colouring and click-to-inspect
come for free.

The bar shows a one-line summary of what is hidden and, on the Detail toggle, four
read-only preview panes -- Original (how it looks), Detail (each hidden character
named inline), and exactly what each send button would deliver (stripped to ASCII,
or with printable unicode kept). Three choices: Reject (default, and what Enter/Esc
do while the paste is held), Paste stripped, and Paste with unicode. Both send
buttons are countdown-gated so a stray click cannot fire a paste; Reject is always
available. The choice is dispatched to the tab that held the paste, which is the
only path that lets a byte reach the shell.
"""

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QLabel, QGridLayout, QHBoxLayout, QVBoxLayout, QPushButton,
    QToolButton,
)

from secure_terminal.sanitize import (
    classify_paste, sanitize_paste, sanitize_paste_unicode,
)
from secure_terminal.terminal import SecureTerminal

# (column title, display mode, risk-class colouring on?) for the four panes.
_PANES = (
    ('Original (as copied)', 'show', False),      # how it looks -- deceptive, untinted
    ('Detail (what is really there)', 'detail', True),   # named + tinted + inspectable
    ('Paste stripped sends', 'show', False),      # the ASCII result
    ('Paste with unicode sends', 'show', True),   # printable non-ASCII kept, tinted
)


class PasteReviewBar(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self._window = window
        self._term = None
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
        dot.setStyleSheet('background-color:#d83933; border-radius:7px;')
        row.addWidget(dot)
        self._summary = QLabel('', self)
        self._summary.setStyleSheet('font-weight:bold;')
        self._summary.setWordWrap(True)
        row.addWidget(self._summary, 1)
        self._detail_btn = QToolButton(self)
        self._detail_btn.setText('Detail')
        self._detail_btn.setCheckable(True)
        self._detail_btn.setToolTip('Show what the paste really contains, and what '
                                    'each button would send')
        self._detail_btn.toggled.connect(self._toggle_detail)
        row.addWidget(self._detail_btn)
        self._reject = QPushButton('Reject', self)
        self._reject.setToolTip('Do not paste (Enter or Esc)')
        self._reject.clicked.connect(lambda: self._choose('reject'))
        row.addWidget(self._reject)
        self._stripped = QPushButton('Paste stripped', self)
        self._stripped.setStyleSheet('color:#0a5c37; font-weight:600;')
        self._stripped.clicked.connect(lambda: self._choose('stripped'))
        row.addWidget(self._stripped)
        self._unicode = QPushButton('Paste with unicode', self)
        self._unicode.setStyleSheet('color:#b1170f; font-weight:600;')
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
        for column, (title, _mode, _mark) in enumerate(_PANES):
            grid.addWidget(QLabel(title, self._panes_host), 0, column)
            view = SecureTerminal(preview=True)
            view.setMinimumSize(200, 130)
            grid.addWidget(view, 1, column)
            self._views.append(view)
        self._panes_host.setVisible(False)
        outer.addWidget(self._panes_host)

    # -- lifecycle ------------------------------------------------------------
    def show_review(self, term, raw, delay):
        """Show the bar for `term`'s held paste `raw`, gating the send buttons for
        `delay` seconds. Focus lands on Reject so Enter/Esc reject and no keystroke
        can reach the shell."""
        self._term = term
        # Each review opens collapsed: a prior review's expanded Detail must not
        # reveal the next paste's previews without an explicit toggle.
        self._detail_btn.setChecked(False)
        findings = classify_paste(raw)
        parts = ['%d %s%s' % (n, label, '' if n == 1 else 's')
                 for label, n in findings]
        self._summary.setText('This paste hides ' + ', '.join(parts) + '.'
                              if parts else 'This paste contains hidden characters.')

        theme = getattr(term, '_theme', 'dark')
        family = term.current_font_family() if hasattr(term, 'current_font_family') \
            else None
        sanitized = (raw, raw,
                     sanitize_paste(raw).replace('\r', '\n'),
                     sanitize_paste_unicode(raw).replace('\r', '\n'))
        for view, text, (_title, mode, mark) in zip(self._views, sanitized, _PANES):
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
        """Hide the bar and stop the countdown; called when the paste is resolved."""
        self._countdown.stop()
        self._term = None
        self.setVisible(False)

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
        term.dispatch_pending_paste(action)

    def _toggle_detail(self, on):
        self._panes_host.setVisible(bool(on))

    def _gate(self, disabled):
        self._stripped.setEnabled(not disabled)
        self._unicode.setEnabled(not disabled)

    def _tick_labels(self):
        if self._remaining > 0:
            self._stripped.setText('Paste stripped (%d)' % self._remaining)
            self._unicode.setText('Paste with unicode (%d)' % self._remaining)
        else:
            self._stripped.setText('Paste stripped')
            self._unicode.setText('Paste with unicode')

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
