## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""The paste-warning dialog.

When a paste carries unicode or control characters, this dialog shows the text
two ways side by side -- the original as it would look, and a Reveal rendering
where every non-ASCII character is a <U+XXXX> badge -- so you can see what is
really there before it reaches the shell. The Allow button is disabled for a few
seconds so a stray Enter cannot auto-accept a hostile paste; Reject cancels.
"""

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QDialog, QLabel, QPlainTextEdit, QPushButton, QHBoxLayout, QVBoxLayout,
    QGridLayout, QWidget,
)

from secure_terminal.terminal import render_output, paste_findings


class PasteWarningDialog(QDialog):
    def __init__(self, text, delay_seconds, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Paste warning')
        self.setModal(True)
        self._remaining = max(0, int(delay_seconds))

        has_unicode, has_control = paste_findings(text)
        detected = []
        if has_unicode:
            detected.append('unicode')
        if has_control:
            detected.append('control characters')
        headline = 'This paste contains ' + ' and '.join(detected) + '.'

        outer = QVBoxLayout(self)

        # warning row: a red dot + the headline
        row = QHBoxLayout()
        dot = QLabel()
        dot.setFixedSize(16, 16)
        dot.setStyleSheet('background-color:#d83933; border-radius:8px;')
        row.addWidget(dot)
        title = QLabel(headline)
        title.setStyleSheet('font-weight:bold;')
        row.addWidget(title)
        row.addStretch(1)
        outer.addLayout(row)

        outer.addWidget(QLabel(
            'Only sanitized plain ASCII will be sent to the shell. Review it '
            'first: the left pane is how it looks, the right pane reveals every '
            'hidden character.'))

        # side-by-side previews
        grid = QGridLayout()
        grid.addWidget(QLabel('Original (as copied)'), 0, 0)
        grid.addWidget(QLabel('Reveal (what is really there)'), 0, 1)
        original = QPlainTextEdit(text)
        original.setReadOnly(True)
        revealed = QPlainTextEdit(render_output(text, 'reveal'))
        revealed.setReadOnly(True)
        for view in (original, revealed):
            view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
            view.setMinimumSize(320, 160)
        grid.addWidget(original, 1, 0)
        grid.addWidget(revealed, 1, 1)
        outer.addLayout(grid)

        # buttons: Reject (default focus) and a countdown-gated Allow
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self._reject = QPushButton('Reject')
        self._reject.clicked.connect(self.reject)
        buttons.addWidget(self._reject)
        self._allow = QPushButton('Allow')
        self._allow.clicked.connect(self.accept)
        buttons.addWidget(self._allow)
        outer.addLayout(buttons)

        self._reject.setDefault(True)
        self._reject.setFocus()

        if self._remaining > 0:
            self._allow.setEnabled(False)
            self._tick()
            self._countdown = QTimer(self)
            self._countdown.timeout.connect(self._tick)
            self._countdown.start(1000)

    def _tick(self):
        if self._remaining > 0:
            self._allow.setText('Allow (%d)' % self._remaining)
            self._remaining -= 1
        else:
            self._allow.setText('Allow')
            self._allow.setEnabled(True)
            if hasattr(self, '_countdown'):
                self._countdown.stop()

    @staticmethod
    def confirm(text, delay_seconds, parent=None):
        """Show the dialog; return True to paste (sanitized), False to cancel."""
        dialog = PasteWarningDialog(text, delay_seconds, parent)
        return dialog.exec() == QDialog.DialogCode.Accepted
