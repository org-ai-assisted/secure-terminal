## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Run the review popup by itself.

Hosts the SAME shared ReviewBar that the docked bar (main window) and the clipboard
sanitizer use, in its own top-level frame, with no terminal, tab or pty behind it --
a way to see and drive the review UI standalone on a sample or supplied payload. The
decision the user makes (Reject, or Deliver the possibly-edited text) is printed to
stdout, then the process exits.

Because it reuses the one ReviewBar, its behaviour stays in lockstep with the docked
bar and the clipboard popup for free -- this module only supplies a frame and a small
holder object for the bar to dispatch the decision back to (the standalone analogue of
a tab or the clipboard controller).
"""

import argparse
import sys

from PyQt6.QtWidgets import QApplication, QVBoxLayout, QWidget

from secure_terminal import settings
from secure_terminal.review import ReviewBar
from secure_terminal.sanitize import THEMES

# A benign built-in payload that exercises the review UI when no text is supplied:
# a non-breaking space (U+00A0) and a zero-width space (U+200B) hidden in an ordinary
# command, so the bar has invisibles to reveal. Built with chr() to keep this source
# ASCII-only (the raw bytes would trip the ASCII commit gate and be unreviewable).
_SAMPLE = 'ls' + chr(0x00A0) + '-la' + chr(0x200B) + ' /tmp'


def _default_theme():
    """The user's configured colour theme, so the standalone preview matches the real
    terminal; falls back to the shipped default when unset/unknown. Mirrors the
    clipboard watcher's loader rather than importing its private helper."""
    theme = settings.load().get('theme')
    return theme if theme in THEMES else 'light'


class _StandaloneReview:
    """The object ReviewBar dispatches the decision back to when the popup runs by
    itself: no terminal, it just reports the outcome and quits. Exposes _theme (the
    only hard attribute the bar needs; every terminal-specific hook is hasattr-guarded
    in ReviewBar), so the preview panes are themed like the real app."""

    def __init__(self, theme):
        self._theme = theme

    def _report(self, action, text):
        # 'reject' carries no text; 'unicode' (Deliver) carries the exact delivered
        # string (the box plus the neutralized tail). Print it verbatim so a caller can
        # capture what would have crossed, then end the single-shot review.
        if action == 'reject':
            sys.stdout.write('rejected\n')
        else:
            sys.stdout.write((text or '') + '\n')
        sys.stdout.flush()
        app = QApplication.instance()
        if app is not None:
            app.quit()

    # The three directions dispatch to differently-named methods (see review._KINDS);
    # standalone, all three simply report and quit.
    def dispatch_pending_paste(self, action, text=None):
        self._report(action, text)

    def dispatch_pending_copy(self, action, text=None):
        self._report(action, text)

    def dispatch_pending_clipboard(self, action, text=None):
        self._report(action, text)


class _ReviewWindow(QWidget):
    """Top-level frame hosting the shared ReviewBar for the standalone launcher -- the
    docked bar lives in the terminal window and the clipboard sanitizer has its own
    popup; here the bar gets this frame. The frame governs visibility, not the bar."""

    def __init__(self):
        super().__init__(None)
        # Fixed title -- never program-supplied text on this out-of-grid surface.
        self.setWindowTitle('secure-terminal: review')
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.bar = ReviewBar(self)
        self.bar.setVisible(True)
        layout.addWidget(self.bar)


def _resolve_payload(args):
    """The text to review: --text if given; else piped stdin when it carries content;
    else the built-in sample (so a bare headless launch still shows something)."""
    if args.text is not None:
        return args.text.rstrip('\n')
    piped = '' if sys.stdin.isatty() else sys.stdin.read()
    return (piped if piped.strip() else _SAMPLE).rstrip('\n')


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='secure-terminal-review',
        description='Show the secure-terminal review popup by itself on a sample or '
                    'supplied payload, and print the decision (rejected, or the '
                    'delivered text) to stdout.')
    parser.add_argument('--kind', choices=('paste', 'copy', 'clipboard'),
                        default='paste',
                        help='review direction (default: paste)')
    parser.add_argument('--text',
                        help='payload to review (default: piped stdin, else a '
                             'built-in sample)')
    parser.add_argument('--theme', choices=sorted(THEMES),
                        help='colour theme (default: the configured theme)')
    parser.add_argument('--delay', type=int, default=0,
                        help='anti-fat-finger Deliver countdown, seconds '
                             '(default: 0)')
    args = parser.parse_args(argv)

    payload = _resolve_payload(args)
    theme = args.theme or _default_theme()

    # Pass only the program name to Qt: our own flags (--kind, ...) are argparse's,
    # and Qt would otherwise reject them.
    app = QApplication.instance() or QApplication(sys.argv[:1])
    holder = _StandaloneReview(theme)
    window = _ReviewWindow()
    window.bar.show_review(holder, payload, max(0, args.delay), kind=args.kind)
    window.adjustSize()
    window.show()
    window.raise_()
    window.activateWindow()
    return app.exec()
