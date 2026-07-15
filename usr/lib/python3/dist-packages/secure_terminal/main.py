## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Application entry point for secure-terminal."""

import signal
import sys

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QMainWindow

from secure_terminal.terminal import SecureTerminal


def _install_signal_quit(app):
    """Terminate on the usual signals from the launching terminal: Ctrl+C
    (SIGINT), plus SIGTERM and SIGHUP. Qt's C++ event loop does not deliver
    Python signal handlers on its own, so a periodic no-op timer wakes it often
    enough for the handler to run."""
    def handler(_signum, _frame):
        app.quit()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, handler)
        except (OSError, ValueError, AttributeError):
            pass
    wake = QTimer(app)
    wake.timeout.connect(lambda: None)
    wake.start(200)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('secure-terminal')
    _install_signal_quit(app)

    window = QMainWindow()
    window.setWindowTitle('secure-terminal')
    terminal = SecureTerminal(window)
    window.setCentralWidget(terminal)
    window.resize(820, 520)
    window.show()
    terminal.setFocus()

    return app.exec()


if __name__ == '__main__':
    sys.exit(main())
