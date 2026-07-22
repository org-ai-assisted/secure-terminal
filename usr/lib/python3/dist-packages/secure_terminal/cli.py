## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Interactive sanitizing terminal wrapper (the CLI form of secure-terminal).

Runs a shell or command in a pseudo-terminal and streams its output to the real
terminal with the same line-mode neutralization the GUI uses: escape sequences
are removed and non-ASCII output is handled per the display mode, so it is safe
to run an untrusted program or `cat` a hostile file even on a plain console or
over SSH, where the outer terminal would otherwise interpret hostile bytes. The
sanitization core is shared with the GUI (secure_terminal.sanitize); this module
adds no Qt and no escape parser.

Scope, honestly: this sanitizes what a program DISPLAYS (the attack surface).
Your own keystrokes are forwarded as typed -- unlike the GUI it does not gate a
paste, because a raw stdin stream cannot tell typing from a paste. It also does
not judge whether a command is dangerous; that is the (planned) hook's job.
"""

import os
import sys
import pty
import tty
import fcntl
import codecs
import select
import signal
import struct
import termios
import argparse

from secure_terminal.sanitize import render_output, DISPLAY_MODES


def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
    except OSError:
        pass            # not a tty / closed -> nothing to size


def _outer_winsize():
    for stream in (sys.stdout, sys.stdin):
        try:
            packed = fcntl.ioctl(stream.fileno(), termios.TIOCGWINSZ,
                                 b'\x00' * 8)
            rows, cols, _, _ = struct.unpack('HHHH', packed)
            if rows and cols:
                return rows, cols
        except (OSError, ValueError):
            continue
    return 24, 80


def _run(argv, mode):
    argv = list(argv) or [os.environ.get('SHELL') or '/bin/bash']
    pid, fd = pty.fork()
    if pid == 0:  # pragma: no cover
        # child: a dumb terminal so programs emit little to strip; the wrapper
        # honours only the safe cursor controls (backspace, carriage return).
        # (no cover: this branch immediately execvp()s or os._exit()s, so a
        # coverage tracer in the parent never receives the child's line data;
        # the behaviour is exercised end-to-end by the CLI tests instead.)
        os.environ['TERM'] = 'dumb'
        os.environ.setdefault('PAGER', 'cat')
        try:
            os.execvp(argv[0], argv)
        except OSError:
            os._exit(127)

    rows, cols = _outer_winsize()
    _set_winsize(fd, rows, cols)

    def on_resize(_signum, _frame):
        _set_winsize(fd, *_outer_winsize())
    try:
        signal.signal(signal.SIGWINCH, on_resize)
    except (OSError, ValueError):  # pragma: no cover - only off the main thread
        pass            # no controlling terminal -> resize just does not fire

    decoder = codecs.getincrementaldecoder('utf-8')('replace')
    stdin_fd = sys.stdin.fileno()
    out_fd = sys.stdout.fileno()
    old_attr = None
    if os.isatty(stdin_fd):
        old_attr = termios.tcgetattr(stdin_fd)
        tty.setraw(stdin_fd)        # forward keystrokes immediately; child's pty cooks
    try:
        while True:
            try:
                readable, _, _ = select.select([fd, stdin_fd], [], [])
            except (OSError, select.error):  # pragma: no cover - PEP 475 retries EINTR
                continue            # EINTR from SIGWINCH etc. -> retry
            if fd in readable:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    break
                if not data:  # pragma: no cover - Linux pty EOF raises EIO (above)
                    break           # child exited / pty closed
                safe = render_output(decoder.decode(data), mode)
                os.write(out_fd, safe.encode('utf-8', 'replace'))
            if stdin_fd in readable:
                try:
                    keys = os.read(stdin_fd, 65536)
                except OSError:  # pragma: no cover - defensive stdin read-error guard
                    break
                if not keys:
                    os.write(fd, b'\x04')   # our EOF -> send the child EOF
                else:
                    os.write(fd, keys)
    finally:
        if old_attr is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_attr)

    try:
        _, status = os.waitpid(pid, 0)
    except OSError:
        return 0
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return os.WEXITSTATUS(status)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='secure-terminal-cli',
        description='Run a command or your shell in a sanitizing terminal '
                    'wrapper: escape sequences are removed and non-ASCII output '
                    'is neutralized before it reaches your terminal.')
    parser.add_argument('--mode', choices=DISPLAY_MODES, default='detail',
                        help="how to show non-ASCII output: detail (safe default, "
                             "each non-ASCII character named inline as "
                             "<U+XXXX NAME>), box (non-ASCII becomes '_' in the "
                             "CLI), show (render printable glyphs), reveal "
                             "(<U+XXXX> badges)")
    parser.add_argument('command', nargs=argparse.REMAINDER,
                        help='command to run (default: your login shell)')
    args = parser.parse_args(argv)
    cmd_argv = args.command
    if cmd_argv and cmd_argv[0] == '--':      # argparse leaves a leading -- in REMAINDER
        cmd_argv = cmd_argv[1:]
    try:
        return _run(cmd_argv, args.mode)
    except KeyboardInterrupt:
        return 130
