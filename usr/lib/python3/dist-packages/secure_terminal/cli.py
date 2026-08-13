#!/usr/bin/python3 -Bsu
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
Your own keystrokes are forwarded as typed. Auto-submit protection for a PASTE
is delivered the way every shell already gets it: by enabling bracketed paste
(DECSET 2004) on the OUTER terminal, which then wraps a paste in ESC[200~ ..
ESC[201~ framing. That framing, not a byte-shape guess, is what tells a paste
from typing -- a raw stdin stream cannot, because os.read() boundaries are
scheduling artifacts, so fast typing and a paste can arrive in the same shape.
Inside the framing the wrapper applies the GUI's neutralization -- the trailing
auto-submit is stripped so a pasted command waits at the prompt for the user's
explicit Enter -- and it removes the 200~/201~ markers before the (dumb) child
ever sees them; UNframed (typed) bytes are forwarded verbatim, so typing is never
eaten.

This paste protection is scoped to a bracketed-paste-capable outer terminal
(every modern terminal, and every shell already relies on it). On a legacy
console that ignores DECSET 2004 no framing arrives, so a paste behaves like
ordinary typed input -- exactly as in any other wrapper, no better and no worse.
This wrapper does not judge whether a command is dangerous either; that is the
(planned) hook's job.
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

from secure_terminal.sanitize import (
    render_output, feed_chunk_carry, DISPLAY_MODES, sanitize_paste)

# Bracketed-paste framing the OUTER terminal wraps a paste in once DECSET 2004 is
# enabled. Stripped before the child sees it (the child runs TERM=dumb and never
# enabled bracketed paste, so a raw 200~/201~ would print as literal text).
_BP_ENABLE = b'\x1b[?2004h'
_BP_DISABLE = b'\x1b[?2004l'
_PASTE_START = b'\x1b[200~'
_PASTE_END = b'\x1b[201~'


def feed_stdin_paste(data, state):
    r"""Stdin-side bracketed-paste state machine: the input mirror of the
    output-side feed_chunk_carry. Given raw stdin `data` (bytes) and the carried
    `state` (in_paste, paste_buf, carry), return (to_child, new_state).

    - Typed (UNframed) bytes are forwarded to the child VERBATIM -- no byte-level
      submit strip, so typing is never eaten.
    - A paste body (between ESC[200~ and ESC[201~, the framing the outer terminal
      adds) is buffered until its end marker, then run through the GUI's
      neutralization: sanitize_paste drops non-ASCII / control bytes, then EVERY
      submit (CR) is stripped -- not only the trailing one. The GUI can HOLD a
      multiline paste for review; the CLI has no such UI and forwards straight to
      the dumb child, so an interior CR left in the body would auto-run the command
      before it (embedded-CR pastejacking). The whole paste lands as one
      un-submitted line for the user's explicit Enter.
    - The 200~/201~ markers are STRIPPED (the dumb child must not see them), and a
      marker split across two reads is carried to the next chunk.
    """
    in_paste, paste_buf, carry = state
    buf = carry + data
    carry = b''
    out = bytearray()
    i, n = 0, len(buf)
    while i < n:
        marker = _PASTE_END if in_paste else _PASTE_START
        idx = buf.find(b'\x1b', i)
        chunk = buf[i:] if idx == -1 else buf[i:idx]
        # bytes before the next ESC: paste body -> buffer, else typed -> child
        if in_paste:
            paste_buf += chunk
        else:
            out += chunk
        if idx == -1:
            break
        i = idx
        remaining = buf[i:]                    # from this ESC to end-of-buffer
        if remaining.startswith(marker):
            if in_paste:                      # end of paste: neutralize + emit
                text = paste_buf.decode('utf-8', 'replace')
                # Strip EVERY submit (CR), not just the trailing one: the CLI has no
                # hold-for-review, so an interior CR forwarded to the dumb child would
                # auto-run the command before it (embedded-CR pastejacking).
                out += sanitize_paste(text).replace('\r', '').encode('utf-8')
                paste_buf, in_paste = b'', False
            else:
                paste_buf, in_paste = b'', True
            i += len(marker)
        elif marker.startswith(remaining):
            carry = remaining                 # partial marker -> hold for next read
            break
        elif in_paste:
            paste_buf += buf[i:i + 1]          # an ESC in paste content (dropped later)
            i += 1
        else:
            out += buf[i:i + 1]                # a typed escape (arrow key) -> verbatim
            i += 1
    return bytes(out), (in_paste, paste_buf, carry)


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
    esc_carry = ''              # incomplete escape held from the previous read
    esc_drop = ''               # introducer of an over-cap string sequence
    stdin_fd = sys.stdin.fileno()
    out_fd = sys.stdout.fileno()
    old_attr = None
    paste_state = (False, b'', b'')     # (in_paste, paste_buf, carry) for stdin framing
    if os.isatty(stdin_fd):
        old_attr = termios.tcgetattr(stdin_fd)
        tty.setraw(stdin_fd)        # forward keystrokes immediately; child's pty cooks
        # Enable bracketed paste on the OUTER terminal so a paste arrives framed
        # (ESC[200~..201~) and can be told apart from typing. A legacy console that
        # ignores this just delivers a paste as ordinary typed input.
        os.write(out_fd, _BP_ENABLE)
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
                # Carry an escape split across reads, exactly as the widget does.
                # render_output alone is stateless per chunk, so a sequence cut by
                # a read boundary lost its introducer and the REMAINDER printed as
                # text -- straight onto the outer terminal, `\r` and all, which is
                # a prompt-spoofing primitive that needs no escape to survive.
                text, esc_carry, esc_drop = feed_chunk_carry(
                    decoder.decode(data), esc_carry, esc_drop)
                safe = render_output(text, mode)
                os.write(out_fd, safe.encode('utf-8', 'replace'))
            if stdin_fd in readable:
                try:
                    keys = os.read(stdin_fd, 65536)
                except OSError:  # pragma: no cover - defensive stdin read-error guard
                    break
                if not keys:
                    os.write(fd, b'\x04')   # our EOF -> send the child EOF
                elif old_attr is None:
                    # Non-tty stdin: bracketed paste was never enabled, so nothing
                    # is framed -- forward the bytes verbatim.
                    os.write(fd, keys)
                else:
                    # On a tty, split typed bytes from a bracketed paste: typing is
                    # forwarded verbatim; a paste is neutralized and its markers
                    # stripped (see feed_stdin_paste).
                    to_child, paste_state = feed_stdin_paste(keys, paste_state)
                    if to_child:
                        os.write(fd, to_child)
    finally:
        if old_attr is not None:
            os.write(out_fd, _BP_DISABLE)     # disable bracketed paste on the outer term
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
