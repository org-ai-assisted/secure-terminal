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
Like every bracketed-paste consumer, it relies on the outer terminal to filter a
paste-end marker (ESC[201~) embedded in the clipboard, which the bracketed-paste
spec requires and every modern terminal does; a non-compliant terminal could let a
crafted clipboard break the framing, so this is a best-effort layer, not an absolute
boundary. This wrapper does not judge whether a command is dangerous either; that is
the (planned) hook's job.
"""

import os
import sys
import pty
import tty
import time
import fcntl
import codecs
import select
import signal
import struct
import termios
import argparse

from secure_terminal.sanitize import (
    render_output, cap_zalgo_show, feed_chunk_carry, DISPLAY_MODES, sanitize_paste)

# Bracketed-paste framing the OUTER terminal wraps a paste in once DECSET 2004 is
# enabled. Stripped before the child sees it (the child runs TERM=dumb and never
# enabled bracketed paste, so a raw 200~/201~ would print as literal text).
_BP_ENABLE = b'\x1b[?2004h'
_BP_DISABLE = b'\x1b[?2004l'
_PASTE_START = b'\x1b[200~'
_PASTE_END = b'\x1b[201~'

# Cap the stdin paste buffer. An unterminated or oversized bracketed-paste frame (a
# never-arriving ESC[201~, or a stream repeating ESC[200~ with no close) would otherwise
# grow paste_buf without bound and, because in_paste never clears, absorb every later
# keystroke -- the terminal looks dead with no recovery. On overflow the runaway buffer is
# dropped and paste mode is left, so memory is bounded and typed input recovers. 1 MiB is
# far above any real interactive paste.
_PASTE_MAX = 1 << 20

# How long to hold a lone trailing ESC (a possible split paste-start marker) before
# forwarding it to the child as a real interactive Escape. A paste-start marker split by an
# os.read() boundary as ESC | '[200~...' has its continuation ALREADY in the OS buffer, so
# select() reports stdin readable within microseconds and the marker reassembles; only a
# genuine standalone Escape ever reaches this timeout. Small enough to keep interactive
# Escape (vim) responsive, large enough to reassemble any split marker.
_ESC_HOLD_TIMEOUT = 0.05

# After OUR stdin closes we nudge the child with EOF (Ctrl-D) at this slow cadence until it
# exits -- one ^D can be lost to a shell that flushes type-ahead before its prompt (zsh), and
# re-reading a closed fd every loop would busy-spin. A slow, best-effort re-send delivers EOF
# reliably without pegging the CPU. BOUNDED (_EOF_NUDGE_MAX): a shell -- even a raw-mode ZLE /
# readline line editor -- reads ^D as end-of-input and exits within a nudge or two, but a
# full-screen program where ^D is DATA never exits on it, so cap the re-sends rather than feed
# it ^D forever (the pty mode cannot tell a raw shell from a raw full-screen reader). 2s of
# nudges covers any shell's startup; a non-exiting reader then gets at most a few stray bytes.
_EOF_NUDGE_INTERVAL = 0.2
_EOF_NUDGE_MAX = 10

# Characters an unterminated / over-long string sequence may silently suppress
# before a one-time stderr notice. A sequence that survives a whole 64 KiB read
# without terminating is almost certainly stuck (a real one is shorter and ends),
# so this catches the "output silently blanks forever" freeze without lifting the
# suppression (no escape byte is ever written to the outer terminal).
_ESC_SUPPRESS_NOTICE_CHARS = 65536


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
            # Bound the buffer at _PASTE_MAX: past it, DROP further content but STAY in paste.
            # An oversized / unterminated frame must not (a) grow memory without bound, nor (b)
            # be exited so its runaway TAIL falls through as TYPED input and auto-runs
            # (pastejacking). The end marker -- a real bracketed paste always sends ESC[201~ --
            # or a terminal reset still ends it; a malicious never-closing frame simply drops.
            if len(paste_buf) < _PASTE_MAX:
                paste_buf += chunk[:_PASTE_MAX - len(paste_buf)]   # keep the buffer at the cap
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
            # a split marker PREFIX (>= 1 byte, e.g. a lone ESC, ESC[, or ESC[20) -> hold
            # for the next read. Holding even a LONE ESC closes a pastejacking hole: a
            # paste-start marker split by a read boundary as ESC | '[200~payload\r' must
            # still enter paste mode, or that body reaches the child as typed input and the
            # trailing CR auto-runs it. A real interactive Escape (vim, a lone Escape) has
            # no continuation, so _run flushes the held ESC to the child after a bounded
            # timeout (_ESC_HOLD_TIMEOUT); a split marker's continuation is already buffered
            # and arrives first, so it reassembles here before that timeout fires.
            carry = remaining
            break
        elif in_paste:
            if len(paste_buf) < _PASTE_MAX:
                paste_buf += buf[i:i + 1]      # an ESC in paste content (dropped later)
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
    esc_dropped = 0             # chars suppressed in the current discard run
    esc_notified = False        # the suppression notice printed for this run
    zalgo_carry = 0             # trailing show-mode combining-mark run, capped across reads
    stdin_fd = sys.stdin.fileno()
    out_fd = sys.stdout.fileno()
    old_attr = None
    paste_state = (False, b'', b'')     # (in_paste, paste_buf, carry) for stdin framing
    if os.isatty(stdin_fd):
        old_attr = termios.tcgetattr(stdin_fd)
    try:
        if old_attr is not None:
            tty.setraw(stdin_fd)    # forward keystrokes immediately; child's pty cooks
            # Enable bracketed paste on the OUTER terminal so a paste arrives framed
            # (ESC[200~..201~) and can be told apart from typing. A legacy console that
            # ignores this just delivers a paste as ordinary typed input. Inside the try
            # so a failed setraw / enable still hits the finally that restores termios.
            os.write(out_fd, _BP_ENABLE)
        esc_deadline = None     # monotonic time to flush a held partial paste-start marker
        read_fds = [fd, stdin_fd]   # stdin_fd is dropped from this on its EOF (below)
        eof_nudge = None        # monotonic time to re-send the child EOF after stdin closed
        eof_nudges_left = 0     # remaining bounded EOF re-sends (see _EOF_NUDGE_MAX)
        while True:
            # A held partial paste-start marker (a lone ESC, or ESC[.. prefix) is carried in
            # paste_state[2] while NOT already in a paste. It is flushed to the child as a real
            # interactive Escape once an ABSOLUTE hold deadline passes -- without holding it a
            # split ESC|[200~ marker slips through as typed input and auto-runs (pastejacking);
            # without a deadline a lone ESC is swallowed forever. The deadline is ABSOLUTE (not a
            # per-call select timeout) so a continuously-readable child fd cannot starve it.
            hold = bool(paste_state[2]) and not paste_state[0]
            if hold:
                if esc_deadline is None:
                    esc_deadline = time.monotonic() + _ESC_HOLD_TIMEOUT
                timeout = max(0.0, esc_deadline - time.monotonic())
            else:
                esc_deadline = None
                timeout = None
            if eof_nudge is not None:
                # wake in time for the next EOF nudge (never busy-wait on a closed stdin)
                due = max(0.0, eof_nudge - time.monotonic())
                timeout = due if timeout is None else min(timeout, due)
            try:
                readable, _, _ = select.select(read_fds, [], [], timeout)
            except (OSError, select.error):  # pragma: no cover - PEP 475 retries EINTR
                continue            # EINTR from SIGWINCH etc. -> retry
            if eof_nudge is not None and time.monotonic() >= eof_nudge:
                # Re-send EOF (^D), best-effort. Skip a re-send the pty won't accept (a child
                # not reading its input), so a full input buffer cannot block the reader. Stop
                # after _EOF_NUDGE_MAX tries: a shell exits within a nudge or two, but a program
                # that reads ^D as DATA never exits on it and must not be fed it forever.
                if eof_nudges_left > 0:
                    if select.select([], [fd], [], 0)[1]:
                        os.write(fd, b'\x04')
                    eof_nudges_left -= 1
                    eof_nudge = time.monotonic() + _EOF_NUDGE_INTERVAL
                else:
                    eof_nudge = None
            # esc_deadline is set to a float whenever `hold` is True (above), so the compare
            # is float-vs-float; pyrefly cannot see that correlation.
            if hold and time.monotonic() >= esc_deadline:  # pyrefly: ignore[unsupported-operation]
                # deadline reached (even if the child fd is readable) -> the held prefix got no
                # paste continuation; forward it verbatim and clear the hold, then service any
                # readable fd this iteration.
                os.write(fd, paste_state[2])
                paste_state = (paste_state[0], paste_state[1], b'')
                esc_deadline = None
            if not readable:
                continue
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
                text, esc_carry, esc_drop, esc_dropped = feed_chunk_carry(
                    decoder.decode(data), esc_carry, esc_drop, esc_dropped)
                # A long unterminated string sequence keeps suppressing output (no
                # escape byte reaches the outer terminal -- safe), but looks like a
                # hang. Warn ONCE on stderr so the blank is explained; re-arm when the
                # run ends. stderr, never stdout, so the sanitized stream stays clean.
                if not esc_drop:
                    esc_notified = False
                elif not esc_notified and esc_dropped >= _ESC_SUPPRESS_NOTICE_CHARS:
                    esc_notified = True
                    sys.stderr.write(
                        'secure-terminal-cli: suppressing output -- an over-long or '
                        'unterminated escape sequence is being discarded.\n')
                    sys.stderr.flush()
                safe = render_output(text, mode)
                if mode == 'show':
                    # render_output keeps every combining mark (it is a per-char
                    # homomorphism, per the T1 proof), so a Zalgo flood would reach the
                    # real terminal here. Cap the run at the CLI boundary instead.
                    safe, zalgo_carry = cap_zalgo_show(safe, zalgo_carry)
                os.write(out_fd, safe.encode('utf-8', 'replace'))
            if stdin_fd in readable:
                try:
                    keys = os.read(stdin_fd, 65536)
                except OSError:  # pragma: no cover - defensive stdin read-error guard
                    break
                if not keys:
                    # stdin hit EOF (closed pipe / /dev/null). STOP selecting on stdin_fd: a
                    # closed fd stays readable, so leaving it in read_fds spins the loop at 100%
                    # CPU. Arm the bounded EOF nudge (due now): the nudge block delivers ^D at a
                    # slow cadence -- one ^D can be flushed by a shell that clears type-ahead
                    # before its prompt -- until the child exits or the re-send budget runs out.
                    read_fds.remove(stdin_fd)
                    eof_nudge = time.monotonic()
                    eof_nudges_left = _EOF_NUDGE_MAX
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
            try:
                os.write(out_fd, _BP_DISABLE)  # disable bracketed paste on the outer term
            finally:
                # ALWAYS restore the terminal, even if the disable write raised.
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
