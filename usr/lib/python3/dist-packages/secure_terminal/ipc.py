#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Single-instance IPC over an owner-only Unix socket.

The first launch becomes the server (a QLocalServer under $XDG_RUNTIME_DIR/
secure-terminal, directory and socket mode 0700 -- same-UID only). A later launch
connects as a pure-Python client, hands over a request (its parsed launch spec, or
a remote-control command), and exits; the running instance acts on it.

The socket is same-user only (the directory is 0700 and the socket is created with
UserAccessOption), so a request comes from the same UID -- no privilege boundary
is crossed, running a command in a tab is no more than the user could do anyway.
The server still frames and type-validates every request defensively, and
remote-control ops beyond opening tabs are gated separately (see main.py)."""

import os
import json
import socket
import struct
import time

_APP = 'secure-terminal'
_MAX_REQUEST = 1 << 20         # 1 MiB frame cap (defensive)


def socket_dir():
    base = os.environ.get('XDG_RUNTIME_DIR') \
        or os.path.join('/run/user', str(os.getuid()))
    return os.path.join(base, _APP)


def socket_path(group='default'):
    """The socket file for an instance group. The group name is reduced to a safe
    filename so it can never escape the socket directory."""
    safe = ''.join(c for c in (group or 'default')
                   if c.isalnum() or c in '-_.') or 'default'
    return os.path.join(socket_dir(), safe + '.sock')


def _makedirs_private(path):
    """Create `path` and any MISSING parents, each newly-created component at 0o700
    (mode set explicitly, so umask cannot widen it). An EXISTING component is left
    untouched -- it may be a system-owned dir (e.g. /run/user/UID) at its own correct
    mode, which we must not chmod."""
    parent = os.path.dirname(path)
    if parent and parent != path and not os.path.isdir(parent):
        _makedirs_private(parent)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        return                              # already present -> leave its mode alone
    try:
        os.chmod(path, 0o700)               # umask may have widened mkdir's mode
    except OSError:
        pass                                # best-effort; a chmod failure must not crash provisioning


def ensure_socket_dir():
    directory = socket_dir()
    # os.makedirs(mode=) applies the mode ONLY to the leaf and lets umask widen any
    # intermediate dir it must create (e.g. a missing $XDG_RUNTIME_DIR base) -- a
    # world-traversable parent, contradicting the same-UID-only 0700 contract. Create
    # each missing component explicitly at 0700 instead.
    _makedirs_private(directory)
    try:
        os.chmod(directory, 0o700)          # enforce owner-only even if pre-existing
    except OSError:
        pass                                # best-effort; a bad chmod must not crash
    return directory


def frame(payload):
    """Length-prefix a bytes payload for the wire."""
    return struct.pack('<I', len(payload)) + payload


def send_request(group, request, timeout=1.5):
    """Connect to a running instance and send a JSON request; return the parsed
    reply dict, or None if no instance is reachable or the exchange failed."""
    path = socket_path(group)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(path)
    except OSError:
        return None                         # no server, or a stale socket
    try:
        client.sendall(frame(json.dumps(request).encode('utf-8')))
        # A cumulative deadline, not a per-recv timeout: settimeout() restarts its window
        # on every recv, so a trickling same-UID peer (one byte just under the timeout,
        # repeatedly) could hold this short-lived ctl/launch client open far past `timeout`.
        # Bound the WHOLE receive by one wall-clock deadline instead.
        reply = _recv_framed(client, time.monotonic() + timeout)
        # An empty read is a FAILED exchange, not a reply: a primary that has bound
        # the socket but whose Qt event loop is not yet servicing connections accepts
        # the connect (socket_is_live) and can close it with no framed answer. Every
        # real reply is a non-empty dict ({'ok': ...}), so map empty -> None and let
        # the caller retry (_wait_primary / _handoff) rather than mistake it for a
        # valid pidless reply.
        if not reply:
            return None
        parsed = json.loads(reply.decode('utf-8'))
        # Every real reply is a dict ({'ok': ...}); callers use reply.get(). A same-UID
        # squatter could frame a non-dict (json.loads('[]') -> a list) that .get() would
        # AttributeError on -- return None so the caller sees a clean "no instance".
        return parsed if isinstance(parsed, dict) else None
    # RecursionError: json.loads raises it (not ValueError) on a deeply-nested reply -- a
    # squatter answering our probe could else crash this short-lived ctl/launch client.
    except (OSError, ValueError, RecursionError):
        return None
    finally:
        client.close()


def socket_is_live(group='default', timeout=0.5):
    """True if a process is LISTENING on the group socket right now -- a raw
    connect succeeds. Unlike send_request (which needs a REPLY, so a primary still
    starting its Qt event loop reads as dead), this only needs the kernel to accept
    the connection, which a QLocalServer.listen() enables immediately. That lets a
    concurrent second launch see a peer that has already bound but cannot yet
    answer, so it stays server-less instead of stealing the just-bound socket. A
    stale socket file (no listener) refuses the connect -> False."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(socket_path(group))
        return True
    except OSError:
        return False                        # no listener: absent or stale socket
    finally:
        client.close()


def _recv_framed(sock, deadline):
    head = _recv_exactly(sock, 4, deadline)
    if head is None:
        return b''
    (length,) = struct.unpack('<I', head)
    if length <= 0 or length > _MAX_REQUEST:
        return b''
    return _recv_exactly(sock, length, deadline) or b''


def _recv_exactly(sock, count, deadline):
    """Read exactly `count` bytes, bounded by an overall wall-clock `deadline`
    (time.monotonic seconds). Returns None on EOF or once the deadline passes, so a
    peer that trickles bytes cannot keep the caller blocked past it."""
    buf = b''
    while len(buf) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None                     # overall deadline exceeded
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(count - len(buf))
        except (TimeoutError, socket.timeout):
            return None                     # no byte within the remaining budget
        if not chunk:
            return None
        buf += chunk
    return buf


class Framer:
    """Reassembles a single length-prefixed frame from a byte stream (the server
    side, fed QLocalSocket.readAll() chunks). Returns the payload once complete."""

    def __init__(self):
        self._buf = b''

    def feed(self, data):
        """Add bytes; return the completed payload (bytes) or None if not yet
        complete. Raises ValueError on an over-long frame."""
        self._buf += data
        if len(self._buf) < 4:
            return None
        (length,) = struct.unpack('<I', self._buf[:4])
        if length <= 0 or length > _MAX_REQUEST:
            raise ValueError('bad frame length')
        if len(self._buf) < 4 + length:
            return None
        frame = self._buf[4:4 + length]
        self._buf = self._buf[4 + length:]   # consume the frame so a reused Framer
                                             # advances instead of re-returning frame 1
        return frame
