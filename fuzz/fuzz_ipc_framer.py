#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Atheris fuzz harness for the single-instance IPC frame reassembler.

ipc.Framer reassembles one length-prefixed frame from a stream of same-UID
socket chunks. For any byte stream, fed in any chunking, it must:
  - never raise except the declared ValueError on an over-long/zero length;
  - return None until the frame is complete;
  - return exactly the declared payload (its length == the 4-byte header) once
    complete -- so a hostile peer can neither over-read nor desync the server.

Run locally:
    python3 -m atheris fuzz/fuzz_ipc_framer.py -max_total_time=300
"""

import struct
import sys

import atheris

with atheris.instrument_imports():
    from secure_terminal.ipc import Framer, _MAX_REQUEST


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    framer = Framer()
    fed = b''
    for _ in range(fdp.ConsumeIntInRange(1, 8)):
        chunk = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096))
        fed += chunk
        try:
            out = framer.feed(chunk)
        except ValueError:
            # ValueError is allowed ONLY for a declared-invalid length (zero or
            # over the cap); for any other length it is a regression -> re-raise.
            length = struct.unpack('<I', fed[:4])[0] if len(fed) >= 4 else 0
            if 0 < length <= _MAX_REQUEST:
                raise
            return
        if out is None:
            continue                    # not complete yet
        if not isinstance(out, bytes):
            raise RuntimeError("Framer.feed returned non-bytes: {0!r}".format(out))
        length = struct.unpack('<I', fed[:4])[0]
        if out != fed[4:4 + length]:
            raise RuntimeError(
                "Framer returned the wrong payload: got {0!r} want {1!r} fed={2!r}"
                .format(out, fed[4:4 + length], fed))
        return


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == '__main__':
    main()
