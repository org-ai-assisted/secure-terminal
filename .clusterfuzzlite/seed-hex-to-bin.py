#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Decode a hex string on stdin to raw bytes on stdout.

Standalone helper for .clusterfuzzlite/build.sh so the build script carries no
inline python program (-c). python3 is guaranteed in the OSS-Fuzz
base-builder-python image; xxd (vim-common) is not.
"""

import binascii
import sys

sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))
