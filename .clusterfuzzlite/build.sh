#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite build script. Invoked inside the OSS-Fuzz
## base-builder-python container by the ClusterFuzzLite tooling.
##
## Standard OSS-Fuzz contract:
##   - $SRC      - source root (we COPY the repo here in the Dockerfile)
##   - $OUT      - output directory; harnesses go here
##   - compile_python_fuzzer - OSS-Fuzz helper that wraps a python
##                              harness into a runnable executable
##                              and copies it to $OUT/

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

## NOTE: no CI-guard here. This script is invoked by ClusterFuzzLite
## inside the OSS-Fuzz base-builder container; it does not see the
## GitHub Actions CI=true env var. The trust boundary is the container
## itself, not this script.

cd -- "$SRC/secure-terminal"

## Make secure_terminal importable inside the harnesses. The sanitize
## core is Qt-free and self-contained, so no extra dependency needs to
## be cloned here.
export PYTHONPATH="$SRC/secure-terminal/usr/lib/python3/dist-packages${PYTHONPATH+:${PYTHONPATH}}"

## Wrap each fuzz/fuzz_*.py harness for OSS-Fuzz's Python runtime.
for harness in fuzz/fuzz_*.py; do
  name="$(basename -- "${harness}" .py)"
  compile_python_fuzzer "${harness}"
  printf 'compiled %s\n' "${name}"
done
