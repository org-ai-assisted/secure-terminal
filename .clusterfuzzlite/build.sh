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
##
## SRC and OUT are exported by the OSS-Fuzz base-builder container, not this
## script, so shellcheck cannot see their assignment.
# shellcheck disable=SC2154

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose
export LC_ALL=C

## NOTE: no CI-guard here. This script is invoked by ClusterFuzzLite
## inside the OSS-Fuzz base-builder container; it does not see the
## GitHub Actions CI=true env var. The trust boundary is the container
## itself, not this script.

cd -- "${SRC}/secure-terminal"

## Make secure_terminal importable inside the harnesses. The sanitize
## core is Qt-free and self-contained, so no extra dependency needs to
## be cloned here.
export PYTHONPATH="${SRC}/secure-terminal/usr/lib/python3/dist-packages${PYTHONPATH+:${PYTHONPATH}}"

## Shared CFLite smoke-run guard (single source of truth in dist-ai; the
## Dockerfile clones it to $SRC/dist-ai). It bounds-runs each compiled fuzzer
## with PYTHONPATH + every *_REPO override unset and FAILs the build on a
## non-zero exit -- catching a frozen-bundle SystemExit(77) silent skip that
## would otherwise pass vacuously.
# shellcheck disable=SC1090,SC1091
source "${SRC}/dist-ai/usr/share/clusterfuzzlite-lib/smoke-run.bash"

## Explode the shared seed corpus into individual input files. Without a seed
## corpus every run cold-starts from empty and burns its whole budget
## rediscovering that ESC exists; these seeds carry the hostile shapes the
## sanitizer actually defends against (C1, bidi, zero-width, combining runs,
## oversized numeric params, framer length prefixes).
##
## Stored as NAME<space>HEX so the file stays pure ASCII and survives the
## repo-wide non-ASCII gate; the same file is driven by the dist-ai suite
## test_fuzz_harnesses.py, so the corpus cannot rot unnoticed.
seed_dir="$(mktemp --directory)"
seed_count=0
while read -r seed_name seed_hex; do
  case "${seed_name}" in
    ''|'##'*)
      continue
      ;;
  esac
  [ -n "${seed_hex}" ] || continue
  ## Decode via the standalone seed-hex-to-bin.py (python3, not xxd: the
  ## base-builder-python image guarantees python3, while xxd rides in
  ## vim-common and may be absent).
  printf '%s' "${seed_hex}" \
    | .clusterfuzzlite/seed-hex-to-bin.py \
    > "${seed_dir}/${seed_name}"
  seed_count=$(( seed_count + 1 ))
done < fuzz/corpus/seeds.txt
printf 'prepared %s seed inputs\n' "${seed_count}"

## Wrap each fuzz/fuzz_*.py harness for OSS-Fuzz's Python runtime, and give each
## the same seed corpus (every harness reads these bytes through its own
## FuzzedDataProvider, so one seed exercises a different shape in each).
for harness in fuzz/fuzz_*.py; do
  name="$(basename -- "${harness}" .py)"
  compile_python_fuzzer "${harness}"
  ## Smoke-run the compiled onefile to catch a frozen-bundle SILENT SKIP.
  cflite_smoke_run_fuzzers "${name}"
  ( cd -- "${seed_dir}" && zip --quiet --recurse-paths \
      "${OUT}/${name}_seed_corpus.zip" . )
  printf 'compiled %s (+%s seeds)\n' "${name}" "${seed_count}"
done
