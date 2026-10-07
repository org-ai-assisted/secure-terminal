## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## ClusterFuzzLite Python Dockerfile.
## https://google.github.io/clusterfuzzlite/build-integration/python-lang/

## Image: gcr.io/oss-fuzz-base/base-builder-python.
##
## Trust root - this image path is the canonical Python base for
## OSS-Fuzz / ClusterFuzzLite, published by Google's OSS-Fuzz
## project. The Dockerfile that produces this image lives in the
## OSS-Fuzz repo; the language-specific guide tells integrators to
## use this exact path:
##   https://github.com/google/oss-fuzz/tree/master/infra/base-images/base-builder-python
##   https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang/
##
## The digest below is kept in sync across our packages (helper-scripts,
## kloak, ...) so every repo builds on the same audited base. It is
## resolved from the 'latest' tag via the registry manifest API
## (verification step, not trust source):
##   https://gcr.io/v2/oss-fuzz-base/base-builder-python/manifests/latest
##   (docker-content-digest header)
##
## :latest stays matched to clusterfuzzlite-run-fuzzers:v1's ABI
## (Ubuntu 20.04 / glibc 2.31) - OSS-Fuzz keeps this guarantee so
## binaries built in the base-builder land cleanly in the run
## container. Do not pin to the ubuntu-24-04 tag without also
## forking CFLite to override its hardcoded run image.
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:9dd557a4ba0e0cdfbeabc0bb115c98896f2dab68c3e8f301abf169469b8b5ef5

## sanitize.py imports regex unconditionally: the grapheme-cluster flood cap
## needs UAX #29 \X, which the stdlib re cannot express. The base image has no
## Debian packaging, so install the wheel; without it every harness fails
## bad_build_check at startup with ModuleNotFoundError.
RUN pip3 install --no-cache-dir regex

## sanitize.py imports confusable_homoglyphs as a HARD dependency too: the confusable/
## homoglyph detection fails loud (ImportError) if the package is absent rather than
## silently degrading. The base image has no Debian packaging, so install the wheel;
## without it every harness fails bad_build_check at startup with ModuleNotFoundError.
RUN pip3 install --no-cache-dir confusable-homoglyphs

## The base image compiles CPython into /usr/local (no apt python3), so it ships
## python3 at /usr/local/bin/python3 with NO /usr/bin/python3. Our scripts use the
## project-standard `#!/usr/bin/python3` shebang and are run DIRECTLY (style R-193:
## via the shebang, not `python3 <script>`, which drops the shebang's flags), so
## build.sh's `./seed-hex-to-bin.py` would fail "bad interpreter: /usr/bin/python3".
## Symlink the absolute path to the image's own python3 (same interpreter PATH already
## resolves; /usr/local/bin precedes /usr/bin, so this shadows nothing).
RUN ln -sf "$(command -v python3)" /usr/bin/python3

## The shared CFLite smoke-run guard lives in org-ai-assisted/dist-ai (the single
## source for our cross-repo test/fuzz assets), NOT this package. Clone it at
## build time; build.sh sources $SRC/dist-ai/usr/share/clusterfuzzlite-lib/
## smoke-run.bash. dist-ai is public; @master per the org's branch-tracking model.
RUN git clone --depth 1 --branch master \
      https://github.com/org-ai-assisted/dist-ai "$SRC/dist-ai"

COPY . $SRC/secure-terminal
COPY .clusterfuzzlite/build.sh $SRC/build.sh
WORKDIR $SRC/secure-terminal
