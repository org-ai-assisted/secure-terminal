#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Resolve the apt package set for the local-adversarial-corpus workflow.

Reads the single source of truth (.github/dm-consumer.yml, the dist-ai-tests
apt-packages list) and prints `packages=<space-separated list>` for $GITHUB_OUTPUT.
Kept in one place rather than hand-copied: usr/bin/secure-terminal preflight-checks
its runtime deps and exits 1 naming the first missing one, so a stale copy would
never start the app -- the harness then refuses to trust the whole run.

That list targets the debian:trixie-slim container the reusable dist-ai-tests job
runs in; THIS workflow installs it on the bare ubuntu-24.04 host, where a few Qt6
packages are split differently. apt aborts the WHOLE install on the first "Unable
to locate package", so translate the trixie names that do not exist on noble. Qt6
SVG imageformats plugin (libqsvg.so): trixie ships it in qt6-svg-plugins, noble
bundles it into libqt6svg6.
"""

import yaml

TRIXIE_TO_NOBLE = {'qt6-svg-plugins': 'libqt6svg6'}

with open('.github/dm-consumer.yml', encoding='utf-8') as handle:
    declared = yaml.safe_load(handle)['dist-ai-tests']['apt-packages']
packages = ' '.join(TRIXIE_TO_NOBLE.get(name, name) for name in declared.split())
print('packages=%s' % packages)
