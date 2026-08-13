#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Preflight dependency check: fail loud on stderr with a non-zero exit BEFORE
the app starts, instead of a confusing mid-import traceback when a runtime
dependency is missing. Deliberately tiny and stdlib-only (no Qt/pyte import), so
it still runs when the heavy dependencies are the ones absent. No GUI use -- the
entry-point launchers call require() before importing the app."""

import importlib.util
import sys


def require(*deps):
    """Exit 1 if ANY dependency is missing, naming every missing module on stderr
    alongside a SINGLE Debian install command listing ALL declared packages -- not
    only the one that failed -- so one `apt install` line pulls the complete set
    (installing just the first-missing package would only surface the next missing
    one on the following launch). Each dep is an (import_name, apt_package) pair;
    dotted import names are supported. A no-op when every dependency is present."""
    missing = []
    for module, _package in deps:
        try:
            present = importlib.util.find_spec(module) is not None
        except (ImportError, ValueError):   # a dotted name whose parent is absent
            present = False
        if not present:
            missing.append(module)
    if not missing:
        return
    packages = []
    for _module, package in deps:
        if package not in packages:
            packages.append(package)        # dedup, preserve declared order
    sys.stderr.write(
        'secure-terminal: missing dependency: %s\n'
        'if on debian, install all dependencies:\n'
        'sudo apt install %s\n' % (', '.join(missing), ' '.join(packages)))
    raise SystemExit(1)
