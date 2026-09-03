#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""Per-tab resource isolation via cgroup v2.

Bounds one tab's forkbomb or memory runaway to its OWN cgroup, so it cannot
starve sibling tabs of PIDs nor drive a system OOM that kills the whole app.
Each tab's spawned shell (and every descendant) lives in
<base>/tab-N with a `pids.max` ceiling and a `memory.max` cap plus
`memory.oom.group`: a fork loop hits its own PID wall, and a memory runaway is
OOM-killed inside its cgroup, as a unit, leaving the app and other tabs alive.

Scope: intra-VM, tab-vs-tab robustness ONLY. This is NOT a security boundary --
the Qubes VM the terminal runs in is that. A hostile program has other ways to
misbehave; this just stops one tab's accidental (or crude) resource blowup from
taking down the others.

Fail-open EVERYWHERE: any cgroup operation that cannot complete leaves the tab
UNLIMITED and never blocks a shell from starting. Modern cgroup v2 (unified
hierarchy, delegated `memory`+`pids`) only; a legacy/v1 or non-delegated host
simply gets no per-tab limits, silently.

The process-identity model is untouched: the shell stays a direct pty.fork child
whose pid the app owns (reaping, exec-detection, the panic-button killpg all keep
working). cgroup membership is orthogonal to pid ownership -- we only move the
pid into a limited cgroup, never hand it to another manager.
"""

import os

## Unified cgroup v2 mount, and the two proc files describing our own placement
## and the machine's memory. Parameterised on every entry point so the tests can
## point them at a fake tree and exercise each fail-open branch.
CGROUP_ROOT = '/sys/fs/cgroup'
PROC_SELF_CGROUP = '/proc/self/cgroup'
PROC_MEMINFO = '/proc/meminfo'

## Fixed, no user knob. PIDS_MAX is generous: it stops a fork bomb dead while
## breaking no real program. MEM_FRACTION caps a single tab at half the memory
## currently AVAILABLE (see effective_mem), so a runaway hits its own cgroup OOM
## while the system still has headroom -- never dragging the app into a system OOM.
PIDS_MAX = 4096
MEM_FRACTION = 0.5

## Controllers a tab cgroup needs; both must be delegated to us or the feature is
## off (fail-open).
CONTROLLERS = ('memory', 'pids')


def _read(path):
    with open(path, encoding='utf-8') as handle:
        return handle.read()


def _write(path, text):
    ## A cgroup write either applies in full or raises; the fail-open callers turn
    ## any OSError into "no limit", never a half-applied one.
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)


def own_cgroup(root=CGROUP_ROOT, proc_cgroup=PROC_SELF_CGROUP):
    """Absolute path of THIS process's cgroup v2 directory, or None when the host
    is not a unified hierarchy (no single `0::<path>` line)."""
    try:
        content = _read(proc_cgroup)
    except OSError:
        return None
    for line in content.splitlines():
        if line.startswith('0::'):
            rel = line[3:].strip().lstrip('/')
            return os.path.normpath(os.path.join(root, rel))
    return None


def base_setup(root=CGROUP_ROOT, proc_cgroup=PROC_SELF_CGROUP):
    """Prepare THIS process's cgroup to host limited child cgroups, returning the
    base directory under which per-tab cgroups are created, or None if isolation
    is unavailable (not cgroup v2, controllers not delegated, or not writable).

    cgroup v2 forbids a cgroup from both holding processes and governing child
    controllers ("no internal processes"). So move ourselves (whole process, all
    threads) into a `main` leaf, then enable memory+pids in the base's
    subtree_control. Call ONCE at startup and cache the result: a second call
    would see us already relocated into `main` and mis-root.
    """
    base = own_cgroup(root, proc_cgroup)
    if base is None:
        return None
    try:
        controllers = _read(os.path.join(base, 'cgroup.controllers')).split()
    except OSError:
        return None
    if not all(name in controllers for name in CONTROLLERS):
        return None
    main = os.path.join(base, 'main')
    try:
        try:
            os.mkdir(main)
        except FileExistsError:
            pass
        _write(os.path.join(main, 'cgroup.procs'), str(os.getpid()))
        enabled = _read(os.path.join(base, 'cgroup.subtree_control')).split()
        missing = [name for name in CONTROLLERS if name not in enabled]
        if missing:
            _write(os.path.join(base, 'cgroup.subtree_control'),
                   ' '.join('+' + name for name in missing))
    except OSError:
        return None
    return base


def effective_mem(base, meminfo=PROC_MEMINFO):
    """Byte budget the MEM_FRACTION applies to: the memory currently AVAILABLE
    (MemAvailable), NOT total RAM. Sizing the cap from available memory keeps it
    below what the system can actually give, so a tab's runaway hits its OWN cgroup
    OOM while the system still has headroom -- a cap sized from TOTAL RAM would let a
    runaway exhaust the system first, and the system OOM killer could then pick the
    app instead of the tab. Falls back to the base cgroup's own memory.max when
    MemAvailable is unreadable; None if neither is knowable (then no memory cap)."""
    try:
        for line in _read(meminfo).splitlines():
            if line.startswith('MemAvailable:'):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    try:
        raw = _read(os.path.join(base, 'memory.max')).strip()
        if raw != 'max':
            return int(raw)
    except (OSError, ValueError):
        pass
    return None


def create_tab(base, name):
    """Create a FRESH limited cgroup <base>/<name> and return its path, or None on
    any failure (fail-open: the tab then runs unlimited). Sets pids.max, and -- when a
    memory budget is knowable -- memory.max + memory.oom.group + memory.swap.max=0 so
    the tab is OOM-killed as a unit at a hard RAM wall. All-or-nothing: a partial
    failure removes the cgroup and returns None rather than leave a half-limited tab.

    The name is caller-unique (per process + tab), so the mkdir must SUCCEED: an
    existing <name> is a stale or foreign cgroup (a crashed instance's leftover, or a
    concurrent one) and is NOT adopted -- reusing it would silently share the new
    shell's limits with whatever processes it already holds. mkdir failure (EEXIST
    included) fails open.
    """
    if base is None:
        return None
    path = os.path.join(base, name)
    try:
        os.mkdir(path)
    except OSError:
        return None
    try:
        _write(os.path.join(path, 'pids.max'), str(PIDS_MAX))
        mem = effective_mem(base)
        if mem is not None:
            _write(os.path.join(path, 'memory.max'),
                   str(int(mem * MEM_FRACTION)))
            _write(os.path.join(path, 'memory.oom.group'), '1')
            # Deny swap so memory.max is a hard RAM wall: without it a runaway can be
            # paged out past the cap instead of hitting the cgroup OOM. Present on
            # every modern swap-accounting kernel; a write failure fails the tab open.
            _write(os.path.join(path, 'memory.swap.max'), '0')
    except OSError:
        remove_tab(path)
        return None
    return path


def open_procs(path):
    """Open the tab cgroup's cgroup.procs for the child to write its own pid into,
    O_CLOEXEC so a successful execvp drops it. None (fail-open) on any error."""
    if path is None:
        return None
    try:
        return os.open(os.path.join(path, 'cgroup.procs'),
                       os.O_WRONLY | os.O_CLOEXEC)
    except OSError:
        return None


def place_pid(fd, pid):
    """Write `pid` into an open cgroup.procs fd. Best-effort: on failure the
    process stays in its inherited (parent) cgroup -- unlimited, never blocked.
    Called from the post-fork/pre-exec child, so it must not raise."""
    try:
        os.write(fd, str(pid).encode('ascii'))
    except OSError:
        pass          # cgroup gone/unwritable -> stay in the inherited cgroup, never block


def remove_tab(path):
    """Best-effort removal of a tab cgroup. An empty cgroup is rmdir-able; a
    still-populated or vanished one raises and is ignored."""
    if path is None:
        return
    try:
        os.rmdir(path)
    except OSError:
        pass          # still populated or already gone -> systemd reaps it at app exit
