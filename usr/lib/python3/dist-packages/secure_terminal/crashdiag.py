"""Durable crash diagnostics: make every crash leave a readable trace.

A GUI-launched secure-terminal (from a .desktop file, a session manager, or an
autostart unit) has no visible stderr, so a crash vanishes with no diagnostic --
exactly the reported gap. Three failure paths matter:

- a Python exception escaping a Qt slot: PyQt6 delivers it to `sys.excepthook`
  and then aborts the process (SIGABRT), so the traceback is the only clue;
- a native fatal signal (SIGSEGV / SIGABRT / SIGFPE / SIGBUS / SIGILL) from Qt's
  C++ layer (e.g. a bad paint/layout at extreme zoom);
- a HANG: a wedged event loop emits no signal and no exception, so neither path
  above fires and the log stays empty. On a ptrace-restricted VM (Kicksecure
  security-misc `kernel.yama.ptrace_scope=3`, no py-spy/gdb) a live freeze is then
  un-introspectable. Two complementary dumpers close that: an ALWAYS-ON watchdog
  thread auto-dumps every thread's stack when the main-thread heartbeat stalls
  (no human action, catches an unattended freeze), and an on-demand SIGUSR1 dumper
  (`kill -USR1 <pid>`) does the same on request. Both append to the same log.

The first two are teed to a durable, owner-only file at one fixed path under the
state root (found regardless of instance group), and to stderr for a terminal
launch. `faulthandler` runs inside the signal handler and cannot call back into
Python, so it writes the dump straight to the log's fd; a terminal user reads the
same file. A handler here must never itself raise -- losing the diagnostic is the
one unacceptable outcome.
"""

import datetime
import faulthandler
import os
import signal
import stat
import sys
import threading
import time
import traceback

CRASH_LOG_NAME = 'crash.log'

# Always-on hang detector knobs. The main-thread heartbeat timer ticks every
# HANG_HEARTBEAT_MS; the watchdog thread declares a stall when the loop has not
# advanced the heartbeat for HANG_WATCHDOG_DEFAULT_SECS (env-overridable). The
# threshold is kept well above the longest legitimate main-thread pause (the 5s
# exec handshake, a modal still ticks timers) so a busy app is never mis-flagged.
HANG_HEARTBEAT_MS = 1000
HANG_WATCHDOG_DEFAULT_SECS = 12.0
HANG_WATCHDOG_MIN_SECS = 2.0
HANG_WATCHDOG_ENV = 'SECURE_TERMINAL_HANG_WATCHDOG_SECS'


def crash_log_path(state_root):
    return os.path.join(state_root, CRASH_LOG_NAME)


def _open_append(path):
    # 0600 + O_NOFOLLOW, matching session's other durable diagnostic writers
    # (terminate-debug.txt, transcripts): a planted symlink cannot redirect the
    # write, and the log stays owner-only since a traceback can carry paths/argv.
    # O_NONBLOCK + a regular-file check: a planted FIFO at this path would else make
    # O_WRONLY BLOCK until a reader opens it, hanging the launch forever (O_NOFOLLOW
    # rejects only a symlink, not a FIFO). O_NONBLOCK is a no-op on a regular file.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
                 | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError('crash log is not a regular file')
    except OSError:
        os.close(fd)
        raise
    return os.fdopen(fd, 'a', encoding='utf-8')


def _banner(kind):
    return ('\n===== secure-terminal %s pid=%d %s =====\n'
            % (kind, os.getpid(),
               datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')))


def format_exception(exc_type, exc, tb):
    """The traceback text. A standalone function so a test can assert on the
    formatting without installing a process-global excepthook."""
    return ''.join(traceback.format_exception(exc_type, exc, tb))


def _tee(streams, text):
    for stream in streams:
        if stream is None:
            continue
        try:
            stream.write(text)
            stream.flush()
        except Exception:      # pylint: disable=broad-except
            pass               # a crash handler must never raise -- diagnostic first


def make_excepthook(log, stderr):
    """The sys.excepthook: tee an unhandled exception's traceback to the durable
    log and to stderr. Does NOT chain the previous hook -- PyQt aborts after this
    regardless, and the default hook would only re-print to (invisible) stderr;
    a non-Qt exit still shows the trace via the stderr write here."""
    def excepthook(exc_type, exc, tb):
        _tee((log, stderr), _banner('unhandled exception')
             + format_exception(exc_type, exc, tb))
    return excepthook


def write_note(log, kind, text):
    """Append a one-off note (e.g. a captured Qt Critical/Fatal message, which
    aborts the process right after) to the durable log. Best-effort."""
    _tee((log,), _banner(kind) + text)


def append_line(log, text):
    """Append one newline-terminated line to the durable log, with NO banner, for
    dense opt-in tracing (e.g. the IPC lifecycle under SECURE_TERMINAL_IPC_DEBUG).
    A no-op when there is no log. Best-effort -- a trace must never raise out of a
    Qt slot."""
    if log is None:
        return
    _tee((log,), text + '\n')


def echo_stderr(text, stream=None):
    """Best-effort stderr echo of a Qt message line. A broken/closed stderr -- the
    exact GUI case the durable log exists for -- must never raise out of the Qt
    message handler, so this swallows the failure (the durable copy is written first)."""
    _tee((stream if stream is not None else sys.stderr,), text + '\n')


def qt_message_is_fatal(mode):
    """True for a Qt Critical/Fatal message (worth persisting). Compared by the
    enum's numeric value so this stays importable without PyQt (a plain-Python
    unit test), and tolerant of either the enum or its int."""
    # QtMsgType: Debug=0, Warning=1, Critical=2, Fatal=3, Info=4.
    return int(getattr(mode, 'value', mode)) in (2, 3)


def note_qt_message(log, mode, message):
    """Persist a Qt Critical/Fatal message (Qt aborts the process right after one)
    to the durable log. A no-op when there is no log yet or the message is not
    fatal, so the Qt message handler can call this UNCONDITIONALLY."""
    if log is None or not qt_message_is_fatal(mode):
        return
    write_note(log, 'qt message', message + '\n')


def register_hang_dumper(stream):
    """On-demand all-thread stack dump for a HANG. A wedged event loop raises no
    exception and triggers no fatal signal, so excepthook/faulthandler never fire
    and the log stays empty; on a ptrace-restricted VM there is then no external
    way to see where it is stuck. SIGUSR1 (the app uses no USR signal) dumps every
    thread's Python stack to `stream`, so `kill -USR1 <pid>` introspects a live
    freeze. chain=False: there is no prior USR1 handler worth preserving, and an
    unhandled SIGUSR1's default action is to TERMINATE -- so registering it is also
    what makes the signal safe to send."""
    faulthandler.register(signal.SIGUSR1, file=stream, all_threads=True, chain=False)


class _HangWatchdog:
    """Auto hang detector. A wedged Qt event loop raises no exception and triggers
    no fatal signal, so excepthook/faulthandler never fire and the on-demand SIGUSR1
    dumper needs a human to send the signal -- useless for a freeze nobody is
    watching. This daemon thread watches a heartbeat the MAIN thread advances (via a
    QTimer); when the loop stops servicing it past `threshold` seconds, the thread --
    which keeps running while the main thread is wedged -- dumps EVERY thread's Python
    stack to the durable log. Dump-only: it never kills or recovers the app (a
    security terminal; recovery is the operator's call). One dump per wedge; it
    re-arms when the heartbeat advances again, so a recover-then-hang is captured
    twice rather than lost."""

    def __init__(self, log, threshold):
        self._log = log
        self._threshold = threshold
        self._lock = threading.Lock()
        self._beat = time.monotonic()
        self._dumped = False
        self._stop = threading.Event()
        # Poll a quarter of the threshold so detection latency stays small relative
        # to it (worst case ~1.25x the threshold), floored at 0.25s to avoid a hot
        # spin. At the shipped 12s threshold this is a 3s poll; the floor only bites
        # for the tiny thresholds a test uses.
        self._interval = max(0.25, threshold / 4.0)
        self._thread = threading.Thread(target=self._run, name='st-hang-watchdog',
                                        daemon=True)

    def beat(self):
        """Advance the heartbeat (called from the main thread by the heartbeat
        timer). Re-arms the dumper after a recovery."""
        with self._lock:
            self._beat = time.monotonic()
            self._dumped = False

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        """Stop the watchdog thread (tests; the process otherwise runs it for life
        as a daemon thread that never blocks exit)."""
        self._stop.set()

    def _run(self):
        while not self._stop.wait(self._interval):
            do_dump = False
            with self._lock:
                stalled = time.monotonic() - self._beat
                if stalled >= self._threshold and not self._dumped:
                    # Claim the dump UNDER the lock, BEFORE the (possibly slow) _dump: a
                    # beat() that recovers the loop mid-dump then correctly re-arms (sets
                    # _dumped False) instead of being clobbered back to True afterwards --
                    # which would leave the NEXT real wedge undumped until another beat.
                    self._dumped = True
                    do_dump = True
            if do_dump:
                self._dump(stalled)

    def _dump(self, stalled):
        try:
            self._log.write(
                _banner('hang detected')
                + 'event loop stalled %.1fs (threshold %.1fs); '
                  'all-thread stack follows\n' % (stalled, self._threshold))
            self._log.flush()
        except Exception:      # pylint: disable=broad-except
            pass               # a hang handler must never raise -- diagnostic first
        try:
            # dump_traceback is safe to call from a non-main thread and prints every
            # thread's Python stack, so the wedged MAIN thread's frames are captured.
            faulthandler.dump_traceback(all_threads=True, file=self._log)
            self._log.flush()
        except Exception:      # pylint: disable=broad-except
            pass


def hang_threshold_from_env():
    """The watchdog stall threshold in seconds: env override, floored at
    HANG_WATCHDOG_MIN_SECS, else the default. A malformed value falls back to the
    default rather than disabling the watchdog."""
    raw = os.environ.get(HANG_WATCHDOG_ENV)
    if raw is None:
        return HANG_WATCHDOG_DEFAULT_SECS
    try:
        val = float(raw)
    except ValueError:
        return HANG_WATCHDOG_DEFAULT_SECS
    return max(HANG_WATCHDOG_MIN_SECS, val)


# The live watchdog, set by start_hang_watchdog so the main-thread heartbeat()
# timer can find it without the caller threading a handle through.
_watchdog = None


def start_hang_watchdog(log, threshold=None):
    """Start the always-on auto hang detector against `log` and return it (or None
    when there is no log). Call once from main() as the Qt event loop is about to
    run -- NOT during startup, whose synchronous window/tab build can legitimately
    exceed the threshold under load. Pair with heartbeat() driven by a main-thread
    QTimer at HANG_HEARTBEAT_MS."""
    global _watchdog
    if log is None:
        return None
    if threshold is None:
        threshold = hang_threshold_from_env()
    stop_hang_watchdog()          # never leak a prior watchdog thread on a second call
    _watchdog = _HangWatchdog(log, threshold).start()
    return _watchdog


def stop_hang_watchdog():
    """Stop the live hang watchdog, if any, and clear it. Called once after the Qt
    event loop returns (app.exec), so the detector lives exactly as long as the loop
    it watches -- and a test that drives main() with a mocked app.exec starts then
    stops it at once rather than leaking a thread that would later false-dump.
    Idempotent."""
    global _watchdog
    watchdog = _watchdog
    _watchdog = None
    if watchdog is not None:
        watchdog.stop()


def heartbeat():
    """Advance the hang watchdog's heartbeat. Wired to a main-thread QTimer; a no-op
    when no watchdog is running, so the timer can call it unconditionally."""
    watchdog = _watchdog
    if watchdog is not None:
        watchdog.beat()


def install(state_root, stderr=None):
    """Wire crash diagnostics; return (path, log_stream). Call once, early in
    main(), before the Qt event loop. The log stream is kept open for the process
    lifetime (faulthandler writes to its fd from the signal handler)."""
    if stderr is None:
        stderr = sys.stderr
    # Register the SIGUSR1 hang dumper against stderr FIRST, so the signal is NON-FATAL
    # even if the durable log fails to open below. An unregistered SIGUSR1 TERMINATES the
    # process (default action), so an operator's `kill -USR1` on a hung instance would kill
    # it rather than dump -- the one thing the dumper exists to prevent. Re-pointed at the
    # durable log once it opens (the preferred target; faulthandler keeps only the last
    # file registered per signal).
    # Best-effort: a CLOSED/unusable stderr (a GUI launch may have none) makes
    # faulthandler.register raise -- that must NOT abort the whole install, which would lose
    # the durable log too. Swallow it; the log registration below is the real target.
    try:
        register_hang_dumper(stderr)
    except (OSError, RuntimeError, ValueError):
        pass
    path = crash_log_path(state_root)
    log = _open_append(path)
    # Native fatal signals -> dump every thread's Python stack to the durable log.
    faulthandler.enable(file=log, all_threads=True)
    register_hang_dumper(log)
    sys.excepthook = make_excepthook(log, stderr)
    return path, log


def install_best_effort(state_root, stderr=None):
    """install(), but never raise: a launch must not fail because the crash log
    could not be opened or diagnostics could not be wired. Returns the log stream,
    or None when the durable log is unavailable -- in which case install() has still
    registered the SIGUSR1 hang dumper against stderr, so `kill -USR1` dumps there
    instead of killing the app. Catches faulthandler's RuntimeError/ValueError too,
    not only the log's OSError, to honour the never-raise contract."""
    try:
        return install(state_root, stderr)[1]
    except (OSError, RuntimeError, ValueError):
        return None
