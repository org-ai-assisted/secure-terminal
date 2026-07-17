# Pending AI reviews

Reviews that could not complete because a cloud reviewer (codex) was
rate-limited / timed out. Re-run each once the reviewer is available again,
ideally on a backoff timer (retry later, not in a tight loop), and fold in any
real findings. Remove an entry once it has had a clean review.

How to run one (see the `ai-review` skill):

    ai-review <range> --with codex --timeout 480 -- <paths...>

Prefer `--detach` for the longer ones, and re-run FOREGROUND with a single fast
reviewer if a detached run comes back empty.

## Open

(none)

## Done

- **TUI emulator (fixes commit)** -- `0c55f9d^..0c55f9d`: reviewed 2026-07-17.
  Found 2 more issues (alternate-screen transition DoS; uncapped restored-history
  seed), both fixed + regression-tested in `560dda6`.
- **OSC granular handlers + UI** -- `3d2f267^..23eb186`: reviewed 2026-07-17.
  Found 6 issues (legacy allow_title default clobber + lock bypass, OSC split
  across PTY reads, per-tab OSC state not persisted, OSC 7 path not sanitized,
  OSC 8 ST terminator), all fixed + regression-tested in `560dda6`.

## Note

A simpler alternative to specific ranges: once codex is available, review the
whole delta since the last clean point on `origin/master` and reconcile.
