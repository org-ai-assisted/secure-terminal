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

- **TUI emulator (fixes commit)** -- `0c55f9d^..0c55f9d`
  - Files: `usr/lib/python3/dist-packages/secure_terminal/terminal.py`
  - The FIRST review of the emulator (`6e3534b`) completed and found 5 real
    bugs, all fixed + regression-tested. The confirmatory pass on the fixes
    (`0c55f9d`) never completed (codex timeout). Re-run to confirm the fixes.

- **OSC granular handlers + UI** -- `3d2f267^..23eb186`
  - Files: `terminal.py`, `main.py`, `sanitize.py`
  - Security-sensitive: clipboard (OSC 52) write, palette (OSC 4/10/11/12)
    contrast guard, hyperlink (OSC 8) surfacing, the per-feature dispatcher.
  - Self-review already caught + fixed a DoS (OSC 4 palette-flood re-render).
    A clean external review is still wanted.

## Note

A simpler alternative to specific ranges: once codex is available, review the
whole delta since the last clean point on `origin/master` and reconcile.
