# Pending AI reviews

Reviews that could not run because a cloud reviewer (codex) was unavailable /
rate-limited / timed out. Re-run each once the reviewer is available again,
ideally on a backoff timer (retry later, not in a tight loop), fold in any real
findings, and then DELETE the entry. Do NOT keep a log of completed reviews --
an empty "Open" list below means everything has been reviewed.

How to run one (see the `ai-review` skill):

    ai-review <range> --with codex --timeout 480 -- <paths...>

Prefer `--detach` for the longer ones, and re-run FOREGROUND with a single fast
reviewer if a detached run comes back empty.

## Open

### claude final pass on the transcript_text rework (commit 2d38ded)
- Scope: `ai-review --with claude 2d38ded^ 2d38ded` -- the document-walk
  transcript_text, the "pure ASCII" claim scoping, and the prompt chunk-boundary
  note.
- Why pending: the local `claude` reviewer timed out in the sandbox (481s, no
  output -- likely a headless-auth / sandbox issue), so this is a NO-RESULT, not
  a clean pass.
- codex + coderabbit already reviewed this work; their findings were reconciled
  and fixed (raw-stream -> document-walk, line-edit resolution, TUI coverage,
  claim scoping). Only the independent `claude` sweep is outstanding.
- Action: re-run on a backoff once the sandbox reviewer is reachable; fold in any
  findings and delete this entry.
