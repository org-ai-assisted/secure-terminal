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

### agy + glm pass on the clash/bypass hardening (704e942..HEAD, now committed)
- Scope: the escape-grammar widening in `ANSI_RE` (charset designators, SS2/SS3),
  the `tui_cell` default-ignorable + combining-run caps, the shared
  `is_bidi_control` / `is_invisible` predicates, `cli.py`'s escape carry,
  `cli_terminfo_dir` freshness + both-entries rule, and the `Cs@/Cr@/rv@/xr@`
  terminfo cancellations. Re-run over the same range the other reviewers
  covered (704e942 = the R-180 base, 936fe62 = the last code commit before
  the pass was recorded):
  `ai-review --only agy,glm 704e942..936fe62`.
- Why pending: both are quota-locked until roughly 2026-08-04 (weekly lockout),
  so they were not attempted -- a NO-RESULT for the two non-Claude, non-OpenAI
  model families, not a clean pass.
- codex + coderabbit + static + claude did run on the related terminfo commit
  (79df146) and their findings are folded in.
- Action: re-run on a backoff after the quota resets; fold in any findings and
  delete this entry.
- Since committed, codex + coderabbit + static DID run over 704e942..HEAD and
  their findings are folded in: the granular-OSC legacy lock escape, the
  ungated controls whose setters now refuse a locked change, the unbounded
  lru_cache on _is_mark, a leading zero-width character left unmarked in the
  TUI grid, and a private base64.binascii re-export. agy + glm remain a
  NO-RESULT for this range, not a clean pass.

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

### claude final pass on the #93/#94/#95/#98/#99 session work (58b780f..00b71f4)
- Scope: `ai-review --with claude 58b780f` -- the terminate/foreground-pgrp +
  self-kill guard (#93), the EL-burst TUI advisory (#94), the clickable settings
  InfoTip (#95), the XCB-teardown close fix (#98), and the restore-placeholder
  machinery + its interaction hardening (#99).
- Files: `usr/lib/python3/dist-packages/secure_terminal/{main.py,terminal.py,sanitize.py}`.
- Why pending: the local `claude` reviewer timed out with no output on BOTH a
  full-session and a 27-line scope (same recurring sandbox headless issue as the
  entry above) -- NO-RESULT, not a clean pass.
- coderabbit already ran clean; its two findings (placeholder interaction safety,
  placeholder label field) were reconciled, fixed (00b71f4), and gated at 100%.
  Only the independent `claude` sweep is outstanding.
- Action: re-run on a backoff once the sandbox reviewer is reachable; fold in any
  findings and delete this entry.
