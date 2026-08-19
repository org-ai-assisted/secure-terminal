# Known issues and design limitations

Open trade-offs in the current design. Not bugs with a clear fix; each needs a
decision.

## 1. Partial input line + the CLI/TUI re-export

Switching a tab between CLI and TUI mode re-exports `TERM` into the running shell
by writing `export TERM=...\r` at the prompt (so the shell re-reads terminfo
without a restart). If you have a **partially typed command** at the prompt and
then toggle mode, the re-export is appended to that line and the `\r` submits the
combined text.

- Impact: usually a harmless `command not found` on the mangled line, not a
  dangerous command. There is no reliable, shell-agnostic way to detect or
  preserve a partial input line from outside the shell.
- The switch IS already refused while a foreground program owns the terminal, and
  the re-export is skipped for `-- PROGRAM` tabs (only the default login shell
  gets it) -- so this is specifically the bare-prompt, mid-typing case.
- Options:
  - (a) Prefix the re-export with a line-clear (`Ctrl-A Ctrl-K`): safe, but
    discards whatever you had typed.
  - (b) Drop the auto-submit: switch rendering only, and let `TERM` update on the
    next command the shell runs.
  - (c) Accept it as a rare edge (current behaviour).

## 2. `TERM=secure-terminal` breaks curses apps over ssh

In CLI mode a tab advertises `TERM=secure-terminal`. `ssh` forwards `TERM` to the
remote host, which does not have this custom terminfo entry, so a remote
curses/readline program reports `unknown terminal` and degrades. Installing the
entry in the LOCAL system terminfo db does not help remote hosts.

- Design expectation: use **TUI mode** for ssh -- it advertises `xterm-256color`,
  which every host has.
- This is the concrete downside of keeping the custom entry instead of the
  standard `dumb`. `dumb` is in every base terminfo db (resolves over ssh) and is
  fingerprint-neutral, but drops all colour and in-line editing. See the
  compatibility page's terminfo comparison.
- Worth reconsidering `dumb` for CLI mode if ssh-in-CLI is a common workflow.

## 3. CLI-mode tab-completion garble -- FIXED (residual narrow-width limit)

Was: `ls a<Tab>` cycling completion candidates rendered garbage, e.g.
`aiuto-generated-dan-pages`. Root cause: a completion menu emits a BEL (`\x07`),
and the CLI line renderer treated BEL as a display cell, shifting the cursor one
column off; zle's following backspace+reprint then duplicated a character. BEL is
cursor-neutral on every real terminal (it rings the bell, writes no glyph, moves
no column) -- now consumed in `feed_line_edits`, aligning with `render_output`
which already dropped it. Fixed + regression-tested at all realistic widths.

Residual (not the reported bug): at a terminal SO narrow that the prompt itself
wraps (< ~50 columns for a 52-char prompt) AND a candidate spans multiple display
rows, zle -- which cannot move the cursor UP under the restricted entry (`cuu@`)
-- emits its own broken no-cursor-up redraw (a partial reprint that does not
reconstruct the row). No renderer can salvage that; a real no-cursor-up terminal
shows the same garble. It only bites below a normally-usable width. If it ever
matters, the fix is at the terminfo level (a wide reported width, or restoring a
minimal up-capability), not in the renderer.

## 4. Line pitch is ~1px tighter than gnome-terminal/VTE

The same font renders at a 26px line pitch in secure-terminal (Qt QPlainTextEdit)
vs 27px in gnome-terminal (VTE), so text in the homepage before/after slider
drifts ~1px per line. Both use their engine's natural default line height (no
added leading) -- it is toolkit metric rounding, not a spacing choice, so
secure-terminal already matches gnome's default POLICY. A configurable
line-spacing setting is not a one-liner: QPlainTextEdit's layout ignores
line-height, so it needs a hot-path widget change. Full description, measurement,
options and the resume pointer: `line-spacing.md`.
