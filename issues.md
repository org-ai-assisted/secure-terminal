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

## 3. CLI-mode redraw garble on completion / wrapped lines

An interactive shell's line editor (zsh's zle) redraws the prompt line with
optimised, cursor-RELATIVE sequences: differential rewrites (`CSI nD`/`CSI nC` +
`CSI K`), and partial-line reprints after a completion listing. These assume the
terminal can move the cursor UP to a previous row -- a capability the restricted
`secure-terminal` entry deliberately cancels (`cuu@`). With no cursor-up, zle
falls back to redraws that operate on the current DISPLAY row; when the prompt +
input WRAP past the terminal width, the CLI line renderer (which models one
logical line) and zle's wrapped-row cursor math diverge, and the line garbles.

- Symptom: `ls a<Tab>` cycling long candidates can render e.g.
  `aiuto-generated-dan-pages` or corrupt the prompt to `-terminal% ...`.
- Only bites when the prompt+input is long enough to wrap; short lines are fine.
- Root cause is structural: faithfully replaying a full terminal's cursor-relative
  redraws in a line-oriented renderer under a no-cursor-up terminfo. `dumb` (even
  fewer caps) does not obviously fix it -- zle still cannot move up.
- Options: (a) a substantial CLI-renderer investment to track display-row cursor
  position across wraps; (b) report a very wide width to the shell so its line
  never wraps (display trade-off); (c) reconsider the CLI terminfo/mode approach.
  This is the strongest of the accumulating signals that the custom restricted
  entry, while elegant, is fragile against real interactive redraws.
