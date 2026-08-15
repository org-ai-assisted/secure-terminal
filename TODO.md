# TODO

## Second-launch behavior: new independent instance per launch

### Problem (verified in sandbox)

- Bare `secure-terminal` relaunch while an instance is open: exit 0, still 1
  process, still 1 tab, NO new window. Running instance just `show()/raise()/
  activateWindow()` on the existing window (`_ipc_open`, `main.py`: opens 0 tabs,
  and with a tab already present opens nothing). This "nothing happens" is the bug.
- Only the BARE relaunch dead-ends; a second `secure-terminal -e CMD` opens a new
  TAB in the existing window. Never a new window.

### Reference terminals (measured: Xvfb + openbox + session bus)

- gnome-terminal: 2nd launch -> NEW WINDOW; shared server (gnome-terminal-server).
- xfce4-terminal: 2nd launch -> NEW WINDOW; shared server.
- qterminal: 2nd launch -> NEW WINDOW; independent new process.
- konsole: independent new process confirmed (procs 1->2); new window by design
  (visible-window mapping not reproduced in bare headless KDE -- Plasma limitation).
- Convention is unanimous: a second launch gives the user a new terminal window.
  secure-terminal is the sole outlier.

### Decision

New INDEPENDENT INSTANCE per launch (konsole/qterminal model). Reuse becomes
opt-in. Chosen because: mechanism already exists and is proven; independent
processes give real session isolation; does NOT touch the settled ONE-MainWindow-
per-process invariant (teardown/signal-quit segfault fix depends on it); admin
locks re-read per process, so hardening unchanged.

### Behavioral contract (gnome-terminal --window/--tab mental model)

- `secure-terminal` (bare)          -> NEW independent instance (own window+process).
- `secure-terminal -e CMD` / `-- CMD` -> NEW independent instance running CMD.
- `secure-terminal --reuse [...]`    -> hand off to the group's running instance,
                                        open a new tab there (spawn one if none).
- `secure-terminal --instance-group NAME ...` -> selects group socket identity;
                                        still new-window unless `--reuse`.
- `secure-terminal --new-instance`   -> unchanged (force fresh, server-less);
                                        now effectively the default, kept for compat.
- `secure-terminal ctl ...`          -> unchanged; targets the group's PRIMARY instance.

Primary-instance rule: the FIRST live instance of a group owns `<group>.sock` and
answers `ctl`/`--reuse`; later bare launches run server-less and independent.

### Flag-name collision (caught via man page)

`--tab` is ALREADY taken -- it is the per-tab option-group separator (multi-tab
launch in one window). So the reuse-intent flag is `--reuse` (NOT `--tab`).
Open: confirm spelling `--reuse` vs `--attach`/`--existing`.

### Code touch points (`~/private-sources/secure-terminal`)

1. `main.py` argparse: add `--reuse` (reuse intent) and `--window` (default,
   documented). Keep `--tab` (existing meaning), `--new-instance`, `--instance-group`.
2. `main.py` `main()` decision block: call `ipc.send_request` (handoff) ONLY when
   `--reuse`; otherwise skip straight to spawning a window.
3. `main.py` `start_instance_server` / `ipc.py` -- load-bearing correctness fix:
   today it unconditionally `QLocalServer.removeServer(path)` (safe only because
   one instance ever exists). Under multi-instance it would STEAL a live socket.
   New rule: PING first -- if a live server answers, run server-less; only
   `removeServer` when the socket is stale (no answer). Needs its own regression test.

### Man page + help (REQUIRED -- currently under-documented and will be WRONG)

- `man/secure-terminal.1.ronn` has NO instance-model section; behavior only implied
  by three lines that become FALSE after the change:
  - DESCRIPTION: "Without `--`, `-e` or a reused instance, a shell ... is started."
  - `--new-instance`: "Force a fresh process instead of reusing a running instance."
  - `--instance-group`: "Which running instance to reuse (default: 'default')."
- Rewrite those three lines to the new default.
- Add an INSTANCES section (new-window default; `--reuse`/`--instance-group` to add
  a tab to the primary; `ctl` targets the primary).
- Add the `--reuse` option entry; adjust `--new-instance` wording.
- Regenerate `auto-generated-man-pages/secure-terminal.1` from the `.ronn` (both are
  committed and must stay in sync); confirm the generator (ronn; genmkfile path).
- Keep `main.py` `--help` strings in step, same batch.
- Check `secure-terminal-cli.1.ronn`; update only if it references instance behavior.

### Public pages

- Update `index.html` / comparison copy if it claims single-instance behavior
  (honest-claims standing rule).

### Tests (out-of-tree, dist-ai) -- each canary-checked against current code

- BUG regression: second bare launch -> 2 independent processes (fails today: stays 1).
- `--reuse` second launch -> stays 1 process, tabs 1->2 in the primary.
- Socket not stolen: A owns `default.sock`; bare B spawns server-less; A still
  answers `ping`/`ctl ls`.
- `--instance-group other` -> owns `other.sock`; `ctl other` works; default untouched.
- `ctl ls` unchanged against the primary.
- Existing sandbox rig (Xvfb/offscreen + `ctl ls` + `safe-pgrep` counting) reused.

### Delivery

- Multi-file across `secure-terminal` (code + man + pages) and `dist-ai` (tests).
- Push to BOTH `origin` and `org-ai-assisted` (must not drift; `git` skill).
