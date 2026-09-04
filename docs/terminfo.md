# terminfo / tic files

How secure-terminal's restricted CLI-mode `TERM` types are defined, compiled, and
found at runtime. The code is the source of truth for behaviour.

## Source of truth

- `usr/share/secure-terminal/terminfo/secure-terminal.ti` -- the terminfo SOURCE,
  the only terminfo file committed to the repo.
- Defines two TERM types for CLI mode's escape-stripping renderer:
  - `secure-terminal` -- line-editing CLI.
  - `secure-terminal-noedit` -- append-only CLI.
- Compiled entries are `tic` build artifacts and are NEVER committed: the compiled
  format is ncurses/version specific, so it is produced by the target's `tic`, not
  checked in.

## Build-time compilation (installed users)

- `debian/rules` runs `tic -x` twice and installs the result into two places:
  - `/usr/share/terminfo/s/secure-terminal{,-noedit}` -- the SYSTEM db, so bare
    `TERM=secure-terminal` resolves everywhere (nested shell, ssh, tmux, mode-switch
    re-export) with no `TERMINFO_DIRS`.
  - `/usr/share/secure-terminal/terminfo/s/secure-terminal{,-noedit}` -- an
    app-local copy the app points `TERMINFO_DIRS` at.
- An installed system therefore has both compiled entries; the runtime path below
  never runs `tic`.

## Runtime fallback cache (source checkouts / drift)

- `~/.cache/secure-terminal/terminfo/` (honours `XDG_CACHE_HOME`).
- `cli_terminfo_dir()` in `usr/lib/python3/dist-packages/secure_terminal/terminal.py`
  resolves the terminfo dir handed to the child shell. It compiles the `.ti` into
  this cache with one `tic` ONLY when the installed compiled entries are:
  - absent -- running straight from a source checkout (git tracks only the `.ti`),
    or
  - stale -- either compiled entry's mtime is older than the `.ti` (the drift guard:
    a `.ti` change must not keep advertising the old capabilities).
- Both entries must be present or the cache is recompiled.
- Regenerable and safe to delete; the next launch re-creates it with one `tic`.
