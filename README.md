# secure-terminal

A terminal where paste is safe by construction.

Paste a command copied from the web, or read text a program printed, without
worrying about invisible characters, bidi overrides or escape sequences.
secure-terminal accepts and displays plain printable ASCII by default and nothing
else, so a pasted or printed lie has nothing to hide in.

This is the problem [output lies](https://output-lies.github.io) documents,
removed at the source.

## How it stays safe

- **ASCII-only display.** Program output is passed through a sanitizer: ANSI/OSC
  escape sequences are removed and every byte that is not printable ASCII (plus
  tab and newline) is dropped, the way `stcat` does for logs. A hostile filename,
  a forged status line or a Trojan-Source comment cannot redraw or reorder what
  you read.
- **No escape-sequence interpretation.** There is no ANSI parser to attack. The
  terminal advertises `TERM=dumb` and honors no cursor moves, colors, alternate
  screens or OSC hyperlinks from the child process.
- **Sanitized paste, with a warning.** Pasted text is stripped to printable
  ASCII before it reaches the shell, so invisible or bidi characters never enter
  your command line. When a paste actually contains unicode or control
  characters, a dialog first shows it two ways side by side, the original and a
  Reveal rendering that makes every hidden character visible, and holds the
  Allow button disabled for a few seconds (configurable) so a stray Enter cannot
  wave a hostile paste through. A plain-ASCII paste is not interrupted.
- **Tiny input allowlist.** You type printable ASCII plus a small set of control
  keys that the pseudo-terminal turns into signals:

  | Key | Signal |
  |---|---|
  | `Ctrl+C` | `SIGINT` |
  | `Ctrl+Z` | `SIGTSTP` |
  | `Ctrl+\` | `SIGQUIT` |
  | `Ctrl+D` | EOF |

  We only write the control byte; the kernel line discipline does the rest.
  Backspace is honored so you can rub out a typo; it erases one character and
  never crosses a line, so it cannot rewrite earlier output.

## Everyday comforts

The safety model above does not cost you the usual conveniences:

- **Tabs.** Each tab is its own shell over its own pseudo-terminal. Open with
  `Ctrl+Shift+T`, close with `Ctrl+Shift+W`; closing a shell closes its tab.
- **Copy and paste.** Toolbar buttons and `Ctrl+Shift+C` / `Ctrl+Shift+V`
  (plain `Ctrl+C` stays `SIGINT`). Paste is still sanitized before it reaches
  the shell.
- **Text zoom.** `Ctrl+wheel`, `Ctrl+plus` / `Ctrl+minus`, or the percentage box
  in the top right (Up/Down keys or type a value). `Ctrl+0` resets to 100%.
- **Themes.** White-on-black and black-on-white, under **View -> Theme**. Plain,
  high-contrast, no syntax coloring.
- **Unicode display mode** (top bar, per tab, default **Strip**). Strip replaces
  non-ASCII with `_` (safe). Show renders legitimate unicode as glyphs so you can
  read a log, while still neutralizing the invisible, bidi and homoglyph classes.
  Reveal shows every non-ASCII character as a `<U+XXXX>` badge to inspect exactly
  what is there. Escapes are stripped in every mode.
- **Save transcript** (File menu, `Ctrl+Shift+S`). Writes the current tab's
  scrollback to a file. Because the buffer is already sanitized plain ASCII, the
  saved file is safe to open anywhere, unlike a normal terminal's raw log.
- **Scrollback length** (View menu): 1,000 / 10,000 / 100,000 lines or Unlimited
  (default). Held in memory while running.
- **Session restore** (File menu, on by default). On exit the open tabs -- their
  names, colours, per-tab settings and scrollback -- are saved to
  `~/.local/state/secure-terminal/session.json` and restored next launch, with a
  fresh shell under the restored history. The running programs are not
  resurrected. Turn it off, or clear the saved session, from the File menu; when
  off, nothing is written. An unlimited tab's saved scrollback is capped so the
  file cannot grow without bound.
- **Persistent settings** in systemd-style drop-in directories. Settings are
  KEY=value `.conf` files read, lowest precedence first, from
  `/etc/secure-terminal.d/`, `/usr/local/etc/secure-terminal.d/` and
  `~/.config/secure-terminal.d/` -- so a distro or admin can seed defaults and
  the user overrides them. Only `*.conf` files are read; within a directory they
  apply in lexical order, later winning. The app writes its own settings to
  `~/.config/secure-terminal.d/99-user.conf`. **Settings -> Folders & Files...**
  shows every location with Copy and Open buttons.
- **Tabs you can name and colour.** Double-click a tab to rename it; right-click
  for rename, a colour, or close. Handy when several tabs each run a different
  TUI. A user name and a program-set title are kept separately (your name wins as
  the label; the program title shows in the tooltip).
- **Run a specific program** (File -> New Tab Running..., `Ctrl+Shift+R`). Opens
  a tab straight into `ssh host`, `tmux`, `claude`, etc. instead of the login
  shell. A plain new tab (`Ctrl+Shift+T`) still runs `$SHELL`.
- **Optional title / notifications** (View menu, per tab, default off). When on,
  and only in TUI mode, a program may set the tab title (OSC 0/2) and send
  notifications (OSC 9), both sanitized to plain ASCII first. Clipboard-write
  (OSC 52) and hyperlink (OSC 8) escapes stay blocked either way.
- **Menu bar** for the same actions, discoverable rather than memorized.

## TUI mode (opt-in, run full-screen programs)

The strict line mode above cannot run curses apps, because they are driven
entirely by the escape sequences it refuses to parse. **TUI mode** (top bar and
**View -> TUI mode**, per tab, default off, needs `python3-pyte`) relaxes that so
you can run `ssh`, an editor, or the Claude Code CLI. A yellow indicator and a
hover tooltip flag it while it is active, because it is a deliberate,
lower-guarantee mode:

- Escapes are interpreted, but inside an isolated in-memory screen model (`pyte`)
  that has no OS reach: it **cannot set the window title or touch the system
  clipboard**, so those spoofing/exfil vectors stay closed.
- Every character placed on the screen is **still ASCII/unicode-filtered**, so a
  program can position and colour text but cannot smuggle an invisible, bidi or
  homoglyph character into what you read.
- Colours use the same contrast guard, so nothing can be painted invisibly.

What you give up: a program can draw a *misleading interface* within its own
screen (a fake prompt, say), so only run programs you trust. This is
"restricted-emulator safe," not "safe by construction." The default line mode,
and everything the project's guarantees rest on, is unchanged.

## What it does not do (on purpose)

- **No non-ASCII by default.** Additional character sets may become opt-in much
  later, always as an explicit allowlist, never a general decoder.
- **No terminal side-effects.** No window-title control, no clipboard escape
  (OSC 52), no hyperlink escapes, in either mode.

This is a deliberately minimal, line-oriented first version. Backspace works, but
because the display neutralizes the escapes readline uses to redraw, richer
in-line editing (mid-line cursor movement, history recall) is intentionally
basic; compose or paste a line, read the exact bytes, then run it.

## Run

```
secure-terminal
```

## Build

Standard Debian source package (`debhelper`); depends on `python3-pyqt6`.

```
dpkg-buildpackage -us -uc -b
```

Built with Python and Qt6. AI-assisted; see
[org-ai-assisted](https://github.com/org-ai-assisted).
