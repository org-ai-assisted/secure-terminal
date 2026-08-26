# Design notes: unicode display, paste/copy review, and boundary safety

Terse record of the ideas, problems, and decisions behind secure-terminal's
display modes and its paste/copy review. Rationale lives here; the code is the
source of truth for behaviour.

## Display modes

- Modes: `box`, `show`, `reveal`, `detail` (default). The `box` key was `strip`
  (renamed pre-release, no back-compat).
- **Box**: every non-ASCII byte becomes a box glyph, coloured by risk class. A
  saved transcript / copy maps the box back to ASCII `_`.
- **Show**: a printable non-ASCII glyph is rendered as itself but TINTED by risk
  class, so a homoglyph is shown yet flagged. A no-glyph character (zero-width,
  bidi, control) cannot be "shown", so Show falls back to the SAME tinted box as
  Box mode - Show and Box are consistent for characters with nothing to show.
- **Reveal / Detail**: `<U+XXXX>` / `<U+XXXX NAME>` badges (ASCII).
- Escapes are stripped in every mode; there is no escape parser in line mode.

## Risk classes and colouring

- Classes: bidi (red), confusable (rose), invisible (amber), control (blue),
  nonascii (purple). Colours are fixed (not theme-derived) and chosen to read on
  both the dark and light theme backgrounds (tested).
- **Confusable** = a non-ASCII code point that is a look-alike of printable ASCII
  (homoglyph), detected via the Unicode confusables dataset
  (python3-confusable-homoglyphs). It is louder than honest foreign text
  (`nonascii`), which is not a look-alike.
- Font: fonts-hack is a hard Depends (no fallback chain) - Hack disambiguates
  look-alikes and has no ligatures.

## Contrast guard

- Invariant: the drawn foreground is NEVER near-invisible against its effective
  background (`too_close`, luminance gap < 30), so a program cannot hide text by
  painting fg == bg, not even by moving the default colours together via OSC
  10/11. The fallback foreground is a fixed readable colour, never a program-set
  one.
- Tested exhaustively: every ANSI palette fg x bg x bold, and every pyte colour x
  bold x reverse, across BOTH themes, plus a hypothesis sweep of truecolour.

## TUI-needed / clear advisories (line mode is append-only)

- **Problem**: the "needs TUI mode" hint only fired on the alternate screen, so an
  in-place vertical repaint that does NOT use it - notably zsh/readline
  completion menus (default child TERM is xterm-256color, so the shell emits the
  escapes) - was stripped into garbage with no hint.
  **Fix**: also advise on CUU (cursor-up) or absolute row;col addressing
  (`wants_screen_repaint`). Kept precise: a `\r` progress bar, `clear`, horizontal
  moves and erase-line do not trip it.
- A whole-screen `clear` / `Ctrl+L` / `reset` (ED2/ED3/RIS) is a no-op BY DESIGN
  (append-only SCROLLBACK is tamper-evident; nothing may erase a line already
  scrolled past). Scope, per the previous point: the line currently being written
  is not covered -- horizontal moves and erase-in-line redraw it, exactly as `\r`
  does, so its earlier content is lost. A once-per-tab notice explains the
  whole-screen no-op rather than letting it read as broken. The `line_edits`
  setting (default true) turns the four ops off for anyone who wants the stricter
  guarantee; it is admin-lockable like the other display keys. What the ops are
  for and what turning them off costs: the `line_edits` entry in
  `usr/lib/secure-terminal.d/30_defaults.conf` (the single authoritative copy).

## Mouse reporting (konsole/xterm parity)

- **Problem**: on the alternate screen a full-screen program owns the display, but
  secure-terminal reported no mouse events, so a mouse-aware UI (Claude Code, `vim`
  with mouse, `htop`, `tmux`) could not be scrolled by the wheel or driven by
  clicks -- the wheel scrolled outside the TUI, and its buttons (a "jump to bottom"
  affordance, a menu) were dead.
- **Decision**: implement standard SGR mouse reporting, matching konsole, at the
  explicit request of the maintainer. This is a deliberate reversal of the earlier
  "no mouse reporting" hardening (see the trade below).
- **Behaviour (`wheelEvent` / `mousePressEvent` / `mouseReleaseEvent` /
  `mouseMoveEvent` / `focusInEvent` / `focusOutEvent`)**: when the child has enabled
  mouse tracking (1000/1002/1003) with SGR encoding (1006) -- tracked off the output
  stream by `scan_mouse_modes` -- its events are reported as `ESC[<b;col;rowM/m` at
  the cell UNDER THE POINTER (`_event_cell`), so it scrolls line-by-line and its UI
  is clickable exactly as in konsole:
  - wheel: 64 up / 65 down, 66 left / 67 right (one event per notch);
  - buttons: left/middle/right press (`M`) + release (`m`), codes 0/1/2;
  - motion: drag (button held, +32) under 1002; any-motion (code 35) under 1003,
    coalesced to one report per CELL so it does not flood (widget mouse tracking is
    enabled only while 1003 is set);
  - keyboard modifiers encoded into the button byte (Ctrl +16, Alt +8);
  - focus in/out (`ESC[I` / `ESC[O`) under 1004.
  - A plain alt-screen pager that did NOT request the mouse still gets arrow-key
    line scrolls on the wheel (xterm's alternateScroll).
- **Shift is the LOCAL override** throughout (konsole convention): Shift+wheel
  scrolls local scrollback, Shift+click/drag selects text, Shift+middle pastes
  PRIMARY -- none of those are forwarded, so text selection and paste stay reachable
  while a program grabs the mouse. (Reaching primary scrollback BEHIND an alt-screen
  app via Shift+wheel is a known follow-up; the alt grid is pinned there today.)
- **Security trade (recorded)**: this drops the mouse-tracking-reflection hardening
  -- secure-terminal now reflects mouse reports like every mainstream terminal, so a
  program whose output you merely display can, by enabling 1003, learn your pointer
  motion while it is shown. The invariant that REMAINS, and that the oracle guards:
  a program's OUTPUT never fabricates input -- enabling the modes writes nothing
  back; only a genuine user event, of a mode the program requested, produces a
  report, and Shift keeps any event local. Oracle: `test_widget.py` mouse-reporting
  block + the konsole-parity block.
## Paste review (text coming IN)

- **In-window bar**, not a modal (one window). The preview panes are read-only
  SecureTerminal instances (preview=True: no child, read-only), so they reuse the
  terminal's own renderer - risk-class colouring and click-to-inspect for free.
- **Async hold-and-gate**: a risky paste is HELD (`_pending_paste`,
  `paste_review_requested`); terminal input is suspended (keyPressEvent swallows
  keys, Enter/Esc reject); the choice (stripped / with-unicode / reject) is
  dispatched to the tab, the only path that lets a byte reach the shell.
- Both send buttons are countdown-gated. Detail pane names each hidden character.
- Config `paste_warn`: always / unicode (default) / never. `never` does NOT strip
  the text (so real unicode can be pasted deliberately); risky text crosses
  UNREVIEWED but a red risk lamp marks the crossing -- not silent. A multi-line
  paste is still held for review whatever the setting (the pastejacking gate),
  unless a TUI's bracketed paste (DEC 2004) is active.

## Copy review (text going OUT)

- **Same bar** (ReviewBar with a paste|copy kind), configured SEPARATELY
  (`copy_warn`) - copy and paste are opposite trust directions. No countdown (a
  copy is not executed).
- The display is already sanitised, so a copy review only arises in Show mode,
  where real glyphs are kept: e.g. after `cat evil-log`, selecting and copying a
  homoglyph would otherwise land on the system clipboard.
- All copy paths are covered: Ctrl+Shift+C, AND the standard right-click Copy/Cut
  (which fire Qt's NON-virtual C++ copy() and would bypass the override - rerouted
  through the reviewed copy()). Paste via the menu is already safe
  (insertFromMimeData is virtual).

## Clipboard sanitisers (shared)

- `sanitize_clipboard` (ASCII) / `sanitize_clipboard_unicode` (keep printable):
  like the paste sanitisers but newlines are preserved (clipboard is multi-line
  content). The OSC 52 clipboard-WRITE path reuses the unicode one.
- **Invisible-but-printable gap**: `str.isprintable()` keeps Unicode
  default-ignorable characters (variation selectors, combining grapheme joiner,
  Hangul/Mongolian fillers). Both unicode-keep sanitisers drop them
  (`is_default_ignorable`), while ordinary combining marks (real accents) are
  kept.

## Discussed and REJECTED (kept here so it is not re-litigated)

- **Tint stdout vs stderr**: not feasible. Both share one pty
  (`pty.fork()`), so by the master fd they are one interleaved stream. Separating
  stderr onto a pipe breaks tty semantics (programs disable colour, change
  buffering) and loses interleave ordering - itself deceptive. Do not.
- **Chatbox / composer split** (separate input box below the output, like
  local-llm-chat): wrong shape for a shell prompt. zsh/bash/fish own their line
  editor and redraw the prompt line THROUGH the output stream, so there is no seam
  to peel the input into a separate widget. A real composer forces the app to own
  the line editor -> you lose zsh completion / syntax highlighting / plugins. Keep
  the prompt inline; the paste/copy bar never needed the split. (An app-owned
  "safe REPL" front-end is a different product.)
- **No-echo detection is doable** (for a hypothetical composer): the master fd
  sees the slave's termios; `termios.tcgetattr(fd)` exposes ECHO (mask a password)
  and ICANON (line vs raw). But a password pasted into a no-echo prompt must not
  be shown in the review preview.
- zsh interactive completion (menu-select) is inherently a TUI-class feature
  (cursor-addressed in-place repaint); the shipped `secure-terminal` terminfo
  cancels those caps so line mode degrades to a plain appended list.
- **Colour quantization of the truecolour grid render**: rejected outright - not
  the default AND not an opt-in mode. Snapping 24-bit cell colours onto a small
  fixed set would let same-colour cells coalesce (fewer render runs), but it BANDS
  the gradient - and the truecolour board exists precisely to show that
  secure-terminal renders the EXACT 24-bit colour a program asked for, where a
  256-colour terminal snaps it to the nearest palette entry. Quantizing our own
  render does the very thing the comparison page holds up as the other terminals'
  failure. An opt-in reduced-colour toggle is NOT a compromise worth keeping: it is
  config surface (a knob this app avoids) for a mode whose only effect is to make
  the display less truthful - there is no user who benefits from a terminal that
  lies about colour on request. The speed case is gone anyway: the grid render is a
  plain-text insert per row with the per-cell formats painted by a
  QSyntaxHighlighter from each block's `_GridRow` (`terminal.py`), which already
  took the pathological full-viewport distinct-colour board from ~15s to ~0.55s
  shot-mode; real program output has runs of near-equal colour that coalesce, so it
  was never the slow case.

## Screenshots (generators already exist - do not hand-roll)

All the Pages site's screenshots are generated from committed code in dist-ai
(`usr/share/secure-terminal-shots/`), driven by one wrapper -
`secure-terminal-shots [review|comparison]`. Regenerate via it, do not paint.

- **Review-bar shots** (`shots/paste-warning.png`, `shots/copy-warning.png`):
  headless Qt grab of the real ReviewBar (`secure-terminal-shots review`).
- **Terminal-comparison shots** (`comparison/shots/*.png`): real Debian terminals
  under nested labwc (`secure-terminal-shots comparison`; needs an X server, so
  run it in the sandbox).

See dist-ai `usr/share/secure-terminal-shots/README.md` and the site's
`shots/README.md`.
