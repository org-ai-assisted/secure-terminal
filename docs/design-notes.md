# Design notes: unicode display, paste/copy review, and boundary safety

Terse record of the ideas, problems, and decisions behind secure-terminal's
display modes and its paste/copy review. Rationale lives here; the code is the
source of truth for behaviour.

## Display modes

- Modes: `box` (default), `show`, `reveal`, `detail`. Internal key is `box`
  (was `strip`; renamed pre-release, no back-compat).
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
  (append-only scrollback is tamper-evident; nothing may erase what was shown). A
  once-per-tab notice explains it rather than letting it read as broken.

## Paste review (text coming IN)

- **In-window bar**, not a modal (one window). The preview panes are read-only
  SecureTerminal instances (preview=True: no child, read-only), so they reuse the
  terminal's own renderer - risk-class colouring and click-to-inspect for free.
- **Async hold-and-gate**: a risky paste is HELD (`_pending_paste`,
  `paste_review_requested`); terminal input is suspended (keyPressEvent swallows
  keys, Enter/Esc reject); the choice (stripped / with-unicode / reject) is
  dispatched to the tab, the only path that lets a byte reach the shell.
- Both send buttons are countdown-gated. Detail pane names each hidden character.
- Config `paste_warn`: always / unicode (default) / never. Never still sanitises
  to ASCII silently.

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

## Screenshots (generators already exist - do not hand-roll)

The Pages site's screenshots come from two committed generators; regenerate via
them rather than painting shots.

- **Review-bar shots** (`shots/paste-warning.png`, `shots/copy-warning.png`):
  headless Qt grab of the real ReviewBar. Regenerate with dist-ai's
  `secure-terminal-shots` (drives `paste-warning-shot.py <out.png> [paste|copy]`).
- **Terminal-comparison shots** (`comparison/shots/*.png`): real Debian terminals
  under nested labwc, from terminal-poc-corpus `comparison/capture.sh`
  (`ST_REPO=<checkout>`; needs an X server, so run it in the sandbox).

See also the site's `shots/README.md`.
