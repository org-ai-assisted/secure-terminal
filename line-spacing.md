# Line spacing: the ~1px-per-line difference vs gnome-terminal

A known rendering difference and an open design decision. Not a bug with a clear
fix; it needs a call. Companion to `issues.md`.

## Observation

In the homepage before/after slider (`secure-terminal.github.io`, the hero
compare), the two windows' text lines up at the top and drifts apart going down:
the overlap shrinks the further down the payload you read. The compose step aligns
only the FIRST text line, so any per-line pitch difference accumulates.

## Measurement

Same font (Hack), same point size, same DPI, measured from the real captures:

- secure-terminal (Qt `QPlainTextEdit`): line pitch **26 px** (at 2x device px).
- gnome-terminal (VTE / Cairo): line pitch **27 px**.

A ~1 px per-line difference, accumulating to ~13 px over the ~13-line board.

## Root cause

NOT a spacing choice on either side. Both terminals use their engine's natural,
default line height for the font -- no added leading (VTE `cell-height-scale`
1.0; secure-terminal sets no `setLineHeight`). The 26-vs-27 px difference is how
the two toolkits round the SAME font's line box: Qt's document line height vs
VTE's cell height. So secure-terminal already uses "the same default" line-spacing
POLICY as gnome; the 1 px is metric rounding, not a knob either terminal turned.

## Why it is not a one-liner

`SecureTerminal` is a `QPlainTextEdit` (chosen for performance -- the per-char
render loop is the bottleneck). `QPlainTextEdit`'s optimized layout ignores
line-height:

- `QTextBlockFormat.setLineHeight(...)` -- measured no-op (pitch stayed 26 px).
- stylesheet `line-height` -- measured no-op.
- `QPlainTextDocumentLayout` -- not exposed in this PyQt6 build to subclass.

A real, configurable line-spacing setting would require migrating the hot render
path to `QTextEdit` (which honours line height) or a custom document layout --
a large, performance-sensitive change that also risks the 100% coverage gate,
disproportionate to a 1 px cosmetic drift.

## Honesty consideration

Forcing secure-terminal to 27 px means adding artificial leading it does not
naturally render, PURELY to match a screenshot of a different engine. That makes
the app render differently just to win a comparison -- contrary to the "what you
see is what is there" and honest-comparison principles. The 1 px difference is a
real, honest reflection of how the two engines render the same font.

## Options

- **(a) Accept the honest 1 px difference (recommended).** Both engines render
  the same font at its natural line height; the drift is real and minor.
- **(b) Shrink gnome-terminal's cell to 26 px** (VTE `cell-height-scale`) so the
  shots align. Makes the TRADITIONAL side non-default -- less honest for a shot
  meant to show a normal traditional terminal.
- **(c) Make line spacing a real, configurable setting.** The larger investment:
  migrate the render widget (`QTextEdit` or a custom `QAbstractTextDocumentLayout`)
  and wire a `line_spacing` setting per the "Adding a setting" checklist. Default
  it to whatever makes the shots align, and expose it like zoom/theme.

## Resume

Start in `usr/lib/python3/dist-packages/secure_terminal/terminal.py`, class
`SecureTerminal(QPlainTextEdit)`. Evaluate a `QTextEdit` migration vs a custom
document layout, confirm the per-char render loop does not regress, then wire the
setting through every surface (see the "Adding a setting" checklist in the
`secure-terminal` skill / `AGENTS.md`).
