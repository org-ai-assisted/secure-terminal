# Future design: one external review window for all reviews (DEFERRED, not built)

Status: DESIGN ONLY. Not implemented. Captures the approved design + UX decisions so a
future change can execute it directly. The code is still the current two-frame model
described under "Current state" below.

## Why

Reviews of text crossing the trust boundary appear in TWO different frames today:

- a DOCKED `ReviewBar` in the main window (`self._review_bar` in the `_vsplit` splitter,
  `main.py`), for paste-IN and copy-OUT;
- a separate top-level `_ReviewPopup` hosting its own `ReviewBar` (`clipboard_watch.py`),
  for the clipboard sanitizer.

Two problems users hit:

1. The docked paste bar stays visible across a tab switch, so a paste confirmed from a
   different tab "teleports" back to the origin tab -- the docked bar is bound to the tab
   strip, not to a labelled destination (`_show_review` guards the target only at open).
2. The sanitizer review looks different (a separate window), so windowed and cs-only
   reviews are inconsistent.

## Goal

ONE persistent top-level review window for ALL reviews (paste, copy, clipboard), reusing
the single `ReviewBar` widget (generalizing `_ReviewPopup`). Retire the docked
`self._review_bar` and the `_vsplit` splitter. `ReviewBar._window` is stored but unused,
so the bar hosts cleanly in a top-level frame.

## Destination-based scoping (not tab-strip scoping)

- **paste-IN** targets a specific tab. The window BINDS to the origin `SecureTerminal` at
  open and LABELS it ("Paste into: <tab name>"); dispatch -> that term's
  `dispatch_pending_paste`, even after the user switches tabs. A separate labelled window
  decoupled from the tab strip removes the "current tab" illusion -> fixes the teleport
  (the origin binding, not the now-current tab, receives the paste).
- **copy-OUT** and the **general clipboard sanitizer** are destined for the SYSTEM
  CLIPBOARD. Copy dispatches via the tab's `dispatch_pending_copy`; the sanitizer via
  `_ClipboardReview` (`clipboard_watch.py`, TOCTOU-guarded write). Not tab-bound; no
  "Paste into" label.
- **cs-only / hidden-to-tray**: the review is its own top-level window, so it shows with no
  terminal window forced open. (This is why the single-window model handles cs-only for
  free.)

## Confirmed UX decisions (operator)

These were decided explicitly; do not re-litigate without asking.

1. **Focus-steal, but NEVER auto-rewrite the clipboard.** The review window RAISES +
   ACTIVATES for ALL reviews, including the clipboard sanitizer, so the user is made aware
   BEFORE they might paste the risky text into another app (ST cannot intercept Ctrl+V in
   another app, so focus is the awareness lever). The sanitizer keeps the documented
   flag-and-offer principle: it does NOT touch the clipboard until the user chooses (Leave
   it / Replace). Auto-rewrite ("safe-by-default write-back") was REJECTED to preserve
   "never auto-swap".

2. **Contention: ONE review at a time, pause-while-open, NO queue.** While any review is
   open, the continuous clipboard watcher is PAUSED (reuse its existing `set_enabled(False)`
   / `_enabled` guard) so a clipboard change -- including a copy made from WITHIN the review
   edit box -- cannot raise a nested/second review. On close, re-enable and RE-CHECK the
   current clipboard once (its `_dismissed` guard means a Leave-it choice will not re-nag).
   Paste/copy text is HELD by the terminal (existing mechanism) and shown when the window is
   free -- never lost, never queued in a confusing FIFO.

3. **Self-copy out of the review box -> passive notification.** A PASTE into the box is
   always allowed (it reads, never writes, the clipboard, and `RevealedEditor` re-sanitizes
   it). A COPY out of the box is allowed as an editing convenience and raises no nested
   review, BUT it is not silent: the review window shows a PASSIVE, non-focus-stealing
   inline notice (a status line, not a modal/new review) that a snippet went to the system
   clipboard un-reviewed -- so the user stays aware the copied substring may still carry the
   hidden characters shown in the box. Add a `RevealedEditor.copied` signal (sibling of the
   existing `pasted`) for the window to surface it; the watcher stays paused, so no
   recursion.

## Implementation sketch

- New `ReviewWindow(QWidget)` in `review.py` (co-located with `ReviewBar`): a top-level
  frame holding a destination `QLabel` + a `ReviewBar`; fixed window title (never program
  text). `show_review(term, raw, delay, kind, dest_label=None)` sets/hides the label and
  delegates to the bar. Raises + activates on show; a passive-notice slot for the
  self-copy signal.
- `MainWindow` owns ONE `self._review_window`. Remove `self._review_bar` / `self._vsplit`;
  central layout becomes `col.addWidget(self.tabs)` + the find bar. Retarget
  `_show_review` / `_hide_paste_review` / the `close_tab` guard / the `rerender_mirror`
  call sites from `self._review_bar` to `self._review_window` (its `.bar`). Bind paste to
  the origin term at open (drop the "current tab" retarget); pass the origin tab's
  sanitized name as `dest_label`.
- `ClipboardWatcher` (`clipboard_watch.py`): stop creating its own `_ReviewPopup`; accept an
  injected review host from `MainWindow` and route deceptive-clipboard reviews through the
  SHARED `self._review_window`. After the daemon retirement the watcher is only ever
  embedded in-process, so the injection is always available. `_clip_review_now` +
  `_clip_bg_watcher` both use the shared window -> the pause-while-open rule serializes
  paste/copy/clipboard through one surface.
- Pause-while-open: MainWindow disables the continuous watcher (`set_enabled(False)`) while
  the review window is open and re-enables + re-checks on close.

## Tests (dist-ai) to add with the implementation

- Teleport canary: a paste-IN review confirmed AFTER switching tabs dispatches to the
  ORIGIN tab and the window names it (fails on the old docked code, which lacked the
  guarding label / origin binding).
- copy-OUT and clipboard reviews dispatch to the SYSTEM CLIPBOARD (not a tab).
- Pause-while-open: while a review is open the watcher is disabled and a clipboard change
  raises NO second/nested review; on close the current clipboard is re-checked once (a
  `_dismissed` Leave-it choice is not re-nagged).
- Self-copy passive-notice: a copy from the review box shows the passive notice (via the new
  `RevealedEditor.copied` signal) and opens no nested review.
- cs-only: a review with no visible terminal window still shows the review window.

## Current state (what exists today, unchanged by this deferred design)

- `review.py::ReviewBar` -- the shared review widget, used by BOTH frames below.
- `main.py` -- the docked `self._review_bar` in `self._vsplit`; paste/copy signals routed
  via `_show_review` / `_hide_paste_review`.
- `clipboard_watch.py::_ReviewPopup` -- the standalone top-level frame the in-process
  `ClipboardWatcher` shows for the sanitizer.
