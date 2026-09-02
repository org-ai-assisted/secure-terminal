#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""An editable, REVEALED, multi-line text box for the review bar.

The review box is the exact preview of what will cross the terminal boundary AND
the field the user edits it in -- one surface, not a hidden edit box plus a
separate read-only mirror. Every character renders through the SAME cell pipeline
the terminal uses (feed_line_edits builds the logical cells, cells_to_runs renders
them detail-tinted, a collapse-aware walk places the caret), so a homoglyph is tinted,
a bidi override is named, an invisible is boxed -- the deception cannot hide in the
box the way it hid in a plain edit widget.

MODEL -- deliberately just (source string, caret index):
  The box holds its content as a plain source string with '\n' line breaks; the
  caret is an INDEX into that string. The rendered cells (one per source
  character, a badge many columns wide) are re-derived from the string on every
  change, never stored. This makes ATOMIC-TOKEN editing fall out for free: deleting
  source[pos-1] removes exactly one source character and its whole <U+XXXX> badge,
  and an arrow steps one source character (jumping the badge), because the index
  counts source characters, not rendered columns. feed_line_edits is 1:1 on the box
  content (each source char -> one cell; '\n' -> a line break; no '\r'/escape/BEL,
  which the display sanitizer already dropped), so the caret math -- render the
  prefix, take its width -- can never drift from the render.

The box is display-form: newlines stay '\n' (so the box renders multi-line) and
invisibles are dropped for display; the '\n'->'\r' shell-submit mapping and the
defensive re-drop happen only on DELIVER, in review.py.
"""

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QTextCharFormat, QTextCursor, QFont, QGuiApplication
from PyQt6.QtWidgets import QPlainTextEdit

from secure_terminal.sanitize import (
    feed_line_edits, cells_to_runs, sanitize_clipboard_unicode, reveal_display,
    MARK_KEY, THEMES, DISPLAY_MODES, BASE_POINT_SIZE,
    display_len, _cell_display, _collapse_zalgo_runs,
    _is_mark, _COMBINING_RUN_MAX,
)
from secure_terminal.terminal import SecureTerminal, DEFAULT_FONT_FAMILY

# The SGR state a plain (no-program-colour) review cell carries -- what
# feed_line_edits stores when handed the default state dict. Reviewed text has no
# ANSI colour, so colours are OFF in the box and this key renders as the default
# format; only risk MARKINGS tint a cell.
_DEF_SGR = {'fg': None, 'bg': None, 'bold': False}


class RevealedEditor(QPlainTextEdit):
    """One editable, revealed, multi-line review box. Emits `changed` after every
    edit so the review bar can recompute the hidden-character table live."""

    changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ''
        self._pos = 0
        self._mode = 'detail'
        self._markings = True
        self._theme = 'light'
        self._font_family = DEFAULT_FONT_FAMILY
        self._zoom = 100
        self.setUndoRedoEnabled(False)
        # self._text is the ONLY authority for what the box holds (source() + deliver
        # read it); the base QPlainTextEdit document is a pure RENDER of it, rebuilt only
        # by _render(). Every base-editor mutation path that could edit the document
        # OUTSIDE our handlers -- and thereby desync _text from what is shown (Deliver
        # would then cross stale text) -- is shut off here: the context menu (its Cut /
        # Paste / Delete actions), and drag-and-drop (a drop-in, or a drag-MOVE that
        # deletes the dragged text from the doc). The remaining paths are all routed
        # through _text: keyPressEvent (mutating chords handled, others swallowed),
        # insertFromMimeData (paste, re-sanitized), and mousePressEvent (which collapses
        # any selection BEFORE the base sees the press, so no drag-move can start).
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu)
        self.setAcceptDrops(False)
        # NoWrap: a revealed line of wide badges must keep its glyph columns stable,
        # and the box is short; the scrollbar-as-needed exposes an over-wide line
        # for manual inspection without an auto-follow hiding the row start.
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setFrameStyle(0)
        self._apply_font()
        self.apply_theme(self._theme)

    # -- appearance -----------------------------------------------------------
    def _apply_font(self):
        """The terminal font at the tab's family + zoom, so the box's glyph metrics
        match the console detail view exactly (DEFAULT_FONT_FAMILY is a hard package
        dependency; the Monospace hint still steers Qt for a user-picked family)."""
        font = QFont()
        font.setFamily(self._font_family or DEFAULT_FONT_FAMILY)
        font.setStyleHint(QFont.StyleHint.Monospace)
        font.setFixedPitch(True)
        font.setPointSize(max(1, round(BASE_POINT_SIZE * self._zoom / 100.0)))
        self.setFont(font)

    def set_font_family(self, family):
        """Follow the reviewed tab's font family."""
        self._font_family = (family or '').strip() or DEFAULT_FONT_FAMILY
        self._apply_font()

    def apply_zoom(self, percent):
        """Follow the reviewed tab's zoom (scales the base point size)."""
        try:
            self._zoom = max(10, min(1000, int(percent)))
        except (ValueError, TypeError):
            return
        self._apply_font()

    def apply_theme(self, theme):
        """Follow the reviewed tab's theme, so a homoglyph's risk tint reads on the
        same background the terminal draws. Unknown -> the app default 'light'."""
        self._theme = theme if theme in THEMES else 'light'
        base, text = THEMES[self._theme]
        self.setStyleSheet('QPlainTextEdit{background:%s;color:%s;}' % (base, text))
        self._render()

    def set_mode(self, mode):
        """Follow the reviewed tab's display mode (box/show/reveal/detail), so the
        box reveals risk exactly as the console does. Unknown -> 'detail'."""
        self._mode = mode if mode in DISPLAY_MODES else 'detail'
        self._render()

    # -- content --------------------------------------------------------------
    def set_source(self, text):
        """Load `text` as the box content, caret at the end. `text` is expected to be
        already display-sanitized (newline-preserving keep-printable); it is passed
        through the same sanitizer here as a belt-and-braces guard so the box can
        never hold an invisible/control the model would not render 1:1."""
        self._text = self._display_clean(text)
        self._pos = len(self._text)
        self._render()
        self.changed.emit()

    def set_source_revealed(self, text):
        """Load `text` FULLY REVEALED (reveal_display): keep every deception character
        -- invisibles, bidi, control, look-alikes -- so it renders as a named badge in
        place and the user SEES the whole trap, instead of pre-cleaning it. Caret at the
        end. This is the review box's default on open; a later typed/pasted edit goes
        through the cleaning set_source/insert path, so the user cannot ADD a hidden
        character even though the ORIGINAL's hidden characters are shown as evidence."""
        self._text = self._cap_combining(reveal_display(text))
        self._pos = len(self._text)
        self._render()
        self.changed.emit()

    def source(self):
        """The box's current source string -- the exact text (display form, '\n'
        line breaks) that DELIVER will sanitize and send."""
        return self._text

    @staticmethod
    def _cap_combining(text):
        """Cap each run of combining marks at _COMBINING_RUN_MAX, dropping the excess --
        the SAME cap feed_line_edits applies when it builds the render cells. Without
        it a Zalgo flood (a base + hundreds of marks) would live in self._text but be
        DROPPED from the render, desyncing the source<->cell accounting the caret /
        selection mapping depends on (source indices with no rendered cell). A run past
        the cap is a flood, never real orthography (the heaviest legit stack is ~5)."""
        out = []
        run = 0
        for ch in text:
            if ord(ch) >= 0x0300 and _is_mark(ch):
                run += 1
                if run > _COMBINING_RUN_MAX:
                    continue                  # drop the flood tail; keep the cap's worth
            else:
                run = 0
            out.append(ch)
        return ''.join(out)

    @classmethod
    def _display_clean(cls, text):
        """Display keep-printable: drop invisibles/bidi/control/default-ignorable, keep
        printable look-alikes/accents/CJK, keep '\n'/'\t', and cap combining-mark runs
        (see _cap_combining) so the source stays 1:1 with the render cells. Newline-
        preserving (unlike sanitize_paste*, which map '\n'->'\r' for the shell) because
        the box is a display surface; the shell mapping is applied only on deliver."""
        return cls._cap_combining(sanitize_clipboard_unicode(text))

    # -- rendering ------------------------------------------------------------
    def _build(self, text):
        """(completed cell-lines, current cell-line) for `text` -- the SAME cell
        construction the terminal uses, so the box renders identically. line_edits
        off: the box content carries no escape/CSI to honour."""
        completed, current, _col, _sgr, _wraps = feed_line_edits(
            [], 0, dict(_DEF_SGR), text, 0, False)
        return completed, current

    def _format(self, key):
        """QTextCharFormat for a cell's render key. A (MARK_KEY, class, cp) key tints
        a neutralized/revealed marking by its risk class (the same MARKING_COLORS the
        terminal and the review table use); every other key is the default format
        (reviewed text has no program colour)."""
        fmt = QTextCharFormat()
        if isinstance(key, tuple) and len(key) == 3 and key[0] == MARK_KEY:
            color = key[1]
            if isinstance(color, str):
                spec = SecureTerminal.MARKING_COLORS[self._theme][color]
                fmt.setForeground(QColor(spec['fg']))
                if spec['bg'] is not None:
                    fmt.setBackground(QColor(spec['bg']))
        return fmt

    def _render(self):
        """Rebuild the document from the source string and place the caret at the
        display offset of the source-index caret. Colours OFF, markings ON -- the box
        exists to REVEAL risk, exactly like the review mirror it replaces."""
        completed, current = self._build(self._text)
        runs, _prefix = cells_to_runs(completed, current, self._mode,
                                      colors=False, markings=self._markings)
        doc_cursor = QTextCursor(self.document())
        doc_cursor.select(QTextCursor.SelectionType.Document)
        doc_cursor.removeSelectedText()
        for run_text, key in runs:
            doc_cursor.insertText(run_text, self._format(key))
        caret = self._caret_doc_pos()
        tc = self.textCursor()
        tc.setPosition(min(caret, self.document().characterCount() - 1))
        self.setTextCursor(tc)
        self.ensureCursorVisible()

    def _offset(self, index):
        """The document offset of source `index`: the display width up to the START of
        the CELL that source `index` falls in, walking the FULL render's cell structure
        (with the show-mode Zalgo collapse applied).

        Monotonic non-decreasing in `index` -- which the binary search in
        _source_index_for_doc_pos REQUIRES. The old approach rendered text[:index] and
        took its width; in 'show' a prefix cutting a >_ZALGO_MARK_MAX combining run
        showed the partial marks as separate cells (widths 1..N) while the full run
        collapses to ONE box cell (width 1), so _offset dropped back across the cluster
        (non-monotonic) and the search returned mid-cluster indices -- a click/selection
        after the cluster resolved to the wrong source chars. Here a collapsed run is
        ATOMIC: every source index inside it shares the cell-start offset, so the width
        never drops. self._text is capped to _COMBINING_RUN_MAX (_cap_combining), so the
        render cells account for EVERY source char (feed_line_edits never drops one) and
        the len(ch) walk below is exact."""
        completed, current = self._build(self._text)
        lines = completed + [current]
        src = 0
        doc = 0
        for line_index, cellline in enumerate(lines):
            rendered = (_collapse_zalgo_runs(cellline) if self._mode == 'show'
                        else cellline)
            for ch, _key in rendered:
                if index < src + len(ch):
                    return doc            # index is inside this cell -> its start offset
                src += len(ch)            # len(ch) > 1 only for a collapsed Zalgo cell
                doc += display_len(_cell_display(ch, self._mode))
            if line_index != len(lines) - 1:
                # a '\n' separates this line from the next: one source char, one column
                if index == src:
                    return doc            # caret at end-of-line, before the break
                src += 1
                doc += 1
        return doc

    def _caret_doc_pos(self):
        return self._offset(self._pos)

    # -- editing --------------------------------------------------------------
    def _replace(self, new_text, new_pos):
        # Re-cap combining runs over the WHOLE new text: an insert can JOIN two runs
        # (each under the cap) across the splice into an over-cap flood that neither
        # piece was, which would then desync source<->cell accounting. Idempotent on
        # already-capped text (deletes never introduce a run), so this only bites a
        # Zalgo-flood edit; clamp the caret in case the cap dropped chars before it.
        self._text = self._cap_combining(new_text)
        self._pos = max(0, min(new_pos, len(self._text)))
        self._render()
        self.changed.emit()

    def _edit_range(self):
        """The source [start, end) an edit acts on: the base cursor's SELECTION mapped
        to source indices (via the same boundary-snapping as a click), or the caret
        (an empty range at _pos) when nothing is selected. Reading the selection off
        the base cursor -- which it maintains for free from a mouse drag or Ctrl+A --
        lets a type-over / cut / delete REPLACE the selection through _text, so the
        base can never edit the rendered doc behind the model's back."""
        cur = self.textCursor()
        if cur.hasSelection():
            a = self._source_index_for_doc_pos(cur.selectionStart())
            b = self._source_index_for_doc_pos(cur.selectionEnd())
            return min(a, b), max(a, b)
        return self._pos, self._pos

    def _insert(self, chunk):
        """Insert `chunk` (already display-sanitized) at the caret, REPLACING any
        selection first (type-over / paste-over), and advance past it. Newlines in the
        chunk make real line breaks in the box. An empty chunk with a selection still
        deletes the selection (typing a dropped invisible over a selection replaces
        it with nothing, as any editor); an empty chunk with no selection is a no-op."""
        start, end = self._edit_range()
        if start == end and not chunk:
            return
        self._replace(self._text[:start] + chunk + self._text[end:], start + len(chunk))

    def _paste_clipboard(self):
        """Ctrl+V: insert the clipboard through the SAME sanitize + selection-replace
        path as any other paste-into-the-box (insertFromMimeData), so a clipboard
        paste can neither smuggle a hidden character nor edit the doc behind _text."""
        board = QGuiApplication.clipboard()
        self._insert(self._display_clean(board.text() if board is not None else ''))

    def _cut(self):
        """Ctrl+X: DELETE the selection through _text -- a trim, not a clipboard cut.
        Deliberately writes NOTHING to the OS clipboard: the box holds text that has
        not yet been reviewed to cross a trust boundary, so a reflexive Ctrl+X must not
        exfiltrate it (and the base cut would also desync _text). Copy (Ctrl+C, the
        inert rendered form) stays available for a deliberate copy-out."""
        start, end = self._edit_range()
        if end > start:
            self._replace(self._text[:start] + self._text[end:], start)

    def _delete_word(self, forward):
        """Ctrl+Backspace / Ctrl+Delete: delete the selection if any, else the word to
        one side of the caret, through _text (never the base's own word-delete, which
        would edit the doc behind the model)."""
        start, end = self._edit_range()
        if end > start:
            self._replace(self._text[:start] + self._text[end:], start)
            return
        text = self._text
        if forward:
            i = self._pos
            while i < len(text) and text[i].isspace():
                i += 1
            while i < len(text) and not text[i].isspace():
                i += 1
            self._replace(text[:self._pos] + text[i:], self._pos)
        else:
            i = self._pos
            while i > 0 and text[i - 1].isspace():
                i -= 1
            while i > 0 and not text[i - 1].isspace():
                i -= 1
            self._replace(text[:i] + text[self._pos:], i)

    def _line_bounds(self):
        """(start, end) source indices of the line the caret is on (end excludes the
        trailing '\n')."""
        start = self._text.rfind('\n', 0, self._pos) + 1
        end = self._text.find('\n', self._pos)
        if end == -1:
            end = len(self._text)
        return start, end

    def keyPressEvent(self, event):
        key = event.key()
        mods = event.modifiers()
        if key == Qt.Key.Key_Escape:
            # Bubble Esc to the review bar (its keyPressEvent rejects from anywhere);
            # the box must never swallow the safe backout.
            event.ignore()
            return
        ctrl = bool(mods & Qt.KeyboardModifier.ControlModifier)
        if ctrl:
            # WHITELIST, not blacklist: only the base ops that CANNOT mutate the
            # document (select-all, copy the rendered selection) fall through to the
            # base; the mutating chords are routed through _text; and EVERY other Ctrl
            # chord is swallowed, so no base edit action can ever reach the document
            # unhandled (a blacklist of named chords would leave the next one open).
            if key in (Qt.Key.Key_A, Qt.Key.Key_C, Qt.Key.Key_Insert):
                super().keyPressEvent(event)      # select-all / copy: no mutation
            elif key == Qt.Key.Key_V:
                self._paste_clipboard()
            elif key == Qt.Key.Key_X:
                self._cut()
            elif key in (Qt.Key.Key_Backspace, Qt.Key.Key_Delete):
                self._delete_word(forward=(key == Qt.Key.Key_Delete))
            return
        if key in (Qt.Key.Key_Backspace,):
            start, end = self._edit_range()
            if end > start:
                self._replace(self._text[:start] + self._text[end:], start)
            elif start > 0:
                self._replace(self._text[:start - 1] + self._text[start:], start - 1)
            return
        if key in (Qt.Key.Key_Delete,):
            start, end = self._edit_range()
            if end > start:
                self._replace(self._text[:start] + self._text[end:], start)
            elif start < len(self._text):
                self._replace(self._text[:start] + self._text[start + 1:], start)
            return
        if key in (Qt.Key.Key_Left,):
            self._pos = max(0, self._pos - 1)
            self._render()
            return
        if key in (Qt.Key.Key_Right,):
            self._pos = min(len(self._text), self._pos + 1)
            self._render()
            return
        if key in (Qt.Key.Key_Home,):
            self._pos = self._line_bounds()[0]
            self._render()
            return
        if key in (Qt.Key.Key_End,):
            self._pos = self._line_bounds()[1]
            self._render()
            return
        if key in (Qt.Key.Key_Up, Qt.Key.Key_Down):
            self._move_vertical(-1 if key == Qt.Key.Key_Up else 1)
            return
        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self._insert('\n')
            return
        text = event.text()
        if text:
            self._insert(self._display_clean(text))
            return
        super().keyPressEvent(event)

    def _move_vertical(self, direction):
        """Move the caret one line up/down, keeping the source-character column
        offset within the line (clamped to the target line's length)."""
        start, _end = self._line_bounds()
        col = self._pos - start
        if direction < 0:
            if start == 0:
                self._pos = 0
            else:
                prev_start = self._text.rfind('\n', 0, start - 1) + 1
                self._pos = min(prev_start + col, start - 1)
        else:
            nl = self._text.find('\n', self._pos)
            if nl == -1:
                self._pos = len(self._text)
            else:
                next_start = nl + 1
                next_end = self._text.find('\n', next_start)
                if next_end == -1:
                    next_end = len(self._text)
                self._pos = min(next_start + col, next_end)
        self._render()

    def insertFromMimeData(self, source):
        """A paste INTO the box: re-sanitize the pasted text the same way (drop
        invisibles, keep printable, preserve newlines) before inserting, so the box
        can never adopt a hidden character a re-paste tried to smuggle in."""
        self._insert(self._display_clean(source.text() if source is not None else ''))

    def mousePressEvent(self, event):
        """Place the caret at the SOURCE character nearest the click. Qt lands the
        native caret at a document offset that can be mid-badge; snap it to the
        source index whose rendered caret offset is closest, so the caret always
        sits on a cell boundary.

        Collapse any selection BEFORE the base sees the press: the base starts a
        drag-MOVE (which deletes the dragged text from the doc, desyncing _text) only
        when a press lands ON an existing selection, so clearing it first means a press
        can only ever begin a fresh click or a drag-SELECT, never a move."""
        cur = self.textCursor()
        if cur.hasSelection():
            cur.clearSelection()
            self.setTextCursor(cur)
        super().mousePressEvent(event)
        doc_pos = self.textCursor().position()
        self._pos = self._source_index_for_doc_pos(doc_pos)
        self._render()

    def _source_index_for_doc_pos(self, doc_pos):
        """The source index whose caret document offset is nearest `doc_pos`. _offset
        is monotonic in the index, so bisect for the crossing point and pick the
        nearer of the two neighbours -- O(log n) offset builds instead of a full
        scan, and it reuses the one offset function, so a click lands exactly where
        the caret would draw for that index."""
        lo, hi = 0, len(self._text)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._offset(mid) < doc_pos:
                lo = mid + 1
            else:
                hi = mid
        # lo is the first index whose offset >= doc_pos; compare it with lo-1.
        if lo > 0 and abs(self._offset(lo - 1) - doc_pos) <= abs(self._offset(lo) - doc_pos):
            return lo - 1
        return lo
