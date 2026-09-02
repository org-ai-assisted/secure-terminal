#!/usr/bin/python3 -Bsu
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""An editable, REVEALED, multi-line text box for the review bar.

The review box is the exact preview of what will cross the terminal boundary AND
the field the user edits it in -- one surface, not a hidden edit box plus a
separate read-only mirror. Every character renders through the SAME cell pipeline
the terminal uses (feed_line_edits builds the logical cells, cells_to_runs renders
them detail-tinted, cells_display_col places the caret), so a homoglyph is tinted,
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
from PyQt6.QtGui import QColor, QTextCharFormat, QTextCursor, QFont
from PyQt6.QtWidgets import QPlainTextEdit

from secure_terminal.sanitize import (
    feed_line_edits, cells_to_runs, cells_display_col,
    sanitize_clipboard_unicode, MARK_KEY, THEMES, DISPLAY_MODES,
    BASE_POINT_SIZE,
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

    def source(self):
        """The box's current source string -- the exact text (display form, '\n'
        line breaks) that DELIVER will sanitize and send."""
        return self._text

    @staticmethod
    def _display_clean(text):
        """Display keep-printable: drop invisibles/bidi/control/default-ignorable,
        keep printable look-alikes/accents/CJK, keep '\n'/'\t'. Newline-preserving
        (unlike sanitize_paste*, which map '\n'->'\r' for the shell) because the box
        is a display surface; the shell mapping is applied only on deliver."""
        return sanitize_clipboard_unicode(text)

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
        """The document offset of source-string `index`: render the source PREFIX
        (text[:index]) and take its full display width. Reuses cells_to_runs's own
        prefix_len (offset where the current line begins) plus the current line's
        width via cells_display_col, so the offset can never disagree with the render
        -- the prefix renders as an exact prefix of the whole (deterministic,
        left-to-right, no autowrap). Monotonic non-decreasing in `index`."""
        completed, current = self._build(self._text[:index])
        _runs, prefix = cells_to_runs(completed, current, self._mode,
                                      colors=False, markings=self._markings)
        return prefix + cells_display_col(current, len(current), self._mode)

    def _caret_doc_pos(self):
        return self._offset(self._pos)

    # -- editing --------------------------------------------------------------
    def _replace(self, new_text, new_pos):
        self._text = new_text
        self._pos = max(0, min(new_pos, len(new_text)))
        self._render()
        self.changed.emit()

    def _insert(self, chunk):
        """Insert `chunk` (already display-sanitized) at the caret, advancing past
        it. Newlines in the chunk make real line breaks in the box."""
        if not chunk:
            return
        self._replace(self._text[:self._pos] + chunk + self._text[self._pos:],
                      self._pos + len(chunk))

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
            # Leave Ctrl chords (copy, select-all) to the base editor: they read the
            # rendered document, never mutate the source model.
            super().keyPressEvent(event)
            return
        if key in (Qt.Key.Key_Backspace,):
            if self._pos > 0:
                self._replace(self._text[:self._pos - 1] + self._text[self._pos:],
                              self._pos - 1)
            return
        if key in (Qt.Key.Key_Delete,):
            if self._pos < len(self._text):
                self._replace(self._text[:self._pos] + self._text[self._pos + 1:],
                              self._pos)
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
        sits on a cell boundary."""
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
