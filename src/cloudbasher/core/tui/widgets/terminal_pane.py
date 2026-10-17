"""Production TerminalPane widget — pyte-backed terminal grid."""

from __future__ import annotations

import os

from typing import Any, Literal, Optional

import pyte
from rich.segment import Segment
from rich.style import Style
from textual.geometry import Size
from textual.message import Message
from textual.reactive import reactive
from textual.strip import Strip
from textual.widget import Widget

from cloudbasher.core.utils.output import mask_secrets
from cloudbasher.core.utils.redact import (
    get_redaction_mode,
    is_redaction_enabled,
    redact_field,
    redact_text,
)


def _current_redaction_state() -> tuple[bool, str]:
    """The settings a rendered screen depends on, for snapshot invalidation."""
    return (is_redaction_enabled(), get_redaction_mode())


_PYTE_BASIC_COLORS = {
    "black",
    "red",
    "green",
    "yellow",
    "blue",
    "magenta",
    "cyan",
    "white",
    "brown",
    "default",
}


def _pyte_color_to_rich(color: str) -> Optional[str]:
    """Translate a pyte color name/hex to a Rich-compatible color string."""
    if not color or color == "default":
        return None
    if color in _PYTE_BASIC_COLORS:

        return "yellow" if color == "brown" else color
    if len(color) == 6 and all(c in "0123456789abcdefABCDEF" for c in color):
        return f"#{color}"
    return None


def _pyte_char_to_style(char: pyte.screens.Char) -> Style:
    """Build a Rich Style from a pyte Char's color/attribute info."""
    return Style(
        color=_pyte_color_to_rich(char.fg),
        bgcolor=_pyte_color_to_rich(char.bg),
        bold=char.bold,
        italic=char.italics,
        underline=char.underscore,
        reverse=char.reverse,
        strike=char.strikethrough,
    )


PaneMode = Literal["dispatcher", "shell"]


def _common_prefix(words: list[str]) -> str:
    """The longest prefix every word shares -- what Tab may safely insert."""
    return os.path.commonprefix(words)


class TerminalPane(Widget, can_focus=True):
    """Pyte-backed terminal grid widget."""

    DEFAULT_CSS = """
    TerminalPane {
        height: 1fr;
        background: $surface;
        color: $text;
        /* The pyte screen owns the visible content; Textual must not try
           to scroll the widget itself. Without `overflow: hidden`, a tiny
           mismatch between `get_content_height` and the actual viewport
           causes Textual to treat the widget as scrollable, and every
           focus change calls `scroll_visible()` which shifts the widget
           by one row — visible bug: clicking between CLI and Log panes
           appears to "scroll" the CLI pane by a line. */
        overflow: hidden;
    }
    """


    focused_chrome: reactive[bool] = reactive(False)


    class Submitted(Message):
        """User pressed Enter on a non-empty input line in dispatcher mode."""

        def __init__(self, terminal_pane: "TerminalPane", value: str) -> None:
            super().__init__()
            self.terminal_pane = terminal_pane
            self.value = value

        @property
        def control(self) -> "TerminalPane":
            return self.terminal_pane

    class LeaveRequested(Message):
        """User pressed Ctrl-D on an empty input (matches original handle_ctrl_d)."""

        def __init__(self, terminal_pane: "TerminalPane") -> None:
            super().__init__()
            self.terminal_pane = terminal_pane

        @property
        def control(self) -> "TerminalPane":
            return self.terminal_pane

    class ClearRequested(Message):
        """User pressed Ctrl-C — input cleared; App chooses the echo source."""

        def __init__(self, terminal_pane: "TerminalPane") -> None:
            super().__init__()
            self.terminal_pane = terminal_pane

        @property
        def control(self) -> "TerminalPane":
            return self.terminal_pane

    class ModeChanged(Message):
        """Vi editing mode changed — carries the display label the App should show in the status bar (e.g. "normal", "edit", "search:/foo"), not the raw internal state name. Label wording is ported verbatim from prompt_toolkit_app.py's `_render_status_text` mode_indicator mapping."""

        def __init__(self, label: str) -> None:
            super().__init__()
            self.label = label

    class EscapeAtNormal(Message):
        """Escape pressed while already in vi "normal" mode -- a redundant Escape, signalling the user wants to leave the pane entirely rather than exit insert mode."""

        def __init__(self, terminal_pane: "TerminalPane") -> None:
            super().__init__()
            self.terminal_pane = terminal_pane

        @property
        def control(self) -> "TerminalPane":
            return self.terminal_pane

    class ScrollPositionChanged(Message):
        """The local pyte viewport moved; refresh any title that reports it."""

        def __init__(self, terminal_pane: "TerminalPane") -> None:
            super().__init__()
            self.terminal_pane = terminal_pane

        @property
        def control(self) -> "TerminalPane":
            return self.terminal_pane


    SCROLLBACK_LINES = 1000


    RAW_FEED_MAX_CHARS = 512 * 1024

    def __init__(
        self,
        *,
        cols: int = 80,
        rows: int = 24,
        history: Optional[list[str]] = None,
        name: Optional[str] = None,
        id: Optional[str] = None,
        classes: Optional[str] = None,
        quick_quit: bool = False,
    ) -> None:
        super().__init__(name=name, id=id, classes=classes)


        self._quick_quit = quick_quit


        self._screen, self._stream = self._build_screen_and_stream(cols, rows)


        self._raw_feed: list[str] = []
        self._raw_feed_chars: int = 0


        self._redact_literals: tuple[tuple[str, str], ...] = ()


        self._mode: PaneMode = "dispatcher"


        self._completer = None
        self._input_buffer: str = ""
        self._cursor_offset: int = 0
        self._input_draft: str = ""
        self._history: list[str] = list(history or [])
        self._history_idx: int = -1


        self._search_mode: bool = False
        self._search_query: str = ""
        self._search_draft: str = ""
        self._search_draft_cursor: int = 0


        self._vi_mode: str = "insert"
        self._vi_pending_operator: Optional[str] = None


        self._vi_search_query: str = ""
        self._vi_search_last_query: str = ""


        self._prompt_cursor: tuple[int, int] = (0, 0)


        self._prompt_text: str = ""


        self._quiet_signals: bool = False


        self._input_locked: bool = False

    def set_input_locked(self, locked: bool) -> None:
        """Swallow line-editing input until unlocked (Ctrl-C/Ctrl-D exempt)."""
        self._input_locked = locked

    def _build_screen_and_stream(self, cols: int, rows: int) -> tuple[Any, Any]:
        """Construct a fresh, bound pyte.HistoryScreen/ByteStream pair."""
        screen = pyte.HistoryScreen(cols, rows, history=self.SCROLLBACK_LINES)
        stream = pyte.ByteStream(screen)


        try:
            import os

            if os.environ.get("CSR_DEBUG_FEED"):
                import traceback
                from cloudbasher.core.utils.output import log

                _real_feed = stream.feed

                def _diagnostic_feed(data):
                    try:
                        stack = traceback.extract_stack(limit=8)
                        callers = " <- ".join(f"{f.name}@{f.lineno}" for f in stack[:-1][-5:])
                        preview = data[:60].decode("utf-8", errors="replace")
                        preview = (
                            preview.replace("\x1b", "ESC").replace("\r", "\\r").replace("\n", "\\n")
                        )
                        log(
                            f"[stream.feed] cursor.y={screen.cursor.y} "
                            f"len={len(data)} preview={preview!r} "
                            f"from={callers}"
                        )
                    except Exception:
                        pass
                    _real_feed(data)

                stream.feed = _diagnostic_feed
        except Exception:
            pass
        return screen, stream

    def on_mount(self) -> None:

        size = self.size
        if size.width > 0 and size.height > 0:
            self._screen.resize(size.height, size.width)

    def on_resize(self, event) -> None:
        self._screen.resize(event.size.height, event.size.width)
        self.refresh()

    def on_focus(self) -> None:
        self.focused_chrome = True

    def on_blur(self) -> None:
        self.focused_chrome = False

    def key_pageup(self, event) -> None:
        """Claim PageUp before framework/app bindings can redirect it."""
        self._scroll_page_up()
        event.stop()

    def key_pagedown(self, event) -> None:
        """Claim PageDown before framework/app bindings can redirect it."""
        self._scroll_page_down()
        event.stop()

    def key_ctrl_b(self, event):
        """Vi-normal page-back; leave insert and remote-shell input alone."""
        if self._mode == "dispatcher" and self._vi_mode == "normal":
            self._scroll_page_up()
            event.stop()
            return None
        return False

    def key_ctrl_f(self, event):
        """Vi-normal page-forward; leave insert and remote-shell input alone."""
        if self._mode == "dispatcher" and self._vi_mode == "normal":
            self._scroll_page_down()
            event.stop()
            return None
        return False

    def on_mouse_scroll_up(self, event) -> None:
        """Mouse wheel up: page back through pyte scrollback. Suppress the default Textual scroll-by-line behavior that would shift the widget itself (visible bug: clicking between panes appeared to scroll the CLI pane by one line)."""
        self._scroll_page_up()
        event.stop()

    def on_mouse_scroll_down(self, event) -> None:
        """Mouse wheel down: page forward through pyte scrollback."""
        self._scroll_page_down()
        event.stop()


    def set_mode(self, mode: PaneMode) -> None:
        """Switch between dispatcher and shell modes."""
        self._mode = mode

    def feed_bytes(self, data: bytes) -> None:
        """Feed bytes to the pyte stream. Used for command output, prompt, ANY external content that should land on the screen."""
        if not data:
            return
        try:
            import os

            if os.environ.get("CSR_DEBUG_FEED"):
                import traceback
                from cloudbasher.core.utils.output import log

                stack = traceback.extract_stack(limit=6)
                callers = " <- ".join(f"{f.name}@{f.lineno}" for f in stack[:-1][-4:])
                preview = data[:60].decode("utf-8", errors="replace")
                preview = preview.replace("\x1b", "ESC").replace("\r", "\\r").replace("\n", "\\n")
                log(
                    f"[feed_bytes] cursor.y={self._screen.cursor.y} "
                    f"len={len(data)} preview={preview!r} from={callers}"
                )
        except Exception:
            pass
        self._stream.feed(data)
        self.refresh()

    def _record_feed(self, text: str) -> None:
        """Append to the un-redacted replay log, trimming oldest-first at the cap."""
        if not text:
            return
        self._raw_feed.append(text)
        self._raw_feed_chars += len(text)
        while self._raw_feed_chars > self.RAW_FEED_MAX_CHARS and len(self._raw_feed) > 1:
            self._raw_feed_chars -= len(self._raw_feed.pop(0))

    def set_redact_literals(self, pairs: "tuple[tuple[str, str], ...]") -> None:
        """Declare (value, field_type) strings this pane should always redact."""
        self._redact_literals = tuple(pairs)

    def _for_display(self, text: str) -> str:
        """Apply everything that is toggle-gated: the free-text sweep, then this pane's own node literals. The single place display filtering happens, so feed_text() and rescrub() cannot disagree about what a line looks like."""
        text = redact_text(text)
        for value, field_type in self._redact_literals:
            masked = redact_field(value, field_type)
            if value and masked and masked != value:
                text = text.replace(value, masked)
        return text

    def feed_text(self, text: str) -> None:
        """Feed a string to the screen: masked, then redacted, recording the former."""
        masked = mask_secrets(text)
        self._record_feed(masked)
        self.feed_bytes(self._for_display(masked).encode("utf-8", errors="replace"))

    def set_prompt(self, prompt_text: str = "clb> ") -> None:
        """Write a prompt to the screen and arm the input tracker."""


        lead = "\r\n" if self._screen.cursor.x != 0 else ""

        self.feed_text(f"{lead}\x1b[0m{prompt_text}")
        self._prompt_cursor = (self._screen.cursor.x, self._screen.cursor.y)
        self._prompt_text = prompt_text
        self._input_buffer = ""
        self._cursor_offset = 0
        self._input_draft = ""
        self._history_idx = -1
        self.refresh()

    def reset_terminal(self) -> None:
        """Fully reset visible + interactive state, as if freshly constructed."""
        self._screen, self._stream = self._build_screen_and_stream(
            self._screen.columns, self._screen.lines
        )


        self._raw_feed = []
        self._raw_feed_chars = 0
        self._input_buffer = ""
        self._cursor_offset = 0
        self._input_draft = ""
        self._history = []
        self._history_idx = -1
        self._search_mode = False
        self._search_query = ""
        self._search_draft = ""
        self._search_draft_cursor = 0
        self._vi_mode = "insert"
        self._vi_pending_operator = None
        self._vi_search_query = ""
        self._vi_search_last_query = ""
        self._prompt_cursor = (0, 0)
        self._prompt_text = ""
        self.refresh()

    def snapshot_state(self) -> dict:
        """Capture this pane's full visible + interactive state so it can be restored later via restore_state() -- e.g. the multi-node side Connect pane caching each node's own terminal instead of losing scrollback on every switch, the way reset_terminal() (above) deliberately discards it."""
        return {
            "screen": self._screen,
            "stream": self._stream,


            "raw_feed": list(self._raw_feed),
            "raw_feed_chars": self._raw_feed_chars,
            "redact_literals": self._redact_literals,


            "redaction_state": _current_redaction_state(),
            "input_buffer": self._input_buffer,
            "cursor_offset": self._cursor_offset,
            "input_draft": self._input_draft,
            "history": list(self._history),
            "history_idx": self._history_idx,
            "search_mode": self._search_mode,
            "search_query": self._search_query,
            "search_draft": self._search_draft,
            "search_draft_cursor": self._search_draft_cursor,
            "vi_mode": self._vi_mode,
            "vi_pending_operator": self._vi_pending_operator,
            "vi_search_query": self._vi_search_query,
            "vi_search_last_query": self._vi_search_last_query,
            "prompt_cursor": self._prompt_cursor,
            "prompt_text": self._prompt_text,
        }

    def restore_state(self, snapshot: dict) -> None:
        """Restore a snapshot_state() capture. `screen`/`stream` are swapped in as the bound pair they were constructed as (a pyte.ByteStream is tied to one specific pyte.Screen instance), not copied field-by-field -- restores the exact prior scrollback."""
        self._screen = snapshot["screen"]
        self._stream = snapshot["stream"]
        self._raw_feed = list(snapshot.get("raw_feed", ()))
        self._raw_feed_chars = snapshot.get("raw_feed_chars", 0)
        self._redact_literals = tuple(snapshot.get("redact_literals", ()))
        self._input_buffer = snapshot["input_buffer"]
        self._cursor_offset = snapshot["cursor_offset"]
        self._input_draft = snapshot["input_draft"]
        self._history = list(snapshot["history"])
        self._history_idx = snapshot["history_idx"]
        self._search_mode = snapshot["search_mode"]
        self._search_query = snapshot["search_query"]
        self._search_draft = snapshot["search_draft"]
        self._search_draft_cursor = snapshot["search_draft_cursor"]
        self._vi_mode = snapshot["vi_mode"]
        self._vi_pending_operator = snapshot["vi_pending_operator"]
        self._vi_search_query = snapshot["vi_search_query"]
        self._vi_search_last_query = snapshot["vi_search_last_query"]
        self._prompt_cursor = snapshot["prompt_cursor"]
        self._prompt_text = snapshot.get("prompt_text", "")


        if snapshot.get("redaction_state") != _current_redaction_state():
            self.rescrub()
            return
        self.refresh()

    def rescrub(self) -> None:
        """Rebuild the visible screen from _raw_feed at the CURRENT redaction setting -- what makes the `m` toggle retroactive instead of only affecting output that has yet to arrive."""
        self._screen, self._stream = self._build_screen_and_stream(
            self._screen.columns, self._screen.lines
        )
        for chunk in self._raw_feed:
            self._stream.feed(self._for_display(chunk).encode("utf-8", errors="replace"))


        self._prompt_cursor = (self._screen.cursor.x, self._screen.cursor.y)
        self._redraw_input_line()
        self.refresh()

    def current_prompt_text(self) -> str:
        """Return the literal prompt string from the last set_prompt() call."""
        return self._prompt_text

    def resize_rows(self, rows: int) -> None:
        """Directly resize the pyte screen's row count without waiting for a Textual layout/on_resize round trip."""
        rows = max(1, rows)
        if rows != self._screen.lines:
            self._screen.resize(rows, self._screen.columns)
        self.styles.height = rows

    def current_input_line(self) -> str:
        """Return whatever the user has typed since the last set_prompt()."""
        return self._input_buffer

    def clear_current_input(self) -> None:
        """Erase the current input line visually and reset the buffer."""


        prompt_x, prompt_y = self._prompt_cursor
        self._stream.feed(f"\x1b[{prompt_y + 1};{prompt_x + 1}H\x1b[0J".encode("utf-8"))
        self._input_buffer = ""
        self._cursor_offset = 0
        self.refresh()

    def prefill_input(self, text: str) -> None:
        """Type `text` as if the user typed it after the prompt."""
        if not text:
            return
        self._input_buffer = text
        self._cursor_offset = len(text)
        self._stream.feed(text.encode("utf-8", errors="replace"))
        self.refresh()

    def set_completer(self, completer) -> None:
        """Install the Tab-completion source."""
        self._completer = completer

    def _on_tab(self) -> bool:
        """Complete the word under the cursor, or list the alternatives."""
        if self._completer is None:
            return False
        line, offset = self._input_buffer, self._cursor_offset
        try:
            candidates, replace_from = self._completer(line, offset)
        except Exception:


            return False
        if not candidates:
            return False
        prefix = _common_prefix(candidates)
        stem = line[replace_from:offset]
        if len(candidates) == 1:
            insert = candidates[0] + " "
        elif len(prefix) > len(stem):
            insert = prefix
        else:


            self._stream.feed(("\r\n" + "  ".join(candidates) + "\r\n").encode())
            self._redraw_input_line()
            return True
        self._input_buffer = line[:replace_from] + insert + line[offset:]
        self._cursor_offset = replace_from + len(insert)
        self._redraw_input_line()
        return True

    def set_quiet_signals(self, quiet: bool) -> None:
        """Toggle silent Ctrl-C / Ctrl-D handling."""
        self._quiet_signals = quiet


    def on_paste(self, event) -> None:
        """Bracketed-paste text (Textual enables this automatically) — without this handler, pasted text was silently dropped since on_key only ever sees one character at a time."""
        if self._mode == "shell":
            return

        text = event.text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
        if not text:
            event.stop()
            return

        if self._search_mode:
            self._vi_search_query += text
            self._notify_vi_mode_display()
            event.stop()
            return

        if self._vi_mode not in ("insert", "replace"):


            event.stop()
            return

        offset = self._cursor_offset
        self._input_buffer = self._input_buffer[:offset] + text + self._input_buffer[offset:]
        self._cursor_offset += len(text)
        self._redraw_input_line()
        event.stop()

    def on_key(self, event) -> None:
        """Translate Textual key events into pyte input + buffer updates."""
        key = event.key

        if self._mode == "shell":


            return

        if self._search_mode:
            self._on_search_key(event)
            return


        if self._input_locked and key not in ("ctrl+c", "ctrl+d"):
            event.stop()
            return

        if key == "escape":
            self._on_vi_escape()
            event.stop()
            return

        if key == "enter":
            if self._vi_mode == "search":
                self._apply_vi_search(backward=True)
                event.stop()
                return
            if self._vi_mode == "replace-one":
                self._set_vi_mode("normal")
                event.stop()
                return
            if self._vi_mode == "normal":
                self._set_vi_mode("insert")
            self._submit_current_line()
            event.stop()
            return

        if key == "tab":


            if self._on_tab():
                event.stop()
            return

        if key == "ctrl+c":
            self._on_ctrl_c()
            event.stop()
            return

        if key == "ctrl+d":
            self._on_ctrl_d()
            event.stop()
            return

        if key == "ctrl+u":
            self.clear_current_input()
            event.stop()
            return

        if key == "ctrl+r":
            self._enter_search_mode()
            event.stop()
            return

        if key == "up":
            self._history_older()
            event.stop()
            return

        if key == "down":
            self._history_newer()
            event.stop()
            return

        if key == "left":
            self._move_cursor_left()
            event.stop()
            return

        if key == "right":
            self._move_cursor_right()
            event.stop()
            return

        if key in ("home", "ctrl+a"):
            self._move_cursor_to_start()
            event.stop()
            return

        if key in ("end", "ctrl+e"):
            self._move_cursor_to_end()
            event.stop()
            return

        if key == "ctrl+left":
            self._move_cursor_to_previous_word()
            event.stop()
            return

        if key == "ctrl+right":
            self._move_cursor_to_next_word()
            event.stop()
            return

        if key == "ctrl+w":
            self._delete_word_before_cursor()
            event.stop()
            return

        if key == "ctrl+k":
            self._delete_to_end_of_line()
            event.stop()
            return

        if key == "delete":
            self._on_delete_forward()
            event.stop()
            return

        if key == "backspace":
            if self._vi_mode == "search":
                self._vi_search_query = self._vi_search_query[:-1]
                self._notify_vi_mode_display()
                event.stop()
                return
            if self._vi_mode == "normal":


                event.stop()
                return
            self._on_backspace()
            event.stop()
            return

        if event.character is not None and event.character.isprintable():
            ch = event.character
            if self._vi_mode == "search":
                self._vi_search_query += ch
                self._notify_vi_mode_display()
                event.stop()
                return
            if self._vi_mode == "replace-one":
                self._replace_char_at_cursor(ch)
                self._set_vi_mode("normal")
                event.stop()
                return
            if self._vi_mode == "normal":
                self._handle_vi_normal_key(ch)
                event.stop()
                return
            if self._vi_mode == "replace":
                self._replace_char_at_cursor(ch)
                event.stop()
                return
            self._on_printable(ch)
            event.stop()
            return


    def _on_printable(self, ch: str) -> None:
        """Insert a printable character at the cursor and redraw the line."""
        offset = self._cursor_offset
        self._input_buffer = self._input_buffer[:offset] + ch + self._input_buffer[offset:]
        self._cursor_offset += 1
        self._redraw_input_line()

    def _on_backspace(self) -> None:
        """Delete the character before the cursor + redraw."""
        if self._cursor_offset == 0:
            return
        offset = self._cursor_offset
        self._input_buffer = self._input_buffer[: offset - 1] + self._input_buffer[offset:]
        self._cursor_offset -= 1
        self._redraw_input_line()

    def _on_delete_forward(self) -> None:
        """Delete the character under/after the cursor (forward-delete) + redraw."""
        if self._cursor_offset >= len(self._input_buffer):
            return
        offset = self._cursor_offset
        self._input_buffer = self._input_buffer[:offset] + self._input_buffer[offset + 1 :]
        self._redraw_input_line()


    def _redraw_input_line(self) -> None:
        """Repaint the input line from `_prompt_cursor` to reflect the current `_input_buffer` and reposition the cursor at `_cursor_offset`."""
        prompt_x, prompt_y = self._prompt_cursor
        columns = max(self._screen.columns, 1)
        seq = f"\x1b[{prompt_y + 1};{prompt_x + 1}H\x1b[0J{self._input_buffer}"
        target = prompt_x + self._cursor_offset
        cursor_row = prompt_y + target // columns
        cursor_col = target % columns
        seq += f"\x1b[{cursor_row + 1};{cursor_col + 1}H"
        self._stream.feed(seq.encode("utf-8", errors="replace"))
        self.refresh()

    @staticmethod
    def _word_char(value: str) -> bool:
        return value.isalnum() or value == "_"

    def _next_word_offset(self, offset: int) -> int:
        """Ported from the prompt_toolkit backend's ``_next_word_offset`` (vi/emacs-style word motion: skip non-word chars, then word chars, then trailing non-word chars) — see prompt_toolkit_app.py."""
        text = self._input_buffer
        current = max(0, min(offset, len(text)))
        if current >= len(text):
            return len(text)
        while current < len(text) and not self._word_char(text[current]):
            current += 1
        while current < len(text) and self._word_char(text[current]):
            current += 1
        while current < len(text) and not self._word_char(text[current]):
            current += 1
        return current

    def _previous_word_offset(self, offset: int) -> int:
        """Ported from the prompt_toolkit backend's ``_previous_word_offset``."""
        text = self._input_buffer
        current = max(0, min(offset, len(text)))
        if current <= 0:
            return 0
        current -= 1
        while current >= 0 and not self._word_char(text[current]):
            current -= 1
        while current >= 0 and self._word_char(text[current]):
            current -= 1
        return max(0, current + 1)

    def _move_cursor_left(self) -> None:
        if self._cursor_offset > 0:
            self._cursor_offset -= 1
            self._redraw_input_line()

    def _move_cursor_right(self) -> None:
        if self._cursor_offset < len(self._input_buffer):
            self._cursor_offset += 1
            self._redraw_input_line()

    def _move_cursor_to_start(self) -> None:
        if self._cursor_offset != 0:
            self._cursor_offset = 0
            self._redraw_input_line()

    def _move_cursor_to_end(self) -> None:
        if self._cursor_offset != len(self._input_buffer):
            self._cursor_offset = len(self._input_buffer)
            self._redraw_input_line()

    def _move_cursor_to_next_word(self) -> None:
        self._cursor_offset = self._next_word_offset(self._cursor_offset)
        self._redraw_input_line()

    def _move_cursor_to_previous_word(self) -> None:
        self._cursor_offset = self._previous_word_offset(self._cursor_offset)
        self._redraw_input_line()

    def _delete_word_before_cursor(self) -> None:
        start = self._previous_word_offset(self._cursor_offset)
        if start == self._cursor_offset:
            return
        end = self._cursor_offset
        self._input_buffer = self._input_buffer[:start] + self._input_buffer[end:]
        self._cursor_offset = start
        self._redraw_input_line()

    def _delete_to_end_of_line(self) -> None:
        if self._cursor_offset >= len(self._input_buffer):
            return
        self._input_buffer = self._input_buffer[: self._cursor_offset]
        self._redraw_input_line()


    def _enter_search_mode(self) -> None:
        if not self._history:
            return
        self._search_mode = True
        self._search_query = ""
        self._search_draft = self._input_buffer
        self._search_draft_cursor = self._cursor_offset
        self._redraw_search_line()

    def _search_match(self) -> Optional[str]:
        if not self._search_query:
            return self._search_draft
        for entry in reversed(self._history):
            if self._search_query in entry:
                return entry
        return None

    def _redraw_search_line(self) -> None:
        prompt_x, prompt_y = self._prompt_cursor
        match = self._search_match() or ""
        text = f"(reverse-i-search)'{self._search_query}': {match}"
        seq = f"\x1b[{prompt_y + 1};{prompt_x + 1}H\x1b[K{text}"
        self._stream.feed(seq.encode("utf-8", errors="replace"))
        self.refresh()

    def _on_search_key(self, event) -> None:
        key = event.key
        if key == "escape":
            self._search_mode = False
            self._input_buffer = self._search_draft
            self._cursor_offset = self._search_draft_cursor
            self._redraw_input_line()
            event.stop()
            return
        if key == "enter":
            match = self._search_match()
            self._search_mode = False
            self._input_buffer = match if match is not None else self._search_draft
            self._cursor_offset = len(self._input_buffer)
            self._redraw_input_line()
            event.stop()
            return
        if key == "backspace":
            self._search_query = self._search_query[:-1]
            self._redraw_search_line()
            event.stop()
            return
        if event.character is not None and event.character.isprintable():
            self._search_query += event.character
            self._redraw_search_line()
            event.stop()
            return
        event.stop()


    def _vi_mode_display_label(self) -> str:
        """Map internal `_vi_mode` to the status-bar label, ported verbatim from prompt_toolkit_app.py's `_render_status_text` mode_indicator mapping (note the ptk wording is intentionally inverted: its "insert" state — ordinary typing — is *labeled* "normal", and its "normal" state — vi navigation — is *labeled* "edit"). We skip ptk's "edit (n/m)" history-position suffix — no history-position indicator exists elsewhere in this backend."""
        if self._vi_mode == "insert":
            return "normal"
        if self._vi_mode == "normal":
            return "edit"
        if self._vi_mode == "search":
            return f"search:/{self._vi_search_query}"
        return self._vi_mode

    def _notify_vi_mode_display(self) -> None:
        self.post_message(self.ModeChanged(self._vi_mode_display_label()))

    def _set_vi_mode(self, mode: str) -> None:
        self._vi_mode = mode
        self._vi_pending_operator = None
        if mode in ("normal", "search"):
            self._vi_search_query = ""
        self._notify_vi_mode_display()

    def enter_insert_mode(self) -> None:
        """Force insert mode. For a freshly-opened command bar."""
        self._set_vi_mode("insert")

    def _on_vi_escape(self) -> None:
        was_already_normal = self._vi_mode == "normal"

        self._set_vi_mode("normal")
        if was_already_normal:
            self.post_message(self.EscapeAtNormal(self))

    def _handle_vi_normal_key(self, ch: str) -> None:
        """Ported from prompt_toolkit_app.py's `_handle_vi_normal_key`, rewired onto the cursor/delete primitives already built for Bug #2 (vi normal-mode offsets use the same 0..len range as insert mode — only the cursor's on-screen rendering differs, and pyte already draws a reverse-video block over the cursor cell regardless of mode)."""
        if self._vi_pending_operator == "d":
            self._handle_vi_delete_motion(ch)
            return
        if ch == "h":
            self._move_cursor_left()
        elif ch == "l":
            self._move_cursor_right()
        elif ch == "0":
            self._move_cursor_to_start()
        elif ch == "$":
            self._move_cursor_to_end()
        elif ch == "b":
            self._move_cursor_to_previous_word()
        elif ch == "w":
            self._move_cursor_to_next_word()
        elif ch == "x":
            self._on_delete_forward()
        elif ch == "D":
            self._delete_to_end_of_line()
        elif ch == "d":
            self._vi_pending_operator = "d"
        elif ch == "j":
            self._history_newer()
        elif ch == "k":
            self._history_older()
        elif ch == "/":
            self._set_vi_mode("search")
        elif ch == "n":
            self._apply_vi_search(backward=True)
        elif ch == "i":
            self._set_vi_mode("insert")
        elif ch == "a":
            self._move_cursor_right()
            self._set_vi_mode("insert")
        elif ch == "r":
            self._set_vi_mode("replace-one")
        elif ch == "R":
            self._set_vi_mode("replace")
        elif ch == "s":
            self._on_delete_forward()
            self._set_vi_mode("insert")
        elif ch == "S":
            self.clear_current_input()
            self._set_vi_mode("insert")


    def _vi_motion_target_offset(self, motion: str) -> Optional[int]:
        """Ported from prompt_toolkit_app.py's `_motion_target_offset`."""
        current = self._cursor_offset
        if motion == "h":
            return max(0, current - 1)
        if motion == "l":
            return min(len(self._input_buffer), current + 1)
        if motion == "0":
            return 0
        if motion == "$":
            return len(self._input_buffer)
        if motion == "w":
            return self._next_word_offset(current)
        if motion == "b":
            return self._previous_word_offset(current)
        return None

    def _handle_vi_delete_motion(self, motion: str) -> None:
        """Ported from prompt_toolkit_app.py's `_handle_delete_motion` (handles `d{motion}`, including `dd` clearing the whole line)."""
        self._vi_pending_operator = None
        if motion == "d":
            self.clear_current_input()
            return
        target = self._vi_motion_target_offset(motion)
        if target is None:
            return
        current = self._cursor_offset
        if target > current:
            self._delete_range(current, target)
        else:
            self._delete_range(target, current)

    def _delete_range(self, start: int, end: int) -> None:
        """Delete `_input_buffer[start:end]` and redraw. Generic range-delete needed for `d{motion}` — Bug #2 only needed delete-word-before and delete-to-end, not an arbitrary [start, end) range."""
        clamped_start = max(0, min(start, len(self._input_buffer)))
        clamped_end = max(0, min(end, len(self._input_buffer)))
        if clamped_end < clamped_start:
            clamped_start, clamped_end = clamped_end, clamped_start
        if clamped_start == clamped_end:
            return
        self._input_buffer = self._input_buffer[:clamped_start] + self._input_buffer[clamped_end:]
        self._cursor_offset = clamped_start
        self._redraw_input_line()

    def _replace_char_at_cursor(self, ch: str) -> None:
        """Ported from prompt_toolkit_app.py's `_replace_command_char_at_cursor` (always `advance=True` at both of its call sites, so that's the only behavior reproduced here)."""
        offset = self._cursor_offset
        if offset >= len(self._input_buffer):
            self._input_buffer += ch
        else:
            self._input_buffer = self._input_buffer[:offset] + ch + self._input_buffer[offset + 1 :]
        self._cursor_offset = offset + 1
        self._redraw_input_line()

    def _apply_vi_search(self, *, backward: bool) -> None:
        """Ported from prompt_toolkit_app.py's `_apply_history_search`. Distinct from Ctrl-R's `_search_match`: this commits on Enter/`n` against a query typed in full first, not a live incremental match."""
        query = self._vi_search_query or self._vi_search_last_query
        self._set_vi_mode("normal")
        if not query or not self._history:
            return
        entries = self._history
        if self._history_idx == -1:
            self._input_draft = self._input_buffer
            start_index = len(entries) - 1
        else:
            start_index = self._history_idx - 1 if backward else self._history_idx + 1
        search_range = range(start_index, -1, -1) if backward else range(start_index, len(entries))
        found_index: Optional[int] = None
        for index in search_range:
            if query in entries[index]:
                found_index = index
                break
        self._vi_search_last_query = query
        if found_index is None:
            return
        self._history_idx = found_index
        self._replace_input_with(entries[found_index])

    def _submit_current_line(self) -> None:
        """Submit the line: emit Submitted message and advance to next row."""
        line = self._input_buffer


        self._record_feed(mask_secrets(line))

        self._stream.feed(b"\r\n")
        self._record_feed("\r\n")
        self._input_buffer = ""
        self._cursor_offset = 0
        self._history_idx = -1
        self.refresh()


        self.post_message(self.Submitted(self, line))

    def _on_ctrl_c(self) -> None:
        """Clear input and let the App route Ctrl-C and choose its echo."""
        if self._quiet_signals:
            return


        self._input_buffer = ""
        self._cursor_offset = 0
        self._history_idx = -1
        self.refresh()
        self.post_message(self.ClearRequested(self))

    def echo_ctrl_c(self) -> None:
        """Render the local Ctrl-C echo when no remote PTY will echo it."""
        self._stream.feed(b"^C\r\n")
        self.refresh()

    def _on_ctrl_d(self) -> None:
        """LEAVE this surface. Ctrl-D used to mean "quit the program" in one pane and "hide the pane" in another, chosen by the pane id in the App's handler, with nothing on screen distinguishing them -- so one reflex was harmless here and started a shutdown there."""
        if self._quiet_signals:
            return
        if self._input_buffer and not self._quick_quit:
            return
        self.post_message(self.LeaveRequested(self))


    def _history_older(self) -> None:
        """Up arrow: load older history entry into input."""
        if not self._history:
            return
        if self._history_idx == -1:
            self._input_draft = self._input_buffer
            self._history_idx = len(self._history) - 1
        elif self._history_idx > 0:
            self._history_idx -= 1
        else:
            return

        self._replace_input_with(self._history[self._history_idx])

    def _history_newer(self) -> None:
        """Down arrow: load newer history entry, or restore draft."""
        if self._history_idx == -1:
            return
        self._history_idx += 1
        if self._history_idx >= len(self._history):
            self._history_idx = -1
            self._replace_input_with(self._input_draft)
        else:
            self._replace_input_with(self._history[self._history_idx])

    def _replace_input_with(self, text: str) -> None:
        """Clear current input visually and type the replacement text."""
        self.clear_current_input()
        self._input_buffer = text
        self._cursor_offset = len(text)
        self._stream.feed(text.encode("utf-8", errors="replace"))
        self.refresh()

    def append_history(self, line: str) -> None:
        """Append a successfully-submitted command to the history list."""
        if line and (not self._history or self._history[-1] != line):
            self._history.append(line)

    def _scroll_page_up(self) -> None:
        """Scroll the pyte HistoryScreen viewport one screen toward older content."""
        try:
            self._screen.prev_page()
            self.refresh()
            if self.is_mounted:
                self.post_message(self.ScrollPositionChanged(self))
        except Exception:
            pass

    def _scroll_page_down(self) -> None:
        """Scroll the pyte HistoryScreen viewport one screen toward newer content."""
        try:
            self._screen.next_page()
            self.refresh()
            if self.is_mounted:
                self.post_message(self.ScrollPositionChanged(self))
        except Exception:
            pass

    def get_plain_text(self) -> str:
        """Return the visible screen content as plain text (newline-separated)."""
        rows: list[str] = []
        for y in range(self._screen.lines):
            row = self._screen.buffer.get(y, {})
            line = "".join(
                (row.get(x).data if x in row else " ") for x in range(self._screen.columns)
            )
            rows.append(line.rstrip())

        while rows and not rows[-1]:
            rows.pop()
        return "\n".join(rows)


    def render_line(self, y: int) -> Strip:
        """Paint one row from pyte.Screen.buffer."""
        if y >= self._screen.lines:


            return Strip.blank(self.size.width, Style())

        row = self._screen.buffer.get(y, {})
        cursor_col = self._screen.cursor.x
        cursor_row = self._screen.cursor.y

        segments: list[Segment] = []
        run_text: list[str] = []
        run_style: Optional[Style] = None

        for x in range(self._screen.columns):
            char = row.get(x)
            if char is None:
                cell_text = " "
                cell_style = Style()
            else:
                cell_text = char.data or " "
                cell_style = _pyte_char_to_style(char)


            if y == cursor_row and x == cursor_col and self.has_focus:
                cell_style = cell_style + Style(reverse=True)

            if run_style is not None and cell_style == run_style:
                run_text.append(cell_text)
            else:
                if run_text:
                    segments.append(Segment("".join(run_text), run_style))
                run_text = [cell_text]
                run_style = cell_style

        if run_text:
            segments.append(Segment("".join(run_text), run_style))

        return Strip(segments).simplify()

    def get_content_width(self, container: Size, viewport: Size) -> int:


        return container.width

    def get_content_height(self, container: Size, viewport: Size, width: int) -> int:


        return container.height
