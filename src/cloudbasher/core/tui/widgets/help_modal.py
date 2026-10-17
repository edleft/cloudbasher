"""Centered, scrollable help overlay for the multi-node TUI (`?`)."""

from __future__ import annotations

from typing import ClassVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Container, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Static


class HelpModal(ModalScreen[None]):
    """Full help text over a dimmed app, dismissed by any obvious key."""


    BINDINGS: ClassVar[list[BindingType]] = [
        Binding("escape", "dismiss_help", "Close", show=False),
        Binding("question_mark", "dismiss_help", "Close", show=False),
        Binding("q", "dismiss_help", "Close", show=False),
        Binding("enter", "dismiss_help", "Close", show=False),


        Binding("up", "page_up", "Page up", show=False, priority=True),
        Binding("down", "page_down", "Page down", show=False, priority=True),
        Binding("pageup", "page_up", "Page up", show=False),
        Binding("pagedown", "page_down", "Page down", show=False),


        Binding("j", "page_down", "Page down", show=False),
        Binding("k", "page_up", "Page up", show=False),
        Binding("ctrl+f", "page_down", "Page down", show=False),
        Binding("ctrl+b", "page_up", "Page up", show=False),
        Binding("h", "page_left", "Page left", show=False),
        Binding("l", "page_right", "Page right", show=False),
        Binding("left", "page_left", "Page left", show=False, priority=True),
        Binding("right", "page_right", "Page right", show=False, priority=True),
        Binding("g", "scroll_top", "Top", show=False),
        Binding("G", "scroll_bottom", "Bottom", show=False),


        Binding("space", "page_down", "Page down", show=False),
        Binding("shift+space", "page_up", "Page up", show=False),


        Binding("ctrl+d", "half_page_down", "Half page down", show=False),
        Binding("ctrl+u", "half_page_up", "Half page up", show=False),
    ]


    DEFAULT_CSS = """
    HelpModal {
        align: center middle;
        background: $background 60%;
    }

    HelpModal > #help-dialog {
        width: 90%;
        max-width: 110;
        height: 85%;
        border: double ansi_cyan;
        background: $surface;
        padding: 0 1;
    }

    HelpModal #help-body {
        /* scrollbar-gutter keeps the text from reflowing by one column the
           moment the bar appears. overflow-x auto pairs with the body's
           no_wrap: long lines extend past the panel and become scrollable
           rather than being folded at column 0. */
        scrollbar-gutter: stable;
        scrollbar-background: $surface;
        overflow-x: auto;
    }

    HelpModal #help-text {
        /* Grow to the widest line rather than the panel, or there is nothing
           for overflow-x to scroll. */
        width: auto;
    }

    HelpModal #help-hint {
        height: 1;
        color: ansi_cyan;
        text-align: center;
    }
    """

    def __init__(self, help_text: str, *, title: str = "Help") -> None:
        super().__init__()
        self._help_text = help_text
        self._title = title

    def compose(self) -> ComposeResult:
        with Container(id="help-dialog") as dialog:


            dialog.border_title = self._title
            with VerticalScroll(id="help-body"):


                body = self._help_text
                if not isinstance(body, Text):
                    body = Text(str(body))
                body = body.copy()
                body.no_wrap = True
                yield Static(body, id="help-text")
            yield Static(self._hint(), id="help-hint")

    @staticmethod
    def _hint() -> Text:
        """The one line that has to be on screen: how to get out again."""
        return Text("↑/↓ j/k · ←/→ h/l · g/G  —  Esc, q or ? to close", style="dim")

    def on_mount(self) -> None:


        self.query_one("#help-body", VerticalScroll).focus()

    @property
    def _body(self) -> VerticalScroll:
        return self.query_one("#help-body", VerticalScroll)

    def action_dismiss_help(self) -> None:
        self.dismiss(None)


    def _half_page(self) -> int:
        """Half the visible height, at least one line."""
        return max(1, self._body.size.height // 2)

    def action_half_page_down(self) -> None:
        self._body.scroll_relative(y=self._half_page(), animate=False)

    def action_half_page_up(self) -> None:
        self._body.scroll_relative(y=-self._half_page(), animate=False)

    def action_page_up(self) -> None:
        self._body.scroll_page_up(animate=False)

    def action_page_down(self) -> None:
        self._body.scroll_page_down(animate=False)

    def action_page_left(self) -> None:
        self._body.scroll_page_left(animate=False)

    def action_page_right(self) -> None:
        self._body.scroll_page_right(animate=False)

    def action_scroll_top(self) -> None:
        self._body.scroll_home(animate=False)

    def action_scroll_bottom(self) -> None:
        self._body.scroll_end(animate=False)
