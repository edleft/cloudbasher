"""Keymap footer + transient command-bar mode (tasks #106/#122)."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import Container
from textual.reactive import reactive
from textual.widgets import Static

from cloudbasher.core.tui.keymap import command_footer_segments, view_footer_segments
from cloudbasher.core.tui.widgets.terminal_pane import TerminalPane


class KeymapFooter(Container):
    """CMD row (row 1, static) + a second row (row 2) that's either the VIEW hint text or the live command bar, never both, + an armed-command grammar row shown only while something is armed."""

    active_pane: reactive[str] = reactive("node")
    command_mode: reactive[bool] = reactive(False)


    hint_grammar: reactive[str] = reactive("")
    hint_note: reactive[str] = reactive("")


    last_message: reactive[str] = reactive("")

    DEFAULT_CSS = """
    KeymapFooter {
        height: auto;
        dock: bottom;
        color: $text-muted;
        /* This container had no
           background of its own, relying entirely on its children's own
           `background: $surface` to cover its whole box. Belt-and-suspenders
           explicit declaration, matching every other pane's own chrome
           convention (PaneTitle/PaneFooter both set this on themselves too)
           -- removes any possibility of the Screen's own much darker
           `$background` showing through at this container's edges instead
           of the intended grey. */
        background: $surface;
    }
    KeymapFooter > #footer-cmd-row {
        height: 1;
        background: $surface;
    }
    KeymapFooter > #footer-view-row {
        height: 1;
        background: $surface;
    }
    KeymapFooter > #footer-view-row.-hidden {
        display: none;
    }
    KeymapFooter > #footer-hint-row {
        height: 1;
        background: $surface;
    }
    KeymapFooter > TerminalPane {
        display: none;
        /* The single-node #cli-terminal CSS rule in textual_app.py is an
           unscoped id selector (authored for single-node's real,
           always-visible CLI pane) -- it applies here too, since this
           bar shares the literal id. Its `padding: 0 1` would shift this
           bar 1 cell right of the unpadded CMD/VIEW rows above it;
           override back to 0 so the bar stays left-aligned with them.
           `background: $surface` from that same rule is fine/wanted --
           matches the explicit backgrounds on the two rows above.

           This override was
           still losing to `#cli-terminal`'s own `padding: 0 1` even after
           being added in round 3 -- confirmed by reading Textual's own
           specificity model (textual/css/styles.py's `Styles.extract_rules`):
           specificity is compared as an (id-count, class-count,
           type-count) tuple, so an ID selector like `#cli-terminal`
           ALWAYS outranks a plain type/child-combinator selector like
           `KeymapFooter > TerminalPane`, regardless of source order or
           DOM nesting depth -- there is no way to out-specify an ID
           selector without either renaming the id or using `!important`
           (confirmed supported: textual/css/tokenize.py's `important`
           token, used the same way in Textual's own built-in widget CSS,
           e.g. widgets/_button.py). `!important` is the correct fix here:
           renaming `#cli-terminal` would ripple through every id-keyed
           lookup that intentionally shares it with single-node's real CLI
           pane (see _compose_multi_node()'s comment on this widget). This
           is what actually caused the reported ':' prompt misalignment --
           the leftover 1-cell `padding: 0 1` shifts the prompt exactly one
           column right of the unpadded CMD row above it (from under 'C' to
           under 'M' in "CMD"). */
        padding: 0 !important;
    }
    KeymapFooter > TerminalPane.-open {
        display: block;
    }
    """

    def __init__(self, terminal: TerminalPane, **kwargs) -> None:
        super().__init__(**kwargs)
        self._terminal = terminal

    def compose(self) -> ComposeResult:
        yield Static(self._cmd_text(), id="footer-cmd-row")
        yield Static(self._view_text(), id="footer-view-row")


        yield Static(self._hint_text(), id="footer-hint-row")
        yield self._terminal

    def _hint_text(self) -> Text:
        """The armed hint as `Text`, NOT markup."""
        text = Text()
        if self.hint_grammar:
            text.append(self.hint_grammar, style="bold")
        if self.hint_note:
            if text.plain:
                text.append("  ")
            text.append(self.hint_note, style="dim")
        if text.plain:
            return text


        if self.last_message:
            text.append(self.last_message, style="dim")
        return text

    def set_hint(self, grammar: str = "", note: str = "") -> None:
        """Show an armed command's grammar, or clear it when both are empty."""
        self.hint_grammar = grammar
        self.hint_note = note

    def _refresh_hint(self) -> None:
        """Repaint the row. It is never hidden -- see `compose`. #130."""
        try:
            row = self.query_one("#footer-hint-row", Static)
        except Exception:
            return
        row.update(self._hint_text())

    def watch_hint_grammar(self, _old: str, _new: str) -> None:
        self._refresh_hint()

    def watch_hint_note(self, _old: str, _new: str) -> None:
        self._refresh_hint()

    def watch_last_message(self, _old: str, _new: str) -> None:
        self._refresh_hint()

    def set_last_message(self, text: str = "") -> None:
        """Record the last command's outcome, or clear it. #131."""
        self.last_message = text

    def _cmd_text(self) -> str:
        body = self._markup_segments(command_footer_segments())
        return f"[bold white]CMD[/bold white]  {body}"

    def _view_text(self) -> str:
        body = self._markup_segments(view_footer_segments(self.active_pane))
        return f"[bold white]VIEW[/bold white] {body}"

    @staticmethod
    def _markup_segments(segments: list[tuple[str, str]]) -> str:
        """Render (key, label) pairs as Rich markup -- cyan key letters, plain labels. `keymap.py` stays plain data; this is the one place that decides how it's styled."""
        return " ".join(
            f"[cyan]{key}[/cyan] {label}" if label else f"[cyan]{key}[/cyan]"
            for key, label in segments
        )

    def watch_active_pane(self, _old: str, _new: str) -> None:
        try:
            self.query_one("#footer-view-row", Static).update(self._view_text())
        except Exception:
            pass

    def watch_command_mode(self, _old: bool, new: bool) -> None:
        try:
            self.query_one("#footer-view-row", Static).set_class(new, "-hidden")
        except Exception:
            pass
        try:
            self._terminal.set_class(new, "-open")
        except Exception:
            pass
