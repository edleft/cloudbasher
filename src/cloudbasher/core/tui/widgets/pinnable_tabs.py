"""One tiled tab-group for the multi-node info pane."""

from __future__ import annotations

from collections import deque
from typing import Callable, ClassVar, Optional

from textual.app import ComposeResult
from textual.binding import Binding, BindingType
from textual.containers import Container
from textual.reactive import reactive
from rich.text import Text as _RichText
from textual.widgets import RichLog, Static, TabbedContent, TabPane, Tabs

from cloudbasher.core.tui.widgets.follow_tail import FollowTailLog


def _ansi(line: str) -> "_RichText":
    """A console line as rich `Text`, with ANSI escapes turned into style."""
    return _RichText.from_ansi(line)


from cloudbasher.core.utils.redact import redact_text


def _log_buffer_maxlen() -> int:
    from cloudbasher.core.utils.perf_config import get_log_buffer_lines

    return get_log_buffer_lines()


_TAB_ORDER = ("tab-log", "tab-csp-log", "tab-csp-billing")


HIDDEN_TABS = frozenset({"tab-csp-log", "tab-csp-billing"})


def _visible_tab_order() -> tuple[str, ...]:
    return tuple(t for t in _TAB_ORDER if t not in HIDDEN_TABS)


class _NavigableLog(FollowTailLog, can_focus=False):
    """Display-only log widget for the Info pane's tabs."""


    DEFAULT_CSS = """
    _NavigableLog {
        overflow-y: auto;
    }
    """


class PinnableTabs(Container, can_focus=True):
    """One tiled tab-group in the bottom info pane."""

    DEFAULT_CSS = """
    PinnableTabs Tab.-active {
        color: $foreground 50%;

        &:ansi {
            text-style: dim;
        }
    }
    """


    pinned: reactive[bool] = reactive(False)
    active_csp: reactive[str] = reactive("AWS")

    BINDINGS: ClassVar[list[BindingType]] = [


        Binding("left", "log_page_left", "Page left", show=False),
        Binding("right", "log_page_right", "Page right", show=False),
        Binding("pageup", "log_page_up", "Page up", show=False),
        Binding("pagedown", "log_page_down", "Page down", show=False),


        Binding("up", "log_page_up", "Page up", show=False),
        Binding("down", "log_page_down", "Page down", show=False),
        Binding("shift+left", "log_page_left", "Page left", show=False),
        Binding("shift+right", "log_page_right", "Page right", show=False),


        Binding("j", "log_half_page_down", "Half page down", show=False),
        Binding("k", "log_half_page_up", "Half page up", show=False),
        Binding("h", "log_page_left", "Page left", show=False),
        Binding("l", "log_page_right", "Page right", show=False),


        Binding("G", "log_scroll_bottom", "Bottom", show=False),
        Binding("ctrl+f", "log_page_down", "Page down", show=False),
        Binding("ctrl+b", "log_page_up", "Page up", show=False),
    ]

    def __init__(
        self,
        csp: str,
        *,
        pinned: bool = False,
        on_billing_activate: Optional[Callable[[str], None]] = None,
        on_billing_deactivate: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__()
        self._initial_csp = csp
        self._initial_pinned = pinned


        self._log_lines_by_csp: dict[str, deque[str]] = {}
        self._billing_by_csp: dict[str, str] = {}


        self._console_lines: deque[str] = deque(maxlen=_log_buffer_maxlen())


        self._console_flushed = False


        self._on_billing_activate = on_billing_activate
        self._on_billing_deactivate = on_billing_deactivate


        self._pending_g = False

    def on_key(self, event) -> None:
        if event.key == "g":
            if self._pending_g:
                self._pending_g = False
                self.action_log_scroll_top()
                event.stop()
                event.prevent_default()
            else:
                self._pending_g = True
                event.stop()
                event.prevent_default()
        elif self._pending_g:
            self._pending_g = False

    def compose(self) -> ComposeResult:


        with TabbedContent():
            with TabPane("Log", id="tab-log"):
                yield self._new_log_widget("console-log-body")
            if "tab-csp-log" not in HIDDEN_TABS:
                with TabPane(
                    self._tab_label(self._initial_csp, "Logs", self._initial_pinned),
                    id="tab-csp-log",
                ):
                    yield self._new_log_widget("csp-log-body")
            if "tab-csp-billing" not in HIDDEN_TABS:
                with TabPane(
                    self._tab_label(self._initial_csp, "Billing", self._initial_pinned),
                    id="tab-csp-billing",
                ):
                    yield Static(
                        f"({self._initial_csp} billing — not yet wired)", id="csp-billing-body"
                    )

    def on_mount(self) -> None:
        self.active_csp = self._initial_csp
        self.pinned = self._initial_pinned


        self._refresh_tab_bodies()
        self._flush_buffered_console_lines()


        try:
            tabs = self.query_one(Tabs)
            tabs.can_focus = False
            self._disable_underline_animation(tabs)
        except Exception:
            pass


        self.set_interval(0.25, self._update_scroll_indicator)
        self._update_scroll_indicator()

    @staticmethod
    def _disable_underline_animation(tabs: Tabs) -> None:
        """Make tab switching instant."""
        original = tabs._highlight_active

        def _instant(*_args, **_kwargs) -> None:
            original(animate=False)

        tabs._highlight_active = _instant  # type: ignore[method-assign]

    @staticmethod
    def _new_log_widget(widget_id: str) -> _NavigableLog:


        return _NavigableLog(id=widget_id, max_lines=_log_buffer_maxlen(), auto_scroll=True)

    def action_previous_tab(self) -> None:
        self._cycle_tab(-1)

    def action_next_tab(self) -> None:
        self._cycle_tab(1)

    def _cycle_tab(self, direction: int) -> None:


        try:
            order = _visible_tab_order()
            if not order:
                return
            tabbed = self.query_one(TabbedContent)
            current_index = order.index(tabbed.active) if tabbed.active in order else 0
            tabbed.active = order[(current_index + direction) % len(order)]
        except Exception:
            pass


    def action_log_page_up(self) -> None:
        self._scroll_active_log(lambda w: w.scroll_page_up(animate=False))

    def action_log_page_down(self) -> None:
        self._scroll_active_log(lambda w: w.scroll_page_down(animate=False))

    def action_log_half_page_up(self) -> None:
        self._scroll_active_log(
            lambda w: w.scroll_relative(y=-max(1, int(w.size.height) // 2), animate=False)
        )

    def action_log_half_page_down(self) -> None:
        self._scroll_active_log(
            lambda w: w.scroll_relative(y=max(1, int(w.size.height) // 2), animate=False)
        )

    def action_log_page_left(self) -> None:
        self._scroll_active_log(lambda w: w.scroll_page_left(animate=False))

    def action_log_page_right(self) -> None:
        self._scroll_active_log(lambda w: w.scroll_page_right(animate=False))

    def action_log_scroll_top(self) -> None:


        self._scroll_active_log(lambda w: w.scroll_home(animate=False))

    def action_log_scroll_bottom(self) -> None:
        self._scroll_active_log(lambda w: w.scroll_end(animate=False))

    def _scroll_active_log(self, action: Callable[[RichLog], None]) -> None:
        """Page-scroll (or jump) whichever tab is currently active. No-op on the Billing tab (a plain Static, nothing to scroll) -- page-only by design, no incremental line/character scrolling anywhere here."""
        try:
            body_id = {
                "tab-log": "#console-log-body",
                "tab-csp-log": "#csp-log-body",
            }.get(self.query_one(TabbedContent).active)
            if body_id is None:
                return
            action(self.query_one(body_id, RichLog))
        except Exception:
            pass

    def _update_scroll_indicator(self) -> None:
        """Show visible-bottom / total rendered lines for the active log tab."""
        from cloudbasher.core.tui.textual_app import CloudShellTUIApp, PaneTitle

        try:
            title_widget = self.screen.query_one("#info-title", PaneTitle)
        except Exception:
            return
        try:
            active = self.query_one(TabbedContent).active
        except Exception:
            return
        body_id = {
            "tab-log": "#console-log-body",
            "tab-csp-log": "#csp-log-body",
        }.get(active)
        if body_id is None:
            title_widget.update("Info")
            return
        try:
            widget = self.query_one(body_id, RichLog)
            total_lines = max(len(widget.lines), 1)
            current_line = CloudShellTUIApp._visible_bottom_line(widget, total_lines)
        except Exception:
            return
        title_widget.update(f"Info {current_line}/{total_lines}")

    @staticmethod
    def _tab_label(csp: str, suffix: str, pinned: bool) -> str:
        pin = "\U0001f4cc " if pinned else ""
        return f"{pin}{csp} {suffix}"

    def _refresh_tab_labels(self) -> None:
        try:
            tabbed = self.query_one(TabbedContent)
            tabbed.get_tab("tab-csp-log").update(
                self._tab_label(self.active_csp, "Logs", self.pinned)
            )
            tabbed.get_tab("tab-csp-billing").update(
                self._tab_label(self.active_csp, "Billing", self.pinned)
            )
        except Exception:
            pass

    def watch_pinned(self) -> None:
        self._refresh_tab_labels()
        self._refresh_tab_bodies()

    def watch_active_csp(self) -> None:
        self._refresh_tab_labels()
        self._refresh_tab_bodies()

    def sync_to_selection(self, csp: str) -> None:
        if not self.pinned:
            self.active_csp = csp

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        """Start/stop the billing poll as the Billing tab becomes visible/hidden, and keep focus on PinnableTabs itself regardless of how the switch happened."""
        if event.pane.id == "tab-csp-billing":
            if self._on_billing_activate is not None:
                try:
                    self._on_billing_activate(self.active_csp)
                except Exception:
                    pass
        elif self._on_billing_deactivate is not None:
            try:
                self._on_billing_deactivate()
            except Exception:
                pass
        if self.has_focus_within:
            self.focus()

    def append_console_line(self, line: str) -> None:
        """Append one line to the CSP-agnostic "Log" tab -- startup/general console output (out()/eprint()/log()/detail() in multi-node mode)."""


        self._console_lines.append(line)
        if not self._console_flushed:


            return
        try:
            self.query_one("#console-log-body", RichLog).write(_ansi(redact_text(line)))
        except Exception:
            pass

    def _flush_buffered_console_lines(self) -> None:
        try:
            console_widget = self.query_one("#console-log-body", RichLog)
        except Exception:


            return


        self._console_flushed = True
        for line in self._console_lines:
            try:
                console_widget.write(_ansi(redact_text(line)))
            except Exception:
                pass

    def rescrub_logs(self) -> None:
        """Re-render both log tabs from their buffers at the CURRENT redaction setting -- the Log-tab half of what the `m` toggle does."""
        try:
            console_widget = self.query_one("#console-log-body", RichLog)
            console_widget.clear()
            for line in self._console_lines:
                console_widget.write(_ansi(redact_text(line)))
        except Exception:
            pass

        self._refresh_tab_bodies()

    def activate_log_tab(self) -> None:
        """Switch to the "Log" tab -- called on every command submit from the global command bar so its (buffered, atomically-flushed) output is visible the instant it lands, instead of sitting in a tab the user isn't looking at. Honors `pinned` the same way sync_to_selection() already does: a pinned group means the user deliberately froze which tab/CSP this group shows, so auto-activation backs off rather than yanking them away from it."""
        if self.pinned:
            return
        try:
            self.query_one(TabbedContent).active = "tab-log"
        except Exception:
            pass

    def append_log_line(self, csp: str, line: str) -> None:
        """Append one live-feed line to ``csp``'s buffer."""
        buf = self._log_lines_by_csp.setdefault(csp, deque(maxlen=_log_buffer_maxlen()))
        buf.append(line)
        if csp == self.active_csp:
            try:


                self.query_one("#csp-log-body", RichLog).write(_ansi(redact_text(line)))
            except Exception:
                pass

    def update_billing(self, csp: str, rendered_text: str) -> None:
        """Cache the latest billing summary for ``csp`` and, if it's the CSP currently visible, push it into the Static body immediately."""
        self._billing_by_csp[csp] = rendered_text
        if csp == self.active_csp:
            try:
                self.query_one("#csp-billing-body", Static).update(rendered_text)
            except Exception:
                pass

    def _refresh_tab_bodies(self) -> None:
        """Re-render the log RichLog and billing Static from the active CSP's buffered data."""
        try:
            log_widget = self.query_one("#csp-log-body", RichLog)
            log_widget.clear()
            buf = self._log_lines_by_csp.get(self.active_csp)
            if buf:
                for line in buf:
                    log_widget.write(_ansi(redact_text(line)))
            else:
                log_widget.write(f"({self.active_csp} log — not yet wired)")
        except Exception:
            pass
        try:
            self.query_one("#csp-billing-body", Static).update(
                self._billing_by_csp.get(self.active_csp)
                or f"({self.active_csp} billing — not yet wired)"
            )
        except Exception:
            pass
