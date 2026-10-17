"""Textual-based TUI application for CloudShell interactive mode."""

from __future__ import annotations

import queue
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Callable, Optional

from rich.style import Style
from rich.text import Text
from textual.app import App, ComposeResult, ScreenStackError
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import Header, RichLog, Static

if TYPE_CHECKING:
    from ..types import NodeRecord
    from .widgets import CredNodeTable, NodeStatusLine

from ..branding import (
    get_app_name,
    get_mouse_capture,
    get_prompt_text,
)
from ..interactive.repl_shared import (
    APP_QUIT_COMMANDS,
    SURFACE_EXIT_COMMANDS,
    expand_history_bang,
    is_confirm_answer,
    is_quit_confirmed,
    pending_question,
)
from ..node_supervisor import NodeSupervisor
from ..session.activity import activity_of
from ..session.prompt import display_prompt
from ..utils.output import (
    eprint,
    log,
    render_pty_output,
    set_console_output_sinks,
)
from ..utils.output import (
    out as _out,
)
from ..utils.redact import redact_field, redact_text
from .application import ShellContextInfo
from .keymap import root_bindings
from .widgets import KeymapFooter, OutputPane, TerminalPane

_UNCHANGED_TITLE_FIELD = object()


_FIELD_SEP = " · "


_CLI_BAR_MAX_ROWS = 5


_CLI_PANE_ID = "cli-terminal"
_SIDE_PANE_ID = "node-side-terminal-pane"


_SPLIT_UI_EOF_SENTINEL = "\0__split_ui_eof__\0"


def _format_cloudtrail_feed_line(payload: dict) -> str:
    """Render one CloudTrail-via-EventBridge payload (already trimmed by the Lambda -- see terraform/cloudtrail-eventbridge-ws/lambda_src/handler.py's _trim_cloudtrail_detail()) as a single log line for the AWS Logs tab."""
    event_time = payload.get("eventTime", "")
    event_source = payload.get("eventSource", "")
    event_name = payload.get("eventName", "")
    region = payload.get("awsRegion", "")
    identity = payload.get("userIdentity", "")
    line = f"{event_time} {event_source}:{event_name} region={region} who={identity}"
    error_code = payload.get("errorCode")
    if error_code:
        line += f" error={error_code}"
    return line


class PaneTitle(Static):
    """Pane header — left-aligned title block with horizontal-line fill."""

    LINE_CHAR = "─"
    DEFAULT_TITLE_W = 15


    _ACTIVE_TITLE_STYLE = "bold black on cyan"
    _META_TITLE_STYLE = "bold #d7dee8 on #5f6b7a"
    _ACTIVE_BORDER_STYLE = "bold cyan"
    _META_BORDER_STYLE = "#5f6b7a"

    focused: reactive[bool] = reactive(False)

    def __init__(
        self,
        renderable: str = "",
        *,
        title_width: Optional[int] = None,
        **kwargs,
    ) -> None:
        super().__init__(renderable, **kwargs)
        self.title_width = title_width if title_width is not None else self.DEFAULT_TITLE_W

    def render(self) -> Text:
        """The title block, PRESERVING any styling the caller applied."""
        try:
            content = self.content
            rich_title = content.copy() if isinstance(content, Text) else Text(str(content))
        except Exception:
            rich_title = Text("")


        rich_title.rstrip()
        title = rich_title.plain


        title_block = f" {title} ".center(self.title_width)

        width = self.size.width if self.size and self.size.width else 60


        fill_chars = max(0, width - 1 - len(title_block))

        title_style = self._ACTIVE_TITLE_STYLE if self.focused else self._META_TITLE_STYLE
        border_style = self._ACTIVE_BORDER_STYLE if self.focused else self._META_BORDER_STYLE

        text = Text()
        text.append(self.LINE_CHAR, style=border_style)


        lead = len(title_block) - len(title_block.lstrip())
        block = Text(title_block)
        block.stylize(title_style)
        for span in rich_title.spans:
            block.stylize(span.style, lead + span.start, lead + span.end)


        if rich_title.spans:
            first = min(rich_title.spans, key=lambda sp: sp.start)
            last = max(rich_title.spans, key=lambda sp: sp.end)


            unmarked = Style(underline=False)
            block.stylize(Style.parse(str(first.style)) + unmarked, 0, lead)
            block.stylize(
                Style.parse(str(last.style)) + unmarked,
                lead + len(title),
                len(title_block),
            )
        text.append_text(block)
        text.append(self.LINE_CHAR * fill_chars, style=border_style)
        return text

    def on_click(self, event) -> None:
        """1-click close for the side Connect pane's own title bar only -- every other PaneTitle instance (CLI/Log/Status/Nodes) no-ops here. Live-testing feedback: typing 'exit'/.exit or Ctrl-D-on-empty-line to close the side pane was klugey; this is the mouse equivalent."""
        if self.id != "node-side-title":
            return
        try:
            self.app.query_one("#multi-node-root", _MultiNodeRoot).close_side_terminal()
        except NoMatches:
            pass


class PaneFooter(Static):
    """Pane bottom border: a row of horizontal-line characters."""

    LINE_CHAR = "─"

    focused: reactive[bool] = reactive(False)

    def render(self) -> Text:
        width = self.size.width if self.size and self.size.width else 60
        style = PaneTitle._ACTIVE_BORDER_STYLE if self.focused else PaneTitle._META_BORDER_STYLE
        return Text(self.LINE_CHAR * width, style=style)


_STATUS_LABEL_WIDTH = 13


class _StatusRow(Static):
    """Base class for status rows. Disables focus and renders a padded label."""

    can_focus = False

    @staticmethod
    def _label_text(text: str) -> Text:
        """Build the padded bold-white label + Unicode-line divider."""
        padded = f"{text:<{_STATUS_LABEL_WIDTH}}"
        result = Text()
        result.append(padded, style="bold")
        result.append(" │ ", style="dim")
        return result


class HeaderBar(_StatusRow):
    """Cloud row of the status panel: 'Cloud [AWS] : IAM:... Account:... Region:...'."""

    context_info: reactive[Optional[ShellContextInfo]] = reactive(None)
    csp_label: reactive[str] = reactive("CSP")

    def render(self) -> Text:
        ctx = self.context_info
        cloud_text = f"Cloud [{self.csp_label or 'CSP'}]"
        text = self._label_text(cloud_text)
        if ctx is None or not (ctx.identity or ctx.scope or ctx.region):
            text.append("—")
            return text

        parts: list[str] = []
        if ctx.identity:
            parts.append(f"IAM:{redact_field(ctx.identity, 'identity')}")
        if ctx.scope:
            scope_label = "Account" if (self.csp_label or "").upper() == "AWS" else "Organization"
            parts.append(f"{scope_label}:{redact_field(ctx.scope, 'account')}")
        if ctx.region:
            parts.append(f"Region:{ctx.region}")
        text.append(_FIELD_SEP.join(parts))
        return text


_STATUS_BACKEND_LABEL = {"textual": "txt", "ptk": "ptk"}


class StatusBar(_StatusRow):
    """State row: 'State │ Mode: normal · TUI: txt · Ready'."""

    vi_mode: reactive[str] = reactive("normal")
    is_initializing: reactive[bool] = reactive(False)
    processing_command: reactive[Optional[str]] = reactive(None)


    tui_backend: reactive[str] = reactive("txt")


    recovering: reactive[str] = reactive("")


    provisioning: reactive[str] = reactive("")

    def render(self) -> Text:
        text = self._label_text("State")
        text.append(f"Mode: {self.vi_mode} · TUI: {self.tui_backend} · ")


        if self.is_initializing:
            text.append("Initializing...", style="bold white")
        elif self.recovering:


            text.append(redact_text(self.recovering), style="bold #FFEE00")
        elif self.processing_command:
            cmd = redact_text(self.processing_command)
            if len(cmd) > 30:
                cmd = cmd[:27] + "..."
            text.append(f"Processing: {cmd}", style="bold white")
            if self.provisioning:


                text.append(f" · {self.provisioning}", style="bold white")


            text.append("  (Ctrl-C to interrupt)", style="dim")
        else:
            text.append("Ready")
        return text


_VERB_GERUND = {
    "provision": "Provisioning",
    "reconnect": "Reconnecting",
    "delete": "Deleting",
    "bulk": "Running",
    "start": "Starting",
    "stop": "Stopping",
    "connect": "Connecting",
    "disconnect": "Disconnecting",
    "unregister": "Unregistering",
    "heartbeat": "Checking",
}


_REPORTED_SWALLOWED: set[str] = set()


def _report_swallowed(where: str) -> None:
    """Log the exception currently being handled, once per distinct site."""
    import traceback

    from ..utils.output import log

    formatted = traceback.format_exc()


    signature = f"{where}\n{formatted.strip().splitlines()[-1] if formatted.strip() else formatted}"
    if signature in _REPORTED_SWALLOWED:
        return
    _REPORTED_SWALLOWED.add(signature)
    try:
        log(f"SWALLOWED in {where} -- the Nodes pane may now be stale:\n{formatted}")
    except Exception:

        pass


def _log_line(text: str) -> None:
    """Write one diagnostic line to the log file and the Log tab."""
    try:
        from ..utils.output import log

        log(text)
    except Exception:
        pass


def _gerund(verb: str) -> str:
    """This verb's progress word, or a capitalised fallback."""
    return _VERB_GERUND.get((verb or "").strip().lower(), "Working")


def _provisioning_summary(nodes_by_id: dict) -> str:
    """The State row's fan-out progress line, or "" when nothing is Pending."""
    from cloudbasher.core.cancel import current_operation

    token = current_operation()
    try:
        nodes = list(nodes_by_id.values())
    except RuntimeError:


        return ""

    declared = token.total if token is not None else 0
    if declared:


        line = f"{_gerund(token.verb)} {token.settled}/{declared}"
        running = token.running
        return f"{line} · {running} in flight" if running else line
    else:


        pending = sum(1 for node in nodes if getattr(node, "container_status", "") == "Pending")
        if not pending:
            return ""
        total = len(nodes)
        line = f"Provisioning {total - pending}/{total}"

    running = token.running if token is not None else 0
    if running:
        line = f"{line} · {running} in flight"
    failed = sum(1 for node in nodes if getattr(node, "container_status", "") == "Failed")
    return f"{line} · {failed} failed" if failed else line


def _recovering_summary(nodes_by_id: dict) -> str:
    """The State row's cold-shell line, or "" when nothing is recovering."""
    recovering = [
        activity
        for node in nodes_by_id.values()
        if (activity := activity_of(node)) is not None and activity.phase == "recovering"
    ]
    if not recovering:
        return ""
    if len(recovering) == 1:
        return f"Shell rebuild {recovering[0].detail()}"
    return f"Shell rebuild on {len(recovering)} nodes"


class CloudShellRow(_StatusRow):
    """CloudShell row: '<not connected>' or 'IP:... User:... Hostname:...'."""

    context_info: reactive[Optional[ShellContextInfo]] = reactive(None)

    def render(self) -> Text:
        ctx = self.context_info
        text = self._label_text("CloudShell")
        if ctx is None or not (ctx.ext_ip or ctx.os_user or ctx.hostname):
            text.append("<not connected>")
            return text
        parts: list[str] = []
        if ctx.ext_ip:
            parts.append(f"IP:{redact_field(ctx.ext_ip, 'ip')}")
        if ctx.os_user:
            parts.append(f"User:{redact_field(ctx.os_user, 'username')}")
        if ctx.hostname:
            parts.append(f"Hostname:{redact_field(ctx.hostname, 'hostname')}")
        text.append(_FIELD_SEP.join(parts))
        return text


class NavigationRow(_StatusRow):
    """Static navigation hint row."""

    def render(self) -> Text:
        text = self._label_text("Navigation")
        text.append("Tab focus · Left/Right page · Up/Down line · Opt-Up/Down home/end")
        return text


_MULTI_NODE_GLOBAL_ONLY_COMMANDS = frozenset({".bulk", ".output", ".provision"})


@contextmanager
def _node_dispatch_context(state: Any, node: "NodeRecord"):
    """Temporarily point state._session_obj/api_client/credentials at `node`'s own runtime session/api client/credentials for the duration of one dispatch call, restoring the previous (primary) values afterward."""


    try:
        from ..cli.dispatcher import ensure_node_session

        ensure_node_session(state.csp_provider, state, node)
    except Exception:
        pass
    with state._credentials_lock:
        prev_session = getattr(state, "_session_obj", None)
        prev_api = state.api_client
        prev_creds = state.credentials
        rec = state.credentials_by_id.get(node.credential_id)
        state._session_obj = node._runtime_session
        state.api_client = node._runtime_api_client
        state.credentials = rec.raw if rec is not None else None


        prev_node = getattr(state, "_dispatch_node", None)
        state._dispatch_node = node
        try:
            yield
        finally:
            state._dispatch_node = prev_node
            state._session_obj = prev_session
            state.api_client = prev_api
            state.credentials = prev_creds


def _derive_side_terminal_prompt(pane: "TerminalPane") -> str:
    """Same ``[<UTC-ts>][<idx>]:<prompt>`` format as the main CLI pane's CloudShellTUIApp._derive_prompt_text(), but keyed off the side Connect terminal's own submitted-command history instead of the global CLI's -- user-reported bug: the side terminal previously showed a bare ``<node_id>$ `` prompt, not matching the rest of the app's convention. Module-level (not a method) since both _MultiNodeRoot.action_toggle_terminal and CloudShellTUIApp._handle_side_terminal_submitted need it."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    prompt_index = len(pane._history) + 1
    return f"[{ts}][{prompt_index}]:{get_prompt_text()} "


class _MultiNodeRoot(Container):
    """Wraps the whole multi-node layout so its page-level bindings (bulk-apply, connect, deregister, quit) are scoped to this widget's subtree rather than the App class -- single-letter keys on the App would intercept keystrokes typed into the single-node TerminalPane too (see the BINDINGS comment on CloudShellTUIApp for why that ordering matters). This container only exists in the tree when ``multi_node=True``, so single-node mode is structurally unaffected."""


    BINDINGS = [Binding(kb.key, kb.action, kb.label, show=False) for kb in root_bindings()] + [
        Binding("tab", "cycle_focus", "Cycle focus", show=False),
    ]


    _SIDE_PANE_CACHE_TTL_SECONDS = 3600

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


        self._side_node_id: Optional[str] = None
        self._side_title_base = "Terminal"
        self._side_title_ip: Optional[str] = None
        self._side_title_hostname: Optional[str] = None


        self._side_pane_cache: dict[str, tuple[dict, float]] = {}


        self._side_connect_timer: Any = None
        self._side_connect_frame: int = 0


        self._side_recovery_locked: bool = False


        self._pre_command_focus: Optional[Any] = None


        self._cli_bar_rows_timer: Any = None

    def _update_side_terminal_title(
        self,
        base: Optional[str] = None,
        *,
        ip: Any = _UNCHANGED_TITLE_FIELD,
        hostname: Any = _UNCHANGED_TITLE_FIELD,
    ) -> None:
        """Render raw, typed title fields through the shared redaction model."""
        if base is not None:
            self._side_title_base = base
            self._side_title_ip = None
            self._side_title_hostname = None
        if ip is not _UNCHANGED_TITLE_FIELD:
            self._side_title_ip = ip
        if hostname is not _UNCHANGED_TITLE_FIELD:
            self._side_title_hostname = hostname
        try:
            pane = self.query_one(f"#{_SIDE_PANE_ID}", TerminalPane)
            history = pane._screen.history
            rows = pane._screen.lines
            total = max(len(history.top) + len(history.bottom) + rows, 1)
            current = min(len(history.top) + rows, total)
            title = redact_text(self._side_title_base)
            if self._side_title_ip or self._side_title_hostname:
                ip_text = redact_field(self._side_title_ip, "ip") or "—"
                host_text = redact_field(self._side_title_hostname, "hostname") or "—"
                title += f" · {ip_text} ({host_text})"
            self.query_one("#node-side-title", PaneTitle).update(f"{title} [{current}/{total}]")
        except NoMatches:
            pass

    _SIDE_CONNECT_FRAMES = (".  ", ".. ", "...")

    def _enter_command_bar_mode(self) -> Optional[TerminalPane]:
        """Reveal the one-line command bar and remember what had focus so `_exit_command_bar_mode()` can put it back. Shared by all 9 entry points: the bare `:` key (`action_focus_command_bar`) and the 8 arm-actions below. Returns the focused TerminalPane (already focused), or None on NoMatches, in which case callers no-op exactly as they did before this refinement existed."""
        try:


            terminal = self.app.query_one("#cli-terminal", TerminalPane)
        except NoMatches:
            return None
        if self._pre_command_focus is None:


            self._pre_command_focus = self.app.focused
        try:


            self.app.query_one("#keymap-footer", KeymapFooter).command_mode = True
        except NoMatches:
            pass


        terminal.feed_text("\x1b[2J\x1b[H")
        terminal.resize_rows(1)
        terminal.set_prompt(self.app._derive_prompt_text())


        terminal.enter_insert_mode()
        terminal.focus()
        if self._cli_bar_rows_timer is None:


            self._cli_bar_rows_timer = self.set_interval(0.1, self.app._sync_cli_bar_rows)
        return terminal

    def discard_armed_state(self, *, ran: bool = False) -> None:
        """Retire whatever an arm action left on screen."""
        from .widgets import CredNodeTable


        self._retire_arm_hint_to_last_message(ran=ran)

        try:
            table = self.query_one("#node-table", CredNodeTable)
        except NoMatches:
            return
        table.clear_auto_selection()

    def _exit_command_bar_mode(self, *, cancelled: bool = False) -> None:
        """Hide the command bar and restore focus to whatever had it before entry -- called on both submit (`on_terminal_pane_submitted`) and a redundant Escape (`on_terminal_pane_escape_at_normal`)."""
        from .widgets import CredNodeTable

        if cancelled:
            self.discard_armed_state()

        if self._cli_bar_rows_timer is not None:
            try:
                self._cli_bar_rows_timer.stop()
            except Exception:
                pass
            self._cli_bar_rows_timer = None
        try:


            self.app.query_one("#cli-terminal", TerminalPane).resize_rows(1)
        except NoMatches:
            pass
        try:
            self.app.query_one("#keymap-footer", KeymapFooter).command_mode = False
        except NoMatches:
            pass

        restore = self._pre_command_focus
        self._pre_command_focus = None
        restored = False
        if restore is not None:
            try:
                restore.focus()
                restored = True
            except Exception:
                pass
        if not restored:


            try:
                self.query_one("#node-table", CredNodeTable).focus()
            except NoMatches:
                pass

    def _sync_side_terminal_recovery_lock(self, nodes_by_id: dict) -> None:
        """Freeze the side terminal's input while ITS node's shell is rebuilding."""
        from .widgets import TerminalPane

        try:
            pane = self.query_one(f"#{_SIDE_PANE_ID}", TerminalPane)
        except NoMatches:
            return
        node_id = self._side_node_id
        node = nodes_by_id.get(node_id) if node_id else None
        activity = activity_of(node) if node is not None else None
        recovering = activity is not None and activity.phase == "recovering"
        if recovering == self._side_recovery_locked:
            return
        if recovering:


            if self._side_connect_timer is not None:
                return
            pane.set_input_locked(True)
            self._side_recovery_locked = True
            pane.feed_text(
                "\x1b[2mThe shell stopped executing and is being rebuilt; input is "
                "held until it answers (Ctrl-C to abandon).\x1b[0m\r\n"
            )
        else:
            pane.set_input_locked(False)
            self._side_recovery_locked = False
            pane.feed_text("\x1b[2mShell is answering again.\x1b[0m\r\n")
            pane.set_prompt(_derive_side_terminal_prompt(pane))

    def _stop_side_connect_spinner(self) -> None:
        """Cancel the connecting animation, if one is running. Idempotent."""
        if self._side_connect_timer is not None:
            try:
                self._side_connect_timer.stop()
            except Exception:
                pass
            self._side_connect_timer = None

    def _evict_stale_side_pane_cache(self) -> None:
        now = time.monotonic()
        stale = [
            nid
            for nid, (_snapshot, cached_at) in self._side_pane_cache.items()
            if now - cached_at > self._SIDE_PANE_CACHE_TTL_SECONDS
        ]
        for nid in stale:
            del self._side_pane_cache[nid]

    def _resolve_selection_scope(
        self, table: "CredNodeTable", status: Optional["NodeStatusLine"], label: str
    ) -> Optional[tuple[str, int]]:
        """Smart scope: arm-action keys used to require an explicit selection and error out otherwise. Vi/Gmail muscle memory expects the opposite default -- act on the selection if one exists, else on whatever row is under the cursor -- so a single highlighted row no longer needs a throwaway `x` press first."""
        selected = table.get_selected_ids()
        if selected:
            return "selected", len(selected)
        if table.cursor_row is None or table.row_count == 0:
            if status is not None:
                status.show_message(
                    f"{label}: no nodes selected and no row highlighted.",
                    is_error=True,
                )
            return None
        if table.cursor_is_childless_credential():
            if status is not None:
                status.show_message(
                    f"{label}: that credential has provisioned nothing yet — "
                    "press p to create a node on it.",
                    is_error=True,
                )
            return None
        if table.cursor_is_credential_row():


            return "selected", len(table.select_current_row())
        row_number = table.cursor_row_number()
        if row_number is None:


            if status is not None:
                status.show_message(
                    f"{label}: that row is a column header, not a node.",
                    is_error=True,
                )
            return None


        display_id = table.cursor_display_id()
        if display_id is None:
            if status is not None:
                status.show_message(
                    f"{label}: that node has no Cred#.Node# id — its credential "
                    "is not in the registry, so nothing can address it.",
                    is_error=True,
                )
            return None


        table.select_current_row()
        visible_row_node_ids = getattr(self.app.state, "visible_row_node_ids", None) or []
        count = (
            len(visible_row_node_ids[row_number - 1])
            if 1 <= row_number <= len(visible_row_node_ids)
            else 1
        )
        return display_id, count

    def _retire_arm_hint_to_last_message(self, *, ran: bool) -> None:
        """Retire the armed hint; record what ran, if anything."""
        subject = getattr(self, "_armed_subject", "")


        self._set_arm_hint()
        self._armed_subject = ""
        if not ran:
            return
        try:
            footer = self.app.query_one("#keymap-footer", KeymapFooter)
        except NoMatches:
            return
        if subject:
            footer.set_last_message(f"last: {subject}")

    def _set_arm_hint(self, grammar: str = "", note: str = "") -> None:
        """THE one place an armed command writes to the footer hint row."""
        try:
            footer = self.app.query_one("#keymap-footer", KeymapFooter)
        except NoMatches:
            return
        footer.set_hint(grammar, note)


        if grammar or note:
            footer.set_last_message("")

    def _armed_grammar(self, command: str, label: str) -> str:
        """`"<Label> armed — <grammar>"`, with the grammar GENERATED."""
        from ..cli.command_spec import usage

        dispatcher = getattr(self.app, "_dispatcher", None)
        spec = dispatcher.spec_for(f".{command}") if dispatcher is not None else None
        if spec is None:
            return f"{label} armed — .{command}"
        text = usage(spec).removeprefix("Usage: ").removeprefix(f".{command} ")
        return f"{label} armed — {text}"


    _UNMANAGED_REFUSALS = {
        "bulk": "there is no session to run a command in",
        "output": "there is no session, so there is no output",
        "connect": "nothing to connect to yet",
        "disconnect": "these are not connected",
        "start": "nothing to start until it is tracked",
        "stop": "nothing to stop until it is tracked",


        "unregister": "these rows are already not registered -- that is what " "'unmanaged' means",
    }

    def _refuse_in_unmanaged(self, command: str, label: str) -> bool:
        """True if `command` is refused because the Unmanaged view is on."""
        from .widgets import CredNodeTable, NodeStatusLine

        try:
            table = self.query_one("#node-table", CredNodeTable)
        except NoMatches:
            return False
        if getattr(table, "_view_mode", "") != "unmanaged":
            return False
        why = self._UNMANAGED_REFUSALS.get(command)
        if why is None:
            return False
        try:
            status = self.query_one("#node-status-line", NodeStatusLine)
        except NoMatches:
            return True
        status.show_message(
            f"{label.lower()}: {why}. Press r to register these rows, then {label[0].lower()}.",
            is_error=True,
        )
        return True

    def _arm_node_command(
        self, command: str, label: str, *, trailing_space: bool = True
    ) -> Optional[str]:
        """Arm a node-selector command: resolve scope, prefill, hint. ONE path."""
        from .widgets import CredNodeTable, NodeStatusLine

        if self._refuse_in_unmanaged(command, label):
            return None

        try:
            status = self.query_one("#node-status-line", NodeStatusLine)
        except NoMatches:
            status = None

        try:
            table = self.query_one("#node-table", CredNodeTable)
        except NoMatches:
            return None
        scope = self._resolve_selection_scope(table, status, label)
        if scope is None:
            return None
        selector, count = scope

        terminal = self._enter_command_bar_mode()
        if terminal is None:
            return None
        terminal.clear_current_input()
        terminal.prefill_input(f"{command} {selector}" + (" " if trailing_space else ""))
        self._set_arm_hint(
            self._armed_grammar(command, label),
            f"acts on {count} node(s); press Enter to run.",
        )


        self._armed_subject = f"{label}: {count} node(s)"
        return selector

    def action_bulk_apply(self) -> None:
        """Arm ``.bulk`` by pre-filling the command line; the selection itself lives in ``InteractiveState.selected_node_ids``."""
        self._arm_node_command("bulk", "Bulk apply")

    def action_deregister_arm(self) -> None:
        """Arm the two-step node deregistration; ``.unregister`` is a kept alias."""
        self._arm_node_command("unregister", "Unregister")

    def _unmanaged_scope(self, label: str) -> Optional[tuple[str, int]]:
        """`("selected", n)` for the UNMANAGED view, or None once refused."""
        from .widgets import CredNodeTable, NodeStatusLine

        try:
            table = self.query_one("#node-table", CredNodeTable)
        except NoMatches:
            return None
        picked = set(getattr(table, "_selected_finding_ids", set()))
        if picked:
            return "selected", len(picked)
        try:
            status = self.query_one("#node-status-line", NodeStatusLine)
        except NoMatches:
            return None
        if table.unmanaged_row_count() is None:
            status.show_message(
                f"{label.lower()}: no discovery has run -- type .discover or .enum first.",
                is_error=True,
            )
        else:
            status.show_message(
                f"{label.lower()}: tick rows with x first (or a for all).", is_error=True
            )
        return None

    def _arm_unmanaged_command(self, verb: str, label: str) -> None:
        """Arm `.unmanaged <verb> selected`"""
        scope = self._unmanaged_scope(label)
        if scope is None:
            return
        selector, count = scope
        terminal = self._enter_command_bar_mode()
        if terminal is None:
            return
        terminal.clear_current_input()


        terminal.prefill_input(f"unmanaged {verb} {selector}" + (" " if verb == "delete" else ""))
        self._set_arm_hint(
            f"unmanaged {verb} {selector}",
            f"acts on {count} unmanaged environment(s); press Enter to run."
            + (" Add --yes to actually delete." if verb == "delete" else ""),
        )

    def action_unmanaged_register_arm(self) -> None:
        """`r` -- start TRACKING the ticked unmanaged environments"""
        from .widgets import CredNodeTable, NodeStatusLine

        try:
            table = self.query_one("#node-table", CredNodeTable)
        except NoMatches:
            return
        if getattr(table, "_view_mode", "") != "unmanaged":
            try:
                self.query_one("#node-status-line", NodeStatusLine).show_message(
                    "register: these rows are already tracked. Press 3 for the "
                    "Unmanaged view, where there is something to register.",
                    is_error=True,
                )
            except NoMatches:
                pass
            return
        self._arm_unmanaged_command("register", "Register")

    def action_delete_arm(self) -> None:
        """Arms .delete: mirrors action_deregister_arm's prefill-then-Enter pattern, but for the operation with real blast radius -- permanent deletion of the underlying cloud environment. Closes the prior gap where .forget had a TUI safety net and .delete (higher risk) had none. The dispatcher-side --yes gate (sub-item D) still applies for multi-node selections -- this key doesn't bypass it, it only saves typing the command name."""


        from .widgets import CredNodeTable

        try:
            if getattr(self.query_one("#node-table", CredNodeTable), "_view_mode", "") == (
                "unmanaged"
            ):
                self._arm_unmanaged_command("delete", "Delete")
                return
        except NoMatches:
            pass
        selector = self._arm_node_command("delete", "Delete")
        if selector is None:
            return


        app_state = getattr(self.app, "state", None)
        if app_state is not None:
            app_state.delete_armed_selector = selector

    def action_connect_arm(self) -> None:
        """Arm ``.connect`` for the highlighted row -- a COMMAND-tier action; opening a terminal is ``t``."""
        self._arm_node_command("connect", "Connect")

    def action_disconnect_arm(self) -> None:
        """Arms .disconnect: bound to shift+c, case-paired with `c` (connect) as its natural opposite -- the same convention `s`/`S` (Start/Stop) uses. Mirrors action_deregister_arm's prefill-then-Enter pattern."""
        self._arm_node_command("disconnect", "Disconnect")

    def action_start_arm(self) -> None:
        """Arms .start: brings a suspended/stopped environment back up without connecting. Mirrors action_deregister_arm's prefill-then-Enter pattern."""
        self._arm_node_command("start", "Start")

    def action_stop_arm(self) -> None:
        """Arms .stop: suspends a running environment without disconnecting. Live-probed and confirmed real against AWS; mirrors action_deregister_arm's prefill-then-Enter pattern."""
        self._arm_node_command("stop", "Stop")

    def action_toggle_redact(self) -> None:
        """Flips the demo-obfuscation master on/off switch and immediately re-renders the Nodes table so the effect is visible without waiting for the next node status change. User-reported: the previous off/partial/pseudonym 3-state cycle was one state too many to track mid-demo -- style (partial vs. pseudonym, per field or regex rule) is entirely rc-configured now, so the TUI only ever offers plain on/off. Unlike .bulk/.output/.forget this is a direct single-keypress toggle, not a prefill-then-Enter -- there's no destructive or consequential action to guard against, just a display mode."""
        from ..utils.redact import toggle_redaction
        from .widgets import NodeStatusLine

        enabled = toggle_redaction()
        self.app.refresh_node_table()
        self.app.rescrub_display_surfaces()


        self._update_side_terminal_title()
        try:
            status = self.query_one("#node-status-line", NodeStatusLine)
        except NoMatches:
            return
        status.show_message(f"Redaction: {'on' if enabled else 'off'}")

    def action_toggle_verbose(self) -> None:
        """`v` -- full ARNs in Identity, Acts As and Target Identity, or the short forms."""
        from ..identity_listing import toggle_verbose_identity
        from .widgets import NodeStatusLine

        enabled = toggle_verbose_identity()
        self.app.refresh_node_table()
        try:
            status = self.query_one("#node-status-line", NodeStatusLine)
        except NoMatches:
            return
        status.show_message(f"Verbose identities: {'on' if enabled else 'off'}")

    _INFO_ZOOM_CLASS = "-info-zoom"

    def action_toggle_info_zoom(self) -> None:
        """`z` -- zoom the Info pane to full height, or restore the split."""
        from .widgets import CredNodeTable, PinnableTabs

        zoomed = not self.has_class(self._INFO_ZOOM_CLASS)
        self.set_class(zoomed, self._INFO_ZOOM_CLASS)


        try:
            if zoomed:
                self.query_one(PinnableTabs).focus()
            else:
                self.query_one("#node-table", CredNodeTable).focus()
        except NoMatches:
            pass


    def action_output_arm(self) -> None:
        """Arm ``.output``, pre-filling ``.output selected`` -- mirrors ``action_bulk_apply``."""
        self._arm_node_command("output", "Output", trailing_space=False)

    def _provision_scope(self) -> str:
        """"provisioning cred 1" / "creds 1, 3" / "5 credentials" -- what `.provision selected` will actually act on."""
        from ..node_ids import build_id_map
        from ..selection import selected_credential_records

        state = self.app.state
        records = selected_credential_records(state, provider="aws")


        _nodes, cred_ids = build_id_map(state.credentials_by_id, state.nodes_by_id)
        nums = [cred_ids[r.id] for r in records if r.id in cred_ids]
        if not nums:
            return "provisioning the selection"
        if len(nums) == 1:
            return f"provisioning cred {nums[0]}"
        if len(nums) <= 4:
            return "provisioning creds " + ", ".join(nums)
        return f"provisioning {len(nums)} credentials"

    def action_provision_arm(self) -> None:
        """Arms .provision (manual-verification feedback): pre-fills the command line and shifts focus to the CLI pane, mirroring action_bulk_apply's 'b' -- unlike bulk apply, provisioning doesn't depend on a row selection, so this is always available."""
        from .widgets import CredNodeTable as _CNT
        from .widgets import NodeStatusLine as _NSL

        try:
            if getattr(self.query_one("#node-table", _CNT), "_view_mode", "") == "unmanaged":
                try:
                    self.query_one("#node-status-line", _NSL).show_message(
                        "provision: the cursor is on an unmanaged environment, not a "
                        "credential. Press 1 or 2 to pick the credential to provision on.",
                        is_error=True,
                    )
                except NoMatches:
                    pass
                return
        except NoMatches:
            pass
        terminal = self._enter_command_bar_mode()
        if terminal is None:
            return
        terminal.clear_current_input()


        from cloudbasher.core.provision_grammar import bulk_grammar, grammar_for

        cred_num = None
        selected_count = 0
        csp = mode = kind = ""
        try:
            from .widgets import CredNodeTable

            table = self.query_one("#node-table", CredNodeTable)


            selected_count = len(table.get_selected_credential_ids() | table.get_selected_ids())


            if not selected_count:
                table.select_current_row()
            cred_num = table.cursor_credential_number()
            csp = table.cursor_credential_provider()
            mode = table.cursor_credential_mode()
            kind = table.cursor_credential_kind()
        except NoMatches:
            pass


        if selected_count:


            grammar = bulk_grammar(selected_count)
            terminal.prefill_input(f"provision selected {grammar.prefill_suffix}")


            self._set_arm_hint(grammar.grammar, f"{grammar.note} · {self._provision_scope()}")
            return

        grammar = grammar_for(csp, mode, kind)
        if cred_num:


            terminal.prefill_input(f"provision {cred_num} {grammar.prefill_suffix}")
        else:
            terminal.prefill_input("provision ")


        self._set_arm_hint(grammar.grammar, grammar.note)

    def action_toggle_terminal(self) -> None:
        """Open, switch or close the side Terminal pane -- a VIEW-tier action."""
        from .widgets import CredNodeTable, NodeStatusLine

        try:
            table = self.query_one("#node-table", CredNodeTable)
        except NoMatches:
            return


        if getattr(table, "_view_mode", "") == "unmanaged":
            try:
                self.query_one("#node-status-line", NodeStatusLine).show_message(
                    "terminal: an unmanaged environment has no session. Press r to "
                    "register it, then c to connect, then t.",
                    is_error=True,
                )
            except NoMatches:
                pass
            return
        node_id = table.current_node_id()

        if node_id is not None and node_id == self._side_node_id:
            self.close_side_terminal()
            return
        if node_id is None:
            try:
                self.query_one("#node-status-line", NodeStatusLine).show_message(
                    "Terminal: highlight a single node row first.", is_error=True
                )
            except NoMatches:
                pass
            return

        app = self.app
        node = app.state.nodes_by_id.get(node_id)
        if node is None:
            return


        from ..node_ids import display_id_for

        node_ref = (
            display_id_for(node_id, app.state.credentials_by_id, app.state.nodes_by_id) or "?"
        )


        from ..cli.dispatcher import node_busy_reason

        busy = node_busy_reason(node)
        if busy is not None:
            try:
                self.query_one("#node-status-line", NodeStatusLine).show_message(
                    f"Terminal: {node_ref} is not ready — {busy}.", is_error=True
                )
            except NoMatches:
                pass
            return


        try:
            container = self.query_one("#node-side-terminal")
            container.add_class("-open")
            self._update_side_terminal_title(f"Terminal — {node_ref} · {node.region or '—'}")
            pane = self.query_one(f"#{_SIDE_PANE_ID}", TerminalPane)
        except NoMatches:
            return


        old_node_id = self._side_node_id
        if old_node_id is not None and old_node_id != node_id:
            self._side_pane_cache[old_node_id] = (pane.snapshot_state(), time.monotonic())
        self._evict_stale_side_pane_cache()
        cached = self._side_pane_cache.pop(node_id, None)
        if cached is not None:
            pane.restore_state(cached[0])
        else:
            pane.reset_terminal()


            pane.feed_text(
                "\x1b[2mCtrl-D or 'exit' hides this pane (the connection stays live) -- "
                "press 'c' again to reopen it, or 'C' from the Nodes pane to actually "
                "disconnect.\x1b[0m\r\n"
            )
        self._side_node_id = node_id


        pane.set_input_locked(True)
        self._stop_side_connect_spinner()
        self._side_connect_frame = 0
        connect_label = f"Connecting to {node_ref} · {node.region or '—'} "

        def _tick_spinner() -> None:
            if self._side_node_id != node_id:
                self._stop_side_connect_spinner()
                return
            frame = self._SIDE_CONNECT_FRAMES[
                self._side_connect_frame % len(self._SIDE_CONNECT_FRAMES)
            ]
            self._side_connect_frame += 1


            pane.feed_text(f"\r\x1b[2m{connect_label}{frame}\x1b[0m\x1b[K")

        _tick_spinner()
        self._side_connect_timer = self.set_interval(0.4, _tick_spinner)
        pane.focus()

        def _connect() -> None:
            from ..cli.dispatcher import (
                begin_node_activity,
                end_node_activity,
                ensure_node_session,
            )


            begin_node_activity(app.state, node, connecting=True)


            try:
                session, err = ensure_node_session(app.state.csp_provider, app.state, node)
            except Exception as exc:
                session, err = None, str(exc)
            finally:


                end_node_activity(app.state, node, connecting=True)

            def _finish() -> None:


                self._stop_side_connect_spinner()
                if self._side_node_id != node_id:
                    return
                pane.set_input_locked(False)

                pane.feed_text("\r\x1b[K")
                if session is None:
                    pane.feed_text(f"Connect failed: {err}\r\n")
                    pane.set_prompt("(not connected) ")
                else:
                    pane.feed_text("\x1b[2mConnected.\x1b[0m\r\n")
                    pane.set_prompt(_derive_side_terminal_prompt(pane))


                    ip = node.session.ip_address if node.session else None
                    host = node.session.hostname if node.session else None
                    if ip or host:
                        self._update_side_terminal_title(ip=ip, hostname=host)

            try:
                app.call_from_thread(_finish)
            except Exception:
                pass

        threading.Thread(target=_connect, daemon=True).start()

    def close_side_terminal(self) -> None:
        """Hide the side Connect terminal and return focus to the Nodes table. Public (not `_`-prefixed) since the App-level on_terminal_pane_leave_requested/on_terminal_pane_submitted handlers call this too, on Ctrl-D or exit/.exit typed inside the pane."""
        from .widgets import CredNodeTable, TerminalPane


        self._stop_side_connect_spinner()


        if self._side_node_id is not None:
            try:
                pane = self.query_one(f"#{_SIDE_PANE_ID}", TerminalPane)
                pane.set_input_locked(False)


                self._side_recovery_locked = False
                self._side_pane_cache[self._side_node_id] = (
                    pane.snapshot_state(),
                    time.monotonic(),
                )
            except NoMatches:
                pass
        self._side_node_id = None
        self._side_title_base = "Terminal"
        self._side_title_ip = None
        self._side_title_hostname = None
        try:
            self.query_one("#node-side-terminal").remove_class("-open")
            self.query_one("#node-side-title", PaneTitle).update("Terminal")
        except NoMatches:
            pass
        try:
            self.query_one("#node-table", CredNodeTable).focus()
        except NoMatches:
            pass

    def action_quit_app(self) -> None:
        """'Q' no longer quits outright -- it ARMS the command bar with "quit", so Enter is needed to actually leave. Live testing found an instant, unconfirmed exit from a single keypress too easy to hit by accident mid-demo."""
        from .widgets import NodeStatusLine

        terminal = self._enter_command_bar_mode()
        if terminal is None:


            self.app.exit()
            return
        terminal.clear_current_input()
        terminal.prefill_input("quit")
        try:
            self.query_one("#node-status-line", NodeStatusLine).show_message(
                "Quit armed — press Enter to confirm, Escape to cancel."
            )
        except NoMatches:
            pass


    _TAB_STOPS: tuple[str, ...] = ("node-pane", "node-side-terminal", "info-pane")

    def _focus_pane(self, pane_id: str) -> None:
        """Focus the focusable widget INSIDE a pane container."""
        from .widgets import CredNodeTable, PinnableTabs

        if pane_id == "info-pane":


            self.query_one(PinnableTabs).focus()
        elif pane_id == "node-pane":
            self.query_one("#node-table", CredNodeTable).focus()
        else:
            self.query_one(f"#{_SIDE_PANE_ID}", TerminalPane).focus()

    def action_cycle_focus(self) -> None:
        """Cycle focus across the visible panes with Tab."""
        stops = []
        for pane_id in self._TAB_STOPS:
            try:
                pane = self.query_one(f"#{pane_id}")
            except NoMatches:
                continue
            if pane.display:
                stops.append(pane_id)
        if not stops:
            return


        current = None
        widget = self.app.focused
        while widget is not None:
            wid = getattr(widget, "id", None)
            if wid in stops:
                current = wid
                break
            widget = getattr(widget, "parent", None)


        index = stops.index(current) + 1 if current in stops else 0

        try:
            self._focus_pane(stops[index % len(stops)])
        except NoMatches:
            pass

    def action_focus_command_bar(self) -> None:
        """Enter the one-line command bar with ':' -- a VIEW-tier action."""
        self._enter_command_bar_mode()

    def action_show_help(self) -> None:
        """`?` opens the help overlay (2026-08-12) -- the same text `.help` prints, without having to type it."""
        from .widgets import HelpModal

        dispatcher = getattr(self.app, "_dispatcher", None)
        if dispatcher is None:
            return


        from rich.text import Text as _RichText

        body = _RichText.from_ansi("\n".join(dispatcher.full_help_lines(self.app.state)))
        self.app.push_screen(HelpModal(body))


class CloudShellTUIApp(App):
    """Textual TUI for CloudShell, modeled on the original prompt_toolkit layout."""


    CSS = """
    Screen {
        background: $surface;
    }

    /* Top title bar — bold white on black. Hide the dropdown ○ icon which
       Textual's Header puts in the top-left by default. */
    Header {
        background: black;
        color: white;
        text-style: bold;
        height: 1;
    }
    HeaderIcon {
        display: none;
    }
    HeaderTitle {
        text-style: bold;
        color: white;
    }

    /* Pane titles + footers render their own focus-aware styling inside
       render() — see PaneTitle/PaneFooter classes. CSS only sets layout
       (height / padding); colors live in the Rich Text styles. */
    PaneTitle {
        height: 1;
        padding: 0;
        background: $surface;
    }
    PaneFooter {
        height: 1;
        padding: 0;
        background: $surface;
    }

    /* CLI pane */
    /* CLI pane: FIXED ~80% of screen height (matches original prompt_toolkit
       SplitUi where command_frame had Dimension(weight=65) of middle space).
       The pane hosts a single TerminalPane that owns the entire pyte-backed
       grid: committed history, prompt, and current input render as one
       buffer — matching original SplitUi single-buffer model. */
    #cli-pane {
        height: 80%;
        min-height: 8;
        border: none;
    }
    #cli-terminal {
        height: 1fr;
        padding: 0 1;
        border: none;
        background: $surface;
        /* Pyte handles its own line wrapping at column boundary. Disable
           horizontal overflow so a transient resize doesn't expose a
           horizontal scrollbar — content is always clipped or wrapped. */
        overflow-x: hidden;
    }

    /* Log pane */
    #log-pane {
        height: 1fr;
        min-height: 5;
        border: none;
    }
    #log-output {
        height: 1fr;
        padding: 0 1;
        border: none;
        background: $surface;
        /* Wrap long lines instead of showing a horizontal scrollbar. The
           RichLog widget itself has wrap=True; this rule belt-and-braces
           the layout so a redraw or terminal resize can't expose hscroll. */
        overflow-x: hidden;
    }

    /* Status panel: 4-row dock at the bottom. Rows are not focusable so
       Tab cycles only through CLI input ↔ Log pane. */
    #status-pane {
        dock: bottom;
        height: 5;  /* 1 title + 4 rows */
        border: none;
    }
    /* Padding applies to the data rows only — NOT the PaneTitle.
       Padding the title would shrink its rendered width by 2 cells, making
       its ─── line visibly narrower than the CLI/Log pane titles.
       Status rows are also explicitly not focusable; border:none. */
    #status-cloud, #status-cloudshell, #status-nav, #status-state {
        height: 1;
        padding: 0 1;
        border: none;
    }
    #status-title {
        height: 1;
        padding: 0;
    }

    /* Multi-node layout. Node pane gets the
       majority of vertical space (table is the primary content); info pane
       (log/CSP-log/billing tabs) fills the remainder. min-height on both
       keeps either from collapsing to nothing on a very short terminal. */
    #multi-node-root {
        height: 1fr;
        /* `default` is named explicitly and FIRST: Widget.layer returns
           `styles.layer or "default"`, so every pane that sets no `layer:` of
           its own is on "default" -- omitting it here would leave the panes on
           a layer absent from the declared z-order. #node-side-terminal is the
           only tenant of "terminal", and it draws over them. */
        layers: default terminal;
    }
    /* 3fr/1fr (not 75%/1fr) so the split is computed on the space left
       AFTER #cli-pane's fixed 8 rows are subtracted, not on the full
       container height -- see #multi-node-root #cli-pane's comment. */
    #node-pane {
        height: 3fr;
        min-height: 10;
        border: none;
    }
    #node-body {
        height: 1fr;
    }
    #node-table {
        height: 1fr;
        width: 1fr;
    }
    /* Use one background across the cursor row, including its frozen columns
       and row-number gutter. Textual gives fixed cells and row labels distinct
       cursor classes; without these overrides, the active row is split into
       color bands. The Azure label uses a lighter blue on this selection. */
    #node-table > .datatable--cursor {
        background: #005A96;
    }
    #node-table > .datatable--fixed-cursor,
    #node-table > .datatable--header-cursor {
        background: #005A96;
    }
    /* The row-label hover/cursor state also uses the shared background so
       neither fixed columns nor pointer hover creates a color seam. */
    #node-table > .datatable--header-hover {
        background: #005A96;
    }
    /* Hidden (display: none) until 's' Connect (side) opens it.
       A closed pane costs nothing here -- _arrange() filters on `display`
       before it builds the layers at all.

       An OVERLAY (2026-08-13), not a member of the flow, because the reported
       requirement -- "Terminal always shows full size regardless if Zoom is in
       effect" -- is unsatisfiable in the flow. #node-pane and #info-pane are
       vertical siblings summing to the root's height, so while the Terminal
       lived inside #node-pane, its height was bounded by node-pane's, and zoom
       grows the log by shrinking node-pane to 6 rows. Zoomed, this pane got
       2 rows minus its own title and footer: nothing. Any CSS that keeps the
       Terminal tall keeps the log short. Leaving the flow is the only way out,
       which is what the user proposed by asking for an overlay.

       Consequence accepted deliberately (option (a), chosen 2026-08-13): this
       covers the right 70% of #node-status-line and #node-footer whenever it is
       open. The status line carries the untruncated Identity/Target for the
       cursor row, but that serves the TABLE workflow, and its left 30% stays
       visible. The alternative -- moving the status line up to root level so
       the overlay's region ends where #node-body does -- was declined as a
       bigger restructure for a narrower win. */
    #node-side-terminal {
        layer: terminal;
        dock: right;
        width: 0;
        display: none;
        border-left: solid $accent;
    }
    #node-side-terminal.-open {
        /* User-reported bug: 60 columns was far too narrow to be usable --
           couldn't even see a full command's output on one line. DataTable
           column widths are dynamic/content-based (no fixed pixel boundary
           to target "through the Host column" precisely), so a generous
           percentage of the pane is the practical proxy -- comfortably
           wider than CSP..Host's typical combined width while still
           leaving the table a usable strip on most terminals.

           As an overlay this now COVERS that strip's right 70% instead of
           compressing the table into the left 30%. Same visible left column
           either way: _truncate_middle() in node_table.py truncates to a fixed
           48 chars, not to a measured width, so cell content does not change
           when the table's own width does. */
        width: 70%;
        /* Mirrors #node-pane's 3fr of the root's 3fr/1fr split -- the height
           this pane USED to inherit, so "full size" means the size it always
           had. A literal here rather than something derived from #node-pane,
           because deriving it is what coupled the two in the first place: this
           value must NOT move when zoom changes node-pane's height. That is
           the whole feature, and it is why `.-info-zoom` has no rule for this
           pane. Being a few rows off node-pane's exact bottom edge does not
           matter -- per the overlay note above, nothing has to line up with
           this pane's bottom. */
        height: 75%;
        display: block;
    }
    /* 2 rows: status summary + full untruncated Identity/Target (the table's
       Identity/Target Identity columns are middle-truncated -- see
       node_table.py's _truncate_middle -- so this is where the full text
       for the highlighted row is always visible). */
    /* The Status row sat on $surface -- the same background as the table
       immediately above it, with nothing in between -- so reading down the
       Nodes pane, the untruncated Identity/Target for the cursor row arrived
       looking like one more table row. Two cues rather than one, because a
       background shift alone is easy to miss on a dim terminal: a rule in
       PaneFooter's own grey (#5f6b7a, so the pane is bordered top and bottom
       by the same hand) and a darker surface under it.

       height is 3, not 2: Textual draws the border INSIDE the box, so the two
       content rows need a third for the rule. The zoom heights below count
       this row -- change one, change the other. */
    #node-status-line {
        height: 3;
        padding: 0 1;
        background: $panel;
        border-top: solid #5f6b7a;
    }
    #info-pane {
        height: 1fr;
        min-height: 6;
        border: none;
    }
    /* `z` zoom (VIEW tier, keymap.py): the 3fr/1fr split above is right when
       the work is in the Nodes table, but leaves the Info pane too short to
       read a log in -- the reported problem. Zoomed, the Nodes pane collapses
       to the smallest thing that still answers "which row am I on": the
       DataTable's column-label row + TWO data rows, plus the status line that
       carries the untruncated Identity/Target for the cursor row.

       Two data rows, not one (changed 2026-08-15): one row answers "which row
       am I on" and nothing else, so the cursor had no neighbour to be read
       against. The second row costs the Info pane one line and restores the
       sense of position that a single row cannot carry.

       Heights are fixed rather than fr so the split cannot drift: #node-pane
       is 1 (PaneTitle) + 3 (#node-body) + 3 (#node-status-line, 2 content
       rows + its top rule) + 1 (PaneFooter) = 8, and #info-pane takes the 1fr
       remainder. min-height must be overridden too -- the base rule's
       `min-height: 10` would otherwise silently win and eat rows the Info
       pane was promised.

       No scroll plumbing is needed to keep the cursor row visible: DataTable
       already scrolls to keep its cursor in view.

       #node-side-terminal is deliberately absent from these rules. It is on the
       root's overlay layer, so nothing here reaches it and its height is the
       same zoomed or not -- the requirement. Before that (2026-08-13) it was
       inside #node-body and `height: 2` left it with no rows at all: zooming
       with the Terminal open made the Terminal vanish. */
    #multi-node-root.-info-zoom #node-pane {
        height: 8;
        min-height: 8;
    }
    #multi-node-root.-info-zoom #node-body {
        height: 3;
    }
    #info-tabs-row {
        height: 1fr;
    }
    PinnableTabs {
        width: 1fr;
        height: 100%;
        background: $surface;
    }
    /* Container/RichLog have no border by default. The focused-pane indicator
       is handled by the PaneTitle / PaneFooter color rules above (cyan when
       the parent Container has :focus-within). No border-* rules here, to
       avoid shifting content position when focus changes. */
    Container, RichLog {
        border: none;
    }
    /* Slim grey scrollbars */
    * {
        scrollbar-size-vertical: 1;
        scrollbar-size-horizontal: 1;
        scrollbar-color: gray 60%;
        scrollbar-color-hover: gray;
        scrollbar-color-active: gray;
        scrollbar-background: $surface;
        scrollbar-background-hover: $surface;
        scrollbar-background-active: $surface;
        scrollbar-corner-color: $surface;
    }
    """

    BINDINGS = [


        Binding("ctrl+c", "interrupt_command", "Interrupt", show=False),


        Binding("ctrl+q", "request_exit", "Quit", show=False),


        ("left", "pane_page_up", "Page up"),
        ("right", "pane_page_down", "Page down"),
        ("alt+up", "pane_home", "Top"),
        ("alt+down", "pane_end", "Bottom"),
    ]


    ENABLE_COMMAND_PALETTE = False


    context_info: reactive[Optional[ShellContextInfo]] = reactive(None)

    vi_mode: reactive[str] = reactive("normal")

    is_initializing: reactive[bool] = reactive(True)


    processing_command: reactive[Optional[str]] = reactive(None)


    recovering: reactive[str] = reactive("")

    provisioning: reactive[str] = reactive("")

    def __init__(
        self,
        state: Any,
        csp_label: str = "CSP",
        history_getter: Optional[Callable[[], list[str]]] = None,
        startup_callback: Optional[Callable[[], None]] = None,
        tui_backend: str = "textual",
        multi_node: bool = False,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.state = state
        self.csp_label = csp_label
        self.tui_backend = tui_backend


        self.multi_node = multi_node


        self.title = get_app_name()
        self._history_getter = history_getter or (lambda: [])
        self._startup_callback = startup_callback


        self._pinnable_tabs: Any = None
        self._event_feed_client: Any = None


        self._cli_output_buffer: list[str] = []


        self._billing_poll_timer: Any = None

        self.input_queue: queue.Queue[str] = queue.Queue()
        self._stop_event = threading.Event()


        self._active_remote_commands: dict[str, Any] = {}


        self._dispatcher: Any = None
        self._next_ui_mode: Optional[str] = None
        self._startup_error: Optional[BaseException] = None


        self._in_quit_prompt: bool = False

        self._saved_input_before_quit: str = ""


        self._node_refresh_scheduled: bool = False
        self._node_refresh_lock = threading.Lock()


        self._last_node_refresh_at: float = 0.0


        self._node_refresh_deferred_since: float = 0.0


        self._node_refresh_waiting_on: str = ""


        self._node_refresh_stalls: int = 0


    def _compose_multi_node(self) -> ComposeResult:
        from .widgets import CredNodeTable, NodeStatusLine

        yield Header(show_clock=False)
        with _MultiNodeRoot(id="multi-node-root"):
            with Container(id="node-pane"):


                yield PaneTitle("Credentials", id="node-title")
                with Horizontal(id="node-body"):
                    yield CredNodeTable(id="node-table", cursor_type="row")
                yield NodeStatusLine(id="node-status-line")
                yield PaneFooter(id="node-footer")
            with Container(id="info-pane"):
                yield PaneTitle("Info", id="info-title")
                yield Container(id="info-tabs-row")
                yield PaneFooter(id="info-footer")


            with Container(id="node-side-terminal"):
                yield PaneTitle("Terminal", id="node-side-title")
                yield TerminalPane(id="node-side-terminal-pane", quick_quit=True)
                yield PaneFooter(id="node-side-footer")


        history = self._history_getter()
        yield KeymapFooter(TerminalPane(id="cli-terminal", history=history), id="keymap-footer")

    def _provision_completer(self, line: str, offset: int):
        """Tab-completion for `.provision`, restricted to what the selected credential declares (item 10c)."""
        from cloudbasher.core.provision_grammar import grammar_for

        head = line[:offset]
        words = head.split()


        if not words or words[0].lstrip(".") != "provision":
            return [], offset
        stem = "" if head.endswith(" ") else (words[-1] if words else "")
        replace_from = offset - len(stem)
        csp = mode = kind = ""
        try:
            from .widgets import CredNodeTable

            table = self.query_one("#node-table", CredNodeTable)
            csp = table.cursor_credential_provider()
            mode = table.cursor_credential_mode()
            kind = table.cursor_credential_kind()
        except NoMatches:
            pass
        already = {w for w in words[1:] if w != stem}
        candidates = [
            k
            for k in grammar_for(csp, mode, kind).keywords
            if k.startswith(stem) and k not in already
        ]
        return sorted(candidates), replace_from

    def _wire_cli_terminal(self, terminal) -> None:
        """App-level wiring every mount path owes the CLI pane."""
        terminal.set_completer(self._provision_completer)

    def _push_unmanaged(self, table: Any) -> None:
        """Hand the provider's UNMANAGED rows to the table"""
        provider = getattr(self.state, "csp_provider", None)
        if provider is None:
            return
        try:
            rows = provider.unmanaged_rows(self.state)
            scanned_at, age = provider.unmanaged_meta(self.state)
            table.set_unmanaged(rows, scanned_at=scanned_at, scope=age)
        except Exception:  # noqa: BLE001 - redrawn on the next tick
            pass

    def _on_mount_multi_node(self) -> None:
        from .widgets import CredNodeTable, NodeStatusLine, PinnableTabs

        try:
            self._wire_cli_terminal(self.query_one("#cli-terminal", TerminalPane))
        except NoMatches:
            pass

        table = self.query_one("#node-table", CredNodeTable)
        credentials_by_id = getattr(self.state, "credentials_by_id", {}) or {}
        nodes_by_id = getattr(self.state, "nodes_by_id", {}) or {}
        self._push_unmanaged(table)
        table.reload(credentials_by_id, nodes_by_id)
        table.focus()


        self._sync_chrome_focus(table)
        self._pinnable_tabs = PinnableTabs(
            self.csp_label,
            on_billing_activate=self._start_billing_poll,
            on_billing_deactivate=self._stop_billing_poll,
        )
        self.query_one("#info-tabs-row", Container).mount(self._pinnable_tabs)


        self.state.node_supervisor = NodeSupervisor(self.state)
        self.state.node_supervisor.start()


        if self._startup_callback is not None:


            self._install_multi_node_startup_sinks()
            self.query_one("#node-status-line", NodeStatusLine).show_message(
                "Bootstrapping credentials/session..."
            )
            threading.Thread(target=self._run_startup_multi_node, daemon=True).start()
        else:


            terminal = self.query_one("#cli-terminal", TerminalPane)
            self._write_welcome_banner(terminal)
            terminal.set_prompt(self._derive_prompt_text())
            self._install_multi_node_interactive_sinks()
            threading.Thread(target=self.run_command_worker, daemon=True).start()

    def _run_startup_multi_node(self) -> None:
        """Multi-node counterpart to _run_startup_in_background(): once bootstrap succeeds, arms the global command bar -- swaps console sinks from the Log-tab-only startup routing to out()/eprint() -> CLI terminal, writes the welcome banner + prompt, and starts run_command_worker() -- same split as single-node's on_mount/_run_startup_in_background, just pointed at multi-node's own widgets."""
        from .widgets import NodeStatusLine

        startup_exc: Optional[BaseException] = None
        try:
            self._startup_callback()  # type: ignore[misc]
        except Exception as exc:
            startup_exc = exc
            self._startup_error = exc


            eprint(f"Bootstrap failed: {exc}")
            log(f"[startup] bootstrap FAILED: {type(exc).__name__}: {exc}")


        try:
            self.call_from_thread(self.refresh_node_table, status=True)
        except Exception:
            pass

        if startup_exc is None:


            self._start_aws_event_feed()
        else:


            def _push_error() -> None:
                try:
                    self.query_one("#node-status-line", NodeStatusLine).show_message(
                        f"Bootstrap failed: {startup_exc} — commands still work; "
                        "see the Log tab",
                        is_error=True,
                    )
                except Exception:
                    pass

            try:
                self.call_from_thread(_push_error)
            except Exception:
                pass

        def _arm_command_bar() -> None:
            try:
                terminal = self.query_one("#cli-terminal", TerminalPane)
                self._write_welcome_banner(terminal)


                terminal.set_prompt(self._derive_prompt_text())
                self._install_multi_node_interactive_sinks()
            except Exception:
                pass

        try:
            self.call_from_thread(_arm_command_bar)
        except Exception:
            pass
        threading.Thread(target=self.run_command_worker, daemon=True).start()

    def _first_originating_aws_creds(self) -> tuple[Optional[Any], str]:
        """Return (AwsSessionCreds, region) for the first *originating* AWS CredentialRecord in state.credentials_by_id, or (None, "") if there isn't one or it's missing access/secret key material."""
        from cloudbasher.csp.aws.credentials import signing_creds_from_extra

        credentials_by_id = getattr(self.state, "credentials_by_id", {}) or {}
        aws_record = next(
            (
                rec
                for rec in credentials_by_id.values()
                if rec.provider == "aws" and rec.role == "originating"
            ),
            None,
        )
        if aws_record is None:
            return None, ""

        extra = aws_record.raw.extra if hasattr(aws_record.raw, "extra") else {}
        access_key = extra.get("access_key", "")
        secret_key = extra.get("secret_key", "")
        if not (access_key and secret_key):
            return None, ""


        creds = signing_creds_from_extra(extra)
        region = extra.get("region") or "us-east-1"
        return creds, region

    def _start_aws_event_feed(self) -> None:
        """Start the CloudTrail/EventBridge live-log WebSocket feed backing the multi-node "{AWS} Logs" tab, if configured."""
        try:
            from urllib.parse import urlparse

            from cloudbasher.csp.aws.eventbridge_feed import EventFeedClient

            from ..config import active_config


            ws_url = active_config().get_string("aws.eventbridge_ws_url")
            if not ws_url:
                return

            creds, region = self._first_originating_aws_creds()
            if creds is None:
                return

            parsed = urlparse(ws_url)
            if not parsed.hostname:
                return
            ws_host = parsed.hostname + (f":{parsed.port}" if parsed.port else "")


            host_parts = parsed.hostname.split(".")
            try:
                ws_region = host_parts[host_parts.index("execute-api") + 1]
            except (ValueError, IndexError):
                ws_region = region

            def _on_message(payload: dict) -> None:
                line = _format_cloudtrail_feed_line(payload)
                try:
                    self.call_from_thread(self._append_aws_log_line, line)
                except Exception:
                    pass

            def _on_status(text: str) -> None:
                try:
                    self.call_from_thread(self._append_aws_log_line, f"[{text}]")
                except Exception:
                    pass

            self._event_feed_client = EventFeedClient(
                ws_host=ws_host,
                canonical_uri=parsed.path or "/",
                region=ws_region,
                creds=creds,
                on_message=_on_message,
                on_status=_on_status,
            )
            self._event_feed_client.start()
        except Exception:
            pass

    def _append_aws_log_line(self, line: str) -> None:
        """Push one line to the AWS Logs tab. Must run on the App thread -- see _start_aws_event_feed's on_message/on_status callbacks."""
        pinnable_tabs = self._pinnable_tabs
        if pinnable_tabs is None:
            return
        try:
            pinnable_tabs.append_log_line("AWS", line)
        except Exception:
            pass

    def _start_billing_poll(self, csp: str) -> None:
        """Start the CUR billing fetch+poll for the "{AWS} Billing" tab, wired as PinnableTabs' on_billing_activate callback -- called on the App thread whenever that tab becomes visible."""
        if csp != "AWS":
            return
        try:
            from ..config import active_config

            cfg = active_config()
            bucket = cfg.get_string("aws.cur_bucket_name")
            report_name = cfg.get_string("aws.cur_report_name")
            if not (bucket and report_name):
                return
            prefix = cfg.get_string("aws.cur_s3_prefix")


            cur_region = cfg.get_string("aws.cur_region") or None
            try:
                interval = int(cfg.get_string("aws.billing_poll_interval_seconds") or "900")
            except ValueError:
                interval = 900

            self._fetch_billing_once(csp, bucket, report_name, prefix, cur_region)
            self._stop_billing_poll()
            self._billing_poll_timer = self.set_interval(
                interval,
                lambda: self._fetch_billing_once(csp, bucket, report_name, prefix, cur_region),
            )
        except Exception:
            pass

    def _stop_billing_poll(self) -> None:
        """Stop the CUR billing re-poll timer, if one is running -- wired as PinnableTabs' on_billing_deactivate callback (fires on every switch away from the Billing tab, so must tolerate no timer being active) and also called from on_unmount() for app-teardown cleanup."""
        timer = self._billing_poll_timer
        if timer is None:
            return
        try:
            timer.stop()
        except Exception:
            pass
        self._billing_poll_timer = None

    def _fetch_billing_once(
        self,
        csp: str,
        bucket: str,
        report_name: str,
        prefix: str,
        cur_region: Optional[str] = None,
    ) -> None:
        """Fetch+format one CUR billing summary off the App thread (real S3 GetObject calls -- must not block the UI), then push the rendered text back via call_from_thread. Never raises back into the Timer/ caller -- a fetch failure already renders as an error string inside format_billing_summary()'s own contract; anything else defensive."""

        def _worker() -> None:
            try:
                from cloudbasher.csp.aws.cost_and_usage_report import (
                    fetch_month_to_date_summary,
                    format_billing_summary,
                )

                creds, session_region = self._first_originating_aws_creds()
                if creds is None:
                    return
                summary = fetch_month_to_date_summary(
                    creds,
                    bucket=bucket,
                    report_name=report_name,
                    prefix=prefix,
                    region=cur_region or session_region,
                )
                text = format_billing_summary(summary)
                self.call_from_thread(self._update_billing_body, csp, text)
            except Exception:
                pass

        threading.Thread(target=_worker, daemon=True).start()

    def _update_billing_body(self, csp: str, text: str) -> None:
        """Push one rendered billing summary to the Billing tab. Must run on the App thread -- see _fetch_billing_once's worker above."""
        pinnable_tabs = self._pinnable_tabs
        if pinnable_tabs is None:
            return
        try:
            pinnable_tabs.update_billing(csp, text)
        except Exception:
            pass

    def schedule_node_table_refresh(self) -> None:
        """Coalesced, non-blocking counterpart to ``call_from_thread(self.refresh_node_table)`` -- call this from a background thread instead when many callers may fire in a tight burst (e.g. on_node_change during a large .provision fan-out). Only the first caller in a burst pays the call_from_thread round trip; every other concurrent caller returns immediately. See _node_refresh_scheduled's docstring in __init__ for why this exists."""
        with self._node_refresh_lock:
            if self._node_refresh_scheduled and not self._reclaim_stalled_refresh():


                return
            self._node_refresh_scheduled = True


            self._node_refresh_deferred_since = time.monotonic()
            self._node_refresh_waiting_on = "call_from_thread"
        try:
            self.call_from_thread(self._flush_node_table_refresh)
        except Exception:
            _report_swallowed("schedule_node_table_refresh")
            with self._node_refresh_lock:
                self._node_refresh_scheduled = False
                self._node_refresh_deferred_since = 0.0
                self._node_refresh_waiting_on = ""

    def _flush_node_table_refresh(self) -> None:
        """Runs on the App thread. Clears the pending flag BEFORE refreshing (not after) so a fresh on_node_change arriving while this refresh is in flight schedules a genuine follow-up instead of being dropped."""
        from ..utils.perf_config import get_node_refresh_min_interval_seconds

        interval = get_node_refresh_min_interval_seconds()
        now = time.monotonic()
        elapsed = now - self._last_node_refresh_at
        if interval > 0 and elapsed < interval:

            try:
                self.set_timer(interval - elapsed, self._flush_node_table_refresh)


                with self._node_refresh_lock:
                    self._node_refresh_waiting_on = "timer"
                return
            except Exception:
                _report_swallowed("_flush_node_table_refresh: set_timer")


                pass
        with self._node_refresh_lock:
            self._node_refresh_scheduled = False


            self._node_refresh_deferred_since = 0.0
            self._node_refresh_waiting_on = ""
            recovered = self._node_refresh_stalls
            self._node_refresh_stalls = 0
        if recovered:


            _log_line(
                f"#767: node-table repaint RECOVERED after {recovered} stall "
                f"report(s). The pane is live again."
            )
        self._last_node_refresh_at = now
        self.refresh_node_table()


    _NODE_REFRESH_STALL_SECONDS = 5.0

    def _reclaim_stalled_refresh(self) -> bool:
        """Is the pending repaint LOST, and should this caller take the latch?"""
        since = self._node_refresh_deferred_since
        if not since:


            return False
        stalled = time.monotonic() - since
        if stalled < self._NODE_REFRESH_STALL_SECONDS:
            return False
        self._node_refresh_stalls += 1
        waiting_on = self._node_refresh_waiting_on or "unknown"
        _log_line(
            f"#767: node-table repaint PENDING for {stalled:.1f}s waiting on "
            f"{waiting_on} -- treating it as lost and re-arming "
            f"(stall {self._node_refresh_stalls}). The Nodes pane is stale; "
            "the registry is not."
        )
        return True

    def rescrub_display_surfaces(self) -> None:
        """Re-render every surface that holds text, at the current redaction setting. The other half of `m` -- refresh_node_table() covers the Nodes-table cells, this covers everything that scrolls."""
        from .widgets import PinnableTabs, TerminalPane

        for pane in self.query(TerminalPane):
            try:
                pane.rescrub()
            except Exception:


                pass
        try:
            self.query_one(PinnableTabs).rescrub_logs()
        except (NoMatches, ScreenStackError):
            pass

    def refresh_node_table(self, *, status: bool = False) -> None:
        """Re-render the Nodes table from the current state.credentials_by_id/ nodes_by_id. Must run on the App thread -- callers on a background thread (bootstrap, off-thread identity resolution in tui_mode.py's _resolve_and_push_identity) go through call_from_thread()."""
        from .widgets import CredNodeTable, NodeStatusLine

        try:
            table = self.query_one("#node-table", CredNodeTable)
            credentials_by_id = getattr(self.state, "credentials_by_id", {}) or {}
            nodes_by_id = getattr(self.state, "nodes_by_id", {}) or {}


            self._push_unmanaged(table)
            table.reload(credentials_by_id, nodes_by_id)
            self.recovering = _recovering_summary(nodes_by_id)
            self.provisioning = _provisioning_summary(nodes_by_id)


            try:
                self.query_one(
                    "#multi-node-root", _MultiNodeRoot
                )._sync_side_terminal_recovery_lock(nodes_by_id)
            except NoMatches:
                pass


            try:
                from ..utils.redact import is_redaction_enabled
                from .widgets.node_table import (
                    _originating_count,
                    view_pane_title,
                )


                self.query_one("#node-title", PaneTitle).update(
                    view_pane_title(
                        getattr(table, "_view_mode", "tree"),
                        len(nodes_by_id),
                        _originating_count(credentials_by_id),
                        redacted=is_redaction_enabled(),
                        unmanaged_count=table.unmanaged_row_count(),
                        unmanaged_age=getattr(table, "_unmanaged_scope", ""),
                    )
                )
            except Exception:
                pass
            if status:


                action_msg = getattr(self.state, "last_node_action_message", None)
                if action_msg:
                    self.state.last_node_action_message = None
                    ready_msg = f"{action_msg} · {len(nodes_by_id)} node(s) remain."
                else:
                    ready_msg = f"Ready — {len(nodes_by_id)} node(s)."
                if not nodes_by_id:


                    ready_msg += " Run .provision/.register to add one."
                self.query_one("#node-status-line", NodeStatusLine).show_message(ready_msg)
        except Exception:


            _report_swallowed("refresh_node_table")

    def _install_multi_node_startup_sinks(self) -> None:
        """Route out()/eprint()/log()/detail() to the Info pane's "Log" tab (full scrollable history, via PinnableTabs.append_console_line()) during bootstrap, before the global command bar exists to take over out()/eprint() -- see _install_multi_node_interactive_sinks, called once bootstrap succeeds (_run_startup_multi_node), which is multi-node's counterpart to single-node's startup->interactive sink swap. Until then, log()/detail() keep going to the Log tab always."""

        def to_status(text: str) -> None:
            def _push() -> None:
                pinnable_tabs = self._pinnable_tabs
                if pinnable_tabs is not None:
                    try:
                        pinnable_tabs.append_console_line(text)
                    except Exception:
                        pass

            try:
                self.call_from_thread(_push)
            except Exception:
                try:
                    _push()
                except Exception:
                    pass


        set_console_output_sinks(
            out_sink=to_status,
            err_sink=to_status,
            detail_sink=to_status,
            redacts_at_render=True,
        )

    def _install_multi_node_interactive_sinks(self) -> None:
        """After bootstrap: out()/eprint() -> buffered, flushed into the Info pane's "Log" tab once the command finishes; log()/detail() stay routed there too, unbuffered. Multi-node counterpart to single-node's _install_interactive_sinks -- can't reuse that one directly, since it hardcodes #log-output (a RichLog), which doesn't exist in the multi-node layout (the Log tab is a PinnableTabs child instead)."""

        def to_cli(text: str) -> None:


            buffer = self._cli_output_buffer
            if buffer and not buffer[-1].endswith(("\n", "\r")):
                buffer.append("\n")
            buffer.append(text)


            self._schedule_cli_flush()

        def to_log(text: str) -> None:
            def _push() -> None:
                pinnable_tabs = self._pinnable_tabs
                if pinnable_tabs is not None:
                    try:
                        pinnable_tabs.append_console_line(text)
                    except Exception:
                        pass

            try:
                self.call_from_thread(_push)
            except Exception:
                try:
                    _push()
                except Exception:
                    pass


        set_console_output_sinks(
            out_sink=to_cli, err_sink=to_cli, detail_sink=to_log, redacts_at_render=True
        )

    def _schedule_cli_flush(self) -> None:
        """Flush the buffer on the App thread, from wherever this was called."""
        try:
            self.call_from_thread(self._flush_cli_output_buffer)
        except Exception:
            try:
                self._flush_cli_output_buffer()
            except Exception:
                pass

    def _flush_cli_output_buffer(self) -> None:
        """Write the command bar's buffered out()/eprint() text (see `_install_multi_node_interactive_sinks`' `to_cli()`) into the Log tab as ONE call, then clear the buffer. Called from `run_command_worker()`'s `finally` block, via `call_from_thread()` since it touches the widget tree -- a no-op if nothing was buffered (most dot-commands don't call out()/eprint() at all)."""
        if not self._cli_output_buffer:
            return
        text = "".join(self._cli_output_buffer)
        self._cli_output_buffer = []
        pinnable_tabs = self._pinnable_tabs
        if pinnable_tabs is not None:
            try:
                pinnable_tabs.append_console_line(text)
            except Exception:
                pass


    def compose(self) -> ComposeResult:
        if self.multi_node:
            yield from self._compose_multi_node()
            return

        yield Header(show_clock=False)


        with Container(id="cli-pane"):
            yield PaneTitle("CLI 1/1", id="cli-title")
            history = self._history_getter()
            yield TerminalPane(id="cli-terminal", history=history)
            yield PaneFooter(id="cli-footer")

        with Container(id="log-pane"):
            yield PaneTitle("Log 0/0", id="log-title")
            yield OutputPane(id="log-output", wrap=True, markup=False, auto_scroll=True)
            yield PaneFooter(id="log-footer")

        with Container(id="status-pane"):


            yield PaneTitle("Status", id="status-title", title_width=14)
            header_row = HeaderBar(id="status-cloud")
            header_row.csp_label = self.csp_label
            yield header_row
            yield CloudShellRow(id="status-cloudshell")
            yield NavigationRow(id="status-nav")
            yield StatusBar(id="status-state")

    def on_mount(self) -> None:
        if self.multi_node:
            self._on_mount_multi_node()
            return


        self._sync_status_widgets()


        self._install_startup_sinks()

        terminal = self.query_one("#cli-terminal", TerminalPane)
        self._wire_cli_terminal(terminal)

        if self._startup_callback is not None:


            terminal.feed_text("\x1b[1mInitializing...\x1b[0m\r\n")
        else:

            self._write_welcome_banner(terminal)


        terminal.focus()


        self._sync_chrome_focus(terminal)


        self.set_interval(0.25, self._refresh_pane_titles)

        self._refresh_pane_titles()


        if self._startup_callback is not None:
            threading.Thread(target=self._run_startup_in_background, daemon=True).start()
        else:


            self.is_initializing = False
            self._install_interactive_sinks()
            terminal.set_prompt(f"{get_prompt_text()} ")
            threading.Thread(target=self.run_command_worker, daemon=True).start()

    def _write_welcome_banner(self, terminal: TerminalPane) -> None:
        """Write the welcome help line into the CLI pane."""
        terminal.feed_text(
            "\x1b[2mType .help for commands, exit/quit (or Ctrl-D) to leave. "
            "PageUp/PageDown to scroll output."
            "\x1b[0m\r\n"
        )


        nodes_by_id = getattr(self.state, "nodes_by_id", {}) or {}
        if not nodes_by_id:
            terminal.feed_text(
                "\x1b[2mNo nodes registered yet -- run .provision (create + connect) "
                "or .register (attach to something that already exists).\x1b[0m\r\n"
            )

    def _run_startup_in_background(self) -> None:
        """Run the startup callback off-thread, then start the worker on success."""
        try:
            self._startup_callback()  # type: ignore[misc]
        except Exception as exc:
            self._startup_error = exc


            message = f"\n[!] Bootstrap failed: {exc}"

            def _push_error() -> None:
                try:
                    log_pane = self.query_one("#log-output", RichLog)
                    log_pane.write(Text(message, style="bold red"))
                    log_pane.write(Text("[!] Press Ctrl-D or Ctrl-C to leave.", style="dim"))
                except Exception:
                    pass

            try:
                self.call_from_thread(_push_error)
            except Exception:
                pass
            return


        try:
            self.call_from_thread(self._install_interactive_sinks)
            self.call_from_thread(self._post_bootstrap_banner)
            self.call_from_thread(self._issue_prompt)
            self.call_from_thread(setattr, self, "is_initializing", False)
        except Exception:
            pass
        threading.Thread(target=self.run_command_worker, daemon=True).start()

    def _post_bootstrap_banner(self) -> None:
        """Called from the App thread after bootstrap to write the banner."""
        try:
            terminal = self.query_one("#cli-terminal", TerminalPane)
            self._write_welcome_banner(terminal)
        except Exception:
            pass

    def on_unmount(self) -> None:
        set_console_output_sinks()


        if self._event_feed_client is not None:
            try:
                self._event_feed_client.stop()
            except Exception:
                pass
        self._stop_billing_poll()


    def _install_startup_sinks(self) -> None:
        """During bootstrap, route everything to the Log pane."""
        log_pane = self.query_one("#log-output", RichLog)

        def to_log(text: str) -> None:
            try:
                self.call_from_thread(log_pane.write, Text.from_ansi(text))
            except Exception:
                try:
                    log_pane.write(Text.from_ansi(text))
                except Exception:
                    pass

        set_console_output_sinks(out_sink=to_log, err_sink=to_log, detail_sink=to_log)

    def _install_interactive_sinks(self) -> None:
        """After bootstrap: out()/eprint() → CLI TerminalPane, log()/detail() → Log pane."""
        terminal = self.query_one("#cli-terminal", TerminalPane)
        log_pane = self.query_one("#log-output", RichLog)

        def to_cli(text: str) -> None:
            normalized = text.replace("\r\n", "\n").replace("\n", "\r\n")
            if not normalized.endswith("\r\n"):
                normalized += "\r\n"
            try:
                self.call_from_thread(terminal.feed_text, normalized)
            except Exception:
                try:
                    terminal.feed_text(normalized)
                except Exception:
                    pass

        def to_log(text: str) -> None:


            rendered = redact_text(text)
            try:
                self.call_from_thread(log_pane.write, Text.from_ansi(rendered))
            except Exception:
                try:
                    log_pane.write(Text.from_ansi(rendered))
                except Exception:
                    pass

        set_console_output_sinks(
            out_sink=to_cli, err_sink=to_cli, detail_sink=to_log, redacts_at_render=True
        )


    def _sync_status_widgets(self) -> None:
        """Push current reactive state into mounted status-row widgets."""
        try:
            cloud = self.query_one("#status-cloud", HeaderBar)
            cloud.context_info = self.context_info
            cloud.csp_label = self.csp_label
            self.query_one("#status-cloudshell", CloudShellRow).context_info = self.context_info
            state_row = self.query_one("#status-state", StatusBar)
            state_row.vi_mode = self.vi_mode
            state_row.is_initializing = self.is_initializing
            state_row.processing_command = self.processing_command
            state_row.recovering = self.recovering
            state_row.provisioning = self.provisioning
            state_row.tui_backend = _STATUS_BACKEND_LABEL.get(self.tui_backend, self.tui_backend)
        except (NoMatches, ScreenStackError):
            pass

    def watch_context_info(self, value: Optional[ShellContextInfo]) -> None:


        try:
            self.query_one("#status-cloud", HeaderBar).context_info = value
            self.query_one("#status-cloudshell", CloudShellRow).context_info = value
        except (NoMatches, ScreenStackError):
            pass

    def watch_vi_mode(self, value: str) -> None:
        try:
            self.query_one("#status-state", StatusBar).vi_mode = value
        except (NoMatches, ScreenStackError):
            pass

    def watch_is_initializing(self, value: bool) -> None:
        try:
            self.query_one("#status-state", StatusBar).is_initializing = value
        except (NoMatches, ScreenStackError):
            pass

    def watch_processing_command(self, value: Optional[str]) -> None:
        """Mirror to the State row + CLI pane title."""
        try:
            self.query_one("#status-state", StatusBar).processing_command = value
        except (NoMatches, ScreenStackError):
            pass
        self._refresh_pane_titles()

    def watch_recovering(self, value: str) -> None:
        try:
            self.query_one("#status-state", StatusBar).recovering = value
        except (NoMatches, ScreenStackError):
            pass

    def watch_provisioning(self, value: str) -> None:
        try:
            self.query_one("#status-state", StatusBar).provisioning = value
        except (NoMatches, ScreenStackError):
            pass


    def on_descendant_focus(self, event) -> None:
        self._sync_chrome_focus(event.widget)

    def on_descendant_blur(self, event) -> None:


        self._sync_chrome_focus(self.focused)

    def _sync_chrome_focus(self, focused_widget) -> None:
        """Mirror app focus state onto the chrome `focused` reactives."""
        from textual.css.query import NoMatches

        if self.multi_node:


            panes = {
                "node-pane": "node",
                "info-pane": "info",
                "node-side-terminal": "node-side",
            }
        else:
            panes = {"cli-pane": "cli", "log-pane": "log"}

        focused_key = None
        widget = focused_widget
        while widget is not None:
            wid = getattr(widget, "id", None)
            if wid in panes:
                focused_key = panes[wid]
                break
            widget = getattr(widget, "parent", None)

        try:
            for key in panes.values():
                is_focused = key == focused_key
                self.query_one(f"#{key}-title", PaneTitle).focused = is_focused
                self.query_one(f"#{key}-footer", PaneFooter).focused = is_focused
        except NoMatches:
            pass

        if self.multi_node and focused_key is not None:
            try:
                self.query_one("#keymap-footer", KeymapFooter).active_pane = focused_key
            except NoMatches:
                pass

    def _refresh_pane_titles(self) -> None:
        """Update CLI/Log pane titles with current line counts and processing state."""
        from textual.css.query import NoMatches


        if not self.multi_node:
            try:
                cli_title = self.query_one("#cli-title", PaneTitle)
                terminal = self.query_one("#cli-terminal", TerminalPane)
                history = terminal._screen.history
                rows = terminal._screen.lines
                total = max(len(history.top) + len(history.bottom) + rows, 1)
                current = min(len(history.top) + rows, total)
                text = f"CLI {current}/{total}"
                if self.processing_command:

                    cmd = self.processing_command
                    if len(cmd) > 40:
                        cmd = cmd[:37] + "..."
                    text += f"  —  Processing: {cmd}"
                cli_title.update(text)
            except NoMatches:
                pass


        try:
            log_log = self.query_one("#log-output", RichLog)
            log_title = self.query_one("#log-title", PaneTitle)
            total = max(len(log_log.lines), 1)
            current = self._visible_bottom_line(log_log, total)
            log_title.update(f"Log {current}/{total}")
        except NoMatches:
            pass


        if self.multi_node:
            try:
                root = self.query_one("#multi-node-root", _MultiNodeRoot)
                if root._side_node_id is not None:
                    root._update_side_terminal_title()
            except NoMatches:
                pass

    def _sync_cli_bar_rows(self) -> None:
        """Grow the one-line command bar up to `_CLI_BAR_MAX_ROWS` when the current prompt+input would otherwise wrap, so pyte's own autowrap never has to scroll the prompt row into history (the exact corruption TerminalPane.resize_rows()'s docstring describes). Runs on a 100ms poll rather than hooking every keystroke -- same granularity `_refresh_pane_titles` already uses successfully for CLI/Log line-count updates, and it avoids adding a second event path into TerminalPane's own key handling. Shrinking back to 1 row happens immediately on submit instead (see `on_terminal_pane_submitted`), not via this poll -- waiting up to 100ms to visibly collapse after Enter would look laggy."""
        try:
            terminal = self.query_one("#cli-terminal", TerminalPane)
        except NoMatches:
            return
        if not terminal.has_class("-open"):
            return
        columns = max(terminal.size.width, 1)
        content_len = len(terminal.current_prompt_text()) + len(terminal.current_input_line())
        needed = min(max(1, -(-content_len // columns)), _CLI_BAR_MAX_ROWS)
        if needed != terminal._screen.lines:
            terminal.resize_rows(needed)

    @staticmethod
    def _visible_bottom_line(richlog: RichLog, total: int) -> int:
        """Return the line index visible at the bottom of the viewport."""
        try:
            scroll_y = int(richlog.scroll_offset.y)
            view_h = max(int(richlog.size.height), 1)
            bottom = scroll_y + view_h
            return max(1, min(bottom, total))
        except Exception:
            return total


    def get_cli_pane(self):
        """Return the CLI TerminalPane (pyte-backed grid for prompt/input/output)."""
        return self.query_one("#cli-terminal", TerminalPane)

    def get_log_pane(self):
        """Return the Log OutputPane (where bootstrap/debug messages appear)."""
        return self.query_one("#log-output", OutputPane)

    def get_status_rows(self) -> dict[str, Any]:
        """Return the four Status panel row widgets keyed by name."""
        return {
            "cloud": self.query_one("#status-cloud", HeaderBar),
            "cloudshell": self.query_one("#status-cloudshell", CloudShellRow),
            "navigation": self.query_one("#status-nav", NavigationRow),
            "state": self.query_one("#status-state", StatusBar),
        }

    async def wait_ready(self, *, timeout_s: float = 5.0) -> bool:
        """Block until the app finishes initializing (bootstrap done)."""
        import asyncio as _asyncio

        start = time.time()
        while self.is_initializing:
            if time.time() - start > timeout_s:
                return False
            await _asyncio.sleep(0.05)
        return True

    def _append_cli_history(self, line: str) -> None:
        """Feed a submitted line into the CLI pane's own up/down history."""
        try:
            terminal = self.query_one("#cli-terminal", TerminalPane)
            terminal.append_history(line)
        except (NoMatches, ScreenStackError):
            pass

    def _issue_prompt(self, prompt_text: Optional[str] = None) -> None:
        """Arm the next interactive prompt on the TerminalPane."""
        self._sync_shell_context_to_status_row()
        if prompt_text is None:
            prompt_text = self._derive_prompt_text()
        try:
            terminal = self.query_one("#cli-terminal", TerminalPane)
            terminal.set_prompt(prompt_text)
        except (NoMatches, ScreenStackError):


            pass

    def _sync_shell_context_to_status_row(self) -> None:
        """Push shell-mode user/ip/host into the CloudShell status row."""
        current = self.context_info or ShellContextInfo()
        new_ctx = current.with_shell_fields_from(self.state)
        if new_ctx is not current:
            self.context_info = new_ctx

    def _derive_prompt_text(self) -> str:
        """Return the right prompt text for the current mode."""
        if self.multi_node:
            return ": "
        if getattr(self.state, "in_shell_mode", False):
            session = getattr(self.state, "_session_obj", None)
            captured = display_prompt(session) if session else None
            if captured:
                return f"{captured} "
            return "$ "

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        history_len = 0
        try:
            hist = self._history_getter() or []
            history_len = len(hist)
        except Exception:
            pass
        prompt_index = history_len + 1
        return f"[{ts}][{prompt_index}]:{get_prompt_text()} "

    def exit_app(self, next_mode: Optional[str] = None) -> None:
        self._next_ui_mode = next_mode
        self._stop_event.set()
        self.exit()


    def _focused_scrollable(self) -> Optional[Any]:
        """Return the focused widget if it's scrollable, else the log RichLog."""
        focused = self.focused
        if isinstance(focused, RichLog):
            return focused

        try:
            return self.query_one("#log-output", RichLog)
        except Exception:
            return None

    def action_pane_page_up(self) -> None:
        target = self._focused_scrollable()
        if target is not None:
            target.action_page_up()

    def action_pane_page_down(self) -> None:
        target = self._focused_scrollable()
        if target is not None:
            target.action_page_down()

    def action_pane_home(self) -> None:
        target = self._focused_scrollable()
        if target is not None:
            target.scroll_home(animate=False)

    def action_pane_end(self) -> None:
        target = self._focused_scrollable()
        if target is not None:
            target.scroll_end(animate=False)

    def begin_confirm_prompt(self, question: str) -> None:
        """Show a pending `[Y/n]` question AS THE PROMPT, so it can be answered."""
        if self.multi_node:
            try:
                self.query_one("#multi-node-root", _MultiNodeRoot)._enter_command_bar_mode()
            except Exception:
                pass
        try:
            terminal = self.query_one("#cli-terminal", TerminalPane)
            terminal.clear_current_input()
            terminal.set_prompt(f"{question} ")
            terminal.enter_insert_mode()
            terminal.focus()
        except Exception:
            pass

    def action_request_exit(self) -> None:
        """Begin an inline 'quit [Y/n]' prompt — matches original prompt_toolkit."""

        if self._startup_error is not None:
            self.exit_app()
            return


        if self._in_quit_prompt:
            return


        if self.multi_node:
            try:
                self.query_one("#multi-node-root", _MultiNodeRoot)._enter_command_bar_mode()
            except Exception:
                pass

        try:
            terminal = self.query_one("#cli-terminal", TerminalPane)
            self._saved_input_before_quit = terminal.current_input_line()
            terminal.clear_current_input()
            terminal.feed_text("\r\n")
            terminal.set_prompt("quit [Y/n] ")
            terminal.set_quiet_signals(True)
        except Exception:
            self._saved_input_before_quit = ""

        self._in_quit_prompt = True

    def _exit_quit_prompt(self, *, confirmed: bool) -> None:
        """Tear down the inline quit prompt; restore the prompt for the current mode. Bug regression: previously hardcoded 'csr> ' which broke shell-mode context — Ctrl-D + 'n' from inside `.command` appeared to drop the user back to top-level dispatcher mode."""
        self._in_quit_prompt = False
        try:
            terminal = self.query_one("#cli-terminal", TerminalPane)
            terminal.set_quiet_signals(False)
            if not confirmed:
                terminal.set_prompt(self._derive_prompt_text())
                if self._saved_input_before_quit:
                    terminal.prefill_input(self._saved_input_before_quit)
        except Exception:
            pass
        self._saved_input_before_quit = ""
        if not confirmed and self.multi_node:


            try:
                self.query_one("#multi-node-root", _MultiNodeRoot)._exit_command_bar_mode()
            except Exception:
                pass
        if confirmed:
            self.exit_app()


    async def on_terminal_pane_submitted(self, event: TerminalPane.Submitted) -> None:
        """User pressed Enter inside the TerminalPane. Route to worker."""
        line = event.value


        if self.multi_node and event.control is not None and event.control.id == _SIDE_PANE_ID:
            self._handle_side_terminal_submitted(line)
            return


        if self._in_quit_prompt:
            confirmed = is_quit_confirmed(line)
            self._exit_quit_prompt(confirmed=confirmed)
            return


        if self.multi_node and event.control is not None and event.control.id == _CLI_PANE_ID:
            pinnable_tabs = self._pinnable_tabs
            if pinnable_tabs is not None:
                try:
                    pinnable_tabs.activate_log_tab()
                except Exception:
                    pass
            try:
                self.query_one("#multi-node-root", _MultiNodeRoot)._exit_command_bar_mode()
            except NoMatches:
                pass


        self.input_queue.put(line)

    def _leave_surface(self, pane_id: str | None) -> None:
        """Leave the surface ``pane_id`` names -- the one verb this action has."""


        if not self.multi_node:
            return
        try:
            root = self.query_one("#multi-node-root", _MultiNodeRoot)
        except (NoMatches, ScreenStackError):


            return
        if pane_id == _SIDE_PANE_ID:
            root.close_side_terminal()
        elif pane_id == _CLI_PANE_ID:
            root._exit_command_bar_mode(cancelled=True)

    async def on_terminal_pane_leave_requested(self, event: TerminalPane.LeaveRequested) -> None:
        """`Ctrl-D` on an empty line: leave THIS surface, never the program."""
        self._leave_surface(event.control.id if event.control is not None else None)

    async def on_terminal_pane_scroll_position_changed(
        self, event: TerminalPane.ScrollPositionChanged
    ) -> None:
        """Refresh viewport counters immediately after terminal paging."""
        pane = event.control
        if pane is not None and pane.id == _SIDE_PANE_ID:
            try:
                self.query_one("#multi-node-root", _MultiNodeRoot)._update_side_terminal_title()
            except (NoMatches, ScreenStackError):
                pass
        else:
            self._refresh_pane_titles()

    def action_interrupt_command(self) -> None:
        """Ctrl-C with no TerminalPane focused -- the runaway case."""
        self._interrupt_or(self._help_quit_fallback)

    def _background_activity(self) -> tuple[int, int]:
        """`(live background loops, nodes whose heartbeat is retrying)`."""
        loops = 0
        retrying = 0
        state = getattr(self, "state", None)
        for node in list(getattr(state, "nodes_by_id", {}).values()):


            loops += len(node.live_background_loops())
            if getattr(node, "_heartbeat_retry_count", 0) > 0:
                retrying += 1


        if state is not None and state.unowned_singleton_heartbeat() is not None:
            loops += 1
        return loops, retrying

    def _help_quit_fallback(self) -> None:
        """Ctrl-C with nothing dispatched: say what IS running, or fall back."""
        loops, retrying = self._background_activity()
        if loops:
            detail = f"{loops} background keepalive loop(s) still running"
            if retrying:
                detail += f", {retrying} node(s) with a retrying heartbeat"
            eprint(
                f"Nothing to cancel -- no command is running. {detail}. "
                "Ctrl-C cancels a COMMAND; it does not stop keepalive. "
                "Use `.disconnect ALL` to stand the fleet down (local only, "
                "no cloud call; `.connect` brings it back)."
            )
            return


        eprint("Nothing to cancel -- no command is running.")

    def _interrupt_or(self, otherwise: Callable[[], None]) -> bool:
        """Cancel the running command, or run `otherwise`. True if cancelled."""
        from cloudbasher.core.cancel import request_cancel

        cancelled, message = request_cancel()
        if message:


            eprint(message)
        if not cancelled and not message:
            otherwise()
            return False
        return cancelled

    async def on_terminal_pane_clear_requested(self, event: TerminalPane.ClearRequested) -> None:
        """User pressed Ctrl-C with the TerminalPane focused."""
        if self._in_quit_prompt:
            return
        pane_id = event.control.id if event.control is not None else ""
        remote_session = self._active_remote_commands.get(pane_id)
        if remote_session is not None:
            try:
                request_interrupt = getattr(remote_session, "request_shell_interrupt", None)
                if request_interrupt is not None:
                    request_interrupt(grace_seconds=5.0)
                else:
                    remote_session.interrupt_shell_command()
            except Exception as exc:
                eprint(f"Remote Ctrl-C could not be sent; command may still be running: {exc}")
            else:
                eprint(
                    "Sent Ctrl-C to the remote shell; waiting up to 5 seconds for completion. "
                    "If it does not respond, the command outcome will be unknown and the "
                    "session should be reconnected before retrying."
                )


            return

        event.control.echo_ctrl_c()


        self._interrupt_or(lambda: None)
        if self.multi_node and event.control is not None and event.control.id == _SIDE_PANE_ID:
            return
        self._issue_prompt()

    async def on_terminal_pane_escape_at_normal(self, event: TerminalPane.EscapeAtNormal) -> None:
        """Handle a redundant Escape pressed while already in vi normal mode."""


        pane_id = event.control.id if event.control is not None else None
        if pane_id == _CLI_PANE_ID:
            self._leave_surface(pane_id)

    def _handle_side_terminal_submitted(self, line: str) -> None:
        """Execute one line against the side-connected node's own session, mirroring _route_line's shape but scoped to that node instead of the primary session. Raw shell always works; a subset of single-node dot-commands work too via _dispatch_for_node (_MULTI_NODE_GLOBAL_ONLY_COMMANDS stays exclusive to the main CLI pane). Runs on a one-shot background thread -- unlike the global pane, there's no persistent per-node worker/queue."""
        from .widgets import TerminalPane

        try:
            root = self.query_one("#multi-node-root", _MultiNodeRoot)
            pane = self.query_one(f"#{_SIDE_PANE_ID}", TerminalPane)
        except NoMatches:
            return
        node_id = root._side_node_id
        stripped = line.strip()


        if stripped in SURFACE_EXIT_COMMANDS:
            root.close_side_terminal()
            return
        if stripped in APP_QUIT_COMMANDS:
            self.action_request_exit()
            return

        node = self.state.nodes_by_id.get(node_id) if node_id else None
        if node is None:
            pane.feed_text("Not connected.\r\n")
            pane.set_prompt("(not connected) ")
            return


        from ..cli.dispatcher import session_busy_reason

        busy = session_busy_reason(node)
        if busy is not None:
            pane.feed_text(f"Busy: {busy}.\r\n")
            pane.set_prompt(_derive_side_terminal_prompt(pane))
            return


        sess = getattr(node, "session", None)
        if sess is not None:
            pane.set_redact_literals(
                tuple(
                    (value, field_type)
                    for value, field_type in (
                        (getattr(sess, "hostname", None), "hostname"),
                        (getattr(sess, "ip_address", None), "ip"),
                    )
                    if value
                )
            )

        def _run() -> None:
            remote_shell = False
            try:
                if stripped.startswith("."):
                    cmd_name = stripped.split()[0]
                    if cmd_name in _MULTI_NODE_GLOBAL_ONLY_COMMANDS:
                        output = f"{cmd_name} is not available here; use the main CLI pane.\r\n"
                    else:
                        output = self._dispatch_for_node(node, stripped)
                else:


                    from ..cli.dispatcher import ensure_node_session

                    session, err = ensure_node_session(self.state.csp_provider, self.state, node)
                    if session is None:
                        output = f"Error: {err or 'no live session'}\r\n"
                    else:
                        remote_shell = True
                        self._active_remote_commands[_SIDE_PANE_ID] = session
                        raw_out = session.exec_command(
                            stripped, raw=True, record_history=True
                        )
                        rendered = render_pty_output(
                            raw_out,
                            stripped,
                            command_echo_present=getattr(
                                session, "raw_exec_output_has_command_echo", True
                            ),
                            framed_output=(
                                getattr(session, "raw_exec_output_is_framed", False) is True
                            ),
                        )


                        output = (rendered + "\r\n") if rendered else ""
                node.mark_activity()
            except Exception as exc:
                output = f"Error: {exc}\r\n"

            def _finish() -> None:
                if remote_shell:
                    self._active_remote_commands.pop(_SIDE_PANE_ID, None)
                if root._side_node_id != node_id:
                    return
                if output:


                    normalized = output.replace("\r\n", "\n").replace("\n", "\r\n")
                    pane.feed_text(normalized)
                pane.append_history(stripped)
                pane.set_prompt(_derive_side_terminal_prompt(pane))

            try:
                self.call_from_thread(_finish)
            except Exception:
                pass

        threading.Thread(target=_run, daemon=True).start()

    def _dispatch_for_node(self, node: Any, line: str) -> str:
        """2/4p-3: run a single-node dot-command against `node`'s own session/api_client/credentials instead of the primary session (_node_dispatch_context), capturing its out()/eprint() output into a string instead of the global CLI pane's sink -- both swaps are restored immediately after; dispatch() runs synchronously and interactive typing paces commands one at a time, so there's no overlap to worry about. Called from a background thread (see _handle_side_terminal_submitted) -- the sink restore goes through call_from_thread since it touches the widget tree."""
        from ..cli.dispatcher import CommandDispatcher
        from ..utils.output import set_console_output_sinks

        captured: list[str] = []


        set_console_output_sinks(
            out_sink=captured.append,
            err_sink=captured.append,
            detail_sink=None,
            redacts_at_render=True,
        )
        try:
            dispatcher = CommandDispatcher(self.state.csp_provider)
            self.state.csp_provider.register_dot_commands(dispatcher)
            with _node_dispatch_context(self.state, node):
                dispatcher.dispatch(line, self.state)
        finally:
            try:
                self.call_from_thread(self._install_multi_node_interactive_sinks)
            except Exception:
                set_console_output_sinks()
        if not captured:
            return ""
        return "\r\n".join(captured) + "\r\n"

    def on_terminal_pane_mode_changed(self, event: TerminalPane.ModeChanged) -> None:
        """Mirror the TerminalPane's vi-mode label into the `vi_mode` reactive — pre-existing plumbing (see StatusBar.render()) that was wired all the way to the status bar but never driven by anything until Bug #3 added vi modal editing to TerminalPane."""
        self.vi_mode = event.label

    def on_cred_node_table_selection_changed(self, event: "CredNodeTable.SelectionChanged") -> None:
        """Mirror the table's multi-select into InteractiveState -- the .bulk dot-command only ever sees `state`, never the widget tree."""
        self.state.selected_node_ids = event.selected_ids


        self.state.selected_credential_ids = event.credential_ids


        self.state.selected_finding_ids = event.finding_ids

    def on_cred_node_table_selection_refused(self, event: "CredNodeTable.SelectionRefused") -> None:
        """Surface a selection gesture that could not act."""
        from .widgets import NodeStatusLine

        try:
            self.query_one("#node-status-line", NodeStatusLine).show_message(event.reason)
        except NoMatches:
            pass

    def on_cred_node_table_cursor_credential_changed(
        self, event: "CredNodeTable.CursorCredentialChanged"
    ) -> None:
        """Mirror the cursor's credential into InteractiveState, so a bare `.provision` can mean "the one I am pointing at" -- the same thing `p` means. Same shape as SelectionChanged above: the dot-command only ever sees `state`, never the widget tree."""
        self.state.cursor_credential_id = event.credential_id

    def on_cred_node_table_visible_order_changed(
        self, event: "CredNodeTable.VisibleOrderChanged"
    ) -> None:
        """Mirror the table's current row order into InteractiveState (Phase A) -- resolve_node_selector()'s row-number ranges ("1-3") only ever see `state`, never the widget tree."""
        self.state.visible_row_node_ids = event.row_node_ids

    def _discard_armed_state(self) -> None:
        """App-thread bridge to _MultiNodeRoot.discard_armed_state(ran=True) for the command worker, which runs on a background thread and so can only reach the widget tree via call_from_thread."""
        try:
            self.query_one("#multi-node-root", _MultiNodeRoot).discard_armed_state(ran=True)
        except NoMatches:
            pass

    def _expand_history_bang(self, line: str) -> str:
        """Expand `!N` to the Nth (1-based) history entry; pass through otherwise."""
        return expand_history_bang(line, self.state)

    def run_command_worker(self) -> None:
        """Worker thread: drain input_queue, route via dispatcher, push results."""
        from ..cli.dispatcher import CommandDispatcher

        dispatcher = CommandDispatcher(self.state.csp_provider)
        self.state.csp_provider.register_dot_commands(dispatcher)


        self._dispatcher = dispatcher

        while not self._stop_event.is_set():
            try:
                raw_line = self.input_queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if raw_line == _SPLIT_UI_EOF_SENTINEL:
                self.exit_app()
                return

            line = raw_line.strip()
            if not line and getattr(self.state, "pending_confirm", None) is None:
                continue


            try:
                expanded = self._expand_history_bang(line)
            except IndexError as exc:
                eprint(str(exc))
                continue
            if expanded != line:
                _out(expanded)
                line = expanded

            self.state.add_history(line)
            self.call_from_thread(self._append_cli_history, line)


            if self.multi_node:
                _out(f"> {line}")


            self.call_from_thread(setattr, self, "processing_command", line)
            issue_next_prompt = True
            remote_shell_command = bool(
                not self.multi_node
                and getattr(self.state, "in_shell_mode", False)
                and line not in SURFACE_EXIT_COMMANDS
                and not line.lstrip().startswith(".")
            )
            if remote_shell_command:
                session = getattr(self.state, "_session_obj", None)
                if session is not None:


                    self._active_remote_commands[_CLI_PANE_ID] = session
            try:
                continue_loop = self._route_line(line, dispatcher)
                if not continue_loop:


                    issue_next_prompt = False
                    self.call_from_thread(self.action_request_exit)
                    continue

                question = pending_question(self.state)
                if question is not None:


                    issue_next_prompt = False
                    self.call_from_thread(self.begin_confirm_prompt, question)
                    continue

                ui_mode = getattr(self.state, "ui_mode", None)
                if ui_mode and ui_mode != "tui":
                    issue_next_prompt = False
                    self.exit_app(ui_mode)
                    return
            except KeyboardInterrupt:
                _out("^C")
            except Exception as exc:
                eprint(f"Error: {exc}")
            finally:
                if remote_shell_command:
                    self._active_remote_commands.pop(_CLI_PANE_ID, None)
                self.call_from_thread(setattr, self, "processing_command", None)


                self.call_from_thread(self._flush_cli_output_buffer)
                if self.multi_node and issue_next_prompt:


                    self.call_from_thread(self._discard_armed_state)
                if issue_next_prompt:


                    self.call_from_thread(self._issue_prompt)

    def _route_line(self, line: str, dispatcher: Any) -> bool:
        """Route a single input line. Returns continue_loop bool."""
        in_shell = getattr(self.state, "in_shell_mode", False)


        if pending_question(self.state) is not None and is_confirm_answer(line):
            return dispatcher.dispatch(line, self.state)


        if in_shell and line in SURFACE_EXIT_COMMANDS:
            self.state.in_shell_mode = False
            _out("Exited shell mode")
            return True


        if not in_shell and not self.multi_node and line in ("exit", "quit"):


            return False

        if not in_shell and self.multi_node and line in SURFACE_EXIT_COMMANDS:
            self._leave_surface(_CLI_PANE_ID)
            return True

        if not line.startswith("."):


            if self.multi_node:


                return dispatcher.dispatch(f".{line}", self.state)

            session = getattr(self.state, "_session_obj", None)
            if session is None:
                eprint("Error: No session available")
            else:
                try:
                    raw_out = session.exec_command(
                        line, raw=True, record_history=True
                    )
                    output = render_pty_output(
                        raw_out,
                        line,
                        command_echo_present=getattr(
                            session, "raw_exec_output_has_command_echo", True
                        ),
                        framed_output=(
                            getattr(session, "raw_exec_output_is_framed", False) is True
                        ),
                    )
                    if output:
                        _out(output)
                    log(f"[tui_command] cmd={line[:80]}")
                    active_id = getattr(self.state, "active_node_id", None)
                    active_node = self.state.nodes_by_id.get(active_id) if active_id else None
                    if active_node is not None:
                        active_node.mark_activity()
                except Exception as cmd_exc:
                    eprint(f"Error: {cmd_exc}")
            return True

        return dispatcher.dispatch(line, self.state)


    def run(self, *args, **kwargs) -> Optional[str]:


        kwargs.setdefault("mouse", get_mouse_capture())
        result = super().run(*args, **kwargs)
        if self._startup_error is not None:
            raise self._startup_error


        if result is not None:
            return result
        return self._next_ui_mode
