"""One-line node-status row for the multi-node UX."""

from __future__ import annotations

from typing import Optional

from rich.cells import cell_len
from rich.text import Text
from textual.widgets import Static

from cloudbasher.core.tui.widgets.node_table import NodeDisplayRow, _configured_csp_cell


_STATUS_LABEL_WIDTH = 13


def _status_label(text: str) -> Text:
    padded = f"{text:<{_STATUS_LABEL_WIDTH}}"
    result = Text()
    result.append(padded, style="bold")
    result.append(" │ ", style="dim")
    return result


def _continuation_label(row_pos: Optional[int] = None, row_total: Optional[int] = None) -> Text:
    """User-reported layout bug: the 2nd line of a 2-line status row previously started flush at column 0 with no visual relationship to the row above it. This mirrors _status_label's prefix width (blank instead of repeating the label) plus the same " │ " divider, so line 2's content aligns directly under line 1's (starting where "Status:" starts) with a matching left border."""
    result = Text()
    marker = f"({row_pos}/{row_total})" if row_pos is not None and row_total else ""
    result.append(marker.center(_STATUS_LABEL_WIDTH), style="bold")
    result.append(" │ ", style="dim")
    return result


def _status_label_for_csp(csp: str, display_id: Optional[str] = None) -> Text:
    """Same padded-label-plus-divider convention as ``_status_label``, but with the CSP name colored to match the CSP column. Built entirely via ``.append()`` onto the same ``Text`` object ``_csp_cell`` returned -- see ``node_table.py``'s module docstring, rendering-bug #2, for why a ``+``-concatenated ``Text(string, style=...)`` would leak color into the rest of the line instead of just the CSP name."""
    label = _configured_csp_cell(csp, suffix=" ")
    label.append(f"Node {display_id}" if display_id else "Node", style="bold")
    pad = _STATUS_LABEL_WIDTH - cell_len(label.plain)
    if pad > 0:
        label.append(" " * pad, style="bold")
    label.append(" │ ", style="dim")
    return label


_IDLE_WARN_SECONDS = 300.0


class NodeStatusLine(Static):
    """Two-line status row docked above the info pane."""


    _row_pos: Optional[int] = None
    _row_total: Optional[int] = None

    def set_row_position(self, row_pos: Optional[int], row_total: Optional[int]) -> None:
        """Record which row is highlighted, for the "(M/N)" gutter. Does not re-render on its own -- callers set this immediately before the show*() call that paints the row, and later transient messages pick it up from the cache."""
        self._row_pos = row_pos
        self._row_total = row_total

    def _continuation(self) -> Text:
        return _continuation_label(self._row_pos, self._row_total)

    def _update_two_line(self, line1: Text, line2: Optional[Text] = None) -> None:
        """Every render path goes through here so the second line -- and therefore the "(M/N)" gutter -- always exists. `line2` is None for the message forms that have nothing to continue; the gutter still renders, just with no content beside it."""
        line1.append("\n")
        line1.append(self._continuation())
        if line2 is not None:
            line1.append(line2)
        self.update(line1)

    def on_mount(self) -> None:


        text = _status_label("Node")
        text.append("Select a node to see details.")
        self._update_two_line(text)

    def show(
        self,
        node: NodeDisplayRow,
        *,
        secret_display: str = "—",
    ) -> None:
        """The table's Identity/Target Identity columns are middle-truncated (long ARNs would otherwise blow out the column widths) -- this line is the "happy medium": the full, untruncated values for whichever row is highlighted, always one keystroke (arrow key) away."""


        retry_suffix = (
            f" ({node.heartbeat_retry_count}/{node.heartbeat_max_retries})"
            if node.heartbeat_retry_count > 0
            else ""
        )


        activity_suffix = f" {node.activity_detail}" if node.activity_detail else ""
        text = _status_label_for_csp(node.csp, node.display_id)
        text.append(


            f"Status:{node.container_status}/{node.connection}"
            f"/{node.control_plane}{retry_suffix}{activity_suffix} · "
            f"Credential:{node.cred_type} {secret_display} · "
            f"Region:{node.region} · IP:{node.ip} · Host:{node.host}"
        )
        line2 = Text(f"Identity:{node.identity} · Target Identity:{node.target_identity_full}")
        if node.shared_env:


            line2.append(" · ")
            line2.append(
                "Shared container: another credential resolves to the same "
                "IAM principal and sees this same environment",
                style="bold yellow",
            )
        if node.failure_label:


            line2.append(" · ")
            line2.append(f"Last failure: {node.failure_label}", style="bold red")
        if node.supervisor_note:


            line2.append(" · ")
            line2.append(f"Supervisor: {node.supervisor_note}", style="bold red")
        if node.last_kind == "machine":


            line2.append(" · ")
            line2.append(
                "Last was moved by a keepalive, not by you -- the session "
                "idle clock is still running",
                style="yellow",
            )
        if node.idle_remaining is not None:


            _rem = node.idle_remaining
            line2.append(" · ")
            if _rem < 0:
                line2.append(
                    f"Session idle deadline passed {int(-_rem) // 60}m ago", style="bold red"
                )
            else:
                line2.append(
                    f"Session idle: {int(_rem) // 60}m {int(_rem) % 60}s left",
                    style="yellow" if _rem < _IDLE_WARN_SECONDS else "dim",
                )
        if node.cred_unbound:


            line2.append(" · ")
            line2.append(
                "Container credentials: NONE (ACT_AS=direct-unbound; " "in-shell `aws` will fail)",
                style="bold yellow",
            )
        self._update_two_line(text, line2)

    def show_group(self, members: list[NodeDisplayRow], *, identity: str = "") -> None:
        """The status line for a highlighted credential row."""
        if not members:
            text = _status_label_for_csp("AWS")
            text.append(
                "No nodes on this credential yet — press p to provision one.",
                style="dim",
            )
            self._update_two_line(text, Text(f"Identity:{identity}" if identity else ""))
            return
        text = _status_label_for_csp(members[0].csp)
        text.append(f"{len(members)} nodes grouped under this identity — press Enter to expand.")
        self._update_two_line(text, Text(f"Identity:{members[0].identity}"))

    def show_not_implemented(self, action_label: str) -> None:
        """Visible, non-silent placeholder for row/bulk actions that don't have real backend wiring yet -- never swallow the keypress quietly."""
        text = _status_label("Node")
        text.append(f"{action_label} — not yet implemented in this phase.")
        self._update_two_line(text)

    def show_message(self, text: str, *, is_error: bool = False) -> None:
        """Generic status message -- used for multi-node startup-callback progress/errors (there's no Log pane in the multi-node layout yet; the Info tab's "Log" tab is still a static placeholder), since out()/eprint()/log()/detail() have nowhere else safe to render during bootstrap without corrupting the TUI's raw-stdout-free rendering."""
        label = _status_label("Node")
        label.append(text, style="bold red" if is_error else None)
        self._update_two_line(label)
