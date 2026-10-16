"""Single source of truth for the multi-node TUI's key bindings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cloudbasher.core.interactive.repl_shared import quit_command_help


_NODE_TABLE_ACTIONS = frozenset(
    {
        "toggle_select",
        "toggle_select_all",
        "expand_toggle",
        "expand_all_toggle",


        "show_cred_view",
        "show_node_view",


        "show_unmanaged_view",
        "page_left",
        "page_right",


        "cursor_down",
        "cursor_up",


        "range_select",
    }
)


@dataclass(frozen=True)
class KeyBinding:
    key: str
    action: str
    label: str
    tier: str
    help_text: str
    command: Optional[str] = None
    scope: str = "global"


    footer: bool = True


COMMAND_KEYS: tuple[KeyBinding, ...] = (
    KeyBinding(
        "b",
        "bulk_apply",
        "Bulk",
        "command",
        "Arm bulk selected <cmd> for the current selection.",
        command="bulk selected ",
        scope="selection",
    ),
    KeyBinding(
        "o",
        "output_arm",
        "Output",
        "command",
        "Arm output selected to show last output for the current selection.",
        command="output selected",
        scope="selection",
    ),
    KeyBinding(
        "p",
        "provision_arm",
        "Provision",
        "command",
        "Arm provision to create new CloudShell environments.",
        command="provision ",
        scope="global",
    ),
    KeyBinding(
        "c",
        "connect_arm",
        "Connect",
        "command",
        "Arm connect selected to open sessions for the current selection.",
        command="connect selected ",
        scope="selection",
    ),
    KeyBinding(
        "d",
        "disconnect_arm",
        "Disconnect",
        "command",
        "Arm disconnect selected to close sessions for the current selection.",
        command="disconnect selected ",
        scope="selection",
    ),
    KeyBinding(
        "s",
        "start_arm",
        "Start",
        "command",
        "Arm start selected to resume suspended/stopped environments.",
        command="start selected ",
        scope="selection",
    ),
    KeyBinding(
        "S",
        "stop_arm",
        "Stop",
        "command",
        "Arm stop selected to suspend running environments.",
        command="stop selected ",
        scope="selection",
    ),
    KeyBinding(
        "U",
        "deregister_arm",
        "Unregister",
        "command",
        "Arm unregister selected to drop the current selection from the local registry.",
        command="unregister selected ",
        scope="selection",
    ),
    KeyBinding(
        "D",
        "delete_arm",
        "Delete",
        "command",
        "Arm delete selected to permanently delete the underlying cloud environment.",
        command="delete selected ",
        scope="selection",
    ),


    KeyBinding(
        "r",
        "unmanaged_register_arm",
        "Register",
        "command",
        "Arm unmanaged register selected -- start tracking the selected unmanaged "
        "environments as nodes. Unmanaged view only.",
        command="unmanaged register selected",
        scope="selection",
        footer=False,
    ),
)


VIEW_KEYS: tuple[KeyBinding, ...] = (
    KeyBinding(
        "t",
        "toggle_terminal",
        "Terminal",
        "view",
        "Open/close the side terminal for the highlighted node.",
        scope="row",
    ),
    KeyBinding(
        "x",
        "toggle_select",
        "Select",
        "view",
        "Toggle selection of the highlighted row or group (also sets the range-select anchor).",
        scope="row",
    ),


    KeyBinding(
        "X",
        "range_select",
        "Range",
        "view",
        "Select every row between the last 'x'-toggled row and here, inclusive (Gmail-style).",
        scope="row",
        footer=False,
    ),
    KeyBinding(
        "a", "toggle_select_all", "All", "view", "Select (or deselect) every node.", scope="global"
    ),


    KeyBinding(
        "j",
        "cursor_down",
        "Down",
        "view",
        "Move the highlight down one row (vi-style alias for ↓).",
        scope="row",
        footer=False,
    ),
    KeyBinding(
        "k",
        "cursor_up",
        "Up",
        "view",
        "Move the highlight up one row (vi-style alias for ↑).",
        scope="row",
        footer=False,
    ),
    KeyBinding(
        "enter",
        "expand_toggle",
        "Expand",
        "view",
        "Expand/collapse the highlighted group.",
        scope="row",
    ),


    KeyBinding(
        "e",
        "expand_toggle",
        "Expand",
        "view",
        "Expand/collapse the highlighted group (same as Enter).",
        scope="row",
        footer=False,
    ),


    KeyBinding(
        "E",
        "expand_all_toggle",
        "ExpandAll",
        "view",
        "Expand every credential's nodes, or collapse them all.",
        scope="global",


        footer=False,
    ),
    KeyBinding(
        "1",
        "show_cred_view",
        "Creds",
        "view",
        "Show the Credential View (credentials, with their nodes nested). "
        "A DIRECT selector, not a toggle -- pressing it twice leaves you here.",
        scope="global",


        footer=False,
    ),
    KeyBinding(
        "3",
        "show_unmanaged_view",
        "Unmanaged",
        "view",
        "Show the Unmanaged View -- environments .discover/.enum found that "
        "cloudbasher is not tracking. A DIRECT selector, not a toggle.",
        scope="global",


        footer=False,
    ),
    KeyBinding(
        "2",
        "show_node_view",
        "Nodes",
        "view",
        "Show the Node View (every node, flat). A DIRECT selector, not a "
        "toggle -- pressing it twice leaves you here.",
        scope="global",
        footer=False,
    ),
    KeyBinding(
        "v",
        "toggle_verbose",
        "Verbose",
        "view",
        "Show full identity values: SSO start URL and Azure tenant UUID in "
        "Act|Org|Ten, plus full ARNs. The pane scrolls horizontally while on.",


        scope="global",
    ),
    KeyBinding(
        "left",
        "page_left",
        "Cols",
        "view",
        "Page the Nodes table's columns left.",
        scope="global",
    ),
    KeyBinding(
        "right",
        "page_right",
        "Cols",
        "view",
        "Page the Nodes table's columns right.",
        scope="global",
    ),
    KeyBinding(
        "h",
        "page_left",
        "Cols",
        "view",
        "Page the Nodes table's columns left (vi-style alias for ←).",
        scope="global",
        footer=False,
    ),
    KeyBinding(
        "l",
        "page_right",
        "Cols",
        "view",
        "Page the Nodes table's columns right (vi-style alias for →).",
        scope="global",
        footer=False,
    ),
    KeyBinding(
        "m",
        "toggle_redact",
        "Mask",
        "view",
        "Cycle demo redaction of sensitive fields on/off.",
        scope="global",
    ),


    KeyBinding(
        "z",
        "toggle_info_zoom",
        "Zoom",
        "view",
        "Zoom the Info pane to full height (Nodes keeps its header + cursor row); press again to restore.",
        scope="global",
        footer=False,
    ),
    KeyBinding(
        "Q",
        "quit_app",
        "Quit",
        "view",
        "Quit CloudBasher. Arms 'quit' in the command bar; Enter confirms, "
        "Escape cancels. Ctrl-Q and every typed quit verb are the same path "
        f"(`#454`): {quit_command_help()} (`#805`).",
        scope="global",
    ),
    KeyBinding(
        ":",
        "focus_command_bar",
        "Command",
        "view",
        "Focus the one-line command bar (Esc returns to Nodes/Info).",
        scope="global",
    ),


    KeyBinding(
        "?",
        "show_help",
        "Help",
        "view",
        "Open the help overlay (the same text as .help); Esc, q or ? closes it.",
        scope="global",
    ),
)

KEYMAP: tuple[KeyBinding, ...] = COMMAND_KEYS + VIEW_KEYS


PANE_VIEW_HINTS: dict[str, tuple[str, ...]] = {
    "info": (


        "z Zoom",
        "pgup/pgdn Scroll",


        "←/→ Scroll horiz",
    ),


    "node-side": ("Ctrl-D/exit Leave (session stays live)",),
}

_ARROW_GLYPH = {"left": "←", "right": "→"}


def node_table_bindings() -> tuple[KeyBinding, ...]:
    """VIEW-tier entries that resolve to a CredNodeTable action."""
    return tuple(kb for kb in VIEW_KEYS if kb.action in _NODE_TABLE_ACTIONS)


def root_bindings() -> tuple[KeyBinding, ...]:
    """Every entry that resolves to a _MultiNodeRoot action: the whole COMMAND tier, plus the VIEW-tier keys CredNodeTable doesn't own."""
    return tuple(kb for kb in KEYMAP if kb.action not in _NODE_TABLE_ACTIONS)


def command_footer_segments() -> list[tuple[str, str]]:
    """(key, label) pairs for the CMD footer row, in COMMAND_KEYS order. Plain data -- callers (the widget) decide how to style it."""
    return [(kb.key, kb.label) for kb in COMMAND_KEYS if kb.footer]


def view_footer_segments(pane: str) -> list[tuple[str, str]]:
    """(key, label) pairs for the focus-sensitive VIEW footer row for `pane` ("node", "info", "cli", or "terminal"). Merges consecutive VIEW_KEYS entries that share a label (left/right "Cols") into one "←/→"-style key segment. Non-"node" panes' hints are pre-baked "<keys> <label>" strings (PANE_VIEW_HINTS) -- split on the first space to keep the same (key, label) shape."""
    if pane != "node":
        segments: list[tuple[str, str]] = []
        for hint in PANE_VIEW_HINTS.get(pane, ()):
            key_part, _, label_part = hint.partition(" ")
            segments.append((key_part, label_part))
        return segments

    footer_keys = [kb for kb in VIEW_KEYS if kb.footer]
    segments = []
    seen_labels: set[str] = set()
    for kb in footer_keys:
        if kb.label in seen_labels:
            continue
        pair = [k for k in footer_keys if k.label == kb.label]
        if len(pair) > 1:
            glyphs = "/".join(_ARROW_GLYPH.get(k.key, k.key) for k in pair)
            segments.append((glyphs, kb.label))
        else:
            segments.append((kb.key, kb.label))
        seen_labels.add(kb.label)
    return segments


def command_footer_row() -> str:
    """Render the static CMD footer row (row 1). Single-space segment separators -- at 9 COMMAND keys, the double-space spacing tried first ran to 101 columns, one over the "nothing dropped at 100 columns" acceptance criterion."""
    return " ".join(f"{key} {label}" for key, label in command_footer_segments())


def view_footer_row(pane: str) -> str:
    """Render the focus-sensitive VIEW footer row (row 2) for `pane` ("node", "info", "cli", or "terminal")."""
    return " ".join(f"{key} {label}" if label else key for key, label in view_footer_segments(pane))


def nodes_help_lines() -> list[str]:
    """`(Nodes pane) <key>  <help_text>` lines for `_cmd_help`."""
    lines = []
    for kb in KEYMAP:
        key_label = kb.key if kb.key != "left" else "left / right"
        if kb.key == "right":
            continue
        lines.append(f"  (Nodes pane) {key_label:<12} {kb.help_text}")
    return lines
