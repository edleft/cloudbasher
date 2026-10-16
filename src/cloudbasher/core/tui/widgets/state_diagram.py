"""ITEMS #75 part 2: ONE state/flow diagram, built from the real glyph tables."""

from __future__ import annotations

from rich.text import Text

from ...types import CONTAINER_TRANSITIONS


_TERMINAL_STATES: tuple[tuple[str, str], ...] = (
    ("Failed", "the last operation errored — see Info"),
    ("CredentialInvalid", "STS refused the credential — never reachable"),
    ("Unknown", "no status read yet"),
)


def _lifecycle_edge(status: str, command: str) -> tuple[str, str, str]:
    """One `(from, command, to)` row, READ OFF the lifecycle table."""
    leaving, heading = CONTAINER_TRANSITIONS[status]
    if leaving is None or heading is None:
        raise ValueError(f"{status!r} does not name both ends of an edge")
    return (leaving, command, heading)


_CONTAINER_EDGES: tuple[tuple[str, str, str], ...] = (
    ("(no node)", "provision", "Running"),
    _lifecycle_edge("Suspending", "stop"),
    _lifecycle_edge("Starting", "start"),
    ("Running", "delete", "(no node)"),
)

_CONN_EDGES: tuple[tuple[str, str, str], ...] = (
    ("Disconnected", "connect", "Connected"),
    ("Connected", "disconnect", "Disconnected"),
)


def _glyph(table: dict, name: str) -> Text:
    return table.get(name, Text("·", style="dim")).copy()


def state_flow_lines() -> list[Text]:
    """The diagram, as styled lines. Consumed by the `?` modal and `.help`."""
    from .node_table import (
        _CONN_GLYPH,
        _CONTAINER_GLYPH,
        _CONTAINER_GLYPH_WORKED,
        _CP_GLYPH,
        _TRANSITION,
    )

    def line(*parts) -> Text:
        out = Text()
        for part in parts:
            out.append_text(part) if isinstance(part, Text) else out.append(part)
        return out

    run = _glyph(_CONTAINER_GLYPH, "Running")
    susp = _glyph(_CONTAINER_GLYPH, "Suspended")
    none = Text("·", style="dim")

    lines: list[Text] = [
        Text("CONTAINER — the FIRST glyph in the Status column", style="bold"),
        Text(""),
        line("      ", none, "  (no node)"),
        Text("      │            ▲"),
        Text("      │ provision  │ delete"),
        Text("      ▼            │"),
        line("      ", run, " Running ──── stop ────▶ ", susp, " Suspended"),
        Text("        ▲                                │"),
        Text("        └──────────── start ─────────────┘"),
        Text(""),
    ]
    for name, why in _TERMINAL_STATES:
        lines.append(line("      ", _glyph(_CONTAINER_GLYPH, name), f"  {name:<18}{why}"))

    lines += [
        Text(""),


        Text("  While a WORKER is on the row the glyph STAYS and takes a background tint:"),
        line(
            "      ",
            _glyph(_CONTAINER_GLYPH_WORKED, "Suspending"),
            "  still ",
            run,
            " Running, on its way down (.stop)",
        ),
        line(
            "      ",
            _glyph(_CONTAINER_GLYPH_WORKED, "Starting"),
            "  still ",
            susp,
            " Suspended, on its way up (.start)",
        ),
        line(
            "      ",
            _glyph(_CONTAINER_GLYPH_WORKED, "Pending"),
            "  no container yet (.provision), or destination not yet known",
        ),
        Text(""),
        Text(
            "  The tint says WHICH axis is moving; the glyph under it says what that",
            style="dim",
        ),
        Text(
            "  axis still is. It is drawn ONLY on a row the hourglass is on (`#760`) --",
            style="dim",
        ),
        Text(
            "  axis still is. It replaced a shared "
            f"{_TRANSITION} that hid both (`#450`, `#755`).",
            style="dim",
        ),
        Text(""),
        Text("CONNECTION — the SECOND glyph, and it is INDEPENDENT", style="bold"),
        Text(""),
        line(
            "      ",
            _glyph(_CONN_GLYPH, "Disconnected"),
            " Disconnected ── connect ──▶ ",
            _glyph(_CONN_GLYPH, "Connected"),
            " Connected",
        ),
        Text("        ▲                                  │"),
        Text("        └─────────── disconnect ───────────┘"),
        Text(""),


        Text("CONTROL PLANE — the THIRD glyph, and it is INDEPENDENT too", style="bold"),
        Text(""),
        line(
            "      ",
            _glyph(_CP_GLYPH, "Retrying"),
            "  Retrying      the control plane's heartbeat is mid-retry-cycle",
        ),
        line(
            "      ",
            _glyph(_CP_GLYPH, "NoIdentity"),
            "  NoIdentity    latest control-plane request explicitly rejected authentication",
        ),
        Text(""),
        line(
            "      ",
            run,
            " ",
            _glyph(_CONN_GLYPH, "Disconnected"),
            "  is normal right after .provision — the container is up and",
        ),
        Text(
            "           nothing is attached to it yet. Three node axes, three facts —",
            style="dim",
        ),
        Text("           and a separate COLUMN for whether a worker is on it.", style="dim"),
    ]
    return lines


def state_flow_text() -> Text:
    """The diagram as one `Text`, newline-joined."""
    out = Text()
    for i, ln in enumerate(state_flow_lines()):
        if i:
            out.append("\n")
        out.append_text(ln)
    return out
