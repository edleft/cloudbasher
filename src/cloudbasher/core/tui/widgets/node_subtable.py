"""The nested node block, and the width planner both rows share."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Callable, Literal, NamedTuple, Optional, Sequence

from rich.cells import cell_len
from rich.text import Text

from cloudbasher.core import identity_listing as _il

if TYPE_CHECKING:  # pragma: no cover
    from cloudbasher.core.tui.widgets.node_table import NodeDisplayRow


BLOCK_STYLE = "on grey27"


BLOCK_HEADER_STYLE = "bold grey93 on grey27"


BLOCK_ID_STYLE = "bold cyan"

BORDER_STYLE = "grey50"


BLOCK_INDENT = 1

_ELLIPSIS = "…"

GAP = 2

_UNSET = "—"


class ColumnSpec(NamedTuple):
    """One column, and how it behaves when the width runs out."""

    header: str
    field: str
    floor: int
    rank: int


    middle: bool = False


    grow: bool = False


    group: int = 0


    smart: bool = False


    cap: int = 0


    hide_when_empty: bool = False


SUB_COLUMNS: tuple[ColumnSpec, ...] = (


    ColumnSpec("Target Identity", "target_identity", 10, 25, middle=True),
    ColumnSpec("Env ID", "environment_id", 8, 40, middle=True),
    ColumnSpec("IP", "ip", 7, 30),
    ColumnSpec("Host", "host", 8, 50, middle=True),
    ColumnSpec("Region", "region", 6, 10),
    ColumnSpec("Last", "last", 5, 60),
    ColumnSpec("Created", "created", 5, 70),
    ColumnSpec("$?", "exit_code", 2, 0),


    ColumnSpec("Cmd Out", "command_output_preview", 6, 100, grow=True, cap=40),
)


CRED_COLUMNS_SPEC: tuple[ColumnSpec, ...] = (
    ColumnSpec("Nodes", "nodes", 5, 0, group=0),


    ColumnSpec("Regions", "regions", 5, 35, group=0),
    ColumnSpec("CSP", "csp", 3, 0, group=0),
    ColumnSpec("Act|Org|Ten", "account", 6, 30, group=1),
    ColumnSpec("Identity", "identity", 12, 60, middle=True, smart=True, group=1),


    ColumnSpec("Cred Type", "cred", 6, 20, group=1),


    ColumnSpec("Cred ID", "cred_id", 6, 55, middle=True, group=1),
    ColumnSpec("Tgt Act|Org|Ten", "target_account", 6, 50, group=2),


    ColumnSpec("Acts As", "acts_as", 8, 40, middle=True, smart=True, group=2, cap=28),


    ColumnSpec("Name", "declared_name", 6, 85, middle=True, group=2, hide_when_empty=True),
    ColumnSpec("Index", "declared_index", 5, 90, group=2, hide_when_empty=True),


    ColumnSpec("Region", "declared_region", 6, 95, group=2, hide_when_empty=True),
    ColumnSpec("Description", "description", 10, 100, grow=True, group=2),
)


MINT_RAIL = "▎"


MINT_FRAME_FIELDS = ("cred",)


MINT_STYLE = "bold #AF87FF"


MINT_FILL = "on grey15"


MINT_FRAME_BUDGET = 2 * len(MINT_RAIL)


BIND_RAIL = MINT_RAIL


BIND_FRAME_FIELDS = ("target_identity",)


BIND_DECLARED_STYLE = _il.CRED_FLAGS["unbound"][1]


BIND_FAILED_STYLE = "bold bright_red"


BIND_FRAME_BUDGET = 2 * len(BIND_RAIL)


BIND_STYLES = {
    "declared": f"{BIND_DECLARED_STYLE} {BLOCK_STYLE}",
    "failed": f"{BIND_FAILED_STYLE} {BLOCK_STYLE}",
}

GROUP_RAIL = "│"
GROUP_RAIL_EXTRA = 1


def group_rail_budget(specs: "Sequence[ColumnSpec]") -> int:
    """Cells to hold back for group rails, computed over the FULL spec."""
    groups = [c.group for c in specs]
    return GROUP_RAIL_EXTRA * sum(1 for a, b in zip(groups, groups[1:]) if a != b)


def unclipped_budget(specs: Sequence[ColumnSpec], natural: dict[str, int]) -> int:
    """The width at which `plan_widths` neither drops, shrinks nor grows."""
    widths = sum(natural.get(c.field, cell_len(c.header)) for c in specs)
    return widths + GAP * max(0, len(specs) - 1)


def block_lead(indent: int = BLOCK_INDENT) -> int:
    """Cells a node block spends before its first column: indent, rail, space."""
    return indent + 2 + BIND_FRAME_BUDGET


def pane_span(
    specs: Sequence[ColumnSpec],
    natural: dict[str, int],
    *,
    lead: int = 0,
    extra: int = 0,
) -> int:
    """One surface's unclipped width in PANE cells, not column cells."""
    return lead + extra + unclipped_budget(specs, natural)


def shared_budget(available: int, first_demand: int, *demands: int) -> int:
    """ONE target width for EVERY surface drawn in the pane."""
    from cloudbasher.core.identity_listing import is_verbose_identity

    if not is_verbose_identity():
        return available
    return max(available, first_demand, *demands)


def plan_budget(specs: Sequence[ColumnSpec], natural: dict[str, int], available: int) -> int:
    """`shared_budget` for a surface that is the only one on screen."""
    return shared_budget(available, pane_span(specs, natural))


def plan_widths(
    specs: Sequence[ColumnSpec],
    natural: dict[str, int],
    available: int,
    *,
    lead: int = 0,
) -> list[tuple[ColumnSpec, int]]:
    """Which columns survive at `available`, and how wide each is."""
    widths = {c.field: natural.get(c.field, cell_len(c.header)) for c in specs}


    live = [c for c in specs if widths[c.field] > 0]

    def total(cols: list[ColumnSpec]) -> int:
        return lead + sum(widths[c.field] for c in cols) + GAP * max(0, len(cols) - 1)

    def floors(cols: list[ColumnSpec]) -> int:
        return lead + sum(c.floor for c in cols) + GAP * max(0, len(cols) - 1)


    for col in sorted((c for c in live if c.rank > 0), key=lambda c: -c.rank):
        if floors(live) <= available:
            break
        live.remove(col)

    for col in sorted(live, key=lambda c: (-c.rank, -widths[c.field])):
        if total(live) <= available:
            break
        if col.rank == 0:
            continue
        widths[col.field] = max(col.floor, widths[col.field] - (total(live) - available))


    slack = available - total(live)
    if slack > 0:
        greedy = next((c for c in live if c.grow), None)
        if greedy is not None:
            widths[greedy.field] += slack

    return [(col, widths[col.field]) for col in specs if col in live]


def natural_widths(
    specs: Sequence[ColumnSpec], rows: Sequence[Any], value: Callable[[Any, str], str]
) -> dict[str, int]:
    """The widest of each column's header and its values, bounded by `cap`."""
    from cloudbasher.core.identity_listing import is_verbose_identity


    verbose = is_verbose_identity()

    def _has_data(c: ColumnSpec) -> bool:
        return any(str(value(r, c.field) or "").strip() for r in rows)

    def _measured(c: ColumnSpec) -> int:
        widest = (
            max(cell_len(c.header), *(cell_len(value(r, c.field)) for r in rows))
            if rows
            else cell_len(c.header)
        )
        if c.cap and not verbose:
            return max(cell_len(c.header), min(widest, c.cap))
        return widest


    return {c.field: (0 if c.hide_when_empty and not _has_data(c) else _measured(c)) for c in specs}


class SubTableLine(NamedTuple):
    """One rendered line, what it IS, and the node it addresses if it addresses one."""

    node_id: Optional[str]
    text: Text
    role: Literal["rule", "header", "node"] = "node"


SHARED_ENV_MARK = "="


def _value(row: Any, field: str) -> str:
    """One cell's text."""
    text = str(getattr(row, field, "") or _UNSET)
    if field == "environment_id" and getattr(row, "shared_env", False) and text != _UNSET:
        return f"{SHARED_ENV_MARK}{text}"
    return text


def elide(value: str, width: int, *, middle: bool = False) -> str:
    """Fit `value` into `width` CELLS, marking that something was removed."""
    if width <= 0:
        return ""
    if cell_len(value) <= width:
        return value
    if width <= 1:
        return _ELLIPSIS[:width]
    if not middle:
        cut = value[: width - 1]
        while cut and cell_len(cut) > width - 1:
            cut = cut[:-1]
        return cut + _ELLIPSIS
    head = (width - 1) // 2
    tail = width - 1 - head
    out = value[:head] + _ELLIPSIS + (value[-tail:] if tail else "")
    while len(out) > 1 and cell_len(out) > width:
        out = out[:-2] + _ELLIPSIS
    return out


SHORTEN_KEYWORDS = (
    "AWS",
    "SSO",
    "Admin",
    "IAM",
    "Root",
    "Power",
    "ReadOnly",
    "Read",
    "Write",
    "Full",
    "Prod",
    "Dev",
    "Test",
    "Ops",
    "Billing",
    "Security",
)


_HASHISH = re.compile(r"^[0-9a-f]{8,}$", re.I)


_TOKENS = re.compile(r"([_-])")


def _shorten_token(token: str, keep: int) -> str:
    """One token cut to roughly `keep` characters, keyword-first."""
    if len(token) <= keep:
        return token
    lowered = token.lower()


    best = 0
    for word in SHORTEN_KEYWORDS:
        at = lowered.find(word.lower())
        if at == -1:
            continue
        end = at + len(word)
        if end <= max(keep, len(word)) and end > best:
            best = end
    if best:
        return token[:best] + _ELLIPSIS
    return token[:keep] + _ELLIPSIS


def smart_shorten(value: str, width: int) -> str:
    """Fit `value` into `width` by abbreviating its TOKENS, not its tail."""
    if cell_len(value) <= width:
        return value
    head, sep, tail = value.rpartition("/")
    prefix = head + sep
    budget = width - cell_len(prefix)
    if budget < 4:
        return elide(value, width)

    parts = _TOKENS.split(tail)

    def rendered(keep: int) -> str:
        out = []
        for part in parts:
            if part in ("_", "-"):
                out.append(part)
            elif _HASHISH.match(part):
                out.append(_ELLIPSIS)
            else:
                out.append(_shorten_token(part, keep))


        text = "".join(out)
        while True:
            collapsed = (
                text.replace(_ELLIPSIS + "_", _ELLIPSIS)
                .replace(_ELLIPSIS + "-", _ELLIPSIS)
                .replace(_ELLIPSIS + _ELLIPSIS, _ELLIPSIS)
            )
            if collapsed == text:
                return text
            text = collapsed

    for keep in range(max(len(t) for t in parts if t) if parts else 8, 2, -1):
        candidate = rendered(keep)
        if cell_len(candidate) <= budget:
            return prefix + candidate
    return elide(value, width)


def fit(value: str, width: int, col: ColumnSpec) -> str:
    """One cell's text at `width`, by whichever rule the column asked for."""
    if col.smart:
        return smart_shorten(value, width)
    return elide(value, width, middle=col.middle)


def _line(
    cells: dict[str, str],
    plan: list[tuple[ColumnSpec, int]],
    *,
    rail: str,
    body_style: str,
    indent: int,
    bind: str = "",
) -> Text:
    """One rendered row of a node block."""
    frame_style = BIND_STYLES.get(bind, "")
    text = Text(" " * indent)
    text.append(f"{rail} ", style=BORDER_STYLE)
    for index, (col, width) in enumerate(plan):
        if index:
            text.append(" " * GAP, style=body_style)


        if col.field == BIND_FRAME_FIELDS[0]:
            text.append(BIND_RAIL if frame_style else " ", style=frame_style or body_style)
        shown = fit(cells.get(col.field, ""), width, col)
        cell = shown + " " * max(0, width - cell_len(shown))
        text.append(cell, style=body_style)
        if col.field == BIND_FRAME_FIELDS[-1]:
            text.append(BIND_RAIL if frame_style else " ", style=frame_style or body_style)
    return text


def block_natural(rows: Sequence["NodeDisplayRow"]) -> dict[str, int]:
    """What each sub-table column would ask for, measured over `rows`."""
    return natural_widths(SUB_COLUMNS, rows, _value)


def plan_node_block(
    natural: dict[str, int], budget: int, *, indent: int = BLOCK_INDENT
) -> list[tuple[ColumnSpec, int]]:
    """THE one place a node block's column widths are decided."""
    return plan_widths(SUB_COLUMNS, natural, budget, lead=block_lead(indent))


def block_header_line(
    plan: list[tuple[ColumnSpec, int]],
    *,
    indent: int = BLOCK_INDENT,
) -> Text:
    """The sub-table's column-name row, once per block."""
    return _line(
        {c.field: c.header for c, _w in plan},
        plan,
        rail="│",
        body_style=BLOCK_HEADER_STYLE,
        indent=indent,
    )


def render_node_block(
    rows: list["NodeDisplayRow"],
    available_width: int,
    *,
    indent: int = BLOCK_INDENT,
    plan: Optional[list[tuple[ColumnSpec, int]]] = None,
) -> list[SubTableLine]:
    """The nested block for one expanded credential: rule, HEADER, nodes, rule."""
    if not rows:
        return []
    lead = block_lead(indent)
    if plan is None:


        natural = block_natural(rows)
        plan = plan_node_block(
            natural, plan_budget(SUB_COLUMNS, natural, available_width), indent=indent
        )
    span = lead + sum(w for _c, w in plan) + GAP * max(0, len(plan) - 1)
    rule = " " * indent

    lines = [
        SubTableLine(
            None,
            Text(rule + "┌" + "─" * max(0, span - indent - 1), style=BORDER_STYLE),
            role="rule",
        ),
        SubTableLine(None, block_header_line(plan, indent=indent), role="header"),
    ]
    for row in rows:
        lines.append(
            SubTableLine(
                row.node_id,
                _line(
                    {c.field: _value(row, c.field) for c, _w in plan},
                    plan,
                    rail="│",
                    body_style=BLOCK_STYLE,
                    indent=indent,


                    bind=getattr(row, "container_unbound", "") or "",
                ),
            )
        )
    lines.append(
        SubTableLine(
            None,
            Text(rule + "└" + "─" * max(0, span - indent - 1), style=BORDER_STYLE),
            role="rule",
        )
    )
    return lines


def block_enabled() -> bool:
    """Is the sub-table renderer on? `[ui] node_subtable`, default TRUE."""


    from cloudbasher.core.config import switch

    return switch("ui.node_subtable")
