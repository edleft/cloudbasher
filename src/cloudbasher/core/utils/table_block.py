"""Aligned tables that survive redaction."""

from __future__ import annotations

from typing import Callable, Optional


TABLE_MARK = "\x1e"


CELL_SEP = "\x1f"

_DEFAULT_GAP = "  "


def is_table_block(text: str) -> bool:
    """True if ``text`` CONTAINS a marked table -- not only if it starts with one."""
    return bool(text) and TABLE_MARK in text


def format_table_block(
    rows: list[list[str]],
    *,
    indent: str = _DEFAULT_GAP,
    gap: str = _DEFAULT_GAP,
    lead_blank: bool = False,
) -> str:
    """Lay ``rows`` out as an aligned table, marked for later re-fitting."""
    if not rows:
        return ""
    if lead_blank:
        rows = [[""], *rows]
    width = max(len(row) for row in rows)
    padded = [list(row) + [""] * (width - len(row)) for row in rows]
    col_widths = [max(len(row[i]) for row in padded) for i in range(width)]

    lines = []
    for row in padded:
        parts = [row[i].ljust(col_widths[i]) + gap for i in range(width - 1)]
        parts.append(row[width - 1])


        lines.append((indent + CELL_SEP.join(parts)).rstrip())

    return TABLE_MARK + "\n".join(lines) + TABLE_MARK


def strip_table_marks(text: str) -> str:
    """The block as plain text, keeping the layout it was written with."""
    if not text:
        return text
    return text.replace(TABLE_MARK, "").replace(CELL_SEP, "")


def render_table_block(text: str, transform: Optional[Callable[[str], str]] = None) -> str:
    """Re-fit a marked table, optionally rewriting each cell first."""
    if not is_table_block(text):
        return text
    if transform is None:


        return strip_table_marks(text)


    parts = text.split(TABLE_MARK)
    out = []
    for index, segment in enumerate(parts):
        if index % 2 == 0:
            out.append(transform(segment) if segment else segment)
        else:
            out.append(_refit(segment, transform))
    return "".join(out)


def _refit(body: str, transform: Callable[[str], str]) -> str:
    """Rewrite one marked block's cells, then lay it out at the new widths."""
    indent = ""
    rows: list[list[str]] = []
    for line in body.split("\n"):
        stripped = line.lstrip(" ")
        if not indent:
            indent = line[: len(line) - len(stripped)]
        cells = [cell.rstrip() for cell in stripped.split(CELL_SEP)]
        rows.append([transform(cell) for cell in cells])
    return strip_table_marks(format_table_block(rows, indent=indent or _DEFAULT_GAP))
