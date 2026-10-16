"""ONE id namespace for the Nodes view: `Cred#` and `Cred#.Node#`."""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional, cast

from cloudbasher.core.types import CredentialRecord, numbered_originating_records


CRED_ID_RE = re.compile(r"^(\d+)$")

NODE_ID_RE = re.compile(r"^(\d+)\.(\d+)$")

RANGE_RE = re.compile(r"^(\d+(?:\.\d+)?)-(\d+(?:\.\d+)?)$")


_UNBOUNDED_NODE = 1 << 30


def originating_root_record(
    credential_id: Optional[str], credentials_by_id: dict[str, Any]
) -> "Optional[CredentialRecord]":
    """Walk a credential up to the originating RECORD that `Cred#` numbers."""
    rec = credentials_by_id.get(credential_id) if credential_id else None
    if rec is None:
        return None
    seen: set[str] = set()
    while (
        getattr(rec, "parent_id", None)
        and rec.parent_id in credentials_by_id
        and rec.parent_id not in seen
    ):
        seen.add(rec.id)
        rec = credentials_by_id[rec.parent_id]


    return cast("CredentialRecord", rec)


def originating_root_id(
    credential_id: Optional[str], credentials_by_id: dict[str, Any]
) -> Optional[str]:
    """`originating_root_record`'s id -- the form most callers want."""
    rec = originating_root_record(credential_id, credentials_by_id)


    return None if rec is None else str(rec.id)


def build_id_map(
    credentials_by_id: dict[str, Any],
    nodes_by_id: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    """Return `(node_id -> "1.2", credential_id -> "1")`."""
    cred_ids: dict[str, str] = {}
    for number, record in numbered_originating_records(credentials_by_id):
        cred_ids[record.id] = str(number)

    by_root: dict[str, list[Any]] = {}
    for node in nodes_by_id.values():
        root = originating_root_id(getattr(node, "credential_id", None), credentials_by_id)
        if root is None or root not in cred_ids:
            continue
        by_root.setdefault(root, []).append(node)

    node_ids: dict[str, str] = {}
    for root, nodes in by_root.items():


        for index, node in enumerate(sorted(nodes, key=lambda n: getattr(n, "seq", 0) or 0), 1):
            node_ids[node.id] = f"{cred_ids[root]}.{index}"
    return node_ids, cred_ids


def order_like(reference: Iterable[str], node_ids: Iterable[str]) -> list[str]:
    """`node_ids`, re-ordered to follow `reference`. Stable for the rest."""
    position = {node_id: index for index, node_id in enumerate(reference)}
    return sorted(node_ids, key=lambda node_id: position.get(node_id, len(position)))


def in_display_order(
    node_ids: Iterable[str],
    credentials_by_id: dict[str, Any],
    nodes_by_id: dict[str, Any],
) -> list[str]:
    """`node_ids` re-ordered to match the Nodes pane, top to bottom."""


    return order_like(
        (node_id for _display, node_id in ordered_node_ids(credentials_by_id, nodes_by_id)),
        node_ids,
    )


def display_id_for(
    node_id: str,
    credentials_by_id: dict[str, Any],
    nodes_by_id: dict[str, Any],
) -> Optional[str]:
    """This node's addressable id (`1.2`), or None if it has none."""
    node_ids, _ = build_id_map(credentials_by_id, nodes_by_id)
    return node_ids.get(node_id)


def ordered_node_ids(
    credentials_by_id: dict[str, Any],
    nodes_by_id: dict[str, Any],
) -> list[tuple[str, str]]:
    """`[(display_id, node_id), ...]` in `Cred#.Node#` order."""
    node_ids, _ = build_id_map(credentials_by_id, nodes_by_id)

    def _key(item: tuple[str, str]) -> tuple[int, int]:
        cred, _, node = item[0].partition(".")
        return int(cred), int(node)


    return sorted(((disp, nid) for nid, disp in node_ids.items()), key=_key)


def resolve_id_selector(
    selector: str,
    credentials_by_id: dict[str, Any],
    nodes_by_id: dict[str, Any],
) -> Optional[set[str]]:
    """Resolve `1`, `1.2` or `1.1-2.1` into node ids, or None if not this syntax."""
    selector = selector.strip()
    node_ids, _ = build_id_map(credentials_by_id, nodes_by_id)

    m = CRED_ID_RE.match(selector)
    if m:


        prefix = f"{int(m.group(1))}."
        return {nid for nid, disp in node_ids.items() if disp.startswith(prefix)}

    if NODE_ID_RE.match(selector):
        return {nid for nid, disp in node_ids.items() if disp == selector}

    m = RANGE_RE.match(selector)
    if m:
        return _resolve_range(m.group(1), m.group(2), credentials_by_id, nodes_by_id)

    return None


def explain_no_match(
    selector: str,
    credentials_by_id: dict[str, Any],
    nodes_by_id: dict[str, Any],
) -> str:
    """Why `selector` matched no nodes, when the id map can tell."""
    selector = selector.strip()
    node_ids, cred_ids = build_id_map(credentials_by_id, nodes_by_id)
    known = sorted({int(d.split(".", 1)[0]) for d in cred_ids.values() if d.isdigit()})

    def _nodes_of(number: int) -> list[str]:
        prefix = f"{number}."
        return sorted(d for d in node_ids.values() if d.startswith(prefix))

    def _about(number: int, no_nodes: str) -> str:
        """The three things that can be said about a credential number."""
        if number not in known:
            return f" -- there is no credential {number}" + (
                f" (ids run {known[0]}-{known[-1]})" if known else ""
            )
        siblings = _nodes_of(number)
        if siblings:


            return f" -- credential {number} has {', '.join(siblings)}"
        return no_nodes

    m = CRED_ID_RE.match(selector)
    if m:
        number = int(m.group(1))
        return _about(
            number,
            f" -- {number} is credential {number}, which has no nodes yet. "
            f"`.provision {number}` creates one; a NODE is addressed as "
            f"<cred>.<node>" + (f", e.g. {_any_node(node_ids)}" if node_ids else ""),
        )

    m = NODE_ID_RE.match(selector)
    if m:
        number = int(m.group(1))
        return _about(number, f" -- credential {number} has no nodes yet")

    hint = _any_node(node_ids)
    return f" -- node ids look like <cred>.<node>, e.g. {hint}" if hint else ""


def _any_node(node_ids: dict[str, str]) -> str:
    """One real node id to show in a hint, or "" when there are none."""
    return sorted(node_ids.values())[0] if node_ids else ""


def _resolve_range(
    lo: str, hi: str, credentials_by_id: dict[str, Any], nodes_by_id: dict[str, Any]
) -> set[str]:
    """Inclusive range over the flattened `Cred#.Node#` order."""
    ordered = ordered_node_ids(credentials_by_id, nodes_by_id)

    def _bounds(token: str) -> tuple[tuple[int, int], tuple[int, int]]:
        if "." in token:
            cred, _, node = token.partition(".")
            point = (int(cred), int(node))
            return point, point


        return (int(token), 0), (int(token), _UNBOUNDED_NODE)

    lo_low, lo_high = _bounds(lo)
    hi_low, hi_high = _bounds(hi)
    low = min(lo_low, hi_low)
    high = max(lo_high, hi_high)

    matched: set[str] = set()
    for display, node_id in ordered:
        cred, _, node = display.partition(".")
        key = (int(cred), int(node))
        if low <= key <= high:
            matched.add(node_id)
    return matched
