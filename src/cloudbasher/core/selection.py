"""What "selected" means, in ONE place."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pragma: no cover
    from cloudbasher.core.types import CredentialRecord, InteractiveState


def originating_for_node(
    state: "InteractiveState",
    node_id: Optional[str],
    *,
    provider: Optional[str] = None,
) -> Optional["CredentialRecord"]:
    """The originating record behind one node, walking a target back to its root."""
    node = state.nodes_by_id.get(node_id) if node_id else None
    if node is None:
        return None
    from cloudbasher.core.tui.widgets.node_table import resolve_credential_display

    _kind, _ident, _target, root = resolve_credential_display(
        node.credential_id, state.credentials_by_id
    )
    for candidate in (root, state.credentials_by_id.get(node.credential_id)):
        if candidate is None or candidate.role != "originating":
            continue
        if provider is not None and candidate.provider != provider:
            continue
        return candidate
    return None


def selected_credential_records(
    state: "InteractiveState", *, provider: Optional[str] = None
) -> list["CredentialRecord"]:
    """Every credential the user has selected, by EITHER gesture, deduped."""
    ordered: dict[str, "CredentialRecord"] = {}

    for rec_id in state.selected_credential_ids:
        rec = state.credentials_by_id.get(rec_id)
        if rec is None or rec.role != "originating":
            continue
        if provider is not None and rec.provider != provider:
            continue
        ordered[rec.id] = rec

    for node_id in state.selected_node_ids:
        rec = originating_for_node(state, node_id, provider=provider)
        if rec is not None:
            ordered[rec.id] = rec


    position = {rec_id: i for i, rec_id in enumerate(state.credentials_by_id)}
    return sorted(ordered.values(), key=lambda rec: position.get(rec.id, len(position)))


def implicit_credential_records(
    state: "InteractiveState", *, provider: Optional[str] = None
) -> list["CredentialRecord"]:
    """What an **omitted** credential slot resolves to. `[]` means "fall through"."""
    return selected_credential_records(state, provider=provider)


def selected_credential_ids(
    state: "InteractiveState", *, provider: Optional[str] = None
) -> set[str]:
    """`selected_credential_records` as an id set, for callers that only test."""
    return {rec.id for rec in selected_credential_records(state, provider=provider)}


def resolve_numbered_selector(
    numbered: "list[tuple[int, Any]]", token: str
) -> "tuple[list[tuple[int, Any]], list[str], list[str]]":
    """THE `1,3,5` grammar over a `numbered_originating_records()` listing."""
    by_num = {n: rec for n, rec in numbered}
    picked: "dict[int, tuple[int, Any]]" = {}
    unknown: list[str] = []
    malformed: list[str] = []
    for raw in token.split(","):
        part = raw.strip()
        if not part.isdigit():
            malformed.append(part)
        elif int(part) not in by_num:
            unknown.append(part)
        else:
            picked.setdefault(int(part), (int(part), by_num[int(part)]))
    return [picked[n] for n in sorted(picked)], unknown, malformed


def nothing_selected_message(noun: str = "credential") -> str:
    """Why an empty `selected` refused, and what to do about it."""
    return (
        f"nothing is selected -- no {noun} rows are checked. "
        "Check rows in the Credentials pane (`space`, or `a` for all), "
        "or name them explicitly like `1,3,5`."
    )


__all__ = [
    "nothing_selected_message",
    "resolve_numbered_selector",
    "originating_for_node",
    "selected_credential_ids",
    "selected_credential_records",
]
