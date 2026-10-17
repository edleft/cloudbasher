"""Provider-neutral session liveness signals used by the node supervisor."""

from __future__ import annotations

from typing import Any


def node_session_is_condemned(node: Any) -> bool:
    """Return true only when the node's current handle explicitly says so."""
    if node is None:
        return False
    session = getattr(node, "_runtime_session", None)
    return getattr(session, "is_condemned", False) is True


def condemn_node_session(node: Any, session: Any, reason: str) -> bool:
    """Mark the still-current session unusable after a provider write failure."""
    if node is None or getattr(node, "_runtime_session", None) is not session:
        return False
    condemn = getattr(session, "condemn", None)
    if not callable(condemn):
        return False
    condemn(reason)
    node._last_failure_class = "socket_dead"
    return True
