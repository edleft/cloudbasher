"""Provider-neutral, process-local control-plane auth evidence."""

from __future__ import annotations

from typing import Any

from cloudbasher.core.types import (
    CONTROL_PLANE_ACCEPTED,
    CONTROL_PLANE_DENIED,
    CONTROL_PLANE_INCONCLUSIVE,
    CONTROL_PLANE_OK,
    CONTROL_PLANE_REJECTED,
    CONTROL_PLANE_UNASKED,
    CONTROL_PLANE_UNCONFIRMED,
    CONTROL_PLANE_UNOBSERVABLE,
)

_VALID = frozenset(
    {
        CONTROL_PLANE_UNASKED,
        CONTROL_PLANE_ACCEPTED,
        CONTROL_PLANE_REJECTED,
        CONTROL_PLANE_DENIED,
        CONTROL_PLANE_INCONCLUSIVE,
    }
)


def record_control_plane_evidence(node: Any, observation: str) -> str:
    """Store one normalized observation on its owning live node."""
    if observation not in _VALID:
        raise ValueError(f"unknown control-plane observation: {observation!r}")
    node._runtime_control_plane_evidence = observation
    return observation


def normalize_control_plane_evidence(observation: Any) -> str:
    """Map legacy AWS presign verdicts into the shared evidence vocabulary."""
    value = str(observation or "")
    if value in {CONTROL_PLANE_OK, CONTROL_PLANE_ACCEPTED}:
        return CONTROL_PLANE_ACCEPTED
    if value == CONTROL_PLANE_REJECTED:
        return CONTROL_PLANE_REJECTED
    if value == CONTROL_PLANE_DENIED:
        return CONTROL_PLANE_DENIED
    if value in {CONTROL_PLANE_UNCONFIRMED, CONTROL_PLANE_UNOBSERVABLE, CONTROL_PLANE_INCONCLUSIVE}:
        return CONTROL_PLANE_INCONCLUSIVE
    return CONTROL_PLANE_UNASKED


def classify_control_plane_exception(exc: BaseException) -> str:
    """Classify only structured auth outcomes; all other failures are unknown."""
    status = getattr(exc, "status_code", None)
    error_code = str(getattr(exc, "error_code", "") or "").lower()
    if status == 401 or error_code in {"invalid_token", "unauthorized", "invalid_grant"}:
        return CONTROL_PLANE_REJECTED
    if status == 403 or error_code in {"accessdenied", "permission_denied", "forbidden"}:
        return CONTROL_PLANE_DENIED
    return CONTROL_PLANE_INCONCLUSIVE


__all__ = [
    "classify_control_plane_exception",
    "normalize_control_plane_evidence",
    "record_control_plane_evidence",
]
