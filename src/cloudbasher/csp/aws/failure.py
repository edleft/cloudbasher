"""W5 -- one classifier over every layer AWS can fail on."""

from __future__ import annotations

from typing import Any, Callable, Optional

from cloudbasher.core.session.failure import ALL_CLASSES, FailureClass
from cloudbasher.core.session.transport_faults import (
    is_dns_resolution_failure,
    is_fd_exhaustion,
)
from cloudbasher.csp.aws.signing import _EXPIRED_CREDENTIAL_CODES


PERMANENT_ERROR_CODES = frozenset({"AccessDenied", "AccessDeniedException"})


CREDENTIAL_DEAD_ERROR_CODES = _EXPIRED_CREDENTIAL_CODES | frozenset(
    {


        "InvalidAccessKeyId",
        "UnrecognizedClientException",
    }
)


_SOCKET_DEAD_TYPES: tuple[type[BaseException], ...] = (
    BrokenPipeError,
    ConnectionResetError,
    ConnectionAbortedError,
)


_SOCKET_DEAD_TEXT = (
    "websocketconnectionclosed",
    "connection is already closed",
    "connection to remote host was lost",
    "socket is already closed",
)


_SUSPENDED_STATES = frozenset({"SUSPENDED", "SUSPENDING", "STOPPED", "STOPPING"})
_GONE_STATES = frozenset({"DELETED", "ERROR"})


_QUOTA_CONTAINER_CODES = frozenset(
    {
        "LimitExceededException",
        "ServiceQuotaExceededException",


        "ExceedingConcurrentEnvironmentsException",
    }
)


def probe_verdict(exc: Exception) -> tuple[str, str]:
    """A `.creds <ID> perms` row's verdict and reason, from one vocabulary."""
    if isinstance(exc, (TypeError, AttributeError, NameError)):
        return "error", f"probe bug, not a permission answer: {str(exc)[:90]}"

    code = getattr(exc, "error_code", None) or ""
    text = str(exc).replace("\n", " ")
    if not code:
        for known in CREDENTIAL_DEAD_ERROR_CODES | {"SignatureDoesNotMatch", "AccessDenied"}:
            if known.lower() in text.lower():
                code = known
                break

    if code in CREDENTIAL_DEAD_ERROR_CODES:
        return "invalid", f"credential cannot sign ({code})"
    if code == "SignatureDoesNotMatch":


        return "invalid", f"credential cannot sign ({code})"
    return "denied", (code or text[:90])


def classify_failure(
    exc: Optional[BaseException] = None, *, status: Optional[str] = None
) -> FailureClass:
    """One class for a failure, from an exception, an environment status, or both."""
    if status:
        upper = status.upper()
        if upper in _GONE_STATES:
            return "environment_gone"
        if upper in _SUSPENDED_STATES:
            return "environment_suspended"

    if exc is None:
        return "unknown"


    declared = _declared_class(exc)
    if declared is not None:
        return declared  # type: ignore[return-value]


    if getattr(exc, "cb_permanent", False) is True:
        return "access_denied"

    error_code = getattr(exc, "error_code", None) or ""
    status_code = getattr(exc, "status_code", None)

    if error_code == "InvalidStatusException":


        return "environment_suspended"
    if error_code in _QUOTA_CONTAINER_CODES:
        return "quota_containers"
    if status_code == 403 and error_code in PERMANENT_ERROR_CODES:
        return "access_denied"
    if status_code in (401, 403) and error_code in CREDENTIAL_DEAD_ERROR_CODES:
        return "credential_expired"


    if is_fd_exhaustion(exc):
        return "local_resource_exhausted"


    if is_dns_resolution_failure(exc):
        return "dns_unresolvable"

    if isinstance(exc, _SOCKET_DEAD_TYPES):
        return "socket_dead"
    text = f"{type(exc).__name__} {exc}".lower()
    if any(needle in text for needle in _SOCKET_DEAD_TEXT):
        return "socket_dead"


    if status_code is None and not error_code:
        if isinstance(exc, (TimeoutError, OSError)):
            return "network_transient"

    return "unknown"


def _declared_class(exc: BaseException) -> Optional[str]:
    """A class a raiser declared on `exc` or on its explicit CAUSE, if valid."""
    seen: set[int] = set()
    current: Optional[BaseException] = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        declared = getattr(current, "cb_failure_class", None)
        if isinstance(declared, str) and declared in ALL_CLASSES:
            return declared
        current = current.__cause__
    return None


def explain_failure(exc: BaseException) -> tuple[str, str, str]:
    """`(class, human label, what to do)` for a failure a user must act on."""
    from cloudbasher.core.session.failure import is_terminal, label_for, recovery_for

    cls = classify_failure(exc)
    recovery = "" if is_terminal(cls) else recovery_for(cls)
    return cls, label_for(cls), recovery


def failure_sentence(label: str, recovery: str) -> str:
    """`"<label>"`, or `"<label> -- <recovery>"` when there is one."""
    return f"{label} -- {recovery}" if recovery else label


def note_node_failure(
    node: Any,
    exc: BaseException,
    on_node_change: Optional[Callable[[Any], None]] = None,
) -> tuple[str, str]:
    """Mark `node` failed, publish it, and return `(label, sentence)`."""
    try:
        _cls, label, recovery = mark_node_failed(node, exc)
        sentence = failure_sentence(label, recovery)
    except Exception:
        node.container_status = "Failed"
        node.end_connect()
        label, sentence = "unknown", str(exc)
    if on_node_change is not None:
        on_node_change(node)
    return label, sentence


def mark_node_failed(node: Any, exc: BaseException) -> tuple[str, str, str]:
    """Put `node` into Failed with its reason recorded. Returns `explain_failure`."""
    cls, label, recovery = explain_failure(exc)
    node.container_status = "Failed"
    node.end_connect()
    node._last_failure_class = cls
    return cls, label, recovery


_REFUSAL_BODY_CHARS = 400


def refusal_detail(exc: BaseException) -> str:
    """The part of a refusal AWS wrote, ready to append to the part we generated."""
    body = getattr(exc, "response_body", "") or ""
    if not body:
        return ""
    flat = " ".join(body[: _REFUSAL_BODY_CHARS * 10].split())
    if len(flat) > _REFUSAL_BODY_CHARS:
        flat = flat[:_REFUSAL_BODY_CHARS] + "..."
    return f" | AWS said: {flat}"
