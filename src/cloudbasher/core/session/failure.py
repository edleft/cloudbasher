"""The failure taxonomy: what went wrong, and whether waiting can fix it."""

from __future__ import annotations

from typing import Literal, get_args


FailureClass = Literal[
    "network_transient",


    "dns_unresolvable",


    "local_resource_exhausted",
    "socket_dead",
    "credential_expired",
    "environment_suspended",
    "environment_gone",
    "quota_containers",
    "quota_hours",
    "access_denied",


    "credentials_not_projected",


    "not_provisioned",


    "console_presign_refused",
    "unknown",
]


CREDENTIALS_NOT_PROJECTED = "credentials_not_projected"


CONSOLE_PRESIGN_REFUSED = "console_presign_refused"


ALL_CLASSES: frozenset[str] = frozenset(get_args(FailureClass))


TERMINAL: frozenset[str] = frozenset(
    {
        "quota_containers",
        "quota_hours",
        "access_denied",
        "not_provisioned",


        "console_presign_refused",
    }
)


_CREDENTIAL_OWNED: frozenset[str] = frozenset({"credential_expired", "credentials_not_projected"})


_NEEDS_CONTROL_PLANE: frozenset[str] = frozenset({"environment_suspended", "environment_gone"})


SESSION_REBUILDABLE: frozenset[str] = (
    ALL_CLASSES - TERMINAL - _CREDENTIAL_OWNED - _NEEDS_CONTROL_PLANE - {"dns_unresolvable"}
)


RECOVERY: dict[str, str] = {
    "credentials_not_projected": (
        "reconnect the node to re-project, or wait for the keepalive to do it"
    ),
    "network_transient": "retry in place with backoff; do NOT escalate",
    "dns_unresolvable": "check DNS/network; do NOT back off -- a retry re-queries the resolver",
    "local_resource_exhausted": (
        "stop opening sockets process-wide and let descriptors free; do NOT retry -- "
        "every attempt consumes another"
    ),
    "socket_dead": "createSession -> new socket; environment untouched",
    "credential_expired": "re-derive (key) or re-login (console)",
    "environment_suspended": "startEnvironment, poll to RUNNING, new session",
    "environment_gone": "createEnvironment -- but check quota first",
    "unknown": "bounded retry, then treat as socket_dead once",


}


LABEL: dict[str, str] = {
    "credentials_not_projected": "no credentials in the container",
    "network_transient": "network blip",
    "dns_unresolvable": "cannot resolve endpoint (DNS)",
    "local_resource_exhausted": "out of file descriptors",
    "socket_dead": "socket dead",
    "credential_expired": "credential expired",
    "environment_suspended": "container suspended",
    "environment_gone": "container gone",
    "quota_containers": "region full (10 containers)",
    "quota_hours": "monthly hours exhausted",
    "access_denied": "access denied",
    "unknown": "unknown failure",
    "not_provisioned": "never provisioned",


    "console_presign_refused": "console cannot presign (HTTP 401)",
}


ENVIRONMENT_WIDE: frozenset[str] = frozenset(
    {
        "dns_unresolvable",
        "local_resource_exhausted",
    }
)


def is_environment_wide(cls: str) -> bool:
    """Does `cls` mean the NEXT node would fail for the same reason?"""
    return cls in ENVIRONMENT_WIDE


def is_session_rebuildable(cls: str) -> bool:
    """Can a plain `createSession` plausibly clear this? Mirrors `is_terminal`."""
    return cls == "" or cls in SESSION_REBUILDABLE


def is_terminal(cls: str) -> bool:
    """Is this class beyond recovery? Unrecognised classes are NOT terminal."""
    return cls in TERMINAL


def recovery_for(cls: str) -> str:
    """One line on what to do about `cls`, or a bounded-retry default."""
    return RECOVERY.get(cls, RECOVERY["unknown"])


def label_for(cls: str) -> str:
    """Human-facing text for `cls`. Falls back to the class name itself, which is ugly but never misleading -- unlike a generic "error", which would erase the one piece of information the classifier just produced."""
    return LABEL.get(cls, cls)
