"""Faults a client can detect LOCALLY, from a transport attempt's exception."""

from __future__ import annotations

import socket
from typing import Iterator

from cloudbasher.core.utils.fd_limit import NO_DESCRIPTOR_ERRNOS, under_descriptor_pressure

__all__ = ["is_dns_resolution_failure", "is_fd_exhaustion"]


def _exception_chain(exc: BaseException) -> Iterator[BaseException]:
    """Every exception reachable from `exc`, each once."""
    seen: set[int] = set()
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))


        yield current
        for nxt in (current.__cause__, current.__context__, getattr(current, "reason", None)):
            if isinstance(nxt, BaseException):
                pending.append(nxt)
        for arg in getattr(current, "args", ()):
            if isinstance(arg, BaseException):
                pending.append(arg)


def is_dns_resolution_failure(exc: BaseException) -> bool:
    """Did the NAME fail to resolve, as opposed to the backend answering badly?"""
    for current in _exception_chain(exc):
        if isinstance(current, socket.gaierror):
            return True
        if type(current).__name__ == "NameResolutionError":
            return True
    text = str(exc)
    return "NameResolutionError" in text or "Failed to resolve" in text


def is_fd_exhaustion(exc: BaseException) -> bool:
    """Did this fail because the PROCESS ran out of file descriptors?"""
    for current in _exception_chain(exc):
        if not isinstance(current, OSError):
            continue
        if current.errno in NO_DESCRIPTOR_ERRNOS:
            return True
        if "too many open files" in str(current).lower():
            return True
    return is_dns_resolution_failure(exc) and under_descriptor_pressure()
