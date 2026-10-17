"""Raise this process's open-file limit, and say what it got"""

from __future__ import annotations

import errno
import os
import sys
from typing import Callable, NamedTuple, Optional

try:
    import resource
except ImportError:  # pragma: no cover -- exercised on Windows, not here
    resource = None  # type: ignore[assignment]


DEFAULT_TARGET = 65536


_LADDER = (1048576, 184320, 131072, 65536, 32768, 10240, 8192, 4096, 2048, 1024)


FLEET_FLOOR = 1024


class LimitResult(NamedTuple):
    """What we found, what we got, and whether the user needs to act."""

    supported: bool
    before: Optional[int]
    after: Optional[int]
    hard: Optional[int]
    raised: bool
    adequate: bool
    note: str

    def summary(self) -> str:
        if not self.supported:
            return f"open files: not limited on this platform ({self.note})"
        if self.raised:
            return (
                f"open files: soft limit {self.before} -> {self.after} (hard {self._hard_text()})"
            )
        return f"open files: soft limit {self.after} (hard {self._hard_text()}), unchanged"

    def _hard_text(self) -> str:
        if resource is not None and self.hard == getattr(resource, "RLIM_INFINITY", -1):
            return "unlimited"
        return str(self.hard)

    def advice(self) -> str:
        """What the user can do, when we could not get enough. Platform-specific because the remedy is, even though the problem is not."""
        if self.adequate or not self.supported:
            return ""
        if sys.platform == "darwin":
            return (
                "Raise it for the shell with `ulimit -n 65536` before running, or "
                "system-wide with `sudo launchctl limit maxfiles 65536 unlimited`."
            )
        if sys.platform.startswith("linux"):
            return (
                "The HARD limit is the cap and a process cannot raise its own. "
                "Try `ulimit -Hn`; raise it in /etc/security/limits.conf, or with "
                "`LimitNOFILE=` in the systemd unit, or `--ulimit nofile=` on the "
                "container."
            )
        return "Raise the process open-file limit for this shell before running."


def _try_set(soft: int, hard: Optional[int]) -> bool:
    assert resource is not None
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard if hard is not None else soft))
        return True
    except (ValueError, OSError):
        return False


def raise_soft_limit(
    target: int = DEFAULT_TARGET, _setter: Optional[Callable[[int, Optional[int]], bool]] = None
) -> LimitResult:
    """Raise the soft descriptor limit toward `target`. Never raises."""
    try:
        return _raise_soft_limit(target, _setter)
    except Exception as exc:  # noqa: BLE001


        return LimitResult(False, None, None, None, False, True, f"limit check failed: {exc!r}")


def _raise_soft_limit(
    target: int, _setter: Optional[Callable[[int, Optional[int]], bool]] = None
) -> LimitResult:
    setter = _setter or _try_set
    if resource is None or not hasattr(resource, "RLIMIT_NOFILE"):
        return LimitResult(
            supported=False,
            before=None,
            after=None,
            hard=None,
            raised=False,
            adequate=True,
            note=(
                "sockets are handles here, bounded by the process handle table "
                "rather than by a descriptor rlimit"
            ),
        )

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft >= target:
        return LimitResult(True, soft, soft, hard, False, soft >= FLEET_FLOOR, "already sufficient")


    unlimited = hard == resource.RLIM_INFINITY


    wanted = [target] + [r for r in _LADDER if r < target]
    for rung in wanted:
        if rung <= soft:
            continue
        if not unlimited and rung > hard:
            continue
        if setter(rung, hard):
            return LimitResult(
                True,
                soft,
                rung,
                hard,
                True,
                rung >= FLEET_FLOOR,
                "raised" if rung >= target else f"capped below the {target} requested",
            )

    return LimitResult(
        True,
        soft,
        soft,
        hard,
        False,
        soft >= FLEET_FLOOR,
        "could not raise it -- every candidate was refused",
    )


NO_DESCRIPTOR_ERRNOS: frozenset[int] = frozenset({errno.EMFILE, errno.ENFILE})


_TABLE_FULL_NOTE = "TABLE FULL"


_PRESSURE_FRACTION = 0.9


def open_descriptor_count() -> tuple[Optional[int], str]:
    """Roughly how many descriptors this process holds, in O(1)."""
    try:
        fd = os.open(os.devnull, os.O_RDONLY)
    except OSError as exc:
        if exc.errno in NO_DESCRIPTOR_ERRNOS:
            return None, f"{_TABLE_FULL_NOTE} (errno={exc.errno}) -- cannot open even one more"
        return None, f"probe failed: errno={exc.errno}"
    try:
        return fd, ""
    finally:
        os.close(fd)


def under_descriptor_pressure() -> bool:
    """Is this process near or at its descriptor limit, right now?"""
    count, note = open_descriptor_count()
    if count is None:


        return note.startswith(_TABLE_FULL_NOTE)
    limit = current_soft_limit()
    if limit is None or limit <= 0:


        return False
    return count >= limit * _PRESSURE_FRACTION


def accurate_descriptor_count() -> Optional[int]:
    """An exact count, for the few moments it is worth O(n) to have one."""
    try:
        return len(os.listdir("/dev/fd"))
    except OSError:
        return None


def current_soft_limit() -> Optional[int]:
    """The soft limit as it stands NOW, or None where the concept does not apply."""
    if resource is None or not hasattr(resource, "RLIMIT_NOFILE"):
        return None
    try:
        return int(resource.getrlimit(resource.RLIMIT_NOFILE)[0])
    except Exception:  # noqa: BLE001 -- a diagnostic must not raise
        return None
