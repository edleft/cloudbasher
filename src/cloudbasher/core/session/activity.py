"""What a session is doing right now, as one immutable value."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, replace
from typing import ClassVar, Literal, Optional


Phase = Literal["idle", "running", "recovering"]


@dataclass(frozen=True, slots=True)
class SessionActivity:
    """A snapshot of what one session is doing. Immutable; rebound, never mutated."""

    phase: Phase = "idle"


    owner_thread: int = 0


    argv0: str = ""

    started_at: float = 0.0


    deadline: Optional[float] = None

    rebuilds: int = 0
    attempts: int = 0


    recovered_at: Optional[float] = None
    recovery_seconds: float = 0.0

    IDLE: ClassVar["SessionActivity"]


    @classmethod
    def running(cls, command: str) -> "SessionActivity":
        return cls(
            phase="running",
            owner_thread=threading.get_ident(),
            argv0=(command.strip().split() or [""])[0],
            started_at=time.monotonic(),
        )

    def recovering(self, deadline: float) -> "SessionActivity":
        """Enter recovery, keeping the owner and argv0 of the command that hit it."""
        return replace(
            self,
            phase="recovering",
            deadline=deadline,
            started_at=time.monotonic(),
            rebuilds=0,
            attempts=0,
        )

    def recovered(self, elapsed: float) -> "SessionActivity":
        """Leave recovery for ``running`` -- NOT for idle."""
        return replace(
            self,
            phase="running",
            deadline=None,
            rebuilds=0,
            attempts=0,
            recovered_at=time.monotonic(),
            recovery_seconds=elapsed,
        )

    def idle(self) -> "SessionActivity":
        """Return to idle, PRESERVING the recovery aftermath fields (see above)."""
        return SessionActivity(
            recovered_at=self.recovered_at,
            recovery_seconds=self.recovery_seconds,
        )


    def seconds_left(self, now: Optional[float] = None) -> float:
        if self.deadline is None:
            return 0.0
        return max(0.0, self.deadline - (now if now is not None else time.monotonic()))

    def connection_state(self) -> Optional[str]:
        """What `_connection_state()` should return, or None to defer to it."""
        return "Recovering" if self.phase == "recovering" else None

    def busy_reason(self, *, caller_thread: int) -> Optional[str]:
        """Why *someone else's* work here blocks new work, or None."""
        if self.phase == "idle" or self.owner_thread == caller_thread:
            return None
        if self.phase == "recovering":
            return (
                "the shell stopped executing and is being rebuilt -- "
                f"{self.seconds_left():.0f}s of the recovery budget left"
            )
        name = f" ({self.argv0})" if self.argv0 else ""
        return f"a command is already running on this node{name}"

    def detail(self) -> str:
        """The status-line suffix, or "" when there is nothing worth saying."""
        if self.phase != "recovering":
            return ""
        return (
            f"({self.rebuilds} socket(s), {self.attempts} probes, "
            f"{self.seconds_left():.0f}s left)"
        )


SessionActivity.IDLE = SessionActivity()


def activity_of(node: object) -> Optional[SessionActivity]:
    """The live ``SessionActivity`` behind a node, or None when there is none."""
    return activity_from(getattr(node, "_runtime_session", None))


def activity_from(session: object) -> Optional[SessionActivity]:
    """The same guard, applied directly to a session object."""
    activity = getattr(session, "activity", None)
    return activity if isinstance(activity, SessionActivity) else None
