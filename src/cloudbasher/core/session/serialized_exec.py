"""One command at a time on one session -- and a diagnosis when you had to wait."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Callable, Iterator

from cloudbasher.core.session.activity import SessionActivity
from cloudbasher.core.utils.output import log


class SerializedExec:
    """Mixin giving a session an exec lock and a published `SessionActivity`."""


    _EXEC_LABEL: str = "session"

    def _init_exec_serialization(self) -> None:
        """Call from `__init__`. Separate from `__init__` because these sessions take long keyword-only constructor signatures and do not cooperate via `super().__init__()`; an explicit call is one line and cannot be silently skipped by a signature change."""


        self._exec_lock = threading.RLock()
        self.activity: SessionActivity = SessionActivity.IDLE
        self.on_activity_change: Callable[[], None] = lambda: None

        self._activity_depth: int = 0

    def _publish(self, activity: SessionActivity) -> None:
        """Rebind `activity` and ask for a repaint. Never raises."""
        self.activity = activity
        try:
            self.on_activity_change()
        except Exception:
            pass

    @contextmanager
    def _serialized_exec(self, command: str, wait_budget: float) -> Iterator[None]:
        """Hold the exec lock for `command`, publishing running/idle around it."""
        from cloudbasher.core.exceptions import SessionError

        if not self._exec_lock.acquire(blocking=False):


            log(f"{self._EXEC_LABEL}: command queued behind a running one " f"command={command!r}")
            if not self._exec_lock.acquire(timeout=wait_budget):
                raise SessionError(
                    f"another command is still running on this session; waited "
                    f"{wait_budget:.0f}s for it to finish"
                )


        outermost = self._activity_depth == 0
        self._activity_depth += 1
        if outermost:
            self._publish(SessionActivity.running(command))
        try:
            yield
        finally:
            self._activity_depth -= 1
            if self._activity_depth == 0:
                self._publish(self.activity.idle())
            self._exec_lock.release()
