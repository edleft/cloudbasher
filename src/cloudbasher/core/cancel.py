"""Cancelling a command that is already running -- `#433`."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Callable, Iterator, Optional


class CancellationToken:
    """One command's stop signal, plus the counts its report needs."""

    __slots__ = (
        "_label",
        "_lock",
        "_cancelled",
        "_reason",
        "_started",
        "_finished",
        "_skipped",
        "_total",
        "_verb",
    )

    def __init__(self, label: str = "") -> None:
        self._label = label
        self._reason = ""
        self._lock = threading.Lock()
        self._cancelled = False
        self._started = 0
        self._finished = 0
        self._skipped = 0


        self._total = 0
        self._verb = ""

    @property
    def label(self) -> str:
        return self._label

    @property
    def total(self) -> int:
        """Size of the current fan-out's selection, or 0 if none declared it."""
        with self._lock:
            return self._total

    @property
    def verb(self) -> str:
        """The fan-out's OWN verb -- `"delete"`, never `".delete"`."""
        with self._lock:
            return self._verb

    def describe(self, total: int, verb: str) -> tuple[int, str]:
        """Set `(total, verb)` together; RETURN the pair that was there."""
        with self._lock:
            previous = (self._total, self._verb)
            self._total, self._verb = max(0, int(total)), verb
        return previous

    @property
    def settled(self) -> int:
        """Finished plus skipped -- nodes the fan-out will not touch again."""
        _started, finished, skipped = self.counts
        return finished + skipped

    @property
    def cancelled(self) -> bool:
        """Read without the lock, deliberately."""
        return self._cancelled

    @property
    def reason(self) -> str:
        """Why it stopped, or "" for a plain Ctrl-C (`#466`)."""
        return self._reason

    def cancel(self, reason: str = "") -> bool:
        """Signal stop. Returns False if it was ALREADY cancelled."""
        with self._lock:
            if self._cancelled:
                return False
            self._cancelled = True
            self._reason = reason
            return True

    def note_started(self) -> None:
        with self._lock:
            self._started += 1

    def note_finished(self) -> None:
        with self._lock:
            self._finished += 1

    def note_skipped(self) -> None:
        with self._lock:
            self._skipped += 1

    @property
    def counts(self) -> tuple[int, int, int]:
        """`(started, finished, skipped)`, read consistently."""
        with self._lock:
            return self._started, self._finished, self._skipped

    @property
    def running(self) -> int:
        """Started and not yet finished."""
        started, finished, _ = self.counts
        return max(0, started - finished)

    def report(self) -> str:
        """One line: what was stopped, and what was left running."""
        if not self._cancelled:
            return ""
        started, finished, skipped = self.counts
        running = max(0, started - finished)
        parts = [f"{skipped} not started"]
        if running:
            parts.append(f"{running} still finishing (left to complete, not killed)")
        parts.append(f"{finished} already done")
        why = f" -- {self._reason}" if self._reason else ""
        return f"Cancelled {self._label or 'command'}{why}: " + ", ".join(parts)


_current: Optional[CancellationToken] = None
_current_lock = threading.Lock()


def begin_operation(label: str = "") -> Optional[CancellationToken]:
    """Make a fresh token current, or return None if one already is."""
    global _current
    with _current_lock:


        if _current is not None:
            return None
        _current = CancellationToken(label)
        return _current


def end_operation(token: Optional[CancellationToken]) -> None:
    """Clear `token` if it is the current one. Safe to call with None."""
    global _current
    with _current_lock:
        if token is not None and _current is token:
            _current = None


def current_operation() -> Optional[CancellationToken]:
    """The running command's token, or None outside a dispatched command."""
    return _current


def is_cancelled() -> bool:
    """The one-liner a fan-out worker needs. False when nothing is running."""
    token = _current
    return token is not None and token.cancelled


def request_cancel(reason: str = "") -> tuple[bool, str]:
    """Cancel whatever is running. Returns `(did_cancel, message)`."""
    token = _current
    if token is None:
        return False, ""
    what = token.label or "the running command"
    if not token.cancel(reason):
        why = f" ({token.reason})" if token.reason else ""
        return False, (
            f"Already cancelling {what}{why} -- "
            f"{token.running} node(s) still finishing. "
            "They are being left to complete rather than killed, so that "
            "anything already created is recorded."
        )
    why = f" -- {reason}" if reason else ""
    return True, (
        f"Cancelling {what}{why}: no further nodes will be started; "
        f"{token.running} already running will be left to finish."
    )


class OperationCancelled(Exception):
    """Raised (or returned) by a pool worker that Ctrl-C reached before it started. NOT a failure, and the distinction is the whole point."""


def was_cancelled(exc: object) -> bool:
    """Is `exc` a node that was stopped rather than one that broke?"""
    return isinstance(exc, OperationCancelled)


def skip_if_cancelled() -> bool:
    """True if the caller should return WITHOUT doing its unit of work."""
    token = _current
    if token is None or not token.cancelled:
        return False
    token.note_skipped()
    return True


@contextmanager
def in_flight() -> Iterator[None]:
    """Count the enclosed work as started, and as finished however it exits."""
    token = _current
    if token is None:
        yield
        return
    token.note_started()
    try:
        yield
    finally:
        token.note_finished()


@contextmanager
def declaring_fanout(total: int, verb: str) -> Iterator[None]:
    """Describe the enclosed fan-out on the current token, and undo it on exit."""
    token = _current
    if token is None:
        yield
        return
    previous = token.describe(total, verb)
    try:
        yield
    finally:
        token.describe(*previous)


def report_cancellation(emit: Callable[[str], None]) -> None:
    """Print the current token's cancellation report, if there is one."""
    token = current_operation()
    if token is None:
        return
    report = token.report()
    if report:
        emit(report)


def reset_for_tests() -> None:
    """Drop any current token. Process-wide state needs a reset hook, for the same reason `output.reset_log_repeat_state()` does: a test that leaves a cancelled token current would silently skip every fan-out after it."""
    global _current
    with _current_lock:
        _current = None
