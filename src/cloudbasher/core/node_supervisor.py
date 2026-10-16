"""The thing that reads the mark."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional

from cloudbasher.core.session.failure import is_session_rebuildable, is_terminal
from cloudbasher.core.session.keepalive_policy import (
    recovers_container,
    recovers_session,
)
from cloudbasher.core.types import node_socket_is_dead
from cloudbasher.core.utils.output import detail, log
from cloudbasher.core.utils.timeline import mark as timeline_mark
from cloudbasher.core.utils.perf_config import (
    get_supervisor_max_recoveries,
    get_supervisor_poll_seconds,
)


_BACKOFF_SECONDS: tuple[float, ...] = (0.0, 15.0, 60.0, 300.0)


_MAX_ATTEMPTS_AT_TOP = 4


_MAX_FAILURES = len(_BACKOFF_SECONDS) - 1 + _MAX_ATTEMPTS_AT_TOP


_PAUSE_RECHECK_SECONDS = 30.0


class _NodeAttempts:
    """One node's ladder position. Supervisor-owned, deliberately."""

    __slots__ = ("failures", "next_attempt_at", "abandoned_because")

    def __init__(self) -> None:
        self.failures = 0
        self.next_attempt_at = 0.0
        self.abandoned_because: str = ""


_MARK_SOCKET_DEAD = "socket_dead"
_MARK_CONTAINER_FAILED = "container_failed"


def _mark_of(node: Any) -> str:
    """Which mark is up on `node`, or `""` if it is not broken at all."""
    if node_socket_is_dead(node):
        return _MARK_SOCKET_DEAD
    from cloudbasher.core.session.liveness import node_session_is_condemned

    if node_session_is_condemned(node):
        return _MARK_SOCKET_DEAD
    if getattr(node, "container_status", "") == "Failed":
        return _MARK_CONTAINER_FAILED
    return ""


def _policy_allows(mark: str, node: Any) -> bool:
    """Does this node's keepalive policy WANT the supervisor to repair `mark`?"""
    if mark == _MARK_SOCKET_DEAD:
        return recovers_session(node)
    return recovers_container(node)


def _is_eligible(mark: str, node: Any) -> bool:
    """Can the gateway plausibly fix THIS mark, given the recorded class?"""
    cls = getattr(node, "_last_failure_class", "") or ""
    if mark == _MARK_SOCKET_DEAD:
        return is_session_rebuildable(cls)
    return not is_terminal(cls)


class NodeSupervisor:
    """One thread per multi-node TUI mount, not one per node."""

    def __init__(
        self,
        state: Any,
        *,


        poll_seconds: Optional[float] = None,
        max_recoveries: Optional[int] = None,


        should_recover: Optional[Callable[[str, Any], bool]] = None,
    ) -> None:
        self._state = state
        self._poll_seconds = (
            poll_seconds if poll_seconds is not None else get_supervisor_poll_seconds()
        )
        self._max_recoveries = max(
            1, max_recoveries if max_recoveries is not None else get_supervisor_max_recoveries()
        )
        self._should_recover = should_recover or _policy_allows

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None


        self._lock = threading.Lock()
        self._attempts: dict[str, _NodeAttempts] = {}


        self._in_flight: set[str] = set()
        self._paused_until = 0.0
        self._pool: Optional[ThreadPoolExecutor] = None


    def start(self) -> None:
        """Begin polling. Called from `on_mount()`, after the app is mounted."""
        if self._thread is not None:
            return
        self._pool = ThreadPoolExecutor(
            max_workers=self._max_recoveries, thread_name_prefix="node-recover"
        )
        self._thread = threading.Thread(target=self._run, name="node-supervisor", daemon=True)
        self._thread.start()
        detail(
            f"[supervisor] started poll={self._poll_seconds}s "
            f"max_recoveries={self._max_recoveries}"
        )

    def stop(self, *, timeout: float = 2.0) -> None:
        """Signal and join. Safe to call twice, and safe if never started."""
        self._stop.set()
        pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=timeout)
            if thread.is_alive():
                log("[supervisor] did not stop in time")


    def describe(self, node_id: str) -> str:
        """Why this node is not being retried, or "" if that is not the case."""
        with self._lock:
            entry = self._attempts.get(node_id)
            return entry.abandoned_because if entry else ""


    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:
                log(f"[supervisor] poll failed: {exc}")
            self._stop.wait(self._poll_seconds)

    def _tick(self) -> None:
        now = self._now()
        if now < self._paused_until:
            return
        due = self._due(now)
        if not due:
            return
        pool = self._pool
        if pool is None:
            return


        for node, mark in due:
            try:
                pool.submit(self._recover, node, mark)
            except RuntimeError:


                with self._lock:


                    self._in_flight.difference_update(n.id for n, _mark in due)
                return

    def _due(self, now: float) -> list[tuple[Any, str]]:
        """Every node that is marked dead, idle, past its backoff and eligible."""


        from cloudbasher.core.cli.dispatcher import session_busy_reason

        nodes_by_id = getattr(self._state, "nodes_by_id", None) or {}


        due: list[tuple[Any, str]] = []
        with self._lock:


            for stale in [k for k in self._attempts if k not in nodes_by_id]:
                self._attempts.pop(stale, None)
            for node_id, node in nodes_by_id.items():
                if node_id in self._in_flight:
                    continue
                mark = _mark_of(node)
                if not mark:


                    self._attempts.pop(node_id, None)
                    continue
                if getattr(node, "_disconnecting", False):
                    continue


                if session_busy_reason(node) is not None:
                    continue


                if not _is_eligible(mark, node):
                    continue
                entry = self._attempts.setdefault(node_id, _NodeAttempts())
                if entry.abandoned_because or now < entry.next_attempt_at:
                    continue
                self._in_flight.add(node_id)
                due.append((node, mark))


        keep: list[tuple[Any, str]] = []
        drop: list[Any] = []
        for node, mark in due:
            if self._should_recover(mark, node):


                keep.append((node, mark))
            else:
                drop.append(node)
        if drop:
            with self._lock:
                self._in_flight.difference_update(n.id for n in drop)
        return keep

    def _recover(self, node: Any, mark: str) -> None:
        """One attempt, through the gateway. Never raises into the pool."""
        node_id = node.id


        if self._now() < self._paused_until or self._stop.is_set():
            with self._lock:
                self._in_flight.discard(node_id)
            return


        node.clear_queued()
        try:
            from cloudbasher.core.cli.dispatcher import ensure_node_session


            _session, err = ensure_node_session(self._state.csp_provider, self._state, node)
            if err:
                self._failed(node, mark, str(err))
            else:
                self._succeeded(node, mark)
        except Exception as exc:


            from cloudbasher.core.cli.dispatcher import _mark_failed_best_effort

            _mark_failed_best_effort(node, exc)
            self._failed(node, mark, f"{type(exc).__name__}: {exc}")
        finally:
            with self._lock:
                self._in_flight.discard(node_id)
            self._republish(node)


    def _succeeded(self, node: Any, mark: str) -> None:
        with self._lock:
            self._attempts.pop(node.id, None)


        node._runtime_supervisor_abandoned = ""


        log(f"[supervisor] recovered {node.id} ({mark})")


        timeline_mark("supervisor.recovered", node=node.id, mark=mark)

    def _failed(self, node: Any, mark: str, why: str) -> None:


        if node._last_failure_class == "local_resource_exhausted":
            self._pause_globally()
            return

        with self._lock:
            entry = self._attempts.setdefault(node.id, _NodeAttempts())
            entry.failures += 1
            rung = min(entry.failures, len(_BACKOFF_SECONDS) - 1)
            entry.next_attempt_at = self._now() + _BACKOFF_SECONDS[rung]
            if entry.failures >= _MAX_FAILURES:
                entry.abandoned_because = (
                    f"recovery abandoned after {_MAX_ATTEMPTS_AT_TOP} attempts at the "
                    f"longest backoff; last failure: {why}"
                )
                giving_up = entry.abandoned_because
            else:
                giving_up = ""


        if giving_up:
            node._runtime_supervisor_abandoned = giving_up


            log(f"[supervisor] {node.id} ({mark}): {giving_up}")
            timeline_mark("supervisor.abandoned", node=node.id, mark=mark, why=why)
        else:
            detail(f"[supervisor] {node.id} ({mark}) attempt failed, backing off: {why}")
            timeline_mark("supervisor.backoff", node=node.id, mark=mark, why=why)

    def _pause_globally(self) -> None:


        now = self._now()
        already = self._paused_until > now
        self._paused_until = now + _PAUSE_RECHECK_SECONDS
        if not already:


            log(
                "[supervisor] paused: out of file descriptors. No node may open "
                "a socket until they free."
            )


    def _republish(self, node: Any) -> None:
        """The ONLY route to the UI. The supervisor never touches a widget."""
        callback = getattr(self._state, "on_node_change", None)
        if callback is None:
            return
        try:
            callback(node)
        except Exception as exc:
            detail(f"[supervisor] republish failed for {node.id}: {exc}")

    @staticmethod
    def _now() -> float:
        return time.monotonic()
