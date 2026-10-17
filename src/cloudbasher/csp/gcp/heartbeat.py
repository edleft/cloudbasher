"""Cloud Shell PTY activity keepalive."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from cloudbasher.core.utils.output import log

DEFAULT_INTERVAL_SECONDS = 20 * 60
MAX_INTERVAL_SECONDS = 30 * 60


@dataclass
class PTYKeepalive:
    stop_event: threading.Event
    thread: Optional[threading.Thread]
    session: Any
    node: Any = None
    pending_failure: Optional[tuple[Any, str]] = None
    handoff_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def attach_session(self, session: Any) -> None:
        self.session = session

    def attach_to_node(self, node: Any) -> None:
        node._runtime_pty_keepalive_stop = self.stop_event
        node._runtime_pty_keepalive_thread = self.thread
        node._runtime_pty_keepalive_attacher = self.attach_session
        with self.handoff_lock:
            self.node = node
            pending_failure = self.pending_failure
            self.pending_failure = None
        if pending_failure is not None:
            session, reason = pending_failure
            _mark_session_unusable(self, session, reason)

    @property
    def node_id(self) -> str:
        return str(getattr(self.node, "id", "unbound"))


def start_pty_keepalive_loop(
    session: Any,
    *,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    stop_event: Optional[threading.Event] = None,
) -> PTYKeepalive:
    """Start node-owned activity on a ready persistent PTY."""
    if interval <= 0 or interval > MAX_INTERVAL_SECONDS:
        raise ValueError(
            f"GCP PTY keepalive interval must be >0 and <= {MAX_INTERVAL_SECONDS}s"
        )
    if stop_event is None:
        stop_event = threading.Event()
    handles = PTYKeepalive(stop_event, None, session)

    def worker() -> None:
        while not stop_event.wait(interval):
            current = handles.session
            try:
                outcome = (
                    current.send_pty_keepalive()
                    if current is not None
                    else "unavailable:session_missing"
                )
                log(
                    f"[gcp.keepalive] event=pty_newline outcome={outcome} "
                    f"interval_seconds={interval:g} node_id={handles.node_id} "
                    f"session_ref={id(current):x}"
                )
                if outcome.startswith("unavailable:"):
                    _mark_session_unusable(handles, current, outcome)
                    break
            except Exception as exc:
                _mark_session_unusable(handles, current, f"write_failed:{type(exc).__name__}")


                break

    thread = threading.Thread(target=worker, name="gcp-pty-keepalive", daemon=True)
    handles.thread = thread
    thread.start()
    return handles


def _mark_session_unusable(handles: PTYKeepalive, session: Any, reason: str) -> None:
    from cloudbasher.core.session.liveness import condemn_node_session

    with handles.handoff_lock:
        node = handles.node
        if node is None:


            handles.pending_failure = (session, reason)
            marked = False
        else:
            marked = condemn_node_session(node, session, reason)
    log(
        f"[gcp.keepalive] event=session_unusable node_id={handles.node_id} "
        f"session_ref={id(session):x} reason={reason} "
        f"recovery_marked={str(marked).lower()}"
    )


def start_session_pty_keepalive(session: Any) -> Optional[PTYKeepalive]:
    """Only real GCP SSH sessions own the transport worker."""
    from cloudbasher.csp.gcp.session import GCPSession

    if not isinstance(session, GCPSession):
        return None
    return start_pty_keepalive_loop(session)


def stop_pty_keepalive_loop(
    stop_event: threading.Event, thread: Optional[threading.Thread] = None
) -> None:
    stop_event.set()
    if thread is not None and thread.is_alive() and threading.current_thread() is not thread:
        thread.join(timeout=2)


def start_heartbeat_loop(
    api: Any,
    environment_id: str,
    interval: int = 300,
    stop_event: Optional[threading.Event] = None,
) -> threading.Thread:
    """Compatibility no-op for the nonexistent public GCP heartbeat API."""
    del api, environment_id, interval
    if stop_event is None:
        stop_event = threading.Event()
    thread = threading.Thread(
        target=stop_event.wait,
        name="gcp-api-heartbeat-noop",
        daemon=True,
    )
    thread.start()
    return thread


def stop_heartbeat_loop(stop_event: threading.Event) -> None:
    stop_event.set()
