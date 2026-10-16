"""Azure's observed terminal-WebSocket relay keepalive."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from cloudbasher.core.utils.output import detail, log

DEFAULT_INTERVAL_SECONDS = 1.0


@dataclass
class RelayKeepalive:
    stop_event: threading.Event
    thread: Optional[threading.Thread]
    session: Any
    node: Any = None
    pending_failure: Optional[tuple[Any, str, Optional[str]]] = None
    handoff_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def attach_to_node(self, node: Any) -> None:
        node._runtime_relay_keepalive_stop = self.stop_event
        node._runtime_relay_keepalive_thread = self.thread
        node._runtime_relay_keepalive_attacher = self.attach_session
        with self.handoff_lock:
            self.node = node
            pending_failure = self.pending_failure
            self.pending_failure = None
        if pending_failure is not None:
            session, reason, error_type = pending_failure
            _fail(self, session, reason, error_type)

    @property
    def node_id(self) -> str:
        return str(getattr(self.node, "id", "unbound"))

    def attach_session(self, session: Any) -> None:
        self.session = session


def start_relay_keepalive_loop(
    session: Any,
    *,
    interval: float = DEFAULT_INTERVAL_SECONDS,
    stop_event: Optional[threading.Event] = None,
) -> RelayKeepalive:
    """Start the native-shaped, session-scoped empty-text-frame worker."""
    if interval <= 0 or interval > DEFAULT_INTERVAL_SECONDS:
        raise ValueError("Azure relay keepalive interval must be >0 and <= 1 second")
    if stop_event is None:
        stop_event = threading.Event()
    handles = RelayKeepalive(stop_event, None, session)

    def worker() -> None:
        sent = 0
        log(
            f"[azure.keepalive] event=started mechanism=empty_text_frame "
            f"interval_seconds={interval:g} node_id={handles.node_id} "
            f"session_ref={id(session):x}"
        )
        while not stop_event.wait(interval):
            current = handles.session
            if current is None:
                _fail(handles, current, "session_missing", None)
                break
            try:
                current.send_relay_keepalive()
                sent += 1
                if sent == 1 or sent % 60 == 0:
                    detail(
                        f"[azure.keepalive] event=sent mechanism=empty_text_frame "
                        f"sent_count={sent} node_id={handles.node_id} "
                        f"session_ref={id(current):x}"
                    )
            except Exception as exc:  # noqa: BLE001 - failure is handed to supervisor
                _fail(handles, current, "send_failed", type(exc).__name__)
                break
        log(
            f"[azure.keepalive] event=stopped mechanism=empty_text_frame "
            f"sent_count={sent} node_id={handles.node_id} "
            f"session_ref={id(handles.session):x}"
        )

    thread = threading.Thread(target=worker, name="azure-relay-keepalive", daemon=True)
    handles.thread = thread
    thread.start()
    return handles


def start_session_relay_keepalive(session: Any) -> Optional[RelayKeepalive]:
    """Attach only to a real Azure terminal session, not a test/mock shell."""
    from cloudbasher.csp.azure.session import AzureSession

    if not isinstance(session, AzureSession):
        return None
    return start_relay_keepalive_loop(session)


def _fail(
    handles: RelayKeepalive, session: Any, reason: str, error_type: Optional[str]
) -> None:
    from cloudbasher.core.session.liveness import condemn_node_session

    with handles.handoff_lock:
        node = handles.node
        if node is None:


            handles.pending_failure = (session, reason, error_type)
            marked = False
        else:
            marked = condemn_node_session(node, session, reason)
    log(
        f"[azure.keepalive] event=session_unusable mechanism=empty_text_frame "
        f"reason={reason} error_type={error_type or 'none'} "
        f"node_id={handles.node_id} "
        f"session_ref={id(session):x} recovery_marked={str(marked).lower()}"
    )
