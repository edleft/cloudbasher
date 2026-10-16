"""The one place a connected AWS node starts keeping itself alive."""

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from cloudbasher.core.types import CONTROL_PLANE_NO_IDENTITY
from cloudbasher.core.utils.output import detail, log
from cloudbasher.csp.aws.api import SessionRole


def control_plane_signer_gap(api: Any) -> str:
    """`""` when `api` can sign a control-plane call, else WHAT IS MISSING."""
    if api is None:
        return "no control-plane client was built for this node"
    from cloudbasher.csp.aws.console_api import ConsoleCloudShellAPI

    if not isinstance(api, ConsoleCloudShellAPI):
        return ""
    region = api.region or ""
    try:
        from cloudbasher.csp.aws.browser import await_presign_for_region

        verdict = await_presign_for_region(api.page, region, wait_seconds=0)
    except Exception as exc:  # noqa: BLE001
        detail(f"[keepalive] could not ask whether {region} has presigned ({exc!r}); assuming yes")
        return ""
    if verdict not in CONTROL_PLANE_NO_IDENTITY:
        return ""
    return (
        f"this console page holds NO presign identity for region={region} "
        f"(verdict={verdict!r}): the CloudShell widget never presigns, so the "
        f"`x-console-api-token` comes only from the console chrome and this page "
        f"never caught one. Every control-plane call signed through it answers "
        f"HTTP 401, so layer 1 keeps no environment and layer 3 keeps no session. "
        f"Re-asked every tick, and a reconnect asks again with a real budget."
    )


@dataclass
class KeepaliveHandles:
    """Stop-event/thread pairs for the layers that actually started."""

    heartbeat_stop: Optional[Any] = None
    heartbeat_thread: Optional[Any] = None
    bridge_stop: Optional[Any] = None
    bridge_thread: Optional[Any] = None


    bind_node: Optional[Any] = None


    attach_session: Optional[Any] = None


    on_reproject: Optional[Callable[[], None]] = None


def start_all_keepalives(
    api: Any,
    environment_id: str,
    *,
    session: Optional[Any] = None,
    node: Optional[Any] = None,
    on_node_change: Optional[Callable[[Any], None]] = None,


    on_credential_invalid: Optional[Callable[[Any], None]] = None,


    on_reproject: Optional[Callable[[], None]] = None,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> KeepaliveHandles:
    """Start every keepalive layer this node can run. Call on connect."""
    import threading

    from cloudbasher.core.utils.perf_config import (
        get_heartbeat_interval_seconds,
        get_heartbeat_max_retries,
        get_heartbeat_retry_interval_seconds,
    )

    handles = KeepaliveHandles(on_reproject=on_reproject)


    _node_slot: dict[str, Any] = {"node": node}


    _snapshot: dict[str, Any] = {"_runtime_api_client": api, "_runtime_session": session}


    _reusable = node.reusable_background_loops() if node is not None else []

    def _from_node(attr: str) -> Callable[[], Any]:
        """A getter for the node's CURRENT `attr`, falling back to a snapshot."""

        def _get() -> Any:
            current = _node_slot["node"]
            if current is None:
                return _snapshot[attr]
            live = getattr(current, attr, None)
            return live if live is not None else _snapshot[attr]

        return _get

    _live_api = _from_node("_runtime_api_client")


    _gap_seen = ""

    def _signing_api() -> Any:
        """Layer 1's client, or `None` while it could not sign. `#823`."""
        nonlocal _gap_seen
        current = _live_api()
        gap = control_plane_signer_gap(current)
        if gap != _gap_seen:
            _gap_seen = gap
            if gap:
                log(f"[keepalive] layer 1 not beating for {environment_id}: {gap}")
            else:
                log(f"[keepalive] layer 1 has a signer again for {environment_id}; resuming")
        return None if gap else current

    def _live_session() -> Any:
        """The node's CURRENT session, and its `None` IS an answer."""
        current = _node_slot["node"]
        if current is None:
            return _snapshot["_runtime_session"]
        return getattr(current, "_runtime_session", None)

    def _arm_session_layers() -> None:
        """Change A. Stamp the traffic clock on the CONNECTED transition."""
        node = _node_slot["node"]


        if node is None or _live_session() is None:
            return
        node.mark_real_traffic()
        detail(f"[layer4] armed for {getattr(node, 'id', '?')} at connect")

    if api is None and session is None:
        log(f"[keepalive] nothing to start for {environment_id}: no api client, no session")
        return handles


    if node is not None and "heartbeat" in _reusable:


        handles.heartbeat_stop = node._runtime_heartbeat_stop
        handles.heartbeat_thread = node._runtime_heartbeat_thread
        handles.attach_session = node._runtime_session_attacher


        if handles.attach_session is not None:


            handles.attach_session(session)
        else:
            log(
                f"[keepalive] kept the heartbeat loop for {environment_id} but "
                "have no session writer for it; layers 2 and 4 stay dormant "
                "until the next reconnect"
            )
        detail(f"[keepalive] existing heartbeat loop kept for {environment_id}")


    else:
        try:
            from cloudbasher.csp.aws.heartbeat import start_heartbeat_loop

            stop = threading.Event()
            handles.heartbeat_stop = stop

            def _bind_node(n: Any) -> None:
                _node_slot["node"] = n


                if n is not None and getattr(n, "_runtime_session", None) is None:
                    held = _snapshot["_runtime_session"]
                    if held is not None:
                        n._runtime_session = held
                _arm_session_layers()

            def _attach_session(s: Any) -> None:
                _snapshot["_runtime_session"] = s


                current = _node_slot["node"]
                if current is not None:
                    current._runtime_session = s
                _arm_session_layers()

            handles.bind_node = _bind_node
            handles.attach_session = _attach_session
            handles.heartbeat_thread = start_heartbeat_loop(
                _signing_api,
                environment_id,
                interval=get_heartbeat_interval_seconds(),
                stop_event=stop,
                session_getter=_live_session,
                node_getter=lambda: _node_slot["node"],
                on_node_change=on_node_change or (lambda _n: None),
                retry_interval=get_heartbeat_retry_interval_seconds(),
                max_retries=get_heartbeat_max_retries(),
                on_credential_invalid=on_credential_invalid,
                on_reproject=on_reproject,
            )
            detail(
                f"[keepalive] heartbeat + socket ping started env_id={environment_id} "
                f"interval={get_heartbeat_interval_seconds()}s"
            )
        except Exception as exc:
            handles.heartbeat_stop = None
            handles.heartbeat_thread = None
            log(f"[keepalive] heartbeat loop could not start for {environment_id}: {exc}")


    if "bridge" in _reusable:
        detail(f"[keepalive] existing bridge still alive for {environment_id}; kept")
        return handles


    _bridge_gap = control_plane_signer_gap(api)
    if _bridge_gap:
        log(
            f"[keepalive] layer 3 (extensions bridge) NOT started for "
            f"{environment_id}: {_bridge_gap}"
        )
        return handles

    try:
        from cloudbasher.csp.aws.bridge import start_extensions_bridge

        handles.bridge_stop, handles.bridge_thread = start_extensions_bridge(
            _live_api,
            environment_id,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,


            node_getter=lambda: _node_slot["node"],
        )
        detail(f"[keepalive] extensions bridge started env_id={environment_id}")
    except Exception as exc:
        handles.bridge_stop = None
        handles.bridge_thread = None
        log(f"[keepalive] extensions bridge could not start for {environment_id}: {exc}")

    return handles


def attach_to_node(node: Any, handles: KeepaliveHandles) -> None:
    """Record the handles on the node, which owns their teardown."""
    node._runtime_heartbeat_stop = handles.heartbeat_stop
    node._runtime_heartbeat_thread = handles.heartbeat_thread


    node._runtime_session_attacher = handles.attach_session


    node._runtime_reprojector = handles.on_reproject


    if handles.bind_node is not None:
        handles.bind_node(node)
    if handles.bridge_thread is not None:
        node._runtime_bridge_stop = handles.bridge_stop
        node._runtime_bridge_thread = handles.bridge_thread


KEEPALIVE_LAYERS: tuple[tuple[int, str, str], ...] = (
    (1, "env", "sendHeartBeat"),
    (2, "ping", "__ping__"),
    (3, "bridge", SessionRole.BRIDGE),
    (4, "shell", "interaction"),
)


def _cascade_dead_credential(node: Any, exc: Exception, state: Any) -> None:
    """A beat that proved its credential dead invalidates the others."""
    try:
        from cloudbasher.csp.aws.multi_region import _credential_invalidator

        from .heartbeat import _classify_heartbeat_error, cascade_credential_invalidation

        if _classify_heartbeat_error(exc) != "credential_invalid":
            return
        cascade_credential_invalidation(
            node, _credential_invalidator(state), where="[keepalive] .heartbeat"
        )
    except Exception as cascade_exc:


        log(f"[keepalive] .heartbeat credential invalidation cascade failed: {cascade_exc}")


def beat_node_now(node: Any, state: Any) -> tuple[list[str], list[str]]:
    """One AWS node's manual beat. Returns `(sent, skipped)` layer labels."""
    from cloudbasher.core.session.keepalive_policy import layer_is_live, runs_layer
    from cloudbasher.csp.base import beat_environment_layer

    from .heartbeat import _interaction_ping_default, ping_idle_socket, record_ping_result
    from .interaction_ping import send_interaction_ping

    names = {layer: f"{layer} {label}" for layer, label, _mech in KEEPALIVE_LAYERS}
    session = getattr(node, "_runtime_session", None)
    on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)


    sent, skipped = beat_environment_layer(
        node,
        names[1],
        on_failure=lambda exc: _cascade_dead_credential(node, exc, state),
    )


    if not runs_layer(node, 2):
        skipped.append(f"{names[2]} (policy)")
    elif session is None:
        skipped.append(f"{names[2]} (no session)")
    else:


        ok = ping_idle_socket(session)
        if ok:
            sent.append(names[2])
        elif ok is None:
            skipped.append(f"{names[2]} (no open socket yet)")
        else:
            skipped.append(f"{names[2]} (no round trip)")


        record_ping_result(node, ok, on_node_change=on_node_change, now=time.time(), last_relog=0.0)


    if not runs_layer(node, 3):
        skipped.append(f"{names[3]} (policy)")
    elif layer_is_live(node, 3):
        skipped.append(f"{names[3]} (running, not forceable)")
    else:
        skipped.append(f"{names[3]} (DEAD)")


    if not runs_layer(node, 4):
        skipped.append(f"{names[4]} (policy)")
    elif not _interaction_ping_default():
        skipped.append(f"{names[4]} (rc off)")
    elif session is None:
        skipped.append(f"{names[4]} (no session)")
    else:
        try:
            if send_interaction_ping(node, session):
                sent.append(names[4])
            else:
                skipped.append(f"{names[4]} (no round trip)")
        except Exception as exc:
            skipped.append(f"{names[4]} FAILED: {exc}")
    return sent, skipped
