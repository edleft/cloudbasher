#!/usr/bin/env python3
"""AWS CloudShell environment heartbeat (keepalive) logic."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from cloudbasher.core.types import (
    SOCKET_DEAD_AFTER_FAILURES,
    last_real_traffic_at,
    node_socket_is_dead,
)
from cloudbasher.core.utils.output import detail, log
from cloudbasher.core.session.failure import CONSOLE_PRESIGN_REFUSED, TERMINAL
from cloudbasher.core.session.keepalive_policy import layer_follows_interaction, runs_layer
from cloudbasher.csp.aws.failure import CREDENTIAL_DEAD_ERROR_CODES, classify_failure


_KEEPALIVE_TERMINAL = TERMINAL | {"environment_suspended"}
from cloudbasher.csp.aws.interaction_ping import send_interaction_ping, should_ping
from cloudbasher.csp.aws.signing import last_transport_retries
from cloudbasher.core.utils.perf_config import (
    get_credential_reproject_interval_seconds,
    get_heartbeat_ws_ping_interval_seconds,
)
from cloudbasher.csp.aws.api import AWSCloudShellAPI


_WS_PING_INTERVAL_SECONDS = get_heartbeat_ws_ping_interval_seconds()


_TICK_SECONDS = 1.0


_CREDENTIAL_REPROJECT_INTERVAL_SECONDS = get_credential_reproject_interval_seconds()


_CREDENTIAL_DEAD_ERROR_CODES = CREDENTIAL_DEAD_ERROR_CODES


def cascade_credential_invalidation(
    node: Any, hook: Optional[Callable[[Any], None]], *, where: str = "[heartbeat]"
) -> None:
    """Invalidate this credential's OTHER nodes, and never raise doing it."""
    if hook is None:
        return
    try:
        hook(node)
    except Exception as cascade_exc:
        log(f"{where} credential invalidation cascade failed: {cascade_exc}")


def _classify_heartbeat_error(exc: Exception) -> str:
    """The heartbeat's four-name vocabulary, DERIVED from the one classifier."""
    cls = classify_failure(exc)
    if cls == "access_denied":
        return "access_denied"
    if cls == "credential_expired":
        return "credential_invalid"
    if cls == CONSOLE_PRESIGN_REFUSED:
        return CONSOLE_PRESIGN_REFUSED
    return "unavailable"


def is_permanent_failure(exc: Exception) -> bool:
    """Whether retrying `exc` is pointless. Shared with the bridge, which runs its own reconnect ladder and would otherwise climb it forever."""
    return classify_failure(exc) in _KEEPALIVE_TERMINAL


def _node_detail(node: Any) -> str:
    """Structured log-line detail for a node -- identifier, IP, hostname, CSP, identity -- so a heartbeat failure can be troubleshot from the log alone."""
    ip = getattr(node.session, "ip_address", None) if node.session else None
    hostname = getattr(node.session, "hostname", None) if node.session else None
    return (
        f"node={node.id} region={node.region} environment_id={node.environment_id} "
        f"csp=aws credential_id={node.credential_id} ip={ip} hostname={hostname}"
    )


_SOCKET_DEAD_AFTER_FAILURES = SOCKET_DEAD_AFTER_FAILURES


_SOCKET_DEAD_RELOG_SECONDS = 300


def ping_idle_socket(session: Any) -> Optional[bool]:
    """Keepalive layer 2: one `__ping__` on the session's socket."""
    ws = getattr(session, "ws", None)
    if ws is None:
        return None
    if not getattr(ws, "is_connected", False):
        detail("[heartbeat] idle WS ping skipped: no open socket yet")
        return None
    try:
        ws.send_ping()
        return True
    except Exception as e:


        detail(f"[heartbeat] idle WS ping failed: {e}")
        return False


def _mark_node_session(node: Any, method: str, *args: Any) -> None:
    """Call `condemn`/`clear_condemnation` on this node's live handle (W8a)."""
    session = getattr(node, "_runtime_session", None)
    fn = getattr(session, method, None)
    if callable(fn):
        try:
            fn(*args)
        except Exception as exc:  # pragma: no cover - defensive
            detail(f"[heartbeat] could not {method} the session handle: {exc}")


def _condemn_node_session(node: Any, reason: str) -> None:
    """Mark this node's live session handle unusable (W8a)."""
    _mark_node_session(node, "condemn", reason)


def _clear_node_session_condemnation(node: Any) -> None:
    """Withdraw the mark after the socket answers again (W8a)."""
    _mark_node_session(node, "clear_condemnation")


def record_ping_result(
    node: Any,
    sent: Optional[bool],
    *,
    on_node_change: Callable[[Any], None],
    now: float,
    last_relog: float,
) -> float:
    """Fold one idle-ping outcome into the node's state. Returns `last_relog`."""
    if node is None or sent is None:
        return last_relog
    if sent:
        if node._socket_ping_failures:
            log(
                f"[heartbeat] idle WS ping recovered after "
                f"{node._socket_ping_failures} failure(s) ({_node_detail(node)})"
            )
            node._socket_ping_failures = 0


            _clear_node_session_condemnation(node)
            on_node_change(node)
        return last_relog

    node._socket_ping_failures += 1
    count = node._socket_ping_failures
    if count == 1:
        log(f"[heartbeat] idle WS ping failed ({_node_detail(node)})")
        return last_relog
    if count == _SOCKET_DEAD_AFTER_FAILURES:

        log(
            f"[heartbeat] socket declared DEAD after {count} consecutive failed "
            f"pings -- the node is no longer usable and will not repair itself "
            f"from here; reconnect rebuilds it ({_node_detail(node)})"
        )


        _condemn_node_session(
            node,
            f"the socket failed {count} consecutive keepalive pings",
        )
        on_node_change(node)
        return now
    if now - last_relog >= _SOCKET_DEAD_RELOG_SECONDS:
        log(
            f"[heartbeat] socket still dead, {count} consecutive failed pings "
            f"({_node_detail(node)})"
        )
        return now
    return last_relog


socket_is_dead = node_socket_is_dead


def _interaction_ping_default() -> bool:
    """Is keepalive layer 4 on? `[keepalive] interaction_ping`, default TRUE."""


    from cloudbasher.core.config import switch

    return switch("keepalive.interaction_ping")


def _reproject_once(on_reproject: Callable[[], None], busy: "threading.Event") -> None:
    """Run one credential re-projection, on its own thread. Never raises."""
    try:
        on_reproject()
        detail("[keepalive] container credentials re-projected")
    except Exception as exc:  # noqa: BLE001 -- see above


        if is_permanent_failure(exc):
            log(
                "[keepalive] credential re-projection PERMANENTLY refused: "
                f"{exc}. In-shell `aws` will stop working when the container's "
                "current token expires; the shell itself is unaffected. "
                "Re-provision or re-derive this credential."
            )
        else:
            log(f"[keepalive] credential re-projection failed (will retry): {exc}")
    finally:
        busy.clear()


def _layer_one_is_quiet(node: Any, *, since: float) -> bool:
    """`#602`. Should layer 1 SKIP this beat because nothing has happened?"""
    if node is None or not layer_follows_interaction(node, 1):
        return False
    traffic = last_real_traffic_at(node)
    return traffic is None or traffic <= since


def start_heartbeat_loop(
    api_getter: Callable[[], Optional[AWSCloudShellAPI]],
    environment_id: str,
    interval: int = 270,
    stop_event: Optional[threading.Event] = None,
    session_getter: Optional[Callable[[], Any]] = None,
    node: Optional[Any] = None,
    node_getter: Optional[Callable[[], Any]] = None,
    on_node_change: Optional[Any] = None,
    retry_interval: int = 60,
    max_retries: int = 3,
    on_credential_invalid: Optional[Callable[[Any], None]] = None,
    on_reproject: Optional[Callable[[], None]] = None,
    reproject_interval: Optional[int] = None,
) -> threading.Thread:
    """Start a background heartbeat thread."""


    if not callable(api_getter):
        raise TypeError(
            "start_heartbeat_loop takes a zero-arg getter, not a client: a "
            "thread that snapshots the client keeps signing with it after a "
            "reconnect or credential refresh. Pass `lambda: api` if this "
            "caller genuinely never rebinds."
        )
    if session_getter is not None and not callable(session_getter):
        raise TypeError(
            "start_heartbeat_loop takes a zero-arg session getter, not a "
            "session: the session is what a reconnect REPLACES, so a thread "
            "that snapshots it pings a handle the gateway already discarded. "
            "Pass `lambda: session` if this caller genuinely never rebinds."
        )
    if stop_event is None:
        stop_event = threading.Event()
    on_node_change = on_node_change or (lambda _n: None)


    _node_getter = node_getter or (lambda: node)


    _session_getter = session_getter or (lambda: getattr(_node_getter(), "_runtime_session", None))


    interaction_ping_enabled = _interaction_ping_default()


    if reproject_interval is None:
        reproject_interval = get_credential_reproject_interval_seconds()

    def heartbeat_worker():
        """Worker thread that sends periodic env heartbeats + WS pings."""
        elapsed = 0.0
        current_env_interval = interval


        exhausted = False
        last_env_heartbeat = -interval


        last_env_beat_at = 0.0


        l1_quiet = False
        last_ws_ping = -_WS_PING_INTERVAL_SECONDS
        last_socket_relog = 0.0


        layer4_successes = 0
        last_layer4_relog = 0.0


        last_reproject = 0.0


        reproject_busy = threading.Event()
        while not stop_event.is_set():


            api = api_getter()
            node = _node_getter()
            session = _session_getter()
            self_heal_enabled = node is not None


            runs_l1 = runs_layer(node, 1)
            runs_l2 = runs_layer(node, 2)
            runs_l4 = runs_layer(node, 4)


            if on_reproject is not None and elapsed - last_reproject >= reproject_interval:
                last_reproject = elapsed


                if reproject_busy.is_set():


                    detail("[keepalive] re-projection still running; skipping this interval")
                else:
                    reproject_busy.set()
                    threading.Thread(
                        target=_reproject_once,
                        args=(on_reproject, reproject_busy),
                        name="creds-reproject",
                        daemon=True,
                    ).start()


            _l1_due = runs_l1 and elapsed - last_env_heartbeat >= current_env_interval
            if _l1_due and _layer_one_is_quiet(node, since=last_env_beat_at):


                last_env_heartbeat = elapsed
                _l1_due = False
                if not l1_quiet:
                    l1_quiet = True
                    detail(
                        f"[heartbeat] layer 1 quiet for {environment_id}: policy "
                        f"follows interaction and none has happened since the "
                        f"last beat"
                    )
            if _l1_due and api is not None:
                try:
                    api.send_heartbeat(environment_id)


                    _flaps = last_transport_retries()
                    if _flaps:
                        log(
                            f"[heartbeat] environment beat OK but the transport "
                            f"flapped ({_flaps} retr{'y' if _flaps == 1 else 'ies'}) "
                            f"-- this says the control plane is reachable, NOT "
                            f"that the session is alive"
                        )
                    if session is not None:


                        session._last_heartbeat_at = time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                        )
                    if self_heal_enabled and node._heartbeat_retry_count > 0:


                        retries_taken = node._heartbeat_retry_count
                        try:
                            from cloudbasher.core.cli.dispatcher import _AWS_STATUS_MAP

                            status_resp = api.get_environment_status(environment_id)
                            node.container_status = _AWS_STATUS_MAP.get(
                                status_resp.get("status", ""), "Unknown"
                            )
                        except Exception as status_exc:
                            log(
                                f"[heartbeat] recovered but status confirmation "
                                f"failed ({_node_detail(node)}): {status_exc}"
                            )
                        log(
                            f"[heartbeat] recovered after {retries_taken}/{max_retries} "
                            f"retries, confirmed container_status="
                            f"{node.container_status} ({_node_detail(node)})"
                        )
                        node._heartbeat_retry_count = 0
                        exhausted = False
                        current_env_interval = interval
                        on_node_change(node)
                except Exception as e:
                    if not self_heal_enabled:
                        log(f"[heartbeat] send_heartbeat failed: {e}")
                        if is_permanent_failure(e):


                            log(
                                "[heartbeat] stopping: this is an authorization "
                                "denial, not an outage -- retrying cannot change it"
                            )
                            return
                    elif exhausted:


                        log(
                            f"[heartbeat] still failing after exhausting retries "
                            f"({_node_detail(node)}): {e}"
                        )
                    else:
                        error_class = _classify_heartbeat_error(e)
                        status_code = getattr(e, "status_code", None)
                        error_code = getattr(e, "error_code", None)
                        log(
                            f"[heartbeat] send_heartbeat failed, classified="
                            f"{error_class} status_code={status_code} "
                            f"error_code={error_code} ({_node_detail(node)}): {e}"
                        )
                        if error_class in ("credential_invalid", "access_denied"):


                            try:
                                if node._runtime_session is not None:
                                    node._runtime_session.close()
                            except Exception:
                                pass
                            node._runtime_session = None
                            node._runtime_heartbeat_stop = None
                            node._runtime_heartbeat_thread = None


                            denied = error_class == "access_denied"
                            node.container_status = (
                                "AccessDenied" if denied else "CredentialInvalid"
                            )
                            node._heartbeat_retry_count = 0


                            if not denied:
                                cascade_credential_invalidation(node, on_credential_invalid)
                            on_node_change(node)
                            log(
                                f"[heartbeat] {'access denied' if denied else 'credential invalidated'}"
                                f", disconnected ({_node_detail(node)})"
                                + (
                                    " -- this is an authorization boundary, not an "
                                    "outage and not a bad credential; retrying "
                                    "cannot change it"
                                    if denied
                                    else ""
                                )
                            )
                            return
                        if error_class == CONSOLE_PRESIGN_REFUSED:


                            try:
                                if node._runtime_session is not None:
                                    node._runtime_session.close()
                            except Exception:
                                pass
                            node._runtime_session = None
                            node._runtime_heartbeat_stop = None
                            node._runtime_heartbeat_thread = None
                            node.end_connect()
                            node.container_status = "Failed"
                            node._last_failure_class = CONSOLE_PRESIGN_REFUSED
                            node._heartbeat_retry_count = 0
                            on_node_change(node)
                            log(
                                f"[heartbeat] console presign refused, disconnected "
                                f"({_node_detail(node)}) -- reconnect this node to "
                                "run the console login again; the credential was not "
                                "invalidated"
                            )
                            return


                        if status_code in (401, 403) and error_class == "unavailable":
                            log(
                                f"[heartbeat] HTTP {status_code} named "
                                f"error_code={error_code!r}, which is not "
                                "recognised as credential death -- retrying "
                                "instead of invalidating the credential "
                                "fleet-wide. If this credential really is dead, "
                                "that code belongs in "
                                "_CREDENTIAL_DEAD_ERROR_CODES "
                                f"({_node_detail(node)})"
                            )


                        was_healthy = node._heartbeat_retry_count == 0
                        node._heartbeat_retry_count = min(
                            node._heartbeat_retry_count + 1, max_retries
                        )
                        if was_healthy:
                            current_env_interval = retry_interval
                            on_node_change(node)
                        log(
                            f"[heartbeat] retry {node._heartbeat_retry_count}/"
                            f"{max_retries} ({_node_detail(node)})"
                        )
                        if node._heartbeat_retry_count >= max_retries:


                            try:
                                from cloudbasher.core.cli.dispatcher import _AWS_STATUS_MAP

                                status_resp = api.get_environment_status(environment_id)
                                node.container_status = _AWS_STATUS_MAP.get(
                                    status_resp.get("status", ""), "Unknown"
                                )
                                log(
                                    f"[heartbeat] exhausted retries, real state "
                                    f"observed: {node.container_status} "
                                    f"({_node_detail(node)})"
                                )
                            except Exception as status_exc:
                                log(
                                    f"[heartbeat] exhausted retries, status "
                                    f"confirmation also failed "
                                    f"({_node_detail(node)}): {status_exc}"
                                )
                            exhausted = True
                            current_env_interval = interval
                            on_node_change(node)
                last_env_heartbeat = elapsed
                last_env_beat_at = time.time()
                if l1_quiet:
                    l1_quiet = False
                    detail(f"[heartbeat] layer 1 resumed for {environment_id} (interaction seen)")


            if (
                runs_l2
                and session is not None
                and elapsed - last_ws_ping >= _WS_PING_INTERVAL_SECONDS
            ):
                sent = ping_idle_socket(session)
                last_ws_ping = elapsed


                last_socket_relog = record_ping_result(
                    node,
                    sent,
                    on_node_change=on_node_change,
                    now=time.time(),
                    last_relog=last_socket_relog,
                )


                if runs_l4 and interaction_ping_enabled and node is not None and sent:
                    if should_ping(node, time.monotonic()):
                        if send_interaction_ping(node, session):
                            layer4_successes += 1
                            wall = time.time()
                            if layer4_successes == 1:


                                log(
                                    f"[layer4] idle session ping succeeded -- session "
                                    f"held open ({_node_detail(node)})"
                                )
                                last_layer4_relog = wall
                            elif wall - last_layer4_relog >= _SOCKET_DEAD_RELOG_SECONDS:


                                log(
                                    f"[layer4] idle session ping still holding "
                                    f"({layer4_successes} so far) ({_node_detail(node)})"
                                )
                                last_layer4_relog = wall


            if stop_event.wait(timeout=_TICK_SECONDS):
                break
            elapsed += _TICK_SECONDS

    thread = threading.Thread(target=heartbeat_worker, daemon=True)
    thread.start()
    return thread


def stop_heartbeat_loop(stop_event: threading.Event) -> None:
    """Signal a heartbeat loop to stop."""
    stop_event.set()
