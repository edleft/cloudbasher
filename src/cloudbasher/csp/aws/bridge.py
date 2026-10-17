"""The `EXTENSIONS_BRIDGE` WebSocket session -- the keepalive channel the AWS console itself holds open for a CloudShell environment, distinct from the command session."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from cloudbasher.core.session.keepalive_policy import policy_of, runs_layer
from cloudbasher.core.utils.output import detail, log
from cloudbasher.csp.aws.api import SessionRole


BRIDGE_MESSAGE = '{"type":"webapp/connected"}'


BRIDGE_INTERVAL_SECONDS = 5.0


_RECEIVE_TIMEOUT_SECONDS = 1.0


_RECONNECT_DELAYS_SECONDS = (1.0, 5.0, 15.0, 30.0)


class _BridgeSocket:
    """One `EXTENSIONS_BRIDGE` session: `createSession`, connect, tick, delete."""

    def __init__(
        self,
        api: Any,
        environment_id: str,
        *,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
    ) -> None:
        self._api = api
        self._env_id = environment_id
        self._proxy_url = proxy_url
        self._proxy_insecure = proxy_insecure
        self._ws: Any = None
        self._session_id: Optional[str] = None
        self._seq = 0

    def _require_ws(self) -> Any:
        """`self._ws`, or a failure that says the socket is gone"""
        from cloudbasher.csp.aws.protocol import require_ws

        return require_ws(self._ws, where="_BridgeSocket._ws")

    def open(self) -> None:
        from cloudbasher.csp.aws.protocol import CloudShellWsSession

        info = self._api.open_stream(self._env_id, session_type=SessionRole.BRIDGE)
        self._session_id = info.get("session_id")
        self._ws = CloudShellWsSession(
            stream_url=info.get("stream_url", ""),
            token_value=info.get("token_value", ""),
            proxy_url=self._proxy_url,
            proxy_insecure=self._proxy_insecure,
        )
        ws = self._require_ws()
        ws.connect()
        ws.send_token_envelope()


        self._seq = 0
        detail(f"[bridge] opened env={self._env_id} session_id={self._session_id}")

    def tick(self) -> None:
        """Send one `webapp/connected`. Raises if the socket is gone."""
        self._require_ws().send_input(BRIDGE_MESSAGE, sequence=self._seq)
        self._seq += 1

    def drain(
        self,
        deadline: Optional[float] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> None:
        """Consume whatever came back, ACKing output so the server sees us."""
        while True:


            if should_stop is not None and should_stop():
                return
            if deadline is not None and time.monotonic() >= deadline:
                return


            ws = self._require_ws()
            frame = ws.receive_frame(timeout_seconds=_RECEIVE_TIMEOUT_SECONDS)
            if frame is None:
                return
            if frame.message_type == "output_stream_data":
                ws.send_ack(frame)

    def close(self) -> None:
        """Close the socket and retire the session server-side, so the environment is not left holding a session this process no longer has."""
        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        session_id, self._session_id = self._session_id, None
        from cloudbasher.csp.aws.api import retire_session_best_effort


        retire_session_best_effort(self._api, self._env_id, session_id)


def _bridge_loop(
    api_getter: Callable[[], Any],
    environment_id: str,
    stop_event: threading.Event,
    *,
    interval: float,
    proxy_url: Optional[str],
    proxy_insecure: bool,
    node_getter: Optional[Callable[[], Any]] = None,
) -> None:
    attempt = 0


    gated_off = False
    while not stop_event.is_set():


        _node = node_getter() if node_getter is not None else None
        if not runs_layer(_node, 3):
            if not gated_off:
                gated_off = True
                detail(
                    f"[bridge] not running for env={environment_id}: keepalive "
                    f"policy {policy_of(_node)!r} does not include layer 3"
                )


            stop_event.wait(interval)
            continue
        if gated_off:
            gated_off = False
            detail(f"[bridge] resumed for env={environment_id} (policy now includes layer 3)")


        api = api_getter()
        socket = _BridgeSocket(
            api, environment_id, proxy_url=proxy_url, proxy_insecure=proxy_insecure
        )
        try:
            socket.open()
            attempt = 0
            next_tick = time.monotonic()
            while not stop_event.is_set():
                now = time.monotonic()
                if now >= next_tick:
                    socket.tick()


                    next_tick += interval
                    if next_tick < now:
                        next_tick = now + interval

                socket.drain(deadline=next_tick, should_stop=stop_event.is_set)
        except Exception as exc:
            if stop_event.is_set():
                break


            from cloudbasher.csp.aws.heartbeat import is_permanent_failure

            if is_permanent_failure(exc):


                log(
                    f"[bridge] stopped env={environment_id}: not retryable "
                    f"({exc}). Waiting cannot change this."
                )
                break
            delay = _RECONNECT_DELAYS_SECONDS[min(attempt, len(_RECONNECT_DELAYS_SECONDS) - 1)]
            attempt += 1
            log(f"[bridge] socket lost env={environment_id} ({exc}); retrying in {delay}s")
            stop_event.wait(delay)
        finally:
            socket.close()
    detail(f"[bridge] stopped env={environment_id}")


def start_extensions_bridge(
    api_getter: Callable[[], Any],
    environment_id: str,
    *,
    stop_event: Optional[threading.Event] = None,
    interval: float = BRIDGE_INTERVAL_SECONDS,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,


    node_getter: Optional[Callable[[], Any]] = None,
) -> tuple[threading.Event, threading.Thread]:
    """Start a node's bridge. Returns its (stop_event, thread)."""
    if not callable(api_getter):
        raise TypeError(
            "start_extensions_bridge takes a zero-arg getter, not a client: "
            "this thread is kept across reconnects, so a snapshot outlives "
            "the page or credential it was bound to. Pass `lambda: api` if "
            "this caller genuinely never rebinds."
        )
    stop = stop_event or threading.Event()
    thread = threading.Thread(
        target=_bridge_loop,
        args=(api_getter, environment_id, stop),
        kwargs={
            "interval": interval,
            "proxy_url": proxy_url,
            "proxy_insecure": proxy_insecure,
            "node_getter": node_getter,
        },
        daemon=True,
        name=f"cb-bridge-{environment_id[:8]}",
    )
    thread.start()
    log(f"[bridge] EXTENSIONS_BRIDGE started env={environment_id} every {interval}s")
    return stop, thread
