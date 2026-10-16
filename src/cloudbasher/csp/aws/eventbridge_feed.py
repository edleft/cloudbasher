#!/usr/bin/env python3
"""Long-lived WebSocket client for the CloudTrail/EventBridge live-events feed."""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Optional

from cloudbasher.csp.aws._ws_common import build_proxy_and_ssl_opts
from cloudbasher.csp.aws.credentials import AwsSessionCreds
from cloudbasher.csp.aws.protocol import ensure_websocket_available
from cloudbasher.csp.aws.signing import presign_websocket_url

try:
    from websocket import WebSocketTimeoutException, create_connection
except ImportError:
    WebSocketTimeoutException = None  # type: ignore[assignment,misc]
    create_connection = None  # type: ignore[assignment]


_INITIAL_BACKOFF_SECONDS = 1
_MAX_BACKOFF_SECONDS = 30
_RECV_TIMEOUT_SECONDS = 5
_CONNECT_TIMEOUT_SECONDS = 10


class EventFeedClient:
    """Maintains a reconnecting WebSocket connection to a CloudTrail/ EventBridge live-events feed served over AWS API Gateway WebSocket API."""

    def __init__(
        self,
        *,
        ws_host: str,
        canonical_uri: str,
        region: str,
        creds: AwsSessionCreds,
        on_message: Callable[[dict], None],
        on_status: Callable[[str], None],
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
    ) -> None:
        self.ws_host = ws_host
        self.canonical_uri = canonical_uri
        self.region = region
        self.creds = creds
        self.on_message = on_message
        self.on_status = on_status
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Spawn the daemon reconnect-loop thread."""
        ensure_websocket_available()
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the loop to stop and close any live socket."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=_RECV_TIMEOUT_SECONDS + 1)

    def _run_loop(self) -> None:
        backoff = _INITIAL_BACKOFF_SECONDS
        while not self._stop_event.is_set():
            ws: Any = None
            try:
                self.on_status("Connecting")
                url = presign_websocket_url(
                    host=self.ws_host,
                    region=self.region,
                    creds=self.creds,
                    canonical_uri=self.canonical_uri,
                )
                proxy_settings, sslopt = build_proxy_and_ssl_opts(
                    self.proxy_url, self.proxy_insecure
                )
                ws = create_connection(
                    url,
                    timeout=_CONNECT_TIMEOUT_SECONDS,
                    enable_multithread=False,
                    **proxy_settings,
                    sslopt=sslopt,
                )
                self.on_status("Connected")
                backoff = _INITIAL_BACKOFF_SECONDS
                ws.settimeout(_RECV_TIMEOUT_SECONDS)

                while not self._stop_event.is_set():
                    try:
                        raw = ws.recv()
                    except WebSocketTimeoutException:


                        continue
                    if not raw:

                        break
                    try:
                        self.on_message(json.loads(raw))
                    except Exception:

                        pass
            except Exception as exc:
                self.on_status(f"Disconnected: {exc}")
            finally:
                if ws is not None:
                    try:
                        ws.close()
                    except Exception:
                        pass

            if not self._stop_event.is_set():
                time.sleep(backoff)
                backoff = min(backoff * 2, _MAX_BACKOFF_SECONDS)
