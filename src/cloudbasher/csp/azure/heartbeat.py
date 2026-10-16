"""Azure CloudShell heartbeat — background keepalive thread."""

from __future__ import annotations

import threading
from typing import Any

from cloudbasher.core.utils.output import detail, eprint, log


_WARN_AFTER_CONSECUTIVE = 3


def send_heartbeat(api: Any, console: Any) -> bool:
    """Send one keepalive. Returns True on success; never raises."""
    try:
        api.send_keepalive(console)
        detail(f"Keepalive sent: {console.console_id}")
        return True
    except Exception as exc:  # noqa: BLE001 -- a keepalive must not kill the loop
        detail(f"Keepalive error: {exc}")
        return False


def start_heartbeat_loop(
    api: Any,
    console: Any,
    *,
    interval: float = 60.0,
) -> tuple[threading.Event, threading.Thread]:
    """Start a background keepalive thread. Returns (stop_event, thread)."""
    stop_event = threading.Event()

    def _loop() -> None:
        consecutive = 0
        warned = False
        while not stop_event.is_set():
            if send_heartbeat(api, console):
                if warned:


                    eprint(f"keepAlive recovered after {consecutive} failure(s).")
                consecutive, warned = 0, False
            else:
                consecutive += 1
                if consecutive >= _WARN_AFTER_CONSECUTIVE and not warned:
                    warned = True
                    eprint(
                        f"keepAlive has failed {consecutive} times in a row for console "
                        f"{console.console_id}. The console idles out after 20 minutes "
                        f"without one, so this session will drop unless it recovers. "
                        f"Run with -v for the underlying error."
                    )
            stop_event.wait(interval)

    t = threading.Thread(target=_loop, daemon=True, name="azure-heartbeat")
    t.start()
    log(f"Heartbeat loop started (interval={interval}s)")
    return stop_event, t


def stop_heartbeat_loop(stop_event: threading.Event) -> None:
    stop_event.set()
