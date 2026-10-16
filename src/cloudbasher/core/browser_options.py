"""The knobs every browser login needs, read once. `#538`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

__all__ = ["BrowserOptions", "browser_options"]


DEFAULT_UI_WAIT_TIMEOUT = 60


DEFAULT_LOGIN_TTL_SECONDS = 1800


@dataclass(frozen=True)
class BrowserOptions:
    """How a browser login should be run. Frozen -- nothing mutates a run's knobs."""

    headless: bool = True
    proxy_url: Optional[str] = None
    proxy_insecure: bool = False
    ui_wait_timeout: int = DEFAULT_UI_WAIT_TIMEOUT
    login_ttl_seconds: int = DEFAULT_LOGIN_TTL_SECONDS


def browser_options(args: Any) -> BrowserOptions:
    """The browser-login knobs from an `args` namespace, or from nothing."""
    if args is None:
        return BrowserOptions()
    return BrowserOptions(
        headless=not bool(getattr(args, "show_browser", False)),
        proxy_url=getattr(args, "proxy", None) or None,
        proxy_insecure=bool(getattr(args, "proxy_insecure", False)),


        ui_wait_timeout=_positive_int(
            getattr(args, "ui_wait_timeout", None), DEFAULT_UI_WAIT_TIMEOUT
        ),


        login_ttl_seconds=_positive_int(
            getattr(args, "console_login_ttl", None), DEFAULT_LOGIN_TTL_SECONDS
        ),
    )


def _positive_int(raw: Any, default: int) -> int:
    """`raw` as a positive int, or `default`. Zero and junk both mean unset."""
    try:
        return int(raw) or default
    except (TypeError, ValueError):
        return default
