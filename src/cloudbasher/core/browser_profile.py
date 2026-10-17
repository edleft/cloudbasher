"""What our browser presents to a CSP backend."""

from __future__ import annotations

from typing import Any, Optional


_UA_CACHE: dict[str, str] = {}


DEFAULT_VIEWPORT = {"width": 1440, "height": 900}


def chrome_like_user_agent(browser: Any) -> Optional[str]:
    """The browser's OWN user agent, minus the ``Headless`` token."""
    key = str(getattr(browser, "version", "") or "?")
    cached = _UA_CACHE.get(key)
    if cached is not None:
        return cached or None
    probe = None
    try:
        probe = browser.new_context()
        ua = probe.new_page().evaluate("navigator.userAgent")
    except Exception:
        _UA_CACHE[key] = ""
        return None
    finally:
        if probe is not None:
            try:
                probe.close()
            except Exception:
                pass
    if not isinstance(ua, str) or not ua:
        _UA_CACHE[key] = ""
        return None


    ua = ua.replace("HeadlessChrome", "Chrome")
    _UA_CACHE[key] = ua
    return ua


def launch_args() -> list[str]:
    """Chromium flags that remove automation tells at the browser level."""
    return ["--disable-blink-features=AutomationControlled"]


def context_kwargs(browser: Any, *, extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Everything to pass to ``browser.new_context()``."""
    kwargs: dict[str, Any] = {
        "viewport": dict(DEFAULT_VIEWPORT),
        "locale": "en-US",


        "extra_http_headers": {"Accept-Language": "en-US,en;q=0.9"},
    }
    ua = chrome_like_user_agent(browser)
    if ua:
        kwargs["user_agent"] = ua
    if extra:
        kwargs.update(extra)
    return kwargs
