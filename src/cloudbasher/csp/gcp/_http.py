"""Shared HTTP helpers for GCP CloudShell API clients."""

from __future__ import annotations

import json
import ssl
import urllib.request
from typing import Any, Optional


def strip_xssi(body: Any) -> Any:
    """Strip Google's XSSI prefix )]}' from response text before JSON parse."""
    if isinstance(body, str) and body.startswith(")]}'"):
        stripped = body[4:].strip()
        try:
            return json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return stripped
    return body


def build_opener(
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> urllib.request.OpenerDirector:
    """Build a urllib opener with optional HTTP(S) proxy and insecure-TLS handling."""
    handlers: list[urllib.request.BaseHandler] = []
    if proxy_url:
        handlers.append(
            urllib.request.ProxyHandler(
                {
                    "http": proxy_url,
                    "https": proxy_url,
                }
            )
        )
    if proxy_insecure and proxy_url:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)
