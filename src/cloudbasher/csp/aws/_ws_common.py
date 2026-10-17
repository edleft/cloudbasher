#!/usr/bin/env python3
"""Shared proxy/SSL option-building helpers for AWS WebSocket clients."""

from __future__ import annotations

from typing import Any, Optional


def build_proxy_and_ssl_opts(
    proxy_url: Optional[str], proxy_insecure: bool
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Returns (proxy_settings, sslopt) kwargs for websocket-client's create_connection(), extracted from CloudShellWsSession.connect() so EventFeedClient can reuse the exact same proxy/SSL handling instead of duplicating it."""

    proxy_settings: dict[str, Any] = {}
    if proxy_url:
        import urllib.parse

        parsed = urllib.parse.urlparse(proxy_url.strip())
        if parsed.hostname and parsed.port:
            proxy_settings = {
                "http_proxy_host": parsed.hostname,
                "http_proxy_port": parsed.port,
            }
            if parsed.username:
                proxy_settings["http_proxy_auth"] = (
                    urllib.parse.unquote(parsed.username),
                    urllib.parse.unquote(parsed.password or ""),
                )


    sslopt: dict[str, Any] = {}
    if proxy_insecure and proxy_url:
        import ssl

        sslopt = {"cert_reqs": ssl.CERT_NONE, "check_hostname": False}

    return proxy_settings, sslopt
