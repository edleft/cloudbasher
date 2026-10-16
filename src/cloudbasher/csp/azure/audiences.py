"""Evidence-bounded Azure CLI audience policy shared by token providers."""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True)
class AzureAudienceProfile:
    """A requested broker audience, its redemption scope, and accepted JWT aud."""

    host: str
    scope: str
    jwt_audiences: frozenset[str]


AZURE_AUDIENCE_PROFILES = {
    "graph.microsoft.com": AzureAudienceProfile(
        host="graph.microsoft.com",
        scope="https://graph.microsoft.com/.default",
        jwt_audiences=frozenset({"https://graph.microsoft.com"}),
    ),
    "vault.azure.net": AzureAudienceProfile(
        host="vault.azure.net",
        scope="https://vault.azure.net/.default",


        jwt_audiences=frozenset({"cfa8b339-82a2-471a-a3c9-0fc0be7a4093"}),
    ),
}


def resolve_azure_audience(audience: str) -> AzureAudienceProfile | None:
    """Resolve only the exact HTTPS resource roots in the evidence allowlist."""
    try:
        parsed = urllib.parse.urlsplit(audience)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme.lower() != "https"
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        return None
    return AZURE_AUDIENCE_PROFILES.get(host)


def normalized_jwt_audiences(claims: dict) -> frozenset[str]:
    """Normalize `aud` without assuming every Azure resource uses a URL."""
    value = claims.get("aud")
    values = value if isinstance(value, list) else [value]
    return frozenset(
        item.rstrip("/").lower()
        for item in values
        if isinstance(item, str) and item
    )
