"""Derive the AWS account number from an access key id, offline."""

from __future__ import annotations

import base64
from typing import Optional


_ACCOUNT_MASK = 0x7FFFFFFFFF80
_ACCOUNT_SHIFT = 7


_UNSUPPORTED_FIFTH_CHARS = frozenset({"I", "J"})


_MIN_KEY_LENGTH = 16
_MAX_KEY_LENGTH = 32


_MIN_DECODED_BYTES = 6


def looks_like_access_key(value: str) -> bool:
    """True if ``value`` has the shape of an access key id."""
    if not value or not (_MIN_KEY_LENGTH <= len(value) <= _MAX_KEY_LENGTH):
        return False
    return value[:4].isalpha()


def account_id_from_access_key(access_key: Optional[str]) -> Optional[str]:
    """The 12-digit account that minted ``access_key``, or None."""
    if not access_key:
        return None
    key = access_key.strip()
    if not looks_like_access_key(key):
        return None
    if key[4].upper() in _UNSUPPORTED_FIFTH_CHARS:
        return None

    body = key[4:]


    padding = (-len(body)) % 8
    try:
        decoded = base64.b32decode(body + ("=" * padding), casefold=True)
    except Exception:
        return None
    if len(decoded) < _MIN_DECODED_BYTES:
        return None

    packed = int.from_bytes(decoded[:_MIN_DECODED_BYTES], byteorder="big")
    masked = packed & _ACCOUNT_MASK
    return str(masked >> _ACCOUNT_SHIFT).zfill(12)


def account_for_credential(extra: dict) -> Optional[str]:
    """The AWS account for a credential's ``extra``, without any API call."""


    from cloudbasher.csp.aws.credentials import is_sso_extra

    if is_sso_extra(extra):
        return None
    for key in ("account", "account_id"):
        value = str(extra.get(key) or "").strip()
        if value:
            return value
    return account_id_from_access_key(extra.get("access_key"))
