"""Azure Portal-compatible names for the automatic Cloud Shell storage profile."""

from __future__ import annotations

import re
from typing import Any, Mapping

MAX_SHARE_NAME = 63
_NOT_ALLOWED = re.compile(r"[^a-z|0-9|\-]")
_DASH_RUN = re.compile(r"-+")
_PUID = re.compile(r"^[0-9a-fA-F]{16}$")


def storage_suffix_from_claims(claims: Mapping[str, Any]) -> str:
    """Return the directory-side PUID used by Portal, never ACC_PUID."""
    suffix = claims.get("puid")
    if not isinstance(suffix, str) or not suffix:
        altsecid = claims.get("altsecid")
        if isinstance(altsecid, str) and altsecid:
            first = altsecid.split(",", 1)[0]
            fields = first.split(":")
            suffix = fields[2] if len(fields) > 2 else None
    if not isinstance(suffix, str) or not _PUID.fullmatch(suffix):
        raise ValueError("ARM token has no usable 16-hex puid/altsecid storage suffix")
    return suffix.lower()


def select_identity(claims: Mapping[str, Any]) -> str | None:
    """The Portal's claim selection for deriving the Mounted file-share name."""
    upn = claims.get("upn")
    if isinstance(upn, str) and re.search(r"\S", upn):
        return upn
    name = claims.get("unique_name")
    if not isinstance(name, str):
        return None
    hash_at = name.find("#")
    if hash_at != -1 and hash_at != len(name) - 1:
        return name[hash_at + 1 :]
    return name


def _fold(identity: str) -> str:
    folded = ("cs-" + identity + "-").lower()
    return _DASH_RUN.sub("-", _NOT_ALLOWED.sub("-", folded))


def derive_share_name(
    claims: Mapping[str, Any], suffix: str, *, max_len: int = MAX_SHARE_NAME
) -> str:
    """Port Portal's `Fr` share-name rule, including truncation at 63 chars."""
    suffix = suffix.lower()
    identity = select_identity(claims)
    if identity is None:
        raise ValueError("ARM token has neither a usable upn nor unique_name claim")
    prefix = _fold(identity)
    if len(prefix) + len(suffix) <= max_len:
        return prefix + suffix
    cut = max(0, max_len - 1 - len(suffix))
    return _DASH_RUN.sub("-", prefix[:cut] + "-" + suffix)


def derive_storage_names(claims: Mapping[str, Any], region: str) -> tuple[str, str, str]:
    """Return `(resource_group, storage_account, file_share)` for a region."""
    suffix = storage_suffix_from_claims(claims)
    return (
        f"cloud-shell-storage-{region}",
        f"cs4{suffix}",
        derive_share_name(claims, suffix),
    )
