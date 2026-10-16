"""Encrypted Azure refresh-token cache."""

from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from cloudbasher.csp.azure.app_ids import AzureClientIds as _AzureClientIds


_CACHE_MAGIC = b"CSR\x03"
_CACHE_SALT_LEN = 32
_CACHE_NONCE_LEN = 12
_CACHE_SCRYPT_N = 131072
_CACHE_SCRYPT_R = 8
_CACHE_SCRYPT_P = 1
_TAG_LEN = 16

_BROWSER_AUTH_PASSPHRASE: Optional[str] = None

_DEVICE_CODE_PARAMS = {
    "client_id": _AzureClientIds.MSAL,
}


class BrowserAuthError(Exception):
    """Base class for browser-auth-cache failures."""


class BrowserAuthCorruptError(BrowserAuthError):
    """Magic byte / version / structural integrity check failed."""


class BrowserAuthWrongPassphrase(BrowserAuthError):
    """AES-GCM auth-tag check failed — wrong passphrase or tampered ciphertext."""


@dataclass
class AzureBrowserAuthEntry:
    """A single cached refresh-token entry, keyed by tenant_id in the cache dict."""

    tenant_id: str
    refresh_token: str
    client_id: str
    account_email: Optional[str] = None
    audiences: list[str] = field(default_factory=list)
    cached_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("tenant_id")
        return d

    @classmethod
    def from_dict(cls, tenant_id: str, raw: dict[str, Any]) -> "AzureBrowserAuthEntry":
        return cls(
            tenant_id=tenant_id,
            refresh_token=str(raw.get("refresh_token") or ""),
            client_id=str(raw.get("client_id") or ""),
            account_email=raw.get("account_email"),
            audiences=list(raw.get("audiences") or []),
            cached_at=raw.get("cached_at"),
        )


def set_browser_auth_passphrase(passphrase: Optional[str]) -> None:
    """Set the encryption passphrase for the cache (None → plaintext JSON)."""
    global _BROWSER_AUTH_PASSPHRASE
    _BROWSER_AUTH_PASSPHRASE = passphrase


def _cache_path() -> Path:
    """Return the path on disk: .bin if encrypted, .json if plaintext."""
    ext = ".bin" if _BROWSER_AUTH_PASSPHRASE else ".json"
    return Path(__file__).parent / f"azure_browser_auth{ext}"


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=_CACHE_SCRYPT_N,
        r=_CACHE_SCRYPT_R,
        p=_CACHE_SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt(plaintext: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(_CACHE_SALT_LEN)
    nonce = os.urandom(_CACHE_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return _CACHE_MAGIC + salt + nonce + ct_tag


def _decrypt(blob: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    minimum = len(_CACHE_MAGIC) + _CACHE_SALT_LEN + _CACHE_NONCE_LEN + _TAG_LEN
    if len(blob) < minimum:
        raise BrowserAuthCorruptError(
            f"cache too short: {len(blob)} bytes, need at least {minimum}"
        )
    if blob[: len(_CACHE_MAGIC)] != _CACHE_MAGIC:
        raise BrowserAuthCorruptError(f"unrecognized cache magic bytes: {blob[:4]!r}")
    off = len(_CACHE_MAGIC)
    salt = blob[off : off + _CACHE_SALT_LEN]
    off += _CACHE_SALT_LEN
    nonce = blob[off : off + _CACHE_NONCE_LEN]
    off += _CACHE_NONCE_LEN
    ct_tag = blob[off:]
    key = _derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct_tag, None)
    except InvalidTag as exc:
        raise BrowserAuthWrongPassphrase("wrong passphrase or tampered ciphertext") from exc


def _write_secure(path: Path, payload: bytes, *, binary: bool) -> None:
    temp = path.with_name(path.name + ".tmp")
    if binary:
        temp.write_bytes(payload)
    else:
        temp.write_text(payload.decode("utf-8"), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    os.chmod(path, 0o600)


def _serialize_cache(cache: dict[str, AzureBrowserAuthEntry]) -> dict[str, Any]:
    return {
        "version": 1,
        "updated_at": _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tenants": {tid: entry.to_dict() for tid, entry in sorted(cache.items())},
    }


def _deserialize_cache(raw: dict[str, Any]) -> dict[str, AzureBrowserAuthEntry]:
    if not isinstance(raw, dict):
        raise BrowserAuthCorruptError("cache root must be a JSON object")
    tenants = raw.get("tenants", {})
    if not isinstance(tenants, dict):
        raise BrowserAuthCorruptError("cache 'tenants' must be a JSON object")
    out: dict[str, AzureBrowserAuthEntry] = {}
    for tid, entry_dict in tenants.items():
        if not isinstance(entry_dict, dict):
            continue
        entry = AzureBrowserAuthEntry.from_dict(str(tid), entry_dict)
        if entry.refresh_token and entry.client_id:
            out[entry.tenant_id] = entry
    return out


def load_browser_auth_cache() -> dict[str, AzureBrowserAuthEntry]:
    """Load the entire cache. Returns {} if the file doesn't exist."""
    path = _cache_path()
    if not path.exists():


        return {}
    if _BROWSER_AUTH_PASSPHRASE and path.suffix == ".bin":
        blob = path.read_bytes()
        plaintext = _decrypt(blob, _BROWSER_AUTH_PASSPHRASE)
        try:
            raw = json.loads(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BrowserAuthCorruptError(
                f"cache plaintext is not valid UTF-8 JSON: {exc}"
            ) from exc
    else:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise BrowserAuthCorruptError(f"cache JSON is malformed: {exc}") from exc
    return _deserialize_cache(raw)


def save_browser_auth_cache(cache: dict[str, AzureBrowserAuthEntry]) -> None:
    """Persist the entire cache, encrypting if passphrase is set."""
    path = _cache_path()
    payload = _serialize_cache(cache)
    plaintext = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    if _BROWSER_AUTH_PASSPHRASE:
        blob = _encrypt(plaintext, _BROWSER_AUTH_PASSPHRASE)
        _write_secure(path, blob, binary=True)
    else:
        _write_secure(path, plaintext, binary=False)


def load_browser_auth_entry(tenant_id: str) -> Optional[AzureBrowserAuthEntry]:
    return load_browser_auth_cache().get(tenant_id)


def save_browser_auth_entry(entry: AzureBrowserAuthEntry) -> AzureBrowserAuthEntry:
    """Merge an entry into the cache (overwrites existing under same tenant_id)."""
    cache = load_browser_auth_cache()
    if not entry.cached_at:
        entry.cached_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cache[entry.tenant_id] = entry
    save_browser_auth_cache(cache)
    return entry


def clear_browser_auth_entry(tenant_id: str) -> None:
    cache = load_browser_auth_cache()
    if cache.pop(tenant_id, None) is not None:
        save_browser_auth_cache(cache)
