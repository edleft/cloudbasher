"""Azure CloudShell credential management — tiered loader + MSAL token refresh."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import logging as _logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Union

from cloudbasher.core.exceptions import CloudShellAutomationError, CredentialError
from cloudbasher.core.types import Credentials
from cloudbasher.core.utils.output import detail, eprint, log, out
from cloudbasher.csp.azure.app_ids import AzureClientIds as _AzureClientIds
from cloudbasher.csp.azure.audiences import (
    normalized_jwt_audiences,
    resolve_azure_audience,
)
from cloudbasher.csp.azure.types import (
    from_unified,
    is_isolated_console,
    is_token_expiring,
    resolve_storage_profile,
    to_unified,
)
from cloudbasher.csp.base import CredentialProvider


_logging.getLogger("msal").setLevel(_logging.WARNING)


_ARM_SCOPE = "https://management.core.windows.net//.default"


class AzureTokenBrokerError(CredentialError):
    """Credential failure with a safe, non-secret diagnostic for broker traces."""

    def __init__(self, diagnostic: str):
        self.safe_diagnostic = diagnostic
        super().__init__(diagnostic)


def credential_rejection_reason(error: BaseException) -> Optional[str]:
    """Return a safe reason only for an authoritative Azure auth rejection."""
    if isinstance(error, CloudShellAutomationError) and error.status_code == 401:
        return "HTTP 401"
    if isinstance(error, CredentialError) and re.search(
        r"\bfailed:\s*invalid_grant\b", str(error), re.IGNORECASE
    ):
        return "invalid_grant"
    return None


def mark_credential_rejected(
    record: Any, records: Optional[dict[str, Any]], error: BaseException
) -> bool:
    """Project a confirmed Azure auth rejection onto its originating TUI row."""
    if not credential_rejection_reason(error):
        return False
    from cloudbasher.core.identity_listing import mark_credential_invalid

    mark_credential_invalid(record, records)
    return True


_CLOUDSHELL_APP_CLIENT_ID = _AzureClientIds.CLOUDSHELL_PORTAL
_WAM_BROKER_CLIENT_ID = _AzureClientIds.WAM_BROKER


_MSAL_CLIENT_ID = _AzureClientIds.MSAL


_AZURE_CLI_CLIENT_ID = _AzureClientIds.AZURE_CLI
_AZURE_POWERSHELL_CLIENT_ID = _AzureClientIds.AZURE_POWERSHELL


_AUTH_CANDIDATES: list[tuple[str, str]] = [
    (_MSAL_CLIENT_ID, "Azure CLI"),
    (_AZURE_CLI_CLIENT_ID, "unverified 04b07795-8542"),
    (_AZURE_POWERSHELL_CLIENT_ID, "Azure PowerShell"),
]


_FOCI_CANDIDATES: list[tuple[str, str]] = [
    (_CLOUDSHELL_APP_CLIENT_ID, "Azure Cloud Shell"),
    (_AZURE_CLI_CLIENT_ID, "Azure CLI"),
    (_AZURE_POWERSHELL_CLIENT_ID, "Azure PowerShell"),
]

try:
    import msal as _msal_module

    _MSAL_AVAILABLE = True
except ImportError:
    _msal_module = None  # type: ignore[assignment]
    _MSAL_AVAILABLE = False


def _require_msal() -> None:
    if not _MSAL_AVAILABLE:
        raise CredentialError("msal package not installed. Run: pip install msal")


def _resolve_tenant(data: dict[str, Any]) -> str:
    return data.get("tenant_id") or os.environ.get("AZURE_TENANT_ID", "")


def _resolve_subscription(data: dict[str, Any]) -> str:
    return data.get("subscription_id") or os.environ.get("AZURE_SUBSCRIPTION_ID", "")


def _make_public_client_app(tenant_id: str, *, tenant_scoped: bool = False) -> Any:


    authority_tenant = tenant_id if tenant_scoped else "organizations"
    return _msal_module.PublicClientApplication(
        client_id=_MSAL_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{authority_tenant}",
    )


@dataclass
class AzureServicePrincipalCreds:
    """2-legged OAuth client_credentials grant material."""

    tenant_id: str
    client_id: str
    client_secret: str = ""
    subscription_id: Optional[str] = None

    certificate_path: Optional[str] = None

    certificate_pem: Optional[str] = None

    certificate_password: Optional[str] = None

    def uses_certificate(self) -> bool:
        return bool(self.certificate_path or self.certificate_pem)


@dataclass
class AzureRefreshTokenCreds:
    """3-legged OAuth refresh-token-grant material (post browser/device-code login)."""

    tenant_id: str
    refresh_token: str
    subscription_id: Optional[str] = None
    client_id: Optional[str] = None
    region: Optional[str] = None
    session_type: Optional[str] = None
    username: Optional[str] = None


@dataclass
class AzureAccessTokenCreds:
    """Pre-supplied opaque access token, no refresh path. Short-lived (~1h)."""

    tenant_id: str
    access_token: str
    subscription_id: Optional[str] = None
    region: Optional[str] = None
    session_type: Optional[str] = None
    username: Optional[str] = None


@dataclass
class AzureConsoleCreds:
    """Username/password credential for an explicit Azure browser-auth flow."""

    username: str
    password: str
    tenant_hint: Optional[str] = None
    subscription_id: Optional[str] = None


    region: Optional[str] = None
    session_type: Optional[str] = None


    auth_flow: str = "device_code"


    mfa_ref: str = ""


    mfa_seed: str = ""


def console_creds_from_record_extra(extra: dict[str, Any]) -> AzureConsoleCreds:
    """Rebuild a declared console credential from a registry record."""
    username = str(extra.get("username") or "")
    password = str(extra.get("password") or "")
    if not (username and password):
        raise CredentialError("Azure console credential record is missing username or password.")
    auth_flow = str(extra.get("auth_flow") or "device_code").strip().lower()
    if auth_flow not in {"device_code", "portal"}:
        raise CredentialError(
            f"Azure console credential record has invalid auth_flow {auth_flow!r}."
        )
    return AzureConsoleCreds(
        username=username,
        password=password,
        tenant_hint=str(extra.get("tenant_hint") or extra.get("tenant_id") or "") or None,
        subscription_id=str(extra.get("subscription_id") or "") or None,
        region=str(extra.get("region") or "") or None,
        session_type=str(extra.get("session_type") or "") or None,
        auth_flow=auth_flow,
        mfa_ref=str(extra.get("mfa_ref") or ""),
        mfa_seed=str(extra.get("mfa_seed") or ""),
    )


ParsedAzureCreds = Union[
    AzureServicePrincipalCreds,
    AzureRefreshTokenCreds,
    AzureAccessTokenCreds,
    AzureConsoleCreds,
]


_CRED_FIELD_ALIASES: dict[str, str] = {
    "client_id": "client_id",
    "clientid": "client_id",
    "appid": "client_id",
    "app_id": "client_id",
    "client_secret": "client_secret",
    "clientsecret": "client_secret",
    "secret": "client_secret",
    "password_secret": "client_secret",
    "tenant_id": "tenant_id",
    "tenantid": "tenant_id",


    "tenant": "tenant_id",
    "authority": "tenant_id",
    "subscription_id": "subscription_id",
    "subscriptionid": "subscription_id",
    "subscription": "subscription_id",
    "sub_id": "subscription_id",
    "region": "region",
    "location": "region",
    "preferred_location": "region",
    "cloudshell_region": "region",
    "session_type": "session_type",
    "sessiontype": "session_type",
    "cloudshell_session_type": "session_type",
    "auth_flow": "auth_flow",
    "authflow": "auth_flow",
    "console_auth_flow": "auth_flow",
    "azure_auth_flow": "auth_flow",
    "certificate_path": "certificate_path",
    "certificatepath": "certificate_path",
    "client_certificate_path": "certificate_path",
    "azure_client_certificate_path": "certificate_path",
    "cert_path": "certificate_path",
    "certificate": "certificate_pem",
    "certificate_pem": "certificate_pem",
    "client_certificate": "certificate_pem",
    "certificate_password": "certificate_password",
    "certificatepassword": "certificate_password",
    "client_certificate_password": "certificate_password",
    "azure_client_certificate_password": "certificate_password",
    "cert_password": "certificate_password",
    "refresh_token": "refresh_token",
    "refreshtoken": "refresh_token",
    "access_token": "access_token",
    "accesstoken": "access_token",
    "bearer": "access_token",
    "username": "username",
    "user": "username",
    "user_name": "username",
    "email": "username",
    "password": "password",
    "passwd": "password",
    "pass": "password",
}


def _mfa_alias_rows() -> "dict[str, str]":
    """The MFA rows of ``_CRED_FIELD_ALIASES``, generated from the console family."""
    from cloudbasher.core import mfa_keys

    rows: "dict[str, str]" = {}
    for key in mfa_keys.CONSOLE.keys:
        canonical = key.lower()
        rows[canonical] = canonical
        rows[canonical.replace("_", "")] = canonical
    return rows


_CRED_FIELD_ALIASES.update(_mfa_alias_rows())


def _normalize_key(raw_key: str) -> Optional[str]:
    k = raw_key.strip().strip('"').strip("'")
    if k.lower().startswith("export "):
        k = k[len("export ") :].strip()
    if k.upper().startswith("AZURE_"):
        k = k[len("AZURE_") :]
    return _CRED_FIELD_ALIASES.get(k.lower())


def _parse_keyvalue_lines(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sep_idx = -1
        for sep in (":", "="):
            i = line.find(sep)
            if i > 0 and (sep_idx == -1 or i < sep_idx):
                sep_idx = i
        if sep_idx < 0:
            continue
        raw_key = line[:sep_idx].strip()
        raw_val = line[sep_idx + 1 :].strip().strip('"').strip("'")
        canonical = _normalize_key(raw_key)
        if canonical:
            out[canonical] = raw_val
    return out


def _msal_cache_first_refresh_token(cache: dict[str, Any]) -> Optional[dict[str, str]]:
    rts = cache.get("RefreshToken")
    if not isinstance(rts, dict) or not rts:
        return None
    rt_key = sorted(rts.keys())[0]
    rt_entry = rts[rt_key]
    if not isinstance(rt_entry, dict):
        return None
    refresh_token = rt_entry.get("secret")
    client_id = rt_entry.get("client_id")
    if not refresh_token or not client_id:
        return None
    home_account_id = rt_entry.get("home_account_id", "")
    accounts = cache.get("Account") or {}
    tenant_id = ""
    for acc in accounts.values():
        if isinstance(acc, dict) and acc.get("home_account_id") == home_account_id:
            tenant_id = acc.get("realm") or ""
            break
    return {
        "refresh_token": refresh_token,
        "client_id": client_id,
        "tenant_id": tenant_id,
    }


def parse_creds_file(path: str) -> ParsedAzureCreds:
    """Parse a credential file and return the matching typed dataclass."""
    from cloudbasher.core.secret_refs import read_credential_file

    try:
        text = read_credential_file(path)
    except CredentialError:
        raise
    except FileNotFoundError:
        raise CredentialError(f"Credential file not found: {path}")
    except OSError as exc:
        raise CredentialError(f"Could not read {path}: {exc}") from exc

    is_json_path = path.lower().endswith(".json")
    return parse_creds_text(text, source=path, force_json=is_json_path)


def parse_creds_text(
    text: str, *, source: str = "<credential text>", force_json: bool = False
) -> ParsedAzureCreds:
    """Same format detection as parse_creds_file(), but from an in-memory string."""
    stripped = text.lstrip()
    parsed_dict: dict[str, Any]

    looks_like_json = stripped.startswith("{") or stripped.startswith("[")
    if looks_like_json or force_json:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise CredentialError(f"Invalid JSON in credential file {source}: {exc}") from exc
        if not isinstance(obj, dict):
            raise CredentialError(f"Credential file must be a JSON object: {source}")
        if any(k in obj for k in ("RefreshToken", "AccessToken", "IdToken", "Account")):
            extracted = _msal_cache_first_refresh_token(obj)
            if extracted is None:
                raise CredentialError(
                    f"{source}: looks like an MSAL token cache but has no usable refresh_token entry."
                )
            parsed_dict = extracted
        else:
            parsed_dict = {}
            for raw_key, val in obj.items():
                if not isinstance(val, str):
                    continue
                canonical = _normalize_key(raw_key)
                if canonical:
                    parsed_dict[canonical] = val
    else:
        parsed_dict = _parse_keyvalue_lines(text)

    has = lambda k: bool(parsed_dict.get(k))

    if has("username") and has("password"):
        auth_flow = (parsed_dict.get("auth_flow") or "device_code").strip().lower()
        if auth_flow not in {"device_code", "portal"}:
            raise CredentialError(
                f"{source}: Azure console auth_flow must be 'device_code' or 'portal', "
                f"not {auth_flow!r}."
            )
        return AzureConsoleCreds(
            username=parsed_dict["username"],
            password=parsed_dict["password"],
            tenant_hint=parsed_dict.get("tenant_id") or None,
            subscription_id=parsed_dict.get("subscription_id") or None,
            region=parsed_dict.get("region") or None,
            session_type=parsed_dict.get("session_type") or None,
            auth_flow=auth_flow,


            mfa_ref=parsed_dict.get("mfa_code") or parsed_dict.get("totp") or "",
            mfa_seed=parsed_dict.get("mfa_secret") or "",
        )

    has_cert = has("certificate_path") or has("certificate_pem")
    if has("client_secret") or has_cert:
        missing = [k for k in ("tenant_id", "client_id") if not has(k)]
        if missing:
            proof = "a certificate" if has_cert else "client_secret"
            raise CredentialError(
                f"{source}: service principal is missing field(s): {', '.join(missing)}. "
                f"Required: tenant_id, client_id, and {proof}."
            )
        if has("client_secret") and has_cert:


            raise CredentialError(
                f"{source}: this service principal block declares BOTH a "
                "client_secret and a certificate. Exactly one is the app's "
                "proof of identity -- remove whichever is not."
            )
        return AzureServicePrincipalCreds(
            tenant_id=parsed_dict["tenant_id"],
            client_id=parsed_dict["client_id"],
            client_secret=parsed_dict.get("client_secret", ""),
            subscription_id=parsed_dict.get("subscription_id") or None,
            certificate_path=parsed_dict.get("certificate_path") or None,
            certificate_pem=parsed_dict.get("certificate_pem") or None,
            certificate_password=parsed_dict.get("certificate_password") or None,
        )

    if has("refresh_token"):
        if not has("tenant_id"):
            raise CredentialError(f"{source}: refresh_token credential is missing tenant_id.")
        return AzureRefreshTokenCreds(
            tenant_id=parsed_dict["tenant_id"],
            refresh_token=parsed_dict["refresh_token"],
            subscription_id=parsed_dict.get("subscription_id") or None,
            client_id=parsed_dict.get("client_id") or None,
            region=parsed_dict.get("region") or None,
            session_type=parsed_dict.get("session_type") or None,
            username=parsed_dict.get("username") or None,
        )

    if has("access_token"):
        if not has("tenant_id"):
            raise CredentialError(f"{source}: access_token credential is missing tenant_id.")
        return AzureAccessTokenCreds(
            tenant_id=parsed_dict["tenant_id"],
            access_token=parsed_dict["access_token"],
            subscription_id=parsed_dict.get("subscription_id") or None,
            region=parsed_dict.get("region") or None,
            session_type=parsed_dict.get("session_type") or None,
            username=parsed_dict.get("username") or None,
        )

    if has("client_id") and has("tenant_id") and not has("client_secret"):
        raise CredentialError(
            f"{source}: client_id and tenant_id present, but no proof of "
            "identity. Add a client_secret, or a certificate "
            "(certificate_path=/path/to/key.pem, or certificate_pem=<inline "
            "PEM>), or use --flow refresh / --flow device with a different "
            "cred file."
        )

    raise CredentialError(
        f"Cannot determine credential type from {source}. Expected one of: "
        f"(client_id+client_secret+tenant_id), "
        f"(client_id+certificate_path|certificate_pem+tenant_id), "
        f"(refresh_token+tenant_id), "
        f"(access_token+tenant_id), "
        f"(username+password). Got fields: {sorted(parsed_dict.keys())}"
    )


def _load_cred_file(path: str) -> dict[str, Any]:
    from cloudbasher.core.secret_refs import read_credential_file

    try:
        content = read_credential_file(path).strip()
    except CredentialError:
        raise
    except FileNotFoundError:
        raise CredentialError(f"Credential file not found: {path}")


    lines = [l.strip() for l in content.splitlines() if l.strip()]
    raw = lines[-1] if lines else content
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CredentialError(f"Invalid JSON in credential file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise CredentialError(f"Credential file must be a JSON object: {path}")
    return data


def _certificate_fields(data: dict[str, Any]) -> dict[str, Any]:
    """The certificate material to carry on the credential, or {}."""
    return {
        key: data[key]
        for key in ("certificate_path", "certificate_pem", "certificate_password")
        if data.get(key)
    }


def _msal_client_credential(data: dict[str, Any]) -> Any:
    """What to hand MSAL as `client_credential` -- a secret string, or a cert dict."""
    secret = data.get("client_secret") or ""
    cert_path = data.get("certificate_path") or ""
    cert_pem = data.get("certificate_pem") or ""
    if secret and not (cert_path or cert_pem):
        return secret
    if not (cert_path or cert_pem):
        raise CredentialError(
            "Service principal has neither a client_secret nor a certificate -- "
            "there is nothing to authenticate with."
        )

    if cert_path and not cert_pem:
        path = Path(str(cert_path)).expanduser()
        try:
            cert_pem = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise CredentialError(
                f"Service principal certificate: cannot read {path} -- {exc}"
            ) from exc

    return _certificate_credential(cert_pem, data.get("certificate_password") or "")


def _certificate_credential(pem_text: str, passphrase: str) -> dict[str, Any]:
    """Split a PEM bundle into MSAL's certificate credential dict."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import load_pem_x509_certificate
    except ImportError as exc:  # pragma: no cover - msal depends on cryptography
        raise CredentialError(
            "Certificate authentication needs the `cryptography` package "
            f"(installed as an msal dependency): {exc}"
        ) from exc

    text = pem_text.strip()
    if not text:
        raise CredentialError("Service principal certificate: the PEM is empty.")

    has_key = "PRIVATE KEY-----" in text
    has_cert = "BEGIN CERTIFICATE-----" in text
    if not has_key or not has_cert:
        missing = "the private key" if not has_key else "the certificate"
        raise CredentialError(
            f"Service principal certificate: this PEM is missing {missing}. "
            "MSAL needs both -- the key signs the client assertion, and the "
            "thumbprint that identifies which registered credential is being "
            "used can only be computed from the certificate. Concatenate the "
            "two files, or pass the one that already holds both."
        )

    try:
        private_key = serialization.load_pem_private_key(
            text.encode("utf-8"),
            password=passphrase.encode("utf-8") if passphrase else None,
        )
    except (TypeError, ValueError) as exc:


        hint = (
            " The key looks encrypted -- add certificate_password."
            if not passphrase and "encrypt" in str(exc).lower()
            else " The passphrase may be wrong."
            if passphrase
            else ""
        )
        raise CredentialError(
            f"Service principal certificate: cannot load the private key -- {exc}.{hint}"
        ) from exc

    marker = "-----BEGIN CERTIFICATE-----"
    cert_body = marker + text.split(marker, 1)[1]
    end = "-----END CERTIFICATE-----"
    cert_body = cert_body.split(end, 1)[0] + end
    certificate = load_pem_x509_certificate(cert_body.encode("utf-8"))


    thumbprint = certificate.fingerprint(hashes.SHA1()).hex()

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    detail(
        f"azure: service principal will authenticate with a certificate "
        f"thumbprint={thumbprint[:8]}... expires={certificate.not_valid_after_utc:%Y-%m-%d}"
    )
    return {
        "private_key": key_pem,
        "thumbprint": thumbprint,
        "public_certificate": cert_body,
    }


def _cred_from_service_principal(data: dict[str, Any]) -> Credentials:
    """Mint access token from service principal (client_credentials grant)."""
    _require_msal()
    required = ["client_id", "tenant_id"]
    missing = [k for k in required if not data.get(k)]
    if missing:
        raise CredentialError(f"Service principal credential missing keys: {missing}")


    client_credential = _msal_client_credential(data)

    sub = _resolve_subscription(data)
    if not sub:
        raise CredentialError(
            "subscription_id required. Add it to the credential file or set "
            "AZURE_SUBSCRIPTION_ID environment variable."
        )

    app = _msal_module.ConfidentialClientApplication(
        client_id=data["client_id"],
        client_credential=client_credential,
        authority=f"https://login.microsoftonline.com/{data['tenant_id']}",
    )
    result = app.acquire_token_for_client(scopes=[_ARM_SCOPE])
    _check_msal_result(
        result,
        "service principal client_credentials"
        + (" (certificate)" if isinstance(client_credential, dict) else " (secret)"),
    )

    return to_unified(
        access_token=result["access_token"],
        tenant_id=data["tenant_id"],
        subscription_id=sub,
        token_expiry=_expiry_from_result(result),
        client_id=data["client_id"],
        client_secret=data.get("client_secret") or "",
        extra={
            "msal_app": app,
            "scopes": [_ARM_SCOPE],
            **_certificate_fields(data),
        },
    )


def _cred_from_refresh_token(data: dict[str, Any]) -> Credentials:
    """Exchange refresh_token for access token."""
    _require_msal()
    tenant_id = _resolve_tenant(data)
    if not tenant_id:
        raise CredentialError("tenant_id required for refresh_token credentials.")
    sub = _resolve_subscription(data)
    if not sub:
        raise CredentialError(
            "subscription_id required. Add it to the credential file or set "
            "AZURE_SUBSCRIPTION_ID environment variable."
        )


    client_id = data.get("client_id") or ""
    if not client_id and data.get("access_token"):
        jwt_claims = _decode_jwt_payload(data["access_token"])
        client_id = jwt_claims.get("appid") or jwt_claims.get("azp") or ""
    if not client_id:
        client_id = _MSAL_CLIENT_ID
    app = _msal_module.PublicClientApplication(
        client_id=client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )
    result = app.acquire_token_by_refresh_token(
        refresh_token=data["refresh_token"],
        scopes=[_ARM_SCOPE],
    )
    _check_msal_result(result, "refresh_token exchange")

    return to_unified(
        access_token=result["access_token"],
        tenant_id=tenant_id,
        subscription_id=sub,
        refresh_token=result.get("refresh_token", data["refresh_token"]),
        token_expiry=_expiry_from_result(result),
        client_id=client_id,
        email=_email_from_result(result),
        extra={
            "msal_app": app,
            "scopes": [_ARM_SCOPE],
            "region": data.get("region") or "",
            "session_type": data.get("session_type") or "",
            "cloudshell_region": data.get("region") or "",
            "cloudshell_session_type": data.get("session_type") or "",
        },
    )


def _cred_from_access_token(data: dict[str, Any]) -> Credentials:
    """Load pre-existing access token (short-lived, no refresh)."""
    tenant_id = _resolve_tenant(data)
    sub = _resolve_subscription(data)
    if not tenant_id or not sub:
        raise CredentialError(
            "tenant_id and subscription_id required when using access_token credentials."
        )
    return to_unified(
        access_token=data["access_token"],
        tenant_id=tenant_id,
        subscription_id=sub,
        email=data.get("email"),
        extra={
            "region": data.get("region") or "",
            "session_type": data.get("session_type") or "",
            "cloudshell_region": data.get("region") or "",
            "cloudshell_session_type": data.get("session_type") or "",
        },
    )


def load_credentials_from_file(path: str) -> Credentials:
    """Load credentials from a credential file. Auto-detects credential type."""
    parsed = parse_creds_file(path)

    if isinstance(parsed, AzureServicePrincipalCreds):
        log(f"Loading service principal credentials from {path}")
        return _cred_from_service_principal(
            {
                "client_id": parsed.client_id,
                "client_secret": parsed.client_secret,
                "tenant_id": parsed.tenant_id,
                "subscription_id": parsed.subscription_id or "",
                "certificate_path": parsed.certificate_path or "",
                "certificate_pem": parsed.certificate_pem or "",
                "certificate_password": parsed.certificate_password or "",
            }
        )
    if isinstance(parsed, AzureRefreshTokenCreds):
        log(f"Loading refresh_token credentials from {path}")
        return _cred_from_refresh_token(
            {
                "tenant_id": parsed.tenant_id,
                "refresh_token": parsed.refresh_token,
                "subscription_id": parsed.subscription_id or "",
                "client_id": parsed.client_id or _MSAL_CLIENT_ID,
                "region": parsed.region or "",
                "session_type": parsed.session_type or "",
            }
        )
    if isinstance(parsed, AzureAccessTokenCreds):
        log(f"Loading access_token credentials from {path}")
        return _cred_from_access_token(
            {
                "tenant_id": parsed.tenant_id,
                "access_token": parsed.access_token,
                "subscription_id": parsed.subscription_id or "",
                "region": parsed.region or "",
                "session_type": parsed.session_type or "",
            }
        )
    if isinstance(parsed, AzureConsoleCreds):
        raise CredentialError(
            f"{path}: console credentials (username/password) cannot be used "
            f"with load_credentials_from_file — they require a Playwright login "
            f"driver. Pass the file to the console-flow dispatcher "
            f"explicitly."
        )
    raise CredentialError(f"Unrecognized parsed credential type: {type(parsed).__name__}")


def _list_subscriptions(access_token: str) -> list[dict[str, Any]]:
    """List ARM subscriptions visible to the authenticated user."""
    url = "https://management.azure.com/subscriptions?api-version=2022-12-01"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise CredentialError(
            f"Failed to list subscriptions (HTTP {exc.code}): {exc.reason}"
        ) from exc
    except Exception as exc:
        raise CredentialError(f"Failed to list subscriptions: {exc}") from exc
    return data.get("value", [])


def _list_tenants(access_token: str) -> list[dict[str, Any]]:
    """List all AAD tenants the authenticated user has access to."""
    url = "https://management.azure.com/tenants?api-version=2022-12-01"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        log(f"Warning: could not list tenants: {exc}")
        return []
    return data.get("value", [])


def _find_cloudshell_subscription(
    access_token: str,
    subscriptions: list[dict[str, Any]],
    preferred_sub_id: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    """Return the first subscription that has CloudShell user settings configured."""
    _API = "2023-02-01-preview"
    url = (
        f"https://management.azure.com/providers/Microsoft.Portal/"
        f"userSettings/cloudconsole?api-version={_API}"
    )
    ordered = sorted(
        subscriptions,
        key=lambda s: s["subscriptionId"] != (preferred_sub_id or ""),
    )
    for sub in ordered:
        log(f"  GET userSettings (tenant-level path)")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                props = data.get("properties", data)
                storage = resolve_storage_profile(props)
                region = props.get("preferredLocation", "")
                shell = props.get("preferredShellType", "")
                os_type = props.get("preferredOsType", "")
                net = " network=Isolated" if is_isolated_console(props) else ""
                log(f"    → 200 OK  region={region}  shell={shell}  os={os_type}{net}")
                if storage:
                    acct = storage.get("storageAccountResourceId", "")
                    share = storage.get("fileShareName", "")
                    disk = storage.get("diskSizeInGB", "")
                    log(f"    storageAccount={acct}")
                    log(f"    fileShare={share}  diskSizeGB={disk}")
                if storage or region:
                    return sub
                log("    → settings present but empty (no storage profile/preferredLocation)")
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode(errors="replace")[:120]
            except Exception:
                pass
            log(f"    → HTTP {exc.code}: {exc.reason}  {body}")
            if exc.code in (401, 403, 404):
                continue
        except Exception as exc:
            log(f"    → error: {exc}")
    return None


def _foci_exchange(
    refresh_token: str,
    candidates: list[tuple[str, str]],
    exclude_client_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
) -> Optional[tuple[str, Any, dict[str, Any]]]:
    """Attempt FOCI token exchange with each candidate app."""
    authority = (
        f"https://login.microsoftonline.com/{tenant_id}"
        if tenant_id
        else "https://login.microsoftonline.com/organizations"
    )
    for client_id, name in candidates:
        if client_id == exclude_client_id:
            continue
        app = _msal_module.PublicClientApplication(client_id=client_id, authority=authority)
        result = app.acquire_token_by_refresh_token(
            refresh_token=refresh_token,
            scopes=[_ARM_SCOPE],
        )
        if "access_token" in result:
            log(f"FOCI exchange succeeded: {name} ({client_id})")
            return client_id, app, result
        err = result.get("error_description", result.get("error", ""))[:120]
        log(f"FOCI exchange {name}: {err}")
    return None


def load_credentials_from_oauth_discover(
    *, interactive: bool = True, no_browser: bool = False, login_hint: Optional[str] = None
) -> Credentials:
    """OAuth login with automatic tenant + subscription discovery."""
    _require_msal()

    result: Optional[dict[str, Any]] = None
    auth_app: Optional[Any] = None
    auth_client_id: Optional[str] = None

    def _authority(hint: Optional[str]) -> str:
        if hint and "@" in hint:
            domain = hint.split("@", 1)[1].strip()
            if domain:
                return f"https://login.microsoftonline.com/{domain}"
        return "https://login.microsoftonline.com/organizations"

    for _hint_pass in range(2):
        if _hint_pass == 1 and not login_hint:
            break

        had_aadsts50059 = False
        result = auth_app = auth_client_id = None  # type: ignore[assignment]
        authority = _authority(login_hint)
        if login_hint:
            log(f"Using tenant authority: {authority}")

        for candidate_id, candidate_name in _AUTH_CANDIDATES:
            app = _msal_module.PublicClientApplication(
                client_id=candidate_id,
                authority=authority,
            )

            if (
                result is None
                and not no_browser
                and hasattr(_msal_module.PublicClientApplication, "acquire_token_interactive")
            ):
                log(f"Opening browser OAuth ({candidate_name}, app={candidate_id[:8]}...)...")
                try:
                    browser_kwargs: dict[str, Any] = {"scopes": [_ARM_SCOPE]}
                    if login_hint:
                        browser_kwargs["login_hint"] = login_hint
                    r = app.acquire_token_interactive(**browser_kwargs)
                    if "access_token" in r:
                        result, auth_app, auth_client_id = r, app, candidate_id
                        break
                    err_desc = r.get("error_description", "")
                    if "AADSTS700016" in err_desc or "unauthorized_client" in r.get("error", ""):
                        log(f"App {candidate_id[:8]} blocked by tenant — trying next")
                        continue
                    if "AADSTS50059" in err_desc:
                        log(f"App {candidate_id[:8]}: AADSTS50059 (no tenant hint) — trying next")
                        had_aadsts50059 = True
                        continue
                    if "AADSTS7000218" in err_desc:
                        log(f"App {candidate_id[:8]} is a confidential client — trying next")
                        continue
                except Exception as exc:
                    log(f"Browser OAuth failed ({candidate_id[:8]}): {exc} — trying device code")

            if result is not None:
                break

            flow = app.initiate_device_flow(scopes=[_ARM_SCOPE])
            if "user_code" not in flow:
                err_desc = flow.get("error_description", "")
                if "AADSTS700016" in err_desc or flow.get("error") == "unauthorized_client":
                    log(f"App {candidate_id[:8]} blocked by tenant — trying next")
                    continue
                if "AADSTS50059" in err_desc:
                    log(f"App {candidate_id[:8]}: AADSTS50059 (no tenant hint) — trying next")
                    had_aadsts50059 = True
                    continue
                if "AADSTS7000218" in err_desc:
                    log(f"App {candidate_id[:8]} requires client_secret — skipping device code")
                    continue
                raise CredentialError(f"Device flow initiation failed: {err_desc or flow}")

            eprint(f"\n{flow['message']}\n")
            log(f"Waiting for device code authentication (app={candidate_id[:8]}...)...")
            try:
                r = app.acquire_token_by_device_flow(flow)
            except KeyboardInterrupt:
                raise CredentialError("Authentication cancelled.")

            if "access_token" in r:
                result, auth_app, auth_client_id = r, app, candidate_id
                break
            err_desc = r.get("error_description", r.get("error", ""))
            if "AADSTS700016" in err_desc or r.get("error") == "unauthorized_client":
                log(f"App {candidate_id[:8]} blocked by tenant — trying next")
                continue
            if "AADSTS7000218" in err_desc:
                log(f"App {candidate_id[:8]} is a confidential client — trying next")
                continue
            raise CredentialError(f"Authentication failed: {err_desc}")

        if result is not None:
            break

        if had_aadsts50059 and login_hint is None and interactive:
            eprint(
                "\nAzure cannot identify your tenant (AADSTS50059).\n"
                "Some tenants require an email hint to route the login request.\n"
            )
            try:
                login_hint = input("Enter your email or UPN (e.g. user@example.invalid): ").strip()
            except (EOFError, KeyboardInterrupt):
                raise CredentialError("Authentication cancelled.")
            if not login_hint:
                raise CredentialError(
                    "Email/UPN required. Re-run with --login-hint user@example.invalid"
                )
        else:
            break

    if result is None:
        raise CredentialError(
            "Authentication failed: all app candidates were rejected by the tenant.\n"
            "Ask your tenant admin to consent an application for Azure CloudShell access."
        )

    _check_msal_result(result, "OAuth discovery flow")
    log(f"Authenticated with app={auth_client_id}")

    claims = result.get("id_token_claims", {})
    tenant_id = claims.get("tid", "")
    if not tenant_id:
        _jwt = _decode_jwt_payload(result.get("access_token", ""))
        tenant_id = _jwt.get("tid", "")
    if not tenant_id:
        raise CredentialError("Could not determine tenant_id from OAuth token claims.")

    email = _email_from_result(result)
    expiry = _expiry_from_result(result)
    log(f"Authenticated as {email or 'unknown'}")
    log(f"  token tenant (tid): {tenant_id}")
    log(f"  client_id:          {auth_client_id}")
    log(f"  token_expiry:       {expiry}")


    subscriptions = _list_subscriptions(result["access_token"])
    if not subscriptions:
        rt = result.get("refresh_token", "")
        tenants = _list_tenants(result["access_token"])
        log(
            f"No subscriptions found in home tenant {tenant_id} — "
            f"checking {len(tenants)} tenant(s) via cross-tenant discovery..."
        )
        for t in tenants:
            tid = t.get("tenantId", "")
            if not tid or tid == tenant_id:
                continue
            log(f"  Trying tenant {tid} ({t.get('displayName', '?')})...")
            if not rt:
                log("    No refresh_token available — cannot exchange for this tenant")
                continue
            try:
                app2 = _msal_module.PublicClientApplication(
                    client_id=auth_client_id,
                    authority=f"https://login.microsoftonline.com/{tid}",
                )
                r2 = app2.acquire_token_by_refresh_token(refresh_token=rt, scopes=[_ARM_SCOPE])
                if "access_token" not in r2:
                    log(
                        f"    Token exchange failed: {r2.get('error_description', r2.get('error', '?'))}"
                    )
                    continue
                subs = _list_subscriptions(r2["access_token"])
                if subs:
                    log(f"    Found {len(subs)} subscription(s) in tenant {tid}")
                    subscriptions.extend(subs)
            except Exception as exc:
                log(f"    Error checking tenant {tid}: {exc}")
    if not subscriptions:
        raise CredentialError(
            "No Azure subscriptions found for this account. "
            "Ensure your account has access to at least one subscription."
        )

    log(f"Found {len(subscriptions)} subscription(s):")
    for s in subscriptions:
        log(
            f"  sub={s['subscriptionId']}  tenant={s.get('tenantId', '?')}  "
            f"state={s.get('state', '?')}  name={s.get('displayName', '?')}"
        )

    if len(subscriptions) == 1:
        sub = subscriptions[0]
        subscription_id = sub["subscriptionId"]
        log(f"Using subscription: {sub.get('displayName', subscription_id)} ({subscription_id})")
    elif not interactive:
        sub = subscriptions[0]
        subscription_id = sub["subscriptionId"]
        log(
            f"Auto-selected subscription: {sub.get('displayName', subscription_id)} ({subscription_id})"
        )
    else:
        eprint("\nAvailable Azure subscriptions:")
        for i, s in enumerate(subscriptions, 1):
            eprint(f"  {i}. {s.get('displayName', s['subscriptionId'])} ({s['subscriptionId']})")
        while True:
            try:
                choice = input(f"Select subscription [1-{len(subscriptions)}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                raise CredentialError("Subscription selection cancelled.")
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(subscriptions):
                    sub = subscriptions[idx]
                    subscription_id = sub["subscriptionId"]
                    break
            except ValueError:
                pass
            eprint(f"Enter a number between 1 and {len(subscriptions)}.")

    log(f"Selected subscription: {subscription_id}  tenant={sub.get('tenantId', '?')}")

    log(f"Checking CloudShell user settings for subscription {subscription_id}...")
    cloudshell_sub = _find_cloudshell_subscription(
        result["access_token"], subscriptions, preferred_sub_id=subscription_id
    )
    if cloudshell_sub is None:
        log(
            "Warning: CloudShell user settings not found in any accessible subscription. "
            "Visit https://shell.azure.com to complete the storage setup wizard."
        )
    elif cloudshell_sub["subscriptionId"] != subscription_id:
        cs_name = cloudshell_sub.get("displayName", cloudshell_sub["subscriptionId"])
        cs_id = cloudshell_sub["subscriptionId"]
        eprint(
            f"\nNote: CloudShell storage is configured in subscription "
            f"'{cs_name}' ({cs_id}),\n"
            f"not the selected subscription. Using that for CloudShell access.\n"
        )
        log(f"Switching CloudShell subscription: {subscription_id} → {cs_id}")
        sub = cloudshell_sub
        subscription_id = cs_id
    else:
        log(f"CloudShell user settings confirmed in subscription {subscription_id}")

    sub_tenant_id = sub.get("tenantId", tenant_id)
    access_token = result["access_token"]
    refresh_token = result.get("refresh_token")

    log(f"Token tenant: {tenant_id}  subscription tenant: {sub_tenant_id}")
    if sub_tenant_id and sub_tenant_id != tenant_id:
        log(
            f"Subscription tenant ({sub_tenant_id}) differs from token tenant ({tenant_id})"
            " — re-acquiring token for subscription tenant"
        )
        rt = result.get("refresh_token")
        if rt:
            app2 = _msal_module.PublicClientApplication(
                client_id=auth_client_id,
                authority=f"https://login.microsoftonline.com/{sub_tenant_id}",
            )
            result2 = app2.acquire_token_by_refresh_token(
                refresh_token=rt,
                scopes=[_ARM_SCOPE],
            )
            if "access_token" in result2:
                access_token = result2["access_token"]
                refresh_token = result2.get("refresh_token", rt)
                tenant_id = sub_tenant_id
                auth_app = app2
                log(f"Token re-acquired for subscription tenant ({sub_tenant_id})")
            else:
                err = result2.get("error_description", result2.get("error", "unknown"))
                log(f"Tenant-specific token exchange failed: {err} — using original token")
        else:
            log("No refresh_token available — cannot re-acquire for subscription tenant")

    final_app = auth_app
    if auth_client_id != _CLOUDSHELL_APP_CLIENT_ID and refresh_token:
        log(
            f"Auth app ({auth_client_id}) is not the preferred CloudShell app — "
            "attempting FOCI exchange..."
        )
        foci = _foci_exchange(
            refresh_token,
            _FOCI_CANDIDATES,
            exclude_client_id=auth_client_id,
            tenant_id=tenant_id,
        )
        if foci:
            foci_cid, foci_app, foci_result = foci
            access_token = foci_result["access_token"]
            refresh_token = foci_result.get("refresh_token", refresh_token)
            final_app = foci_app
            log(f"Using FOCI-exchanged token (app={foci_cid})")
        else:
            log("FOCI exchange: no candidate succeeded — proceeding with original token")

    log(
        f"OAuth discovery complete: email={email}  tenant={tenant_id}  "
        f"subscription={subscription_id}  app={auth_client_id}"
    )

    return to_unified(
        access_token=access_token,
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        refresh_token=refresh_token,
        token_expiry=expiry,
        email=email,
        extra={"msal_app": final_app, "scopes": [_ARM_SCOPE]},
    )


def load_credentials_from_browser(tenant_id: str, subscription_id: str) -> Credentials:
    """3LO OAuth browser flow — opens system browser for interactive sign-in."""
    _require_msal()
    if not hasattr(_msal_module.PublicClientApplication, "acquire_token_interactive"):
        raise CredentialError(
            "Browser OAuth requires msal >= 1.10.0. Run: pip install --upgrade msal"
        )

    app = _make_public_client_app(tenant_id)
    log("Opening browser for OAuth authentication...")
    try:
        result = app.acquire_token_interactive(scopes=[_ARM_SCOPE])
    except Exception as exc:
        raise CredentialError(f"Browser OAuth failed: {exc}") from exc

    _check_msal_result(result, "browser OAuth flow")
    return _creds_from_public_client_result(result, app, tenant_id, subscription_id)


def load_credentials_from_device_code(tenant_id: str, subscription_id: str) -> Credentials:
    """Interactive device code OAuth flow — user opens browser and enters code."""
    _require_msal()
    app = _make_public_client_app(tenant_id)
    flow = app.initiate_device_flow(scopes=[_ARM_SCOPE])
    if "user_code" not in flow:
        raise CredentialError(
            f"Device flow initiation failed: {flow.get('error_description', flow)}"
        )

    eprint(f"\n{flow['message']}\n")
    log("Waiting for device code authentication...")

    try:
        result = app.acquire_token_by_device_flow(flow)
    except KeyboardInterrupt:
        raise CredentialError("Authentication cancelled.")
    _check_msal_result(result, "device code flow")
    return _creds_from_public_client_result(result, app, tenant_id, subscription_id)


def _console_creds_from_multi_file(path: str) -> Optional[AzureConsoleCreds]:
    """Return the one declared Azure console block in ``path``, if any."""


    if path.lower().endswith(".json"):
        return None

    from cloudbasher.core.credential_file import parse_multi_creds_file

    azure_blocks = [
        block.parsed for block in parse_multi_creds_file(path) if block.provider == "azure"
    ]
    matches = [parsed for parsed in azure_blocks if isinstance(parsed, AzureConsoleCreds)]
    if len(matches) > 1:
        raise CredentialError(
            f"{path}: found {len(matches)} Azure console credential blocks. "
            "Choose one primary console credential per run."
        )
    if matches and len(azure_blocks) != 1:
        raise CredentialError(
            f"{path}: an Azure console credential cannot be selected from "
            f"{len(azure_blocks)} Azure blocks. Run it as the only Azure block "
            "until per-record Azure bootstrap is implemented."
        )
    return matches[0] if matches else None


def load_credentials_from_console_device_code(
    console: AzureConsoleCreds,
    *,
    headless: bool = True,
) -> Credentials:
    """Approve one Azure-CLI device flow with a declared console credential."""
    tenant_id = console.tenant_hint or ""
    subscription_id = console.subscription_id or ""
    missing = [
        name
        for name, value in (("tenant_id", tenant_id), ("subscription_id", subscription_id))
        if not value
    ]
    if missing:
        raise CredentialError("Azure console credentials require " + ", ".join(missing) + ".")

    _require_msal()


    app = _make_public_client_app(tenant_id, tenant_scoped=True)
    flow = app.initiate_device_flow(scopes=[_ARM_SCOPE])
    user_code = str(flow.get("user_code") or "")
    if not user_code:
        raise CredentialError(
            "Azure device-code initiation failed: "
            f"{flow.get('error_description') or flow.get('error') or 'no user code returned'}"
        )


    from cloudbasher.core import mfa_keys
    from cloudbasher.core.mfa import FactorPrompt, mfa_source
    from cloudbasher.csp.azure.device_flow import approve_device_code
    from cloudbasher.csp.azure.playwright_login import BrowserSession

    factor = FactorPrompt(
        mfa_source(
            ref=console.mfa_ref,
            seed=console.mfa_seed,
            where="Azure console credential",
        ),
        mfa_keys.CONSOLE,
        where="Azure device-code approval",
    )
    with BrowserSession(headless=headless) as browser:
        approval = approve_device_code(
            browser.new_page(),
            console,
            user_code=user_code,
            factor=factor,
            expected_app="Microsoft Azure CLI",
        )
    if not approval.ok:


        raise CredentialError(f"Azure device-code approval failed: {approval.error}")

    try:
        result = app.acquire_token_by_device_flow(flow)
    except KeyboardInterrupt as exc:
        raise CredentialError("Azure device-code authentication cancelled.") from exc
    _check_msal_result(result, "Azure console device-code flow")
    return to_unified(
        access_token=result["access_token"],
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        refresh_token=result.get("refresh_token"),
        token_expiry=_expiry_from_result(result),
        client_id=_MSAL_CLIENT_ID,
        email=_email_from_result(result),
        extra={
            "msal_app": app,
            "scopes": [_ARM_SCOPE],
            "cloudshell_region": console.region or "",
            "cloudshell_session_type": console.session_type or "",
        },
    )


def load_credentials_from_console_portal(
    console: AzureConsoleCreds,
    *,
    headless: bool = True,
) -> Credentials:
    """Use a declared console credential for Portal's in-memory ARM handoff."""
    tenant_id = console.tenant_hint or ""
    subscription_id = console.subscription_id or ""
    missing = [
        name
        for name, value in (("tenant_id", tenant_id), ("subscription_id", subscription_id))
        if not value
    ]
    if missing:
        raise CredentialError("Azure console credentials require " + ", ".join(missing) + ".")

    from cloudbasher.core.mfa import mfa_source
    from cloudbasher.csp.azure.portal_auth import PortalAudienceTokenProvider


    source = mfa_source(
        ref=console.mfa_ref,
        seed=console.mfa_seed,
        where="Azure console credential",
    )


    token_provider = PortalAudienceTokenProvider(
        console,
        mfa=source,
        expected_tenant=tenant_id,
        headless=headless,
    )
    handoff = token_provider.take_initial_token()
    import atexit

    atexit.register(token_provider.close)
    credentials = to_unified(
        access_token=handoff.access_token,
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        token_expiry=handoff.expires_at,
        client_id=handoff.client_id,
        extra={
            "scopes": [_ARM_SCOPE],
            "portal_handoff": True,
            "cloudshell_region": console.region or "",
            "cloudshell_session_type": console.session_type or "",
        },
    )
    credentials._runtime_audience_token_provider = token_provider
    return credentials


def load_credentials_from_console(
    console: AzureConsoleCreds,
    *,
    headless: bool = True,
) -> Credentials:
    """Authenticate one declared console credential through its chosen flow."""
    if console.auth_flow == "portal":
        return load_credentials_from_console_portal(console, headless=headless)
    return load_credentials_from_console_device_code(console, headless=headless)


def load_credentials_from_record_extra(
    extra: dict[str, Any], *, headless: bool = True
) -> Credentials:
    """Materialize one Azure credential declaration stored in a registry record."""
    if extra.get("username") and extra.get("password"):
        return load_credentials_from_console(
            console_creds_from_record_extra(extra), headless=headless
        )

    common = {
        "tenant_id": str(extra.get("tenant_id") or ""),
        "subscription_id": str(extra.get("subscription_id") or ""),
        "region": str(extra.get("region") or extra.get("cloudshell_region") or ""),
        "session_type": str(
            extra.get("session_type") or extra.get("cloudshell_session_type") or ""
        ),
    }
    if extra.get("refresh_token"):
        return _cred_from_refresh_token(
            {
                **common,
                "refresh_token": extra["refresh_token"],
                "client_id": extra.get("client_id") or _MSAL_CLIENT_ID,
                "access_token": extra.get("access_token") or "",
            }
        )
    if extra.get("access_token"):
        return _cred_from_access_token(
            {**common, "access_token": extra["access_token"]}
        )
    raise CredentialError(
        "Azure credential record has no supported Console, refresh-token, or access-token material."
    )


def bind_refresh_token_rotation(
    credentials: Credentials, record_extra: dict[str, Any]
) -> None:
    """Keep a live refresh-token rotation in the encrypted registry record."""
    token = (credentials.extra or {}).get("refresh_token")
    if not token:
        return
    record_extra["refresh_token"] = token

    def _store_rotated(value: str) -> None:
        record_extra["refresh_token"] = value

    credentials._runtime_refresh_token_callback = _store_rotated


def preflight_env_error(*, tenant_id: str = "", subscription_id: str = "") -> Optional[str]:
    """Why `--creds-env` cannot work for Azure right now, or None if it can."""
    client_id = os.environ.get("AZURE_CLIENT_ID", "")
    client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")
    resolved_tenant = os.environ.get("AZURE_TENANT_ID", "") or tenant_id
    resolved_sub = os.environ.get("AZURE_SUBSCRIPTION_ID", "") or subscription_id

    missing = [
        name
        for name, value in (
            ("AZURE_CLIENT_ID", client_id),
            ("AZURE_CLIENT_SECRET", client_secret),
            ("AZURE_TENANT_ID", resolved_tenant),
            ("AZURE_SUBSCRIPTION_ID", resolved_sub),
        )
        if not value
    ]
    if not missing:
        return None
    return (
        f"--creds-env: {', '.join(missing)} "
        f"{'is' if len(missing) == 1 else 'are'} not set in this environment.\n"
        "\n"
        "--creds-env is a valid source -- for Azure it needs a service "
        "principal, all four values:\n"
        "  export AZURE_CLIENT_ID=...\n"
        "  export AZURE_CLIENT_SECRET=...\n"
        "  export AZURE_TENANT_ID=...        # or --tenant\n"
        "  export AZURE_SUBSCRIPTION_ID=...  # or --subscription\n"
        "\n"
        "Or read the identity from a file instead: -F/--creds-file PATH.\n"
        "There is no ambient fallback -- the az CLI is not consulted."
    )


class AzureCredentialProvider(CredentialProvider):
    """Tiered credential loader implementing the CredentialProvider interface."""

    def __init__(
        self,
        *,
        credential_file: Optional[str] = None,
        tenant_id: Optional[str] = None,
        subscription_id: Optional[str] = None,
        interactive: bool = True,
        no_browser: bool = False,
        login_hint: Optional[str] = None,
        show_browser: bool = False,
        saved_state: Optional[dict[str, Any]] = None,
        source: str = "file",
    ) -> None:
        self._credential_file = credential_file
        self._tenant_id = tenant_id or os.environ.get("AZURE_TENANT_ID", "")
        self._subscription_id = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
        self._interactive = interactive
        self._no_browser = no_browser
        self._login_hint = login_hint
        self._show_browser = show_browser
        self._saved_state = saved_state or {}
        self.source = source
        self._cached: Optional[Credentials] = None


        self._existing_creds: Optional[Credentials] = None
        if self._saved_state.get("csp") == "azure" and self._saved_state.get("credentials"):
            try:
                d = self._saved_state["credentials"]
                self._existing_creds = to_unified(
                    access_token=d.get("access_token", ""),
                    tenant_id=d.get("tenant_id", ""),
                    subscription_id=d.get("subscription_id", ""),
                    refresh_token=d.get("refresh_token"),
                    token_expiry=(
                        datetime.datetime.fromisoformat(d["token_expiry"])
                        if d.get("token_expiry")
                        else None
                    ),
                    client_id=d.get("client_id"),
                    client_secret=d.get("client_secret"),
                    email=d.get("email"),
                )
            except Exception:
                pass

    def load(self) -> Credentials:
        """Load credentials using first successful tier."""
        if self._cached is not None:
            return self._cached

        errors: list[str] = []

        if self._existing_creds is not None:
            if not is_token_expiring(self._existing_creds):
                fields = from_unified(self._existing_creds)
                log(f"Using credentials from state (email={fields.get('email') or 'unknown'})")
                self._cached = self._existing_creds
                return self._existing_creds
            detail("State credentials are stale — attempting refresh")
            try:
                refreshed = self.refresh(self._existing_creds)
                self._cached = refreshed
                return refreshed
            except CredentialError as exc:
                errors.append(f"State credential refresh: {exc}")
                detail("State credentials could not be refreshed — re-authenticating")

        if self.source == "file" and self._credential_file:


            console = _console_creds_from_multi_file(self._credential_file)
            if console is not None:
                if self._no_browser:
                    raise CredentialError(
                        "Azure console credentials require the browser approval flow; "
                        "remove --no-browser."
                    )
                creds = load_credentials_from_console(
                    console,
                    headless=not self._show_browser,
                )
                self._cached = creds
                return creds
            try:
                creds = load_credentials_from_file(self._credential_file)
                self._cached = creds
                return creds
            except CredentialError as exc:
                log(f"Credential file ({self._credential_file}) failed: {exc}")
                errors.append(f"Credential file ({self._credential_file}): {exc}")


        if self.source == "env":
            _env_client_id = os.environ.get("AZURE_CLIENT_ID", "")
            _env_client_secret = os.environ.get("AZURE_CLIENT_SECRET", "")
            _env_tenant_id = os.environ.get("AZURE_TENANT_ID", "") or self._tenant_id
            _env_sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "") or self._subscription_id
            if not (_env_client_id and _env_client_secret and _env_tenant_id and _env_sub_id):


                raise CredentialError(
                    preflight_env_error(
                        tenant_id=self._tenant_id,
                        subscription_id=self._subscription_id,
                    )
                    or "--creds-env: no usable Azure service principal in the environment."
                )
            try:
                _require_msal()
                _sp_app = _msal_module.ConfidentialClientApplication(
                    client_id=_env_client_id,
                    client_credential=_env_client_secret,
                    authority=f"https://login.microsoftonline.com/{_env_tenant_id}",
                )
                _sp_result = _sp_app.acquire_token_for_client(scopes=[_ARM_SCOPE])
                _check_msal_result(_sp_result, "env var service principal")
                creds = to_unified(
                    access_token=_sp_result["access_token"],
                    tenant_id=_env_tenant_id,
                    subscription_id=_env_sub_id,
                    client_id=_env_client_id,
                    client_secret=_env_client_secret,
                    token_expiry=_expiry_from_result(_sp_result),
                    extra={"msal_app": _sp_app, "scopes": [_ARM_SCOPE]},
                )
                self._cached = creds
                return creds
            except CredentialError as exc:
                errors.append(f"Env vars (service principal): {exc}")

        if self._interactive:
            if not (self._tenant_id and self._subscription_id):
                log("No credentials found — starting OAuth login with auto-discovery...")
                try:
                    creds = load_credentials_from_oauth_discover(
                        interactive=True,
                        no_browser=self._no_browser,
                        login_hint=self._login_hint,
                    )
                    self._cached = creds
                    fields = from_unified(creds)
                    self._tenant_id = fields["tenant_id"]
                    self._subscription_id = fields["subscription_id"]
                    return creds
                except CredentialError as exc:
                    errors.append(f"OAuth discovery: {exc}")
            else:
                try:
                    if self._no_browser:
                        raise CredentialError("Browser flow disabled by --no-browser")
                    log("No credentials found — opening browser for OAuth authentication...")
                    creds = load_credentials_from_browser(self._tenant_id, self._subscription_id)
                    self._cached = creds
                    return creds
                except CredentialError as exc:
                    detail(f"Browser OAuth unavailable: {exc} — falling back to device code")
                    errors.append(f"Browser OAuth: {exc}")
                try:
                    log("Initiating device code flow...")
                    creds = load_credentials_from_device_code(
                        self._tenant_id, self._subscription_id
                    )
                    self._cached = creds
                    return creds
                except CredentialError as exc:
                    errors.append(f"Device code: {exc}")

        raise CredentialError(
            "All credential sources failed:\n"
            + "\n".join(f"  • {e}" for e in errors)
            + "\n\nProvide credentials via:\n"
            "  -F FILE      JSON credential file (service principal or refresh token)\n"
            "  -m           Resume from state_azure.bin\n"
            "  (no args)    Trigger interactive OAuth login with auto-discovery\n"
        )

    def refresh(self, creds: Credentials) -> Credentials:
        """Refresh access token using stored refresh_token or re-acquire."""
        _require_msal()
        fields = from_unified(creds)
        msal_app = fields.get("msal_app")
        scopes = creds.extra.get("scopes", [_ARM_SCOPE]) if creds.extra else [_ARM_SCOPE]

        if _is_client_credentials(fields):
            if msal_app is None:


                msal_app = _msal_module.ConfidentialClientApplication(
                    client_id=fields["client_id"],
                    client_credential=_msal_client_credential(fields),
                    authority=f"https://login.microsoftonline.com/{fields['tenant_id']}",
                )
            result = msal_app.acquire_token_for_client(scopes=scopes)
            _check_msal_result(result, "service principal refresh")

        elif fields.get("refresh_token"):
            if msal_app is None:
                msal_app = _msal_module.PublicClientApplication(
                    client_id=fields.get("client_id") or _MSAL_CLIENT_ID,


                    authority=f"https://login.microsoftonline.com/{fields['tenant_id']}",
                )
            result = msal_app.acquire_token_by_refresh_token(
                refresh_token=fields["refresh_token"],
                scopes=scopes,
            )
            _check_msal_result(result, "refresh_token refresh")

        else:
            raise CredentialError(
                "Cannot refresh: no client_secret, certificate or refresh_token "
                "available. Re-authenticate with --credentials or device code flow."
            )

        new_creds = to_unified(
            access_token=result["access_token"],
            tenant_id=fields["tenant_id"],
            subscription_id=fields["subscription_id"],
            refresh_token=result.get("refresh_token", fields.get("refresh_token")),
            token_expiry=_expiry_from_result(result),
            client_id=fields.get("client_id"),
            client_secret=fields.get("client_secret"),
            email=fields.get("email") or _email_from_result(result),
            extra={"msal_app": msal_app, "scopes": scopes},
        )
        self._cached = new_creds
        log("Access token refreshed successfully.")
        return new_creds


def _is_client_credentials(fields: dict[str, Any]) -> bool:
    """Whether these fields describe a service principal that can re-mint tokens."""
    if not fields.get("client_id"):
        return False
    return bool(
        fields.get("client_secret")
        or fields.get("certificate_path")
        or fields.get("certificate_pem")
    )


def build_refresher(creds: Credentials) -> Optional[Callable[[Credentials], Credentials]]:
    """Return a token-refresh closure for use by AzureCloudShellAPI on 401."""
    fields = from_unified(creds)
    has_refresh = bool(fields.get("refresh_token") or _is_client_credentials(fields))
    if not has_refresh:
        return None

    provider = AzureCredentialProvider(
        tenant_id=fields.get("tenant_id"),
        subscription_id=fields.get("subscription_id"),
        interactive=False,
    )

    def _refresh(current_creds: Credentials) -> Credentials:
        return provider.refresh(current_creds)

    return _refresh


def build_audience_token_provider(
    creds: Credentials,
) -> Optional[Callable[[Credentials, str], str]]:
    """Build a delegated token provider for this live Azure credential."""
    runtime_provider = getattr(creds, "_runtime_audience_token_provider", None)
    if runtime_provider is not None:
        return runtime_provider

    fields = from_unified(creds)
    if (
        creds.access_token
        and not fields.get("refresh_token")
        and not fields.get("client_secret")
        and not fields.get("certificate_path")
        and not fields.get("certificate_pem")
    ):
        def _reuse_validated_static_token(current: Credentials, audience: str) -> str:
            """Reuse a static token only for its exact, already-validated audience."""
            token = current.access_token or ""
            fingerprint = hashlib.sha256(token.encode("utf-8")).hexdigest()
            validated = getattr(current, "_azure_validated_arm_token", None)
            if not isinstance(validated, dict) or validated.get("fingerprint") != fingerprint:
                raise AzureTokenBrokerError("static_token_not_validated")

            claims = _decode_jwt_payload(token)
            claim_audiences = claims.get("aud")
            if isinstance(claim_audiences, str):
                claim_audiences = [claim_audiences]
            if not isinstance(claim_audiences, list) or audience not in claim_audiences:
                raise AzureTokenBrokerError("static_token_audience_mismatch")
            try:
                expires_at = int(claims.get("exp") or 0)
            except (TypeError, ValueError, OverflowError) as exc:
                raise AzureTokenBrokerError("static_token_invalid_expiry") from exc
            if expires_at <= int(time.time()):
                raise AzureTokenBrokerError("static_token_expired")
            return token

        return _reuse_validated_static_token

    if not fields.get("refresh_token") or fields.get("client_id") != _MSAL_CLIENT_ID:
        return None

    provider = AzureCredentialProvider(
        tenant_id=fields.get("tenant_id"),
        subscription_id=fields.get("subscription_id"),
        interactive=False,
    )
    def _acquire(current: Credentials, audience: str) -> str:
        profile = resolve_azure_audience(audience)
        if profile is None:
            raise AzureTokenBrokerError("audience_unsupported")


        scoped = Credentials(
            provider=current.provider,
            access_token=current.access_token,
            email=current.email,
            extra={**(current.extra or {}), "scopes": [profile.scope]},
        )
        try:
            refreshed = provider.refresh(scoped)
        except CredentialError as exc:


            match = re.search(r"\bAADSTS\d+\b", str(exc))
            diagnostic = f"entra_rejected:{match.group(0)}" if match else "entra_refresh_failed"
            raise AzureTokenBrokerError(diagnostic) from exc
        token = refreshed.access_token or ""
        if not token:
            raise AzureTokenBrokerError("refresh_missing_access_token")
        claims = _decode_jwt_payload(token)
        try:
            expires_at = int(claims.get("exp") or 0)
        except (TypeError, ValueError, OverflowError) as exc:
            raise AzureTokenBrokerError("claims_invalid_expiry") from exc
        app_id = str(claims.get("appid") or claims.get("azp") or "").lower()
        actual_audiences = normalized_jwt_audiences(claims)
        accepted_audiences = {value.lower() for value in profile.jwt_audiences}
        if (
            str(claims.get("tid") or "").lower() != str(fields.get("tenant_id") or "").lower()
            or app_id != _MSAL_CLIENT_ID.lower()
            or not actual_audiences.intersection(accepted_audiences)
            or not claims.get("scp")
            or expires_at <= int(time.time())
        ):
            checks = (
                (
                    str(claims.get("tid") or "").lower()
                    == str(fields.get("tenant_id") or "").lower(),
                    "tenant",
                ),
                (app_id == _MSAL_CLIENT_ID.lower(), "client"),
                (bool(actual_audiences.intersection(accepted_audiences)), "audience"),
                (bool(claims.get("scp")), "scope"),
                (expires_at > int(time.time()), "expiry"),
            )
            failed = ",".join(name for passed, name in checks if not passed)
            raise AzureTokenBrokerError(f"claims_rejected:{failed}")


        rotated = (refreshed.extra or {}).get("refresh_token")
        if rotated:
            if current.extra is None:
                current.extra = {}
            current.extra["refresh_token"] = rotated
            callback = getattr(current, "_runtime_refresh_token_callback", None)
            if callable(callback):
                callback(rotated)
        return token

    return _acquire


def _creds_from_public_client_result(
    result: dict[str, Any],
    app: Any,
    tenant_id: str,
    subscription_id: str,
) -> Credentials:
    return to_unified(
        access_token=result["access_token"],
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        refresh_token=result.get("refresh_token"),
        token_expiry=_expiry_from_result(result),
        email=_email_from_result(result),
        extra={"msal_app": app, "scopes": [_ARM_SCOPE]},
    )


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Base64-decode a JWT payload to extract claims (no signature verification)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception:
        return {}


def _check_msal_result(result: dict[str, Any], context: str) -> None:
    if "access_token" not in result:
        err = result.get("error", "unknown_error")
        desc = result.get("error_description", "No description")
        raise CredentialError(f"MSAL {context} failed: {err} — {desc}")


def _expiry_from_result(result: dict[str, Any]) -> Optional[datetime.datetime]:
    expires_in = result.get("expires_in")
    if expires_in is not None:
        return datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            seconds=int(expires_in)
        )
    return None


def _email_from_result(result: dict[str, Any]) -> Optional[str]:
    """Extract user email from MSAL result or JWT access token claims."""
    claims = result.get("id_token_claims", {})
    email = claims.get("preferred_username") or claims.get("email") or claims.get("upn")
    if not email:
        jwt = _decode_jwt_payload(result.get("access_token", ""))
        email = (
            jwt.get("upn")
            or jwt.get("unique_name")
            or jwt.get("preferred_username")
            or jwt.get("email")
        )
    return email
