#!/usr/bin/env python3
"""GCP credential handling for CloudShell runner."""

from __future__ import annotations

import base64
import http.server
import json
import os
import secrets
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Union

from cloudbasher.core.exceptions import CredentialError
from cloudbasher.core.types import Credentials
from cloudbasher.core.utils.output import detail, log, out
from cloudbasher.csp.base import CredentialProvider


_TOKEN_URL = "https://oauth2.googleapis.com/token"
_DEVICE_AUTH_URL = "https://oauth2.googleapis.com/device/code"
_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_CLOUDSHELL_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


_GCLOUD_CLIENT_ID = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
_GCLOUD_CLIENT_SECRET = "d-FL95Q19q7MQmFpd7hHD0Ty"


_REDIRECT_PORTS = [8085, 8086, 8087, 8088, 8089]

_BROWSER_OAUTH_TIMEOUT = 120


_JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"


_GCP_FIELD_ALIASES: dict[str, frozenset[str]] = {
    "type": frozenset({"type", "credential_type", "kind"}),
    "client_id": frozenset({"client_id", "clientid", "client"}),
    "client_secret": frozenset({"client_secret", "clientsecret", "secret"}),
    "refresh_token": frozenset({"refresh_token", "refresh", "token_refresh"}),
    "rapt_token": frozenset({"rapt_token", "rapt"}),
    "access_token": frozenset({"access_token", "access", "token", "bearer_token", "bearer"}),
    "private_key": frozenset({"private_key", "privatekey"}),
    "client_email": frozenset({"client_email", "service_account_email", "email"}),
    "project_id": frozenset({"project_id", "project"}),
    "quota_project_id": frozenset({"quota_project_id", "quota_project"}),
    "username": frozenset({"username", "user", "login"}),
    "password": frozenset({"password", "passwd", "pass"}),

    "SID": frozenset({"sid"}),
    "HSID": frozenset({"hsid"}),
    "SSID": frozenset({"ssid"}),
    "APISID": frozenset({"apisid"}),
    "SAPISID": frozenset({"sapisid"}),
    "NID": frozenset({"nid"}),
    "__Secure-1PSID": frozenset({"__secure-1psid", "secure_1psid", "1psid"}),
    "__Secure-3PSID": frozenset({"__secure-3psid", "secure_3psid", "3psid"}),
    "__Secure-1PAPISID": frozenset({"__secure-1papisid", "secure_1papisid"}),
    "__Secure-3PAPISID": frozenset({"__secure-3papisid", "secure_3papisid"}),
}


_GCP_COOKIE_NAMES: frozenset[str] = frozenset(
    {
        "SID",
        "HSID",
        "SSID",
        "APISID",
        "SAPISID",
        "NID",
        "__Secure-1PSID",
        "__Secure-3PSID",
        "__Secure-1PAPISID",
        "__Secure-3PAPISID",
    }
)


@dataclass
class GCPServiceAccountFile:
    """Parsed GCP service account JSON (``type=service_account``)."""

    data: dict


@dataclass
class GCPAuthorizedUserFile:
    """Parsed authorized_user JSON (refresh_token + client_id/secret)."""

    data: dict


@dataclass
class GCPCookiesFile:
    """Parsed Google session cookies (dict, key=value, or Playwright array)."""

    cookies: dict[str, str] = field(default_factory=dict)
    project_id: str = ""
    quota_project_id: str = ""


@dataclass
class GCPAccessTokenFile:
    """A bare OAuth2 access token (`ya29.`-prefixed), with no refresh path."""

    access_token: str
    email: str = ""
    project_id: str = ""
    quota_project_id: str = ""


@dataclass
class GCPConsoleCredsFile:
    """Parsed console credentials (username + password) for Playwright login."""

    username: str
    password: str
    project_id: str = ""
    quota_project_id: str = ""


GCPParsedCreds = Union[
    GCPServiceAccountFile,
    GCPAuthorizedUserFile,
    GCPAccessTokenFile,
    GCPCookiesFile,
    GCPConsoleCredsFile,
]


def _normalize_fields(raw: dict) -> dict:
    """Apply the alias table; first canonical match wins (skip subsequent dups)."""
    result: dict = {}
    for key, value in raw.items():
        key_lower = str(key).lower()
        canonical = key
        for canonical_name, aliases in _GCP_FIELD_ALIASES.items():
            if key_lower in aliases:
                canonical = canonical_name
                break
        if canonical not in result:
            result[canonical] = value
    return result


def _parse_block(text: str) -> Optional[dict]:
    """Try JSON dict, JSON array (Playwright cookies), or key=value lines."""
    text = text.strip()
    if not text:
        return None


    try:
        raw = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        raw = None

    if isinstance(raw, dict):
        return _normalize_fields(raw)

    if isinstance(raw, list):

        flat: dict = {}
        for item in raw:
            if isinstance(item, dict) and "name" in item:
                flat[str(item["name"])] = str(item.get("value", ""))
        return _normalize_fields(flat) if flat else None


    kv: dict = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            return None
        k, _, v = line.partition("=")
        kv[k.strip()] = v.strip().strip('"').strip("'")
    return _normalize_fields(kv) if kv else None


def _format_examples_error(path: str) -> CredentialError:
    """Build the actionable 'Expected one of these formats' error."""
    return CredentialError(
        f"Could not recognize credential file: {path}\n"
        "Expected one of these formats:\n"
        "\n"
        "  1. Service account JSON (from GCP Console / gcloud iam service-accounts):\n"
        '       {"type": "service_account", "private_key": "-----BEGIN ...", "client_email": "..."}\n'
        "\n"
        "  2. Authorized-user JSON (from `gcloud auth application-default login`):\n"
        '       {"type": "authorized_user", "refresh_token": "...", "client_id": "...", "client_secret": "..."}\n'
        "\n"
        "  3. Browser session cookies (JSON dict, Playwright cookie array, or key=value):\n"
        '       {"SID": "...", "HSID": "...", "SAPISID": "...", "__Secure-1PSID": "..."}\n'
        "       SID=...\n"
        "       HSID=...\n"
        "\n"
        "  4. Console credentials (key=value or JSON; triggers Playwright login with email prefill):\n"
        "       username=user@example.invalid\n"
        "       password=your-password\n"
    )


def parse_creds_file(path: str) -> GCPParsedCreds:
    """Parse a GCP credential file and return the most specific shape detected."""
    p = Path(path).expanduser()
    if not p.exists():
        raise CredentialError(f"Credential file not found: {path}")
    from cloudbasher.core.secret_refs import read_credential_file

    try:
        text = read_credential_file(str(p))
    except CredentialError:
        raise
    except OSError as e:
        raise CredentialError(f"Cannot read credential file {path}: {e}")
    if not text.strip():
        raise CredentialError(f"Credential file {path} is empty")

    return parse_gcp_block_of(text, source=path)


def parse_gcp_block_of(text: str, *, source: str = "<credential text>") -> GCPParsedCreds:
    """Parse the GCP block of a possibly-multi-CSP `-F` file. `#719`."""
    if not _declares_a_csp(text):
        return parse_creds_text(text, source=source)

    from cloudbasher.core.credential_file import split_blocks_by_declared_csp

    blocks = [body for body, declared in split_blocks_by_declared_csp(text) if declared == "gcp"]
    if not blocks:
        raise CredentialError(
            f"{source} declares no `csp=gcp` block. This file names its clouds, "
            f"and none of them is GCP -- so there is nothing here for the GCP "
            f"provider to load. There is no auto-detection fallback: a block "
            f"belongs to the cloud it declares (`#477`)."
        )
    if len(blocks) > 1:
        raise CredentialError(
            f"{source} declares {len(blocks)} `csp=gcp` blocks and this entry "
            f"point loads exactly ONE identity. Which of them is a decision the "
            f"caller has to make by name -- pick one and pass a file holding it, "
            f"or go through the multi-node path, which is built to carry several."
        )
    return parse_creds_text(blocks[0], source=source)


def _declares_a_csp(text: str) -> bool:
    """Does this text carry a `csp=`/`provider=` directive line anywhere?"""
    for raw in text.splitlines():
        line = raw.strip()
        if "=" not in line:
            continue
        key = line.split("=", 1)[0].strip().lower()
        if key in ("csp", "provider"):
            return True
    return False


def parse_creds_text(text: str, *, source: str = "<credential text>") -> GCPParsedCreds:
    """Same shape-detection as parse_creds_file(), but from an in-memory string."""
    fields = _parse_block(text)
    if not fields:
        raise _format_examples_error(source)


    if fields.get("type") == "service_account" or (
        isinstance(fields.get("private_key"), str)
        and fields["private_key"].lstrip().startswith("-----BEGIN")
        and fields.get("client_email")
    ):
        return GCPServiceAccountFile(data=fields)

    if fields.get("type") == "authorized_user" or (
        fields.get("refresh_token")
        and fields.get("client_id")
        and fields.get("client_secret")
        and not fields.get("private_key")
    ):
        return GCPAuthorizedUserFile(data=fields)


    if (
        fields.get("access_token")
        and not fields.get("refresh_token")
        and not fields.get("private_key")
    ):
        return GCPAccessTokenFile(
            access_token=str(fields["access_token"]),
            email=str(fields.get("client_email") or ""),
            project_id=str(fields.get("project_id") or ""),
            quota_project_id=str(fields.get("quota_project_id") or ""),
        )

    cookies = {n: fields[n] for n in _GCP_COOKIE_NAMES if fields.get(n)}
    if cookies and not (
        fields.get("client_id") or fields.get("private_key") or fields.get("refresh_token")
    ):
        return GCPCookiesFile(
            cookies=cookies,
            project_id=str(fields.get("project_id") or ""),
            quota_project_id=str(fields.get("quota_project_id") or ""),
        )

    if fields.get("username") and fields.get("password"):
        return GCPConsoleCredsFile(
            username=str(fields["username"]),
            password=str(fields["password"]),
            project_id=str(fields.get("project_id") or ""),
            quota_project_id=str(fields.get("quota_project_id") or ""),
        )


    if fields.get("refresh_token") and not fields.get("private_key"):
        raise CredentialError(
            f"{source}: this block has a refresh_token but no client_id and "
            "client_secret.\n"
            "\n"
            "Google will not exchange a refresh token without the OAuth client "
            "it was issued to, so this cannot be completed here -- both fields "
            "have to come from wherever the token did.\n"
            "\n"
            "A gcloud authorized-user JSON file already carries all three: "
            "type=authorized_user, plus client_id, client_secret and refresh_token."
        )


    raise _format_examples_error(source)


def _b64url(data: bytes) -> bytes:
    """URL-safe base64 without padding (JWT canonical form)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def exchange_oauth_refresh_token(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    rapt_token: str | None = None,
) -> str:
    """Exchange an OAuth2 refresh_token for a fresh access_token."""
    fields = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    if rapt_token:
        fields["rapt"] = rapt_token
    body = urllib.parse.urlencode(fields).encode()

    req = urllib.request.Request(
        _TOKEN_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", "replace")
        try:
            error_data = json.loads(body_text)
        except (TypeError, ValueError):
            error_data = {}
        if error_data.get("error_subtype") in {"invalid_rapt", "rapt_required"}:
            raise CredentialError(
                "Google OAuth refresh requires a current reauthentication proof "
                "(RAPT). Refresh the gcloud token cache after completing Google "
                "reauthentication, then update rapt_token in the credential file."
            ) from None
        raise CredentialError(f"OAuth token refresh failed ({e.code}): {body_text}")

    access_token = data.get("access_token", "")
    if not access_token:
        raise CredentialError(f"OAuth token refresh: no access_token in response: {data}")
    log(f"GCP access token refreshed expires_in={data.get('expires_in', '?')}s")
    return access_token


def load_credentials_from_record_extra(extra: dict[str, Any]) -> Credentials:
    """Materialize a file-backed GCP OAuth record for Cloud Shell bootstrap."""
    declaration = dict(extra or {})
    if declaration.get("username") and declaration.get("password"):


        return Credentials(
            provider="gcp",
            extra={
                "pw_username": str(declaration["username"]),
                "pw_password": str(declaration["password"]),
                "_needs_playwright": True,
                **{
                    key: declaration[key]
                    for key in ("project_id", "quota_project_id")
                    if declaration.get(key)
                },
            },
        )

    nested = declaration.get("data")
    if isinstance(nested, dict):

        declaration = {**nested, **{k: v for k, v in declaration.items() if k != "data"}}

    refresh_token = str(declaration.get("refresh_token") or "").strip()
    access_token = str(declaration.get("access_token") or "").strip()
    if refresh_token:
        client_id = str(declaration.get("client_id") or _GCLOUD_CLIENT_ID)
        client_secret = str(declaration.get("client_secret") or _GCLOUD_CLIENT_SECRET)
        rapt_token = str(declaration.get("rapt_token") or "").strip()
        if rapt_token:
            access_token = exchange_oauth_refresh_token(
                refresh_token, client_id, client_secret, rapt_token
            )
        else:
            access_token = exchange_oauth_refresh_token(
                refresh_token, client_id, client_secret
            )
        runtime_extra = {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if rapt_token:
            runtime_extra["rapt_token"] = rapt_token
        for key in ("quota_project_id", "project_id", "client_email", "username"):
            if declaration.get(key):
                runtime_extra[key] = declaration[key]
    elif access_token:
        runtime_extra = {
            key: declaration[key]
            for key in ("quota_project_id", "project_id", "client_email", "username")
            if declaration.get(key)
        }
    else:
        raise CredentialError("GCP record does not contain an OAuth access_token or refresh_token")

    return Credentials(
        provider="gcp",
        access_token=access_token,
        email=str(
            declaration.get("email")
            or declaration.get("client_email")
            or declaration.get("username")
            or ""
        )
        or None,
        extra=runtime_extra,
    )


def mint_service_account_access_token(
    private_key_pem: str, client_email: str, scope: str = _CLOUDSHELL_SCOPE
) -> str:
    """Sign a service-account JWT (RS256) and exchange it for an access_token."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError as exc:  # pragma: no cover
        raise CredentialError(
            "Service account JWT signing requires the 'cryptography' package "
            "(installed transitively via paramiko). Install: pip install cryptography"
        ) from exc

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    claims = {
        "iss": client_email,
        "scope": scope,
        "aud": _TOKEN_URL,
        "iat": now,
        "exp": now + 3600,
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + b"."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode())
    )

    try:
        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    except Exception as exc:
        raise CredentialError(f"Service account private_key is not valid PEM: {exc}")

    if not isinstance(key, rsa.RSAPrivateKey):
        raise CredentialError("Service account private_key must be RSA (got non-RSA key type)")

    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    assertion = signing_input + b"." + _b64url(signature)

    body = urllib.parse.urlencode(
        {
            "grant_type": _JWT_BEARER_GRANT,
            "assertion": assertion.decode("ascii"),
        }
    ).encode()
    req = urllib.request.Request(
        _TOKEN_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode("utf-8", "replace")
        raise CredentialError(f"Service account JWT exchange failed ({e.code}): {body_text}")

    access_token = data.get("access_token", "")
    if not access_token:
        raise CredentialError(f"Service account JWT exchange: no access_token: {data}")
    log(
        f"GCP service account token minted for {client_email} expires_in={data.get('expires_in', '?')}s"
    )
    return access_token


_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
_RESOURCE_MANAGER_V3 = "https://cloudresourcemanager.googleapis.com/v3"


def resolve_quota_project(args: Any, credentials: Any) -> Optional[str]:
    """Resolve the GCP quota project consistently for probes and provisioning."""
    extra = getattr(credentials, "extra", None) or {}
    data = extra.get("data") if isinstance(extra.get("data"), dict) else {}
    project = extra.get("quota_project_id") or data.get("quota_project_id")
    if project:
        return str(project)
    return None


def resolve_project_organization(
    access_token: str,
    project_id: str,
    *,
    quota_project: Optional[str] = None,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> tuple[str, str]:
    """Return the configured project's organization ID and display name."""
    from cloudbasher.csp.gcp._http import build_opener

    opener = build_opener(proxy_url, proxy_insecure)

    def get_json(resource: str) -> dict[str, Any]:
        url = f"{_RESOURCE_MANAGER_V3}/{resource}"
        headers = {"Accept": "application/json", "Authorization": f"Bearer {access_token}"}
        if quota_project:
            headers["x-goog-user-project"] = quota_project
        request = urllib.request.Request(url, headers=headers, method="GET")
        with opener.open(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return payload if isinstance(payload, dict) else {}

    project = get_json(f"projects/{urllib.parse.quote(project_id, safe='')}")
    parent = str(project.get("parent") or "")
    for _ in range(20):
        if parent.startswith("organizations/"):
            org_id = parent.removeprefix("organizations/")
            organization = get_json(
                f"organizations/{urllib.parse.quote(org_id, safe='')}"
            )
            return org_id, str(organization.get("displayName") or "").strip()
        if not parent.startswith("folders/"):
            return "", ""
        folder_id = parent.removeprefix("folders/")
        folder = get_json(f"folders/{urllib.parse.quote(folder_id, safe='')}")
        parent = str(folder.get("parent") or "")
    return "", ""


class GCPInvalidAccessToken(CredentialError):
    """The Cloud Shell API authoritatively rejected the access token."""


def inspect_oauth_access_token(
    access_token: str,
    *,
    project_id: Optional[str] = None,
    quota_project: Optional[str] = None,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> dict[str, Any]:
    """Validate a Google OAuth AT against Cloud Shell and collect identity metadata."""
    if not access_token:
        raise GCPInvalidAccessToken("Google access token is missing")

    from cloudbasher.core.exceptions import CloudShellAutomationError
    from cloudbasher.csp.gcp._http import build_opener
    from cloudbasher.csp.gcp.api import GCPCloudShellAPI

    api = GCPCloudShellAPI(
        access_token=access_token,
        timeout=10,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
        token_refresher=None,
        quota_project=quota_project,
    )
    opener = build_opener(proxy_url, proxy_insecure)

    def get_json(url: str, *, bearer: bool = False) -> dict[str, Any]:
        headers = {"Accept": "application/json"}
        if bearer:
            headers["Authorization"] = f"Bearer {access_token}"
        if quota_project and url.startswith(_RESOURCE_MANAGER_V3):
            headers["x-goog-user-project"] = quota_project
        request = urllib.request.Request(url, headers=headers, method="GET")
        with opener.open(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return payload if isinstance(payload, dict) else {}

    result: dict[str, Any] = {
        "subject": "",
        "email": "",
        "organization_id": "",
        "organization_name": "",
        "cloudshell_access": None,
        "cloudshell_denial": "",
    }
    try:
        userinfo = get_json(_USERINFO_URL, bearer=True)
        userinfo_subject = str(userinfo.get("sub") or "")
        if userinfo.get("email_verified") is True:
            result["email"] = str(userinfo.get("email") or "")
        result["subject"] = userinfo_subject
    except Exception:


        pass

    try:
        if project_id:
            org_id, org_name = resolve_project_organization(
                access_token,
                project_id,
                quota_project=quota_project,
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
            )
            result["organization_id"] = org_id
            result["organization_name"] = org_name


    except Exception:


        pass
    try:
        api.get_environment()
        result["cloudshell_access"] = True
    except CloudShellAutomationError as exc:
        if exc.status_code == 401 or (
            exc.status_code == 200 and "sign-in page" in str(exc).lower()
        ):
            raise GCPInvalidAccessToken(str(exc)) from None
        if exc.status_code == 404:

            result["cloudshell_access"] = True
        elif exc.status_code == 403:
            from cloudbasher.csp.gcp.diagnostics import (
                is_cloudshell_api_disabled,
                is_quota_project_service_usage_denial,
            )

            error_body = exc.response_body or str(exc)
            if is_quota_project_service_usage_denial(error_body):
                result["cloudshell_access"] = False
                result["cloudshell_denial"] = "quota_project_serviceusage"
            elif is_cloudshell_api_disabled(error_body):


                result["cloudshell_access"] = False
                result["cloudshell_denial"] = "cloudshell_api_disabled"
            else:
                raise
        else:
            raise
    return result


def warn_if_scope_insufficient(
    access_token: str,
    *,
    warn: Callable[[str], None] = out,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> bool:
    """Say so, loudly, if this token lacks `cloud-platform`. Returns True if it does."""
    if not access_token:
        return True


    from cloudbasher.csp.gcp._http import build_opener

    try:
        request = urllib.request.Request(
            f"{_TOKENINFO_URL}?access_token={urllib.parse.quote(access_token)}",
            method="GET",
        )
        opener = build_opener(proxy_url, proxy_insecure)
        with opener.open(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except Exception as exc:
        detail(f"gcp: token scope check skipped ({type(exc).__name__}: {exc})")
        return True

    scopes = str(payload.get("scope") or "").split()
    if not scopes or _CLOUDSHELL_SCOPE in scopes:
        return True
    warn(
        "GCP: this token does NOT carry the cloud-platform scope, which Cloud "
        "Shell requires -- it will fail before the environment is even started.\n"
        f"     it has: {', '.join(sorted(scopes)) or '(none reported)'}\n"
        f"     it needs: {_CLOUDSHELL_SCOPE}\n"
        "     Re-mint it with that scope (for gcloud: "
        "--scopes=https://www.googleapis.com/auth/cloud-platform)."
    )
    return False


def build_refresher(credentials: Credentials) -> Optional[Callable[[], str]]:
    """Return a zero-arg callable that produces a fresh access_token, or None."""
    extra = credentials.extra or {}


    refresh_token = extra.get("refresh_token") or ""
    if refresh_token:
        client_id = extra.get("client_id") or _GCLOUD_CLIENT_ID
        client_secret = extra.get("client_secret") or _GCLOUD_CLIENT_SECRET

        def _refresh_oauth() -> str:
            rapt_token = str(extra.get("rapt_token") or "").strip()
            if rapt_token:
                return exchange_oauth_refresh_token(
                    refresh_token, client_id, client_secret, rapt_token
                )
            return exchange_oauth_refresh_token(refresh_token, client_id, client_secret)

        return _refresh_oauth


    private_key = extra.get("private_key") or ""
    client_email = extra.get("service_account_email") or ""
    if private_key and client_email:

        def _refresh_sa() -> str:
            return mint_service_account_access_token(private_key, client_email)

        return _refresh_sa

    return None


def preflight_env_error() -> Optional[str]:
    """Why `--creds-env` cannot work for GCP right now, or None if it might."""
    path = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
    if not path:
        return (
            "--creds-env: GOOGLE_APPLICATION_CREDENTIALS is not set in this "
            "environment.\n"
            "\n"
            "--creds-env is a valid source -- for GCP it expects that variable "
            "to name a service-account or authorized-user JSON file:\n"
            "  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json\n"
            "\n"
            "Or pass the file directly instead: -F/--creds-file PATH.\n"
            "There is no ambient fallback -- application-default credentials "
            "and the gcloud CLI are not consulted."
        )
    if not Path(path).expanduser().exists():
        return (
            f"--creds-env: GOOGLE_APPLICATION_CREDENTIALS points at {path}, "
            "which does not exist."
        )
    return None


_NON_SERIALIZABLE_EXTRA: frozenset = frozenset()


def persist_extra(extra: dict, *, access_token: str) -> dict:
    """The GCP credential as ``state.bin``'s ``credentials`` slot. `#594`."""
    out = {k: v for k, v in (extra or {}).items() if k not in _NON_SERIALIZABLE_EXTRA}
    out["access_token"] = access_token or ""
    return out


class GCPCredentialProvider(CredentialProvider):
    """GCP credential loader."""

    def __init__(
        self,
        *,
        credential_file: Optional[str] = None,
        device_code: bool = False,
        project_id: Optional[str] = None,
        saved_state: Optional[dict] = None,
        source: str = "file",
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
    ) -> None:
        self.credential_file = credential_file
        self.device_code = device_code
        self.project_id = project_id
        self._saved_state: dict = saved_state or {}
        self.source = source


        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure
        self._cached_creds: Optional[Credentials] = None

    def load(self) -> Credentials:
        """Load GCP credentials from exactly one explicitly-named source (see class docstring)."""
        if self._cached_creds:
            return self._cached_creds

        if self.source == "resume":
            creds = self._load_from_state()
            if creds:
                self._cached_creds = creds
                return creds
            raise CredentialError(
                "--resume: no saved GCP credentials in the state file. Start "
                "with --creds-file or --creds-env."
            )

        if self.source == "file":
            if not self.credential_file:
                raise CredentialError("--creds-file requires a path")
            creds = self._load_from_service_account_file(self.credential_file)
            if creds:
                detail(f"credential_source=file path={self.credential_file}")
                self._cached_creds = creds
                return creds
        elif self.source == "env":


            creds = self._load_from_env()
            if creds:
                detail("credential_source=GOOGLE_APPLICATION_CREDENTIALS")
                self._cached_creds = creds
                return creds


            _gac = os.getenv("GOOGLE_APPLICATION_CREDENTIALS", "")
            raise CredentialError(
                preflight_env_error()
                or f"--creds-env: GOOGLE_APPLICATION_CREDENTIALS is set to "
                f"{_gac}, which could not be read as a GCP credential file. "
                "Expected a service-account or authorized-user JSON file.\n"
                "There is no ambient fallback -- application-default "
                "credentials and the gcloud CLI are not consulted."
            )
        else:
            raise CredentialError(f"unknown credential source {self.source!r}")


        raise CredentialError(
            f"could not load GCP credentials from {self.source}"
            f"{' (' + self.credential_file + ')' if self.credential_file else ''}"
        )

    def refresh(self) -> Credentials:
        """Refresh credentials (for temporary tokens)."""
        self._cached_creds = None
        return self.load()

    def _load_from_state(self) -> Optional[Credentials]:
        """Load and refresh credentials from saved state.json (--resume path)."""
        if not self._saved_state:
            return None
        cred_data = self._saved_state.get("credentials", {})
        if not isinstance(cred_data, dict):
            return None
        refresh_token = cred_data.get("refresh_token", "")
        if not refresh_token:
            return None
        client_id = cred_data.get("client_id") or _GCLOUD_CLIENT_ID
        client_secret = cred_data.get("client_secret") or _GCLOUD_CLIENT_SECRET
        try:
            access_token = self._refresh_token(
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                rapt_token=cred_data.get("rapt_token") or None,
            )
        except CredentialError:
            return None
        detail("credential_source=saved_state")
        extra: dict[str, Any] = {
            "refresh_token": refresh_token,
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if cred_data.get("rapt_token"):
            extra["rapt_token"] = cred_data["rapt_token"]
        quota_project_id = cred_data.get("quota_project_id", "")
        if quota_project_id:
            extra["quota_project_id"] = quota_project_id
        project_id = cred_data.get("project_id", "")
        if project_id:
            extra["project_id"] = project_id
        return Credentials(
            provider="gcp",
            access_token=access_token,
            session_id=None,
            extra=extra,
        )

    def _load_from_service_account_file(self, path: str) -> Optional[Credentials]:
        """Load credentials from a GCP credential file."""
        try:
            p = Path(path).expanduser()
            if not p.exists():


                raise CredentialError(f"Credentials file not found: {path}")

            parsed = parse_creds_file(path)

            if isinstance(parsed, GCPServiceAccountFile):
                data = parsed.data
                private_key = data.get("private_key")
                client_email = data.get("client_email")
                if not (private_key and client_email):
                    raise CredentialError(
                        f"Service account file {path} is missing private_key or client_email"
                    )
                access_token = mint_service_account_access_token(
                    private_key_pem=private_key,
                    client_email=client_email,
                )
                detail(f"credential_source=service_account email={client_email}")
                extra = {
                    "project_id": data.get("project_id"),
                    "service_account_email": client_email,
                    "private_key": private_key,
                }
                if data.get("quota_project_id"):
                    extra["quota_project_id"] = data["quota_project_id"]
                return Credentials(
                    provider="gcp",
                    access_token=access_token,
                    session_id=None,
                    extra=extra,
                )

            if isinstance(parsed, GCPAuthorizedUserFile):
                data = parsed.data
                access_token = self._refresh_token(
                    refresh_token=data["refresh_token"],
                    client_id=data.get("client_id", _GCLOUD_CLIENT_ID),
                    client_secret=data.get("client_secret", _GCLOUD_CLIENT_SECRET),
                    rapt_token=data.get("rapt_token") or None,
                )


                warn_if_scope_insufficient(
                    access_token,
                    proxy_url=self.proxy_url,
                    proxy_insecure=self.proxy_insecure,
                )
                return Credentials(
                    provider="gcp",
                    access_token=access_token,
                    session_id=None,
                    email=str(data.get("client_email") or data.get("username") or "") or None,
                    extra={
                        "refresh_token": data.get("refresh_token"),
                        "client_id": data.get("client_id"),
                        "client_secret": data.get("client_secret"),
                        "rapt_token": data.get("rapt_token"),
                        **{
                            key: data[key]
                            for key in ("project_id", "quota_project_id")
                            if data.get(key)
                        },
                    },
                )

            if isinstance(parsed, GCPAccessTokenFile):


                out(
                    "GCP: this is a bare access token -- short-lived (~1h), and "
                    "it cannot be refreshed because there is nothing to refresh "
                    "it with. The session will need fresh credentials when it "
                    "expires."
                )
                detail("credential_source=access_token")
                warn_if_scope_insufficient(
                    parsed.access_token,
                    proxy_url=self.proxy_url,
                    proxy_insecure=self.proxy_insecure,
                )
                return Credentials(
                    provider="gcp",
                    access_token=parsed.access_token,
                    session_id=None,
                    email=parsed.email or None,
                    extra={
                        **({"client_email": parsed.email} if parsed.email else {}),
                        **{
                            key: value
                            for key, value in (
                                ("project_id", parsed.project_id),
                                ("quota_project_id", parsed.quota_project_id),
                            )
                            if value
                        },
                    },
                )

            if isinstance(parsed, GCPCookiesFile):
                detail(f"credential_source=cookies count={len(parsed.cookies)}")
                return Credentials(
                    provider="gcp",
                    access_token="",
                    session_id=None,
                    extra={
                        "cookies": parsed.cookies,
                        **{
                            key: value
                            for key, value in (
                                ("project_id", parsed.project_id),
                                ("quota_project_id", parsed.quota_project_id),
                            )
                            if value
                        },
                    },
                )

            if isinstance(parsed, GCPConsoleCredsFile):
                detail(f"credential_source=console_creds username={parsed.username}")
                return Credentials(
                    provider="gcp",
                    access_token="",
                    session_id=None,
                    extra={
                        "pw_username": parsed.username,
                        "pw_password": parsed.password,
                        "_needs_playwright": True,
                        **{
                            key: value
                            for key, value in (
                                ("project_id", parsed.project_id),
                                ("quota_project_id", parsed.quota_project_id),
                            )
                            if value
                        },
                    },
                )

            return None

        except CredentialError:
            raise
        except Exception as e:
            raise CredentialError(f"Failed to load GCP credentials from {path}: {e}")

    def _load_from_env(self) -> Optional[Credentials]:
        """Load credentials from GOOGLE_APPLICATION_CREDENTIALS env var."""
        cred_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
        if not cred_file:
            return None
        return self._load_from_service_account_file(cred_file)

    def _refresh_token(
        self,
        *,
        refresh_token: str,
        client_id: str,
        client_secret: str,
        rapt_token: str | None = None,
    ) -> str:
        """Exchange a refresh token for a new access token (method form)."""
        return exchange_oauth_refresh_token(
            refresh_token, client_id, client_secret, rapt_token
        )

    def reauth_via_browser_or_device_code(self, *, skip_browser: bool) -> Optional[Credentials]:
        """Public re-authentication entry point for callers outside this class (e.g. cli/main.py's GCP quota-project re-auth path) that need tiers 6-7 of the credential chain without reaching into the private _load_from_browser_oauth/_load_from_device_code methods directly."""
        creds = None if skip_browser else self._load_from_browser_oauth()
        return creds or self._load_from_device_code()

    def _load_from_browser_oauth(self) -> Optional[Credentials]:
        """Authenticate via 3-legged OAuth in browser (authorization code grant)."""

        port = None
        for try_port in _REDIRECT_PORTS:
            with socket.socket() as s:
                try:
                    s.bind(("127.0.0.1", try_port))
                    port = try_port
                    break
                except OSError:
                    continue
        if port is None:
            log("[gcp] Browser OAuth: cannot find free local port")
            return None


        csrf_state = secrets.token_urlsafe(16)


        result_holder: dict[str, str] = {}
        redirect_event = threading.Event()

        class _RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed_url = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed_url.query)

                code_list = params.get("code", [])
                state_list = params.get("state", [])


                if state_list and state_list[0] != csrf_state:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"State mismatch. Close this tab.")
                    log("[gcp] OAuth callback: state mismatch — possible CSRF")
                    redirect_event.set()
                    return

                if code_list:
                    result_holder["code"] = code_list[0]
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(
                        b"<html><body style='font-family:sans-serif'>"
                        b"<h2>Authentication successful!</h2>"
                        b"<p>You may close this tab and return to the terminal.</p>"
                        b"</body></html>"
                    )
                else:
                    error = params.get("error", ["unknown"])[0]
                    result_holder["error"] = error
                    self.send_response(400)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(
                        f"<html><body style='font-family:sans-serif'>"
                        f"<p>Error: {error}. Close this tab.</p>"
                        f"</body></html>".encode()
                    )
                redirect_event.set()

            def log_message(self, fmt: str, *args: Any) -> None:
                pass


        try:
            server = http.server.HTTPServer(("127.0.0.1", port), _RedirectHandler)
        except OSError as e:
            log(f"[gcp] Browser OAuth: cannot start listener on port {port}: {e}")
            return None

        server_thread = threading.Thread(target=server.handle_request, daemon=True)
        server_thread.start()


        redirect_uri = f"http://127.0.0.1:{port}/callback"
        auth_params = urllib.parse.urlencode(
            {
                "client_id": _GCLOUD_CLIENT_ID,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": _CLOUDSHELL_SCOPE,
                "access_type": "offline",
                "prompt": "consent",
                "state": csrf_state,
            }
        )
        auth_url = f"{_AUTH_URL}?{auth_params}"


        try:
            opened = webbrowser.open(auth_url)
        except Exception:
            opened = False

        if not opened:
            server.server_close()
            log("[gcp] Browser OAuth: no browser available, falling through to device code")
            return None

        out("[gcp] Browser opened for OAuth. Waiting for redirect...")


        got_redirect = redirect_event.wait(timeout=_BROWSER_OAUTH_TIMEOUT)
        server.server_close()

        if not got_redirect:
            log("[gcp] Browser OAuth: timed out waiting for redirect")
            return None

        if "error" in result_holder:
            log(f"[gcp] Browser OAuth: error received: {result_holder['error']}")
            return None

        code = result_holder.get("code", "")
        if not code:
            return None


        token_body = urllib.parse.urlencode(
            {
                "code": code,
                "client_id": _GCLOUD_CLIENT_ID,
                "client_secret": _GCLOUD_CLIENT_SECRET,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            }
        ).encode()

        req = urllib.request.Request(
            _TOKEN_URL,
            data=token_body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                token_data = json.loads(resp.read())
        except Exception as e:
            log(f"[gcp] Browser OAuth: token exchange failed: {e}")
            return None

        access_token = token_data.get("access_token", "")
        refresh_token = token_data.get("refresh_token", "")
        if not access_token:
            log("[gcp] Browser OAuth: no access token in response")
            return None

        log("GCP browser OAuth: access token obtained")
        detail("credential_source=browser_oauth")
        return Credentials(
            provider="gcp",
            access_token=access_token,
            session_id=None,
            extra={
                "refresh_token": refresh_token,
                "client_id": _GCLOUD_CLIENT_ID,
                "client_secret": _GCLOUD_CLIENT_SECRET,
            },
        )

    def _load_from_device_code(self) -> Optional[Credentials]:
        """Authenticate via OAuth2 device code flow (RFC 8628)."""

        body = urllib.parse.urlencode(
            {
                "client_id": _GCLOUD_CLIENT_ID,
                "scope": _CLOUDSHELL_SCOPE,
            }
        ).encode()

        req = urllib.request.Request(
            _DEVICE_AUTH_URL,
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                auth_data = json.loads(resp.read())
        except Exception as e:
            raise CredentialError(f"Device code request failed: {e}")

        device_code = auth_data.get("device_code", "")
        user_code = auth_data.get("user_code", "")
        verification_url = auth_data.get("verification_url", "https://google.com/device")
        interval = int(auth_data.get("interval", 5))
        expires_in = int(auth_data.get("expires_in", 1800))

        out(f"\nGCP device authorization required.")
        out(f"  1. Open: {verification_url}")
        out(f"  2. Enter code: {user_code}")
        out(f"  (expires in {expires_in}s)\n")


        deadline = time.time() + expires_in
        while time.time() < deadline:
            time.sleep(interval)
            poll_body = urllib.parse.urlencode(
                {
                    "client_id": _GCLOUD_CLIENT_ID,
                    "client_secret": _GCLOUD_CLIENT_SECRET,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                }
            ).encode()

            poll_req = urllib.request.Request(
                _TOKEN_URL,
                data=poll_body,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            try:
                with urllib.request.urlopen(poll_req, timeout=15) as resp:
                    token_data = json.loads(resp.read())
                    access_token = token_data.get("access_token", "")
                    if access_token:
                        log("GCP device code flow: access token obtained")
                        return Credentials(
                            provider="gcp",
                            access_token=access_token,
                            session_id=None,
                            extra={
                                "refresh_token": token_data.get("refresh_token", ""),
                                "client_id": _GCLOUD_CLIENT_ID,
                                "client_secret": _GCLOUD_CLIENT_SECRET,
                            },
                        )
            except urllib.error.HTTPError as e:
                err_body = json.loads(e.read().decode("utf-8", "replace"))
                error = err_body.get("error", "")
                if error == "authorization_pending":
                    continue
                if error == "slow_down":
                    interval += 5
                    continue
                raise CredentialError(f"Device code poll failed: {err_body}")

        raise CredentialError("Device code authorization timed out")
