"""AWS IAM Identity Center device-code login (credential type 5)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

from cloudbasher.core.exceptions import CredentialError
from cloudbasher.core.utils.output import detail, log, obfuscate_secret, out
from cloudbasher.csp.aws.signing import _build_url_opener


_CLIENT_TYPE = "public"


_DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


_PENDING = "AuthorizationPendingException"


_SLOW_DOWN = "SlowDownException"


_DEFAULT_INTERVAL_SECONDS = 5.0


_SLOW_DOWN_INCREMENT_SECONDS = 5.0


_MAX_DEVICE_CODE_SECONDS = 1800.0


def _masked(token: str) -> str:
    """A bearer token rendered for a log line. Never the value."""
    if not token:
        return "<none>"
    return obfuscate_secret(token)


@dataclass(frozen=True)
class DeviceLogin:
    """What 5.2 hands back -- everything the user and the poll both need."""

    client_id: str
    client_secret: str
    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    interval: float
    expires_in: float


def _endpoint(region: str, host_prefix: str, path: str) -> str:
    return f"https://{host_prefix}.{region}.amazonaws.com{path}"


def _call(
    url: str,
    *,
    method: str,
    body: Optional[dict[str, Any]] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: int,
    proxy_url: Optional[str],
    proxy_insecure: bool,
) -> tuple[dict[str, Any], int, Optional[str]]:
    """One request. Returns (payload, status, error_code)."""
    data = None
    request_headers = dict(headers or {})
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request_headers["content-type"] = "application/json"

    req = urllib.request.Request(url=url, data=data, headers=request_headers, method=method)
    opener = _build_url_opener(proxy_url, proxy_insecure=proxy_insecure)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            status = int(resp.status)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace") if exc.fp is not None else ""
        status = int(exc.code)
    except Exception as exc:


        raise CredentialError(f"SSO: could not reach {url} -- {type(exc).__name__}: {exc}") from exc

    payload: dict[str, Any] = {}
    if raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                payload = parsed
        except json.JSONDecodeError:


            payload = {"RawBody": raw[:400]}

    error_code = payload.get("error") or payload.get("__type") or None
    if isinstance(error_code, str) and "#" in error_code:

        error_code = error_code.rsplit("#", 1)[-1]
    return payload, status, (str(error_code) if error_code else None)


def _fail(step: str, url: str, payload: dict[str, Any], status: int, code: Optional[str]) -> str:
    """One failure message shape, carrying what was actually observed."""
    description = payload.get("error_description") or payload.get("message") or ""
    body = payload.get("RawBody")
    return (
        f"SSO {step} failed: HTTP {status}"
        + (f" {code}" if code else "")
        + (f" -- {description}" if description else "")
        + (f" (body: {body!r})" if body else "")
        + f" [{url}]"
    )


def register_client(
    region: str,
    *,
    client_name: str = "cloudbasher",
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> tuple[str, str]:
    """5.1 -- `sso-oidc:RegisterClient`. Returns (clientId, clientSecret)."""
    url = _endpoint(region, "oidc", "/client/register")
    payload, status, code = _call(
        url,
        method="POST",
        body={"clientName": client_name, "clientType": _CLIENT_TYPE},
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    client_id = str(payload.get("clientId") or "")
    client_secret = str(payload.get("clientSecret") or "")
    if status >= 400 or not client_id or not client_secret:
        raise CredentialError(_fail("RegisterClient", url, payload, status, code))
    detail(f"[sso] registered client region={region} client_id={_masked(client_id)}")
    return client_id, client_secret


def start_device_authorization(
    region: str,
    start_url: str,
    client_id: str,
    client_secret: str,
    *,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> DeviceLogin:
    """5.2 -- `sso-oidc:StartDeviceAuthorization`."""
    url = _endpoint(region, "oidc", "/device_authorization")
    payload, status, code = _call(
        url,
        method="POST",
        body={"clientId": client_id, "clientSecret": client_secret, "startUrl": start_url},
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    device_code = str(payload.get("deviceCode") or "")
    user_code = str(payload.get("userCode") or "")
    if status >= 400 or not device_code:
        raise CredentialError(_fail("StartDeviceAuthorization", url, payload, status, code))

    verification_uri = str(payload.get("verificationUri") or "")
    complete = str(payload.get("verificationUriComplete") or "")
    if not complete and verification_uri and user_code:


        complete = f"{verification_uri}?user_code={urllib.parse.quote(user_code)}"

    interval = float(payload.get("interval") or _DEFAULT_INTERVAL_SECONDS)
    expires_in = min(float(payload.get("expiresIn") or 600.0), _MAX_DEVICE_CODE_SECONDS)
    return DeviceLogin(
        client_id=client_id,
        client_secret=client_secret,
        device_code=device_code,
        user_code=user_code,
        verification_uri=verification_uri,
        verification_uri_complete=complete,
        interval=max(interval, 1.0),
        expires_in=expires_in,
    )


def poll_for_access_token(
    region: str,
    login: DeviceLogin,
    *,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
    on_wait: Optional[Callable[[float], None]] = None,
) -> str:
    """5.4 -- poll `sso-oidc:CreateToken` until the user approves. Returns the access token."""
    url = _endpoint(region, "oidc", "/token")
    deadline = now() + login.expires_in
    interval = login.interval
    body = {
        "clientId": login.client_id,
        "clientSecret": login.client_secret,
        "deviceCode": login.device_code,
        "grantType": _DEVICE_GRANT,
    }
    polls = 0
    while True:
        remaining = deadline - now()
        if remaining <= 0:
            raise CredentialError(
                f"SSO: the device code expired after {login.expires_in:.0f}s "
                f"without being approved ({polls} polls). Re-run to get a fresh "
                "code, and approve it at the URL shown."
            )
        payload, status, code = _call(
            url,
            method="POST",
            body=body,
            timeout=timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        )
        polls += 1
        if status < 400:
            token = str(payload.get("accessToken") or "")
            if not token:
                raise CredentialError(_fail("CreateToken", url, payload, status, code))
            detail(f"[sso] access token acquired after {polls} polls token={_masked(token)}")
            return token
        if code == _SLOW_DOWN:

            interval += _SLOW_DOWN_INCREMENT_SECONDS
            log(f"[sso] server asked to slow down; polling every {interval:.0f}s")
        elif code != _PENDING:
            raise CredentialError(_fail("CreateToken", url, payload, status, code))
        if on_wait is not None:
            on_wait(max(0.0, remaining))
        sleep(min(interval, max(0.0, deadline - now())))


def _portal_get(
    region: str,
    path: str,
    access_token: str,
    *,
    query: Optional[dict[str, str]] = None,
    timeout: int,
    proxy_url: Optional[str],
    proxy_insecure: bool,
) -> tuple[dict[str, Any], int, Optional[str], str]:
    """As `_call`, plus the URL it actually used."""
    url = _endpoint(region, "portal.sso", path)
    if query:
        url = f"{url}?{urllib.parse.urlencode(query)}"
    payload, status, code = _call(
        url,
        method="GET",
        headers={"x-amz-sso_bearer_token": access_token},
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    return payload, status, code, url


def _portal_list(
    region: str,
    access_token: str,
    *,
    step: str,
    path: str,
    key: str,
    query: Optional[dict[str, str]] = None,
    timeout: int,
    proxy_url: Optional[str],
    proxy_insecure: bool,
) -> list[Any]:
    """One list-shaped portal call (5.5). Both users differ only in path and key."""
    payload, status, code, url = _portal_get(
        region,
        path,
        access_token,
        query=query,
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    if status >= 400:
        raise CredentialError(_fail(step, url, payload, status, code))
    items = payload.get(key)
    return list(items) if isinstance(items, list) else []


def list_accounts(
    region: str,
    access_token: str,
    *,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> list[dict[str, Any]]:
    """5.5 -- `sso:ListAccounts`."""
    return _portal_list(
        region,
        access_token,
        step="ListAccounts",
        path="/assignment/accounts",
        key="accountList",
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )


def list_account_roles(
    region: str,
    access_token: str,
    account_id: str,
    *,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> list[str]:
    """5.5 -- `sso:ListAccountRoles`."""
    roles = _portal_list(
        region,
        access_token,
        step="ListAccountRoles",
        path="/assignment/roles",
        key="roleList",
        query={"account_id": account_id},
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    return [str(r.get("roleName") or "") for r in roles if isinstance(r, dict)]


def get_role_credentials(
    region: str,
    access_token: str,
    account_id: str,
    role_name: str,
    *,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> dict[str, Any]:
    """5.6 -- `sso:GetRoleCredentials`. **The join point.**"""
    payload, status, code, url = _portal_get(
        region,
        "/federation/credentials",
        access_token,
        query={"account_id": account_id, "role_name": role_name},
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    role_creds = payload.get("roleCredentials")
    if status >= 400 or not isinstance(role_creds, dict):


        hint = ""
        try:
            available = list_account_roles(
                region,
                access_token,
                account_id,
                timeout=timeout,
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
            )
            if available:
                hint = (
                    f" This token can assume these roles in {account_id}: "
                    f"{', '.join(sorted(available))}."
                )
            else:
                accounts = [
                    str(a.get("accountId") or "")
                    for a in list_accounts(
                        region,
                        access_token,
                        timeout=timeout,
                        proxy_url=proxy_url,
                        proxy_insecure=proxy_insecure,
                    )
                ]
                if accounts:
                    hint = (
                        f" This token has no roles in {account_id}; it can reach "
                        f"accounts: {', '.join(sorted(set(accounts)))}."
                    )
        except CredentialError:


            pass
        raise CredentialError(_fail("GetRoleCredentials", url, payload, status, code) + hint)

    access_key = str(role_creds.get("accessKeyId") or "")
    secret_key = str(role_creds.get("secretAccessKey") or "")
    session_token = str(role_creds.get("sessionToken") or "")
    if not (access_key and secret_key and session_token):
        raise CredentialError(
            "SSO GetRoleCredentials returned an incomplete credential set "
            f"(accessKeyId={'yes' if access_key else 'no'}, "
            f"secretAccessKey={'yes' if secret_key else 'no'}, "
            f"sessionToken={'yes' if session_token else 'no'}) -- "
            f"nothing can be signed with it. [{url}]"
        )
    return {
        "access_key": access_key,
        "secret_key": secret_key,
        "session_token": session_token,


        "expiration": _expiration_iso(role_creds.get("expiration")),
    }


def _expiration_iso(value: Any) -> str:
    try:
        seconds = float(value) / 1000.0
    except (TypeError, ValueError):
        return ""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def resolve_device_credentials(
    *,
    region: str,
    start_url: str,
    account_id: str,
    role_name: str,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    announce: Callable[[str], None] = out,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Steps 5.1-5.6 end to end. Returns the type 1/2 `extra` shape."""
    if not region:
        raise CredentialError(
            "SSO device login needs SSO_REGION -- the region of the Identity "
            "Center INSTANCE, which is not necessarily the region the shell "
            "runs in. It cannot be derived: an Identity Center start URL "
            "carries no region. Add `SSO_REGION=<region>` to the block."
        )
    if not account_id or not role_name:
        raise CredentialError(
            "SSO device login needs ACCOUNT_ID and ROLE_NAME -- they are the "
            "arguments to sso:GetRoleCredentials (step 5.6), so without them "
            "the flow has nothing to ask for. "
            f"(account_id={account_id or '<missing>'}, "
            f"role_name={role_name or '<missing>'})"
        )

    client_id, client_secret = register_client(
        region, timeout=timeout, proxy_url=proxy_url, proxy_insecure=proxy_insecure
    )
    login = start_device_authorization(
        region,
        start_url,
        client_id,
        client_secret,
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )

    announce("")
    announce("  AWS Identity Center sign-in required")
    announce(f"    open:      {login.verification_uri_complete or login.verification_uri}")
    if login.user_code:
        announce(f"    user code: {login.user_code}")


    announce(f"    grants:    {role_name} in account {account_id} ({region})")
    announce(f"    expires:   {login.expires_in:.0f}s from now")
    announce("")

    last_notice = [0.0]

    def _on_wait(remaining: float) -> None:


        if now() - last_notice[0] >= 60.0:
            last_notice[0] = now()
            announce(f"  waiting for approval... {remaining:.0f}s left")

    access_token = poll_for_access_token(
        region,
        login,
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
        sleep=sleep,
        now=now,
        on_wait=_on_wait,
    )
    extra = get_role_credentials(
        region,
        access_token,
        account_id,
        role_name,
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    announce(
        f"  signed in: {role_name} in {account_id} " f"(expires {extra['expiration'] or 'unknown'})"
    )
    return extra
