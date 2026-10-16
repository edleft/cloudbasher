"""AWS CloudShell PKCE/federation credential bootstrap."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import http.cookiejar
import json
import os
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.utils.output import detail, eprint, log
from cloudbasher.core.utils.timeline import record_call
from cloudbasher.csp.aws.signing import api_log
from cloudbasher.csp.aws.credentials import AwsSessionCreds, CloudShellBrowserAuthContext


_CACHE_MAGIC = b"CSR\x02"
_CACHE_SALT_LEN = 32
_CACHE_NONCE_LEN = 12
_CACHE_SCRYPT_N = 131072
_CACHE_SCRYPT_R = 8
_CACHE_SCRYPT_P = 1

_BROWSER_AUTH_PASSPHRASE: Optional[str] = None


_CACHE_WRITE_LOCK = threading.Lock()


def set_browser_auth_passphrase(passphrase: Optional[str]) -> None:
    """Set the passphrase for encrypting/decrypting the browser-auth cache."""
    global _BROWSER_AUTH_PASSPHRASE
    _BROWSER_AUTH_PASSPHRASE = passphrase


def _cache_derive_key(passphrase: str, salt: bytes) -> bytes:
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


def _cache_encrypt(plaintext: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(_CACHE_SALT_LEN)
    nonce = os.urandom(_CACHE_NONCE_LEN)
    key = _cache_derive_key(passphrase, salt)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return _CACHE_MAGIC + salt + nonce + ct_tag


def _cache_decrypt(data: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag

    hdr = len(_CACHE_MAGIC) + _CACHE_SALT_LEN + _CACHE_NONCE_LEN
    if len(data) < hdr + 16:
        raise ValueError("Browser auth cache too short or corrupt")
    if data[: len(_CACHE_MAGIC)] != _CACHE_MAGIC:
        raise ValueError("Unrecognized browser auth cache format")
    off = len(_CACHE_MAGIC)
    salt = data[off : off + _CACHE_SALT_LEN]
    off += _CACHE_SALT_LEN
    nonce = data[off : off + _CACHE_NONCE_LEN]
    off += _CACHE_NONCE_LEN
    ct_tag = data[off:]
    key = _cache_derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct_tag, None)
    except InvalidTag:
        raise ValueError("Wrong passphrase or corrupt browser auth cache")


def _browser_auth_cache_path() -> Path:
    ext = ".bin" if _BROWSER_AUTH_PASSPHRASE else ".json"
    return Path(__file__).parent / f"cloudshell_browser_auth{ext}"


def _browser_auth_legacy_json_path() -> Path:
    return Path(__file__).parent / "cloudshell_browser_auth.json"


def _write_secure_json_file(path: Path, payload: dict[str, Any]) -> None:
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)
    os.chmod(path, 0o600)


def _parse_browser_auth_json(raw: dict[str, Any]) -> dict[str, CloudShellBrowserAuthContext]:
    if not isinstance(raw, dict):
        raise CloudShellAutomationError("Browser auth cache root must be a JSON object")
    entries = raw.get("regions", raw)
    if not isinstance(entries, dict):
        raise CloudShellAutomationError("Browser auth cache 'regions' value must be a JSON object")
    cache: dict[str, CloudShellBrowserAuthContext] = {}
    for region, item in entries.items():
        if not isinstance(item, dict):
            continue
        payload = dict(item)
        payload.setdefault("region", str(region))
        ctx = CloudShellBrowserAuthContext.from_payload(payload)
        if ctx.region:
            cache[ctx.region] = ctx
    return cache


def load_browser_auth_cache() -> dict[str, CloudShellBrowserAuthContext]:
    """Load all cached browser auth contexts from disk."""
    path = _browser_auth_cache_path()
    passphrase = _BROWSER_AUTH_PASSPHRASE

    legacy_path = _browser_auth_legacy_json_path()
    if not path.exists() and legacy_path.exists() and legacy_path != path:
        try:
            legacy_path.rename(path if not passphrase else legacy_path)
            path = _browser_auth_cache_path()
        except OSError:
            pass

    if not path.exists():
        fallback = _browser_auth_legacy_json_path()
        if passphrase and fallback.exists():
            path = fallback
            passphrase = None
        else:
            return {}

    try:
        if passphrase and path.suffix == ".bin":
            raw_bytes = path.read_bytes()
            plaintext = _cache_decrypt(raw_bytes, passphrase)
            raw = json.loads(plaintext.decode("utf-8"))
        else:
            raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:


        eprint(f"Browser auth cache at {path} is unreadable ({exc}); ignoring it.")
        try:
            quarantine = path.with_suffix(path.suffix + ".unreadable")
            path.replace(quarantine)
            eprint(f"  moved aside to {quarantine.name} — a fresh cache will be written.")
        except OSError as move_exc:
            eprint(f"  could not move it aside ({move_exc}); it will be overwritten.")
        return {}
    return _parse_browser_auth_json(raw)


def save_browser_auth_cache(cache: dict[str, CloudShellBrowserAuthContext]) -> None:
    """Persist all browser auth contexts to disk, encrypting if passphrase is set."""
    passphrase = _BROWSER_AUTH_PASSPHRASE
    path = _browser_auth_cache_path()
    payload = {
        "version": 1,
        "updated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "regions": {
            region: ctx.export_state(include_secrets=True) for region, ctx in sorted(cache.items())
        },
    }
    if passphrase:
        plaintext = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        encrypted = _cache_encrypt(plaintext, passphrase)


        temp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            temp.write_bytes(encrypted)
            os.chmod(temp, 0o600)
            os.replace(temp, path)
        finally:


            try:
                temp.unlink()
            except OSError:
                pass
        os.chmod(path, 0o600)
        legacy = _browser_auth_legacy_json_path()
        if legacy.exists() and legacy != path:
            try:
                legacy.unlink()
            except OSError:
                pass
    else:
        _write_secure_json_file(path, payload)


def load_browser_auth_context(region: str) -> Optional[CloudShellBrowserAuthContext]:
    """Load cached browser auth context for a region."""
    return load_browser_auth_cache().get(region)


def save_browser_auth_context(
    context: CloudShellBrowserAuthContext,
) -> CloudShellBrowserAuthContext:
    """Merge and persist a browser auth context for its region."""
    with _CACHE_WRITE_LOCK:
        return _save_browser_auth_context_locked(context)


def _save_browser_auth_context_locked(
    context: CloudShellBrowserAuthContext,
) -> CloudShellBrowserAuthContext:
    cache = load_browser_auth_cache()
    existing = cache.get(context.region)
    merged = existing.merge(context) if existing is not None else context
    if not merged.captured_at:
        merged.captured_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cache[merged.region] = merged
    save_browser_auth_cache(cache)
    return merged


def clear_browser_auth_context(region: str) -> None:
    """Remove cached browser auth context for a region."""
    cache = load_browser_auth_cache()
    if cache.pop(region, None) is not None:
        save_browser_auth_cache(cache)


def _build_ssl_ctx(proxy_url: Optional[str], proxy_insecure: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if proxy_insecure and proxy_url:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _proxy_handler(proxy_url: Optional[str]) -> list[urllib.request.BaseHandler]:
    if not proxy_url:
        return []
    return [urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})]


def call_federation_get_signin_token(
    creds: Any,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> str:
    """Exchange AWS session credentials for a Federation SigninToken."""
    url = _build_get_signin_token_url(creds)
    api_log(creds, "API request: GET signin.aws.amazon.com/federation Action=getSigninToken")

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_build_ssl_ctx(proxy_url, proxy_insecure)),
        *_proxy_handler(proxy_url),
    )

    req = urllib.request.Request(url)
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            api_log(
                creds,
                f"API response: GET signin.aws.amazon.com/federation status={resp.status}",
            )
    except urllib.error.HTTPError as exc:


        body = exc.read().decode("utf-8", "replace")
        raise CloudShellAutomationError(
            f"signin federation getSigninToken failed HTTP {exc.code}: {body[:300]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CloudShellAutomationError(
            f"signin federation getSigninToken network error: {exc.reason}"
        ) from exc

    signin_token = json.loads(body).get("SigninToken", "")
    if not signin_token:
        raise CloudShellAutomationError(
            f"signin federation getSigninToken returned no SigninToken: {body[:200]}"
        )
    return signin_token


def _build_get_signin_token_url(creds: Any) -> str:
    """The A7 federation URL, built once. See `call_federation_get_signin_token`."""


    session = {
        "sessionId": getattr(creds, "access_key", "") or "",
        "sessionKey": getattr(creds, "secret_key", "") or "",
        "sessionToken": getattr(creds, "session_token", "") or "",
    }
    query = urllib.parse.urlencode(
        {
            "Action": "getSigninToken",
            "SessionType": "json",
            "Session": json.dumps(session, separators=(",", ":")),
        }
    )
    return f"https://signin.aws.amazon.com/federation?{query}"


def build_federated_login_url(
    *,
    creds: Any,
    region: str,
    destination: Optional[str] = None,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> str:
    """Build a console login URL using temporary credentials."""
    signin_token = call_federation_get_signin_token(
        creds, timeout=timeout, proxy_url=proxy_url, proxy_insecure=proxy_insecure
    )
    resolved_destination = destination or (
        f"https://{region}.console.aws.amazon.com/console/home?region={region}"
    )
    query = urllib.parse.urlencode(
        {
            "Action": "login",
            "Issuer": "cli-script",
            "Destination": resolved_destination,
            "SigninToken": signin_token,
        }
    )
    log(f"Built federated login URL region={region}")
    return f"https://signin.aws.amazon.com/federation?{query}"


class _OAuthCallbackIntercepted(Exception):
    """Raised by the redirect handler when the OAuth callback.js URL is reached."""

    def __init__(self, url: str) -> None:
        self.callback_url = url


class _OAuthRedirectInterceptor(urllib.request.HTTPRedirectHandler):
    """Follow normal redirects but stop at callback.js — raise instead of fetching."""

    max_repeats = 4
    max_redirections = 4

    def _intercept_if_callback(self, newurl: str) -> None:
        if "/callback.js" in newurl:
            raise _OAuthCallbackIntercepted(newurl)

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        self._intercept_if_callback(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

    def http_error_301(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        self._intercept_if_callback(headers.get("Location", ""))
        return super().http_error_301(req, fp, code, msg, headers)

    def http_error_302(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        self._intercept_if_callback(headers.get("Location", ""))
        return super().http_error_302(req, fp, code, msg, headers)

    def http_error_303(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> Any:
        self._intercept_if_callback(headers.get("Location", ""))
        return super().http_error_303(req, fp, code, msg, headers)


def _prime_signin_session(
    *,
    creds: AwsSessionCreds,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> http.cookiejar.CookieJar:
    """Obtain signin.aws.amazon.com session cookies via the federation API."""
    ssl_ctx = _build_ssl_ctx(proxy_url, proxy_insecure)
    extra = _proxy_handler(proxy_url)


    signin_token = call_federation_get_signin_token(
        creds, timeout=timeout, proxy_url=proxy_url, proxy_insecure=proxy_insecure
    )
    api_log(
        creds,
        f"API response: signin.aws.amazon.com/federation SigninToken len={len(signin_token)}",
    )

    login_url = (
        "https://signin.aws.amazon.com/federation"
        "?Action=login"
        "&Issuer="
        "&Destination=https%3A%2F%2Fconsole.aws.amazon.com%2F"
        f"&SigninToken={urllib.parse.quote(signin_token)}"
    )
    api_log(creds, "API request: GET signin.aws.amazon.com/federation?Action=login")
    cookie_jar = http.cookiejar.CookieJar()
    cookie_opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_ctx),
        urllib.request.HTTPCookieProcessor(cookie_jar),
        *extra,
    )
    try:
        with cookie_opener.open(login_url, timeout=timeout) as resp:
            resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        raise CloudShellAutomationError(
            f"signin federation login failed HTTP {exc.code}: {body[:300]}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CloudShellAutomationError(
            f"signin federation login network error: {exc.reason}"
        ) from exc
    cookie_names = [c.name for c in cookie_jar]
    api_log(creds, f"API response: signin.aws.amazon.com/federation login cookies={cookie_names}")
    return cookie_jar


_SIGNIN_SESSION_CACHE: dict[str, http.cookiejar.CookieJar] = {}
_SIGNIN_SESSION_LOCK = threading.Lock()


def signin_session_key(creds: AwsSessionCreds) -> str:
    """WHICH credential a cached federation session belongs to."""
    material = f"{creds.access_key}\0{creds.session_token or ''}".encode()
    return hashlib.sha256(material).hexdigest()[:16]


def forget_signin_session(creds: AwsSessionCreds) -> None:
    """Drop this credential's cached federation session."""
    with _SIGNIN_SESSION_LOCK:
        _SIGNIN_SESSION_CACHE.pop(signin_session_key(creds), None)


def _signin_session_for(
    *,
    creds: AwsSessionCreds,
    region: str,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    allow_cache: bool = True,
) -> tuple[http.cookiejar.CookieJar, bool]:
    """A federated console session for `creds`, reused when it cannot be stale."""
    key = signin_session_key(creds)
    timeable = not creds.is_expired()
    if allow_cache and timeable:
        with _SIGNIN_SESSION_LOCK:
            cached = _SIGNIN_SESSION_CACHE.get(key)
        if cached is not None:


            record_call(
                "signin.prime",
                signing_path="key",
                region=region,
                duration_ms=0.0,
                cached=True,
            )
            detail("[pkce] reusing the federated console session for this credential")
            return cached, True

    _t0 = time.monotonic()
    _err: Optional[str] = None
    try:
        jar = _prime_signin_session(
            creds=creds, timeout=timeout, proxy_url=proxy_url, proxy_insecure=proxy_insecure
        )
    except Exception as exc:
        _err = f"{type(exc).__name__}: {exc}"
        raise
    finally:


        record_call(
            "signin.prime",
            signing_path="key",
            region=region,
            duration_ms=(time.monotonic() - _t0) * 1000,
            error=_err,
            cached=False,
        )
    with _SIGNIN_SESSION_LOCK:
        if timeable:
            _SIGNIN_SESSION_CACHE[key] = jar
        else:


            _SIGNIN_SESSION_CACHE.pop(key, None)
    return jar, False


def project_credentials_via_presign(
    page: Any,
    *,
    region: str,
    env_id: str,
    timeout: int = 30,
) -> None:
    """Project credentials into `env_id` for a CONSOLE principal, no widget."""
    from cloudbasher.csp.aws.console_api import (
        _presign,
        _signed_headers,
        build_presign_descriptor,
        call_cloudshell,
    )

    pkce = build_oauth_pkce_params(region=region, environment_id=env_id)


    descriptor = build_presign_descriptor(
        region=region,
        method="GET",
        hostname=pkce.auth_host,
        path="/oauth",
        body="",
        query=pkce.query_params,
        content_type=None,
    )
    signed = _signed_headers(_presign(page, region, descriptor, timeout), "oauth", page)

    response = page.context.request.get(pkce.url, headers=signed, timeout=timeout * 1000)
    body = response.text()
    match = AUTH_CODE_RE.search(body or "")
    if not match:


        raise CloudShellAutomationError(
            f"auth.cloudshell /oauth returned HTTP {response.status} with no auth "
            f"code (body {len(body or '')} bytes). presign signed the request, so "
            f"this is the endpoint refusing it, not a missing signature."
        )

    redeemed = call_cloudshell(
        page,
        region=region,
        operation="redeemCode",
        timeout=timeout,
        payload={
            "EnvironmentId": env_id,
            "AuthCode": match.group(1),
            "CodeVerifier": pkce.code_verifier,
            "RedirectUri": pkce.redirect_uri,
            "KeyBase": pkce.key_base,
        },
    )
    refresh_token = str((redeemed or {}).get("RefreshToken") or "")
    if not refresh_token:
        raise CloudShellAutomationError("redeemCode returned no RefreshToken")

    call_cloudshell(
        page,
        region=region,
        operation="putCredentials",
        timeout=timeout,
        payload={
            "EnvironmentId": env_id,
            "KeyBase": pkce.key_base,
            "RefreshToken": refresh_token,
        },
    )
    detail(f"[console] credentials projected into {env_id} via presign (no widget)")


@dataclass
class OAuthPkceParams:
    """Everything the auth.cloudshell PKCE exchange needs, minus the signature."""

    code_verifier: str
    key_base: str
    state: str
    code_challenge: str
    redirect_uri: str
    auth_host: str
    canonical_query: str


    query_params: dict
    url: str


def build_oauth_pkce_params(*, region: str, environment_id: str) -> OAuthPkceParams:
    """Generate the client-side half of the auth.cloudshell PKCE exchange."""
    code_verifier = str(uuid.uuid4()) + str(uuid.uuid4())
    key_base = base64.b64encode(secrets.token_bytes(32)).decode()
    state = str(uuid.uuid4())
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    redirect_uri = f"https://auth.cloudshell.{region}.aws.amazon.com/callback.js?state={state}"
    auth_host = f"auth.cloudshell.{region}.aws.amazon.com"
    query_params = {
        "EnvironmentId": environment_id,
        "codeVerifier": code_challenge,
        "redirectUri": redirect_uri,
    }
    canonical_query = urllib.parse.urlencode(
        sorted(query_params.items()),
        quote_via=urllib.parse.quote,
        safe="-_.~",
    )
    return OAuthPkceParams(
        code_verifier=code_verifier,
        key_base=key_base,
        state=state,
        code_challenge=code_challenge,
        redirect_uri=redirect_uri,
        auth_host=auth_host,
        canonical_query=canonical_query,
        query_params=query_params,
        url=f"https://{auth_host}/oauth?{canonical_query}",
    )


AUTH_CODE_RE = re.compile(r'main\("([^"]+)"')


def call_auth_cloudshell_oauth_flow(
    *,
    region: str,
    environment_id: str,
    creds: AwsSessionCreds,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> CloudShellBrowserAuthContext:
    """Drive the auth.cloudshell OAuth PKCE flow without a browser."""
    from cloudbasher.csp.aws.signing import sigv4_sign

    pkce = build_oauth_pkce_params(region=region, environment_id=environment_id)
    code_verifier = pkce.code_verifier
    key_base = pkce.key_base
    redirect_uri = pkce.redirect_uri
    auth_host = pkce.auth_host
    canonical_query = pkce.canonical_query
    url = pkce.url

    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    auth_headers = sigv4_sign(
        method="GET",
        service="cloudshell",
        region=region,
        host=auth_host,
        canonical_uri="/oauth",
        canonical_query=canonical_query,
        body=b"",
        creds=creds,
        amz_date=amz_date,
        date_stamp=date_stamp,
    )


    auth_code = None
    for _attempt in (1, 2):
        cookie_jar, from_cache = _signin_session_for(
            creds=creds,
            region=region,
            timeout=timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
            allow_cache=_attempt == 1,
        )
        try:
            auth_code = _fetch_oauth_auth_code(
                creds=creds,
                region=region,
                environment_id=environment_id,
                url=url,
                auth_headers=auth_headers,
                cookie_jar=cookie_jar,
                timeout=timeout,
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
            )
            break
        except CloudShellAutomationError:
            if not from_cache:
                raise
            log(
                "[pkce] auth.cloudshell /oauth refused the reused federation "
                "session; re-priming and retrying once"
            )
            forget_signin_session(creds)

    context = CloudShellBrowserAuthContext(
        region=region,
        environment_id=environment_id,
        auth_code=auth_code,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        key_base=key_base,
        captured_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        source="api",
        session_creds=creds,
    )
    return save_browser_auth_context(context)


def _fetch_oauth_auth_code(
    *,
    creds: AwsSessionCreds,
    region: str,
    environment_id: str,
    url: str,
    auth_headers: dict[str, str],
    cookie_jar: http.cookiejar.CookieJar,
    timeout: int,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> str:
    """The `/oauth` GET: signed headers plus a console session in, AuthCode out."""
    api_log(
        creds,
        f"API request: GET auth.cloudshell.{region}/oauth EnvironmentId={environment_id}",
    )
    _oauth_t0 = time.monotonic()
    ssl_ctx = _build_ssl_ctx(proxy_url, proxy_insecure)
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_ctx),
        urllib.request.HTTPCookieProcessor(cookie_jar),
        _OAuthRedirectInterceptor(),
        *_proxy_handler(proxy_url),
    )

    auth_code: Optional[str] = None
    intercepted = False
    _oauth_err: Optional[str] = None
    try:
        req = urllib.request.Request(url=url, method="GET", headers=auth_headers)
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", "replace")
            m = re.search(r'main\("([^"]+)"', body)
            if not m:
                raise CloudShellAutomationError(
                    f"auth.cloudshell OAuth callback.js did not contain auth code; "
                    f"body_prefix={body[:200]!r}"
                )
            auth_code = m.group(1)
    except _OAuthCallbackIntercepted as exc:
        intercepted = True
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(exc.callback_url).query)
        codes = qs.get("code", [])
        if not codes:
            raise CloudShellAutomationError(
                f"auth.cloudshell OAuth callback URL missing code: {exc.callback_url}"
            ) from exc
        auth_code = codes[0]
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        api_log(creds, f"auth.cloudshell OAuth flow HTTP {exc.code} body={body[:500]}")
        _oauth_err = f"{type(exc).__name__}: {exc}"
        raise CloudShellAutomationError(
            f"auth.cloudshell OAuth flow failed HTTP {exc.code}: {body[:500]}"
        ) from exc
    except urllib.error.URLError as exc:
        _oauth_err = f"{type(exc).__name__}: {exc}"
        raise CloudShellAutomationError(
            f"auth.cloudshell OAuth flow network error: {exc.reason}"
        ) from exc
    finally:


        record_call(
            "oauth",
            signing_path="key",
            region=region,
            duration_ms=(time.monotonic() - _oauth_t0) * 1000,


            error=_oauth_err or (None if auth_code else "no auth code"),
            intercepted=intercepted,
        )

    api_log(
        creds,
        f"API response: GET auth.cloudshell.{region}/oauth AuthCode len={len(auth_code or '')}",
    )
    return auth_code or ""


def project_credentials_browser_free(
    api_client: Any,
    *,
    region: str,
    env_id: str,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> None:
    """Run the browser-free OAuth PKCE flow and project credentials into `env_id`."""
    begin_credential_projection(
        api_client,
        region=region,
        env_id=env_id,
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    ).finish()


class PendingProjection:
    """The auth half of credential projection, running while the caller does something else -- specifically, while it opens the WebSocket session."""

    def __init__(self, api_client: Any, env_id: str) -> None:
        self._api_client = api_client
        self._env_id = env_id
        self._ctx: Optional[CloudShellBrowserAuthContext] = None
        self._exc: Optional[BaseException] = None
        self._thread: Optional[threading.Thread] = None

    def _run(self, **kwargs: Any) -> None:
        try:
            self._ctx = call_auth_cloudshell_oauth_flow(**kwargs)
        except Exception as exc:


            self._exc = exc

    def finish(self) -> None:
        """Join the auth flow and project. Raises whatever the worker raised."""
        if self._thread is not None:
            self._thread.join()
        if self._exc is not None:
            raise self._exc
        ctx = self._ctx
        if ctx is None:  # pragma: no cover - _run sets one or the other
            raise CloudShellAutomationError("credential projection produced no auth context")
        create_session_pkce(
            self._api_client,
            self._env_id,
            auth_code=ctx.auth_code,
            code_verifier=ctx.code_verifier,
            redirect_uri=ctx.redirect_uri,
            key_base=ctx.key_base,
        )


def make_reprojector(
    pending: Any,
    api_getter: Any,
    *,
    region: str,
    env_id: str,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> Any:
    """A callable that re-installs this container's credential material (T101)."""
    if pending is None:
        return None

    def _reproject() -> None:
        api = api_getter() if callable(api_getter) else api_getter
        if api is None:
            return
        begin_credential_projection(
            api,
            region=region,
            env_id=env_id,
            timeout=timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        ).finish()

    return _reproject


def presign_projection_enabled() -> bool:
    """Is the fast console projection switched on? Default YES, since 2026-08-16."""
    import os

    return os.environ.get("CLOUDBASHER_PRESIGN_PROJECTION", "1") != "0"


def console_reprojector_for(
    api_getter: Any,
    *,
    region: str,
    env_id: str,
    timeout: int = 30,
) -> Any:
    """`make_reprojector`'s console counterpart, gated (T101a)."""
    if not env_id:
        return None
    if not presign_projection_enabled():
        detail(
            "[keepalive] presign projection is off "
            "(CLOUDBASHER_PRESIGN_PROJECTION=0); this console node will NOT "
            "re-project its container credential, and will lose it when its "
            "RefreshToken expires (T101a)"
        )
        return None

    def _reproject() -> None:
        from cloudbasher.csp.aws.playwright_owner import run_owned

        api = api_getter() if callable(api_getter) else api_getter
        page = getattr(api, "page", None)
        if page is None:


            return
        run_owned(
            page,
            project_credentials_via_presign,
            page,
            region=region,
            env_id=env_id,
            timeout=timeout,
        )

    return _reproject


def begin_credential_projection(
    api_client: Any,
    *,
    region: str,
    env_id: str,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> PendingProjection:
    """Start the OAuth half of projection in the background; see PendingProjection."""
    pending = PendingProjection(api_client, env_id)
    try:
        creds = api_client.get_session_creds()
    except Exception as exc:


        pending._exc = exc
        return pending
    pending._thread = threading.Thread(
        target=pending._run,
        kwargs=dict(
            region=region,
            environment_id=env_id,
            creds=creds,
            timeout=timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        ),
        name=f"cb-oauth-{region}",
        daemon=True,
    )
    pending._thread.start()
    return pending


def create_session_pkce(
    api_client: Any,
    env_id: str,
    auth_code: Optional[str] = None,
    code_verifier: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    key_base: Optional[str] = None,
) -> dict[str, Any]:
    """Project PKCE credentials into CloudShell via redeemCode + putCredentials."""
    if not any([auth_code, code_verifier, redirect_uri, key_base]):
        raise NotImplementedError(
            "create_session_pkce requires PKCE parameters captured from browser flow. "
            "Supply console/SSO credentials via --creds-file to enable browser login."
        )

    detail(f"[pkce] redeem_code env_id={env_id}")

    redeem_resp = api_client._make_request(
        "/redeemCode",
        {
            "EnvironmentId": env_id,
            "AuthCode": auth_code or "",
            "CodeVerifier": code_verifier or "",
            "RedirectUri": redirect_uri or "",
            "KeyBase": key_base or "",
        },
    )
    payload, headers, status = (
        redeem_resp if isinstance(redeem_resp, tuple) else (redeem_resp, {}, 200)
    )
    if isinstance(payload, dict) and status >= 400:
        raise RuntimeError(f"redeemCode failed (status={status}): {payload}")

    refresh_token = payload.get("RefreshToken", "") if isinstance(payload, dict) else ""


    if isinstance(payload, dict):
        detail(f"[pkce] redeemCode payload keys={sorted(payload.keys())}")
    log(f"[pkce] redeemCode OK env_id={env_id} has_refresh_token={bool(refresh_token)}")

    api_client.put_credentials(env_id, {"refresh_token": refresh_token, "key_base": key_base or ""})

    log(f"[pkce] putCredentials OK env_id={env_id}")
    return {
        "session_id": headers.get("x-amzn-RequestId", "unknown"),
        "refresh_token": refresh_token,
    }
