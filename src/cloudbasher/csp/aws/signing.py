#!/usr/bin/env python3
"""AWS SigV4 signing and the HTTP transport for CloudShell API calls."""

from __future__ import annotations

import datetime as dt
import functools
import hashlib
import hmac
import http.cookiejar
import io
import json
import random
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, ClassVar, Optional

from cloudbasher.core.config import switch
from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.session.transport_faults import (
    is_dns_resolution_failure,
    is_fd_exhaustion,
)
from cloudbasher.core.utils.output import detail, log
from cloudbasher.csp.aws.credentials import AwsSessionCreds  # noqa: F401 (re-export)


_SERVER_ERROR_STATUSES = frozenset({500, 502, 503, 504})


_IDEMPOTENT_PATHS = frozenset(
    {
        "/getEnvironmentStatus",
        "/describeEnvironments",
        "/startEnvironment",
        "/stopEnvironment",
        "/sendHeartBeat",
    }
)


_EXPIRED_CREDENTIAL_CODES = frozenset(
    {
        "ExpiredToken",
        "ExpiredTokenException",
        "TokenRefreshRequired",
        "InvalidClientTokenId",
        "RequestExpired",
    }
)


_LAST_CALL = threading.local()


def last_transport_retries() -> int:
    """Retries the calling thread's last signed request needed. 0 = clean."""
    return int(getattr(_LAST_CALL, "transport_retries", 0) or 0)


def _extract_error_code(raw_body: str) -> Optional[str]:
    """Best-effort AWS error-type extraction from an HTTP error body, for CloudShellAutomationError's structured error_code. AWS JSON error responses commonly use a "__type" field (e.g. "AccessDeniedException"); no real captured response for a CloudShell API error exists in this codebase to confirm that field name specifically, so this also tries "Code"/"code" as fallbacks and returns None rather than guessing further -- callers should treat this as a hint, not a guaranteed classification, and any hardening should come from reviewing real logged values."""
    try:
        parsed = json.loads(raw_body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None
    for key in ("__type", "Code", "code"):
        value = parsed.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, msg: str) -> bytes:
    """Compute HMAC-SHA256."""
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _derive_signing_key(*, secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """The SigV4 signing key: `AWS4<secret>` HMAC'd through date, region, service, `aws4_request`"""
    key = hmac_sha256(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    for rung in (region, service, "aws4_request"):
        key = hmac_sha256(key, rung)
    return key


def sigv4_sign(
    *,
    method: str,
    service: str,
    region: str,
    host: str,
    canonical_uri: str,
    canonical_query: str,
    body: bytes,
    creds: AwsSessionCreds,
    amz_date: str,
    date_stamp: str,
    extra_headers: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Generate AWS SigV4 authorization headers."""

    payload_hash = sha256_hex(body)
    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if creds.session_token:
        headers["x-amz-security-token"] = creds.session_token
    if extra_headers:
        for key, value in extra_headers.items():
            headers[key.lower()] = value

    sorted_header_keys = sorted(headers.keys())
    canonical_headers = "".join(f"{key}:{headers[key].strip()}\n" for key in sorted_header_keys)
    signed_headers = ";".join(sorted_header_keys)

    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )


    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            sha256_hex(canonical_request.encode("utf-8")),
        ]
    )


    k_signing = _derive_signing_key(
        secret_key=creds.secret_key, date_stamp=date_stamp, region=region, service=service
    )
    signature = hmac_sha256(k_signing, string_to_sign).hex()


    authorization = (
        "AWS4-HMAC-SHA256 "
        f"Credential={creds.access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    out_headers = {
        "Host": host,
        "X-Amz-Date": amz_date,
        "X-Amz-Content-Sha256": payload_hash,
        "Authorization": authorization,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if creds.session_token:
        out_headers["X-Amz-Security-Token"] = creds.session_token
    if extra_headers:
        out_headers.update(extra_headers)

    return out_headers


def presign_websocket_url(
    *,
    host: str,
    region: str,
    creds: AwsSessionCreds,
    canonical_uri: str = "/",
    expires_seconds: int = 300,
    amz_date: Optional[str] = None,
    date_stamp: Optional[str] = None,
) -> str:
    """Build a SigV4 presigned wss:// URL for an AWS_IAM-authorized API Gateway WebSocket handshake (service="execute-api")."""
    now = dt.datetime.now(dt.timezone.utc)
    if amz_date is None:
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    if date_stamp is None:
        date_stamp = now.strftime("%Y%m%d")

    service = "execute-api"
    method = "GET"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"


    payload_hash = sha256_hex(b"")


    credential = f"{creds.access_key}/{credential_scope}"
    query_params = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": credential,
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires_seconds),
        "X-Amz-SignedHeaders": "host",
    }
    if creds.session_token:
        query_params["X-Amz-Security-Token"] = creds.session_token
    canonical_query = "&".join(
        f"{urllib.parse.quote(key, safe='')}={urllib.parse.quote(value, safe='')}"
        for key, value in sorted(query_params.items())
    )

    canonical_headers = f"host:{host}\n"
    signed_headers = "host"

    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )


    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            sha256_hex(canonical_request.encode("utf-8")),
        ]
    )


    k_signing = _derive_signing_key(
        secret_key=creds.secret_key, date_stamp=date_stamp, region=region, service=service
    )
    signature = hmac_sha256(k_signing, string_to_sign).hex()


    final_query = f"{canonical_query}&X-Amz-Signature={signature}"


    if switch("aws.log_presign"):
        api_detail(creds, f"API presign: GET wss://{host}{canonical_uri}")

    return f"wss://{host}{canonical_uri}?{final_query}"


def _build_https_context(proxy_url: Optional[str], proxy_insecure: bool) -> ssl.SSLContext:
    """Build SSL context for HTTPS."""
    if proxy_insecure and proxy_url:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    return ssl.create_default_context()


class _PooledResponse:
    """A `requests` response wearing urllib's response interface."""

    def __init__(self, resp: Any) -> None:
        self._resp = resp

    def read(self) -> bytes:
        return self._resp.content

    @property
    def status(self) -> int:
        return int(self._resp.status_code)

    @property
    def headers(self) -> Any:
        return self._resp.headers

    def __enter__(self) -> "_PooledResponse":
        return self

    def __exit__(self, *_exc: Any) -> bool:
        return False


_GLOBAL_POOLED_HOSTS = ("sts.amazonaws.com", "iam.amazonaws.com")


@functools.lru_cache(maxsize=1)
def _pool_count() -> int:
    """How many per-host connection pools ONE session has to be able to hold."""
    from cloudbasher.csp.aws.multi_region import _ALL_REGIONS

    return len(_ALL_REGIONS) + len(_GLOBAL_POOLED_HOSTS)


class _RefuseAllCookies(http.cookiejar.DefaultCookiePolicy):
    """Store nothing, send nothing. See `_PooledOpener._session`."""

    def set_ok(self, cookie: Any, request: Any) -> bool:
        return False

    def return_ok(self, cookie: Any, request: Any) -> bool:
        return False


class _PooledOpener:
    """urllib's opener interface over a connection-pooling `requests.Session`."""

    @classmethod
    def _pool_maxsize(cls) -> int:
        """Connections held open PER HOST."""
        from cloudbasher.core.utils.perf_config import get_max_workers

        return max(8, get_max_workers())

    @classmethod
    def _adapter_kwargs(cls) -> dict[str, Any]:
        """One place the adapter is configured, evaluated per adapter."""
        return dict(
            pool_connections=_pool_count(),
            pool_maxsize=cls._pool_maxsize(),


            max_retries=0,
        )


    _shared_adapters: ClassVar[dict[bool, Any]] = {}
    _adapter_lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def _adapter(cls, verify: bool) -> Any:
        """A PLAIN lock, not double-checked locking."""
        import requests.adapters

        with cls._adapter_lock:
            adapter = cls._shared_adapters.get(verify)
            if adapter is None:
                adapter = requests.adapters.HTTPAdapter(**cls._adapter_kwargs())
                cls._shared_adapters[verify] = adapter
            return adapter

    _local = threading.local()

    def __init__(self, proxy_url: Optional[str], proxy_insecure: bool) -> None:
        self._proxy_url = (proxy_url or "").strip()


        self._verify = not (proxy_insecure and bool(self._proxy_url))

    def _session(self) -> Any:
        import requests.adapters

        key = (self._proxy_url, self._verify)
        cache = getattr(self._local, "sessions", None)
        if cache is None:
            cache = self._local.sessions = {}
        session = cache.get(key)
        if session is None:
            session = requests.Session()


            adapter = self._adapter(self._verify)
            session.mount("https://", adapter)
            session.mount("http://", adapter)


            session.cookies.set_policy(_RefuseAllCookies())
            if self._proxy_url:
                session.proxies = {"http": self._proxy_url, "https": self._proxy_url}
            cache[key] = session
        return session

    def open(self, req: urllib.request.Request, timeout: Optional[float] = None) -> Any:
        import requests

        try:
            resp = self._session().request(
                method=req.get_method(),
                url=req.full_url,
                data=req.data,


                headers=dict(req.header_items()),
                timeout=timeout,


                allow_redirects=False,
                verify=self._verify,
            )
        except requests.RequestException as exc:

            raise urllib.error.URLError(exc) from exc
        if resp.status_code >= 400:


            raise urllib.error.HTTPError(
                req.full_url,
                resp.status_code,
                resp.reason or "",
                resp.headers,
                io.BytesIO(resp.content),  # type: ignore[arg-type]
            )
        return _PooledResponse(resp)


def _build_url_opener(
    proxy_url: Optional[str],
    *,
    proxy_insecure: bool = False,
) -> Any:
    """The HTTP transport, with connection reuse and optional proxy support."""
    return _PooledOpener(proxy_url, proxy_insecure)


def acting_as_clause(creds: AwsSessionCreds) -> str:
    """`` as=<principal>`` for one signed request, or an honest refusal."""
    ref = creds.cred_ref or "cred#?"
    if creds.principal_arn:


        return f" as={creds.identity_label} [{ref}]"


    mode = creds.act_as.mode if creds.act_as else "none"
    return f" as={ref} key={creds.identity_label} ACT_AS={mode}"


def api_detail(creds: AwsSessionCreds, message: str, /) -> None:
    """Announce one outbound AWS call at DEBUG, naming the credential"""
    detail(f"{message}{acting_as_clause(creds)}", axis=creds.identity_axis)


def api_log(creds: AwsSessionCreds, message: str, /) -> None:
    """`api_detail` at INFO -- for the call surfaces a user is meant to see."""
    log(f"{message}{acting_as_clause(creds)}", axis=creds.identity_axis)


def signed_cloudshell_post(
    *,
    region: str,
    path: str,
    body_obj: Optional[dict[str, Any]],
    creds: AwsSessionCreds,
    timeout: int,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    max_retries: Optional[int] = None,
) -> tuple[dict[str, Any], dict[str, str], int]:
    """Make a SigV4-signed POST request to CloudShell API."""

    host = f"cloudshell.{region}.amazonaws.com"
    url = f"https://{host}{path}"
    body = b"" if body_obj is None else json.dumps(body_obj, separators=(",", ":")).encode("utf-8")


    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")


    headers = sigv4_sign(
        method="POST",
        service="cloudshell",
        region=region,
        host=host,
        canonical_uri=path,
        canonical_query="",
        body=body,
        creds=creds,
        amz_date=amz_date,
        date_stamp=date_stamp,
        extra_headers={
            "x-amz-user-agent": "cloudshell-automation/1.0",
            "amz-sdk-request": "attempt=1; max=1",
            "amz-sdk-invocation-id": str(uuid.uuid4()),
        },
    )


    req = urllib.request.Request(url=url, data=body, headers=headers, method="POST")
    opener = _build_url_opener(proxy_url, proxy_insecure=proxy_insecure)

    api_detail(creds, f"API request: POST {url} body_bytes={len(body)}")

    from cloudbasher.core.utils.perf_config import (
        get_throttle_backoff_base_seconds,
        get_throttle_max_retries,
    )


    if max_retries is None:
        max_retries = get_throttle_max_retries()
    backoff_base = get_throttle_backoff_base_seconds()
    attempt = 0
    while True:
        try:
            with opener.open(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                status = int(resp.status)
                hdrs = {key: value for key, value in resp.headers.items()}
            break
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", "replace")
            hdrs = {key: value for key, value in exc.headers.items()} if exc.headers else {}
            req_id = hdrs.get("x-amzn-RequestId", "n/a")
            api_detail(creds, f"API response: POST {url} status={exc.code} request_id={req_id}")
            if exc.code == 403:


                code_403 = _extract_error_code(raw)
                if code_403 in _EXPIRED_CREDENTIAL_CODES:
                    hint = (
                        f"the credential has EXPIRED ({code_403}). This is not a "
                        "permissions problem -- derive a fresh one. A "
                        "GetFederationToken session is 12h by default and an "
                        "AssumeRole session 1h, so a long-lived node outlives its "
                        "own credential unless something re-derives it."
                    )
                else:
                    hint = (
                        "(Access Denied) your credentials may lack cloudshell:* IAM "
                        "permissions, or an SCP blocks CloudShell"
                        + (f" (error code {code_403})" if code_403 else "")
                        + ". Verify with: aws sts get-caller-identity"
                    )
                raise CloudShellAutomationError(
                    f"CloudShell API {path} returned HTTP 403: {hint}",
                    status_code=exc.code,
                    error_code=code_403,


                    response_body=raw,
                ) from exc
            _retryable = exc.code == 429 or (
                exc.code in _SERVER_ERROR_STATUSES and path in _IDEMPOTENT_PATHS
            )
            if _retryable and attempt < max_retries:


                delay = min(backoff_base * (2**attempt), 10.0) + random.uniform(0, backoff_base)
                attempt += 1


                _retry_label = (
                    "API throttled: POST" if exc.code == 429 else "API server error: POST"
                )
                api_detail(
                    creds,
                    f"{_retry_label} {url} status={exc.code} "
                    f"retry {attempt}/{max_retries} after {delay:.1f}s",
                )
                time.sleep(delay)
                continue
            raise CloudShellAutomationError(
                f"CloudShell API {path} failed: HTTP {exc.code}; body={raw}",
                status_code=exc.code,
                error_code=_extract_error_code(raw),
            ) from exc
        except urllib.error.URLError as exc:


            if is_fd_exhaustion(exc):


                exc.cb_failure_class = "local_resource_exhausted"  # type: ignore[attr-defined]
            if attempt < max_retries and not (
                is_dns_resolution_failure(exc) or is_fd_exhaustion(exc)
            ):
                delay = min(backoff_base * (2**attempt), 10.0) + random.uniform(0, backoff_base)
                attempt += 1
                api_detail(
                    creds,
                    f"API request failed: POST {url} reason={exc.reason} "
                    f"retry {attempt}/{max_retries} after {delay:.1f}s",
                )
                time.sleep(delay)
                continue
            proxy_msg = f" via proxy {proxy_url}" if proxy_url else ""
            raise CloudShellAutomationError(
                f"HTTP request failed for {url}{proxy_msg}: {exc.reason}"
            ) from exc


    payload: dict[str, Any] = {}
    if raw.strip():
        payload = json.loads(raw)

    req_id = hdrs.get("x-amzn-RequestId", "n/a")
    api_detail(creds, f"API response: POST {url} status={status} request_id={req_id}")

    _LAST_CALL.transport_retries = attempt
    return payload, hdrs, status


def get_caller_identity(
    creds: AwsSessionCreds,
    *,
    timeout: int = 10,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> dict[str, Any]:
    """Return caller identity via STS GetCallerIdentity."""
    import xml.etree.ElementTree as ET

    _NS = "https://sts.amazonaws.com/doc/2011-06-15/"


    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    query = "Action=GetCallerIdentity&Version=2011-06-15"

    headers = sigv4_sign(
        method="GET",
        service="sts",
        region="us-east-1",
        host="sts.amazonaws.com",
        canonical_uri="/",
        canonical_query=query,
        body=b"",
        creds=creds,
        amz_date=amz_date,
        date_stamp=date_stamp,
    )

    url = f"https://sts.amazonaws.com/?{query}"


    api_detail(creds, "API request: GET sts.amazonaws.com Action=GetCallerIdentity")
    req = urllib.request.Request(url, headers=headers, method="GET")
    opener = _build_url_opener(proxy_url, proxy_insecure=proxy_insecure)

    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:


        err = getattr(exc, "reason", str(exc))
        api_detail(creds, f"STS GetCallerIdentity rejected: {err}")
        return {
            "ok": False,
            "arn": "",
            "account": "",
            "user_id": "",
            "error": str(err),
            "transient": False,
        }
    except (urllib.error.URLError, TimeoutError, OSError) as exc:


        err = getattr(exc, "reason", str(exc))
        api_detail(creds, f"STS GetCallerIdentity unreachable: {err}")
        return {
            "ok": False,
            "arn": "",
            "account": "",
            "user_id": "",
            "error": str(err),
            "transient": True,
        }

    try:
        if raw.lstrip().startswith("{"):

            data = json.loads(raw)
            result = data.get("GetCallerIdentityResponse", {}).get("GetCallerIdentityResult", data)
            return {
                "ok": True,
                "arn": result.get("Arn", ""),
                "account": result.get("Account", ""),
                "user_id": result.get("UserId", ""),
                "error": "",
            }
        else:

            root = ET.fromstring(raw)

            def _text(tag: str) -> str:
                el = root.find(f".//{{{_NS}}}{tag}")
                return el.text or "" if el is not None else ""

            return {
                "ok": True,
                "arn": _text("Arn"),
                "account": _text("Account"),
                "user_id": _text("UserId"),
                "error": "",
            }
    except Exception as exc:
        api_detail(creds, f"STS GetCallerIdentity parse error: {exc}")
        return {"ok": False, "arn": "", "account": "", "user_id": "", "error": str(exc)}
