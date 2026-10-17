"""GCP CloudShell private API client (shell.cloud.google.com)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.types import Credentials
from cloudbasher.core.utils.output import detail, log
from cloudbasher.csp.gcp._http import build_opener as _build_opener
from cloudbasher.csp.gcp._http import strip_xssi as _strip_xssi


def _do_request(
    url: str,
    *,
    method: str = "GET",
    body: Optional[bytes] = None,
    headers: Optional[dict[str, str]] = None,
    timeout: float = 30,
    opener: Optional[urllib.request.OpenerDirector] = None,
) -> tuple[Any, dict[str, str], int]:
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    op = opener or urllib.request.build_opener()
    try:
        resp = op.open(req, timeout=timeout)
        raw = resp.read().decode("utf-8", errors="replace")
        hdrs = dict(resp.headers)
        status = resp.getcode()
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        hdrs = dict(e.headers) if e.headers else {}
        status = e.code

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        parsed = raw

    return parsed, hdrs, status


def _safe_request_url(url: str) -> str:
    """Redact bearer-bearing query parameters before diagnostic logging."""
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    safe_query = [
        (
            key,
            "[redacted]"
            if key.lower() in {"request", "token", "access_token", "id_token"}
            else value,
        )
        for key, value in query
    ]
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(safe_query), parts.fragment)
    )


def _safe_protocol_shape(path: str, params: dict[str, str], payload: Any) -> str:
    """Describe native request structure without recording credentials/key bytes."""
    shape: dict[str, Any] = {"query_keys": sorted(params)}
    request_value = params.get("request")
    if request_value:
        try:
            request = json.loads(request_value)
        except (TypeError, ValueError):
            request = None
        if isinstance(request, list):
            if path.endswith("/authorize"):
                shape["request"] = {
                    "arity": len(request), "environment": request[0] if request else None,
                    "access_token_present": bool(request[1]) if len(request) > 1 else False,
                    "expiry": (
                        request[2]
                        if len(request) > 2 and isinstance(request[2], list)
                        else None
                    ),
                    "id_token_present": bool(request[3]) if len(request) > 3 else False,
                }
            else:
                shape["request"] = {
                    "array_arity": len(request),
                    "selector": request[0] if request else None,
                }
    if payload is not None:
        if path.endswith("setupsession") and isinstance(payload, list):
            key = (
                payload[2][1]
                if len(payload) > 2 and isinstance(payload[2], list)
                and len(payload[2]) > 1
                else ""
            )
            shape["body"] = [None, [], [2, f"<public-key-redacted:length={len(key)}>"]]
        elif isinstance(payload, list):
            if path.endswith("/authorize") and len(payload) >= 4:
                expiry = payload[2] if isinstance(payload[2], list) else None
                shape["body"] = {
                    "array_arity": len(payload),
                    "environment": payload[0],
                    "access_token_present": bool(payload[1]),
                    "expiry": expiry,
                    "id_token_present": bool(payload[3]),
                }
            else:
                shape["body"] = {"array_arity": len(payload)}
        elif isinstance(payload, dict):
            shape["body"] = {"object_keys": sorted(payload)}
        else:
            shape["body"] = {"type": type(payload).__name__}
    return json.dumps(shape, sort_keys=True, separators=(",", ":"))


def _safe_response_shape(body: Any) -> str:
    if isinstance(body, dict):
        shape: Any = {"type": "object", "keys": sorted(str(key) for key in body)}
    elif isinstance(body, list):
        shape = {"type": "array", "length": len(body)}
    elif isinstance(body, str):
        shape = {"type": "text", "length": len(body)}
    else:
        shape = {"type": type(body).__name__}
    return json.dumps(shape, sort_keys=True, separators=(",", ":"))


def extract_tab_id(list_tabs_resp: Any) -> Optional[int]:
    """Parse session_id from list_tabs() response."""
    if not isinstance(list_tabs_resp, list) or len(list_tabs_resp) < 2:
        return None
    try:
        tab_entry = list_tabs_resp[1][0]
        if len(tab_entry) > 1:
            ids = tab_entry[1]
            if isinstance(ids, list) and ids:
                return int(ids[0])
    except (IndexError, TypeError, ValueError):
        pass
    return None


class GCSPrivateAPI:
    """GCP CloudShell private API (shell.cloud.google.com)."""

    BASE = "https://shell.cloud.google.com"

    def __init__(
        self,
        credentials: Credentials,
        *,
        authuser: int = 0,
        timeout: float = 30,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
        bearer_token: Optional[str] = None,
        request_headers: Optional[dict[str, str]] = None,
        request_executor: Optional[Callable[..., tuple[Any, dict[str, str], int]]] = None,
    ) -> None:
        self._credentials = credentials


        self._credentials.extra.pop("access_jwt", None)
        self._authuser = authuser
        self._timeout = timeout
        self._opener = _build_opener(proxy_url, proxy_insecure)
        self._xsrf_token: Optional[str] = credentials.extra.get("xsrf_token")


        self._bearer_token = bearer_token
        self._request_headers = dict(request_headers or {})
        self._request_executor = request_executor
        diag_dir = credentials.extra.get("_diagnostics_dir")
        self._diagnostics_dir = Path(diag_dir) if diag_dir else None
        self.last_status: Optional[int] = None
        self.last_body_kind: Optional[str] = None
        self.last_response_ids: dict[str, str] = {}


        self.access_jwt: Optional[str] = None


    def _cookie_header(self) -> str:
        cookies = self._credentials.extra.get("cookies", {})
        if not cookies:
            return ""
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def _base_params(self) -> dict[str, str]:
        return {"authuser": str(self._authuser)}

    def _mutating_params(self) -> dict[str, str]:


        p: dict[str, str] = {}
        if self._xsrf_token:
            p["token"] = self._xsrf_token
        p["authuser"] = str(self._authuser)
        return p

    def _build_url(self, path: str, params: Optional[dict[str, str]] = None) -> str:
        qs = urllib.parse.urlencode(params or {})
        sep = "?" if qs else ""
        return f"{self.BASE}/{path}{sep}{qs}"

    def _headers(self, *, mutating: bool = False) -> dict[str, str]:
        h: dict[str, str] = dict(self._request_headers)
        if self._bearer_token:
            h["Authorization"] = f"Bearer {self._bearer_token}"
        cookie = self._cookie_header()
        if cookie:
            h["Cookie"] = cookie
        if mutating:
            h["Content-Type"] = "application/json"
        return h

    def _get(
        self,
        path: str,
        params: Optional[dict[str, str]] = None,
        *,
        allow_400: bool = False,
    ) -> Any:
        return self._request("GET", path, params=params, allow_400=allow_400, mutating=False)

    def _post(self, path: str, payload: Any = None, params: Optional[dict[str, str]] = None) -> Any:
        return self._request("POST", path, payload=payload, params=params, mutating=True)

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Any = None,
        params: Optional[dict[str, str]] = None,
        allow_400: bool = False,
        mutating: bool = False,
        allow_reauth: bool = True,
        _is_retry: bool = False,
    ) -> Any:
        """Shared GET/POST implementation with self-refresh on auth failure."""
        p = self._mutating_params() if mutating else self._base_params()
        if params:
            p.update(params)
        url = self._build_url(path, p)
        data = json.dumps(payload).encode() if (mutating and payload is not None) else None
        detail(f"[private_api] {method} {_safe_request_url(url)}")
        headers = self._headers(mutating=mutating)
        log(
            f"[private_api] request {method} /{path} "
            f"transport={'browser-context' if self._request_executor else 'http-client'} "
            f"headers={sorted(key.lower() for key in headers if key.lower() != 'cookie')} "
            f"cookie_present={bool(headers.get('Cookie'))} "
            f"body_bytes={len(data) if data is not None else 0} "
            f"shape={_safe_protocol_shape(path, p, payload)}"
        )
        if self._request_executor is not None:


            headers.pop("Cookie", None)
            raw_body, response_headers, status = self._request_executor(
                method, url, data, headers, self._timeout
            )
        else:
            raw_body, response_headers, status = _do_request(
                url,
                method=method,
                body=data,
                headers=headers,
                timeout=self._timeout,
                opener=self._opener,
            )
        self.last_status = status
        safe_id_headers = {
            "x-request-id",
            "x-goog-request-id",
            "x-cloud-trace-context",
        }
        self.last_response_ids = {
            key.lower(): value
            for key, value in response_headers.items()
            if key.lower() in safe_id_headers and value
        }
        self.last_body_kind = (
            "xssi-json"
            if isinstance(raw_body, str) and raw_body.startswith(")]}'")
            else "json-or-empty"
            if not isinstance(raw_body, str)
            else "html-or-text"
        )
        if self._diagnostics_dir is not None:


            from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

            append_private_jsonl(
                self._diagnostics_dir,
                "private-api.jsonl",
                {
                    "method": method,
                    "url": url,
                    "request_headers": headers,
                    "request_body": data.decode("utf-8", "replace") if data else None,
                    "response_status": status,
                    "response_headers": response_headers,
                    "response_body": raw_body,
                },
            )
        response_meta = {
            "status": status,
            "body_kind": self.last_body_kind,
            "body_bytes": (
                len(raw_body.encode("utf-8")) if isinstance(raw_body, str)
                else len(json.dumps(raw_body, separators=(",", ":")).encode("utf-8"))
            ),
            "shape": _safe_response_shape(raw_body),
            "request_ids": self.last_response_ids,
            "content_type": next(
                (v for k, v in response_headers.items() if k.lower() == "content-type"),
                None,
            ),
            "allow": next((v for k, v in response_headers.items() if k.lower() == "allow"), None),
        }
        log(f"[private_api] response {method} /{path} {json.dumps(response_meta, sort_keys=True)}")


        if status == 400 and allow_400:
            return None


        missing_xssi = (
            status == 200 and isinstance(raw_body, str) and not raw_body.startswith(")]}'")
        )


        retryable_status = status in {401, 403} or status >= 500
        auth_failed = retryable_status or missing_xssi

        if status >= 400 and not retryable_status:
            raise CloudShellAutomationError(
                f"{method} /{path} returned HTTP {status} (request_ids={self.last_response_ids}, "
                f"allow={response_meta['allow']!r}); no XSRF retry was made because this is "
                "not an authentication/server failure. Response body omitted."
            )

        if auth_failed:
            if allow_reauth and not _is_retry:
                log(
                    f"[private_api] {method} /{path} failed (status={status}, "
                    f"missing_xssi={missing_xssi}); refreshing XSRF token and retrying once"
                )
                try:
                    self.new_token()
                except CloudShellAutomationError as exc:
                    raise CloudShellAutomationError(
                        f"{method} /{path} failed (status={status}) and the XSRF token "
                        "refresh also failed — this looks like a full session/cookie "
                        "expiry, not just XSRF-token staleness; re-authenticate with fresh "
                        f"browser cookies rather than retrying. Original error: {exc}"
                    ) from exc
                return self._request(
                    method,
                    path,
                    payload=payload,
                    params=params,
                    allow_400=allow_400,
                    mutating=mutating,
                    allow_reauth=allow_reauth,
                    _is_retry=True,
                )
            raise CloudShellAutomationError(
                f"{method} /{path} returned HTTP {status} (request_ids={self.last_response_ids}); "
                f"XSRF_retry={_is_retry} — "
                "the request was rejected; response bodies are intentionally omitted. "
                "Review the session/cookie authentication state; re-authenticate if needed, "
                "then retry only after checking the safe status/metadata."
            )

        return _strip_xssi(raw_body)


    def new_token(self) -> str:
        """GET /newtoken — obtain XSRF token."""
        resp = self._request("GET", "newtoken", allow_reauth=False)
        if (
            isinstance(resp, list)
            and len(resp) >= 2
            and resp[0] == "ssh.nxt"
            and isinstance(resp[1], str)
            and bool(resp[1])
        ):
            self._xsrf_token = resp[1]
            self._credentials.extra["xsrf_token"] = resp[1]

            log("[private_api] new_token ok")
            return resp[1]


        raise CloudShellAutomationError(
            "GET /newtoken returned an unexpected response shape "
            f"(HTTP {self.last_status}; body_kind={self.last_body_kind}; "
            f"shape={_safe_response_shape(resp)}; request_ids={self.last_response_ids}). "
            "The fresh XSRF token was not accepted; refresh the Console session and retry.",
            status_code=self.last_status,
        )


    def environments_list(self) -> list:
        """GET the current user's Cloud Shell environment state."""
        return self._get(
            "cloudshell/environments/list",
            {"request": json.dumps(["users/me"], separators=(",", ":"))},
        )

    def environments_get(self, name: str = "users/me/environments/default") -> Any:
        """GET one environment using the native JSON request selector."""
        return self._get(
            "cloudshell/environments/get",
            {"request": json.dumps([name], separators=(",", ":"))},
        )

    def environments_authorize(
        self,
        name: str = "users/me/environments/default",
        *,
        access_token: Optional[str] = None,
        id_token: Optional[str] = None,
        expires_in: Optional[int] = None,
    ) -> Any:
        """POST `/cloudshell/environments/authorize` — project OAuth creds."""
        if not access_token:


            return self._get("cloudshell/environments/authorize", {"name": name})
        expiry = max(1, int(expires_in or 3600))
        expires_at = time.time() + expiry
        seconds = int(expires_at)
        nanos = int((expires_at - seconds) * 1_000_000_000)
        request = [name, access_token, [seconds, nanos], id_token or ""]
        return self._post("cloudshell/environments/authorize", request)


    def setup_session(self, ssh_public_key: str) -> dict[str, Any]:
        """POST /cloudshell/setupsession — create SSH session."""
        parts = ssh_public_key.strip().split()
        key_b64 = parts[1] if len(parts) >= 2 else ssh_public_key

        payload = [None, [], [2, key_b64]]
        resp = self._post("cloudshell/setupsession", payload)

        return self.parse_setup_session_response(resp)

    def parse_setup_session_response(self, resp: Any) -> dict[str, Any]:
        """Parse a native browser setupsession response without another call."""

        if not isinstance(resp, list) or len(resp) < 4:
            raise CloudShellAutomationError(f"Unexpected setupsession response: {resp}")

        session_info = resp[1] if len(resp) > 1 else []
        session_token = session_info[0] if isinstance(session_info, list) and session_info else None
        editor_url = None
        if isinstance(session_info, list) and len(session_info) > 1:
            url_array = session_info[1]
            if isinstance(url_array, list) and len(url_array) > 3:
                editor_url = url_array[3]

        self._credentials.extra["session_token"] = session_token
        status_code = resp[0] if isinstance(resp[0], int) else None
        log(
            f"[private_api] setup_session ok status={status_code} "
            f"({'hot-reconnect' if status_code == 1 else 'cold-start'}) "
            f"has_token={bool(session_token)}"
        )
        return {
            "status": status_code,
            "session_token": session_token,
            "editor_url": editor_url,
            "environment": resp[3] if len(resp) > 3 else [],
        }

    def abandon(self) -> Any:
        """POST the captured native Restart request to ``/devshell/abandon``."""
        response = self._request(
            "POST",
            "devshell/abandon",
            payload=[],
            mutating=True,
            allow_reauth=False,
        )


        if not (
            isinstance(response, list)
            and len(response) == 2
            and response[0] == "ssh.ad"
            and type(response[1]) is int
            and response[1] == 1
        ):
            raise CloudShellAutomationError(
                "POST /devshell/abandon returned without the native success "
                f"acknowledgement (HTTP {self.last_status}; "
                f"body_kind={self.last_body_kind}; "
                f"shape={_safe_response_shape(response)}; "
                f"request_ids={self.last_response_ids}). The node was not removed.",
                status_code=self.last_status,
            )
        return response

    def generate_access_token(
        self,
        name: str = "users/me/environments/default",
        ttl: int = 43200,
    ) -> str:
        """POST /cloudshell/generateaccesstoken — get JWT for file service."""
        payload = [name, None, [ttl]]
        resp = self._post("cloudshell/generateaccesstoken", payload)
        if isinstance(resp, list) and resp:
            jwt = resp[0]
            self.access_jwt = jwt
            log(f"[private_api] generate_access_token ok jwt_len={len(jwt)}")
            return jwt
        raise CloudShellAutomationError(f"Unexpected generateaccesstoken response: {resp}")


    def save_tab(self, port: int = 6000, tab_id: Optional[int] = None) -> Any:
        """POST /devshell/savetab — register terminal tab."""
        if tab_id is None:
            tab_id = int(time.time()) & 0x7FFFFFFF
        return self._post("devshell/savetab", [port, tab_id])

    def delete_tab(self, port: int = 6000, tab_id: int = 0) -> Any:
        """POST /devshell/deletetab — unregister terminal tab."""
        return self._post("devshell/deletetab", [port, tab_id])

    def list_tabs(self) -> Any:
        """GET /devshell/listtabs — list registered terminal tabs."""
        return self._get("devshell/listtabs", allow_400=True)


    def user_state(self) -> Any:
        """GET /cloudshell/userstate — check user's CloudShell state."""
        return self._get("cloudshell/userstate")

    def user_metadata(self) -> Any:
        """GET /cloudshell/usermetadata — UI state tracking."""
        return self._get("cloudshell/usermetadata")

    def environment_metadata(self) -> Any:
        """GET /cloudshell/environmentmetadata — GCE instance ID etc."""
        return self._get("cloudshell/environmentmetadata")

    def quota(self) -> Any:
        """GET /devshell/quota — weekly usage."""
        return self._get("devshell/quota", allow_400=True)

    def allowlisted_commands(self) -> Any:
        """GET /devshell/allowlistedcommands — command allowlist."""
        return self._get("devshell/allowlistedcommands")

    def terminal_theme(self) -> Any:
        """GET /terminaltheme — terminal color theme."""
        return self._get("terminaltheme")
