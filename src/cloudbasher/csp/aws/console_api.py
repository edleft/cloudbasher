"""CloudShell API calls made as the console principal, via `/api/prod/presign`."""

from __future__ import annotations

import uuid

import hashlib
import json
import re
import time
import urllib.parse
from typing import Any, Callable, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.session.failure import (
    CONSOLE_PRESIGN_REFUSED as PRESIGN_REFUSED,
)
from cloudbasher.core.utils.output import detail, log
from cloudbasher.core.utils.timeline import record_call
from cloudbasher.csp.aws.api import DEFAULT_SESSION_TYPE


_CLOUDSHELL_SERVICE = "cloudshell"


def _presign_url(region: str) -> str:
    return f"https://{region}.console.aws.amazon.com/api/prod/presign"


def _cloudshell_host(region: str) -> str:
    return f"cloudshell.{region}.amazonaws.com"


_REPLAYED_PRESIGN_HEADERS = (
    "x-console-api-token",
    "x-console-info",
    "x-web-client-version",
    "x-widget-id",
    "x-widget-stage",
)


def _console_presign_headers(page: Any) -> dict:
    """The presign headers the AWS console itself sends, read back off the live browser session rather than reconstructed."""


    capture = getattr(page, "_cb_capture", None)
    if capture is None:
        detail(
            "[console-api] NO AUTH CAPTURE ON THIS PAGE -- presign will be sent with "
            "no identity headers and will answer 401. That is not a refusal of any "
            "identity; it is a request that carries none. `playwright_console_bootstrap()` "
            "attaches the capture; a page built another way has to."
        )
        return {}
    try:
        observed = capture.console_request_headers(_CLOUDSHELL_SERVICE)
        source = _CLOUDSHELL_SERVICE
        if not observed:
            observed = capture.console_request_headers()
            source = ",".join(capture.presign_services()) or "none"
    except Exception as exc:  # noqa: BLE001
        detail(f"[console-api] auth capture unreadable ({exc!r}); presign will carry no identity")
        return {}
    if not observed:
        detail(
            "[console-api] the console has made NO presign call yet, so there is no "
            "identity to replay; presign will carry none and answer 401"
        )
        return {}

    replayed = {k: observed[k] for k in _REPLAYED_PRESIGN_HEADERS if observed.get(k)}
    if source == _CLOUDSHELL_SERVICE:
        detail(f"[console-api] replaying the CloudShell widget's own presign headers")
        return replayed


    replayed[_WIDGET_ID_HEADER] = _WIDGET_ID
    replayed[_WIDGET_STAGE_HEADER] = _WIDGET_STAGE
    detail(
        f"[console-api] no CloudShell-widget presign captured; synthesising its "
        f"identity from service={source!r} -- session headers reused, "
        f"{_WIDGET_ID_HEADER}={_WIDGET_ID!r} set, but {_WIDGET_SCOPED_HEADER} is "
        f"that widget's and cannot be forged"
    )
    return replayed


_WIDGET_ORIGIN_RE = re.compile(
    r"^https://cloudshell(\.widget)?\.console\.aws\.amazon\.com", re.IGNORECASE
)


def _presign_context(page: Any) -> tuple[Any, str]:
    """Where to run the exchange: the frame served from the CloudShell widget origin."""
    try:
        for frame in page.frames or []:
            url = str(getattr(frame, "url", "") or "")
            if _WIDGET_ORIGIN_RE.match(url):
                host = urllib.parse.urlparse(url).netloc
                return frame, f"the CloudShell widget frame ({host})"
    except Exception:
        pass
    try:
        from cloudbasher.csp.aws.cloudshell_terminal import cloudshell_frame

        frame = cloudshell_frame(page)
        if frame is not None:
            return frame, "the CloudShell iframe (matched by title, not origin)"
    except Exception:
        pass
    return page, "the top-level page (NO widget-origin frame found)"


_CLIENT_SET_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "via",
        "expect",
    }
)


_WIDGET_ORIGIN = "https://cloudshell.widget.console.aws.amazon.com"


_WIDGET_ID = "cloudshell"
_WIDGET_STAGE = "prod"
_WIDGET_ID_HEADER = "x-widget-id"
_WIDGET_STAGE_HEADER = "x-widget-stage"


_SESSION_SCOPED_HEADERS = ("x-console-api-token", "x-web-client-version")


_WIDGET_SCOPED_HEADER = "x-console-info"


_CLOUDSHELL_CONSOLE_INFO = "UNIVERSAL"


_PRESIGN_JS = """
async ({presignUrl, descriptor, presignHeaders}) => {
  const r = await fetch(presignUrl, {
    method: 'POST', credentials: 'include',
    headers: Object.assign({'content-type': 'application/json'}, presignHeaders),
    body: JSON.stringify(descriptor),
  });
  return {status: r.status, text: await r.text()};
}
"""


_DEAD_HANDLE_MARKERS = (
    "Event loop is closed",
    "Playwright already stopped",
    "has been closed",
    "Target closed",
    "Target page, context or browser has been closed",
)


def _handle_is_dead(exc: BaseException) -> bool:
    return any(marker in str(exc) for marker in _DEAD_HANDLE_MARKERS)


def _dead_handle_error(operation: str, exc: BaseException) -> CloudShellAutomationError:
    """A legible failure for "the browser this node needs is gone"."""
    err = CloudShellAutomationError(
        f"{operation}: this node's browser is gone, so there is no console "
        f"session left to sign with ({exc}).\n"
        "  A console credential has no access key -- the parked browser IS the "
        "credential, so this is not recoverable in place.\n"
        "  `.connect` signs in again and parks a new one (it costs a real login, "
        "including any MFA). `.unregister` drops the node without touching the "
        "cloud."
    )


    err.cb_permanent = True  # type: ignore[attr-defined]
    return err


def _presign_services(page: Any) -> str:
    """Which widgets' presign headers we did capture, for a legible refusal."""
    capture = getattr(page, "_cb_capture", None)
    try:
        return ",".join(capture.presign_services()) if capture is not None else ""
    except Exception:
        return ""


def build_presign_descriptor(
    *,
    region: str,
    method: str,
    hostname: str,
    path: str,
    body: str = "",
    query: Optional[dict] = None,
    content_type: Optional[str] = "application/json",
) -> dict:
    """One presign descriptor, in the shape presign actually accepts."""
    return {
        "service": _CLOUDSHELL_SERVICE,
        "region": region,
        "method": method,
        "protocol": "https:",
        "hostname": hostname,
        "path": path,
        "headers": {


            "host": hostname,
            **({"content-type": content_type} if content_type else {}),
            "x-amz-content-sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        },
        "body": body,
        "query": dict(query or {}),
    }


def _presign_headers(page: Any, identity: Optional[dict] = None) -> dict:
    """The headers a presign POST carries: the replayed console identity, the widget origin, and any `identity` override applied over the top."""
    headers = {
        "content-type": "application/json",
        "origin": _WIDGET_ORIGIN,
        "referer": f"{_WIDGET_ORIGIN}/",
        **_console_presign_headers(page),
    }
    for key, value in (identity or {}).items():
        if value is None:
            headers.pop(key, None)
        else:
            headers[key] = value
    return headers


def _presign(
    page: Any,
    region: str,
    descriptor: dict,
    timeout: int,
    *,
    identity: Optional[dict] = None,
) -> dict:
    """Ask presign to sign one descriptor. Returns `{status, text}`."""
    url = _presign_url(region)
    headers = _presign_headers(page, identity)
    try:
        response = page.context.request.post(
            url, headers=headers, data=json.dumps(descriptor), timeout=timeout * 1000
        )
        status, text = response.status, response.text()
        if status == 200:
            detail("[console-api] presigned via the API request context")
            return {"status": status, "text": text}
        detail(
            f"[console-api] presign via the API request context returned "
            f"HTTP {status}; falling back to the page"
        )
    except Exception as exc:
        if _handle_is_dead(exc):
            raise _dead_handle_error("presign", exc) from exc
        detail(f"[console-api] presign via the API request context failed: {exc}")

    context, context_name = _presign_context(page)
    detail(f"[console-api] presigning in {context_name}")
    try:
        return context.evaluate(
            _PRESIGN_JS,
            {


                "presignHeaders": {k: v for k, v in headers.items() if k != "content-type"},
                "presignUrl": url,
                "descriptor": descriptor,
            },
        )
    except Exception as exc:
        if _handle_is_dead(exc):
            raise _dead_handle_error("presign", exc) from exc
        raise


def _signed_headers(result: dict, operation: str, page: Any) -> dict:
    """The `headers` object out of a presign response, or a legible failure."""
    status = result.get("status")
    text = str(result.get("text") or "")
    if status != 200:
        replayed = sorted(_console_presign_headers(page))


        if replayed:
            observed = (
                f"we DID present an identity ({len(replayed)} replayed headers: "
                f"{replayed}) and presign refused it -- so the gate is the "
                f"REGION or the pairing, not a missing token. presign 401s for "
                f"a region whose console this session has never loaded."
            )
        else:
            observed = (
                "we presented NO identity at all -- the capture holds no "
                "presign from any console widget, so this is not a refusal of "
                "anything, it is a request that carried nothing to refuse. The "
                "CloudShell widget never presigns; the token comes only from "
                "the console chrome, on its own cadence."
            )
        error = CloudShellAutomationError(
            f"{operation}: presign refused to sign (HTTP {status}): {text[:400]}\n"
            f"  OBSERVED: {observed}\n"
            f"  presign is authorised by the console session cookie plus "
            f"`x-console-api-token`, replayed from the console's own requests "
            f"(captured this session: {replayed or 'NONE'}), so reconnecting "
            f"the node re-runs the login, which is the only thing that mints a "
            f"fresh one -- a new socket is signed by this same presign, so "
            f"retrying in place cannot change the answer.\n"
            f"  Note an IAM-shaped message here is not an IAM problem -- presign "
            f"answered 403 'explicit deny in an identity-based policy', with no "
            f"CloudTrail event, purely because the descriptor omitted `body`.",
            status_code=status if isinstance(status, int) else None,
        )


        error.cb_presign_status = status  # type: ignore[attr-defined]
        if status == 401:
            error.cb_failure_class = PRESIGN_REFUSED  # type: ignore[attr-defined]


            error.cb_presign_identity = (  # type: ignore[attr-defined]
                "replayed" if replayed else "none"
            )
        raise error
    try:
        signed = (json.loads(text) or {}).get("headers")
    except Exception:
        raise CloudShellAutomationError(
            f"{operation}: presign returned HTTP 200 but not JSON: {text[:200]}"
        ) from None
    if not isinstance(signed, dict) or not signed:
        raise CloudShellAutomationError(
            f"{operation}: presign returned no `headers` object: {text[:200]}"
        )
    return signed


def _credential_of(signed: dict) -> str:
    """Which credential presign signed with, from the `Credential=` scope."""
    auth = str(signed.get("authorization") or signed.get("Authorization") or "")
    m = re.search(r"Credential=([A-Z0-9]+)/([^,\s]*)", auth)
    if not m:
        return "credential=(unparsed)"
    key, scope = m.group(1), m.group(2)
    return f"key={key[:4]}***{key[-4:]} scope={scope}"


def _aws_error_code(text: str) -> Optional[str]:
    """The AWS error code out of a CloudShell error body, or None."""
    try:
        body = json.loads(text)
    except Exception:
        return None
    if not isinstance(body, dict):
        return None
    code = body.get("code") or body.get("Code") or body.get("__type")
    return str(code) if code else None


def _error_context(response: Any, payload: Optional[dict], text: str = "") -> str:
    """The identifiers needed to look a service-side failure up in CloudTrail."""
    parts = []
    error_type = ""
    try:
        headers = response.headers or {}
        lowered = {str(k).lower(): str(v) for k, v in dict(headers).items()}
        request_id = lowered.get("x-amzn-requestid") or lowered.get("x-amz-request-id")
        if request_id:
            parts.append(f"request_id={request_id}")
        error_type = lowered.get("x-amzn-errortype", "")
        if error_type:
            parts.append(f"error_type={error_type}")
    except Exception:
        pass
    if payload:
        parts.append(f"args={payload}")
    if not parts:
        return ""


    hint = ""
    if "Gateway Response mapping" in str(text or ""):
        hint = (
            "\n  An API Gateway 'mapping was applied' message hides the service's own"
            " error; the request id is what CloudTrail can be searched on."
        )
    if "UnrecognizedClient" in error_type:
        hint += (
            "\n  UnrecognizedClientException means the credential the signature "
            "was made with is not one CloudShell accepts -- an authentication "
            "problem, NOT the environment's state and not an IAM policy. Check the "
            "`scope=` on the presigned line above: presign appears to issue a "
            "credential per calling widget, and replaying another widget's "
            "`x-widget-id` (logged as WRONG WIDGET) is the leading suspect."
        )
    return "\n  " + " ".join(parts) + hint


def _post_signed(page: Any, url: str, headers: dict, body: str, timeout: int) -> Any:
    """Issue the signed CloudShell call through Playwright's APIRequestContext."""
    return page.context.request.post(url, headers=headers, data=body, timeout=timeout * 1000)


def call_cloudshell(
    page: Any,
    *,
    region: str,
    operation: str,
    payload: Optional[dict] = None,
    timeout: int = 30,
) -> dict:
    """Call one CloudShell control-plane operation as the console principal."""
    host = _cloudshell_host(region)
    path = f"/{operation.lstrip('/')}"


    body = json.dumps(payload or {})
    descriptor = build_presign_descriptor(
        region=region,
        method="POST",
        hostname=host,
        path=path,
        body=body,
    )


    result = _presign(page, region, descriptor, timeout)
    if not isinstance(result, dict):
        raise CloudShellAutomationError(
            f"{operation}: presign returned {type(result).__name__}, not a result"
        )
    signed = _signed_headers(result, operation, page)
    detail(
        f"[console-api] presigned {operation} signed_keys={sorted(signed)} "
        f"{_credential_of(signed)}"
    )


    headers = {"content-type": "application/json"}
    headers.update({k: v for k, v in signed.items() if str(k).lower() not in _CLIENT_SET_HEADERS})
    try:
        response = _post_signed(page, f"https://{host}{path}", headers, body, timeout)
        status = response.status
        text = response.text()
    except Exception as exc:
        if _handle_is_dead(exc):
            raise _dead_handle_error(operation, exc) from exc
        raise
    if status >= 400:


        raise CloudShellAutomationError(
            f"{operation} failed as the console principal (HTTP {status}): "
            f"{text[:400]}{_error_context(response, payload, text)}",
            status_code=status,
            error_code=_aws_error_code(text),
        )
    log(f"[console-api] {operation} region={region} status={status}")
    if not text.strip():
        return {}
    try:
        parsed = json.loads(text)
    except Exception:
        return {"raw": text}
    return parsed if isinstance(parsed, dict) else {"result": parsed}


class ConsoleCloudShellAPI:
    """A CloudShell control-plane client that signs through the console."""

    def __init__(
        self,
        page: Any,
        *,
        region: str,
        timeout: int = 30,
        refresh_page: Optional[Callable[[Any], Any]] = None,
    ) -> None:
        self.region = region
        self.timeout = timeout
        self._page = page


        self._refresh_page = refresh_page

    @property
    def page(self) -> Any:
        """The Playwright page this client signs through."""
        return self._page

    def _call(self, operation: str, payload: Optional[dict] = None) -> dict:
        return self._call_once(operation, payload, allow_page_refresh=True)

    def _call_once(
        self, operation: str, payload: Optional[dict], *, allow_page_refresh: bool
    ) -> dict:
        from cloudbasher.csp.aws.playwright_owner import run_owned


        detail(f"[console-api] {operation} region={self.region} " f"page=0x{id(self._page):x}")


        t0 = time.monotonic()
        error_for_timeline: Optional[str] = None
        try:
            return run_owned(
                self._page,
                call_cloudshell,
                self._page,
                region=self.region,
                operation=operation,
                payload=payload,
                timeout=self.timeout,
            )
        except Exception as exc:
            error_for_timeline = f"{type(exc).__name__}: {exc}"


            presign_status = getattr(exc, "cb_presign_status", None)
            if (
                allow_page_refresh
                and self._refresh_page is not None
                and presign_status in (401, 403)
            ):
                self._page = self._refresh_page(self._page)
                return self._call_once(operation, payload, allow_page_refresh=False)
            raise
        finally:


            record_call(
                operation,
                signing_path="console",
                region=self.region,
                duration_ms=(time.monotonic() - t0) * 1000,
                error=error_for_timeline,
            )

    def describe_environments(self) -> dict:
        body = self._call("describeEnvironments")
        return {
            "environments": body.get("Environments", []),
            "request_id": None,
        }

    def get_environment_status(self, environment_id: str) -> dict:
        body = self._call("getEnvironmentStatus", {"EnvironmentId": environment_id})
        return {"status": body.get("Status", "")}

    def create_environment(self) -> dict:
        body = self._call("createEnvironment")
        return {"environment_id": body.get("EnvironmentId", "")}

    def delete_environment(self, environment_id: str) -> dict:
        return self._call("deleteEnvironment", {"EnvironmentId": environment_id})

    def start_environment(self, environment_id: str) -> dict:
        return self._call("startEnvironment", {"EnvironmentId": environment_id})

    def stop_environment(self, environment_id: str) -> dict:
        return self._call("stopEnvironment", {"EnvironmentId": environment_id})

    def open_stream(
        self, environment_id: str, session_type: str = DEFAULT_SESSION_TYPE
    ) -> dict[str, Any]:
        """`/createSession` as the console principal -- the browser-derived identity path, which needs no PKCE exchange because the console login already carries a valid identity."""
        from cloudbasher.csp.aws.api import create_session_body

        payload = self._call("createSession", create_session_body(environment_id, session_type))
        stream_url = payload.get("StreamUrl", "")
        token_value = payload.get("TokenValue", "")
        if not stream_url or not token_value:
            raise CloudShellAutomationError(
                f"console createSession did not return StreamUrl/TokenValue: "
                f"keys={sorted(payload)}"
            )
        detail(
            f"[console-api] createSession session_type={session_type} "
            f"session_id={payload.get('SessionId', 'n/a')}"
        )
        return {
            "session_id": payload.get("SessionId"),
            "stream_url": stream_url,
            "token_value": token_value,
            "request_id": None,
            "session_type": session_type,
        }

    def delete_session(self, environment_id: str, session_id: str) -> bool:
        """Retire the console principal's session. Never raises -- see `api.delete_session`."""
        if not session_id or not environment_id:
            return False
        try:
            self._call(
                "deleteSession",
                {"EnvironmentId": environment_id, "SessionId": session_id},
            )
        except Exception as exc:
            detail(f"[console-api] deleteSession failed (ignored): {exc}")
            return False
        return True

    def send_heartbeat(self, environment_id: str) -> dict:
        """Available for the same reason as the rest -- so `send_env_heartbeat=False` for console credentials becomes a choice about the parked browser rather than a limitation."""
        return self._call("sendHeartBeat", {"EnvironmentId": environment_id})

    def _file_urls(self, operation: str, environment_id: str, file_path: str) -> dict:
        """Shared tail of getFileUploadUrls / getFileDownloadUrls."""
        body = self._call(
            operation,
            {
                "EnvironmentId": environment_id,
                **{
                    (
                        "FileUploadPath" if operation == "getFileUploadUrls" else "FileDownloadPath"
                    ): file_path
                },
            },
        )
        return {
            "upload_url": body.get("FileUploadPresignedUrl", ""),
            "upload_fields": body.get("FileUploadPresignedFields", {}),
            "download_url": body.get("FileDownloadPresignedUrl", ""),
            "download_key": body.get("FileDownloadPresignedKey", ""),
            "download_key_hash": body.get("FileDownloadPresignedKeyHash", ""),
            "request_id": None,
        }

    def get_file_upload_urls(self, environment_id: str, file_path: str) -> dict:
        """File transfer as the console principal."""
        return self._file_urls("getFileUploadUrls", environment_id, file_path)

    def get_file_download_urls(self, environment_id: str, file_path: str) -> dict:
        """See get_file_upload_urls(). Same response shape, different request field (`FileDownloadPath`)."""
        return self._file_urls("getFileDownloadUrls", environment_id, file_path)


    def put_credentials(self, env_id: str, creds: dict) -> dict:
        raise CloudShellAutomationError(
            "putCredentials is not called on the console path -- the console's "
            "own JavaScript issues it while the widget loads, so the container "
            "already has its credentials. Reaching this means a caller assumed "
            "the Path A projection step."
        )

    def get_session_creds(self) -> Any:
        """There are none, and that is the point."""
        raise CloudShellAutomationError(
            "a console-signed API client has no credentials -- it signs each "
            "request through /api/prod/presign using the browser's console "
            "session. See csp/aws/console_api.py."
        )
