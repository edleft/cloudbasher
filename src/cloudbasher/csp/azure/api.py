"""Azure CloudShell REST API — ARM control plane + console HTTP endpoints."""

from __future__ import annotations

import json
import hashlib
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError, CredentialError
from cloudbasher.core.types import Credentials
from cloudbasher.core.utils.output import detail
from cloudbasher.csp.azure.types import (
    ConsoleDelete,
    ConsoleInfo,
    ConsoleWrite,
    TerminalInfo,
    parse_console_id_from_uri,
    parse_region_from_uri,
)
from cloudbasher.csp.base import CloudShellAPI


_CONSOLE_API_VERSION = "2023-02-01-preview"
_RESOURCE_GROUP_API_VERSION = "2021-04-01"
_STORAGE_API_VERSION = "2022-09-01"
_STORAGE_PROVIDER_API_VERSION = "2018-07-01"
_ARM_BASE = "https://management.azure.com"
_USER_SETTINGS_NOT_FOUND = "UserSettingsNotFound"
_CONSOLE_PUT_RETRY_DELAYS = (0.2, 0.5, 1.0)


def _arm_error_fields(body: str) -> tuple[Optional[str], Optional[str]]:
    """Extract Azure's stable error code and message without guessing from text."""
    try:
        data = json.loads(body)
    except (TypeError, ValueError):
        return None, None
    if not isinstance(data, dict):
        return None, None
    error = data.get("error", data)
    if not isinstance(error, dict):
        return None, None
    code = error.get("code")
    message = error.get("message")
    return (
        str(code) if isinstance(code, (str, int)) and str(code) else None,
        str(message) if isinstance(message, str) and message else None,
    )


def _header(headers: Any, *names: str) -> Optional[str]:
    """Read a response header case-insensitively, keeping only its value."""
    if headers is None:
        return None
    for name in names:
        try:
            value = headers.get(name)
        except AttributeError:
            value = None
        if value:
            return str(value)
    return None


def _arm_error_diagnostic(
    error_code: Optional[str],
    response_message: Optional[str],
    request_id: Optional[str],
    correlation_id: Optional[str],
) -> str:
    """Format Azure's structured failure metadata for the user-visible error."""
    fields = []
    if error_code:
        fields.append(f"code={error_code}")
    if response_message:
        fields.append(f"message={response_message}")
    if request_id:
        fields.append(f"request_id={request_id}")
    if correlation_id:
        fields.append(f"correlation_id={correlation_id}")
    return f" [Azure {'; '.join(fields)}]" if fields else ""


class AzureCloudShellAPI(CloudShellAPI):
    """Azure CloudShell REST API client."""

    def __init__(
        self,
        credentials: Credentials,
        *,
        timeout: int = 30,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
        token_refresher: Optional[Callable[[Credentials], Credentials]] = None,
        audience_token_provider: Optional[Callable[[Credentials, str], str]] = None,
    ) -> None:
        self.credentials = credentials
        self.timeout = timeout
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure
        self._token_refresher = token_refresher
        self._audience_token_provider = audience_token_provider
        self._opener = self._build_opener()


    def describe_environments(self) -> dict[str, Any]:
        """Return current console info (+ user settings) as a unified dict."""
        result: dict[str, Any] = {}
        try:
            settings = self.get_user_settings()
            result["user_settings"] = settings
        except CloudShellAutomationError:
            pass


        return result

    def create_environment(self) -> dict[str, Any]:
        """Provision the default console (Linux) and return its summary dict."""
        return self.provision_console(os_type="Linux").console.summary_dict()


    def get_user_settings(self) -> dict[str, Any]:
        """GET user settings (preferred region, OS, shell, storage)."""
        url = self._arm_url("/providers/Microsoft.Portal/userSettings/cloudconsole")
        return self._get(url)

    def list_subscriptions(self) -> dict[str, Any]:
        """Read the signed-in user's ARM subscriptions without provisioning."""
        return self._get(self._arm_url("/subscriptions", api_version="2022-12-01"))

    def put_resource_group(
        self, subscription_id: str, resource_group: str, *, location: str
    ) -> dict[str, Any]:
        path = (
            f"/subscriptions/{urllib.parse.quote(subscription_id, safe='')}"
            f"/resourceGroups/{urllib.parse.quote(resource_group, safe='')}"
        )
        return self._put(
            self._arm_url(path, api_version=_RESOURCE_GROUP_API_VERSION),
            {"location": location},
        )

    def get_storage_account(
        self, subscription_id: str, resource_group: str, account_name: str
    ) -> dict[str, Any]:
        path = (
            f"/subscriptions/{urllib.parse.quote(subscription_id, safe='')}"
            f"/resourceGroups/{urllib.parse.quote(resource_group, safe='')}"
            f"/providers/Microsoft.Storage/storageAccounts/"
            f"{urllib.parse.quote(account_name, safe='')}"
        )
        return self._get(self._arm_url(path, api_version=_STORAGE_API_VERSION))

    def put_storage_account(
        self,
        subscription_id: str,
        resource_group: str,
        account_name: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        path = (
            f"/subscriptions/{urllib.parse.quote(subscription_id, safe='')}"
            f"/resourceGroups/{urllib.parse.quote(resource_group, safe='')}"
            f"/providers/Microsoft.Storage/storageAccounts/"
            f"{urllib.parse.quote(account_name, safe='')}"
        )
        return self._put(self._arm_url(path, api_version=_STORAGE_API_VERSION), body)

    def get_storage_provider_state(self, subscription_id: str) -> dict[str, Any]:
        path = (
            f"/subscriptions/{urllib.parse.quote(subscription_id, safe='')}"
            "/providers/Microsoft.Storage"
        )
        return self._get(self._arm_url(path, api_version=_STORAGE_PROVIDER_API_VERSION))

    def register_storage_provider(self, subscription_id: str) -> dict[str, Any]:
        path = (
            f"/subscriptions/{urllib.parse.quote(subscription_id, safe='')}"
            "/providers/Microsoft.Storage/register"
        )
        result = self._request(
            "POST", self._arm_url(path, api_version=_STORAGE_PROVIDER_API_VERSION)
        )
        return result if isinstance(result, dict) else {}

    def put_user_settings(self, settings: dict[str, Any]) -> dict[str, Any]:
        """PUT user settings."""
        url = self._arm_url("/providers/Microsoft.Portal/userSettings/cloudconsole")
        return self._put(url, settings)

    def delete_user_settings(self) -> int:
        """DELETE Azure Cloud Shell user settings as part of an explicit reset."""
        url = self._arm_url("/providers/Microsoft.Portal/userSettings/cloudconsole")
        return self._request_status("DELETE", url, expect_body=False)[0]


    def read_console_probe(self) -> int:
        """`GET consoles/default` for its STATUS CODE. Expect 404, always."""
        url = self._arm_url("/providers/Microsoft.Portal/consoles/default")
        try:
            return self._request_status("GET", url)[0]
        except CloudShellAutomationError as exc:
            if exc.status_code is None:
                raise
            return exc.status_code

    def provision_console(self, *, os_type: str = "Linux") -> ConsoleWrite:
        """PUT the default console. `201` created it, `200` updated an existing one."""
        url = self._arm_url("/providers/Microsoft.Portal/consoles/default")
        body = {"properties": {"osType": os_type}}
        for attempt, delay in enumerate((*_CONSOLE_PUT_RETRY_DELAYS, None)):
            try:
                status, data = self._request_status("PUT", url, body=body)
                return ConsoleWrite(status, _console_from_response(data))
            except CloudShellAutomationError as exc:
                if (
                    exc.status_code != 404
                    or exc.error_code != _USER_SETTINGS_NOT_FOUND
                    or delay is None
                ):
                    raise
                detail(
                    "Azure console PUT returned exact UserSettingsNotFound; "
                    f"retrying ({attempt + 1}/{len(_CONSOLE_PUT_RETRY_DELAYS)}) "
                    f"after {delay:.1f}s without resetting user settings."
                )
                time.sleep(delay)
        raise AssertionError("bounded console PUT retry loop exhausted unexpectedly")

    def delete_console(self) -> ConsoleDelete:
        """DELETE the default console. `200` destroyed one, `204` found none."""
        url = self._arm_url("/providers/Microsoft.Portal/consoles/default")
        return ConsoleDelete(self._request_status("DELETE", url, expect_body=False)[0])

    def wait_console_ready(self, *, timeout: int = 120) -> ConsoleInfo:
        """Re-PUT until provisioningState == Succeeded."""
        deadline = time.monotonic() + timeout
        poll_interval = 3.0
        while True:
            written = self.provision_console()
            state = written.console.provisioning_state
            detail(
                f"Console {written.console.console_id} provisioningState={state} "
                f"(PUT {written.status})"
            )
            if state == "Succeeded":
                return written.console
            if state in ("Failed", "Canceled"):
                raise CloudShellAutomationError(f"Console provisioning failed: state={state}")
            if time.monotonic() + poll_interval >= deadline:
                raise CloudShellAutomationError(
                    f"Console did not reach Succeeded state within {timeout}s "
                    f"(last state={state})."
                )
            time.sleep(poll_interval)


    def get_console_auth_token(self, console: ConsoleInfo) -> str:
        """POST /authorize on the Service Bus relay → opaque auth-token for WebSocket."""
        url = self._console_url(console, "/authorize")
        data = self._post_console(url, body={})
        token = data.get("token", "")
        if not token:
            raise CloudShellAutomationError(f"authorize endpoint returned no token: {data}")
        return token

    def create_terminal(
        self,
        console: ConsoleInfo,
        *,
        cols: int = 220,
        rows: int = 50,
        shell: str = "bash",
    ) -> TerminalInfo:
        """POST to create a new terminal session on the console."""
        url = self._console_url(
            console,
            "/terminals",
            extra_params={
                "cols": str(cols),
                "rows": str(rows),
                "version": "2019-01-01",
                "shell": shell,
            },
        )
        data = self._post_console(url, body={})
        return _terminal_from_response(data, shell=shell)

    def resize_terminal(
        self,
        console: ConsoleInfo,
        terminal: TerminalInfo,
        cols: int,
        rows: int,
    ) -> None:
        """POST to resize an existing terminal."""
        url = self._console_url(
            console,
            f"/terminals/{terminal.terminal_id}/size",
            extra_params={
                "cols": str(cols),
                "rows": str(rows),
                "version": "2019-01-01",
            },
        )
        self._post_console(url, body={})

    def send_keepalive(self, console: ConsoleInfo) -> None:
        """POST keepAlive to prevent the 20-minute console idle timeout."""


        self._post_console(self._console_url(console, "/keepAlive"), body={})


    def upload_file(
        self,
        console: ConsoleInfo,
        terminal: TerminalInfo,
        local_path: str,
        remote_path: str,
    ) -> dict[str, Any]:
        """Upload a file to CloudShell via multipart POST."""
        url = self._console_url(console, f"/terminals/{terminal.terminal_id}/upload")
        with open(local_path, "rb") as fh:
            file_bytes = fh.read()

        filename = os.path.basename(local_path)
        boundary = "----AzureCloudShellBoundary7E4A9F2B"
        body = (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="uploading-file"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + file_bytes
            + f"\r\n--{boundary}--\r\n".encode()
        )

        headers = {
            "Authorization": f"Bearer {self.credentials.access_token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Referer": "https://portal.azure.com/",
        }
        return self._raw_post(url, body=body, extra_headers=headers)

    def request_download(
        self,
        console: ConsoleInfo,
        terminal: TerminalInfo,
        remote_path: str,
    ) -> dict[str, Any]:
        """Step 1 of 3: ask the service to prepare `remote_path`."""
        url = self._console_url(console, f"/terminals/{terminal.terminal_id}/download")
        return self._post_console(url, body={"filename": remote_path})

    def satisfy_token_request(self, console: ConsoleInfo, audience: str) -> None:
        """Acquire one supported delegated token and hand it to Cloud Shell."""
        if self._audience_token_provider is None:
            error = CredentialError(
                "This Azure credential cannot mint delegated tokens for Cloud Shell requests."
            )
            error.safe_diagnostic = "audience_token_provider_unavailable"
            raise error
        try:
            token = self._audience_token_provider(self.credentials, audience)
        except CredentialError as exc:


            if not getattr(exc, "safe_diagnostic", None):
                exc.safe_diagnostic = "audience_token_acquisition_failed"
            raise
        url = self._console_url(console, "/accessToken")
        try:
            self._post_console(url, body={"token": token})
        except CredentialError as exc:
            error = CredentialError("Azure access-token handoff authentication failed.")
            error.safe_diagnostic = "access_token_handoff_auth_failed"
            raise error from exc

    def resolve_download_uri(self, console: ConsoleInfo, file_uri: str) -> str:
        """`/downloads/{32-hex}` is console-relative; anything absolute is used as-is."""
        if file_uri.startswith("/"):
            return console.uri.rstrip("/") + file_uri
        return file_uri

    def fetch_download(self, console: ConsoleInfo, file_uri: str, local_path: str) -> int:
        """Step 3 of 3: fetch the bytes and write them. Returns the size."""
        raw = self._get_bytes(self.resolve_download_uri(console, file_uri))
        os.makedirs(os.path.dirname(os.path.abspath(local_path)), exist_ok=True)
        with open(local_path, "wb") as fh:
            fh.write(raw)
        return len(raw)

    def download_file(
        self,
        console: ConsoleInfo,
        terminal: TerminalInfo,
        remote_path: str,
        local_path: str,
    ) -> None:
        """Download WITHOUT a session -- works only if the service returns a body."""
        resp = self.request_download(console, terminal, remote_path)
        file_uri = resp.get("fileUri") or resp.get("uri") or resp.get("downloadUri")
        if not file_uri:
            raise CloudShellAutomationError(
                "download prepared but no fileUri in the response body -- expected, and not a "
                "failure of this call. POST /download returns 200 with an empty body by design "
                '(AZ-OBS-161); the id arrives as an `audience: "download"` frame on the '
                "terminal WebSocket (AZ-OBS-162), which this API object cannot see. Use "
                "AzureSession.download_file(), which owns the socket."
            )
        size = self.fetch_download(console, file_uri, local_path)
        detail(f"Downloaded {remote_path} → {local_path} ({size} bytes)")

    def list_directory(
        self,
        console: ConsoleInfo,
        terminal: TerminalInfo,
        remote_path: str,
    ) -> list[dict[str, Any]]:
        """GET /files/{path} — list directory contents."""
        encoded = urllib.parse.quote(remote_path.lstrip("/"), safe="/")
        url = self._console_url(console, f"/files/{encoded}")
        try:
            data = self._get_console(url)
        except CloudShellAutomationError as exc:
            if "404" in str(exc):
                return []
            raise
        if isinstance(data, list):
            return data
        return data.get("files", data.get("items", []))


    def _arm_url(self, path: str, *, api_version: str = _CONSOLE_API_VERSION) -> str:
        qs = urllib.parse.urlencode({"api-version": api_version})
        return f"{_ARM_BASE}{path}?{qs}"

    def _console_url(
        self,
        console: ConsoleInfo,
        path: str,
        extra_params: Optional[dict[str, str]] = None,
    ) -> str:
        base = console.uri.rstrip("/")
        params = extra_params or {}
        if params:
            qs = urllib.parse.urlencode(params)
            return f"{base}{path}?{qs}"
        return f"{base}{path}"


    def _bearer_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.credentials.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _console_headers(self) -> dict[str, str]:
        """Headers for console HTTP API (Service Bus relay)."""
        headers = self._bearer_headers()
        headers["Referer"] = "https://portal.azure.com/"
        return headers

    def _build_opener(self) -> urllib.request.OpenerDirector:
        handlers: list[Any] = []
        if self.proxy_url:
            handlers.append(
                urllib.request.ProxyHandler({"https": self.proxy_url, "http": self.proxy_url})
            )
        if self.proxy_insecure and self.proxy_url:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        return urllib.request.build_opener(*handlers)

    def _get(self, url: str) -> dict[str, Any]:
        return self._request("GET", url)

    def _put(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", url, body=body)

    def _delete(self, url: str) -> None:
        self._request("DELETE", url, expect_body=False)

    def _get_console(self, url: str) -> Any:
        return self._request_console("GET", url)

    def _post_console(self, url: str, body: Optional[Any]) -> Any:
        return self._request_console("POST", url, body=body)

    def _get_bytes(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers=self._console_headers())
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise CloudShellAutomationError(
                f"HTTP {exc.code} downloading from {url}: {exc.reason}"
            ) from exc

    def _static_token_refusal_hint(self) -> str:
        """Return the actionable suffix for a 401 with no refresh capability."""
        if self._token_refresher is not None:
            return ""
        return (
            " This credential cannot refresh automatically; it may be expired, "
            "revoked, or rejected by Azure. Replace it with a fresh delegated "
            "ARM access token."
        )

    def _raw_post(
        self,
        url: str,
        body: bytes,
        extra_headers: dict[str, str],
    ) -> dict[str, Any]:
        req = urllib.request.Request(url, data=body, headers=extra_headers, method="POST")
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode(errors="replace")
            raise CloudShellAutomationError(
                f"HTTP {exc.code} POST {url}: {exc.reason} — {body_text[:200]}"
            ) from exc

    def _request(
        self,
        method: str,
        url: str,
        body: Optional[dict[str, Any]] = None,
        expect_body: bool = True,
    ) -> Any:
        """Body-only view of `_request_status`, for callers the code cannot help."""
        return self._request_status(method, url, body=body, expect_body=expect_body)[1]

    def _request_status(
        self,
        method: str,
        url: str,
        body: Optional[dict[str, Any]] = None,
        expect_body: bool = True,
    ) -> tuple[int, Any]:
        """ARM request returning `(status, parsed_body)`."""
        headers = self._bearer_headers()
        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        def _read(resp: Any, token: Optional[str]) -> tuple[int, Any]:
            raw = resp.read()
            status = int(resp.status)
            if 200 <= status < 300 and token:


                self.credentials._azure_validated_arm_token = {
                    "fingerprint": hashlib.sha256(token.encode("utf-8")).hexdigest()
                }
            if not raw or not expect_body:
                return status, {}
            return status, json.loads(raw)

        token_used = self.credentials.access_token
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return _read(resp, token_used)
        except urllib.error.HTTPError as exc:

            if exc.code == 401 and self._token_refresher is not None:
                try:
                    self.refresh_credentials()
                    headers2 = self._bearer_headers()
                    req2 = urllib.request.Request(url, data=data, headers=headers2, method=method)
                    with self._opener.open(req2, timeout=self.timeout) as resp2:
                        return _read(resp2, self.credentials.access_token)
                except urllib.error.HTTPError as exc2:
                    body_text = exc2.read().decode(errors="replace")
                    error_code, response_message = _arm_error_fields(body_text)
                    request_id = _header(exc2.headers, "x-ms-request-id", "request-id")
                    correlation_id = _header(
                        exc2.headers,
                        "x-ms-correlation-request-id",
                        "x-ms-client-request-id",
                    )
                    diagnostic = _arm_error_diagnostic(
                        error_code, response_message, request_id, correlation_id
                    )
                    raise CloudShellAutomationError(
                        f"HTTP {exc2.code} {method} {url} (after token refresh): "
                        f"{exc2.reason} — {body_text[:300]}"
                        f"{diagnostic}",
                        status_code=exc2.code,
                        error_code=error_code,
                        response_body=body_text,
                        response_message=response_message,
                        request_id=request_id,
                        correlation_id=correlation_id,
                    ) from exc2
                except Exception as exc2:
                    raise CredentialError(f"Token refresh failed: {exc2}") from exc2
            body_text = exc.read().decode(errors="replace")
            error_code, response_message = _arm_error_fields(body_text)
            request_id = _header(exc.headers, "x-ms-request-id", "request-id")
            correlation_id = _header(
                exc.headers,
                "x-ms-correlation-request-id",
                "x-ms-client-request-id",
            )
            raise CloudShellAutomationError(
                f"HTTP {exc.code} {method} {url}: {exc.reason} — {body_text[:300]}"
                f"{_arm_error_diagnostic(error_code, response_message, request_id, correlation_id)}"
                f"{self._static_token_refusal_hint()}",
                status_code=exc.code,
                error_code=error_code,
                response_body=body_text,
                response_message=response_message,
                request_id=request_id,
                correlation_id=correlation_id,
            ) from exc
        except urllib.error.URLError as exc:
            raise CloudShellAutomationError(f"Network error {method} {url}: {exc.reason}") from exc

    def refresh_credentials(self) -> None:
        """Re-mint the bearer NOW, instead of waiting for a 401 to force it."""
        if self._token_refresher is not None:
            current = self.credentials
            refreshed = self._token_refresher(current)
            if refreshed is not current:
                current.access_token = refreshed.access_token
                current.session_id = refreshed.session_id
                current.email = refreshed.email
                current.extra = refreshed.extra
                rotated = (current.extra or {}).get("refresh_token")
                callback = getattr(current, "_runtime_refresh_token_callback", None)
                if rotated and callable(callback):
                    callback(rotated)
            self.credentials = current

    def _request_console(
        self,
        method: str,
        url: str,
        body: Optional[Any] = None,
    ) -> Any:
        """Like _request but for console HTTP API (Service Bus relay)."""
        headers = self._console_headers()
        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                if not raw:
                    return {}
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode(errors="replace")


            raise CloudShellAutomationError(
                f"HTTP {exc.code} {method} {url}: {exc.reason} — {body_text[:300]}",
                status_code=exc.code,
                response_body=body_text,
            ) from exc
        except urllib.error.URLError as exc:
            raise CloudShellAutomationError(f"Network error {method} {url}: {exc.reason}") from exc

    def update_creds(self, new_creds: Credentials) -> None:
        """Hot-swap credentials (e.g. after token refresh)."""
        self.credentials = new_creds


def _console_from_response(data: dict[str, Any]) -> ConsoleInfo:
    props = data.get("properties", data)
    uri = props.get("uri", "")
    console_id = parse_console_id_from_uri(uri) if uri else data.get("name", "unknown")


    region = parse_region_from_uri(uri) or props.get("location") or "unknown"
    return ConsoleInfo(
        console_id=console_id,
        uri=uri,
        provisioning_state=props.get("provisioningState", "Unknown"),
        os_type=props.get("osType", "Linux"),
        region=region,
    )


def _terminal_from_response(data: dict[str, Any], shell: str = "bash") -> TerminalInfo:
    socket_uri = data.get("socketUri", data.get("uri", ""))


    if socket_uri and "portal.azure.com" in socket_uri:
        socket_uri = socket_uri.replace("portal.azure.com", "ux.console.azure.com")
    return TerminalInfo(
        terminal_id=data.get("id", data.get("terminalId", "")),
        socket_uri=socket_uri,
        idle_timeout=int(data.get("idleTimeout", 20)),
        root_directory=data.get("rootDirectory", "/home"),
        shell=shell,
    )
