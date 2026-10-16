"""Playwright-based browser login for GCP CloudShell private API path."""

from __future__ import annotations

import base64
import importlib
import json
import os
import queue
import string
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from cloudbasher.core.browser_profile import context_kwargs as _context_kwargs
from cloudbasher.core.browser_profile import launch_args as _launch_args
from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.utils.output import log, out, out_ts


_sync_playwright: Any = None
_PlaywrightTimeoutError: Any = Exception
_PLAYWRIGHT_IMPORT_ERROR: Optional[Exception] = None
_PLAYWRIGHT_SHADOW_PATH: Optional[Path] = None


def _load_playwright() -> None:
    """Resolve playwright lazily; record the failure mode for diagnostics."""
    global _sync_playwright, _PlaywrightTimeoutError
    global _PLAYWRIGHT_IMPORT_ERROR, _PLAYWRIGHT_SHADOW_PATH
    if _sync_playwright is not None:
        return
    try:
        sync_api = importlib.import_module("playwright.sync_api")
        _sync_playwright = getattr(sync_api, "sync_playwright")
        _PlaywrightTimeoutError = getattr(sync_api, "TimeoutError", Exception)
        return
    except Exception as exc:
        _PLAYWRIGHT_IMPORT_ERROR = exc


    cwd = Path.cwd()
    for shadow in [cwd / "playwright.py", cwd / "playwright"]:
        if shadow.exists():
            _PLAYWRIGHT_SHADOW_PATH = shadow
            break


def ensure_playwright_available() -> None:
    """Raise CloudShellAutomationError if playwright is not installed/usable."""
    _load_playwright()
    if _sync_playwright is not None:
        return
    install_hint = "Install with: pip install playwright && playwright install chromium"
    if _PLAYWRIGHT_SHADOW_PATH is not None:
        raise CloudShellAutomationError(
            f"Playwright shadowed by local file: {_PLAYWRIGHT_SHADOW_PATH}. "
            f"Rename or remove it. {install_hint}"
        )
    if _PLAYWRIGHT_IMPORT_ERROR is not None:
        raise CloudShellAutomationError(
            f"Playwright import failed: {_PLAYWRIGHT_IMPORT_ERROR}. {install_hint}"
        )
    raise CloudShellAutomationError(f"Playwright is not installed. {install_hint}")


_GOOGLE_COOKIE_NAMES = frozenset(
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
        "__Secure-1PSIDCC",
        "__Secure-3PSIDCC",
        "__Secure-1PSIDTS",
        "__Secure-3PSIDTS",
    }
)


def extract_google_cookies(context: Any, *, log_result: bool = True) -> dict[str, str]:
    """Extract Google session cookies from a Playwright BrowserContext."""
    cookies_list = context.cookies()
    result: dict[str, str] = {}
    for c in cookies_list:
        name = c.get("name", "")
        domain = c.get("domain", "")
        if name in _GOOGLE_COOKIE_NAMES or ".google.com" in domain:
            result[name] = c.get("value", "")
    if log_result:
        log(f"[gcp.playwright] extracted {len(result)} Google cookies from browser context")
    return result


_DEFAULT_TARGET_URL = "https://shell.cloud.google.com/?show=terminal"


def native_console_project_url(project_id: str) -> str:
    """Open the native Console with the explicitly selected project."""
    project_id = project_id.strip()
    allowed = string.ascii_letters + string.digits + "-_:"
    if not project_id or any(ch not in allowed for ch in project_id):
        raise ValueError("GCP project context must be a non-empty project identifier")
    return "https://console.cloud.google.com/welcome?" + urllib.parse.urlencode(
        {"project": project_id}
    )


_CLOUDSHELL_LAUNCH_SELECTORS = (
    'button[aria-label="Activate Cloud Shell"]',
    'button[aria-label*="Cloud Shell" i]',
    '[data-tooltip*="Activate Cloud Shell" i]',
    'button[title*="Cloud Shell" i]',
    'button:has-text("Activate Cloud Shell")',
)


def _open_native_cloudshell(
    page: Any,
    context: Any,
    diagnostics_dir: Path,
    network_capture: _PrivateBrowserNetworkCapture,
) -> Any:
    """Click Cloud Console's own launch control and return its shell page/frame."""
    from cloudbasher.csp.gcp.diagnostics import append_private_jsonl, write_private

    def checkpoint(label: str) -> None:
        try:
            write_private(
                diagnostics_dir,
                f"native-launch-{label}.png",
                page.screenshot(full_page=False, timeout=10_000),
            )
        except Exception as exc:
            append_private_jsonl(
                diagnostics_dir,
                "browser-bootstrap-errors.jsonl",
                {
                    "stage": f"screenshot-{label}",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )

    def shell_target() -> Any:
        for candidate_page in reversed(list(context.pages)):
            try:
                host = urllib.parse.urlsplit(candidate_page.url).hostname
                if host == "shell.cloud.google.com":
                    return candidate_page
                for frame in candidate_page.frames:
                    if urllib.parse.urlsplit(frame.url).hostname == "shell.cloud.google.com":
                        return frame
            except Exception:
                continue
        return None

    append_private_jsonl(
        diagnostics_dir,
        "browser-navigation.jsonl",
        {"stage": "before-native-cloudshell-launch", "url": page.url},
    )
    checkpoint("before-shell-launch")
    selected: Optional[tuple[str, Any]] = None
    for selector in _CLOUDSHELL_LAUNCH_SELECTORS:
        visible = False
        try:
            locator = page.locator(selector).first
            visible = locator.is_visible()
            if visible:
                selected = (selector, locator)
        except Exception as exc:
            append_private_jsonl(
                diagnostics_dir,
                "browser-selectors.jsonl",
                {
                    "stage": "cloudshell-launch",
                    "selector": selector,
                    "visible": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
            )
        if visible:
            append_private_jsonl(
                diagnostics_dir,
                "browser-selectors.jsonl",
                {"stage": "cloudshell-launch", "selector": selector, "visible": True},
            )
            break
    if selected is None:
        raise CloudShellAutomationError(
            "Signed-in Google Cloud Console did not expose its Activate Cloud Shell control. "
            "The page snapshot and selector diagnostics are in the private GCP capture."
        )

    try:
        selected[1].click(timeout=10_000)
        append_private_jsonl(
            diagnostics_dir,
            "browser-selectors.jsonl",
            {"stage": "cloudshell-launch", "selector": selected[0], "clicked": True},
        )
    except Exception as exc:
        append_private_jsonl(
            diagnostics_dir,
            "browser-selectors.jsonl",
            {
                "stage": "cloudshell-launch",
                "selector": selected[0],
                "clicked": False,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )
        raise CloudShellAutomationError(
            f"Cloud Console's Cloud Shell launch control failed ({type(exc).__name__})."
        ) from exc

    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            page.wait_for_timeout(250)
        except Exception:
            pass
        network_capture.drain()
        if network_capture.native_setupsession_error:
            raise CloudShellAutomationError(
                "Native Cloud Shell setupsession could not be safely captured/replayed; "
                "see private browser-bootstrap diagnostics."
            )
        target = shell_target()
        native_session_ready = (
            network_capture._setupsession_public_key is None
            or network_capture.native_setupsession_response is not None
        )
        if target is not None and native_session_ready:
            checkpoint("after-shell-launch")
            append_private_jsonl(
                diagnostics_dir,
                "browser-navigation.jsonl",
                {
                    "stage": "native-cloudshell-launched",
                    "url": str(target.url),
                    "target_type": type(target).__name__,
                },
            )
            return target
    checkpoint("shell-launch-timeout")
    raise CloudShellAutomationError(
        "Cloud Console accepted the Cloud Shell launch click, but no shell.cloud.google.com "
        "page/frame and native setupsession response did not appear within 45 seconds. "
        "See private browser navigation "
        "and network artifacts."
    )


class _VisibleVerificationRetry(Exception):
    """Headless reached a login/security stage that needs visible user input."""

    def __init__(self, stage: str):
        super().__init__(stage)
        self.stage = stage


def _retry_visibly_if_headless(headless: bool, stage: str) -> None:
    """Turn a missing login control into one user-visible fallback attempt."""
    if headless:
        raise _VisibleVerificationRetry(stage)


def _visible_retry_options(prefill_email: Optional[str]) -> dict[str, Any]:
    """Restart visibly at the ordinary sign-in page without replaying password."""
    return {
        "headless": False,
        "prefill_email": prefill_email,
        "password": None,
        "capture_login_screenshots": True,
    }


def _run_visible_retry_owner(
    *,
    target_url: str,
    proxy_url: Optional[str],
    proxy_insecure: bool,
    timeout_seconds: int,
    wait_mode: str,
    poll_interval_seconds: float,
    prefill_email: Optional[str],
    project_id: Optional[str] = None,
    setupsession_public_key: Optional[str] = None,
    oauth_token_callback: Optional[Callable[[dict[str, Any]], None]],
    oauth_request_callback: Optional[Callable[[], None]],
    xsrf_token_callback: Optional[Callable[[str], None]],
    diagnostics_dir: Path,
    result: dict[str, Any],
    ready: threading.Event,
) -> None:
    """Own the visible retry on a fresh thread after the headless driver exits."""
    try:
        session = playwright_login_for_cookies(
            target_url=target_url,
            project_id=project_id,
            setupsession_public_key=setupsession_public_key,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
            timeout_seconds=timeout_seconds,
            wait_mode=wait_mode,
            poll_interval_seconds=poll_interval_seconds,
            oauth_token_callback=oauth_token_callback,
            oauth_request_callback=oauth_request_callback,
            xsrf_token_callback=xsrf_token_callback,
            keep_browser_open=True,
            _owner_worker=True,
            _diagnostics_dir=diagnostics_dir,
            **_visible_retry_options(prefill_email),
        )
        result["session"] = session
        ready.set()
        session.serve_requests()
    except BaseException as exc:
        result["error"] = exc
        ready.set()


_SIGNED_IN_SENTINELS = ("SID", "__Secure-1PSID")
_CLOUDSHELL_OAUTH_CLIENT_ID = (
    "618104708054-9r9s1c4alg36erliucho9t52n32n6dgq.apps.googleusercontent.com"
)
_CLOUDSHELL_OAUTH_SCOPES = " ".join(
    (
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/drive",
    )
)
OAUTH_TOKEN_ISSUE_TIMEOUT_MS = 15_000

_EMAIL_SELECTORS = (
    'input[type="email"]',
    "input#identifierId",
    'input[name="identifier"]',
    'input[autocomplete="username"]',
)
_PASSWORD_SELECTORS = (
    'input[type="password"]',
    'input[name="Passwd"]',
    'input[autocomplete="current-password"]',
)


def _frame_scopes(page: Any) -> list[Any]:
    """Search the top-level document and embedded account/login frames."""
    try:
        frames = list(page.frames)
    except Exception:
        frames = []
    return frames or [page]


def _visible_control(
    page: Any,
    selectors: tuple[str, ...],
    *,
    on_selector: Optional[Callable[[str, bool], None]] = None,
) -> tuple[Any, Any] | None:
    """Return (frame, locator) for the first visible matching control."""
    for frame in _frame_scopes(page):
        for selector in selectors:
            try:
                locator = frame.locator(selector).first
                if on_selector:
                    on_selector(selector, False)
                visible = locator.is_visible()
                if on_selector:
                    on_selector(selector, True)
                if visible:
                    return frame, locator
            except Exception:
                continue
    return None


def _wait_for_control(
    page: Any,
    selectors: tuple[str, ...],
    timeout_seconds: float,
    *,
    on_selector: Optional[Callable[[str, bool], None]] = None,
) -> tuple[Any, Any] | None:
    deadline = time.monotonic() + timeout_seconds
    while True:
        found = _visible_control(page, selectors, on_selector=on_selector)


        on_selector = None
        if found:
            return found
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(0.2, remaining))


def _login_debug_dir() -> Path:
    """Create a private, persistent directory for headed-login screenshots."""
    path = Path(tempfile.mkdtemp(prefix="cloudbasher-gcp-login-"))
    os.chmod(path, 0o700)
    return path


def _click_account_switch(
    page: Any,
    *,
    on_selector: Optional[Callable[[str, bool], None]] = None,
) -> bool:
    """Select Google's ordinary 'use/add another account' control if shown."""
    selectors = (
        'button:has-text("Use another account")',
        'a:has-text("Use another account")',
        'button:has-text("Add another account")',
        'a:has-text("Add another account")',
        "text=Use another account",
        "text=Add another account",
    )
    for frame in _frame_scopes(page):
        for selector in selectors:
            try:
                locator = frame.locator(selector).first
                if on_selector:
                    on_selector(selector, False)
                visible = locator.is_visible()
                if on_selector:
                    on_selector(selector, True)
                if visible:
                    locator.click(timeout=2000)
                    return True
            except Exception:
                continue
    return False


def _safe_page_location(page: Any) -> str:
    """Summarize page/frame locations without query strings or fragments."""
    locations = []
    try:
        frames = list(page.frames)
    except Exception:
        frames = [page]
    for frame in frames:
        try:
            parsed = urllib.parse.urlsplit(frame.url)
            location = f"{parsed.hostname or 'unknown'}{parsed.path}"
            if location not in locations:
                locations.append(location)
        except Exception:
            continue
    return ",".join(locations[:5]) or "unavailable"


def _safe_page_location_for_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return f"{parsed.hostname or 'unknown'}{parsed.path}"


class _PrivateBrowserNetworkCapture:
    """Owner-thread recorder for every Playwright-visible browser exchange."""

    def __init__(
        self,
        context: Any,
        diagnostics_dir: Path,
        *,
        setupsession_public_key: Optional[str] = None,
    ):
        from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

        self._append = append_private_jsonl
        self._dir = diagnostics_dir
        self._events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._stats = {
            "requests": 0,
            "responses": 0,
            "response_bodies": 0,
            "request_failures": 0,
            "request_body_unavailable": 0,
            "response_body_unavailable": 0,
            "capture_errors": 0,
        }
        self._closed = False
        self._setupsession_public_key = setupsession_public_key
        self.native_setupsession_response: Optional[Any] = None
        self.native_setupsession_error: Optional[str] = None

        def enqueue(event: str) -> Callable[[Any], None]:
            return lambda value: self._events.put((event, value))

        for event in ("request", "response", "requestfinished", "requestfailed"):
            context.on(event, enqueue(event))

        def capture_page(page: Any) -> None:
            def frame_record(event: str, frame: Any) -> None:
                try:
                    parent = frame.parent_frame
                    self._append(
                        self._dir,
                        "browser-frames.jsonl",
                        {
                            "event": event,
                            "time_utc": datetime.now(timezone.utc).isoformat(),
                            "url": str(frame.url),
                            "parent_url": str(parent.url) if parent is not None else None,
                            "main_frame": parent is None,
                        },
                    )
                except Exception as exc:
                    self._error("frame", exc)

            page.on("frameattached", lambda frame: frame_record("attached", frame))
            page.on("framenavigated", lambda frame: frame_record("navigated", frame))
            page.on("framedetached", lambda frame: frame_record("detached", frame))

            def on_page_error(error: Any) -> None:
                self._append(
                    self._dir,
                    "browser-js-errors.jsonl",
                    {
                        "event": "pageerror",
                        "time_utc": datetime.now(timezone.utc).isoformat(),
                        "error": str(error),
                    },
                )

            def on_console(message: Any) -> None:
                self._append(
                    self._dir,
                    "browser-js-errors.jsonl",
                    {
                        "event": "console",
                        "time_utc": datetime.now(timezone.utc).isoformat(),
                        "type": message.type,
                        "text": message.text,
                        "location": message.location,
                    },
                )

            page.on("pageerror", on_page_error)
            page.on("console", on_console)

        for page in list(context.pages):
            capture_page(page)
        context.on("page", capture_page)
        context.on("websocket", lambda ws: _capture_private_websocket(ws, diagnostics_dir))
        if setupsession_public_key:
            context.route("**/cloudshell/setupsession**", self._rewrite_setupsession_key)

    def _rewrite_setupsession_key(self, route: Any) -> None:
        """Replace only the native setupsession SSH key with our paired key."""
        try:
            request = route.request
            original = request.post_data
            original_headers = request.all_headers()
            original_header_array = request.headers_array()
            payload = json.loads(original) if original else None
            key_parts = (self._setupsession_public_key or "").strip().split()
            if (
                not isinstance(payload, list)
                or len(payload) < 3
                or not isinstance(payload[2], list)
                or len(payload[2]) < 2
                or len(key_parts) < 2
            ):
                raise ValueError("native setupsession payload did not match the captured shape")
            payload[2] = [2, key_parts[1]]
            replacement = json.dumps(payload, separators=(",", ":"))
            self._append(
                self._dir,
                "browser-bootstrap.jsonl",
                {
                    "event": "native-setupsession-key-replaced",
                    "time_utc": datetime.now(timezone.utc).isoformat(),
                    "url": str(request.url),
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "original_headers": original_headers,
                    "original_header_array": original_header_array,
                    "original_body": original,
                    "replacement_body": replacement,
                },
            )
            route.continue_(post_data=replacement)
        except Exception as exc:
            self.native_setupsession_error = type(exc).__name__
            self._error("rewrite-native-setupsession", exc)
            try:
                route.abort()
            except Exception:
                pass
    def _error(self, stage: str, error: BaseException) -> None:
        self._stats["capture_errors"] += 1
        self._append(
            self._dir,
            "browser-capture-errors.jsonl",
            {
                "stage": stage,
                "time_utc": datetime.now(timezone.utc).isoformat(),
                "error_type": type(error).__name__,
                "error": str(error),
            },
        )

    @staticmethod
    def _is_browser_request(request: Any) -> bool:
        try:
            parsed = urllib.parse.urlsplit(str(request.url))
            return parsed.scheme in {"http", "https", "ws", "wss"}
        except Exception:
            return False

    def drain(self) -> None:
        while True:
            try:
                event, item = self._events.get_nowait()
            except queue.Empty:
                return
            try:
                request = item.request if event == "response" else item
                if not self._is_browser_request(request):
                    continue
                now = datetime.now(timezone.utc).isoformat()
                if event == "request":
                    self._stats["requests"] += 1
                    body = request.post_data_buffer
                    if body is None:
                        text_body = request.post_data
                        body = text_body.encode("utf-8") if text_body is not None else None
                    headers = request.all_headers()
                    content_length = next(
                        (
                            int(value)
                            for key, value in headers.items()
                            if key.lower() == "content-length" and str(value).isdigit()
                        ),
                        0,
                    )
                    body_complete = body is not None or content_length == 0
                    if not body_complete:
                        self._stats["request_body_unavailable"] += 1
                    record = {
                        "event": event,
                        "time_utc": now,
                        "url": str(request.url),
                        "method": request.method,
                        "resource_type": request.resource_type,
                        "headers": headers,
                        "header_array": request.headers_array(),
                        "post_data": request.post_data,
                        "request_body_present": body is not None,
                        "request_body_base64": (
                            base64.b64encode(body).decode("ascii") if body is not None else None
                        ),
                        "request_body_bytes": len(body) if body is not None else 0,
                        "request_body_complete": body_complete,
                    }
                    self._append(self._dir, "browser-network.jsonl", record)
                elif event == "response":
                    self._stats["responses"] += 1
                    response = item
                    record = {
                        "event": event,
                        "time_utc": now,
                        "url": str(response.url),
                        "method": request.method,
                        "status": response.status,
                        "status_text": response.status_text,
                        "headers": response.all_headers(),
                        "header_array": response.headers_array(),
                        "server_addr": response.server_addr,
                        "security_details": response.security_details,
                    }
                    self._append(self._dir, "browser-network.jsonl", record)
                elif event == "requestfinished":
                    response = request.response()
                    body = response.body() if response is not None else b""
                    if response is None:
                        self._stats["response_body_unavailable"] += 1
                    else:
                        self._stats["response_bodies"] += 1
                    self._append(
                        self._dir,
                        "browser-network.jsonl",
                        {
                            "event": "response-body",
                            "time_utc": now,
                            "url": str(request.url),
                            "method": request.method,
                            "body_base64": base64.b64encode(body).decode("ascii"),
                            "body_bytes": len(body),
                            "body_complete": response is not None,
                        },
                    )
                    if urllib.parse.urlsplit(str(request.url)).path.endswith(
                        "/cloudshell/setupsession"
                    ):
                        try:
                            from cloudbasher.csp.gcp._http import strip_xssi

                            self.native_setupsession_response = strip_xssi(body.decode("utf-8"))
                        except Exception as exc:
                            self.native_setupsession_error = type(exc).__name__
                            self._error("parse-native-setupsession-response", exc)
                else:
                    self._stats["request_failures"] += 1
                    response = request.response()
                    request_path = urllib.parse.urlsplit(str(request.url)).path
                    if (
                        response is not None
                        and request_path.endswith("/cloudshell/setupsession")
                    ):


                        try:
                            body = response.body()
                            self._stats["response_bodies"] += 1
                            self._append(
                                self._dir,
                                "browser-network.jsonl",
                                {
                                    "event": "response-body-after-request-failure",
                                    "time_utc": now,
                                    "url": str(request.url),
                                    "method": request.method,
                                    "body_base64": base64.b64encode(body).decode("ascii"),
                                    "body_bytes": len(body),
                                    "body_complete": True,
                                },
                            )
                            from cloudbasher.csp.gcp._http import strip_xssi

                            self.native_setupsession_response = strip_xssi(
                                body.decode("utf-8")
                            )
                        except Exception as exc:
                            self._stats["response_body_unavailable"] += 1
                            self.native_setupsession_error = type(exc).__name__
                            self._error("setupsession-body-after-request-failure", exc)
                    self._append(
                        self._dir,
                        "browser-network.jsonl",
                        {
                            "event": "request-failed",
                            "time_utc": now,
                            "url": str(request.url),
                            "method": request.method,
                            "failure": request.failure,
                        },
                    )
            except Exception as exc:
                self._stats["capture_errors"] += 1
                if event == "request":
                    self._stats["request_body_unavailable"] += 1
                elif event == "requestfinished":
                    self._stats["response_body_unavailable"] += 1
                self._append(
                    self._dir,
                    "browser-network.jsonl",
                    {
                        "event": f"{event}-capture-unavailable",
                        "time_utc": datetime.now(timezone.utc).isoformat(),
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                )

    def close(self) -> None:
        if self._closed:
            return
        self.drain()
        self._closed = True
        self._append(
            self._dir,
            "browser-network-status.jsonl",
            {
                **self._stats,
                "native_setupsession_intercepted": bool(self._setupsession_public_key),
                "native_setupsession_response_captured": (
                    self.native_setupsession_response is not None
                ),
                "native_setupsession_error": self.native_setupsession_error,
                "pending_events": self._events.qsize(),
                "incomplete": bool(
                    self._events.qsize()
                    or self._stats["request_body_unavailable"]
                    or self._stats["response_body_unavailable"]
                    or self._stats["capture_errors"]
                ),
                "scope": (
                    "Playwright-visible HTTP(S)/WebSocket events; raw CDP/frame/JS source "
                    "capture is in the native capture harness"
                ),
            },
        )


def _capture_private_protocol_network(
    context: Any,
    diagnostics_dir: Path,
    *,
    setupsession_public_key: Optional[str] = None,
) -> _PrivateBrowserNetworkCapture:
    """Install owner-only capture hooks and return their owner-thread drainer."""
    return _PrivateBrowserNetworkCapture(
        context, diagnostics_dir, setupsession_public_key=setupsession_public_key
    )


def _capture_private_websocket(websocket: Any, diagnostics_dir: Path) -> None:
    """Record browser WebSocket handshake metadata and every Playwright frame."""
    from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

    def payload_record(event: str, payload: Any) -> None:
        if isinstance(payload, bytes):
            value: dict[str, Any] = {
                "payload_base64": base64.b64encode(payload).decode("ascii"),
                "payload_bytes": len(payload),
                "binary": True,
            }
        else:
            text = str(payload)
            value = {"payload_text": text, "payload_bytes": len(text.encode()), "binary": False}
        append_private_jsonl(
            diagnostics_dir,
            "browser-websockets.jsonl",
            {
                "event": event,
                "time_utc": datetime.now(timezone.utc).isoformat(),
                "url": str(websocket.url),
                **value,
            },
        )

    append_private_jsonl(
        diagnostics_dir,
        "browser-websockets.jsonl",
        {
            "event": "created",
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "url": str(websocket.url),
        },
    )
    websocket.on("framesent", lambda payload: payload_record("sent", payload))
    websocket.on("framereceived", lambda payload: payload_record("received", payload))
    websocket.on("close", lambda: payload_record("closed", ""))
    websocket.on("socketerror", lambda error: payload_record("error", str(error)))


def _has_signed_in_cookies(cookies: dict[str, str]) -> bool:
    """Return True if the cookie jar contains a usable Google sign-in token."""
    return any(cookies.get(name) for name in _SIGNED_IN_SENTINELS)


def _oauth_token_payload(response: Any) -> Optional[dict[str, Any]]:
    """Extract only the native `iframerpc?action=issueToken` result fields."""
    try:
        parsed = urllib.parse.urlsplit(response.url)
        query = urllib.parse.parse_qs(parsed.query)
        if (
            parsed.hostname != "accounts.google.com"
            or parsed.path != "/o/oauth2/iframerpc"
            or query.get("action") != ["issueToken"]
        ):
            return None
        payload = response.json()
    except Exception:
        return None
    if not isinstance(payload, dict) or not payload.get("access_token"):
        return None
    return {
        key: payload[key]
        for key in ("access_token", "id_token", "expires_in", "scope", "token_type")
        if key in payload
    }


def _is_oauth_token_url(url: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(url)
        return (
            parsed.hostname == "accounts.google.com"
            and parsed.path == "/o/oauth2/iframerpc"
            and urllib.parse.parse_qs(parsed.query).get("action") == ["issueToken"]
        )
    except Exception:
        return False


def _parse_newtoken_response(status: int, body: str) -> str:
    """Validate a browser-fetched /newtoken response without exposing its token."""
    if status < 200 or status >= 300:
        raise CloudShellAutomationError(
            f"Browser GET /newtoken returned HTTP {status}; response body omitted."
        )
    try:
        payload = body.removeprefix(")]}'").strip()
        value = json.loads(payload)
    except Exception as exc:
        raise CloudShellAutomationError(
            "Browser GET /newtoken returned an unrecognized response; body omitted."
        ) from exc
    if not isinstance(value, list) or len(value) < 2 or not isinstance(value[1], str):
        raise CloudShellAutomationError(
            "Browser GET /newtoken response did not contain an XSRF token; body omitted."
        )
    return value[1]


class GCPBrowserSession:
    """Live browser context used for native same-origin private API requests."""

    def __init__(
        self,
        pw_ctx: Any,
        browser: Any,
        page: Any,
        cookies: dict[str, str],
        diagnostics_dir: Optional[Path] = None,
        trace_path: Optional[Path] = None,
        api_target: Any = None,
        network_capture: Optional[_PrivateBrowserNetworkCapture] = None,
    ):
        self._pw_ctx, self._browser, self._page = pw_ctx, browser, page
        self._api_target = api_target or page
        self.cookies = cookies
        self.diagnostics_dir = diagnostics_dir
        self._trace_path = trace_path
        self._trace_active = trace_path is not None
        self._network_capture = network_capture
        self._closed = False
        self._owner_thread = threading.get_ident()
        self._owner_thread_obj = threading.current_thread()
        self._requests: queue.Queue[Any] = queue.Queue()
        self._event_pump_failed = False

    def request(
        self, method: str, url: str, body: Optional[bytes], headers: dict[str, str], timeout: float
    ) -> tuple[Any, dict[str, str], int]:
        if threading.get_ident() == self._owner_thread:
            return self._request_on_owner(method, url, body, headers, timeout)
        completed = threading.Event()
        task: dict[str, Any] = {
            "method": method,
            "url": url,
            "body": body,
            "headers": headers,
            "timeout": timeout,
            "done": completed,
        }
        self._requests.put(task)
        if not completed.wait(timeout + 5):
            raise CloudShellAutomationError("Timed out waiting for browser request owner thread")
        if "error" in task:
            raise task["error"]
        return task["result"]

    def issue_cloudshell_oauth_token(self) -> dict[str, Any]:
        """Ask the signed-in Cloud Shell page for its native delegated token."""
        if self._closed:
            raise CloudShellAutomationError("Cloud Shell browser session is already closed")
        if threading.get_ident() == self._owner_thread:
            return self._issue_cloudshell_oauth_token_on_owner()
        completed = threading.Event()
        task: dict[str, Any] = {"oauth_token_done": completed}
        self._requests.put(task)
        if not completed.wait(OAUTH_TOKEN_ISSUE_TIMEOUT_MS / 1000 + 5):
            raise CloudShellAutomationError(
                "Timed out waiting for browser owner to request the Cloud Shell OAuth token"
            )
        if "error" in task:
            raise task["error"]
        return task["result"]

    @property
    def native_setupsession_response(self) -> Optional[Any]:
        """Return the native setupsession response, retained only in process RAM."""
        if self._network_capture is None:
            return None
        return self._network_capture.native_setupsession_response

    def _issue_cloudshell_oauth_token_on_owner(self) -> dict[str, Any]:
        def request_token(*, immediate: bool) -> dict[str, Any]:
            try:
                result = self._api_target.evaluate(
                    """({clientId, scope, timeoutMs, immediate}) =>
                new Promise((resolve, reject) => {
                  let finished = false;
                  const finish = (fn, value) => {
                    if (finished) return;
                    finished = true;
                    clearTimeout(timer);
                    fn(value);
                  };
                  const timer = setTimeout(
                    () => finish(reject, new Error('issueToken timeout')), timeoutMs
                  );
                  const authorize = () => {
                    const auth = window.gapi && window.gapi.auth;
                    if (!auth || typeof auth.authorize !== 'function') {
                      finish(reject, new Error('gapi auth unavailable'));
                      return;
                    }
                    auth.authorize({
                      client_id: clientId,
                      scope,
                      immediate,
                      response_type: 'token id_token',
                      include_granted_scopes: true
                    }, result => finish(resolve, result || {}));
                  };
                  if (window.gapi && window.gapi.auth &&
                      typeof window.gapi.auth.authorize === 'function') {
                    authorize();
                  } else if (window.gapi && typeof window.gapi.load === 'function') {
                    window.gapi.load('auth', authorize);
                  } else {
                    finish(reject, new Error('gapi unavailable'));
                  }
                })""",
                    {
                        "clientId": _CLOUDSHELL_OAUTH_CLIENT_ID,
                        "scope": _CLOUDSHELL_OAUTH_SCOPES,
                        "timeoutMs": OAUTH_TOKEN_ISSUE_TIMEOUT_MS,
                        "immediate": immediate,
                    },
                )
            except Exception as exc:
                raise CloudShellAutomationError(
                    "Cloud Shell OAuth token request failed "
                    f"({type(exc).__name__}); details omitted."
                ) from exc
            if self._network_capture is not None:
                self._network_capture.drain()
            return result if isinstance(result, dict) else {}

        result = request_token(immediate=True)
        if not result.get("access_token") and result.get("error") == "immediate_failed":


            log(
                "[gcp.playwright] silent issueToken returned immediate_failed; "
                "retrying the native Cloud Shell grant with user interaction"
            )
            result = request_token(immediate=False)
        if not isinstance(result, dict) or not result.get("access_token"):
            safe_error = (
                str(result.get("error"))[:80]
                if isinstance(result, dict) and result.get("error")
                else "no token returned"
            )
            log(
                "[gcp.playwright] native issueToken completed without an access "
                f"token: {safe_error}"
            )
            return {}
        return {
            key: result[key]
            for key in ("access_token", "id_token", "expires_in", "scope", "token_type")
            if key in result
        }

    def _request_on_owner(
        self, method: str, url: str, body: Optional[bytes], headers: dict[str, str], timeout: float
    ) -> tuple[Any, dict[str, str], int]:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "shell.cloud.google.com":
            raise CloudShellAutomationError(
                "Refusing browser API request outside Cloud Shell origin"
            )
        if self._closed:
            raise CloudShellAutomationError("Cloud Shell browser session is already closed")
        safe_headers = {k: v for k, v in headers.items() if k.lower() != "cookie"}
        try:
            result = self._api_target.evaluate(
                """async ({method, url, body, headers, timeout}) => {
                  const controller = new AbortController();
                  const timer = setTimeout(() => controller.abort(), timeout * 1000);
                  try {
                    const response = await fetch(url, {
                      method, body, headers, credentials: 'include', signal: controller.signal
                    });
                    return {status: response.status, body: await response.text(),
                      headers: Object.fromEntries(response.headers.entries())};
                  } finally { clearTimeout(timer); }
                }""",
                {
                    "method": method,
                    "url": url,
                    "body": body.decode("utf-8") if body is not None else None,
                    "headers": safe_headers,
                    "timeout": timeout,
                },
            )
        except Exception as exc:
            raise CloudShellAutomationError(
                f"Browser-backed Cloud Shell request failed ({type(exc).__name__}); "
                "details omitted."
            ) from exc
        if self._network_capture is not None:
            self._network_capture.drain()
        raw = str(result.get("body", ""))
        from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

        if self.diagnostics_dir is not None:
            append_private_jsonl(
                self.diagnostics_dir,
                "browser-api.jsonl",
                {
                    "method": method,
                    "url": url,
                    "request_headers": safe_headers,
                    "request_body": body.decode("utf-8", "replace") if body else None,
                    "status": int(result.get("status", 0)),
                    "response_headers": dict(result.get("headers") or {}),
                    "response_body": raw,
                },
            )
        try:
            parsed_body: Any = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            parsed_body = raw
        return parsed_body, dict(result.get("headers") or {}), int(result.get("status", 0))

    def serve_requests(self) -> None:
        """Run requests and keep the browser event loop active until close."""
        while True:
            try:
                task = self._requests.get(timeout=0.05)
            except queue.Empty:


                try:
                    self._page.wait_for_timeout(50)
                    if self._network_capture is not None:
                        self._network_capture.drain()
                except Exception as exc:
                    if not self._event_pump_failed:
                        log(
                            "[gcp.playwright] browser event pump failed "
                            f"({type(exc).__name__}); further failures suppressed"
                        )
                        self._event_pump_failed = True
                    time.sleep(0.05)
                continue
            if "close_done" in task:
                self._close_on_owner()
                task["close_done"].set()
                return
            if "oauth_token_done" in task:
                try:
                    task["result"] = self._issue_cloudshell_oauth_token_on_owner()
                except BaseException as exc:
                    task["error"] = exc
                finally:
                    task["oauth_token_done"].set()
                continue
            try:
                task["result"] = self._request_on_owner(
                    task["method"],
                    task["url"],
                    task["body"],
                    task["headers"],
                    task["timeout"],
                )
            except BaseException as exc:
                task["error"] = exc
            finally:
                task["done"].set()

    def _close_on_owner(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._trace_active:
            try:
                self._pw_ctx.tracing.stop(path=str(self._trace_path))
                os.chmod(self._trace_path, 0o600)
            except Exception:
                pass
            self._trace_active = False
        if self._network_capture is not None:
            self._network_capture.close()
        _safe_close(self._browser)
        try:
            self._pw_ctx.__exit__(None, None, None)
        except Exception as exc:
            log(
                "[gcp.playwright] driver context close failed "
                f"({type(exc).__name__}); trying stop()"
            )
            try:
                self._pw_ctx.stop()
            except Exception as stop_exc:
                log(f"[gcp.playwright] driver stop failed ({type(stop_exc).__name__})")

    def close(self) -> None:
        if self._closed:
            return
        if threading.get_ident() == self._owner_thread:
            self._close_on_owner()
            return
        completed = threading.Event()
        self._requests.put({"close_done": completed})

        if not completed.wait(10):
            log("[gcp.playwright] browser owner did not acknowledge close")
            return
        self._owner_thread_obj.join(timeout=5)
        if self._owner_thread_obj.is_alive():
            log("[gcp.playwright] browser owner thread did not stop after close")


def playwright_login_for_cookies(
    *,
    target_url: str = _DEFAULT_TARGET_URL,
    project_id: Optional[str] = None,
    setupsession_public_key: Optional[str] = None,
    headless: bool = True,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    timeout_seconds: int = 600,
    wait_mode: str = "auto",
    poll_interval_seconds: float = 2.0,
    prefill_email: Optional[str] = None,
    password: Optional[str] = None,
    oauth_token_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    oauth_request_callback: Optional[Callable[[], None]] = None,
    xsrf_token_callback: Optional[Callable[[str], None]] = None,
    keep_browser_open: bool = False,
    _owner_worker: bool = False,
    capture_login_screenshots: bool = False,
    _diagnostics_dir: Optional[Path] = None,
) -> dict[str, str] | GCPBrowserSession:
    """Open a browser, wait for the user to sign in, and return Google cookies."""
    if wait_mode not in ("auto", "input"):
        raise ValueError(f"wait_mode must be 'auto' or 'input', got {wait_mode!r}")
    if project_id and target_url == _DEFAULT_TARGET_URL:
        target_url = native_console_project_url(project_id)

    if _diagnostics_dir is None:
        from cloudbasher.csp.gcp.diagnostics import private_capture_dir

        _diagnostics_dir = private_capture_dir()
        log(f"[gcp.playwright] private protocol diagnostics: {_diagnostics_dir}")

    if keep_browser_open and not _owner_worker:
        ready = threading.Event()
        result: dict[str, Any] = {}

        def _browser_owner() -> None:
            try:
                session = playwright_login_for_cookies(
                    target_url=target_url,
                    project_id=project_id,
                    setupsession_public_key=setupsession_public_key,
                    headless=headless,
                    proxy_url=proxy_url,
                    proxy_insecure=proxy_insecure,
                    timeout_seconds=timeout_seconds,
                    wait_mode=wait_mode,
                    poll_interval_seconds=poll_interval_seconds,
                    prefill_email=prefill_email,
                    password=password,
                    oauth_token_callback=oauth_token_callback,
                    oauth_request_callback=oauth_request_callback,
                    xsrf_token_callback=xsrf_token_callback,
                    keep_browser_open=True,
                    _owner_worker=True,
                    capture_login_screenshots=capture_login_screenshots,
                    _diagnostics_dir=_diagnostics_dir,
                )
                result["session"] = session
                ready.set()
                session.serve_requests()
            except _VisibleVerificationRetry as exc:
                if not headless:
                    result["error"] = CloudShellAutomationError(
                        f"Visible Google sign-in could not continue at {exc.stage}."
                    )
                    ready.set()
                    return
                log(
                    "[gcp.playwright] headless login reached a verification/selector "
                    f"gate at stage={exc.stage}; reopening visibly for user intervention"
                )
                out(
                    "Google sign-in needs visible user verification. A browser is "
                    "opening now; complete any secondary check there."
                )


                threading.Thread(
                    target=_run_visible_retry_owner,
                    kwargs={
                        "target_url": target_url,
                        "project_id": project_id,
                        "setupsession_public_key": setupsession_public_key,
                        "proxy_url": proxy_url,
                        "proxy_insecure": proxy_insecure,
                        "timeout_seconds": timeout_seconds,
                        "wait_mode": wait_mode,
                        "poll_interval_seconds": poll_interval_seconds,
                        "prefill_email": prefill_email,
                        "oauth_token_callback": oauth_token_callback,
                        "oauth_request_callback": oauth_request_callback,
                        "xsrf_token_callback": xsrf_token_callback,
                        "diagnostics_dir": _diagnostics_dir,
                        "result": result,
                        "ready": ready,
                    },
                    name="gcp-playwright-visible-owner",
                    daemon=True,
                ).start()
            except BaseException as exc:
                result["error"] = exc
                ready.set()

        threading.Thread(target=_browser_owner, name="gcp-playwright-owner", daemon=True).start()
        if not ready.wait(timeout_seconds + 30):
            raise CloudShellAutomationError("Timed out waiting for GCP browser login")
        if "error" in result:
            raise result["error"]
        return result["session"]

    ensure_playwright_available()

    diagnostics_dir = _diagnostics_dir
    trace_path = diagnostics_dir / (
        "playwright-headed.zip" if not headless else "playwright-headless.zip"
    )
    log(f"[gcp.playwright] private protocol diagnostics: {diagnostics_dir}")

    launch_kwargs: dict[str, Any] = {
        "headless": headless,
        "channel": "chromium",
        "args": _launch_args(),
    }
    if proxy_url:
        parsed = urllib.parse.urlparse(proxy_url)
        launch_kwargs["proxy"] = {"server": f"{parsed.scheme}://{parsed.netloc}"}

    _extra: dict[str, Any] = {}
    if proxy_insecure and proxy_url:
        _extra["ignore_https_errors"] = True

    pw_ctx = _sync_playwright().__enter__()
    cookies: dict[str, str] = {}
    oauth_token: dict[str, Any] = {}
    retained_session: Optional[GCPBrowserSession] = None
    trace_started = False
    try:
        browser = pw_ctx.chromium.launch(**launch_kwargs)
        context = browser.new_context(**_context_kwargs(browser, extra=_extra))
        context.tracing.start(screenshots=True, snapshots=True, sources=True)
        trace_started = True
        from cloudbasher.csp.gcp.diagnostics import write_private

        write_private(
            diagnostics_dir,
            f"login-{'headed' if not headless else 'headless'}-manifest.json",
            json.dumps(
                {
                    "started_utc": datetime.now(timezone.utc).isoformat(),
                    "headless": headless,
                    "browser_version": browser.version,
                    "target": _safe_page_location_for_url(target_url),
                    "email_selector_candidates": list(_EMAIL_SELECTORS),
                    "password_selector_candidates": list(_PASSWORD_SELECTORS),
                    "email_prefill_configured": bool(prefill_email),
                    "password_submission_configured": bool(password),
                    "automatic_visible_retry_allowed": headless,
                },
                indent=2,
            ).encode("utf-8"),
        )
        page = context.new_page()
        network_capture = _capture_private_protocol_network(
            context,
            diagnostics_dir,
            setupsession_public_key=setupsession_public_key,
        )
        screenshot_dir = _login_debug_dir() if capture_login_screenshots and not headless else None
        if screenshot_dir is not None:
            log(f"[gcp.playwright] headed login diagnostics directory: {screenshot_dir}")
        screenshot_index = 0

        def login_checkpoint(label: str) -> None:
            """Capture a headed screenshot without logging page contents or secrets."""
            nonlocal screenshot_index
            if screenshot_dir is None:
                return
            screenshot_index += 1
            target = screenshot_dir / f"{screenshot_index:02d}-{label}.png"
            try:
                page.screenshot(path=str(target), full_page=False, timeout=5000)
                os.chmod(target, 0o600)
                log(
                    f"[gcp.playwright] login screenshot {target.name}; "
                    f"location={_safe_page_location(page)}"
                )
            except Exception as exc:
                log(f"[gcp.playwright] login screenshot failed ({type(exc).__name__})")

        def selector_checkpoint(selector: str, after: bool) -> None:
            stage = "after" if after else "before"
            safe_label = "".join(c if c.isalnum() else "-" for c in selector)[:48].strip("-")
            log(f"[gcp.playwright] selector {stage}: {selector!r}")
            login_checkpoint(f"selector-{stage}-{safe_label or 'control'}")

        if oauth_token_callback is not None:

            def _observe_oauth_request(request: Any) -> None:
                url = str(getattr(request, "url", ""))
                if not _is_oauth_token_url(url):
                    return
                query_keys = sorted(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query))
                log(
                    "[gcp.playwright] native issueToken request started "
                    f"query_keys={query_keys}; values omitted"
                )
                if oauth_request_callback is not None:
                    oauth_request_callback()

            def _capture_oauth_response(response: Any) -> None:
                """Keep only the short-lived token response in process memory."""
                try:
                    if _is_oauth_token_url(str(response.url)):
                        log(
                            "[gcp.playwright] native issueToken response received "
                            f"status={response.status}; body omitted"
                        )
                    payload = _oauth_token_payload(response)
                    if payload is None:
                        if _is_oauth_token_url(str(response.url)):
                            log(
                                "[gcp.playwright] native issueToken response had "
                                "no usable token fields"
                            )
                        return
                    oauth_token.clear()
                    oauth_token.update(payload)
                    safe_scopes = sorted(set(str(payload.get("scope") or "").split()))
                    log(
                        "[gcp.playwright] OAuth response metadata "
                        f"access_token_present={bool(payload.get('access_token'))} "
                        f"id_token_present={bool(payload.get('id_token'))} "
                        f"expires_in={payload.get('expires_in')} scopes={safe_scopes}"
                    )
                    oauth_token_callback(dict(oauth_token))
                except Exception as exc:
                    log(
                        "[gcp.playwright] OAuth response could not be parsed "
                        f"({type(exc).__name__})"
                    )

            context.on("request", _observe_oauth_request)
            context.on("response", _capture_oauth_response)

        out_ts("Opening browser for Google sign-in...")
        log(
            "[gcp.playwright] navigating to "
            f"{_safe_page_location_for_url(target_url)} mode={wait_mode}"
        )
        login_checkpoint("before-navigation")
        page.goto(target_url)
        login_checkpoint("after-navigation")

        if prefill_email:


            try:
                login_checkpoint("before-email-selector")
                email_field = _wait_for_control(
                    page,
                    _EMAIL_SELECTORS,
                    2.0,
                    on_selector=selector_checkpoint,
                )
                if email_field is None and _click_account_switch(
                    page, on_selector=selector_checkpoint
                ):
                    login_checkpoint("after-account-switch")
                    email_field = _wait_for_control(
                        page,
                        _EMAIL_SELECTORS,
                        10.0,
                        on_selector=selector_checkpoint,
                    )
                if email_field is None:
                    log(
                        "[gcp.playwright] email input not found; selectors="
                        f"{_EMAIL_SELECTORS!r}; location={_safe_page_location(page)}"
                    )
                    _retry_visibly_if_headless(headless, "email-selector")
                else:
                    _email_scope, email_locator = email_field
                    login_checkpoint("before-email-fill")
                    email_locator.fill(prefill_email)
                    log("[gcp.playwright] configured email entered into Google sign-in form")
                    login_checkpoint("after-email-fill")
                    next_control = _visible_control(
                        page,
                        (
                            "#identifierNext button",
                            "button#identifierNext",
                            'button:has-text("Next")',
                            'input[type="submit"]',
                        ),
                        on_selector=selector_checkpoint,
                    )
                    if next_control:
                        login_checkpoint("before-email-submit")
                        next_control[1].click(timeout=3000)
                    else:
                        login_checkpoint("before-email-enter")
                        email_locator.press("Enter")
                    login_checkpoint("after-email-submit")
            except Exception as exc:
                if isinstance(exc, _VisibleVerificationRetry):
                    raise
                if headless and "timeout" in type(exc).__name__.lower():
                    raise _VisibleVerificationRetry("email-selector-timeout") from exc
                log(
                    "[gcp.playwright] email form interaction failed "
                    f"({type(exc).__name__}); location={_safe_page_location(page)}"
                )

        if password:


            try:
                login_checkpoint("before-password-selector")
                password_field = _wait_for_control(
                    page,
                    _PASSWORD_SELECTORS,
                    15.0,
                    on_selector=selector_checkpoint,
                )
                if password_field is None:
                    log(
                        "[gcp.playwright] password input not found; selectors="
                        f"{_PASSWORD_SELECTORS!r}; "
                        f"manual verification may be required; location={_safe_page_location(page)}"
                    )
                    _retry_visibly_if_headless(headless, "password-selector")
                else:
                    _password_scope, password_locator = password_field
                    login_checkpoint("before-password-fill")
                    password_locator.fill(password)
                    password_locator.press("Enter")

                    log("[gcp.playwright] submitted configured password through sign-in form")
            except Exception as exc:
                if isinstance(exc, _VisibleVerificationRetry):
                    raise
                if headless and "timeout" in type(exc).__name__.lower():
                    raise _VisibleVerificationRetry("password-selector-timeout") from exc
                log(
                    "[gcp.playwright] password form interaction failed "
                    f"({type(exc).__name__}); no password value logged; "
                    f"location={_safe_page_location(page)}"
                )

        out("")
        if headless:
            out("  Completing sign-in in headless Chromium; waiting for Google session...")
        else:
            out("  Complete Google sign-in in the browser window.")
        if wait_mode == "input":
            out("  After sign-in completes, press Enter here to continue.")
            out("")
            try:
                input("  Press Enter when sign-in is complete (Ctrl-C to cancel)... ")
            except (EOFError, KeyboardInterrupt):
                _safe_close(browser)
                raise CloudShellAutomationError("Playwright login cancelled by user")
        else:


            login_timeout = min(timeout_seconds, 20) if headless else timeout_seconds
            out(f"  Waiting up to {login_timeout}s for sign-in to complete...")
            out("")
            deadline = time.time() + login_timeout
            while time.time() < deadline:
                cookies = extract_google_cookies(context, log_result=False)
                if _has_signed_in_cookies(cookies):
                    log("[gcp.playwright] sign-in detected (SID present)")
                    break
                page.wait_for_timeout(max(1, round(poll_interval_seconds * 1000)))
                network_capture.drain()
            else:
                if headless:
                    raise _VisibleVerificationRetry("post-password-verification")
                _safe_close(browser)
                raise CloudShellAutomationError(
                    f"Timed out after {login_timeout}s waiting for Google sign-in. "
                    "No SID/__Secure-1PSID cookie appeared in the browser context."
                )


        cookies = extract_google_cookies(context)
        api_target = page
        if urllib.parse.urlsplit(page.url).hostname == "console.cloud.google.com":
            api_target = _open_native_cloudshell(
                page, context, diagnostics_dir, network_capture
            )
            network_capture.drain()
        if xsrf_token_callback is not None:
            try:
                response = api_target.evaluate(
                    """async () => {
                      const r = await fetch('/newtoken?authuser=0', {
                        method: 'GET', credentials: 'include'
                      });
                      return {status: r.status, body: await r.text()};
                    }"""
                )
                xsrf_token_callback(
                    _parse_newtoken_response(int(response["status"]), str(response["body"]))
                )
                log("[gcp.playwright] browser-context /newtoken succeeded")
            except CloudShellAutomationError:
                raise
            except Exception as exc:


                try:
                    from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

                    append_private_jsonl(
                        diagnostics_dir,
                        "browser-bootstrap-errors.jsonl",
                        {
                            "stage": "browser-context-newtoken",
                            "exception_type": type(exc).__name__,
                            "exception": str(exc),
                            "page_url": page.url,
                            "page_closed": page.is_closed(),
                            "browser_connected": browser.is_connected(),
                            "thread_name": threading.current_thread().name,
                            "thread_id": threading.get_ident(),
                        },
                    )
                except Exception as capture_exc:
                    log(
                        "[gcp.playwright] private /newtoken failure capture failed "
                        f"({type(capture_exc).__name__})"
                    )
                raise CloudShellAutomationError(
                    f"Browser-context /newtoken failed ({type(exc).__name__}); details omitted."
                ) from exc
        if keep_browser_open:
            retained_session = GCPBrowserSession(
                pw_ctx,
                browser,
                page,
                cookies,
                diagnostics_dir,
                trace_path,
                api_target=api_target,
                network_capture=network_capture,
            )
        else:
            if trace_started:
                context.tracing.stop(path=str(trace_path))
                os.chmod(trace_path, 0o600)
                trace_started = False
            _safe_close(browser)
    finally:
        if retained_session is None:
            try:
                network_capture.close()
            except Exception:
                pass
            if trace_started:
                try:
                    context.tracing.stop(path=str(trace_path))
                    os.chmod(trace_path, 0o600)
                except Exception:
                    pass
            try:
                pw_ctx.__exit__(None, None, None)
            except Exception:
                pass

    if not cookies or not _has_signed_in_cookies(cookies):
        raise CloudShellAutomationError(
            "No Google session cookies captured from browser. "
            "Sign-in may have failed or been cancelled before completion."
        )

    return retained_session if retained_session is not None else cookies


def _safe_close(browser: Any) -> None:
    try:
        browser.close()
    except Exception:
        pass
