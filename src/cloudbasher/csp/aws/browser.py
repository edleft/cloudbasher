"""Playwright-backed AWS CloudShell bootstrap."""

from __future__ import annotations

import atexit
import hashlib
import importlib
import json
import re
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

from cloudbasher.core.browser_profile import context_kwargs as _context_kwargs
from cloudbasher.core.browser_profile import launch_args as _launch_args
from cloudbasher.core.types import (
    CONTROL_PLANE_OK,
    CONTROL_PLANE_UNCONFIRMED,
    CONTROL_PLANE_UNOBSERVABLE,
)
from cloudbasher.core.utils.output import detail, eprint, log, masked_key_id, out
from cloudbasher.core.utils.page_poll import decayed_retry_budget, poll_page_until
from cloudbasher.core.utils.timeline import record_call
from cloudbasher.csp.aws.credentials import AwsSessionCreds, CloudShellBrowserAuthContext
from cloudbasher.csp.aws.playwright_owner import (
    PlaywrightOwner,
    attach_owner,
    owner_for,
    run_owned,
)


_sync_playwright: Any = None
_PlaywrightTimeoutError: type = Exception
_PLAYWRIGHT_IMPORT_ERROR: Optional[Exception] = None
_PLAYWRIGHT_SHADOW_PATH: Optional[Path] = None

_CLOUDSHELL_API_HOST_RE = re.compile(r"^cloudshell\.([^.]+)\.amazonaws\.com$", re.IGNORECASE)


_CONSOLE_API_HOST_RE = re.compile(r"^([a-z0-9-]+)\.console\.aws\.amazon\.com$", re.IGNORECASE)


_PRESIGN_URL_RE = re.compile(r"\.console\.aws\.amazon\.com/api/prod/presign", re.I)


_PRESIGN_SAFE_KEYS = frozenset(
    {"operation", "action", "target", "method", "path", "service", "region", "environmentid"}
)


_LIVE_PLAYWRIGHT_CONTEXTS: list = []


def _fingerprint(value: Optional[str]) -> str:
    """A short, stable, non-reversible tag for a secret, so two secrets can be compared in a log without either appearing in it."""
    if not value:
        return "none"
    return hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:8]


class BrowserAuthCapture:
    """Hooks into Playwright request/response events to capture PKCE fields and the createSession stream/token, persisting each capture immediately via save_browser_auth_context()."""

    def __init__(self) -> None:
        self._contexts: dict[str, CloudShellBrowserAuthContext] = {}


        self._contexts_lock = threading.RLock()


        self._logged_auth_probes: set[tuple[str, str]] = set()


        self._logged_presign: set[tuple[str, ...]] = set()
        self._logged_presign_responses: set[str] = set()


        self._console_request_headers: dict[str, dict[str, str]] = {}


        self._presigned_targets: set[tuple[str, str]] = set()


        self._presigned_regions: set[str] = set()

    def attach(self, target: Any) -> None:
        """Attach to a Playwright Page or BrowserContext."""
        target.on("request", self._on_request)
        target.on("response", self._on_response)


    _TIMED_URL_MARKERS = (
        "cloudshell.",
        "/api/prod/presign",
        "/browserCreds",
        "/redeemCode",
        "/putCredentials",
        "callback.js",
    )

    def _record_browser_timing(self, url: str, response: Any) -> None:
        """Record a call the WIDGET made, which our own client never sees."""
        if not url or not any(m in url for m in self._TIMED_URL_MARKERS):
            return
        try:
            path = urllib.parse.urlparse(url).path
            record_call(
                path.rsplit("/", 1)[-1] or path,
                signing_path="browser",
                region=self._region_from_url(url) or "",
                duration_ms=None,
                status=getattr(response, "status", None),
            )
        except Exception:

            pass

    def context_for_region(self, region: str) -> Optional[CloudShellBrowserAuthContext]:
        return self._contexts.get(region)

    def console_request_headers(self, service: str = "") -> dict[str, str]:
        """The console's own presign request headers, for replaying on ours."""
        if service and service in self._console_request_headers:
            return dict(self._console_request_headers[service])
        if service:
            return {}
        for observed in self._console_request_headers.values():
            return dict(observed)
        return {}

    def presigned_regions(self) -> "set[str]":
        """Regions whose console has presigned here. See `_presigned_regions`."""
        return set(self._presigned_regions)

    def presign_services(self) -> list[str]:
        """Which services the console was observed presigning for."""
        return sorted(self._console_request_headers)

    def presigned_targets(self) -> set[tuple[str, str]]:
        """(service, path) pairs the console asked presign to sign."""
        return set(self._presigned_targets)

    @staticmethod
    def _request_headers(request: Any) -> dict[str, str]:
        """A request's headers, including the ones the browser adds itself."""
        raw: Any = None
        for accessor in ("all_headers", "headers"):
            try:
                attr = getattr(request, accessor, None)
                raw = attr() if callable(attr) else attr
            except Exception:
                raw = None
            if isinstance(raw, dict):
                return {str(k).lower(): str(v) for k, v in raw.items()}
        return {}

    def all_contexts(self) -> list[CloudShellBrowserAuthContext]:
        return list(self._contexts.values())

    def _region_from_url(self, url: str) -> Optional[str]:
        parsed = urllib.parse.urlparse(url)
        m = _CLOUDSHELL_API_HOST_RE.match(parsed.netloc or "")
        return m.group(1) if m else None

    def _parse_post_data(self, request: Any) -> Optional[dict[str, Any]]:
        post_data = getattr(request, "post_data", None)
        if callable(post_data):
            post_data = post_data()
        if not isinstance(post_data, str) or not post_data.strip():
            return None
        try:
            obj = json.loads(post_data)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    def _get_or_create(self, region: str) -> CloudShellBrowserAuthContext:
        if region not in self._contexts:
            self._contexts[region] = CloudShellBrowserAuthContext(
                region=region,
                captured_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                source="playwright",
            )
        return self._contexts[region]

    def _save(self, ctx: CloudShellBrowserAuthContext) -> None:
        from cloudbasher.csp.aws.console_bootstrap import save_browser_auth_context

        ctx.captured_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


        known = getattr(self._contexts.get(ctx.region), "environment_id", "")
        if known and not ctx.environment_id:


            ctx.environment_id = known
        before = ctx.environment_id
        saved = save_browser_auth_context(ctx)
        if before and not saved.environment_id:
            log(
                f"[browser] BUG: environment_id lost in save/merge for "
                f"region={ctx.region} -- had {before}, back with none. "
                f"describeEnvironments will have to recover it."
            )
        self._contexts[ctx.region] = saved

    def _on_request(self, request: Any) -> None:
        url = getattr(request, "url", "")
        self._log_presign_request(request, url)
        region = self._region_from_url(url)
        if not region:
            return
        parsed = urllib.parse.urlparse(url)
        self._log_browser_auth(request, parsed.path)
        payload = self._parse_post_data(request)
        if payload is None:
            return


        with self._contexts_lock:
            self._capture_locked(parsed, region, payload)

    def _capture_locked(self, parsed: Any, region: str, payload: dict) -> None:
        """The body of `_on_request`'s capture, under `_contexts_lock`."""
        ctx = self._get_or_create(region)
        if parsed.path.endswith("/redeemCode"):
            ctx.environment_id = str(
                payload.get("EnvironmentId") or ctx.environment_id or ""
            ).strip()
            ctx.auth_code = str(payload.get("AuthCode") or ctx.auth_code or "").strip()
            ctx.code_verifier = str(payload.get("CodeVerifier") or ctx.code_verifier or "").strip()
            ctx.redirect_uri = str(payload.get("RedirectUri") or ctx.redirect_uri or "").strip()
            ctx.key_base = str(payload.get("KeyBase") or ctx.key_base or "").strip()
            detail(f"[browser] captured redeemCode region={region} env_id={ctx.environment_id}")
            self._save(ctx)
        elif parsed.path.endswith("/putCredentials"):
            ctx.environment_id = str(
                payload.get("EnvironmentId") or ctx.environment_id or ""
            ).strip()
            ctx.refresh_token = str(payload.get("RefreshToken") or ctx.refresh_token or "").strip()
            ctx.key_base = str(payload.get("KeyBase") or ctx.key_base or "").strip()
            detail(f"[browser] captured putCredentials region={region}")
            self._save(ctx)
        elif parsed.path.endswith("/createSession"):
            ctx.environment_id = str(
                payload.get("EnvironmentId") or ctx.environment_id or ""
            ).strip()
            self._save(ctx)

    def _log_presign_request(self, request: Any, url: str) -> None:
        """Record the SHAPE of a /api/prod/presign request."""
        if not _PRESIGN_URL_RE.search(url or ""):
            return


        presign_region = ""
        try:


            m = _CONSOLE_API_HOST_RE.match(urllib.parse.urlparse(url).netloc or "")
            if m and m.group(1).lower() != "global":
                presign_region = m.group(1).lower()
        except Exception:  # noqa: BLE001 - a malformed URL must not kill the capture
            pass
        try:
            method = getattr(request, "method", "") or "?"


            payload = self._parse_post_data(request)
            signed_service = (
                str(payload.get("service") or "?") if isinstance(payload, dict) else "?"
            )
            if isinstance(payload, dict):
                self._presigned_targets.add((signed_service, str(payload.get("path") or "?")))


            try:
                lowered = self._request_headers(request)
                if lowered:
                    marker = ("own", f"{signed_service}:{','.join(sorted(lowered))}")


                    if lowered.get("x-console-api-token"):
                        self._console_request_headers[signed_service] = dict(lowered)


                        if presign_region:
                            self._presigned_regions.add(presign_region)
                    if marker not in self._logged_presign:
                        self._logged_presign.add(marker)


                        detail(
                            f"[browser] browser-auth presign[{signed_service}] "
                            f"widget_id={lowered.get('x-widget-id', '-')!r} "
                            f"widget_stage={lowered.get('x-widget-stage', '-')!r} "
                            f"client_version={lowered.get('x-web-client-version', '-')!r} "
                            f"token_fp={_fingerprint(lowered.get('x-console-api-token'))} "
                            f"console_info_fp={_fingerprint(lowered.get('x-console-info'))}"
                        )
                        detail(
                            f"[browser] browser-auth presign[{signed_service}] OWN "
                            f"request headers={sorted(lowered)} cookie="
                            f"{'yes' if lowered.get('cookie') else 'no'} "
                            f"csrf={'yes' if any('csrf' in k for k in lowered) else 'no'} "
                            f"origin={lowered.get('origin', '-')} "
                            f"referer_host="
                            f"{urllib.parse.urlparse(lowered.get('referer', '')).netloc or '-'}"
                        )
            except Exception:
                pass
            if isinstance(payload, dict):
                shape = ", ".join(f"{k}:{type(v).__name__}" for k, v in sorted(payload.items()))


                target = (
                    str(payload.get("service")),
                    str(payload.get("method")),
                    str(payload.get("path")),
                )


                for nested in ("headers", "query"):
                    inner = payload.get(nested)
                    if isinstance(inner, dict):
                        detail(
                            f"[browser] browser-auth presign[{target[0]}"
                            f"{target[2]}] request {nested} keys={sorted(inner)}"
                        )
                        if nested == "headers":


                            keys = {str(k).lower() for k in inner}
                            detail(
                                f"[browser] browser-auth presign[{target[0]}"
                                f"{target[2]}] pre_signed="
                                f"{'yes' if 'authorization' in keys else 'no'} "
                                f"has_token="
                                f"{'yes' if 'x-amz-security-token' in keys else 'no'}"
                            )


                named = {
                    k: v
                    for k, v in payload.items()
                    if isinstance(v, str) and len(v) <= 64 and k.lower() in _PRESIGN_SAFE_KEYS
                }
            else:
                shape, named = "(no JSON body)", {}
                target = (method, "?", "?")


            dedupe_key = target if isinstance(payload, dict) else (method, shape)
            if dedupe_key in self._logged_presign:
                return
            self._logged_presign.add(dedupe_key)
            detail(
                f"[browser] browser-auth presign target service={target[0]!r} "
                f"method={target[1]!r} path={target[2]!r} "
                f"hostname={payload.get('hostname')!r}"
                if isinstance(payload, dict)
                else "[browser] browser-auth presign target (no JSON body)"
            )
            detail(
                f"[browser] browser-auth presign {method} {urllib.parse.urlparse(url).path} "
                f"body_keys=[{shape}] named={named}"
            )
        except Exception:
            pass

    def _log_presign_response(self, response: Any, url: str) -> None:
        """Record the SHAPE of a /api/prod/presign response -- header names and value lengths, never the values, since they are live signatures."""
        if not _PRESIGN_URL_RE.search(url or ""):
            return
        try:
            if getattr(response, "status", 0) != 200:
                status = getattr(response, "status", "?")
                detail(f"[browser] browser-auth presign response status={status}")
                return
            body = self._response_json(response)
            if not isinstance(body, dict):
                detail("[browser] browser-auth presign response was not a JSON object")
                return

            def _describe(value: Any) -> str:
                if isinstance(value, dict):
                    inner = ", ".join(f"{k}:len{len(str(v))}" for k, v in sorted(value.items()))
                    return "{" + inner + "}"
                if isinstance(value, list):
                    return f"[{len(value)} items]"
                return f"{type(value).__name__}:len{len(str(value))}"

            shape = ", ".join(f"{k}={_describe(v)}" for k, v in sorted(body.items()))
            if shape in self._logged_presign_responses:
                return
            self._logged_presign_responses.add(shape)
            detail(f"[browser] browser-auth presign response shape: {shape}")
        except Exception:
            pass

    def _log_browser_auth(self, request: Any, path: str) -> None:
        """Record HOW the browser authenticates its own CloudShell calls."""
        try:
            lowered = self._request_headers(request)
            if not lowered:
                return
            auth = lowered.get("authorization", "")
            scheme = auth.split(" ", 1)[0] if auth else "(none)"
            key_id = ""


            axis = ""
            m = re.search(r"Credential=([A-Z0-9]+)/([^,\s]*)", auth)
            if m:
                raw_key, scope = m.group(1), m.group(2)
                key_id = f" key={raw_key[:4]}***{raw_key[-4:]} scope={scope}"
                axis = masked_key_id(raw_key)


            presigned = "yes" if ("cloudshell", path) in self._presigned_targets else "no"
            seen_key = (path, f"{scheme}{key_id} presigned={presigned}")
            if seen_key in self._logged_auth_probes:
                return
            self._logged_auth_probes.add(seen_key)
            detail(
                f"[browser] browser-auth {path} scheme={scheme}{key_id} "
                f"presigned={presigned} "
                f"cookie={'yes' if lowered.get('cookie') else 'no'} "
                f"security_token={'yes' if lowered.get('x-amz-security-token') else 'no'} "
                f"csrf={'yes' if lowered.get('x-csrf-token') else 'no'}",
                axis=axis,
            )
        except Exception:
            pass

    def _capture_browser_creds(self, response: Any, url: str) -> None:
        """Store /browserCreds as ``ctx.session_creds``."""
        if "browserCreds" not in url or getattr(response, "status", 0) != 200:
            return
        match = _CONSOLE_API_HOST_RE.match(urllib.parse.urlparse(url).netloc or "")
        if not match:
            return
        payload = self._response_json(response)
        if not isinstance(payload, dict):
            return
        key_id = str(payload.get("accessKeyId") or "").strip()
        secret = str(payload.get("secretAccessKey") or "").strip()
        token = str(payload.get("sessionToken") or "").strip()
        if not (key_id and secret):
            return
        ctx = self._get_or_create(match.group(1))


        ctx.session_creds = AwsSessionCreds(
            access_key=key_id,
            secret_key=secret,
            session_token=token or None,
        )
        self._save(ctx)


        detail(
            f"[browser] captured browserCreds region={match.group(1)} "
            f"key={key_id[:4]}***{key_id[-4:]}",


            axis=ctx.session_creds.identity_axis,
        )

    def _on_response(self, response: Any) -> None:
        url = getattr(response, "url", "")
        self._record_browser_timing(url, response)
        self._log_presign_response(response, url)


        self._capture_browser_creds(response, url)

        region = self._region_from_url(url)
        if not region:
            return
        parsed = urllib.parse.urlparse(url)
        ctx = self._get_or_create(region)
        try:
            headers = response.headers
        except Exception:
            headers = {}
        req_id = None
        if isinstance(headers, dict):
            req_id = headers.get("x-amzn-requestid") or headers.get("x-amzn-RequestId")

        if parsed.path.endswith("/redeemCode"):
            body = self._response_json(response)
            if isinstance(body, dict):
                rt = str(body.get("RefreshToken") or "").strip()
                if rt:
                    ctx.refresh_token = rt
            if req_id:
                ctx.redeem_code_request_id = str(req_id)
            self._save(ctx)
        elif parsed.path.endswith("/putCredentials"):
            if req_id:
                ctx.put_credentials_request_id = str(req_id)
            self._save(ctx)
        elif parsed.path.endswith("/createSession"):
            body = self._response_json(response)
            if isinstance(body, dict):
                stream_url = str(body.get("StreamUrl") or "").strip()
                token_value = str(body.get("TokenValue") or "").strip()
                if stream_url:
                    ctx.captured_stream_url = stream_url
                if token_value:
                    ctx.captured_token_value = token_value
            self._save(ctx)

    def _response_json(self, response: Any) -> Optional[dict[str, Any]]:
        try:
            body = response.json()
        except Exception:
            try:
                body = json.loads(response.text())
            except Exception:
                return None
        return body if isinstance(body, dict) else None


def ensure_playwright_available() -> None:
    """Raise CloudShellAutomationError if playwright is not installed."""
    _load_playwright()
    if _sync_playwright is None:
        install_hint = "Install with: pip install playwright && playwright install chromium"
        if _PLAYWRIGHT_SHADOW_PATH is not None:
            raise RuntimeError(
                f"Playwright shadowed by local file: {_PLAYWRIGHT_SHADOW_PATH}. "
                f"Rename or remove it. {install_hint}"
            )
        if _PLAYWRIGHT_IMPORT_ERROR is not None:
            raise RuntimeError(
                f"Playwright import failed: {_PLAYWRIGHT_IMPORT_ERROR}. {install_hint}"
            )
        raise RuntimeError(f"Playwright is not installed. {install_hint}")


def _load_playwright() -> None:
    global _sync_playwright, _PlaywrightTimeoutError, _PLAYWRIGHT_IMPORT_ERROR, _PLAYWRIGHT_SHADOW_PATH
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


def capture_cloudshell_auth(
    *,
    region: str,
    headless: bool = True,
    reuse_page: bool = False,
    ui_wait_timeout: int = 60,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    federated_login_url: Optional[str] = None,
) -> BrowserAuthCapture:
    """Launch a browser, navigate to AWS CloudShell, and capture PKCE credentials."""
    ensure_playwright_available()

    capture = BrowserAuthCapture()

    launch_kwargs: dict[str, Any] = {"headless": headless, "args": _launch_args()}
    if proxy_url:
        parsed = urllib.parse.urlparse(proxy_url)
        launch_kwargs["proxy"] = {
            "server": f"{parsed.scheme}://{parsed.netloc}",
        }

    log(f"[browser] launching chromium headless={headless} region={region}")
    with _sync_playwright() as pw:
        browser = pw.chromium.launch(**launch_kwargs)
        _extra: dict[str, Any] = {}
        if proxy_insecure and proxy_url:
            _extra["ignore_https_errors"] = True
        ctx = browser.new_context(**_context_kwargs(browser, extra=_extra))
        page = ctx.new_page()

        capture.attach(ctx)

        if federated_login_url:
            log(f"[browser] navigating to federated console URL region={region}")
            page.goto(federated_login_url, timeout=ui_wait_timeout * 1000)
        else:
            cloudshell_url = (
                f"https://{region}.console.aws.amazon.com/cloudshell/home?region={region}"
            )
            log(f"[browser] navigating to CloudShell console region={region}")
            out(f"Opening browser: navigate to CloudShell in region {region}")
            page.goto(cloudshell_url, timeout=ui_wait_timeout * 1000)


        terminal_selector = (
            "textarea[aria-label*='CloudShell terminal input' i], textarea.xterm-helper-textarea"
        )
        try:
            page.wait_for_selector(terminal_selector, timeout=ui_wait_timeout * 1000)
            log(f"[browser] CloudShell terminal detected region={region}")
        except Exception:
            log(f"[browser] terminal selector timeout region={region} — continuing anyway")


        time.sleep(2)
        browser.close()

    region_ctx = capture.context_for_region(region)
    if region_ctx:
        log(
            f"[browser] captured auth env_id={region_ctx.environment_id} has_refresh={bool(region_ctx.refresh_token)}"
        )
    else:
        log(f"[browser] no auth context captured for region={region}")

    return capture


_PRESIGN_TICK_MS = 500


PRESIGN_WAIT_SECONDS = 30

PRESIGN_CONFIRMED = CONTROL_PLANE_OK
PRESIGN_UNOBSERVABLE = CONTROL_PLANE_UNOBSERVABLE
PRESIGN_TIMED_OUT = CONTROL_PLANE_UNCONFIRMED


_presign_timed_out_regions: set = set()


def reset_presign_wait_memo() -> None:
    """Forget every recorded timeout. For tests, and for nothing else."""
    _presign_timed_out_regions.clear()


def await_presign_for_region(
    page: Any, region: str, *, wait_seconds: int = PRESIGN_WAIT_SECONDS
) -> str:
    """Wait, WITHOUT NAVIGATING, until `region`'s console has presigned. `#779`."""
    capture = getattr(page, "_cb_capture", None)
    if capture is None:
        return PRESIGN_UNOBSERVABLE


    repeat = wait_seconds > 0 and region in _presign_timed_out_regions


    budget = decayed_retry_budget(wait_seconds, repeat=repeat)
    if repeat:
        detail(
            f"[browser] {region}: the console chrome was already waited out for "
            f"{wait_seconds}s in this run without presigning, so this attempt asks for "
            f"{budget}s instead of re-paying the full wait for a verdict already reported."
        )


    verdict = run_owned(page, _await_presign_on_owner_thread, page, capture, region, budget)
    if verdict == PRESIGN_TIMED_OUT and wait_seconds > 0:
        _presign_timed_out_regions.add(region)
    return verdict


def _await_presign_on_owner_thread(page: Any, capture: Any, region: str, wait_seconds: int) -> str:
    """The poll itself. MUST run on the thread that owns `page` -- see `#791`."""

    def _presigned() -> bool:
        try:
            return region in capture.presigned_regions()
        except Exception:  # noqa: BLE001 - a capture that cannot answer is a miss
            return False


    outcome = poll_page_until(
        page, until=_presigned, budget_ms=max(0, wait_seconds) * 1000, tick_ms=_PRESIGN_TICK_MS
    )
    if not outcome.timed_out:
        return PRESIGN_CONFIRMED


    detail(f"[browser] no presign for region={region} — {outcome.observed()}")
    return PRESIGN_TIMED_OUT


def bootstrap_via_console_login(
    *,
    pw_creds: Any,
    region: str,
    env_id: str,
    headless: bool = True,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    mfa_timeout: int = 120,
    ui_wait_timeout: int = 60,
) -> dict[str, Any]:
    """Log in via Playwright (username/password or SSO) and bootstrap a CloudShell session -- the console-credentials path, which never uses PKCE redeemCode/putCredentials because the browser's own console login already carries a valid identity."""
    from cloudbasher.csp.aws.playwright_login import playwright_console_bootstrap

    browser, context, page, capture = playwright_console_bootstrap(
        creds=pw_creds,
        region=region,
        headless=headless,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
        mfa_timeout=mfa_timeout,
        ui_wait_timeout=ui_wait_timeout,
    )

    ctx = capture.context_for_region(region)
    resolved_env_id = (ctx.environment_id if ctx else "") or env_id
    if not resolved_env_id:


        detail(
            f"[browser] no environment id for region={region}: "
            f"context={'present' if ctx else 'MISSING'} "
            f"known_regions={sorted(capture._contexts)}"
        )


    presign = await_presign_for_region(page, region)
    if presign != PRESIGN_CONFIRMED:


        eprint(
            f"[browser] {region}: the shell is live but this session has NO "
            f"CONTROL-PLANE IDENTITY ({presign}). Commands will work; every CloudShell "
            f"API call -- the heartbeat, .start, .stop, .delete -- will answer HTTP 401."
        )
        log(
            f"[browser] NO PRESIGN IDENTITY for region={region} ({presign}). presign "
            f"replays `x-console-api-token` from a presign the console itself made, and "
            f"this session's console has made none: the CloudShell widget signs its own "
            f"calls with a browserCreds key and never presigns, so the token can only "
            f"come from the console chrome (`console-control`, `userprefs`), on the "
            f"console's own cadence. Reconnecting the node re-runs the login."
        )
    log(
        f"[browser] session live in browser region={region} "
        f"env={resolved_env_id or '?'} presign={presign}"
    )
    return {
        "environment_id": resolved_env_id,
        "page": page,
        "context": context,
        "browser": browser,
        "presign": presign,
    }


def playwright_fallback_execute(
    page: Any,
    command: str,
    *,
    timeout: int = 30,
    poll_interval: float = 1.0,
) -> str:
    """Type a shell command into the CloudShell terminal and return its output."""


    return run_owned(page, _fallback_execute_on_owner_thread, page, command, timeout, poll_interval)


_PROMPT_GRACE_SECONDS = 3.0


_PROMPT_GRACE_TICK_MS = 250


def _fallback_execute_on_owner_thread(
    page: Any, command: str, timeout: int, poll_interval: float
) -> str:
    from cloudbasher.core.exceptions import CloudShellAutomationError
    from cloudbasher.core.utils.output import strip_ansi
    from cloudbasher.csp.aws.cloudshell_terminal import (
        describe_terminal_state,
        extract_between_markers,
        focus_terminal,
        make_output_markers,
        read_terminal_snapshot,
        terminal_prompt_visible,
        wrap_command_with_markers,
    )

    if not focus_terminal(page):
        raise CloudShellAutomationError(
            "playwright_fallback_execute: could not focus the CloudShell terminal — "
            f"{describe_terminal_state(page)}.\n"
            "Nothing was typed. The page is not showing a usable shell: it may still "
            "be loading, the widget may not be open, or the session may have been "
            "taken over in another tab."
        )


    prompt = poll_page_until(
        page,
        until=lambda: terminal_prompt_visible(page),
        budget_ms=int(_PROMPT_GRACE_SECONDS * 1000),
        tick_ms=_PROMPT_GRACE_TICK_MS,
    )
    if prompt.timed_out:
        raise CloudShellAutomationError(
            "playwright_fallback_execute: no shell prompt on this page — "
            f"{describe_terminal_state(page)}.\n"
            f"Waited: {prompt.observed()}.\n"
            "Nothing was typed. The terminal widget is present but there is "
            "nothing behind it -- typically the container was suspended or "
            "restarted while this browser stayed open. Reconnect the node."
        )


    start, end, _token = make_output_markers()
    typed = wrap_command_with_markers(command, start, end)


    try:
        page.keyboard.insert_text(typed)
    except Exception:
        page.keyboard.type(typed)
    page.keyboard.press("Enter")

    deadline = time.time() + timeout
    output = None
    while time.time() < deadline:
        time.sleep(poll_interval)
        snapshot = strip_ansi(read_terminal_snapshot(page))


        output = extract_between_markers(snapshot, start, end)
        if output is not None:
            break

    if output is None:
        raise CloudShellAutomationError(
            f"playwright_fallback_execute: the command did not finish within "
            f"{timeout}s — {describe_terminal_state(page)}"
        )
    return output


def launch_playwright_browser(
    *,
    headless: bool = True,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    owner: Optional[Any] = None,
) -> tuple:
    """Launch a Playwright Chromium browser and return (browser, context, page)."""

    ensure_playwright_available()

    launch_kwargs: dict[str, Any] = {"headless": headless, "args": _launch_args()}
    if proxy_url:
        parsed = urllib.parse.urlparse(proxy_url)
        launch_kwargs["proxy"] = {"server": f"{parsed.scheme}://{parsed.netloc}"}

    pw_owner = owner if owner is not None else PlaywrightOwner()
    return pw_owner.call(
        _launch_on_owner_thread, pw_owner, launch_kwargs, proxy_url, proxy_insecure, headless
    )


def _launch_on_owner_thread(
    pw_owner: Any,
    launch_kwargs: dict,
    proxy_url: Optional[str],
    proxy_insecure: bool,
    headless: bool,
) -> tuple:
    """The body of launch_playwright_browser(), which must run ON the owner thread -- the objects are bound to whichever thread creates them."""

    pw_ctx = _sync_playwright().__enter__()
    browser = pw_ctx.chromium.launch(**launch_kwargs)
    _extra: dict[str, Any] = {}
    if proxy_insecure and proxy_url:
        _extra["ignore_https_errors"] = True
    context = browser.new_context(**_context_kwargs(browser, extra=_extra))
    page = context.new_page()


    try:
        browser._cb_pw_ctx = pw_ctx
    except Exception:
        pass


    for handle in (browser, context, page):
        attach_owner(handle, pw_owner)


    _LIVE_PLAYWRIGHT_CONTEXTS.append((pw_ctx, pw_owner))
    log(f"[browser] launched chromium headless={headless}")
    return browser, context, page


def close_playwright_browser(browser: Any, context: Any = None, page: Any = None) -> None:
    """Close a browser AND stop the Playwright driver behind it."""

    owner = owner_for(browser, context, page)
    if owner is not None and not owner.is_owner_thread():
        owner.call(_close_on_owner_thread, browser, context, page)
        owner.shutdown()
        return
    _close_on_owner_thread(browser, context, page)
    if owner is not None:
        owner.shutdown()


def _close_on_owner_thread(browser: Any, context: Any = None, page: Any = None) -> None:
    for closer in (page, context, browser):
        if closer is None:
            continue
        try:
            closer.close()
        except Exception:
            pass
    pw_ctx = getattr(browser, "_cb_pw_ctx", None)
    if pw_ctx is None:
        return
    try:
        pw_ctx.__exit__(None, None, None)
    except Exception:
        try:
            pw_ctx.stop()
        except Exception:
            pass
    for entry in list(_LIVE_PLAYWRIGHT_CONTEXTS):
        if entry[0] is pw_ctx:
            _LIVE_PLAYWRIGHT_CONTEXTS.remove(entry)


def _stop_leaked_playwright_contexts() -> None:
    """atexit backstop: stop any driver a failure path never closed."""
    for entry in list(_LIVE_PLAYWRIGHT_CONTEXTS):
        pw_ctx, owner = entry
        try:
            if owner is not None and not owner.is_owner_thread():
                owner.call(pw_ctx.__exit__, None, None, None)
                owner.shutdown(wait=False)
            else:
                pw_ctx.__exit__(None, None, None)
        except Exception:
            pass
    _LIVE_PLAYWRIGHT_CONTEXTS.clear()


atexit.register(_stop_leaked_playwright_contexts)


def _safe_screenshot(page: Any, label: str) -> None:
    try:
        path = Path("/tmp") / f"cloudshell_{label}_{int(time.time())}.png"
        page.screenshot(path=str(path), full_page=True)
        log(f"[browser] screenshot saved path={path}")
    except Exception as exc:
        log(f"[browser] screenshot failed: {exc}")
