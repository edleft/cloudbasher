"""Credential-scope control-plane clients -- `#455`."""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Optional

from cloudbasher.core.browser_options import BrowserOptions
from cloudbasher.core.utils.output import detail, eprint
from cloudbasher.core.utils.page_poll import decayed_retry_budget
from cloudbasher.csp.aws.browser import (
    PRESIGN_CONFIRMED,
    PRESIGN_TIMED_OUT,
    PRESIGN_UNOBSERVABLE,
    await_presign_for_region,
)
from cloudbasher.csp.aws.playwright_owner import run_owned


__all__ = [
    "ConsoleSourcePool",
    "ControlPlaneSource",
    "ControlPlaneUnavailable",
    "control_plane_source",
    "forget_login_failures",
    "has_remembered_login_failure",
    "remembered_login_failure",
]


class ControlPlaneUnavailable(Exception):
    """This credential cannot drive control-plane calls, and why."""


class ControlPlaneSource:
    """Control-plane clients for ONE credential, across any number of regions."""

    kind = "unknown"


    blocked_write_urls: "list[str]" = []


    _closed: bool = False


    enumerates: bool = True


    pooled: bool = False

    def client_for(self, region: str) -> Any:
        raise NotImplementedError

    def close(self) -> None:
        """Release anything held. Idempotent."""

    def __enter__(self) -> "ControlPlaneSource":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


class _SigV4Source(ControlPlaneSource):
    """Locally signed, one client per region, nothing to release."""

    kind = "sigv4"

    def __init__(self, creds: Any, *, timeout: int = 30) -> None:
        self._creds = creds
        self._timeout = timeout
        self._clients: dict[str, Any] = {}

    @property
    def credentials(self) -> Any:
        """The signing credentials, for the callers that need more than the control-plane subset -- CloudTrail and STS are not CloudShell calls and cannot go through a client from `client_for()`."""
        return self._creds

    def client_for(self, region: str) -> Any:
        from cloudbasher.csp.aws.api import AWSCloudShellAPI


        if region not in self._clients:
            self._clients[region] = AWSCloudShellAPI(
                region=region, credentials=self._creds, timeout=self._timeout
            )
        return self._clients[region]


MAY_PROVISION: "dict[str, str]" = {
    "cloudbasher.csp.aws.browser:bootstrap_via_console_login": (
        "`.provision` and `.connect` on a console credential. Creating is the job: "
        "it opens the CloudShell widget deliberately (`open_cloudshell=True`)."
    ),
    "scripts/aws/probe_widget_autoload.py:main": (
        "`#496`. Its session-establishing arms (`w2`/`w3`/`w5`) must provision in the "
        "HOME region on purpose -- that provisioning IS the setup whose effect the arm "
        "then observes elsewhere. It passes `block_provisioning=False` and installs the "
        "block itself via `arm_block()` once setup is done, so the OBSERVED regions are "
        "covered. The callee-installed default aborted the setup and voided `w3` a third "
        "time; the owner's screenshot of 'Unable to create the environment' was that."
    ),
}


_FORBIDDEN_ON_A_READ_ONLY_SOURCE = ("**/createEnvironment", "**/startEnvironment")


def _block_provisioning(context: Any, blocked: "Optional[list]" = None) -> None:
    """Make "read-only" STRUCTURAL for this browser. `#495`."""

    def _refuse(route: Any) -> None:


        url = "?"
        try:
            url = str(getattr(getattr(route, "request", None), "url", "?"))
            if blocked is not None:
                blocked.append(url)


            eprint(
                "[control-plane] BLOCKED a provisioning attempt by the CloudShell "
                f"widget during a read-only operation -- no environment was created: {url}"
            )
        except Exception:  # noqa: BLE001 - never let bookkeeping stop the abort
            pass
        route.abort("blockedbyclient")

    try:
        for pattern in _FORBIDDEN_ON_A_READ_ONLY_SOURCE:
            context.route(pattern, _refuse)
        detail(
            "[control-plane] read-only browser: createEnvironment/startEnvironment "
            "are blocked at the network layer"
        )
    except Exception as exc:  # noqa: BLE001


        eprint(
            f"[control-plane] WARNING: COULD NOT block provisioning on this browser ({exc}) -- "
            "the CloudShell widget may create an environment in an empty region"
        )


class _ConsoleSource(ControlPlaneSource):
    """Signed by the console, through one browser login shared by every region."""

    kind = "console"


    _CONSOLE_HOME = "https://{region}.console.aws.amazon.com/console/home?region={region}"


    _TOKEN_WAIT_SECONDS = 15


    _PREPARE_ATTEMPTS = 2

    def __init__(
        self,
        pw_creds: Any,
        *,
        timeout: int = 30,
        browser: "Optional[BrowserOptions]" = None,
    ) -> None:
        self._pw_creds = pw_creds


        self._browser_opts = browser or BrowserOptions()
        self._timeout = timeout
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._clients: dict[str, Any] = {}


        self._page_refresh_lock = threading.Lock()


        self._prepared: set[str] = set()


        self._unconfirmable: set[str] = set()


        self._logged_in_at: float = 0.0


        self.blocked_write_urls: list[str] = []

    def _login_is_usable(self) -> bool:
        """Is the cached login still worth handing out? `#553`."""
        try:
            if self._page is None or self._page.is_closed():
                return False
            if self._browser is not None and not self._browser.is_connected():
                return False
        except Exception:  # noqa: BLE001 - a probe that cannot answer means "no"
            return False
        return (time.monotonic() - self._logged_in_at) < self._browser_opts.login_ttl_seconds

    def _ensure_login(self, region: str) -> Any:
        """Log in once, lazily, and keep the page."""
        if self._page is not None:
            if self._login_is_usable():
                return self._page
            self._teardown_login("console login is stale or dead -- rebuilding it")
        from cloudbasher.csp.aws.playwright_login import playwright_console_bootstrap

        try:
            browser, context, page, capture = playwright_console_bootstrap(
                creds=self._pw_creds,
                region=region,
                headless=self._browser_opts.headless,


                proxy_url=self._browser_opts.proxy_url,
                proxy_insecure=self._browser_opts.proxy_insecure,
                ui_wait_timeout=self._browser_opts.ui_wait_timeout,
                open_cloudshell=False,


                block_provisioning=True,
                blocked_writes=self.blocked_write_urls,
            )
        except Exception as exc:  # noqa: BLE001 - reported against the credential
            raise ControlPlaneUnavailable(
                f"console login failed: {type(exc).__name__}: {exc}"
            ) from exc


        del capture
        self._browser, self._context, self._page = browser, context, page
        self._logged_in_at = time.monotonic()


        try:
            landed = str(getattr(page, "url", "") or "")
        except Exception:  # noqa: BLE001 - a diagnostic must not break the login
            landed = ""
        if landed:
            detail(f"[console] login landed on {landed} (asked for {region})")


        return page

    @staticmethod
    def _visit_console_home(page: Any, region: str, wait_seconds: int) -> str:
        """Land on `region`'s console and wait for THAT REGION to presign."""


        if await_presign_for_region(page, region, wait_seconds=0) == PRESIGN_CONFIRMED:
            return PRESIGN_CONFIRMED
        page.goto(
            _ConsoleSource._CONSOLE_HOME.format(region=region),
            wait_until="domcontentloaded",
            timeout=60000,
        )


        observed = await_presign_for_region(page, region, wait_seconds=wait_seconds)
        if observed == PRESIGN_TIMED_OUT:
            detail(
                f"[control-plane] {region}: no presign from that region's console within "
                f"{wait_seconds}s -- proceeding; presign will answer 401 if the region "
                f"really was never loaded"
            )
        return observed

    def _prepare(self, page: Any, region: str) -> None:
        """Make `page` able to presign for `region`. Once per confirmed region."""
        if region in self._prepared or region in self._unconfirmable:
            return
        for attempt in range(self._PREPARE_ATTEMPTS):


            budget = decayed_retry_budget(self._TOKEN_WAIT_SECONDS, repeat=attempt != 0)
            seen = run_owned(page, self._visit_console_home, page, region, budget)
            if seen == PRESIGN_CONFIRMED:
                self._prepared.add(region)
                return
            if seen == PRESIGN_UNOBSERVABLE:


                self._unconfirmable.add(region)
                return
        detail(
            f"[control-plane] {region}: not confirmed after {self._PREPARE_ATTEMPTS} "
            "console visit(s) -- proceeding; presign will answer if it really "
            "was never loaded"
        )
        self._unconfirmable.add(region)

    def client_for(self, region: str) -> Any:
        from cloudbasher.csp.aws.console_api import ConsoleCloudShellAPI

        page = self._ensure_login(region)
        self._prepare(page, region)
        if region not in self._clients:
            self._clients[region] = ConsoleCloudShellAPI(
                page,
                region=region,
                timeout=self._timeout,
                refresh_page=lambda stale_page: self._refresh_page_after_presign_refusal(
                    stale_page, region
                ),
            )
        return self._clients[region]

    def _refresh_page_after_presign_refusal(self, stale_page: Any, region: str) -> Any:
        """Replace one refused browser page and prepare ``region`` once."""
        with self._page_refresh_lock:
            if self._page is stale_page:
                self._teardown_login("console presign refused -- rebuilding login once")
                page = self._ensure_login(region)
            else:
                page = self._ensure_login(region)
            self._prepare(page, region)
            return page

    def _teardown_login(self, note: str = "") -> None:
        """Close the browser and forget EVERYTHING DERIVED FROM IT. `#553`."""
        browser = self._browser
        self._browser, self._context, self._page = None, None, None
        self._logged_in_at = 0.0
        self._clients.clear()
        self._prepared.clear()
        self._unconfirmable.clear()
        if browser is None:
            return
        if note:
            detail(f"[control-plane] {note}")
        from cloudbasher.csp.aws.browser import close_playwright_browser

        try:
            close_playwright_browser(browser)
        except Exception as exc:  # noqa: BLE001 - a leak beats a failed command


            detail(f"[control-plane] could not close the login: {exc}")

    def close(self) -> None:
        self._teardown_login()


def clear_blocked_write_urls_of(source: Any) -> None:
    """Forget a source's refused writes, IN PLACE. `#553`."""
    urls = getattr(source, "blocked_write_urls", None)
    if isinstance(urls, list):
        urls.clear()


def blocked_write_urls_of(source: Any) -> "list[str]":
    """Provisioning attempts this source REFUSED. `#497`/`#506`."""
    return list(getattr(source, "blocked_write_urls", ()) or ())


_LOGIN_FAILURE_TTL_SECONDS = 300.0


_LOGIN_FAILURES: "dict[str, tuple[float, str]]" = {}


_LOGIN_FAILURES_LOCK = threading.Lock()


def _lookup_login_failure(key: str) -> "Optional[tuple[float, str]]":
    """`(age in seconds, why)` for a live remembered failure, or None."""
    with _LOGIN_FAILURES_LOCK:
        hit = _LOGIN_FAILURES.get(key)
        if hit is None:
            return None
        when, reason = hit
        age = time.monotonic() - when
        if age >= _LOGIN_FAILURE_TTL_SECONDS:


            _LOGIN_FAILURES.pop(key, None)
            return None
    return age, reason


def has_remembered_login_failure(key: str) -> bool:
    """Would a login for `key` be refused from the memo without being tried?"""
    return _lookup_login_failure(key) is not None


def remembered_login_failure(key: str) -> Optional[str]:
    """Why this credential's login failed recently, as a sentence, or None."""
    hit = _lookup_login_failure(key)
    if hit is None:
        return None
    age, reason = hit
    return (
        f"{reason} -- remembered from an earlier command {int(age)}s ago and not retried; "
        f"it will be retried after {int(_LOGIN_FAILURE_TTL_SECONDS)}s"
    )


def _remember_login_failure(key: str, reason: str) -> None:
    """Record why this credential's login failed, for the next command."""
    with _LOGIN_FAILURES_LOCK:
        _LOGIN_FAILURES[key] = (time.monotonic(), reason)


def _record_failure(entry: "_PoolEntry", key: str, exc: BaseException) -> None:
    """Remember why a login failed -- on the pool ENTRY and in the cross-command memo, which are one fact written to two lifetimes."""
    entry.error = f"{type(exc).__name__}: {exc}"
    _remember_login_failure(key, entry.error)


def forget_login_failures(key: Optional[str] = None) -> None:
    """Forget remembered login failures -- one credential's, or all of them."""
    with _LOGIN_FAILURES_LOCK:
        if key is None:
            _LOGIN_FAILURES.clear()
        else:
            _LOGIN_FAILURES.pop(key, None)


def _seed_error(entry: "_PoolEntry", key: str) -> None:
    """Point `entry.error` at what the failure store currently remembers."""
    entry.error = remembered_login_failure(key)


class _PoolEntry:
    """One credential's source, its own lock, and its failure if it had one."""

    __slots__ = ("lock", "source", "error")

    def __init__(self) -> None:


        self.lock = threading.Lock()
        self.source: Optional[ControlPlaneSource] = None
        self.error: Optional[str] = None


class ConsoleSourcePool:
    """One login per credential, shared by every region asking for it. `#493`."""

    def __init__(self) -> None:
        self._entries: dict[str, _PoolEntry] = {}

        self._lock = threading.Lock()

    def _entry(self, key: str) -> _PoolEntry:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                entry = self._entries[key] = _PoolEntry()


                _seed_error(entry, key)
            return entry

    def begin_command(self) -> None:
        """Start a command against this pool. `#553`."""
        with self._lock:
            entries = list(self._entries.items())
        for key, entry in entries:


            with entry.lock:
                _seed_error(entry, key)

    def source_for(self, key: str, factory: "Callable[[], ControlPlaneSource]") -> Any:
        """This credential's source, building it at most once. `#506`."""
        entry = self._entry(key)
        with entry.lock:
            if entry.error is not None:
                raise ControlPlaneUnavailable(entry.error)
            if entry.source is None:
                try:
                    entry.source = factory()
                except Exception as exc:  # noqa: BLE001 - remembered, then re-raised
                    _record_failure(entry, key, exc)
                    raise


                entry.source.pooled = True
            return entry.source

    def client_for(self, key: str, region: str, factory: "Callable[[], ControlPlaneSource]") -> Any:
        """A client for `region`, logging in at most once per `key`."""


        source = self.source_for(key, factory)
        entry = self._entry(key)
        with entry.lock:
            try:
                return source.client_for(region)
            except Exception as exc:


                if isinstance(exc, ControlPlaneUnavailable):
                    _record_failure(entry, key, exc)
                raise

    def blocked_writes(self) -> "dict[str, list[str]]":
        """Refused provisioning attempts, per credential. `#496`."""
        return self._collect_blocked_writes(clear=False)

    def drain_blocked_writes(self) -> "dict[str, list[str]]":
        """`blocked_writes()`, and then FORGET them. `#553`."""
        return self._collect_blocked_writes(clear=True)

    def _collect_blocked_writes(self, *, clear: bool) -> "dict[str, list[str]]":
        """ONE walk, ONE lock acquisition, read-then-clear per source."""
        with self._lock:
            entries = list(self._entries.items())
        out: dict[str, list[str]] = {}
        for key, entry in entries:
            if entry.source is None:


                continue
            urls = blocked_write_urls_of(entry.source)
            if clear:
                clear_blocked_write_urls_of(entry.source)
            if urls:
                out[key] = urls
        return out

    def close(self) -> None:
        """Close every login. Idempotent, and never raises."""
        with self._lock:
            entries, self._entries = list(self._entries.items()), {}
        for key, entry in entries:
            if entry.source is None:
                continue
            try:
                entry.source.close()
            except Exception as exc:  # noqa: BLE001 - a leak beats a lost result
                detail(f"[control-plane] could not close the login for {key}: {exc}")

    def __enter__(self) -> "ConsoleSourcePool":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


_CONSOLE_POOL_KEY = "aws_console_pool"


def session_console_pool(state: Any) -> ConsoleSourcePool:
    """THE session's console-login pool, built on first use. `#553`."""
    if state.extra is None:
        state.extra = {}
    pool = state.extra.get(_CONSOLE_POOL_KEY)
    if not isinstance(pool, ConsoleSourcePool):
        pool = state.extra[_CONSOLE_POOL_KEY] = ConsoleSourcePool()
    pool.begin_command()
    return pool


def close_session_console_pool(state: Any) -> None:
    """Release the session's console logins. `#553`. Called by the PROVIDER."""
    extra = getattr(state, "extra", None)
    if not isinstance(extra, dict):
        return
    pool = extra.pop(_CONSOLE_POOL_KEY, None)
    if pool is None:
        return
    try:
        pool.close()
    except Exception as exc:  # noqa: BLE001 - a leak must not block the exit
        detail(f"[control-plane] could not close the session's console logins: {exc}")


def control_plane_source(
    record: Any, *, timeout: int = 30, browser: "Optional[BrowserOptions]" = None
) -> ControlPlaneSource:
    """A control-plane source for one `CredentialRecord`."""
    if getattr(record, "provider", None) != "aws":
        raise ControlPlaneUnavailable(
            f"{getattr(record, 'provider', 'unknown')} credential cannot sign "
            "AWS control-plane requests"
        )
    extra = dict(getattr(getattr(record, "raw", None), "extra", {}) or {})

    if extra.get("access_key"):


        from cloudbasher.csp.aws.commands import _session_creds_for

        return _SigV4Source(_session_creds_for(record), timeout=timeout)


    opts = browser or BrowserOptions()

    from cloudbasher.csp.aws.commands import _browser_creds_for
    from cloudbasher.csp.aws.credentials import is_sso_extra

    parsed = _browser_creds_for(extra)
    if parsed is None:
        raise ControlPlaneUnavailable(
            "no access key, and neither a console nor an SSO block -- nothing to sign with"
        )

    if is_sso_extra(extra):


        from cloudbasher.csp.aws.commands import _session_creds_for
        from cloudbasher.csp.aws.credentials import (
            merge_sso_keys,
            resolve_sso_to_keys,
            sso_cannot_self_serve,
        )

        if sso_cannot_self_serve(parsed):
            raise ControlPlaneUnavailable(
                "SSO block declares neither a portal login (SSO_USERNAME/SSO_PASSWORD) "
                "nor SSO_FLOW=device, so it cannot sign itself in"
            )
        try:
            resolved = resolve_sso_to_keys(
                parsed,
                headless=opts.headless,
                proxy_url=opts.proxy_url,
                proxy_insecure=opts.proxy_insecure,
            )
        except Exception as exc:  # noqa: BLE001
            raise ControlPlaneUnavailable(f"SSO login failed: {type(exc).__name__}: {exc}") from exc


        merge_sso_keys(record.raw.extra, resolved)
        return _SigV4Source(_session_creds_for(record), timeout=timeout)


    return _ConsoleSource(parsed, timeout=timeout, browser=opts)
