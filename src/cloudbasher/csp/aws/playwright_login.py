"""Playwright-based login flow for AWS console authentication."""

from __future__ import annotations

import re
import threading
import time
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, Iterator, Optional, Union

from cloudbasher.core.exceptions import CloudShellAutomationError, LoginGateExceeded
from cloudbasher.core.keyed_locks import KeyedLocks
from cloudbasher.core.mfa import (
    FACTOR_SETTLE_MS,
    MAX_FACTOR_ATTEMPTS,
    FactorPrompt,
    MfaSource,
    declared_note,
    mfa_source,
)
from cloudbasher.core.utils.output import log, out
from cloudbasher.core.utils.timeline import span as timeline_span
from cloudbasher.csp.aws.browser import (
    BrowserAuthCapture,
    PRESIGN_CONFIRMED,
    _safe_screenshot,
    await_presign_for_region,
    close_playwright_browser,
    ensure_playwright_available,
    launch_playwright_browser,
)
from cloudbasher.csp.aws.credentials import (
    CONSOLE_MFA_KEYS,
    AwsConsoleCreds,
    AwsSSOCreds,
    CloudShellBrowserAuthContext,
)

if TYPE_CHECKING:
    pass


def playwright_browser_auth(
    *,
    creds: Union[AwsConsoleCreds, AwsSSOCreds],
    region: str,
    headless: bool = True,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    mfa_timeout: int = 120,
    ui_wait_timeout: int = 60,
) -> CloudShellBrowserAuthContext:
    """Authenticate via Playwright browser and capture CloudShell PKCE tokens."""
    ensure_playwright_available()

    if isinstance(creds, AwsConsoleCreds):
        return _password_login_flow(
            creds,
            region=region,
            headless=headless,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
            mfa_timeout=mfa_timeout,
            ui_wait_timeout=ui_wait_timeout,
        )
    if isinstance(creds, AwsSSOCreds):


        raise TypeError(
            "AwsSSOCreds no longer authenticates through the browser bootstrap. "
            "It resolves to key material via credentials.resolve_sso_to_keys(), "
            "which happens at the credential-load boundary -- reaching here "
            "means an SSO credential was routed past that."
        )
    raise TypeError(f"Unsupported credential type: {type(creds)}")


_LOGIN_GATE = KeyedLocks()


def _login_gate_key(creds: AwsConsoleCreds) -> str:
    """What counts as "the same identity" for the sign-in gate AND its memo."""
    return f"console-signin:{creds.username or ''}|{creds.account or ''}"


_LOGIN_GATE_HOLD_BUDGET_SECONDS = 165


_LOGIN_GATE_PACE_SECONDS = 30


_LOGIN_GATE_RC_KEY = "net.login_gate_timeout"


def _login_gate_budget() -> Optional[float]:
    """The hold budget in seconds, or None for "wait forever" (the old path)."""
    try:
        from cloudbasher.core.config import active_config

        raw = active_config().get_int(_LOGIN_GATE_RC_KEY, _LOGIN_GATE_HOLD_BUDGET_SECONDS)
    except Exception:  # noqa: BLE001 - see docstring; an rc read may not raise here
        raw = _LOGIN_GATE_HOLD_BUDGET_SECONDS
    return None if raw <= 0 else float(raw)


class _GateHold:
    """One worker's hold on `_LOGIN_GATE`, and what it is doing with it."""

    __slots__ = ("key", "budget_s", "_t0", "_phase", "_lock")

    def __init__(self, key: str, budget_s: Optional[float]) -> None:
        self.key = key
        self.budget_s = budget_s
        self._t0 = time.monotonic()
        self._phase = "acquired"
        self._lock = threading.Lock()

    @property
    def phase(self) -> str:
        with self._lock:
            return self._phase

    def elapsed(self) -> float:
        return time.monotonic() - self._t0

    def enter_phase(self, name: str) -> None:
        with self._lock:
            self._phase = name

    def remaining(self) -> Optional[float]:
        """Seconds left, or None when unbounded. Callers CLAMP with it."""
        if self.budget_s is None:
            return None
        return max(0.0, self.budget_s - self.elapsed())

    def check(self, page: Any = None) -> None:
        """Raise if this hold has outstayed its budget -- WITH WHAT IT SAW."""
        if self.budget_s is None or self.elapsed() <= self.budget_s:
            return
        try:
            url = getattr(page, "url", None) or "unknown"
        except Exception:  # noqa: BLE001 - a page that refuses attributes is a test double
            url = "unavailable"
        raise LoginGateExceeded(
            f"console sign-in held the gate {self.elapsed():.1f}s, past its "
            f"{self.budget_s:.0f}s budget ({_LOGIN_GATE_RC_KEY}).\n"
            f"  identity={self.key}\n"
            f"  It was in phase {self.phase!r} when the budget ran out; page url={url}.\n"
            "  The gate admits ONE sign-in per identity (`#777`/`#493`) and every other\n"
            "  region queues behind this hold, which is why it is capped rather than\n"
            "  left to run. The gate itself was NOT widened.\n"
            f"  Restore the old unbounded hold with -o {_LOGIN_GATE_RC_KEY}=0."
        )


class _GateTraffic:
    """How many sign-ins are in the gate for one identity, and who holds it."""

    __slots__ = ("_lock", "_depth", "_holder")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._depth: dict[str, int] = {}
        self._holder: dict[str, _GateHold] = {}

    def arrive(self, key: str) -> int:
        """Register a new arrival; return how many were already inside."""
        with self._lock:
            ahead = self._depth.get(key, 0)
            self._depth[key] = ahead + 1
            return ahead

    def depart(self, key: str) -> None:
        with self._lock:
            left = self._depth.get(key, 1) - 1
            if left > 0:
                self._depth[key] = left
            else:
                self._depth.pop(key, None)

    def took(self, key: str, hold: _GateHold) -> None:
        with self._lock:
            self._holder[key] = hold

    def released(self, key: str) -> None:
        with self._lock:
            self._holder.pop(key, None)

    def depth(self, key: str) -> int:
        with self._lock:
            return self._depth.get(key, 0)

    def holder_note(self, key: str) -> str:
        """What the holder is doing and for how long, in one line."""
        with self._lock:
            hold = self._holder.get(key)
        if hold is None:
            return "no holder recorded -- it released while this waiter was giving up"
        return f"the holder has been in phase {hold.phase!r} for {hold.elapsed():.1f}s"


_GATE_TRAFFIC = _GateTraffic()


@contextmanager
def _login_gate_hold(key: str) -> "Iterator[_GateHold]":
    """`_LOGIN_GATE.lock_for(key)`, BOUNDED IN BOTH DIRECTIONS. `#856`."""
    budget = _login_gate_budget()
    ahead = _GATE_TRAFFIC.arrive(key)
    lock = _LOGIN_GATE.lock_for(key)
    wait_budget = None if budget is None else budget + _LOGIN_GATE_PACE_SECONDS * ahead
    try:
        with timeline_span("browser.login_gate_wait", ahead=ahead) as _w:
            granted = lock.acquire() if wait_budget is None else lock.acquire(timeout=wait_budget)
            _w["granted"] = granted
            _w["budget_s"] = wait_budget
        if not granted:
            raise LoginGateExceeded(
                f"console sign-in waited {wait_budget:.0f}s for the sign-in gate and "
                "never got in.\n"
                f"  identity={key}\n"
                f"  {ahead} sign-in(s) were ahead of it when it arrived; "
                f"{_GATE_TRAFFIC.depth(key) - 1} are in the gate now.\n"
                f"  {_GATE_TRAFFIC.holder_note(key)}\n"
                "  The gate admits ONE console sign-in per identity on purpose "
                "(`#777`/`#493`:\n"
                "  sixteen concurrent sign-ins lost 7-8 of 16 regions, twice). It was "
                "NOT widened.\n"
                f"  Budget = {budget:.0f}s hold + {_LOGIN_GATE_PACE_SECONDS}s x {ahead} ahead.\n"
                f"  Restore the old unbounded wait with -o {_LOGIN_GATE_RC_KEY}=0."
            )
        hold = _GateHold(key, budget)
        _GATE_TRAFFIC.took(key, hold)
        try:
            with timeline_span("browser.login_gate_hold", ahead=ahead) as _h:
                try:
                    yield hold
                finally:


                    _h["phase"] = hold.phase
                    _h["budget_s"] = budget
        finally:
            _GATE_TRAFFIC.released(key)
            lock.release()
    finally:
        _GATE_TRAFFIC.depart(key)


def _refuse_if_remembered(key: str) -> None:
    """Raise if this identity's sign-in failed recently, naming why."""
    from cloudbasher.csp.aws.control_plane import remembered_login_failure

    remembered = remembered_login_failure(key)
    if remembered:
        raise CloudShellAutomationError(f"AWS Console sign-in: {remembered}")


def record_console_login_failure(key: str, exc: BaseException) -> None:
    """Remember why this console identity's sign-in failed."""
    from cloudbasher.csp.aws.control_plane import _remember_login_failure

    _remember_login_failure(key, f"{type(exc).__name__}: {exc}")


def playwright_console_bootstrap(
    *,
    creds: Union[AwsConsoleCreds, AwsSSOCreds],
    region: str,
    headless: bool = True,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    mfa_timeout: int = 120,
    ui_wait_timeout: int = 60,
    open_cloudshell: bool = True,
    block_provisioning: Optional[bool] = None,
    blocked_writes: Optional[list] = None,
) -> tuple[Any, Any, Any, BrowserAuthCapture]:
    """Log in via Playwright and navigate to CloudShell, WITHOUT closing the browser afterward."""
    from cloudbasher.csp.aws.playwright_owner import PlaywrightOwner

    ensure_playwright_available()
    owner = PlaywrightOwner()
    try:
        return owner.call(
            _console_bootstrap_on_owner_thread,
            owner,
            creds,
            region,
            headless,
            proxy_url,
            proxy_insecure,
            mfa_timeout,
            ui_wait_timeout,
            open_cloudshell,
            (not open_cloudshell) if block_provisioning is None else block_provisioning,
            blocked_writes,
        )
    except Exception:


        owner.shutdown(wait=False)
        raise


def _console_bootstrap_on_owner_thread(
    owner: Any,
    creds: Union[AwsConsoleCreds, AwsSSOCreds],
    region: str,
    headless: bool,
    proxy_url: Optional[str],
    proxy_insecure: bool,
    mfa_timeout: int,
    ui_wait_timeout: int,
    open_cloudshell: bool = True,
    block_provisioning: bool = False,
    blocked_writes: Optional[list] = None,
) -> tuple[Any, Any, Any, BrowserAuthCapture]:
    """The body of playwright_console_bootstrap(), running on the owner thread."""


    with timeline_span("browser.launch", region=region, headless=headless):
        browser, context, page = launch_playwright_browser(
            headless=headless,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
            owner=owner,
        )
    capture = BrowserAuthCapture()
    capture.attach(context)


    try:
        page._cb_capture = capture
    except Exception:  # noqa: BLE001 - a page that refuses attributes is a test double
        log("[login] could not attach the auth capture to the page")


    if block_provisioning:
        from cloudbasher.csp.aws.control_plane import _block_provisioning

        _block_provisioning(context, blocked_writes)

    try:
        if isinstance(creds, AwsConsoleCreds):
            _do_password_login(page, creds, mfa_timeout=mfa_timeout, headless=headless)
        else:

            raise TypeError(f"Unsupported credential type: {type(creds)}")


        def _session_captured() -> bool:
            ctx = capture.context_for_region(region)
            return bool(ctx is not None and ctx.captured_stream_url and ctx.captured_token_value)


        if open_cloudshell:
            navigate_to_cloudshell(
                page,
                region=region,
                ui_wait_timeout=ui_wait_timeout,
                until=_session_captured,
            )
    except Exception:
        _safe_screenshot(page, "console_bootstrap_error")
        close_playwright_browser(browser)
        raise


    return browser, context, page, capture


def _password_login_flow(
    creds: AwsConsoleCreds,
    *,
    region: str,
    headless: bool,
    proxy_url: Optional[str],
    proxy_insecure: bool,
    mfa_timeout: int,
    ui_wait_timeout: int,
) -> CloudShellBrowserAuthContext:
    """Launch browser, login with username/password, navigate to CloudShell."""
    browser, context, page = launch_playwright_browser(
        headless=headless,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    capture = BrowserAuthCapture()
    capture.attach(context)

    try:
        _do_password_login(page, creds, mfa_timeout=mfa_timeout, headless=headless)
        navigate_to_cloudshell(page, region=region, ui_wait_timeout=ui_wait_timeout)

        time.sleep(2)
    except Exception:
        _safe_screenshot(page, "login_error")
        close_playwright_browser(browser)
        raise

    ctx = capture.context_for_region(region)
    if ctx is None:
        close_playwright_browser(browser)
        raise CloudShellAutomationError(
            f"Password login: no PKCE auth tokens captured for region={region}. "
            "The CloudShell terminal may not have loaded completely."
        )
    log(f"[browser] password login complete region={region} has_auth_code={bool(ctx.auth_code)}")
    close_playwright_browser(browser)
    return ctx


def validate_console_login(
    creds: AwsConsoleCreds,
    *,
    headless: bool = True,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    mfa_timeout: int = 120,
) -> None:
    """Prove a console credential can sign in. Raises on failure, else returns."""
    from cloudbasher.csp.aws.playwright_owner import PlaywrightOwner

    ensure_playwright_available()
    owner = PlaywrightOwner()
    try:
        owner.call(
            _validate_login_on_owner_thread,
            owner,
            creds,
            headless,
            proxy_url,
            proxy_insecure,
            mfa_timeout,
        )
    finally:


        owner.shutdown(wait=False)


def _validate_login_on_owner_thread(
    owner: Any,
    creds: AwsConsoleCreds,
    headless: bool,
    proxy_url: Optional[str],
    proxy_insecure: bool,
    mfa_timeout: int,
) -> None:
    """The body of `validate_console_login`, on the owner thread."""
    browser, _context, page = launch_playwright_browser(
        headless=headless,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
        owner=owner,
    )
    try:


        _do_password_login(page, creds, mfa_timeout=mfa_timeout, headless=headless, use_memo=False)
        log(
            f"[browser] console login VALID account={creds.account or 'root'}",
            axis=creds.identity_axis,
        )
    except Exception:


        _safe_screenshot(page, "validate_login_error")
        raise
    finally:
        close_playwright_browser(browser)


def _do_password_login(
    page: Any,
    creds: AwsConsoleCreds,
    *,
    mfa_timeout: int = 120,
    headless: bool = True,
    use_memo: bool = True,
) -> None:
    """ONE SIGN-IN AT A TIME PER IDENTITY, then the steps. `#777`."""
    key = _login_gate_key(creds)


    with _login_gate_hold(key) as _hold:


        if use_memo:
            _refuse_if_remembered(key)
        try:
            _password_login_steps(
                page, creds, mfa_timeout=mfa_timeout, headless=headless, hold=_hold
            )
        except CloudShellAutomationError as exc:


            record_console_login_failure(key, exc)
            raise


def _phase(hold: Optional["_GateHold"], name: str, page: Any = None) -> None:
    """Stamp the step about to run, and refuse the hold if it is already over."""
    if hold is None:
        return
    hold.check(page)
    hold.enter_phase(name)


def _password_login_steps(
    page: Any,
    creds: AwsConsoleCreds,
    *,
    mfa_timeout: int = 120,
    headless: bool = True,
    hold: Optional["_GateHold"] = None,
) -> None:
    """Navigate to AWS Console login page and fill in username/password."""
    log(
        f"Playwright: navigating to AWS Console login account={creds.account or 'root'}",
        axis=creds.identity_axis,
    )
    _phase(hold, "console_home_goto", page)
    page.goto(
        "https://console.aws.amazon.com/console/home",
        wait_until="domcontentloaded",
        timeout=30000,
    )

    _phase(hold, "username_field_wait", page)
    try:
        _wait_for_selector_any(
            page,
            ['input[name="username"]', "#username", "#resolving_input"],
            timeout_ms=15000,
        )
    except Exception:
        _safe_screenshot(page, "login_field_not_found")
        raise CloudShellAutomationError(
            "AWS Console login page did not load or username field not found"
        )


    if creds.account:
        _phase(hold, "fill_account", page)
        _fill_field_verified(
            page,
            ['input[name="account"]', "#account", "#resolving_input"],
            creds.account,
            label="account",
        )
    _phase(hold, "fill_username", page)
    _fill_field_verified(
        page, ['input[name="username"]', "#username"], creds.username, label="username"
    )
    _phase(hold, "fill_password", page)
    _fill_field_verified(
        page, ['input[name="password"]', "#password"], creds.password, label="password"
    )


    log(
        "[browser] sign-in form filled and verified: "
        f"account={'yes' if creds.account else 'n/a'} username=yes password=yes",
        axis=creds.identity_axis,
    )


    log(
        "[browser] second factor "
        + declared_note(CONSOLE_MFA_KEYS, ref=creds.mfa_ref, seed=creds.mfa_secret)
    )
    _phase(hold, "submit", page)
    _click_button(page, ["#signin_button", 'button[type="submit"]', 'input[type="submit"]'])
    log("[browser] sign-in submitted; waiting for redirect, MFA or an error banner")


    _phase(hold, "mfa_or_redirect", page)
    if hold is not None:
        _left = hold.remaining()
        if _left is not None:
            mfa_timeout = max(1, min(mfa_timeout, int(_left)))

    _wait_for_mfa_or_redirect(
        page,
        mfa_timeout=mfa_timeout,
        mfa=mfa_source(
            ref=creds.mfa_ref,
            seed=creds.mfa_secret,
            where="console credential block",
        ),
        headless=headless,
    )
    log(f"Playwright: login succeeded page={page.url}")


_MFA_FIELD_SELECTORS = (
    'input[name="mfaCode"]',
    'input[placeholder*="MFA" i]',
    'input[placeholder*="code" i]',
    "#mfaCode",
)


def _redirected(page: Any) -> bool:
    """Has the browser landed on the console? The success condition, once."""
    return bool(re.search(r"https://[a-z0-9-]+\.console\.aws\.amazon\.com/", page.url or ""))


def _mfa_field_present(page: Any) -> bool:
    """Is the MFA field on the page?"""
    for sel in _MFA_FIELD_SELECTORS:
        try:
            if page.locator(sel).count() > 0:
                return True
        except Exception:
            continue
    return False


def _wait_for_mfa_or_redirect(
    page: Any,
    *,
    mfa_timeout: int,
    mfa: "Optional[MfaSource]" = None,
    headless: bool = True,
) -> None:
    """Wait for either an MFA prompt or a successful post-login redirect."""


    mfa = mfa or mfa_source(where="console credential block")
    prompt = FactorPrompt(mfa, CONSOLE_MFA_KEYS, where="AWS Console login")
    budget = max(mfa_timeout, 30)
    deadline = time.time() + budget
    started = time.time()
    notice_printed = False

    while time.time() < deadline:
        if _redirected(page):
            log(f"[browser] login redirect seen after {time.time() - started:.1f}s")
            return


        rejected = _visible_login_error(page)
        if rejected:
            _safe_screenshot(page, "login_rejected")
            raise CloudShellAutomationError(
                f"AWS Console rejected the sign-in after "
                f"{time.time() - started:.1f}s: {rejected}\n"
                "The form was filled and submitted, and every field is read back "
                "before submit (_fill_field_verified), so this is the credential "
                "being refused -- not a field that failed to fill.\n"
                "  AWS returns this same text for a wrong password, an unknown "
                "user, AND a temporarily blocked sign-in after repeated failures, "
                "so it does not by itself say which. Confirm the credential by "
                "hand in a browser before re-running: further automated attempts "
                "against a real account can turn the first case into the third."
            )

        if _mfa_field_present(page):


            if prompt.answer(
                fill=lambda code: _fill_field_verified(
                    page, list(_MFA_FIELD_SELECTORS), code, label="MFA code"
                ),
                submit=lambda: _click_button(
                    page,
                    [
                        "#mfa_submit_button",
                        'button[type="submit"]',
                        'input[type="submit"]',
                        "#signin_button",
                    ],
                ),
                still_prompting=lambda: _mfa_field_present(page) and not _redirected(page),
                sleep_ms=page.wait_for_timeout,
            ):


                log(
                    f"[browser] MFA challenged; answered from the declared second "
                    f"factor (attempt {prompt.attempts}/{MAX_FACTOR_ATTEMPTS})"
                )
                continue

            if prompt.cap_spent:


                _safe_screenshot(page, "login_mfa_refused")


                raise CloudShellAutomationError(
                    prompt.refused(
                        observed=f"the MFA field was still present {FACTOR_SETTLE_MS}ms "
                        f"after each submit, {time.time() - started:.1f}s into the login"
                    )
                )

            if headless:


                _safe_screenshot(page, "login_mfa_unanswerable")
                raise CloudShellAutomationError(
                    prompt.nothing_declared(
                        observed=f"MFA field present after "
                        f"{time.time() - started:.1f}s, browser headless"
                    )
                    + "\n  Or rerun with --show-browser and complete it by hand."
                )

            if not notice_printed:


                out(prompt.attended_notice(budget_s=budget))
                notice_printed = True

        page.wait_for_timeout(800)

    _safe_screenshot(page, "login_timeout")
    error = _extract_login_error(page)


    raise CloudShellAutomationError(
        f"AWS Console login did not complete within {budget:.0f}s: "
        f"{error or 'no error text found on the page'}\n"


        f"  observed: mfa_field={'yes' if notice_printed or prompt.attempts else 'no'} "
        f"mfa_answered={'yes' if prompt.attempts else 'no'} "
        f"mfa_attempts={prompt.attempts} "
        f"visible_error={'yes' if _visible_login_error(page) else 'no'}\n"
        f"  final page host={_host_of(page.url or '') or '(none)'}\n"
        "  A rejected credential is normally caught in ~1s by the fail-fast "
        "check above, so reaching this line means no error banner rendered -- "
        "look at the screenshot for a page state this flow does not recognise."
    )


def _host_of(url: str) -> str:
    """Host of `url`, or "" -- ISSUES #72's sibling."""
    from urllib.parse import urlparse

    try:
        return urlparse(url).netloc
    except Exception:
        return ""


def navigate_to_cloudshell(
    page: Any,
    *,
    region: str,
    ui_wait_timeout: int,
    until: Optional[Any] = None,
) -> bool:
    """Open the CloudShell widget in the regional console and wait for it."""
    from cloudbasher.csp.aws.cloudshell_terminal import (
        CLOUDSHELL_LAUNCHER_TEST_ID,
        describe_terminal_state,
        panel_open,
        wait_for_terminal_ready,
    )

    console_home = f"https://{region}.console.aws.amazon.com/console/home?region={region}"
    log(f"[browser] opening the regional console region={region}")


    with timeline_span("browser.console_goto", region=region):
        page.goto(console_home, wait_until="domcontentloaded", timeout=60000)


    presign = await_presign_for_region(page, region)
    if presign != PRESIGN_CONFIRMED:
        log(
            f"[browser] refusing CloudShell widget open for region={region}: "
            f"console control-plane identity is {presign}; no launcher click or "
            "environment provisioning was attempted"
        )
        return False


    try:
        _was_open = panel_open(page)
    except Exception:
        _was_open = None
    log(
        f"[browser] opening the CloudShell widget region={region} "
        f"panel_already_open={_was_open}"
    )
    try:
        with timeline_span("browser.launcher_click", region=region):


            page.get_by_test_id(CLOUDSHELL_LAUNCHER_TEST_ID).click(timeout=30000)
    except Exception as exc:


        log(f"[browser] could not click the CloudShell launcher: " f"{type(exc).__name__}: {exc}")

    with timeline_span("browser.terminal_wait", region=region) as _tw:
        ready = wait_for_terminal_ready(
            page, timeout=ui_wait_timeout, also_require=until, region=region
        )
        _tw["ready"] = ready
        _tw["budget_s"] = ui_wait_timeout
    if ready:
        log(f"[browser] CloudShell terminal ready region={region}")
        return True
    _safe_screenshot(page, "cloudshell_terminal_timeout")
    log(
        f"[browser] CloudShell terminal not ready within {ui_wait_timeout}s "
        f"region={region} — {describe_terminal_state(page)}"
    )
    return False


def _fill_field(page: Any, selectors: list[str], value: str) -> None:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                loc.fill(value)
                return
        except Exception:
            continue
    log(f"[browser] could not fill field selectors={selectors}")


def _fill_field_verified(
    page: Any,
    selectors: list[str],
    value: str,
    *,
    label: str,
    attempts: int = 4,
    timeout_ms: int = 15000,
    page_name: str = "AWS sign-in page",
) -> None:
    """Fill a login field and READ IT BACK, retrying until it holds."""
    selector = ", ".join(selectors)
    last_error: Optional[str] = None
    for attempt in range(1, attempts + 1):
        try:
            page.wait_for_selector(selector, timeout=timeout_ms, state="visible")
            loc = page.locator(selector).first
            loc.fill(value)


            if loc.input_value(timeout=5000) == value:
                return
            last_error = "field did not hold the value (page re-rendered?)"
        except Exception as exc:
            last_error = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        if attempt < attempts:
            log(f"[browser] {label}: fill did not stick (attempt {attempt}) -- retrying")
            page.wait_for_timeout(750)

    _safe_screenshot(page, f"login_fill_{label}")
    raise CloudShellAutomationError(
        f"could not fill the {label} field on the {page_name} after "
        f"{attempts} attempts: {last_error}.\n"
        "Nothing was submitted -- an empty field would have been a failed login "
        "attempt against a real account. Re-run with --show-browser to watch the "
        "page, and see the screenshot above."
    )


def _click_button(page: Any, selectors: list[str]) -> None:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                loc.click()
                return
        except Exception:
            continue
    log(f"[browser] could not click button selectors={selectors}")


def _wait_for_selector_any(page: Any, selectors: list[str], timeout_ms: int = 10000) -> None:
    selector = ", ".join(selectors)
    page.wait_for_selector(selector, timeout=timeout_ms)


_LOGIN_ERROR_SELECTORS = [
    "#signin_error",
    ".errorMessage",
    '[class*="error" i]',
    '[id*="error" i]',
]


def _looks_like_stylesheet(text: str) -> bool:
    """CSS that a greedy selector dragged in, rather than a message."""
    return "{" in text and ("font-family" in text or "--color" in text or ";" in text[:200])


def _extract_login_error(page: Any) -> str:
    """Scrape any error text. Used AFTER a failure, where a false positive is cheap -- but not free: whatever this returns is shown to the user as the reason, so obvious non-messages are filtered and the result is capped."""
    for sel in _LOGIN_ERROR_SELECTORS:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                text = (loc.inner_text(timeout=2000) or "").strip()
                if text and not _looks_like_stylesheet(text):
                    return text[:300]
        except Exception:
            continue
    return ""


def _visible_login_error(page: Any) -> str:
    """Error text that is actually RENDERED, or "" -- a fail-fast signal."""
    for sel in _LOGIN_ERROR_SELECTORS:
        try:
            loc = page.locator(sel).first
            if loc.count() == 0 or not loc.is_visible(timeout=1000):
                continue
            text = (loc.inner_text(timeout=2000) or "").strip()


            if text and not _looks_like_stylesheet(text):
                return text[:300]
        except Exception:
            continue
    return ""
