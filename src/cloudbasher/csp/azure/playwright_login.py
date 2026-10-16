"""Driving `login.microsoftonline.com` -- the sign-in leg, and device-code approval."""

from __future__ import annotations

import importlib
import json
import pathlib
from dataclasses import dataclass, field
from typing import Any, Optional

from cloudbasher.core import browser_profile
from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core import mfa_keys
from cloudbasher.core.mfa import FactorPrompt, MfaSource
from cloudbasher.core.utils.output import log, mask_secrets
from cloudbasher.core.utils.page_poll import poll_page_until

_sync_playwright: Any = None
_PlaywrightTimeoutError: Any = Exception
_IMPORT_ERROR: Optional[Exception] = None


DEVICE_LOGIN_URLS = (
    "https://login.microsoft.com/device",
    "https://microsoft.com/devicelogin",
)


def _attr_selectors(pairs: tuple[tuple[str, str], ...]) -> tuple[str, ...]:
    return tuple(f"input[{attr}={value}]" for attr, value in pairs)


_SEL_USERNAME = _attr_selectors((("name", "loginfmt"), ("type", "email"))) + ("#i0116",)
_SEL_SECRET = _attr_selectors((("name", "passwd"), ("type", "password"))) + ("#i0118",)
_SEL_OTP = _attr_selectors(
    (("name", "otc"), ("name", "otpCode"), ("autocomplete", "one-time-code"))
) + ("#idTxtBx_SAOTCC_OTC",)


_SEL_USER_CODE = ("#otc",) + _attr_selectors((("name", "otc"), ("type", "tel")))
_SEL_SUBMIT = _attr_selectors((("type", "submit"),)) + (
    'button[type="submit"]',
    "#idSIButton9",
)


_SEL_STAY_YES = ("#idSIButton9", 'input[value="Yes"]', 'button:has-text("Yes")')


_SEL_CONTINUE = (
    "#idSIButton9",
    'input[value="Continue"]',
    'button:has-text("Continue")',
    'button:has-text("Accept")',
)


def _load_playwright() -> None:
    global _sync_playwright, _PlaywrightTimeoutError, _IMPORT_ERROR
    if _sync_playwright is not None:
        return
    try:
        api = importlib.import_module("playwright.sync_api")
        _sync_playwright = api.sync_playwright
        _PlaywrightTimeoutError = getattr(api, "TimeoutError", Exception)
    except Exception as exc:  # noqa: BLE001
        _IMPORT_ERROR = exc


def ensure_playwright_available() -> None:
    _load_playwright()
    if _sync_playwright is None:
        raise CloudShellAutomationError(
            f"Playwright is not usable: {_IMPORT_ERROR}. "
            "Install with: pip install playwright && playwright install chromium"
        )


def visible_input_names(page: Any) -> list[str]:
    """The `name`/`id` of every visible input, for diagnosing an unknown variant."""
    try:
        return sorted(
            {
                (el.get_attribute("name") or el.get_attribute("id") or "?")
                for el in page.locator("input").all()
                if el.is_visible()
            }
        )
    except Exception:  # noqa: BLE001
        return []


def mask_user_code(code: str) -> str:
    """A device `user_code` is a credential; show only enough to correlate."""
    return f"{code[:2]}****" if len(code) > 2 else "****"


@dataclass
class StepTrace:
    """What a step actually observed -- the antidote to a bare timeout."""

    step: str
    matched: str = ""
    ok: bool = True
    detail: str = ""


@dataclass
class SignInResult:
    ok: bool = False
    trace: list[StepTrace] = field(default_factory=list)
    mfa_prompts: int = 0
    error: str = ""


    presented_credentials: bool = False

    def summary(self) -> str:
        reached = [t.step for t in self.trace if t.ok]
        return (
            f"reached={'>'.join(reached) or 'nothing'} "
            f"mfa_prompts={self.mfa_prompts} presented={self.presented_credentials}"
        )


_VISIBLE_TICK_MS = 250
_GONE_TICK_MS = 250


def _first_visible(page: Any, selectors: tuple[str, ...], timeout_ms: int) -> Optional[str]:
    """The first selector that becomes visible, or None."""

    def _visible() -> str:


        for sel in selectors:
            try:
                if page.locator(sel).first.is_visible():
                    return sel
            except Exception:  # noqa: BLE001
                continue
        return ""

    outcome = poll_page_until(page, until=_visible, budget_ms=timeout_ms, tick_ms=_VISIBLE_TICK_MS)
    return None if outcome.timed_out else str(outcome.verdict)


def _any_visible(page: Any, selectors: "tuple[str, ...]") -> bool:
    """Is any of ``selectors`` visible RIGHT NOW? No polling, no sleep."""
    for sel in selectors:
        try:
            if page.locator(sel).first.is_visible():
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _wait_gone(page: Any, selector: str, timeout_ms: int) -> bool:
    """Wait for `selector` to stop being visible. True if it went."""

    def _gone() -> bool:
        try:
            return not page.locator(selector).first.is_visible()
        except Exception:  # noqa: BLE001 - the old document going away IS the success case
            return True

    return not poll_page_until(
        page, until=_gone, budget_ms=timeout_ms, tick_ms=_GONE_TICK_MS
    ).timed_out


def _click_first(page: Any, selectors: tuple[str, ...], timeout_ms: int = 8000) -> Optional[str]:
    sel = _first_visible(page, selectors, timeout_ms)
    if sel is not None:
        page.locator(sel).first.click()
    return sel


def sign_in_microsoft(
    page: Any,
    creds: Any,
    *,
    mfa: MfaSource,
    result: Optional[SignInResult] = None,
    timeout_ms: int = 30000,
    require_signin: bool = False,
) -> SignInResult:
    """The shared `login.microsoftonline.com` sequence."""
    res = result or SignInResult()

    sel = _first_visible(page, _SEL_USERNAME, timeout_ms)
    if sel:
        page.locator(sel).first.fill(creds.username)
        res.presented_credentials = True
        res.trace.append(StepTrace("username", sel))
        _click_first(page, _SEL_SUBMIT)
    else:
        res.trace.append(StepTrace("username", detail="skipped -- existing session?"))

    sel = _first_visible(page, _SEL_SECRET, timeout_ms)
    if sel:


        page.locator(sel).first.fill(creds.password)
        res.presented_credentials = True
        res.trace.append(StepTrace("secret", sel))
        _click_first(page, _SEL_SUBMIT)
    else:
        res.trace.append(StepTrace("secret", detail="skipped -- not asked"))

    sel = _first_visible(page, _SEL_OTP, timeout_ms)
    if sel:


        prompt = FactorPrompt(mfa, mfa_keys.CONSOLE, where="Azure portal login")
        if not prompt.answer(


            fill=lambda code: page.locator(sel).first.fill(code),
            submit=lambda: _click_first(page, _SEL_SUBMIT),


            still_prompting=lambda: _any_visible(page, _SEL_OTP),
            sleep_ms=page.wait_for_timeout,
        ):
            res.error = prompt.nothing_declared(
                observed=f"a one-time-code field ({sel}) was shown after the password"
            )
            res.trace.append(StepTrace("mfa", sel, False, "challenged, nothing declared"))
            return res
        res.mfa_prompts = prompt.attempts
        res.trace.append(StepTrace("mfa", sel, detail=f"prompt #{res.mfa_prompts}"))
    else:
        res.trace.append(StepTrace("mfa", detail="not challenged -- session already satisfies it"))

    sel = _click_first(page, _SEL_STAY_YES, timeout_ms=6000)
    res.trace.append(
        StepTrace("stay_signed_in", sel or "", detail="not offered" if not sel else "accepted")
    )


    if require_signin and not res.presented_credentials:
        names = visible_input_names(page)
        res.error = (
            "no credential field was recognised on a browser context that has never "
            f"signed in. Page: {page.url}. Visible inputs: {names or 'none'}. "
            "Either Entra served an unrecognised variant or the page never loaded."
        )
        res.trace.append(StepTrace("signin_required", ok=False, detail=res.error))
        return res

    res.ok = True
    return res


def device_code_authorize(
    page: Any,
    creds: Any,
    *,
    user_code: str,
    mfa: MfaSource,
    verification_uri: Optional[str] = None,
    timeout_ms: int = 30000,
    require_signin: bool = False,
) -> SignInResult:
    """Approve one device code, signing in first if no session exists yet."""
    res = SignInResult()
    page.goto(verification_uri or DEVICE_LOGIN_URLS[0], wait_until="domcontentloaded")

    sel = _first_visible(page, _SEL_USER_CODE, timeout_ms)
    if sel is None:
        res.error = (
            f"no device-code field at {page.url}. Visible inputs: "
            f"{visible_input_names(page) or 'none'}. Either Entra changed the page, or "
            "the code expired -- they last 900 s and cannot be batched up in advance."
        )
        res.trace.append(StepTrace("user_code", ok=False, detail=res.error))
        return res
    page.locator(sel).first.fill(user_code)
    res.trace.append(StepTrace("user_code", sel, detail=mask_user_code(user_code)))
    _click_first(page, _SEL_SUBMIT)


    if not _wait_gone(page, sel, timeout_ms):
        res.error = (
            f"the device-code field {sel} is still on screen after submit. Entra "
            "usually names a bad code inline; check the code has not expired (900 s)."
        )
        res.trace.append(StepTrace("user_code_accepted", sel, False, res.error))
        return res
    res.trace.append(StepTrace("user_code_accepted", sel))

    sign_in_microsoft(
        page,
        creds,
        mfa=mfa,
        result=res,
        timeout_ms=timeout_ms,
        require_signin=require_signin,
    )
    if res.error:
        return res

    sel = _click_first(page, _SEL_CONTINUE, timeout_ms=10000)
    res.trace.append(
        StepTrace("consent", sel or "", detail="not shown" if not sel else "confirmed")
    )
    res.ok = True
    log(f"device-code approved for {mask_user_code(user_code)}: {res.summary()}")
    return res


def console_login(
    page: Any,
    creds: Any,
    *,
    mfa: MfaSource,
    url: str = "https://portal.azure.com/",
    timeout_ms: int = 30000,
) -> SignInResult:
    """Portal sign-in -- `#164` / `52.2`'s entry point."""
    page.goto(url, wait_until="domcontentloaded")
    return sign_in_microsoft(page, creds, mfa=mfa, timeout_ms=timeout_ms)


class BrowserSession:
    """One persistent context, reused across every approval in a sweep."""

    def __init__(
        self,
        *,
        headless: bool = True,
        storage_state: Any = None,
        save_state_to: Any = None,
        handle_sigint: bool = True,
    ) -> None:
        """`storage_state` loads cookies from a previous run; `save_state_to` writes them at teardown."""
        ensure_playwright_available()
        self._headless = headless
        self._storage_state = storage_state
        self._save_state_to = save_state_to


        self._handle_sigint = handle_sigint
        self._pw: Any = None
        self._browser: Any = None
        self._context: Any = None

    def __enter__(self) -> "BrowserSession":
        self._pw = _sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=self._headless,
            args=browser_profile.launch_args(),
            handle_sigint=self._handle_sigint,
        )
        kwargs = browser_profile.context_kwargs(self._browser)
        if self._storage_state is not None:
            kwargs["storage_state"] = str(self._storage_state)
        self._context = self._browser.new_context(**kwargs)
        return self

    def __exit__(self, *exc: Any) -> None:


        if self._save_state_to is not None and self._context is not None:
            try:
                self._context.storage_state(path=str(self._save_state_to))
                log(f"browser session state saved to {self._save_state_to}")
            except Exception as err:  # noqa: BLE001
                log(f"could not save browser state: {mask_secrets(str(err))}")
        for closeable in (self._context, self._browser):
            try:
                if closeable is not None:
                    closeable.close()
            except Exception as err:  # noqa: BLE001
                log(f"browser teardown: {mask_secrets(str(err))}")
        try:
            if self._pw is not None:
                self._pw.stop()
        except Exception as err:  # noqa: BLE001
            log(f"playwright teardown: {mask_secrets(str(err))}")

    def save_state(self, path: Any) -> tuple[bool, str]:
        """Write the cookie jar NOW and say plainly whether it worked."""
        if self._context is None:
            return False, "no browser context"
        try:
            self._context.storage_state(path=str(path))
        except Exception as err:  # noqa: BLE001
            return False, f"{type(err).__name__}: {mask_secrets(str(err))}"
        f = pathlib.Path(str(path))
        if not f.is_file():
            return False, "storage_state() returned but wrote no file"
        try:
            cookies = len(json.loads(f.read_text()).get("cookies", []))
        except Exception:  # noqa: BLE001
            cookies = -1
        if cookies == 0:
            return False, "wrote a state file with ZERO cookies -- nothing to reuse"
        return True, f"{f.stat().st_size} bytes, {cookies} cookies"

    def new_page(self) -> Any:
        if self._context is None:
            raise CloudShellAutomationError("BrowserSession used outside its context manager")
        return self._context.new_page()
