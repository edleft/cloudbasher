"""Type 2 — SSO Identity Center username/password to an `ASIA` triple."""

from __future__ import annotations

from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError, CredentialError
from cloudbasher.core.mfa import FactorPrompt, MfaSource, mfa_source
from cloudbasher.core.utils.output import detail, log
from cloudbasher.core.utils.page_poll import poll_page_until
from cloudbasher.csp.aws.browser import _safe_screenshot
from cloudbasher.csp.aws.credentials import SSO_MFA_KEYS
from cloudbasher.csp.aws.playwright_login import _fill_field_verified
from cloudbasher.csp.aws.sso_oidc import _masked


MAX_LOGIN_STEPS = 4


STEP_TIMEOUT_SECONDS = 20.0


BEARER_TIMEOUT_SECONDS = 45.0

_TOKEN_PATH = "/auth/sso-token"


_FIND_FIELD_JS = """() => {
    const vis = el => el.offsetParent !== null && !el.disabled && !el.readOnly;
    const fields = [...document.querySelectorAll('input')].filter(
        el => vis(el) && ['text', 'email', 'password', 'tel'].includes(
            (el.getAttribute('type') || 'text').toLowerCase()));
    const submits = [...document.querySelectorAll('button[type=submit]')].filter(vis);
    return {
        count: fields.length,
        type: fields.length ? (fields[0].getAttribute('type') || 'text') : '',
        id: fields.length ? (fields[0].id || '') : '',
        filled: fields.length ? !!fields[0].value : false,
        submit_count: submits.length,
        submit_text: submits.length ? (submits[0].innerText || '').slice(0, 40) : '',
    };
}"""


_STEP_TICK_MS = 400
_BEARER_TICK_MS = 500


def _field_state(page: Any) -> dict:
    try:
        return page.evaluate(_FIND_FIELD_JS) or {}
    except Exception:
        return {}


def _await_step(page: Any, *, timeout: float, is_done: Any) -> tuple[str, dict]:
    """Wait for whatever comes next, and return which of them arrived."""
    found: dict = {}

    def _arrived() -> str:


        if is_done():
            return "done"
        if _on_dashboard(page):
            return "dashboard"
        st = _field_state(page)
        if st.get("count"):
            found.update(st)
            return "field"
        return ""

    outcome = poll_page_until(
        page, until=_arrived, budget_ms=int(timeout * 1000), tick_ms=_STEP_TICK_MS
    )
    if outcome.timed_out:
        return "timeout", {}


    return str(outcome.verdict), found


def _on_dashboard(page: Any) -> bool:
    """The portal dashboard, which is where a completed login lands."""
    try:
        url = page.url or ""
    except Exception:
        return False
    return "awsapps.com/start/" in url and "#/" in url


def drive_portal_login(
    page: Any,
    *,
    username: str,
    secret: str,
    mfa: "Optional[MfaSource]" = None,
    is_done: Any = lambda: False,
) -> None:
    """Step 2.1. Drive the login form until the login is done, or raise saying why not."""


    prompt = FactorPrompt(
        mfa or mfa_source(where="SSO credential block"),
        SSO_MFA_KEYS,
        where="SSO portal login",
    )

    for step in range(1, MAX_LOGIN_STEPS + 1):
        outcome, st = _await_step(page, timeout=STEP_TIMEOUT_SECONDS, is_done=is_done)
        if outcome in ("done", "dashboard"):
            log(
                f"SSO portal: login complete after {step - 1} step(s) "
                f"({'bearer already minted' if outcome == 'done' else 'reached the dashboard'})"
            )
            return
        if outcome == "timeout":


            _safe_screenshot(page, "sso_portal_step_timeout")
            raise CredentialError(
                f"SSO portal login: step {step} produced nothing within "
                f"{STEP_TIMEOUT_SECONDS:.0f}s -- no bearer, no dashboard and no "
                f"further field. The page is at {getattr(page, 'url', '?')!r}. If "
                "the portal is showing a consent screen, a device-registration "
                "prompt or an error, it has to be read by a human -- rerun "
                "`scripts/capture_sso_login.py` without `--auto-fill` to see it."
            )
        if st.get("count", 0) > 1:


            detail(
                f"SSO portal login: step {step} has {st['count']} fillable fields; "
                "expected 1. Filling the first."
            )

        kind = str(st.get("type") or "text").lower()
        value = secret if kind == "password" else username
        which = "password" if kind == "password" else "username"

        if kind != "password" and step > 1:


            code = prompt.next_code()
            if code is None:
                _safe_screenshot(page, "sso_portal_unexpected_field")


                observed = (
                    f"step {step} asked for another non-password field "
                    f"(type={kind}, id={st.get('id') or '(none)'}) after the password"
                )
                if prompt.cap_spent:
                    raise CredentialError(prompt.refused(observed=observed))
                raise CredentialError(
                    prompt.nothing_declared(observed=observed)
                    + "\n  That is the shape of an MFA or extra-factor prompt. If this "
                    "portal does NOT enforce MFA, the field is something else -- a "
                    "consent or device-registration screen -- and it has to be read by "
                    "a human: rerun scripts/aws/capture_sso_login.py without "
                    "--auto-fill to see it."
                )
            value = code
            which = "MFA code"


            detail(
                f"SSO portal login: step {step} -- answering a factor prompt from "
                f"the declared second factor (type={kind}, "
                f"id={st.get('id') or '(none)'})"
            )
        else:
            detail(
                f"SSO portal login: step {step} -- filling the {which} "
                f"(type={kind}, id={st.get('id') or '(none)'}), "
                f"submit={st.get('submit_text') or '(none)'!r}"
            )

        selector = f"#{st['id']}" if st.get("id") else f"input[type={kind}]"


        try:
            _fill_field_verified(
                page,
                [selector],
                value,
                label=which,
                page_name="Identity Center portal",
            )
        except CloudShellAutomationError as exc:


            raise CredentialError(f"SSO portal login: {exc}") from exc
        if st.get("submit_count"):
            page.click("button[type=submit]", timeout=int(STEP_TIMEOUT_SECONDS * 1000))
        else:
            page.keyboard.press("Enter")


        page.wait_for_timeout(1200)

    if is_done() or _on_dashboard(page):
        return
    raise CredentialError(
        f"SSO portal login: still not signed in after {MAX_LOGIN_STEPS} "
        f"steps (now at {getattr(page, 'url', '?')!r}). The observed form is two "
        "steps; more than that means a flow this does not implement."
    )


def _capture_bearer(context: Any, holder: dict) -> None:
    """Attach the response hook for step 2.2."""

    def _on_response(resp: Any) -> None:
        try:
            if _TOKEN_PATH not in (resp.url or "") or holder.get("token"):
                return
            body = resp.json()
        except Exception:
            return
        token = body.get("token") if isinstance(body, dict) else None
        if isinstance(token, str) and token:
            holder["token"] = token
            log(f"SSO portal: bearer minted at {_TOKEN_PATH} {_masked(token)}")

    context.on("response", _on_response)


def resolve_console_credentials(
    *,
    start_url: str,
    username: str,
    secret: str,
    region: str,
    account_id: str,
    role_name: str,
    mfa: "Optional[MfaSource]" = None,
    headless: bool = True,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> dict[str, Any]:
    """Type 2 end to end: portal login -> bearer -> `ASIA` triple."""
    required = (
        ("SSO_START_URL", start_url),
        ("SSO_USERNAME", username),
        ("SSO_PASSWORD", secret),
        ("SSO_REGION", region),
        ("ACCOUNT_ID", account_id),
        ("ROLE_NAME", role_name),
    )
    for name, value in required:
        if not value:
            raise CredentialError(
                f"SSO Console credential is missing {name}. All six are required: "
                "the portal, the login, the Identity Center instance's region, and "
                "which account/permission-set to fetch credentials for. SSO_REGION "
                "is not derivable from the start URL."
            )

    from cloudbasher.csp.aws.browser import (
        close_playwright_browser,
        launch_playwright_browser,
    )
    from cloudbasher.csp.aws.playwright_owner import run_owned
    from cloudbasher.csp.aws.sso_oidc import get_role_credentials

    holder: dict[str, str] = {}
    browser, context, page = launch_playwright_browser(
        headless=headless, proxy_url=proxy_url, proxy_insecure=proxy_insecure
    )

    def _drive() -> None:
        """Every Playwright touch on the owner thread -- including `context.on`."""
        _capture_bearer(context, holder)
        page.goto(start_url, wait_until="domcontentloaded", timeout=45000)
        drive_portal_login(
            page,
            username=username,
            mfa=mfa,
            secret=secret,


            is_done=lambda: bool(holder.get("token")),
        )
        poll_page_until(
            page,
            until=lambda: bool(holder.get("token")),
            budget_ms=int(BEARER_TIMEOUT_SECONDS * 1000),
            tick_ms=_BEARER_TICK_MS,
        )

    try:
        run_owned(page, _drive)
    finally:


        try:
            close_playwright_browser(browser, context, page)
        except Exception:
            pass

    if not holder.get("token"):
        raise CredentialError(
            f"SSO portal: the login completed but no {_TOKEN_PATH} response was "
            f"seen within {BEARER_TIMEOUT_SECONDS:.0f}s, so there is no bearer to "
            "fetch credentials with. The portal front end normally mints this as "
            "the dashboard loads."
        )


    return get_role_credentials(
        region,
        holder["token"],
        account_id,
        role_name,
        timeout=timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
