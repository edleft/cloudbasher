"""Device-code approval, ported from proven production code."""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.mfa import FactorPrompt
from cloudbasher.core.utils.output import log
from cloudbasher.core.utils.page_poll import poll_page_until


DEVICEAUTH_URL = "https://login.microsoftonline.com/common/oauth2/deviceauth"


EXPECT_TIMEOUT_MS = 5000


ACTION_TIMEOUT_MS = EXPECT_TIMEOUT_MS


def apply_timeouts(page: Any) -> None:
    """Cap every implicit Playwright wait on this page."""
    for setter in ("set_default_timeout", "set_default_navigation_timeout"):
        try:
            getattr(page, setter)(ACTION_TIMEOUT_MS)
        except Exception:  # noqa: BLE001
            pass


_BTN_ADVANCE = ("Next", "Submit", "Continue")
_BTN_SIGNIN = ("Sign in", "Next", "Submit")
_BTN_VERIFY = ("Verify", "Sign in", "Next", "Submit")
_BTN_APPROVE = ("Continue", "Accept", "Yes", "Allow")


_TXT_PICK_ACCOUNT = ("Pick an account", "Choose an account")

_TXT_APPROVE = (
    "Are you trying to sign in to",
    "Only continue if you",
    "trying to sign in",
)


_TXT_CONFIRM = (
    "You have signed in to the",
    "You have signed in",
    "You're all set",
    "You may now close this window",
)

_expect: Any = None


def _load_expect() -> None:
    global _expect
    if _expect is None:
        try:
            _expect = importlib.import_module("playwright.sync_api").expect
        except Exception as exc:  # noqa: BLE001
            raise CloudShellAutomationError(f"Playwright unavailable: {exc}") from exc


def _wait_settled(page: Any) -> None:
    """`load`, `domcontentloaded`, `networkidle` -- `dc.py`'s `wait_page_load`."""
    for state in ("load", "domcontentloaded", "networkidle"):
        try:
            page.wait_for_load_state(state=state)
        except Exception:  # noqa: BLE001


            return


_FEDERATED_IDP = ("github", "google", "apple", "facebook", "linkedin", "twitter")


def _federated_button(text: str) -> bool:
    low = text.lower()
    return any(idp in low for idp in _FEDERATED_IDP)


def _locator_text(loc: Any, timeout: int = EXPECT_TIMEOUT_MS) -> str:
    """An already-resolved locator's REAL text -- what the pattern cannot say."""
    try:
        return str(loc.inner_text(timeout=timeout)).strip()
    except Exception:  # noqa: BLE001
        return ""


def _sees_role(page: Any, role: str, name: str, timeout: int = EXPECT_TIMEOUT_MS) -> bool:
    _load_expect()
    loc = page.get_by_role(role, name=name).first
    try:
        _expect(loc).to_be_visible(timeout=timeout)
    except Exception:  # noqa: BLE001
        return False


    if role == "button" and _federated_button(_locator_text(loc, timeout)):
        return False
    return True


def _sees_text(page: Any, text: str, timeout: int = EXPECT_TIMEOUT_MS) -> bool:
    _load_expect()
    try:
        _expect(page.get_by_text(text).first).to_be_visible(timeout=timeout)
        return True
    except Exception:  # noqa: BLE001
        return False


def _heading_text(page: Any) -> str:
    """The first heading's text, for saying what page we are actually on."""
    try:
        return (page.get_by_role("heading").first.inner_text() or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def snapshot(page: Any) -> dict[str, Any]:
    """Everything needed to fix a drifted page from ONE failed run."""

    def _texts(sel: str, attr: str) -> list[str]:
        try:
            return sorted(
                {
                    (el.get_attribute(attr) or el.inner_text() or "").strip()
                    for el in page.locator(sel).all()
                    if el.is_visible()
                }
                - {""}
            )
        except Exception:  # noqa: BLE001
            return []

    return {
        "url": getattr(page, "url", ""),
        "heading": _heading_text(page),
        "headings": _texts("h1, h2, [role=heading]", "aria-label"),


        "buttons": _texts("button, input[type=submit], [role=button]", "value"),
        "placeholders": _texts("input", "placeholder"),
    }


_MS_LOGIN_ORIGINS = (
    "login.microsoftonline.com",
    "login.live.com",
    "login.microsoft.com",
    "account.live.com",
    "device.login.microsoftonline.com",
)


def _off_microsoft(page: Any) -> str:
    """The page's host, if it is NOT a Microsoft sign-in origin. Else ''."""
    host = ""
    try:
        host = (page.url or "").split("/", 3)[2]
    except Exception:  # noqa: BLE001
        return ""
    return "" if any(host.endswith(o) for o in _MS_LOGIN_ORIGINS) else host


def _save_screenshot(page: Any, snapshot_dir: Any, name: str) -> str:
    """Best effort, and it records WHERE the page was, not only what it showed."""
    if snapshot_dir is None:
        return ""
    try:
        path = snapshot_dir / f"{name}.png"
        page.screenshot(path=str(path))
        try:
            (snapshot_dir / f"{name}.url").write_text(
                f"{page.url}\n{page.title()}\n", encoding="utf-8"
            )
        except Exception:  # noqa: BLE001
            pass
        return str(path)
    except Exception:  # noqa: BLE001
        return ""


def _attr(pairs: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    return tuple(("css", f"input[{a}={v}]") for a, v in pairs)


FIND_USERNAME = (
    (
        ("placeholder", "Email, phone, or Skype"),
        ("placeholder", "Email or phone"),
        ("placeholder", "Email"),
        ("placeholder", "someone@example.com"),
        ("label", "Email or phone"),
    )
    + _attr((("name", "loginfmt"), ("type", "email")))
    + (("css", "#i0116"),)
)

FIND_SECRET = (
    (
        ("placeholder", "Password"),
        ("label", "Password"),
    )
    + _attr((("name", "passwd"), ("type", "password")))
    + (("css", "#i0118"),)
)


FIND_CODE = (
    (("css", "#otc"),) + _attr((("name", "otc"), ("type", "text"))) + (("placeholder", "Code"),)
)


FIND_OTP = (
    ("css", "#idTxtBx_SAOTCC_OTC"),
    ("css", "input[autocomplete=one-time-code]"),
    ("css", "input[type=tel]"),
)


def _locate(page: Any, strategies: tuple[tuple[str, str], ...]) -> tuple[Any, str]:
    """First strategy that yields a VISIBLE element. Returns (locator, label)."""
    for how, what in strategies:
        try:
            loc = {
                "placeholder": page.get_by_placeholder,
                "label": page.get_by_label,
                "css": page.locator,
            }[how](what).first
            if loc.is_visible():
                return loc, f"{how}:{what}"
        except Exception:  # noqa: BLE001
            continue
    return None, ""


def _fill(page: Any, strategies: tuple[tuple[str, str], ...], value: str) -> str:
    """Fill the first field that matches. "" if none did -- never raises."""
    loc, label = _locate(page, strategies)
    if loc is None:
        return ""
    try:
        loc.fill(value)
        return label
    except Exception:  # noqa: BLE001
        return ""


def _click(page: Any, role: str, name: str) -> bool:
    """Click by role+name. REFUSES a federated identity-provider button."""
    try:
        loc = page.get_by_role(role, name=name).first
        if role == "button" and _federated_button(_locator_text(loc)):
            return False
        loc.click()
        return True
    except Exception:  # noqa: BLE001
        return False


_NEXT_PAGE_TICK_MS = 300


def _wait_for_next_page(page: Any, timeout_ms: int = 12000) -> str:
    """Wait until the page becomes one of the states we know how to handle."""

    def _state() -> str:


        if _sees_any_text(page, _TXT_PICK_ACCOUNT):
            return "pick_account"
        if _locate(page, FIND_USERNAME)[0] is not None:
            return "username"
        if _locate(page, FIND_SECRET)[0] is not None:
            return "secret"
        if _locate(page, FIND_OTP)[0] is not None:
            return "otp"
        if _sees_any_text(page, _TXT_APPROVE):
            return "approval"
        if _sees_any_text(page, _TXT_CONFIRM):
            return "confirmation"
        return ""

    outcome = poll_page_until(page, until=_state, budget_ms=timeout_ms, tick_ms=_NEXT_PAGE_TICK_MS)
    return "" if outcome.timed_out else str(outcome.verdict)


def _sees_any_role(page: Any, role: str, names: tuple[str, ...]) -> str:
    """First matching name, or "". Tolerates Entra rewording a button."""
    for n in names:
        if _sees_role(page, role, n, timeout=1500):
            return n
    return ""


def _sees_any_text(page: Any, texts: tuple[str, ...]) -> str:
    for x in texts:
        if _sees_text(page, x, timeout=1500):
            return x
    return ""


def _submit(page: Any, role: str, name: str) -> str:
    """Click, then wait for a state we recognise. Returns that state, or ""."""
    _click(page, role, name)
    _wait_settled(page)
    return _wait_for_next_page(page)


@dataclass
class Step:
    name: str
    ok: bool = True
    detail: str = ""


    url: str = ""


@dataclass
class ApprovalResult:
    ok: bool = False
    steps: list[Step] = field(default_factory=list)
    mfa_prompts: int = 0


    app_seen: str = ""
    error: str = ""


    matched: dict[str, str] = field(default_factory=dict)

    page_state: dict[str, Any] = field(default_factory=dict)
    screenshot: str = ""

    def add(self, name: str, ok: bool = True, detail: str = "", url: str = "") -> None:


        if not url:
            pg = getattr(self, "_page", None)
            url = getattr(pg, "url", "") if pg is not None else ""
        self.steps.append(Step(name, ok, detail, url))

    def summary(self) -> str:
        return (
            f"steps={'>'.join(s.name for s in self.steps if s.ok) or 'none'} "
            f"mfa={self.mfa_prompts} app={self.app_seen or '?'}"
        )

    def trail(self) -> list[dict[str, Any]]:
        """Every step with the url it happened on, for the artifact."""
        return [{"step": s.name, "ok": s.ok, "detail": s.detail, "url": s.url} for s in self.steps]

    def origins(self) -> list[str]:
        """Distinct origins visited, in order. More than one non-Microsoft origin here means the flow left Entra, which is never expected."""
        seen: list[str] = []
        for s in self.steps:
            if not s.url:
                continue
            origin = "/".join(s.url.split("/", 3)[:3])
            if origin and origin not in seen:
                seen.append(origin)
        return seen


def approve_device_code(
    page: Any,
    creds: Any,
    *,
    user_code: str,
    factor: "FactorPrompt",
    expected_app: Optional[str] = None,
    url: str = DEVICEAUTH_URL,
    snapshot_dir: Any = None,
) -> ApprovalResult:
    """Approve one device code. NEVER RAISES."""
    res = ApprovalResult()

    res._page = page
    try:
        return _approve(
            page,
            creds,
            user_code=user_code,
            factor=factor,
            expected_app=expected_app,
            url=url,
            snapshot_dir=snapshot_dir,
            res=res,
        )
    except BaseException as exc:  # noqa: BLE001


        if isinstance(exc, KeyboardInterrupt):
            raise
        res.ok = False
        res.error = f"unforeseen {type(exc).__name__}: {exc}"
        res.page_state = res.page_state or snapshot(page)
        res.screenshot = res.screenshot or _save_screenshot(page, snapshot_dir, "unforeseen")
        res.add("unforeseen", False, res.error)
        return res


def _approve(
    page: Any,
    creds: Any,
    *,
    user_code: str,
    factor: "FactorPrompt",
    expected_app: Optional[str],
    url: str,
    snapshot_dir: Any,
    res: ApprovalResult,
) -> ApprovalResult:
    """The flow itself. Only ever called through `approve_device_code`."""

    apply_timeouts(page)
    page.goto(url)
    _wait_settled(page)


    if not (_sees_role(page, "heading", "Enter code") and _sees_text(page, "code displayed on")):
        res.error = f"not on the device-code page. url={page.url} heading={_heading_text(page)!r}"
        res.add("device_code_page", False, res.error)
        return res
    hit = _fill(page, FIND_CODE, user_code)
    if not hit:
        res.error = "found the device-code page but no field to type the code into"
        res.page_state = snapshot(page)
        res.screenshot = _save_screenshot(page, snapshot_dir, "device_code_field")
        res.add("device_code_page", False, res.error)
        return res
    res.matched["device_code_field"] = hit
    _wait_settled(page)
    btn = _sees_any_role(page, "button", _BTN_ADVANCE)
    if not btn:
        res.error = "no advance button on the device-code page"
        res.page_state = snapshot(page)
        res.screenshot = _save_screenshot(page, snapshot_dir, "device_code_page")
        res.add("device_code_page", False, res.error)
        return res
    res.matched["device_code_next"] = btn
    nxt = _submit(page, "button", btn)
    if not nxt:


        res.page_state = snapshot(page)
        res.screenshot = _save_screenshot(page, snapshot_dir, "after_device_code")
        res.add(
            "after_device_code_unrecognised",
            True,
            f"waited {12000} ms; heading={_heading_text(page)!r}",
        )
    res.matched["after_device_code"] = nxt or "unrecognised"
    res.add("device_code_page", detail=f"button={btn} -> {nxt or 'unrecognised'}")


    if _sees_any_text(page, _TXT_PICK_ACCOUNT):


        picked = ""
        for how, target in (
            ("role", creds.username),
            ("text", creds.username),
            ("css", "#otherTile"),
        ):
            try:
                if how == "role":
                    loc = page.get_by_role("button", name=target).first
                elif how == "text":
                    loc = page.get_by_text(target, exact=False).first
                else:
                    loc = page.locator(target).first
                if loc.is_visible():
                    loc.click()
                    picked = f"{how}:{target}"
                    break
            except Exception:  # noqa: BLE001
                continue
        _wait_settled(page)
        if not picked:
            res.error = (
                "the account picker appeared and no tile matched. Nothing downstream "
                "renders until an account is chosen, so this cannot be skipped."
            )
            res.page_state = snapshot(page)
            res.screenshot = _save_screenshot(page, snapshot_dir, "pick_account")
            res.add("pick_account", False, res.error)
            return res
        res.matched["pick_account"] = picked
        res.add("pick_account", detail=picked)


    if _locate(page, FIND_USERNAME)[0] is not None:
        hit = _fill(page, FIND_USERNAME, creds.username)
        if not hit:
            res.error = (
                "the sign-in page appeared but no username field matched any known "
                "spelling. The page state below is what to add to FIND_USERNAME."
            )
            res.page_state = snapshot(page)
            res.screenshot = _save_screenshot(page, snapshot_dir, "username_field")
            res.add("username", False, res.error)
            return res
        res.matched["username_field"] = hit
        _wait_settled(page)
        btn = _sees_any_role(page, "button", _BTN_ADVANCE) or "Next"
        res.matched["username_next"] = btn
        _submit(page, "button", btn)
        res.add("username", detail=f"button={btn}")


        stray = _off_microsoft(page)
        if stray:
            res.error = (
                f"after the username step the flow is on {stray!r}, not a Microsoft "
                "sign-in origin. REFUSING to type the credential. Most likely an "
                "advance-button match hit a federated identity-provider option."
            )
            res.page_state = snapshot(page)
            res.screenshot = _save_screenshot(page, snapshot_dir, "left_microsoft")
            res.add("left_microsoft_origin", False, stray)
            return res


        if _locate(page, FIND_SECRET)[0] is not None:
            hit = _fill(page, FIND_SECRET, creds.password)
            if not hit:
                res.error = "the secret page appeared but no field matched any known spelling"
                res.page_state = snapshot(page)
                res.screenshot = _save_screenshot(page, snapshot_dir, "secret_field")
                res.add("secret", False, res.error)
                return res
            res.matched["secret_field"] = hit
            _wait_settled(page)
            btn = _sees_any_role(page, "button", _BTN_SIGNIN) or "Sign in"
            res.matched["secret_signin"] = btn
            _submit(page, "button", btn)
            res.add("secret", detail=f"button={btn}")


        if _locate(page, FIND_OTP)[0] is not None or _sees_text(page, "code displayed in"):


            hit: "Any" = None

            def _fill_otp(code: str) -> None:
                nonlocal hit
                hit = _fill(page, FIND_OTP, code)

            def _submit_otp() -> None:
                if not hit:
                    return
                _wait_settled(page)
                btn = _sees_any_role(page, "button", _BTN_VERIFY) or "Verify"
                res.matched["mfa_verify"] = btn
                _submit(page, "button", btn)

            if not factor.answer(
                fill=_fill_otp,
                submit=_submit_otp,
                still_prompting=lambda: _locate(page, FIND_OTP)[0] is not None,
                sleep_ms=page.wait_for_timeout,
            ):
                res.error = factor.nothing_declared(
                    observed="the OTP page was shown during the device-code approval"
                )
                res.add("mfa", False, res.error)
                return res
            if not hit:
                res.error = "the OTP page appeared but no code field matched any known spelling"
                res.page_state = snapshot(page)
                res.screenshot = _save_screenshot(page, snapshot_dir, "otp_field")
                res.add("mfa", False, res.error)
                return res
            res.matched["mfa_field"] = hit


            res.mfa_prompts += 1
            res.add("mfa", detail=f"prompt #{res.mfa_prompts}")


        if _sees_role(page, "heading", "Stay signed in?"):
            _submit(page, "button", "Yes")
            res.add("stay_signed_in")
    else:
        res.add("username", detail="skipped -- established session")


    heading = _heading_text(page)
    looks_like_approval = heading.lower().startswith("are you trying to sign in to") or bool(
        _sees_any_text(page, _TXT_APPROVE)
    )
    btn = _sees_any_role(page, "button", _BTN_APPROVE)
    if not (looks_like_approval or btn):
        res.error = (
            "no approval page and no approve-shaped button, so NOTHING was approved. "
            "This is the failure that previously reported success and then let the "
            "token poll run to its deadline."
        )
        res.page_state = snapshot(page)
        res.screenshot = _save_screenshot(page, snapshot_dir, "approval")
        res.add("approval", False, res.error)
        return res
    if not looks_like_approval:


        res.page_state = snapshot(page)
        res.add("approval_page_drifted", True, f"heading={heading!r} button={btn}")
    res.app_seen = (
        heading.removeprefix("Are you trying to sign in to").strip(" ?")
        if looks_like_approval and heading.lower().startswith("are you")
        else ""
    )
    if expected_app and res.app_seen and expected_app.lower() not in res.app_seen.lower():
        res.add(
            "app_name_mismatch",
            True,
            f"Entra calls this id {res.app_seen!r}, we expected {expected_app!r}",
        )
    res.matched["approve"] = btn or "Continue"
    _submit(page, "button", btn or "Continue")
    res.add("approval", detail=res.app_seen or f"button={btn}")


    stray = _off_microsoft(page)
    if stray:
        res.error = (
            f"the flow LEFT the Microsoft sign-in origin and is on {stray!r}. "
            "Refusing to read this page as a confirmation. A button on the "
            "Microsoft-account page offers a third-party identity provider, and "
            "following one walks the credential off Microsoft entirely."
        )
        res.page_state = snapshot(page)
        res.screenshot = _save_screenshot(page, snapshot_dir, "left_microsoft")
        res.add("left_microsoft_origin", False, stray)
        return res

    hit = _sees_any_text(page, _TXT_CONFIRM)
    if not hit:
        res.error = (
            "Entra did not confirm the sign-in, so the device code is NOT approved -- "
            "whatever the pages looked like on the way here. This is the INVARIANT: "
            "approval wording may drift, an unconfirmed sign-in is never an approval."
        )
        res.page_state = snapshot(page)
        res.screenshot = _save_screenshot(page, snapshot_dir, "confirmation")
        res.add("confirmation", False, res.error)
        return res
    res.matched["confirm"] = hit
    res.add("confirmation", detail=hit)
    res.ok = True
    log(f"device code approved for {res.app_seen or 'unknown app'}: {res.summary()}")
    return res
