"""Locating and driving the AWS CloudShell terminal in a browser page."""

from __future__ import annotations

import re
import time
import uuid
from typing import Any, Optional

from cloudbasher.core.utils.output import detail, log


_CLOUDSHELL_IFRAME = 'iframe[title="AWS CloudShell"]'


_INPUT_SELECTORS = (
    "textarea[aria-label*='CloudShell terminal input' i]",
    "textarea.xterm-helper-textarea",
    "textarea",
)


_FOCUS_SELECTORS = (".xterm-screen", ".xterm-viewport", "canvas")


_PROMPT_TEXT = "~ $"


_PROMPT_RE = re.compile(r"~\s*\]?\s*[$#]\s*$", re.MULTILINE)


_OUTPUT_SELECTORS = ".xterm-rows, .xterm-screen, .terminal"

_WELCOME_TEXT = "Welcome to AWS CloudShell"
_NO_ACTIVE_TABS_TEXT = "No Active Tabs"


_VPC_ENVIRONMENT_FORM_TEXT = "Create a VPC environment"


CLOUDSHELL_LAUNCHER_TEST_ID = "awsc-nav-scallop-icon"


_MIN_PANEL_HEIGHT = 40


ALSO_REQUIRE_GRACE_SECONDS = 5.0


_OPEN_TAB_BUTTON_NAMES = (
    "Open",
    "Start",
    "Launch",
    "Create",
    "Use environment",
    "Use default",
    "New tab",
)


_NEVER_CLICK_BUTTON_PATTERNS = (re.compile(r"\bvpc\b", re.IGNORECASE),)


def cloudshell_frame(page: Any) -> Optional[Any]:
    """The CloudShell iframe's content frame, or None if the page has no iframe."""
    try:
        locator = page.locator(_CLOUDSHELL_IFRAME)
        if locator.count() > 0:
            return locator.content_frame
    except Exception:
        pass
    return None


def terminal_contexts(page: Any) -> list[Any]:
    """Every document the terminal might be in, iframe first."""
    frame = cloudshell_frame(page)
    return [frame, page] if frame is not None else [page]


def find_terminal_input(page: Any) -> Optional[Any]:
    """A locator for the terminal's input element, or None."""
    for ctx in terminal_contexts(page):
        try:
            by_role = ctx.get_by_role(
                "textbox", name=re.compile(r"cloudshell terminal input", re.IGNORECASE)
            ).first
            if by_role.is_visible(timeout=250):
                return by_role
        except Exception:
            pass
        for selector in _INPUT_SELECTORS:
            try:
                loc = ctx.locator(selector).first
                if loc.count() > 0:
                    return loc
            except Exception:
                continue
    return None


def read_terminal_snapshot(page: Any) -> str:
    """The rendered terminal text, or "" if it cannot be read."""
    frame = cloudshell_frame(page)
    if frame is not None:
        for selector in (_OUTPUT_SELECTORS, "body"):
            try:
                loc = frame.locator(selector).first
                if loc.count() > 0:
                    return strip_screen_furniture(str(loc.inner_text(timeout=3000) or ""))
            except Exception:
                continue
    for selector in (_OUTPUT_SELECTORS, "body"):
        try:
            loc = page.locator(selector).first
            if loc.count() > 0:
                return strip_screen_furniture(str(loc.inner_text(timeout=3000) or ""))
        except Exception:
            continue
    return ""


_ACCESSIBILITY_NOISE = ("CloudShell terminal input",)


_LEADING_BORDER_RE = re.compile(r"^[ \t]*[│┃║]")


_FURNITURE_ONLY_RE = re.compile(r"^[ \t·•─-╿░-▓.…]*$")


def strip_screen_furniture(text: str) -> str:
    """Remove pane borders and filler rows from a DOM terminal snapshot."""
    if not text:
        return text
    cleaned: list[str] = []
    for line in text.replace("\r", "").split("\n"):
        border = _LEADING_BORDER_RE.match(line)
        if border:
            line = line[border.end() :]
        if line.strip() and _FURNITURE_ONLY_RE.match(line):
            continue
        cleaned.append(line)
    return "\n".join(cleaned)


def make_output_markers() -> tuple[str, str, str]:
    """A unique (start, end, wrapped_prefix_suffix) triple for one command."""
    token = uuid.uuid4().hex[:12]
    return f"__CB_S_{token}__", f"__CB_E_{token}__", token


def wrap_command_with_markers(command: str, start: str, end: str) -> str:
    """The line to type: print `start`, run the command, print `end`."""
    return f"printf '%s\\n' {start}; {command}; printf '%s\\n' {end}"


def extract_between_markers(snapshot: str, start: str, end: str) -> Optional[str]:
    """The text between the LAST `start` marker and the next `end`, or None."""
    lines = [ln.rstrip() for ln in (snapshot or "").replace("\r", "").split("\n")]
    begin = None
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() == start:
            begin = i + 1
            break
    if begin is None:
        return None
    out: list[str] = []
    for ln in lines[begin:]:
        if ln.strip() == end:
            return "\n".join(out).strip("\n")
        out.append(ln)
    return None


def extract_command_output(snapshot: str, command: str) -> str:
    """Pull just a command's output out of a whole-terminal screen grab."""
    lines = [ln.rstrip() for ln in (snapshot or "").replace("\r", "").split("\n")]
    lines = [ln for ln in lines if ln.strip() not in _ACCESSIBILITY_NOISE]

    needle = (command or "").strip()
    start = 0
    if needle:
        for i in range(len(lines) - 1, -1, -1):
            if needle in lines[i]:
                start = i + 1
                break

    out_lines: list[str] = []
    for ln in lines[start:]:


        if _PROMPT_RE.search(ln.strip()):
            break
        out_lines.append(ln)

    while out_lines and not out_lines[0].strip():
        out_lines.pop(0)
    while out_lines and not out_lines[-1].strip():
        out_lines.pop()
    return "\n".join(out_lines)


def terminal_prompt_visible(page: Any) -> bool:
    """True once a shell prompt has been drawn."""
    for ctx in terminal_contexts(page):
        try:
            if ctx.get_by_text(_PROMPT_TEXT).first.is_visible(timeout=250):
                return True
        except Exception:
            pass
    from cloudbasher.core.utils.output import strip_ansi

    return bool(_PROMPT_RE.search(strip_ansi(read_terminal_snapshot(page)).replace("\r", "")))


def _text_visible(page: Any, text: str) -> bool:
    for ctx in terminal_contexts(page):
        try:
            if ctx.get_by_text(text).first.is_visible(timeout=250):
                return True
        except Exception:
            continue
    return False


def _button_label(btn: Any) -> str:
    """A button's accessible name, or "" if it cannot be read."""
    for reader in ("get_attribute", "inner_text"):
        try:
            value = (
                btn.get_attribute("aria-label") if reader == "get_attribute" else btn.inner_text()
            )
            if value and str(value).strip():
                return " ".join(str(value).split())
        except Exception:
            continue
    return ""


def _never_click_reason(label: str) -> Optional[str]:
    """Why `label` must not be clicked, or None if it is safe."""
    if not label:
        return None
    for pattern in _NEVER_CLICK_BUTTON_PATTERNS:
        if pattern.search(label):
            return (
                "it provisions a VPC environment, which needs "
                "ec2:CreateNetworkInterface and is not a shell"
            )
    return None


def all_page_contexts(page: Any) -> list[Any]:
    """Every frame on the page, plus the page itself."""
    contexts = terminal_contexts(page)
    try:
        for frame in page.frames:
            if frame not in contexts:
                contexts.append(frame)
    except Exception:
        pass
    return contexts


def _text_visible_anywhere(page: Any, text: str) -> bool:
    """_text_visible(), across every frame rather than the terminal's two."""
    for ctx in all_page_contexts(page):
        try:
            if ctx.get_by_text(text).first.is_visible(timeout=250):
                return True
        except Exception:
            continue
    return False


def vpc_environment_form_visible(page: Any) -> bool:
    """Whether the page is showing "Create a VPC environment" instead of a shell."""
    return _text_visible_anywhere(page, _VPC_ENVIRONMENT_FORM_TEXT)


def dismiss_welcome_dialog(page: Any) -> bool:
    """Close the first-use welcome dialog. True if something was dismissed."""
    if not _text_visible(page, _WELCOME_TEXT):
        return False
    log("[browser] CloudShell welcome dialog detected — dismissing")
    try:
        page.keyboard.press("Escape")
        page.wait_for_timeout(150)
        if not _text_visible(page, _WELCOME_TEXT):
            return True
    except Exception:
        pass
    for locator_factory in (
        lambda: page.get_by_role("button", name=re.compile(r"^close$", re.IGNORECASE)).first,
        lambda: page.get_by_label(re.compile(r"close", re.IGNORECASE)).first,
    ):
        try:
            locator = locator_factory()
            if locator.is_visible(timeout=250):
                locator.click(timeout=1000)
                page.wait_for_timeout(150)
                if not _text_visible(page, _WELCOME_TEXT):
                    return True
        except Exception:
            continue
    return False


def panel_height(page: Any) -> Optional[float]:
    """The rendered height of the CloudShell panel, or None if it has none."""
    try:
        loc = page.locator(_CLOUDSHELL_IFRAME).first
        if loc.count() == 0:
            return None
        box = loc.bounding_box(timeout=1000)
        return None if box is None else float(box.get("height") or 0.0)
    except Exception:
        return None


def panel_open(page: Any) -> bool:
    """True when the CloudShell panel is actually rendering at a usable size."""
    height = panel_height(page)
    return height is not None and height >= _MIN_PANEL_HEIGHT


def reopen_collapsed_panel(page: Any) -> bool:
    """Re-open the CloudShell panel when it is present but collapsed."""
    if panel_open(page):
        return False
    if panel_height(page) is None and page.locator(_CLOUDSHELL_IFRAME).count() == 0:


        return False
    log("[browser] CloudShell panel is collapsed — reopening it")
    try:
        page.get_by_test_id(CLOUDSHELL_LAUNCHER_TEST_ID).click(timeout=5000)
        page.wait_for_timeout(500)
        return True
    except Exception as exc:
        detail(f"[browser] could not reopen the collapsed CloudShell panel: {exc}")
        return False


_ENVIRONMENT_ENTRY_ROLES = ("menuitem", "option", "button", "link")


def click_environment_entry(page: Any, region: str) -> bool:
    """Click the environment entry named `region` in an open dropdown."""
    if not region:
        return False
    pattern = re.compile(rf"^\s*{re.escape(region)}\s*$", re.IGNORECASE)
    for ctx in all_page_contexts(page):
        for role in _ENVIRONMENT_ENTRY_ROLES:
            try:
                entry = ctx.get_by_role(role, name=pattern).first
                if not entry.is_visible(timeout=250):
                    continue
                entry.click(timeout=2000)
                log(f"[browser] opened the {region!r} environment from the tab menu")
                return True
            except Exception:
                continue
    return False


def handle_no_active_tabs(page: Any, tried: Optional[set] = None, region: str = "") -> bool:
    """Open a shell tab when CloudShell is showing "No Active Tabs"."""
    if not _text_visible(page, _NO_ACTIVE_TABS_TEXT):
        return False
    log("[browser] CloudShell shows No Active Tabs — opening a shell")


    if click_environment_entry(page, region):
        return True
    for ctx in terminal_contexts(page):
        for name in _OPEN_TAB_BUTTON_NAMES:
            try:
                btn = ctx.get_by_role("button", name=re.compile(name, re.IGNORECASE)).first
                if not btn.is_visible(timeout=250):
                    continue


                label = _button_label(btn)
                skip = _never_click_reason(label)
                if skip is not None:
                    log(
                        f"[browser] NOT clicking {label!r} (matched {name!r}): "
                        f"{skip}. Looking for another button."
                    )
                    continue
                if tried is not None and label in tried:
                    detail(
                        f"[browser] already clicked {label!r} and the state did "
                        f"not change; not clicking it again"
                    )
                    continue
                btn.click(timeout=2000)
                if tried is not None:
                    tried.add(label)
                log(f"[browser] clicked No Active Tabs button={name!r} label={label!r}")
                return True
            except Exception:
                continue
    if tried:
        log(
            f"[browser] No Active Tabs persists after clicking {sorted(tried)!r} "
            f"-- none of them opened a shell"
        )
    return False


def focus_terminal(page: Any, *, attempts: int = 3) -> bool:
    """Put keyboard focus on the terminal. True if focus was transferred."""
    for attempt in range(1, attempts + 1):
        frame = cloudshell_frame(page)
        if frame is not None:
            for selector in _FOCUS_SELECTORS:
                try:
                    loc = frame.locator(selector).first
                    if loc.count() > 0:
                        loc.click(timeout=2000)
                        detail(f"[browser] terminal focus attempt={attempt} via {selector}")
                        return True
                except Exception:
                    continue
        element = find_terminal_input(page)
        if element is not None:
            try:
                element.focus(timeout=2000)
                detail(f"[browser] terminal focus attempt={attempt} via textarea focus()")
                return True
            except Exception:
                pass
        if frame is not None and terminal_prompt_visible(page):
            try:
                frame.get_by_text(_PROMPT_TEXT).first.click(timeout=2000)
                detail(f"[browser] terminal focus attempt={attempt} via prompt click")
                return True
            except Exception:
                pass
        page.wait_for_timeout(500)
    return False


def describe_terminal_state(page: Any) -> str:
    """One line naming what IS on the page, for a timeout message."""
    bits = []
    try:
        bits.append(f"iframe={'yes' if page.locator(_CLOUDSHELL_IFRAME).count() else 'no'}")
    except Exception:
        bits.append("iframe=?")


    height = panel_height(page)
    if height is None:
        bits.append("panel=not-rendered")
    else:
        bits.append(
            f"panel={'open' if height >= _MIN_PANEL_HEIGHT else 'COLLAPSED'} h={height:.0f}"
        )
    bits.append(f"welcome={'yes' if _text_visible(page, _WELCOME_TEXT) else 'no'}")
    bits.append(f"no_active_tabs={'yes' if _text_visible(page, _NO_ACTIVE_TABS_TEXT) else 'no'}")
    if vpc_environment_form_visible(page):


        bits.append("VPC_ENVIRONMENT_FORM=yes")
    bits.append(f"input={'yes' if find_terminal_input(page) is not None else 'no'}")
    bits.append(f"prompt={'yes' if terminal_prompt_visible(page) else 'no'}")
    snapshot = read_terminal_snapshot(page)
    bits.append(f"text_len={len(snapshot)}")
    try:
        bits.append(f"url={page.url}")
    except Exception:
        pass
    return " ".join(bits)


def _describe_extra_condition(also_require: Optional[Any], prompt_since: Optional[float]) -> str:
    """Which of the two conjuncts the wait actually died on"""
    if also_require is None:
        return ""
    if prompt_since is None:
        return "blocked_on=terminal extra_condition=never-evaluated (short-circuited) "
    return (
        "blocked_on=EXTRA_CONDITION (not the terminal) "
        f"prompt_up_for={time.time() - prompt_since:.0f}s "
        "extra_condition=never-met "
    )


def wait_for_terminal_ready(
    page: Any,
    *,
    timeout: int = 60,
    also_require: Optional[Any] = None,
    also_require_grace: Optional[float] = ALSO_REQUIRE_GRACE_SECONDS,
    region: str = "",
) -> bool:
    """Drive the page until the terminal is ready. True if it got there."""
    deadline = time.time() + timeout


    tried_tab_buttons: set = set()
    next_state_log = 0.0


    prompt_since: Optional[float] = None
    while time.time() < deadline:
        if dismiss_welcome_dialog(page):
            page.wait_for_timeout(300)
            continue


        acted = reopen_collapsed_panel(page)
        acted = handle_no_active_tabs(page, tried_tab_buttons, region) or acted
        if terminal_prompt_visible(page):
            if also_require is None or also_require():
                log("[browser] CloudShell terminal ready")
                return True
            if prompt_since is None:
                prompt_since = time.time()
            waited = time.time() - prompt_since
            if also_require_grace is not None and waited >= also_require_grace:


                log(
                    "[browser] CloudShell terminal ready — RELEASED ON THE PROMPT: "
                    f"a shell prompt has been drawn for {waited:.1f}s and the "
                    "caller's extra condition is still unmet after that grace. "
                    "The prompt is the readiness signal and implies createSession "
                    f"was processed. {describe_terminal_state(page)}"
                )
                return True
        if not acted and vpc_environment_form_visible(page):


            log(
                "[browser] CloudShell is showing the 'Create a VPC environment' "
                "form, not a shell -- this page cannot become a terminal on its "
                "own. Not waiting out the remaining timeout. "
                f"{describe_terminal_state(page)}"
            )
            return False
        if not acted and time.time() >= next_state_log:
            next_state_log = time.time() + 10.0
            detail(f"[browser] waiting for CloudShell terminal — {describe_terminal_state(page)}")
        page.wait_for_timeout(800)
    log(
        f"[browser] CloudShell terminal NOT ready after {timeout}s — "
        f"{_describe_extra_condition(also_require, prompt_since)}"
        f"{describe_terminal_state(page)}"
    )
    return False
