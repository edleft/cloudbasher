"""Shell mode handling for interactive terminal sessions."""

from __future__ import annotations

from typing import Optional

from ...csp.base import CloudShellSession
from ..types import ShellPromptInfo
from .quiet import INTERNAL_COMMAND_TIMEOUT_SECONDS, exec_quiet


_MARKER = "CBPROMPTINFO"


_PROBE = (
    "printf '%s\\n%s\\n%s\\n%s\\n' "
    + _MARKER
    + ' "$(curl -s --max-time 3 ip.me | head -n 1)"'
    + ' "$(whoami)"'
    + ' "$(cat /etc/hostname 2>/dev/null | head -n 1)"'
)


def _values_after_marker(text: str) -> Optional[tuple[str, str, str]]:
    """The three lines following the LAST bare `_MARKER` line, or None."""
    lines = text.splitlines()
    index = None
    for i, line in enumerate(lines):
        if line.strip() == _MARKER:
            index = i
    if index is None:
        return None
    values = [line.strip() for line in lines[index + 1 : index + 4]]
    while len(values) < 3:
        values.append("")
    return values[0], values[1], values[2]


class ShellModeHandler:
    """Gathers best-effort remote shell identity (IP/user/host) on shell-mode entry."""

    def __init__(self, session: CloudShellSession):
        """Initialize handler."""
        self.session = session

    def setup_prompt_info(self) -> ShellPromptInfo:
        """Get IP, user, hostname for prompt -- in ONE round trip where possible."""
        try:
            text = exec_quiet(self.session, _PROBE, timeout=8)
        except Exception:
            return ShellPromptInfo(ip="", user="", host="")
        values = _values_after_marker(text or "")
        if values is not None:
            ip, user, host = values
            return ShellPromptInfo(ip=ip, user=user, host=host)
        return self._setup_prompt_info_per_command()

    def _setup_prompt_info_per_command(self) -> ShellPromptInfo:
        """The original one-command-per-value probe. Kept as the fallback."""
        ip = ""
        user = ""
        host = ""


        try:


            ip_out = exec_quiet(self.session, "curl -s --max-time 3 ip.me", timeout=5)
            ip = ip_out.strip().split("\n")[-1].strip() if ip_out else ""
        except Exception:
            pass


        try:
            user_out = exec_quiet(self.session, "whoami", timeout=INTERNAL_COMMAND_TIMEOUT_SECONDS)
            user = user_out.strip().split("\n")[-1].strip() if user_out else ""
        except Exception:
            pass


        try:
            host_out = exec_quiet(
                self.session, "cat /etc/hostname", timeout=INTERNAL_COMMAND_TIMEOUT_SECONDS
            )
            host = host_out.strip().split("\n")[-1].strip() if host_out else ""
        except Exception:
            pass

        return ShellPromptInfo(ip=ip, user=user, host=host)
