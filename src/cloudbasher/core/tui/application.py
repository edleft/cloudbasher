"""TUI application adapter — builds the Textual app and runs it."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Optional


_SPLIT_UI_EOF_SENTINEL = "\0__split_ui_eof__\0"


@dataclass
class ShellContextInfo:
    """Context metadata displayed in the status bar."""

    identity: str = ""
    scope: str = ""
    region: str = ""
    os_user: str = ""
    ext_ip: str = ""
    hostname: str = ""

    def with_shell_fields_from(self, state: Any) -> "ShellContextInfo":
        """Return an instance with ``os_user``/``ext_ip``/``hostname`` synced from ``state.shell_prompt_info``; identity/scope/region preserved."""
        import dataclasses

        in_shell = bool(getattr(state, "in_shell_mode", False))
        if in_shell:
            prompt_info = getattr(state, "shell_prompt_info", None)
            if prompt_info is None:
                return self
            new_user = getattr(prompt_info, "user", "") or ""
            new_ip = getattr(prompt_info, "ip", "") or ""
            new_host = getattr(prompt_info, "host", "") or ""
        else:
            new_user = new_ip = new_host = ""

        if (self.os_user, self.ext_ip, self.hostname) == (new_user, new_ip, new_host):
            return self

        return dataclasses.replace(self, os_user=new_user, ext_ip=new_ip, hostname=new_host)


class TUIApplication:
    """Adapter over `CloudShellTUIApp`: builds it from `state`, runs it."""

    def __init__(self, state: Any) -> None:
        self.state = state
        self._next_ui_mode: Optional[str] = None


        self._backend_app: Optional[Any] = None
        self._textual_app: Optional[Any] = None

    def _csp_label(self) -> str:
        """Get CSP provider name for display."""
        try:
            return self.state.csp_provider.name.upper()
        except Exception:
            return "CSP"

    def _history_getter(self) -> list[str]:
        """Get command history from state."""
        try:
            return list(self.state.get_history())
        except Exception:
            return getattr(self.state, "command_history", [])

    def run(
        self,
        *,
        startup_callback: Optional[Callable[[], None]] = None,
        multi_node: bool = False,
    ) -> Optional[str]:
        """Run the TUI."""
        from .textual_app import CloudShellTUIApp

        app = CloudShellTUIApp(
            state=self.state,
            csp_label=self._csp_label(),
            history_getter=self._history_getter,
            startup_callback=startup_callback,
            tui_backend="textual",
            multi_node=multi_node,
        )
        self._backend_app = app
        self._textual_app = app
        return app.run()
