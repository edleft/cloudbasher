"""Azure CloudShell provider implementation."""

from __future__ import annotations

import argparse
from typing import Any, Optional

from cloudbasher.core.types import Credentials
from cloudbasher.csp.base import (
    CloudShellAPI,
    CloudShellSession,
    CredentialProvider,
    CSPProvider,
)


class AzureProvider(CSPProvider):
    """Azure CloudShell provider."""

    @property
    def name(self) -> str:
        return "azure"

    def create_credential_provider(self, **kwargs: Any) -> CredentialProvider:
        from cloudbasher.csp.azure.credentials import AzureCredentialProvider

        return AzureCredentialProvider(
            credential_file=kwargs.get("credential_file"),
            tenant_id=kwargs.get("tenant_id"),
            subscription_id=kwargs.get("subscription_id"),
            interactive=kwargs.get("interactive", True),
            no_browser=kwargs.get("no_browser", False),
            login_hint=kwargs.get("login_hint"),
            show_browser=kwargs.get("show_browser", False),
            saved_state=kwargs.get("saved_state") or {},
            source=kwargs.get("source", "file"),
        )

    def create_api_client(self, credentials: Credentials, **kwargs: Any) -> CloudShellAPI:
        from cloudbasher.csp.azure.api import AzureCloudShellAPI
        from cloudbasher.csp.azure.credentials import (
            build_audience_token_provider,
            build_refresher,
        )

        return AzureCloudShellAPI(
            credentials=credentials,
            timeout=kwargs.get("timeout", 30),
            proxy_url=kwargs.get("proxy_url"),
            proxy_insecure=kwargs.get("proxy_insecure", False),
            token_refresher=build_refresher(credentials),
            audience_token_provider=build_audience_token_provider(credentials),
        )

    def create_session(
        self,
        credentials: Credentials,
        environment_id: str,
        **kwargs: Any,
    ) -> CloudShellSession:
        from cloudbasher.csp.azure.session import AzureSession
        from cloudbasher.csp.azure.types import ConsoleInfo, TerminalInfo

        console: Optional[ConsoleInfo] = kwargs.get("console")
        terminal: Optional[TerminalInfo] = kwargs.get("terminal")
        assert console is not None, "AzureProvider.create_session requires 'console' kwarg"
        assert terminal is not None, "AzureProvider.create_session requires 'terminal' kwarg"
        return AzureSession(
            console=console,
            terminal=terminal,
            credentials=credentials,
            timeout=kwargs.get("timeout", 60),
            proxy_url=kwargs.get("proxy_url"),
            proxy_insecure=kwargs.get("proxy_insecure", False),
        )

    def reconnect_node(self, state: Any, node: Any) -> CloudShellSession:
        """Rebuild one restored Azure node through the ordinary bootstrap path."""
        rec = (getattr(state, "credentials_by_id", None) or {}).get(node.credential_id)
        if rec is None or rec.provider != "azure":
            raise ValueError(f"Azure reconnect has no matching credential for {node.id}")
        args = getattr(state, "args", None)
        if args is None:
            raise ValueError("Azure reconnect requires the invocation arguments")

        from cloudbasher.cli.main import _bootstrap_primary_node_for_credential
        from cloudbasher.core.utils.output import log

        ready = _bootstrap_primary_node_for_credential(
            args=args,
            rec=rec,
            emit=log,
            gcp_wait_mode="auto",
            node=node,
            credential_registry=state.credentials_by_id,
        )
        session = getattr(ready, "_runtime_session", None)
        if session is None:
            raise RuntimeError(f"Azure reconnect returned no terminal session for {node.id}")
        return session

    def reconnect_node_api_client(self, state: Any, node: Any) -> CloudShellAPI:
        """Return Azure's control-plane client without creating a console."""
        rec = (getattr(state, "credentials_by_id", None) or {}).get(node.credential_id)
        if rec is None or rec.provider != "azure":
            raise ValueError(f"Azure API reconnect has no matching credential for {node.id}")

        args = getattr(state, "args", None)
        extra = rec.raw.extra or {}
        credentials = rec.raw
        if (
            rec.kind == "console"
            or extra.get("access_token")
            or extra.get("refresh_token")
        ):
            from cloudbasher.csp.azure.credentials import (
                bind_refresh_token_rotation,
                load_credentials_from_record_extra,
            )

            credentials = load_credentials_from_record_extra(
                extra,
                headless=not bool(getattr(args, "show_browser", False)),
            )
            bind_refresh_token_rotation(credentials, extra)

        return self.create_api_client(
            credentials,
            timeout=getattr(args, "http_timeout", 30),
            proxy_url=getattr(args, "proxy", None),
            proxy_insecure=getattr(args, "proxy_insecure", False),
        )

    def detect_region(self, credentials: Credentials) -> Optional[str]:
        extra = credentials.extra or {}
        return extra.get("region") or "westus"

    def register_cli_args(self, parser: argparse.ArgumentParser) -> None:
        """No Azure-specific CLI flags in v0.9 (`#340`)."""

    def probe_permissions(
        self, record: Any, *, extra_arns: Optional[list[str]] = None
    ) -> list[tuple[str, str, str]]:
        """`.creds <sel> perms` on Azure."""
        return [
            (
                "(azure)",
                "see .creds perms output",
                "Azure probes the console API, not per-credential derivations",
            )
        ]

    def register_dot_commands(self, dispatcher: Any) -> None:


        from cloudbasher.core.cli.command_specs import DELETE
        from cloudbasher.csp.aws.commands import PROVISION_SPEC
        from cloudbasher.csp.azure.commands import (
            cmd_delete,
            cmd_provision,
            register_azure_commands,
        )

        register_azure_commands(dispatcher)
        dispatcher.register(
            ".provision",
            cmd_provision,
            help="Explicitly create or reuse one Azure CloudShell node per credential",
            spec=PROVISION_SPEC,
        )
        dispatcher.register(
            ".delete",
            cmd_delete,
            help="Reset Azure Cloud Shell; backing storage is retained",
            spec=DELETE,
        )

    def on_session_ready(self, state: Any, args: Any) -> None:
        """Post-bootstrap: start background heartbeat thread."""
        from cloudbasher.csp.azure.heartbeat import start_heartbeat_loop

        api = getattr(state, "api_client", None)
        console = (state.extra or {}).get("azure_console") if hasattr(state, "extra") else None
        if api is not None and console is not None:
            stop_event, thread = start_heartbeat_loop(api, console, interval=180)
            state.heartbeat_stop = stop_event
            state.heartbeat_thread = thread
