#!/usr/bin/env python3
"""GCP CloudShell provider implementation."""

from __future__ import annotations

import argparse
import threading
from typing import Any, Optional

from cloudbasher.core.types import Credentials
from cloudbasher.csp.base import (
    CloudShellAPI,
    CloudShellSession,
    CredentialProvider,
    CSPProvider,
)
from cloudbasher.csp.gcp.api import GCPCloudShellAPI
from cloudbasher.csp.gcp.credentials import GCPCredentialProvider
from cloudbasher.csp.gcp.session import GCPSession


_BROWSER_SESSION_LOCK = threading.Lock()


def retain_browser_session(state: Any, browser_session: Any) -> None:
    """Attach a live Console browser context to state, unless shutdown began."""
    from cloudbasher.core.shutdown import tearing_down

    with _BROWSER_SESSION_LOCK:
        if tearing_down():
            close_now = True
        else:
            sessions = getattr(state, "_gcp_browser_sessions", None)
            if sessions is None:
                sessions = []
                state._gcp_browser_sessions = sessions
            sessions.append(browser_session)
            close_now = False
    if close_now:
        browser_session.close()


class _GCPTokenBindingKeeper:
    """Periodically refresh and re-project a user RT's access token."""

    def __init__(self, api: Any, refresh: Any, *, environment_name: str, interval: float = 2700):
        self._api = api
        self._refresh = refresh
        self._environment_name = environment_name
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="gcp-token-binding-keeper",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=2)

    def _refresh_and_authorize(self) -> None:
        from cloudbasher.core.utils.output import log

        try:
            access_token = self._refresh()
            if not access_token:
                raise RuntimeError("Google refresh grant returned no access token")
            self._api.access_token = access_token
            result = self._api.authorize_environment(
                self._environment_name,
                access_token=access_token,
            )
            operation = result.get("operation_name", "") if isinstance(result, dict) else ""
            if operation:
                self._api.wait_operation(operation, timeout=60)
            log("[gcp] refreshed and re-authorized Cloud Shell user credentials")
        except Exception as exc:
            log(
                "[gcp] Cloud Shell credential refresh/re-authorization failed "
                f"({type(exc).__name__}); the in-container token may expire"
            )

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            self._refresh_and_authorize()


class GCPProvider(CSPProvider):
    """GCP CloudShell provider."""

    @property
    def name(self) -> str:
        """Return provider name identifier."""
        return "gcp"

    def create_credential_provider(self, **kwargs: Any) -> CredentialProvider:
        """Create a GCP credential provider."""
        return GCPCredentialProvider(
            credential_file=kwargs.get("credential_file"),
            device_code=kwargs.get("device_code", False),
            project_id=kwargs.get("project_id"),
            saved_state=kwargs.get("saved_state"),
            source=kwargs.get("source", "file"),
            proxy_url=kwargs.get("proxy_url"),
            proxy_insecure=kwargs.get("proxy_insecure", False),
        )

    def create_session(
        self,
        credentials: Credentials,
        environment_id: str,
        **kwargs: Any,
    ) -> CloudShellSession:
        """Create a GCP CloudShell session via SSH."""

        web_host = kwargs.get("web_host") or credentials.extra.get("web_host", "")
        session_token = kwargs.get("session_token") or credentials.extra.get("session_token")
        cookies = credentials.extra.get("cookies") if web_host else None

        return GCPSession(
            ssh_host=kwargs.get("ssh_host", ""),
            ssh_port=kwargs.get("ssh_port", 6000),
            ssh_username=kwargs.get("ssh_username", ""),
            ssh_key=kwargs.get("ssh_key"),
            ssh_key_passphrase=kwargs.get("ssh_key_passphrase"),
            environment_id=environment_id,
            timeout=kwargs.get("timeout", 60),
            web_host=web_host,
            session_token=session_token,
            cloudshell_access_token=kwargs.get("cloudshell_access_token"),
            cookies=cookies,
            proxy_url=kwargs.get("proxy_url"),
            proxy_insecure=kwargs.get("proxy_insecure", False),
            diagnostics_dir=kwargs.get("diagnostics_dir"),
        )

    def create_api_client(
        self,
        credentials: Credentials,
        **kwargs: Any,
    ) -> CloudShellAPI:
        """Create GCP CloudShell API client (public or private)."""
        api_path = kwargs.get("api_path", "public")
        if api_path == "private":
            cookies = credentials.extra.get("cookies", {})
            if cookies:
                from cloudbasher.csp.gcp.private_api import GCSPrivateAPI

                return GCSPrivateAPI(  # type: ignore[return-value]
                    credentials,
                    timeout=kwargs.get("timeout", 30),
                    proxy_url=kwargs.get("proxy_url"),
                    proxy_insecure=kwargs.get("proxy_insecure", False),
                    request_executor=kwargs.get("request_executor"),
                )

            from cloudbasher.core.utils.output import eprint

            eprint(
                "[GCP] --api-path private requested but no cookies in credentials; using public API"
            )

        access_token = kwargs.get("access_token", "")
        if not access_token and credentials.access_token:
            access_token = credentials.access_token


        from cloudbasher.csp.gcp.credentials import build_refresher

        refresher = build_refresher(credentials)

        quota_project = kwargs.get("quota_project") or credentials.extra.get("quota_project_id")
        return GCPCloudShellAPI(
            access_token=access_token,
            timeout=kwargs.get("timeout", 30),
            proxy_url=kwargs.get("proxy_url"),
            proxy_insecure=kwargs.get("proxy_insecure", False),
            token_refresher=refresher,
            quota_project=quota_project or None,
        )

    def detect_region(self, credentials: Credentials) -> Optional[str]:
        """GCP CloudShell has no selectable region: the environment's zone is assigned by Google. Always returns None; ``.region`` in the CLI is a user-set display label only."""
        return None

    def reconnect_node(self, state: Any, node: Any) -> CloudShellSession:
        """Rebuild a regionless GCP terminal through the normal bootstrap path."""
        rec = (getattr(state, "credentials_by_id", None) or {}).get(node.credential_id)
        if rec is None or rec.provider != "gcp":
            raise ValueError(f"GCP reconnect has no matching credential for {node.id}")
        args = getattr(state, "args", None)
        if args is None:
            raise ValueError("GCP reconnect requires the invocation arguments")

        from cloudbasher.cli.main import _bootstrap_primary_node_for_credential
        from cloudbasher.core.cli.dispatcher import disconnect_node
        from cloudbasher.core.utils.output import log


        disconnect_node(node, scope="session")
        _bootstrap_primary_node_for_credential(
            args=args,
            rec=rec,
            emit=log,
            gcp_wait_mode="auto",
            node=node,
            credential_registry=state.credentials_by_id,
        )
        session = node._runtime_session
        if session is None:
            raise RuntimeError(f"GCP reconnect returned no terminal session for {node.id}")
        return session

    def reconnect_node_api_client(self, state: Any, node: Any) -> CloudShellAPI:
        """Return the current GCP API client; never starts a shell for lifecycle calls."""
        cached = getattr(node, "_runtime_api_client", None)
        if cached is not None:
            return cached
        rec = (getattr(state, "credentials_by_id", None) or {}).get(node.credential_id)
        if rec is None or rec.provider != "gcp":
            raise ValueError(f"GCP API reconnect has no matching credential for {node.id}")
        extra = rec.raw.extra or {}
        if rec.kind == "console":
            raise RuntimeError(
                "GCP Console API context is not available in this process; reconnect the node first"
            )
        from cloudbasher.csp.gcp.credentials import load_credentials_from_record_extra

        credentials = load_credentials_from_record_extra(extra)
        args = getattr(state, "args", None)
        return self.create_api_client(
            credentials,
            api_path="public",
            timeout=getattr(args, "http_timeout", 30),
            proxy_url=getattr(args, "proxy", None),
            proxy_insecure=getattr(args, "proxy_insecure", False),
        )


    def register_cli_args(self, parser: argparse.ArgumentParser) -> None:
        """No GCP-specific CLI flags in v0.9."""

    def register_dot_commands(self, dispatcher: Any) -> None:
        """Register GCP-specific dot commands."""
        from cloudbasher.csp.aws.commands import PROVISION_SPEC
        from cloudbasher.csp.azure.commands import cmd_provision as cmd_non_aws_provision
        from cloudbasher.csp.gcp.commands import register_gcp_commands

        register_gcp_commands(dispatcher)
        dispatcher.register(
            ".provision",
            cmd_non_aws_provision,
            help="Explicitly create or reuse one GCP Cloud Shell node per credential",
            spec=PROVISION_SPEC,
        )

    def on_session_ready(self, state: Any, args: Any) -> None:
        """Post-bootstrap: wire file service if private API and web_host known."""
        if state is None or state.session is None:
            return


        if (
            str(getattr(args, "api_path", "public") or "public") != "private"
            and (state.credentials.extra or {}).get("refresh_token")
        ):
            from cloudbasher.csp.gcp.credentials import (
                build_refresher,
                resolve_quota_project,
            )

            refresh = build_refresher(state.credentials)
            if refresh is not None:
                api = self.create_api_client(
                    state.credentials,
                    api_path="public",
                    timeout=getattr(args, "http_timeout", 30),
                    proxy_url=getattr(args, "proxy", None),
                    proxy_insecure=getattr(args, "proxy_insecure", False),
                    quota_project=resolve_quota_project(args, state.credentials),
                )
                keeper = _GCPTokenBindingKeeper(
                    api,
                    refresh,
                    environment_name=(
                        f"users/me/environments/{state.session.environment_id or 'default'}"
                    ),
                )
                keeper.start()
                state._gcp_token_binding_keeper = keeper

        if str(getattr(args, "api_path", "public") or "public") != "private":
            return
        web_host = state.session.web_host
        if not web_host or web_host == "unknown":
            return
        cached_jwt = getattr(state.api_client, "access_jwt", None) if state.api_client else None
        jwt = cached_jwt if isinstance(cached_jwt, str) else ""
        if not jwt and state.api_client is not None:
            try:
                jwt = state.api_client.generate_access_token()
            except Exception:
                pass
        if jwt:
            from cloudbasher.csp.gcp.file_service import GCSFileService

            state._gcs_file_service = GCSFileService(
                web_host,
                jwt,
                timeout=getattr(args, "http_timeout", 30),
                proxy_url=getattr(args, "proxy", None),
                proxy_insecure=getattr(args, "proxy_insecure", False),
            )
            from cloudbasher.core.utils.output import log

            log(f"[gcp] file_service wired web_host={web_host}")

    def on_session_close(self, state: Any) -> None:
        """Release GCP refresh workers and retained private browser transports."""
        keeper = getattr(state, "_gcp_token_binding_keeper", None) if state else None
        if keeper is not None:
            keeper.stop()
            state._gcp_token_binding_keeper = None
        with _BROWSER_SESSION_LOCK:
            browser_sessions = getattr(state, "_gcp_browser_sessions", []) if state else []
            if state is not None:
                state._gcp_browser_sessions = []
        for browser_session in browser_sessions:
            try:
                browser_session.close()
            except Exception:
                pass
