#!/usr/bin/env python3
"""AWS CloudShell provider implementation."""

from __future__ import annotations

import argparse
import time
from typing import Any, Optional

from cloudbasher.core.types import Credentials
from cloudbasher.core.utils.output import log
from cloudbasher.csp.aws.api import AWSCloudShellAPI
from cloudbasher.csp.aws.credentials import AWSCredentialProvider, session_creds_from_extra
from cloudbasher.csp.aws.keepalive import KEEPALIVE_LAYERS as _AWS_KEEPALIVE_LAYERS
from cloudbasher.csp.aws.session import AWSSession
from cloudbasher.csp.base import (
    CloudShellAPI,
    CloudShellSession,
    CredentialProvider,
    CSPProvider,
)


_RECONNECT_BACKOFF_SECONDS = (1.0, 4.0)


class AWSProvider(CSPProvider):
    """AWS CloudShell provider."""


    KEEPALIVE_LAYERS = _AWS_KEEPALIVE_LAYERS

    @property
    def name(self) -> str:
        """Return provider name identifier."""
        return "aws"

    def beat_node_now(self, node: Any, state: Any) -> tuple[list[str], list[str]]:
        """All four layers. `CSPProvider.beat_node_now` carries the contract."""


        from cloudbasher.csp.aws import keepalive

        return keepalive.beat_node_now(node, state)

    def create_credential_provider(self, **kwargs: Any) -> CredentialProvider:
        """Create an AWS credential provider."""
        return AWSCredentialProvider(
            credential_file=kwargs.get("credential_file"),
            device_code=kwargs.get("device_code", False),
            region=kwargs.get("region", "us-west-1"),
            saved_state=kwargs.get("saved_state"),
            source=kwargs.get("source", "file"),
        )

    def create_api_client(
        self,
        credentials: Credentials,
        **kwargs: Any,
    ) -> CloudShellAPI:
        """Create an AWS CloudShell API client."""
        region = kwargs.get("region", "us-west-1")


        aws_creds = session_creds_from_extra(credentials.extra)


        artifact_dir = kwargs.get("artifact_dir")
        artifact_capture = None
        if artifact_dir:
            from cloudbasher.csp.aws.artifacts import ArtifactCapture

            artifact_capture = ArtifactCapture(artifact_dir)

        return AWSCloudShellAPI(
            region=region,
            credentials=aws_creds,
            timeout=kwargs.get("timeout", 30),
            proxy_url=kwargs.get("proxy_url"),
            proxy_insecure=kwargs.get("proxy_insecure", False),
            artifact_capture=artifact_capture,
            credential_record=kwargs.get("credential_record"),
            credential_registry=kwargs.get("credential_registry"),
        )

    def create_session(
        self,
        credentials: Credentials,
        environment_id: str,
        **kwargs: Any,
    ) -> CloudShellSession:
        """Create an AWS CloudShell session."""
        return AWSSession(
            stream_url=kwargs.get("stream_url", ""),
            token_value=kwargs.get("token_value", ""),
            environment_id=environment_id,
            timeout=kwargs.get("timeout", 60),
            proxy_url=kwargs.get("proxy_url"),
            proxy_insecure=kwargs.get("proxy_insecure", False),
            api_client=kwargs.get("api_client"),
            session_id=kwargs.get("session_id"),


            session_type=kwargs.get("session_type"),
        )

    def reconnect_node(self, state: Any, node: Any) -> CloudShellSession:
        """Satisfies csp.base.SupportsNodeReconnect -- delegates to multi_region.reconnect_node_session(), which does the actual credential-chain resolution + API/WebSocket reconnect work. Reads timeouts/proxy settings from state.args, matching every other AWS bootstrap call site's convention."""
        from cloudbasher.csp.aws.heartbeat import is_permanent_failure
        from cloudbasher.csp.aws.multi_region import reconnect_node_session

        args_ns = getattr(state, "args", None)


        for attempt, delay in enumerate((*_RECONNECT_BACKOFF_SECONDS, None), start=1):
            try:
                return reconnect_node_session(
                    state,
                    node,
                    env_wait_timeout=getattr(args_ns, "env_wait_timeout", 60),
                    http_timeout=getattr(args_ns, "http_timeout", 30),
                    ws_timeout=getattr(args_ns, "ws_timeout", 60),
                    proxy_url=getattr(args_ns, "proxy", None),
                    proxy_insecure=getattr(args_ns, "proxy_insecure", False),
                )
            except Exception as exc:


                if delay is None or is_permanent_failure(exc):
                    raise
                log(
                    f"[recover] reconnect attempt {attempt} failed for "
                    f"{node.id}, retrying in {delay:.0f}s: {exc}"
                )
                time.sleep(delay)


        raise AssertionError("the delay ladder always returns or raises")

    def node_client_is_usable(self, state: Any, node: Any, client: Any) -> bool:
        """Satisfies `SupportsNodeReconnect.node_client_is_usable` (#100)."""
        from cloudbasher.csp.aws.multi_region import node_client_is_usable

        return node_client_is_usable(state, node, client)

    def reconnect_node_api_client(self, state: Any, node: Any) -> Any:
        """Satisfies csp.base.SupportsNodeReconnect's control-plane-only counterpart to reconnect_node() -- delegates to multi_region.reconnect_node_api_client(), which skips the session/heartbeat setup reconnect_node_session() does. Same args-derived timeouts/proxy convention as reconnect_node() above."""
        from cloudbasher.csp.aws.multi_region import (
            reconnect_node_api_client as _reconnect_node_api_client,
        )

        args_ns = getattr(state, "args", None)
        return _reconnect_node_api_client(
            state,
            node,
            http_timeout=getattr(args_ns, "http_timeout", 30),
            proxy_url=getattr(args_ns, "proxy", None),
            proxy_insecure=getattr(args_ns, "proxy_insecure", False),
        )

    def detect_region(self, credentials: Credentials) -> Optional[str]:
        """Always None. There is no ambient region discovery on AWS."""
        return None


    def register_cli_args(self, parser: argparse.ArgumentParser) -> None:
        """No AWS-specific CLI flags. All five moved, and none was lost."""

    def probe_permissions(
        self, record: Any, *, extra_arns: Optional[list[str]] = None
    ) -> list[tuple[str, str, str]]:
        """`.creds <sel> perms` -- which derivations this credential can do."""
        from cloudbasher.csp.aws.commands import probe_record_permissions

        return probe_record_permissions(record, extra_arns=extra_arns)

    def refresh_credential(self, args: Any, state: Any, *, extra: Any = None) -> bool:
        """`.creds <ID> refresh` (I7). Named on the PROVIDER rather than registered as a dot-command because it is a SUBcommand of `.creds`, which the shared dispatcher owns -- the same shape `_cmd_creds_perms` already has. The dispatcher looks this up by name and says so when a CSP does not offer it."""
        from cloudbasher.csp.aws.commands import cmd_creds_refresh

        return cmd_creds_refresh(args, state, extra=extra)

    def unmanaged_rows(self, state: Any) -> "list[Any]":
        """AWS's answer for the Nodes pane's UNMANAGED view. `#504`."""
        try:
            from cloudbasher.csp.aws.commands import unmanaged_store
            from cloudbasher.csp.aws.unmanaged import display_rows

            return display_rows(unmanaged_store(state))
        except Exception:  # noqa: BLE001 - the pane is redrawn on every tick
            return []

    def unmanaged_to_dict(self, state: Any) -> "Optional[dict]":
        """`#520`. `None` when nothing has been scanned, so a session that never ran `.discover` writes no key -- and a restore of that file leaves the tab in its honest never-run state rather than an empty scanned one."""
        from cloudbasher.csp.aws.commands import unmanaged_store

        store = unmanaged_store(state)
        if store.never_run:
            return None
        return store.to_dict()

    def unmanaged_from_dict(self, state: Any, data: dict) -> None:
        """`#520`. Replaces the store wholesale -- this runs at bootstrap, before anything can have scanned, so there is nothing to merge with."""
        from cloudbasher.csp.aws.commands import _UNMANAGED_KEY
        from cloudbasher.csp.aws.unmanaged import UnmanagedStore

        if state.extra is None:
            state.extra = {}
        state.extra[_UNMANAGED_KEY] = UnmanagedStore.from_dict(data)

    def note_unregistered(self, state: Any, nodes: "list[Any]") -> None:
        """`#521`. Never raises: losing the tab row must not fail the unregister the user actually asked for."""
        try:
            from cloudbasher.csp.aws.commands import note_unregistered_nodes

            note_unregistered_nodes(state, nodes)
        except Exception:  # noqa: BLE001 - the unregister already succeeded
            pass

    def note_registered(self, state: Any, node: Any) -> None:
        """`#522`. Never raises: the registration is what matters."""
        env_id = getattr(node, "environment_id", None)
        if not env_id:
            return
        try:
            from cloudbasher.csp.aws.commands import request_table_refresh, unmanaged_store

            store = unmanaged_store(state)
            if any(f.environment_id == env_id for f in store.findings):
                store.drop({env_id})
                request_table_refresh(state)
        except Exception:  # noqa: BLE001
            pass

    def note_deleted(self, state: Any, environment_ids: "list[str]") -> None:
        """`#521`. Never raises: the delete already happened."""
        try:
            from cloudbasher.csp.aws.commands import request_table_refresh, unmanaged_store

            unmanaged_store(state).mark_deleted(set(environment_ids))
            request_table_refresh(state)
        except Exception:  # noqa: BLE001
            pass

    def unmanaged_meta(self, state: Any) -> "tuple[Optional[float], str]":
        """`(scanned_at, age)` -- `None` means no scan has run, which the tab renders as `(-)` rather than `(0)`."""
        try:
            from cloudbasher.csp.aws.commands import unmanaged_store
            from cloudbasher.csp.aws.unmanaged import scope_age

            store = unmanaged_store(state)
            return store.completed_at, scope_age(store)
        except Exception:  # noqa: BLE001
            return None, ""

    def register_dot_commands(self, dispatcher: Any) -> None:
        """Register AWS-specific dot commands."""
        from cloudbasher.core.cli.command_specs import CORE_SPECS
        from cloudbasher.csp.aws.commands import (
            DIAG_SPEC,
            DISCOVER_SPEC,
            ENUM_SPEC,
            GETDOWNLOADURLS_SPEC,
            GETUPLOADURLS_SPEC,
            PROVISION_SPEC,
            UNMANAGED_SPEC,
            cmd_diag,
            cmd_discover,
            cmd_enum,
            cmd_getdownloadurls,
            cmd_getuploadurls,
            cmd_provision,
            cmd_region,
            cmd_unmanaged,
        )

        dispatcher.register(".region", cmd_region, spec=CORE_SPECS[".region"])
        dispatcher.register(".getuploadurls", cmd_getuploadurls, spec=GETUPLOADURLS_SPEC)
        dispatcher.register(".getdownloadurls", cmd_getdownloadurls, spec=GETDOWNLOADURLS_SPEC)
        dispatcher.register(
            ".provision",
            cmd_provision,
            help="Provision new nodes (regions) for the active AWS identity (--multi-node)",


            spec=PROVISION_SPEC,
        )


        dispatcher.register(
            ".enum",
            cmd_enum,
            help=("Find CloudShell environments across regions; " "add `register` to adopt them"),


            spec=ENUM_SPEC,
        )


        dispatcher.register(
            ".discover",
            cmd_discover,
            help=(
                "Find CloudShell environments account-wide via CloudTrail, "
                "including ones no held credential can see"
            ),
            spec=DISCOVER_SPEC,
        )


        dispatcher.register(
            ".unmanaged",
            cmd_unmanaged,
            help=(
                "Delete or start tracking environments .discover/.enum found "
                "and cloudbasher is not managing"
            ),
            spec=UNMANAGED_SPEC,
        )
        dispatcher.register(
            ".diag",
            cmd_diag,
            help="4z reliability test harness: run|reconnect|verify|teardown a small identifiable fleet",

            spec=DIAG_SPEC,
        )

    def on_session_close(self, state: Any) -> None:
        """Release the session's console logins. `#553`."""
        from cloudbasher.csp.aws.control_plane import close_session_console_pool

        close_session_console_pool(state)

    def on_session_ready(self, state: Any, args: Any) -> None:
        """Post-bootstrap hook: confirm Playwright availability when the browser console-login mechanism was used. Selected by credential shape (pw_creds non-None), not by a flag -- see the -F auto-detection and _bootstrap_aws_session in cli/main.py."""
        if getattr(args, "pw_creds", None) is None:
            return
        from cloudbasher.core.utils.output import log, out

        try:
            from cloudbasher.csp.aws.browser import ensure_playwright_available

            ensure_playwright_available()
            out("[AWS] Playwright available — browser bootstrap enabled")
            log("[aws] playwright_available=True")
        except RuntimeError as e:
            from cloudbasher.core.utils.output import eprint

            eprint(f"[AWS] Playwright not available: {e}")
