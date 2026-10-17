"""Abstract base classes for Cloud Service Provider implementations."""

from __future__ import annotations

import argparse
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, ClassVar, Optional, Protocol, runtime_checkable

from ..core.types import Credentials


class CloudShellSession(ABC):
    """Abstract SSH/shell session interface."""


    condemned_reason: Optional[str] = None

    @property
    def is_condemned(self) -> bool:
        """Has this handle been marked unusable? Never raises."""
        return self.condemned_reason is not None

    def ensure_connected(self) -> None:
        """Open the transport NOW, rather than on the first command. Optional."""
        return None

    def condemn(self, reason: str) -> None:
        """Mark this handle unusable. Idempotent; the FIRST reason wins."""
        if self.condemned_reason is None:
            self.condemned_reason = reason

    def clear_condemnation(self) -> None:
        """Withdraw the mark, on the same evidence that set it."""
        self.condemned_reason = None

    def interrupt_shell_command(self) -> None:
        """Send ETX to an active interactive-shell command, if supported."""
        from ..core.exceptions import SessionError

        raise SessionError("remote shell interruption is not supported by this session")

    def request_shell_interrupt(self, *, grace_seconds: float = 5.0) -> None:
        """Send remote Ctrl-C and bound how long the local reader will wait."""
        if getattr(self, "_shell_interrupt_requested_at", None) is not None:
            return
        self._shell_interrupt_requested_at = time.monotonic()
        self._shell_interrupt_grace_seconds = max(0.1, float(grace_seconds))
        try:
            self.interrupt_shell_command()
        except Exception:
            self.clear_shell_interrupt_request()
            raise

    def shell_interrupt_grace_expired(self) -> bool:
        """Has an interrupt remained unacknowledged beyond its local grace?"""
        requested_at = getattr(self, "_shell_interrupt_requested_at", None)
        grace = getattr(self, "_shell_interrupt_grace_seconds", 5.0)
        return requested_at is not None and time.monotonic() - requested_at >= grace

    def clear_shell_interrupt_request(self) -> None:
        """Clear the interrupt timer after observed command completion."""
        self._shell_interrupt_requested_at = None

    def mark_shell_command_uncertain(self) -> None:
        """Block further commands until this session is explicitly reconnected."""
        self._shell_command_uncertain = True

    def assert_shell_command_safe(self) -> None:
        """Refuse to reuse a stream whose previous command boundary was lost."""
        from ..core.exceptions import SessionError

        if self.is_condemned:
            raise SessionError(
                f"this session handle is no longer usable: {self.condemned_reason}"
            )

        if getattr(self, "_shell_command_uncertain", False):
            raise SessionError(
                "the previous shell command did not reach a confirmed completion; "
                "reconnect the node before issuing another command"
            )

    def clear_shell_command_uncertainty(self) -> None:
        """A newly established transport is a safe boundary for new commands."""
        self._shell_command_uncertain = False

    @abstractmethod
    def exec_command(
        self,
        cmd: str,
        timeout: int = 60,
        raw: bool = False,
        *,
        record_history: bool = False,
    ) -> str:
        """Execute command and return output."""
        pass

    @abstractmethod
    def exec_in_shell(self, cmd: str, timeout: int = 60, raw: bool = False) -> str:
        """Execute command in persistent shell and return output."""
        pass

    @abstractmethod
    def open_shell(self) -> None:
        """Open shell PTY."""
        pass

    @abstractmethod
    def interactive_shell(self) -> None:
        """Enter interactive shell mode."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close session."""
        pass

    @abstractmethod
    def upload_file(self, local_path: str, remote_path: str) -> Optional[str]:
        """Upload a local file; optionally return its effective remote path."""
        pass

    @abstractmethod
    def download_file(self, remote_path: str, local_path: str) -> None:
        """Download a file from the CloudShell environment."""
        pass


class CloudShellAPI(ABC):
    """Abstract CloudShell API client."""

    @abstractmethod
    def describe_environments(self) -> dict[str, Any]:
        """List environments."""
        pass

    @abstractmethod
    def create_environment(self) -> dict[str, Any]:
        """Create new environment."""
        pass


@runtime_checkable
class SupportsFileTransfer(Protocol):
    """Optional capability: presigned-URL-style file transfer (AWS-shaped)."""

    def get_file_upload_urls(self, environment_id: str, file_path: str) -> dict[str, Any]:
        """Get presigned upload URLs."""
        ...

    def get_file_download_urls(self, environment_id: str, file_path: str) -> dict[str, Any]:
        """Get presigned download URLs."""
        ...


@runtime_checkable
class SupportsCredentialInjection(Protocol):
    """Optional capability: inject caller credentials into the running shell."""

    def put_credentials(self, env_id: str, creds: dict[str, Any]) -> dict[str, Any]:
        """Put credentials into the CloudShell environment."""
        ...


@runtime_checkable
class SupportsEnvironmentLifecycle(Protocol):
    """Optional capability: query/start an environment by short ID."""

    def get_environment_status(self, environment_id: str) -> dict[str, Any]:
        """Get environment status."""
        ...

    def start_environment(self, environment_id: str) -> dict[str, Any]:
        """Start a stopped/suspended environment."""
        ...


@runtime_checkable
class SupportsNodeReconnect(Protocol):
    """Optional capability: re-open a live session for a node whose connection isn't currently held."""

    def reconnect_node(self, state: Any, node: Any) -> CloudShellSession:
        """Re-open and return a live CloudShellSession for `node`, resolving (and re-deriving if expired) whatever identity it needs from `state.credentials_by_id`. Raises on failure -- callers decide how to report/isolate that (e.g. .bulk's per-node failed list)."""
        ...

    def reconnect_node_api_client(self, state: Any, node: Any) -> Any:
        """Re-derive credentials and return a fresh API client for `node`, without opening a live shell session or starting a heartbeat -- the control-plane-only counterpart to `reconnect_node`, for operations (.delete/.start/.stop) that only need to call REST endpoints (delete_environment/start_environment/stop_environment/ get_environment_status) and don't need an interactive session. Raises on failure, same contract as `reconnect_node`."""
        ...


@runtime_checkable
class SupportsEnvironmentDeletion(Protocol):
    """Optional capability: permanently delete an environment by short ID (4s, 4z harness prerequisite)."""

    def delete_environment(self, environment_id: str) -> dict[str, Any]:
        """Permanently delete the environment. Raises on failure."""
        ...


@runtime_checkable
class SupportsEnvironmentSuspension(Protocol):
    """Optional capability: stop/suspend a running environment by short ID."""

    def get_environment_status(self, environment_id: str) -> dict[str, Any]:
        """Get environment status."""
        ...

    def stop_environment(self, environment_id: str) -> dict[str, Any]:
        """Suspend a running environment. Raises on failure."""
        ...


class CredentialProvider(ABC):
    """Abstract credential loader."""

    @abstractmethod
    def load(self) -> Credentials:
        """Load credentials."""
        pass

    @abstractmethod
    def refresh(self) -> Credentials:
        """Refresh credentials."""
        pass


class CSPProvider(ABC):
    """Abstract Cloud Service Provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name: 'aws', 'gcp', etc."""
        pass

    @abstractmethod
    def create_api_client(self, creds: Credentials) -> CloudShellAPI:
        """Create API client."""
        pass

    @abstractmethod
    def create_session(
        self, creds: Credentials, env_id: str, region: Optional[str] = None
    ) -> CloudShellSession:
        """Create shell session."""
        pass

    @abstractmethod
    def create_credential_provider(self, **kwargs) -> CredentialProvider:
        """Create credential provider."""
        pass

    @abstractmethod
    def detect_region(self, creds: Credentials) -> Optional[str]:
        """Detect default region from environment."""
        pass

    def register_cli_args(self, parser: argparse.ArgumentParser) -> None:
        """Inject CSP-specific CLI flags into the shared argument parser."""

    def register_dot_commands(self, dispatcher: Any) -> None:
        """Register CSP-specific dot commands via dispatcher.register()."""

    def on_session_ready(self, state: Any, args: Any) -> None:
        """Called after bootstrap; start CSP-specific background work."""

    def on_session_close(self, state: Any) -> None:
        """Called from `InteractiveState.close()`; release CSP-scoped resources."""

    def unmanaged_rows(self, state: Any) -> "list[Any]":
        """Rows for the Nodes pane's UNMANAGED view -- environments this CSP has found but cloudbasher is not tracking"""
        return []

    def unmanaged_to_dict(self, state: Any) -> "Optional[dict]":
        """The UNMANAGED set as JSON for `state.bin`, or None"""
        return None

    def unmanaged_from_dict(self, state: Any, data: dict) -> None:
        """Restore what `unmanaged_to_dict` wrote"""

    def note_unregistered(self, state: Any, nodes: "list[Any]") -> None:
        """Nodes just dropped from the registry -- move them to the UNMANAGED view"""

    def note_registered(self, state: Any, node: Any) -> None:
        """A node just entered the registry -- drop it from the UNMANAGED view"""

    def note_deleted(self, state: Any, environment_ids: "list[str]") -> None:
        """Environments just DESTROYED -- grey any UNMANAGED row showing them. The other half of ``note_unregistered``."""

    def unmanaged_meta(self, state: Any) -> "tuple[Any, str]":
        """`(scanned_at, human age)` for the UNMANAGED view's tab"""
        return None, ""


    KEEPALIVE_LAYERS: ClassVar[tuple[tuple[int, str, str], ...]] = ((1, "env", "heartbeat"),)

    def beat_node_now(self, node: Any, state: Any) -> tuple[list[str], list[str]]:
        """One node's MANUAL beat. Returns `(sent, skipped)` layer labels."""
        layer, label, _mech = self.KEEPALIVE_LAYERS[0]
        return beat_environment_layer(node, f"{layer} {label}")


def beat_environment_layer(
    node: Any,
    name: str,
    *,
    on_failure: "Optional[Callable[[Exception], None]]" = None,
) -> tuple[list[str], list[str]]:
    """Layer 1 -- the environment heartbeat -- as `(sent, skipped)`."""
    from ..core.session.keepalive_policy import runs_layer

    if not runs_layer(node, 1):
        return [], [f"{name} (policy)"]
    api = getattr(node, "_runtime_api_client", None)
    env_id = getattr(node, "environment_id", None)
    if api is None or not env_id:
        return [], [f"{name} (no client)"]
    try:
        api.send_heartbeat(env_id)
    except Exception as exc:
        if on_failure is not None:
            on_failure(exc)
        return [], [f"{name} FAILED: {exc}"]
    return [name], []
