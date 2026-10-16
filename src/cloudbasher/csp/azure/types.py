"""Azure-specific types: ConsoleInfo, TerminalInfo, CommandRunOptions."""

from __future__ import annotations

import datetime
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, NamedTuple, Optional

from cloudbasher.core.types import Credentials
from cloudbasher.core.utils.timestamps import iso_to_epoch


@dataclass
class ConsoleInfo:
    """Azure CloudShell console (ARM resource)."""

    console_id: str
    uri: str
    provisioning_state: str
    os_type: str = "Linux"
    region: str = "westus"

    @property
    def is_ready(self) -> bool:
        return self.provisioning_state == "Succeeded"

    def summary_dict(self) -> dict[str, Any]:
        return {
            "console_id": self.console_id,
            "uri": self.uri,
            "provisioning_state": self.provisioning_state,
            "os_type": self.os_type,
            "region": self.region,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ConsoleInfo":
        return cls(
            console_id=d["console_id"],
            uri=d["uri"],
            provisioning_state=d.get("provisioning_state", "Succeeded"),
            os_type=d.get("os_type", "Linux"),
            region=d.get("region", "westus"),
        )


@dataclass
class TerminalInfo:
    """Azure CloudShell terminal session (WebSocket endpoint)."""

    terminal_id: str
    socket_uri: str
    idle_timeout: int = 20
    root_directory: str = "/home"
    shell: str = "bash"

    def summary_dict(self) -> dict[str, Any]:
        return {
            "terminal_id": self.terminal_id,
            "socket_uri": self.socket_uri,
            "idle_timeout": self.idle_timeout,
            "root_directory": self.root_directory,
            "shell": self.shell,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TerminalInfo":
        return cls(
            terminal_id=d["terminal_id"],
            socket_uri=d["socket_uri"],
            idle_timeout=int(d.get("idle_timeout", 20)),
            root_directory=d.get("root_directory", "/home"),
            shell=d.get("shell", "bash"),
        )


@dataclass
class CommandRunOptions:
    """Options collected from CLI arguments for a single Azure run."""

    command: Optional[str] = None
    upload: Optional[tuple[str, str]] = None
    download: Optional[tuple[str, str]] = None
    list_path: Optional[str] = None
    subscription_id: Optional[str] = None
    resource_group: Optional[str] = None
    region: str = "westus"
    shell: str = "bash"
    env_wait_timeout: int = 120
    http_timeout: int = 30
    ws_timeout: int = 60
    proxy_url: Optional[str] = None
    proxy_insecure: bool = False
    keep_stderr_progress: bool = False


NETWORK_TYPE_ISOLATED = "Isolated"


def resolve_storage_profile(props: dict[str, Any]) -> dict[str, Any]:
    """The storage profile that is actually in force for this console."""
    isolated = (props.get("vnetSettings") or {}).get("isolatedStorageProfile")


    return isolated or props.get("storageProfile") or {}


def is_isolated_console(props: dict[str, Any]) -> bool:
    """True when `userSettings` describes a VNet-isolated console."""
    return props.get("networkType") == NETWORK_TYPE_ISOLATED


_NON_SERIALIZABLE_EXTRA = frozenset({"msal_app", "msal_account"})


def to_unified(
    access_token: str,
    tenant_id: str,
    subscription_id: str,
    *,
    refresh_token: Optional[str] = None,
    token_expiry: Optional[datetime.datetime] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    email: Optional[str] = None,
    extra: Optional[dict[str, Any]] = None,
) -> Credentials:
    """Pack Azure auth fields into a unified Credentials object."""
    return Credentials(
        provider="azure",
        access_token=access_token,
        email=email,
        extra={
            "tenant_id": tenant_id,
            "subscription_id": subscription_id,
            "refresh_token": refresh_token,
            "token_expiry": token_expiry.isoformat() if token_expiry else None,
            "client_id": client_id,
            "client_secret": client_secret,
            **(extra or {}),
        },
    )


def from_unified(creds: Credentials) -> dict[str, Any]:
    """Unpack Azure auth fields from a unified Credentials object."""
    extra = creds.extra or {}
    expiry: Optional[datetime.datetime] = None
    raw_expiry = extra.get("token_expiry")
    if raw_expiry:
        try:
            expiry = datetime.datetime.fromisoformat(raw_expiry)
        except (TypeError, ValueError):
            pass
    return {
        "access_token": creds.access_token or "",
        "tenant_id": extra.get("tenant_id", ""),
        "subscription_id": extra.get("subscription_id", ""),
        "refresh_token": extra.get("refresh_token"),
        "token_expiry": expiry,
        "client_id": extra.get("client_id"),
        "client_secret": extra.get("client_secret"),
        "email": creds.email or extra.get("email"),
        "msal_app": extra.get("msal_app"),
        "msal_account": extra.get("msal_account"),


        "certificate_path": extra.get("certificate_path"),
        "certificate_pem": extra.get("certificate_pem"),
        "certificate_password": extra.get("certificate_password"),
    }


def is_token_expiring(creds: Credentials, threshold_seconds: float = 300.0) -> bool:
    """Return True if the Azure access token expires within threshold_seconds."""
    exp = iso_to_epoch((creds.extra or {}).get("token_expiry"))
    return exp is not None and exp - time.time() < threshold_seconds


def serializable_extra(extra: dict[str, Any]) -> dict[str, Any]:
    """Strip non-serializable keys before persisting to state.bin."""
    return {k: v for k, v in extra.items() if k not in _NON_SERIALIZABLE_EXTRA}


def persist_extra(extra: dict[str, Any], *, access_token: str) -> dict[str, Any]:
    """The Azure credential as ``state.bin``'s ``credentials`` slot. `#594`."""
    out = serializable_extra(extra)
    out["access_token"] = access_token or ""
    expiry = out.get("token_expiry")
    if expiry is not None:
        out["token_expiry"] = expiry if isinstance(expiry, str) else expiry.isoformat()
    return out


class ConsoleWrite(NamedTuple):
    """The result of `PUT consoles/default`, status code included."""

    status: int
    console: ConsoleInfo

    @property
    def created(self) -> bool:
        """True when this PUT created the record; False when it updated one."""
        return self.status == 201


class ConsoleDelete(NamedTuple):
    """The result of `DELETE consoles/default`, status code included."""

    status: int

    @property
    def existed(self) -> bool:
        """True when a console was there and this DELETE destroyed it."""
        return self.status == 200

    @property
    def decisive(self) -> bool:
        """True when the status is one this verb's state machine defines."""
        return self.status in (200, 204)


def parse_console_id_from_uri(uri: str) -> str:
    """Extract console ID from Service Bus URI."""
    return uri.rstrip("/").rsplit("/", 1)[-1]


_ACI_RELAY_HOST = re.compile(r"^ccon-[a-z0-9]+-(?P<region>[a-z0-9]+)-aci-\d+$")


def parse_region_from_uri(uri: str) -> Optional[str]:
    """Extract the region from a Service Bus URI host, or None if it has none."""


    host = urllib.parse.urlparse(uri).hostname or ""
    match = _ACI_RELAY_HOST.match(host.split(".")[0])
    return match.group("region") if match else None
