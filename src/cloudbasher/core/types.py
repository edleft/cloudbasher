"""Shared type definitions for CloudBasher."""

from __future__ import annotations

import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, ClassVar, Collection, NamedTuple, Optional

if TYPE_CHECKING:
    from cloudbasher.core.node_supervisor import NodeSupervisor


_STATE_MAGIC = b"CSR\x01"
_SALT_LEN = 32
_NONCE_LEN = 12
_SCRYPT_N = 131072
_SCRYPT_R = 8
_SCRYPT_P = 1


AWS_IDENTITY_EXTRA_KEYS = (


    "act_as_mode",
    "role_arn",
    "federation_name",
    "role_session_name",
)


def carry_aws_identity_keys(src: dict, dest: dict) -> dict:
    """Copy the AWS identity declaration from one ``extra``-shaped dict to another."""
    for key in AWS_IDENTITY_EXTRA_KEYS:
        value = src.get(key)
        if value:
            dest[key] = value
    return dest


def _now_iso() -> str:
    """UTC timestamp, same format used throughout the app (prompts, save_state()'s saved_at, etc)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive 32-byte AES key from passphrase using scrypt."""
    from cryptography.hazmat.backends import default_backend  # type: ignore[import]
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # type: ignore[import]

    kdf = Scrypt(
        salt=salt, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, backend=default_backend()
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt_state(plaintext: bytes, passphrase: str) -> bytes:
    """Encrypt state bytes with AES-256-GCM."""
    import os as _os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import]

    salt = _os.urandom(_SALT_LEN)
    nonce = _os.urandom(_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, None)
    return _STATE_MAGIC + salt + nonce + ct_tag


def _decrypt_state(data: bytes, passphrase: str) -> bytes:
    """Decrypt state bytes. Raises ValueError on wrong passphrase or corruption."""
    from cryptography.exceptions import InvalidTag  # type: ignore[import]
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore[import]

    hdr = len(_STATE_MAGIC) + _SALT_LEN + _NONCE_LEN
    if len(data) < hdr + 16:
        raise ValueError("State file too short or corrupt")
    if data[: len(_STATE_MAGIC)] != _STATE_MAGIC:
        raise ValueError("Unrecognized state file format (not CSR encrypted state)")

    off = len(_STATE_MAGIC)
    salt = data[off : off + _SALT_LEN]
    off += _SALT_LEN
    nonce = data[off : off + _NONCE_LEN]
    off += _NONCE_LEN
    ct_tag = data[off:]

    key = _derive_key(passphrase, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct_tag, None)
    except InvalidTag:
        raise ValueError("Wrong passphrase or corrupt state file")


@dataclass
class Credentials:
    """CSP-agnostic credentials."""

    provider: str


    access_token: Optional[str] = field(default=None, repr=False)
    session_id: Optional[str] = field(default=None, repr=False)
    email: Optional[str] = field(default=None, repr=False)

    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    def get(self, key: str, default: Any = None) -> Any:
        """Get extra credential field."""
        return self.extra.get(key, default)


@dataclass
class SessionInfo:
    """Environment information."""

    environment_id: str
    region: str
    user: str
    hostname: str
    ip_address: str
    web_host: str


_RAW_KEY_IN_ID_RE = re.compile(r"(?<=:)((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})(?=:)")


def migrate_record_id(record_id: str) -> str:
    """Rewrite a persisted id that still embeds a raw access key."""
    if not record_id:
        return record_id


    from cloudbasher.core.utils.output import masked_key_id

    return _RAW_KEY_IN_ID_RE.sub(lambda m: masked_key_id(m.group(1)), record_id)


@dataclass
class CredentialRecord:
    """One identity in the multi-node credential registry."""

    id: str
    provider: str
    kind: str
    role: str
    parent_id: Optional[str]
    label: str
    raw: Credentials
    target_kind: Optional[str] = None
    target_ref: Optional[str] = None


    target_session_name: Optional[str] = None


    target_duration_seconds: Optional[int] = None


    source_block: Optional[int] = None


    status: str = "valid"
    derived: Optional[dict[str, Any]] = None


    _resolved_identity_arn: Optional[str] = field(
        default=None, init=False, repr=False, compare=False
    )


    _credential_verified: bool = field(default=False, init=False, repr=False, compare=False)
    _resolved_account: Optional[str] = field(default=None, init=False, repr=False, compare=False)
    _resolved_organization_name: Optional[str] = field(
        default=None, init=False, repr=False, compare=False
    )


    _identity_rejected: Optional[str] = field(default=None, init=False, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for state.bin persistence (registry, not the legacy single-credential slot)."""
        return {
            "id": self.id,
            "provider": self.provider,
            "kind": self.kind,
            "role": self.role,
            "parent_id": self.parent_id,
            "label": self.label,
            "raw": {
                "provider": self.raw.provider,
                "access_token": self.raw.access_token,
                "session_id": self.raw.session_id,
                "email": self.raw.email,
                "extra": self.raw.extra,
            },
            "target_kind": self.target_kind,
            "target_ref": self.target_ref,
            "target_session_name": self.target_session_name,
            "target_duration_seconds": self.target_duration_seconds,
            "source_block": self.source_block,

            "derived": self.derived,
            "_resolved_identity_arn": self._resolved_identity_arn,
            "_resolved_account": self._resolved_account,
            "_resolved_organization_name": self._resolved_organization_name,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "CredentialRecord":
        """Inverse of to_dict()."""
        raw_d = d["raw"]
        rec = cls(
            id=migrate_record_id(d["id"]),
            provider=d["provider"],
            kind=d["kind"],
            role=d["role"],
            parent_id=d.get("parent_id"),
            label=d.get("label", ""),
            raw=Credentials(
                provider=raw_d["provider"],
                access_token=raw_d.get("access_token"),
                session_id=raw_d.get("session_id"),
                email=raw_d.get("email"),
                extra=raw_d.get("extra") or {},
            ),
            target_kind=d.get("target_kind"),
            target_ref=d.get("target_ref"),
            target_session_name=d.get("target_session_name"),
            target_duration_seconds=d.get("target_duration_seconds"),
            source_block=d.get("source_block"),


            derived=d.get("derived"),
        )


        rec._resolved_identity_arn = d.get("_resolved_identity_arn")
        rec._resolved_account = d.get("_resolved_account")
        rec._resolved_organization_name = d.get("_resolved_organization_name")
        return rec


def numbered_originating_records(
    credentials_by_id: dict[str, "CredentialRecord"],
) -> list[tuple[int, "CredentialRecord"]]:
    """The registry's originating records, paired with the `<cred#>` that names them."""
    return [
        (n, rec)
        for n, rec in enumerate(
            (r for r in credentials_by_id.values() if r.role == "originating"), 1
        )
    ]


_MIGRATE_OLD_STATUS = {
    "N/A": "Unknown",
    "Pending": "Pending",
    "Connecting": "Unknown",
    "Running": "Running",
    "Suspended": "Suspended",
    "Failed": "Failed",
}


def record_env_id_for(node: "Optional[NodeRecord]") -> Callable[[str], None]:
    """The `on_environment_known` callback for `node`"""

    def _record(env_id: str) -> None:
        if node is not None:
            node.environment_id = env_id

    return _record


class ContainerTransition(NamedTuple):
    """Where a transitional `container_status` came FROM and is going TO."""

    leaving: "Optional[str]"
    heading: "Optional[str]"


CONTAINER_TRANSITIONS: "dict[str, ContainerTransition]" = {
    "Starting": ContainerTransition(leaving="Suspended", heading="Running"),
    "Suspending": ContainerTransition(leaving="Running", heading="Suspended"),
    "Pending": ContainerTransition(leaving=None, heading="Running"),
    "Transitioning": ContainerTransition(leaving=None, heading=None),
}


CONTROL_PLANE_UNASKED = ""
CONTROL_PLANE_OK = "confirmed"
CONTROL_PLANE_UNCONFIRMED = "timed-out"
CONTROL_PLANE_UNOBSERVABLE = "unobservable"


CONTROL_PLANE_ACCEPTED = "accepted"
CONTROL_PLANE_REJECTED = "rejected"
CONTROL_PLANE_DENIED = "authorization-denied"
CONTROL_PLANE_INCONCLUSIVE = "inconclusive"


CONTROL_PLANE_NO_IDENTITY = frozenset({CONTROL_PLANE_UNCONFIRMED, CONTROL_PLANE_UNOBSERVABLE})


def control_plane_identity(node: "NodeRecord") -> str:
    """Can this node's control plane sign a call? One of `CONTROL_PLANE_*`."""
    session = node._runtime_session
    if session is None:
        return CONTROL_PLANE_UNASKED
    return getattr(session, "cb_control_plane_identity", CONTROL_PLANE_UNASKED)


@dataclass
class NodeRecord:
    """One CloudShell environment (node) tied to a CredentialRecord."""

    id: str
    credential_id: str
    region: Optional[str]
    environment_id: Optional[str]
    session: Optional[SessionInfo]


    container_status: str = "N/A"


    seq: int = 0


    created_at: Optional[str] = field(default_factory=_now_iso)


    last_activity_at: Optional[str] = None


    keepalive_policy: str = ""


    _runtime_session: Optional[Any] = field(default=None, init=False, repr=False, compare=False)


    _runtime_control_plane_evidence: str = field(default="", init=False, repr=False, compare=False)
    _runtime_api_client: Optional[Any] = field(default=None, init=False, repr=False, compare=False)


    _runtime_prompt_probed_session: Optional[Any] = field(
        default=None, init=False, repr=False, compare=False
    )


    _recovery_lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )


    _runtime_parked_browser: Optional[Any] = field(
        default=None, init=False, repr=False, compare=False
    )


    _runtime_parked_shell_is_dead: bool = field(
        default=False, init=False, repr=False, compare=False
    )


    _connecting: bool = field(default=False, init=False, repr=False, compare=False)


    _runtime_build_owner: str = field(default="", init=False, repr=False, compare=False)


    _socket_ping_failures: int = field(default=0, init=False, repr=False, compare=False)


    _last_real_traffic_at: float = field(default=0.0, init=False, repr=False, compare=False)


    _last_failure_class: str = field(default="", init=False, repr=False, compare=False)


    _disconnecting: bool = field(default=False, init=False, repr=False, compare=False)


    _runtime_bridge_stop: Optional[threading.Event] = field(
        default=None, init=False, repr=False, compare=False
    )
    _runtime_bridge_thread: Optional[threading.Thread] = field(
        default=None, init=False, repr=False, compare=False
    )


    _runtime_reprojector: Optional[Any] = field(default=None, init=False, repr=False, compare=False)


    _runtime_supervisor_abandoned: str = field(default="", init=False, repr=False, compare=False)


    _BACKGROUND_LOOPS: ClassVar[tuple[tuple[str, str, str], ...]] = (
        ("heartbeat", "_runtime_heartbeat_stop", "_runtime_heartbeat_thread"),
        ("bridge", "_runtime_bridge_stop", "_runtime_bridge_thread"),
        ("relay", "_runtime_relay_keepalive_stop", "_runtime_relay_keepalive_thread"),
        ("pty", "_runtime_pty_keepalive_stop", "_runtime_pty_keepalive_thread"),
    )


    _NODE_OWNED_LOOPS: ClassVar[tuple[str, ...]] = ("bridge", "heartbeat")


    _SESSIONLESS_LOOPS: ClassVar[tuple[str, ...]] = ("heartbeat",)

    @classmethod
    def _loop_names_except(cls, exempt: "Collection[str]") -> tuple[str, ...]:
        """Every registered loop name that is not in `exempt`."""
        return tuple(name for name, _stop, _thread in cls._BACKGROUND_LOOPS if name not in exempt)

    @classmethod
    def server_session_loops(cls) -> tuple[str, ...]:
        """The loops holding a server-side session. See `_SESSIONLESS_LOOPS`."""
        return cls._loop_names_except(cls._SESSIONLESS_LOOPS)

    def retire_server_sessions(self) -> list[str]:
        """Retire EVERY server-side session this node owns"""
        retire = getattr(self._runtime_session, "retire_server_session", None)
        if callable(retire):
            retire()
        self.signal_background_loops()
        return self.join_background_loops(names=self.server_session_loops(), where="retire")


    _runtime_destroyed: bool = field(default=False, init=False, repr=False, compare=False)

    def mark_destroyed(self) -> None:
        """Record that this node's environment is gone. See `_runtime_destroyed`."""
        self._runtime_destroyed = True


    _runtime_queued: bool = field(default=False, init=False, repr=False, compare=False)

    def mark_queued(self) -> None:
        """Waiting for a pool thread."""
        self._runtime_queued = True

    def clear_queued(self) -> bool:
        """A worker reached this node, or never will. RETURNS whether it was set."""
        was_queued = self._runtime_queued
        self._runtime_queued = False
        return was_queued


    _runtime_working: bool = field(default=False, init=False, repr=False, compare=False)

    def mark_working(self) -> None:
        """A pool thread is executing this node's work."""
        self._runtime_working = True

    def clear_working(self) -> bool:
        """The worker finished, raised, or was cancelled. RETURNS whether it was set."""
        was_working = self._runtime_working
        self._runtime_working = False
        return was_working

    def begin_connect(self, build_owner: str = "") -> bool:
        """Mark a handshake in flight on this node, and say who owns it."""
        was_idle = not self._connecting
        self._connecting = True
        self._runtime_build_owner = build_owner
        return was_idle

    def end_connect(self) -> bool:
        """The handshake is over, however it ended. Clears BOTH flags."""
        was_held = self._connecting or bool(self._runtime_build_owner)
        self._connecting = False
        self._runtime_build_owner = ""
        return was_held

    def loops_for_scope(self, scope: str) -> Optional[tuple[str, ...]]:
        """The loop names a teardown of `scope` stops; `None` means all of them."""
        if scope == "node":
            return None
        if scope == "session":
            return self._loop_names_except(self._NODE_OWNED_LOOPS)
        raise ValueError(f"unknown teardown scope {scope!r}: expected 'node' or 'session'")

    def _selected_loops(self, names: Optional[Collection[str]]) -> tuple[tuple[str, str, str], ...]:
        """The registry entries `names` asks for; all of them when `None`."""
        if names is None:
            return self._BACKGROUND_LOOPS
        return tuple(entry for entry in self._BACKGROUND_LOOPS if entry[0] in names)

    def signal_background_loops(self, names: Optional[Collection[str]] = None) -> None:
        """Set every background loop's stop event. Cheap, non-blocking."""
        for _name, stop_attr, _thread_attr in self._selected_loops(names):
            stop = getattr(self, stop_attr, None)
            if stop is not None:
                stop.set()

    def straggler_sentence(self, name: str, ref: Optional[str] = None) -> str:
        """The ONE wording for "this loop outlived its join"."""
        return f"{name} for node {ref or self.id} did not stop in time"

    def join_background_loops(
        self,
        *,
        timeout: float = 2.0,
        names: Optional[Collection[str]] = None,
        where: str = "join",
    ) -> list[str]:
        """Join every background loop. LOGS, and returns, the names that did NOT stop."""
        from cloudbasher.core.utils.output import log

        stragglers: list[str] = []
        for name, _stop_attr, thread_attr in self._selected_loops(names):
            thread = getattr(self, thread_attr, None)
            if thread is None:
                continue
            thread.join(timeout=timeout)
            if not thread.is_alive():
                continue
            stragglers.append(name)
            log(
                f"[{where}] {self.straggler_sentence(name)}",
                once_key=f"straggler:{id(thread)}",
            )
        return stragglers

    def live_background_loops(self) -> list[str]:
        """The names of this node's loops that are still RUNNING."""
        live = []
        for name, _stop_attr, thread_attr in self._BACKGROUND_LOOPS:
            thread = getattr(self, thread_attr, None)
            if thread is not None and thread.is_alive():
                live.append(name)
        return live

    def reusable_background_loops(self) -> list[str]:
        """The names of this node's loops a new connect may KEEP rather than replace."""
        out = []
        for name, stop_attr, thread_attr in self._BACKGROUND_LOOPS:
            thread = getattr(self, thread_attr, None)
            stop = getattr(self, stop_attr, None)
            if thread is None or stop is None:
                continue
            if thread.is_alive() and not stop.is_set():
                out.append(name)
        return out

    def release_background_loops(self, names: Optional[Collection[str]] = None) -> None:
        """Drop the handles so the slots can be refilled."""
        for name, stop_attr, thread_attr in self._selected_loops(names):
            thread = getattr(self, thread_attr, None)
            if thread is not None and thread.is_alive():
                continue
            setattr(self, stop_attr, None)
            setattr(self, thread_attr, None)
            if name == "heartbeat":


                self._runtime_session_attacher = None
            elif name == "pty":
                self._runtime_pty_keepalive_attacher = None
            elif name == "relay":
                self._runtime_relay_keepalive_attacher = None

    _runtime_heartbeat_stop: Optional[threading.Event] = field(
        default=None, init=False, repr=False, compare=False
    )
    _runtime_heartbeat_thread: Optional[threading.Thread] = field(
        default=None, init=False, repr=False, compare=False
    )
    _runtime_pty_keepalive_stop: Optional[threading.Event] = field(
        default=None, init=False, repr=False, compare=False
    )
    _runtime_pty_keepalive_thread: Optional[threading.Thread] = field(
        default=None, init=False, repr=False, compare=False
    )
    _runtime_pty_keepalive_attacher: Optional[Any] = field(
        default=None, init=False, repr=False, compare=False
    )
    _runtime_relay_keepalive_stop: Optional[threading.Event] = field(
        default=None, init=False, repr=False, compare=False
    )
    _runtime_relay_keepalive_thread: Optional[threading.Thread] = field(
        default=None, init=False, repr=False, compare=False
    )
    _runtime_relay_keepalive_attacher: Optional[Any] = field(
        default=None, init=False, repr=False, compare=False
    )


    _runtime_session_attacher: Optional[Any] = field(
        default=None, init=False, repr=False, compare=False
    )


    _last_command_output: Optional[str] = field(default=None, init=False, repr=False, compare=False)


    _last_exit_code: Optional[int] = field(default=None, init=False, repr=False, compare=False)


    _last_command_error: Optional[str] = field(default=None, init=False, repr=False, compare=False)


    _heartbeat_retry_count: int = field(default=0, init=False, repr=False, compare=False)

    def mark_activity(self) -> None:
        """Stamp ``last_activity_at`` -- the ONE way that field is written."""
        self.last_activity_at = _now_iso()

    def record_command_result(self, output: Optional[str], exit_code: Optional[int]) -> None:
        """The command ran and was read. One of the two ways the three `.bulk` result fields are written (`#754(c)`); see `record_command_failure`."""
        self._last_command_output = output
        self._last_exit_code = exit_code
        self._last_command_error = None

    def record_command_failure(self, reason: str) -> None:
        """The command was dispatched and could not be READ. (`#754(c)`)"""
        self._last_command_output = None
        self._last_exit_code = None
        self._last_command_error = reason

    def last_command_summary(self) -> Optional[str]:
        """What to SHOW for the most recent `.bulk`: its output, or why there is none. `None` when no command has run, or when one ran and printed nothing -- those two are the same answer to a reader."""
        if self._last_command_output:
            return self._last_command_output
        if self._last_command_error:
            return f"<no output captured: {self._last_command_error}>"
        return None

    def mark_real_traffic(self) -> None:
        """Stamp ``_last_real_traffic_at`` -- the ONE way that field is written."""
        self._last_real_traffic_at = time.monotonic()

    def to_dict(self) -> dict[str, Any]:
        """Serialize for state.bin persistence."""
        return {
            "id": self.id,
            "credential_id": self.credential_id,
            "region": self.region,
            "environment_id": self.environment_id,
            "session": (
                {
                    "environment_id": self.session.environment_id,
                    "region": self.session.region,
                    "user": self.session.user,
                    "hostname": self.session.hostname,
                    "ip_address": self.session.ip_address,
                    "web_host": self.session.web_host,
                }
                if self.session
                else None
            ),
            "container_status": self.container_status,
            "seq": self.seq,
            "created_at": self.created_at,
            "last_activity_at": self.last_activity_at,


            "keepalive_policy": self.keepalive_policy,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "NodeRecord":
        """Inverse of to_dict()."""
        session_d = d.get("session")


        container_status = d.get("container_status")
        if container_status is None:
            legacy_status = d.get("status") or "N/A"
            container_status = _MIGRATE_OLD_STATUS.get(legacy_status, legacy_status)
        return cls(
            id=migrate_record_id(d["id"]),


            credential_id=migrate_record_id(d["credential_id"]),
            region=d.get("region"),
            environment_id=d.get("environment_id"),
            session=SessionInfo(**session_d) if session_d else None,
            container_status=container_status,
            seq=d.get("seq", 0),
            created_at=d.get("created_at"),
            last_activity_at=d.get("last_activity_at"),


            keepalive_policy=d.get("keepalive_policy") or "",
        )


@dataclass
class ShellPromptInfo:
    """Shell prompt metadata."""

    ip: str
    user: str
    host: str

    def format_prompt(self) -> str:
        """Format as [IP][user@host]$ ."""
        ip_part = f"[{self.ip}]" if self.ip else ""
        user_host = ""
        if self.user and self.host:
            user_host = f"[{self.user}@{self.host}]"
        elif self.user:
            user_host = f"[{self.user}]"
        elif self.host:
            user_host = f"[{self.host}]"
        return f"{ip_part}{user_host}$ " if ip_part or user_host else "$ "


@dataclass
class JobRecord:
    """A background job managed by the job-control layer."""

    job_id: int
    name: str
    thread: threading.Thread
    stop_event: threading.Event
    status: str = "running"


@dataclass
class InteractiveState:
    """Global interactive session state."""

    csp_provider: Any
    credentials: Optional[Credentials] = None
    api_client: Optional[Any] = None
    session: Optional[SessionInfo] = None
    command_history: list[str] = field(default_factory=list)
    shell_command_history: list[str] = field(default_factory=list)
    shell_prompt_info: Optional[ShellPromptInfo] = None
    in_shell_mode: bool = False
    ui_mode: str = "tui"
    heartbeat_stop: Optional[threading.Event] = None
    heartbeat_thread: Optional[threading.Thread] = None


    node_supervisor: Optional["NodeSupervisor"] = field(default=None, repr=False, compare=False)
    jobs: dict[int, JobRecord] = field(default_factory=dict)
    _next_job_id: int = field(default=1, init=False, repr=False)

    credentials_by_id: dict[str, CredentialRecord] = field(default_factory=dict)
    nodes_by_id: dict[str, NodeRecord] = field(default_factory=dict)
    active_node_id: Optional[str] = None


    _next_node_seq: int = field(default=1, init=False, repr=False, compare=False)

    extra: Optional[dict[str, Any]] = field(default=None)


    args: Optional[Any] = field(default=None, init=False, repr=False, compare=False)


    selected_node_ids: set[str] = field(default_factory=set, init=False, repr=False, compare=False)


    selected_credential_ids: set[str] = field(
        default_factory=set, init=False, repr=False, compare=False
    )


    selected_finding_ids: set[str] = field(
        default_factory=set, init=False, repr=False, compare=False
    )


    cursor_credential_id: Optional[str] = field(default=None, init=False, repr=False, compare=False)


    visible_row_node_ids: list[frozenset] = field(
        default_factory=list, init=False, repr=False, compare=False
    )


    delete_armed_selector: Optional[str] = field(
        default=None, init=False, repr=False, compare=False
    )


    pending_confirm: Optional[tuple] = field(default=None, init=False, repr=False, compare=False)


    last_node_action_message: Optional[str] = field(
        default=None, init=False, repr=False, compare=False
    )


    _passphrase: Optional[str] = field(default=None, init=False, repr=False)


    _credentials_lock: threading.Lock = field(
        default_factory=threading.Lock, init=False, repr=False, compare=False
    )

    def add_history(self, line: str) -> None:
        """Add to appropriate history."""
        if self.in_shell_mode:
            self.shell_command_history.append(line)
        else:
            self.command_history.append(line)

    def get_history(self) -> list[str]:
        """Get current history."""
        return self.shell_command_history if self.in_shell_mode else self.command_history

    def history_entry(self, index: int) -> str:
        """Return 1-based history entry. Raises IndexError if out of range."""
        entries = self.get_history()
        if index < 1 or index > len(entries):
            raise IndexError(f"No history entry #{index} (have {len(entries)})")
        return entries[index - 1]

    def save_state(self, path: str = "state.bin") -> None:
        """Encrypt and persist session info to state.bin for --resume."""
        if not self._passphrase:
            return

        import os

        data: dict[str, Any] = {
            "csp": self.csp_provider.name if self.csp_provider else "unknown",
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


        with self._credentials_lock:
            if self.session:
                data.update(
                    {
                        "environment_id": self.session.environment_id,
                        "region": self.session.region,
                        "user": self.session.user,
                        "hostname": self.session.hostname,
                        "ip_address": self.session.ip_address,
                        "web_host": self.session.web_host,
                    }
                )

            if self.credentials and self.credentials.provider == "gcp":


                from cloudbasher.csp.gcp.credentials import persist_extra as _gcp_persist

                cred_entry: dict[str, Any] = _gcp_persist(
                    self.credentials.extra or {},
                    access_token=self.credentials.access_token or "",
                )
                data["credentials"] = cred_entry
            elif self.credentials and self.credentials.provider == "aws":
                extra = self.credentials.extra or {}
                access_key = extra.get("access_key", "")
                secret_key = extra.get("secret_key", "")
                if access_key and secret_key:


                    from cloudbasher.csp.aws.credentials import key_extra_to_persist

                    data["credentials"] = key_extra_to_persist(extra)
                elif extra.get("username") and extra.get("password"):


                    from cloudbasher.csp.aws.credentials import browser_extra_to_persist


                    browser_entry = browser_extra_to_persist(extra)
                    if browser_entry:
                        data["credentials"] = browser_entry
            elif self.credentials and self.credentials.provider == "azure":


                from cloudbasher.csp.azure.types import persist_extra as _az_persist

                data["credentials"] = _az_persist(
                    self.credentials.extra or {},
                    access_token=self.credentials.access_token or "",
                )

                az_console = (self.extra or {}).get("azure_console")
                az_terminal = (self.extra or {}).get("azure_terminal")
                if az_console is not None:
                    data["azure_console"] = az_console.summary_dict()
                if az_terminal is not None:
                    data["azure_terminal"] = {
                        "terminal_id": az_terminal.terminal_id,
                        "socket_uri": az_terminal.socket_uri,
                        "idle_timeout": az_terminal.idle_timeout,
                        "root_directory": az_terminal.root_directory,
                        "shell": az_terminal.shell,
                    }
        try:
            plaintext = json.dumps(data, indent=2).encode("utf-8")
            encrypted = _encrypt_state(plaintext, self._passphrase)
            with open(path, "wb") as fh:
                fh.write(encrypted)
            os.chmod(path, 0o600)
        except OSError:
            pass

    @staticmethod
    def load_saved_state(
        path: str = "state.bin",
        passphrase: Optional[str] = None,
    ) -> dict[str, Any]:
        """Load persisted state dict. Returns {} if no file or decryption fails."""
        from pathlib import Path as _Path

        base = _Path(path).with_suffix("")
        bin_path = base.with_suffix(".bin")
        json_path = base.with_suffix(".json")

        if bin_path.exists():
            if not passphrase:
                raise ValueError(
                    f"{bin_path} exists but no passphrase was provided. "
                    "Re-run with the passphrase you set when the session was saved."
                )
            raw = bin_path.read_bytes()
            plaintext = _decrypt_state(raw, passphrase)
            return json.loads(plaintext.decode("utf-8"))


        if json_path.exists():
            try:
                return json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return {}

        return {}

    def save_registry(self, path: str = "state.bin") -> None:
        """Encrypt and persist the multi-node credential/node registry."""
        if not self._passphrase:
            return
        import os

        data = {
            "credential_records": [c.to_dict() for c in self.credentials_by_id.values()],
            "node_records": [n.to_dict() for n in self.nodes_by_id.values()],
            "active_node_id": self.active_node_id,
            "saved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


        try:
            hook = getattr(self.csp_provider, "unmanaged_to_dict", None)
            blob = hook(self) if hook is not None else None


            if isinstance(blob, dict) and blob:
                data["unmanaged"] = blob
        except Exception:  # noqa: BLE001 - the registry matters more than the tab
            pass
        try:
            plaintext = json.dumps(data, indent=2).encode("utf-8")
            encrypted = _encrypt_state(plaintext, self._passphrase)
            with open(path, "wb") as fh:
                fh.write(encrypted)
            os.chmod(path, 0o600)
        except OSError:
            pass

    @staticmethod
    def load_registry(
        path: str = "state.bin",
        passphrase: Optional[str] = None,
    ) -> tuple[dict[str, CredentialRecord], dict[str, NodeRecord], Optional[str], Optional[dict]]:
        """Load the persisted multi-node registry. Returns ({}, {}, None, None) if no file."""
        from pathlib import Path as _Path

        bin_path = _Path(path)
        if not bin_path.exists():
            return {}, {}, None, None
        if not passphrase:
            raise ValueError(
                f"{bin_path} exists but no passphrase was provided. "
                "Re-run with the passphrase you set when the session was saved."
            )
        raw = bin_path.read_bytes()
        plaintext = _decrypt_state(raw, passphrase)
        data = json.loads(plaintext.decode("utf-8"))
        credentials_by_id = {
            c["id"]: CredentialRecord.from_dict(c) for c in data.get("credential_records", [])
        }
        nodes_by_id = {n["id"]: NodeRecord.from_dict(n) for n in data.get("node_records", [])}


        return (
            credentials_by_id,
            nodes_by_id,
            data.get("active_node_id"),
            data.get("unmanaged"),
        )

    def register_node(self, node: "NodeRecord") -> None:
        """Add ``node`` to ``nodes_by_id``, assigning its stable "#"-column seq if it doesn't already have one (e.g. a node restored from state_multi.bin already carries its original seq -- never reassigned). Every code path that creates a NodeRecord should call this instead of writing ``nodes_by_id[node.id] = node`` directly, so every node -- default, provisioned, or reconnected -- ends up with a stable, never-recycled display number."""


        if node._runtime_destroyed:
            return
        if node.seq == 0:
            node.seq = self._next_node_seq
        self._next_node_seq = max(self._next_node_seq, node.seq + 1)
        self.nodes_by_id[node.id] = node


        try:
            hook = getattr(self.csp_provider, "note_registered", None)
            if hook is not None:
                hook(self, node)
        except Exception:  # noqa: BLE001 - the registration is what matters
            pass

    def add_job(self, name: str, thread: threading.Thread, stop_event: threading.Event) -> int:
        """Register a background job and return its job ID."""
        jid = self._next_job_id
        self._next_job_id += 1
        self.jobs[jid] = JobRecord(job_id=jid, name=name, thread=thread, stop_event=stop_event)
        return jid

    def _node_ref(self, node: "NodeRecord") -> str:
        """How a message names a node: its ADDRESSABLE id (`1.2`)."""
        from cloudbasher.core.node_ids import display_id_for

        return display_id_for(node.id, self.credentials_by_id, self.nodes_by_id) or node.id

    def invalidate_credential(
        self,
        credential_id: str,
        *,
        detected_on: Optional["NodeRecord"] = None,
        reason: str = "",
    ) -> list["NodeRecord"]:
        """Mark one credential dead across both registries after a heartbeat proved it can no longer authenticate, and cascade that to every node derived from it."""
        from cloudbasher.core.utils.output import log

        record = self.credentials_by_id.get(credential_id)
        if record is not None:
            if record.status == "invalid":
                return []
            record.status = "invalid"
        log(f"[credential] {credential_id} marked invalid" + (f": {reason}" if reason else ""))


        affected = [
            node
            for node in list(self.nodes_by_id.values())
            if node.credential_id == credential_id
            and not (detected_on is not None and node.id == detected_on.id)
        ]
        if not affected:
            return []


        from cloudbasher.core.cli.dispatcher import disconnect_node


        for node in affected:
            node.signal_background_loops()


        from cloudbasher.core.utils.perf_config import pool_width

        with ThreadPoolExecutor(
            max_workers=pool_width(len(affected)),
            thread_name_prefix="cb-invalidate",
        ) as pool:


            for node, future in [(n, pool.submit(disconnect_node, n)) for n in affected]:
                try:
                    future.result()
                except Exception as exc:
                    log("[credential] teardown of node " f"{self._node_ref(node)} raised: {exc}")


        for node in affected:
            node._runtime_api_client = None
            node.container_status = "Unknown"
            log(
                f"[credential] node {self._node_ref(node)} disconnected, "
                "container status Unknown -- its credential is gone, so its "
                "container state can no longer be verified"
            )
        return affected

    def revalidate_credential(self, credential_id: str, *, reason: str = "") -> bool:
        """Counter-evidence: this credential has just authenticated, so clear the invalid flag an earlier failure set. Does NOT un-cascade -- siblings disconnected by that failure stay disconnected with an Unknown container status, because nothing has been observed about their containers."""
        record = self.credentials_by_id.get(credential_id)
        if record is None or record.status != "invalid":
            return False
        record.status = "valid"
        from cloudbasher.core.utils.output import log

        log(
            f"[credential] {credential_id} cleared back to valid"
            + (f": {reason}" if reason else "")
        )
        return True

    def unowned_singleton_heartbeat(self) -> Optional["threading.Thread"]:
        """The primary slot's loop if NO node also holds it, else `None`."""
        thread = self.heartbeat_thread
        if thread is None:
            return None
        for node in self.nodes_by_id.values():
            if node._runtime_heartbeat_thread is thread:
                return None
        return thread

    def close(self) -> None:
        """Clean up resources: stop all background jobs, the primary session's heartbeat, and -- unify-connect-flow change -- every multi-node NodeRecord's own heartbeat and live session too. Before this, only the primary's singleton heartbeat_stop/heartbeat_thread were ever stopped; every provisioned/reconnected node's heartbeat thread (see NodeRecord._runtime_heartbeat_stop) would otherwise keep pinging AWS as an orphaned daemon thread for the rest of the process."""
        from collections import deque

        from cloudbasher.core.shutdown import begin_teardown
        from cloudbasher.core.utils.output import out
        from cloudbasher.core.utils.perf_config import pool_width


        begin_teardown()


        if self.node_supervisor is not None:
            self.node_supervisor.stop()
            self.node_supervisor = None


        if self.csp_provider is not None:
            try:
                self.csp_provider.on_session_close(self)
            except Exception as exc:  # noqa: BLE001 - a leak must not block the exit
                from cloudbasher.core.utils.output import detail

                detail(f"could not release this session's provider resources: {exc}")
        for job in list(self.jobs.values()):
            job.stop_event.set()
        if self.heartbeat_stop:
            self.heartbeat_stop.set()
        for node in self.nodes_by_id.values():
            node.signal_background_loops()

        nodes = list(self.nodes_by_id.values())


        unowned_heartbeat = self.unowned_singleton_heartbeat()
        heartbeat_count = len([n for n in nodes if n._runtime_heartbeat_thread is not None]) + (
            1 if unowned_heartbeat is not None else 0
        )
        session_count = len([n for n in nodes if n._runtime_session is not None])
        if heartbeat_count:
            out(f"Stopping {heartbeat_count} heartbeat(s)...")

        def _join_and_close(node: "NodeRecord") -> None:


            for straggler in node.join_background_loops(where="quit"):
                out(f"  {node.straggler_sentence(straggler, self._node_ref(node))}")
            if node._runtime_session is not None:
                try:
                    node._runtime_session.close()
                except Exception:
                    pass

        if nodes:
            if session_count:
                out(f"Closing {session_count} session(s)...")


            pending = deque(nodes)
            finished: set[str] = set()
            finished_lock = threading.Lock()

            def _drain_pending() -> None:
                while True:
                    try:
                        node = pending.popleft()
                    except IndexError:
                        return
                    try:
                        _join_and_close(node)
                    except Exception:  # noqa: BLE001
                        pass
                    with finished_lock:
                        finished.add(node.id)

            workers = [
                threading.Thread(target=_drain_pending, name=f"quit-teardown-{i}", daemon=True)
                for i in range(min(pool_width(len(nodes)), len(nodes)))
            ]
            for worker in workers:
                worker.start()
            deadline = time.monotonic() + NODE_TEARDOWN_BUDGET_SECONDS
            for worker in workers:
                worker.join(timeout=max(0.0, deadline - time.monotonic()))
            with finished_lock:
                stuck = [self._node_ref(n) or n.id for n in nodes if n.id not in finished]
            if stuck:


                out(
                    f"  {len(stuck)} node(s) did not finish teardown within "
                    f"{NODE_TEARDOWN_BUDGET_SECONDS:.0f}s and were left running "
                    f"in the background: {', '.join(stuck)}"
                )


        if unowned_heartbeat is not None:
            unowned_heartbeat.join(timeout=2.0)


NODE_TEARDOWN_BUDGET_SECONDS = 10.0


SOCKET_DEAD_AFTER_FAILURES = 2


SESSION_IDLE_TIMEOUT_SECONDS = 19.5 * 60


def last_real_traffic_at(node: Any) -> Optional[float]:
    """When this node's session last carried REAL channel traffic, or None."""
    stamp = getattr(node, "_last_real_traffic_at", 0.0)
    if not stamp:
        return None
    return float(stamp)


def session_idle_remaining(node: Any, now_monotonic: float) -> Optional[float]:
    """Seconds until this node's shell session dies of idleness, or None."""
    stamp = last_real_traffic_at(node)
    if stamp is None:
        return None
    return SESSION_IDLE_TIMEOUT_SECONDS - (now_monotonic - stamp)


def node_socket_is_dead(node: Any) -> bool:
    """Has this node's shell socket failed enough pings to be called dead?"""
    if node is None:
        return False
    return getattr(node, "_socket_ping_failures", 0) >= SOCKET_DEAD_AFTER_FAILURES
