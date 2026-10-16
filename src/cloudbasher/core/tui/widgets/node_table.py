"""Multi-node/multi-credential table."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from functools import lru_cache, partial
from types import MappingProxyType, SimpleNamespace
from typing import Any, Mapping, NamedTuple, Optional

from rich.cells import cell_len, set_cell_size
from rich.color import Color
from rich.text import Text
from textual import events
from textual.binding import Binding
from textual.coordinate import Coordinate
from textual.message import Message
from textual.strip import Strip
from textual.widgets import DataTable

from cloudbasher.core import identity_listing as _il
from cloudbasher.core.control_plane_status import normalize_control_plane_evidence
from cloudbasher.core.session import failure as _fl
from cloudbasher.core.session.activity import activity_of
from cloudbasher.core.session.keepalive_policy import layer_is_live, policy_of
from cloudbasher.core.tui.keymap import node_table_bindings
from cloudbasher.core.types import (
    CONTAINER_TRANSITIONS,
    CredentialRecord,
    NodeRecord,
    control_plane_identity,
    node_socket_is_dead,
    session_idle_remaining,
)
from cloudbasher.core.utils.output import rich_to_ansi
from cloudbasher.core.utils.perf_config import get_heartbeat_max_retries
from cloudbasher.core.utils.redact import redact_field, redact_text

from .node_subtable import (
    BORDER_STYLE,
    GAP,
    GROUP_RAIL,
    MINT_FRAME_FIELDS,
    MINT_RAIL,
    MINT_STYLE,
    SubTableLine,
    fit,
)


UNADDRESSABLE_DISPLAY_ID = "\u2014"


@dataclass
class NodeDisplayRow:
    """Real-data equivalent of the prototype's dummy ``CredNode`` (node rows only -- credential-only records don't get their own row, matching the prototype's ``flatten_for_table()``)."""

    node_id: str
    credential_id: str
    csp: str
    cred_type: str
    identity: str
    target_identity: str
    can_procreate: bool


    container_status: str
    connection: str
    ip: str
    host: str
    region: str
    acct: str = "—"


    cred_unbound: bool = False


    failure_label: str = ""


    root_credential_id: str = ""


    target_acct: str = "—"


    seq: int = 0


    display_id: str = UNADDRESSABLE_DISPLAY_ID


    environment_id: str = "—"


    shared_env: bool = False


    target_identity_full: str = "—"
    armor_locked: bool = False
    armor_shielded: bool = False
    beacon: str = "—"
    conn: str = "—"
    created: str = "—"
    last: str = "—"


    last_kind: str = ""


    idle_remaining: Optional[float] = None


    supervisor_note: str = ""


    container_unbound: str = ""
    uptime_display: str = "—"
    selected: bool = False


    exit_code: str = "—"
    command_output_preview: str = "—"


    control_plane: str = "Unasked"


    heartbeat_retry_count: int = 0
    heartbeat_max_retries: int = 0


    activity_detail: str = ""


    queued: bool = False


    working: bool = False


_provider_display_code = _il.provider_display_code
_is_unbound_credential = _il.is_unbound_credential


_ENVIRONMENTS_PER_REGION = 10


_GROUP_KEY_PREFIX = "grp:"


def group_row_key(credential_id: str) -> str:
    """The table row key for a credential's own row."""
    return f"{_GROUP_KEY_PREFIX}{credential_id}"


def _mints_principals(facts: Optional["CredGroupKey"]) -> bool:
    """Does this credential mint new principals (`ACT_AS=role|federated`)?"""
    if facts is None:
        return False
    return facts.node_ceiling > _region_count()


@lru_cache(maxsize=1)
def _region_count() -> int:
    from cloudbasher.csp.aws.multi_region import _ALL_REGIONS

    return len(_ALL_REGIONS)


def compose_row_line(
    plan: Any,
    cells: dict[str, str],
    rich: Optional[dict[str, Text]] = None,
    *,
    frame: bool = False,
) -> Text:
    """One credential line, as `Text` so a cell can carry its glyphs."""
    out = Text()
    previous_group = None
    for index, (col, width) in enumerate(plan):
        if index:


            if col.group != previous_group:
                out.append(" ")
                out.append(GROUP_RAIL, style=BORDER_STYLE)
                out.append(" ")
            else:
                out.append(" " * GAP)


        if col.field == MINT_FRAME_FIELDS[0]:
            out.append(MINT_RAIL if frame else " ", style=MINT_STYLE)
        previous_group = col.group
        plain = cells.get(col.field, "")
        shown = fit(plain, width, col)
        cell = rich.get(col.field) if rich else None
        if cell is not None and shown == plain:


            fixed = cell.copy()
            fixed.truncate(width, overflow="crop", pad=True)
            out.append_text(fixed)
        else:


            out.append(set_cell_size(shown, width))
        if col.field == MINT_FRAME_FIELDS[-1]:
            out.append(MINT_RAIL if frame else " ", style=MINT_STYLE)
    return out


def _node_ceiling(root: Optional["CredentialRecord"]) -> int:
    """How many CloudShell environments `root` could ever have."""
    if root is None or getattr(root, "provider", None) != "aws":
        return 1
    from cloudbasher.csp.aws.act_as import DERIVING_MODES
    from cloudbasher.csp.aws.provision_request import act_as_mode

    per_region = _ENVIRONMENTS_PER_REGION if act_as_mode(root) in DERIVING_MODES else 1
    return _region_count() * per_region


_cred_type_code = _il.cred_type_code


def resolve_credential_display(
    credential_id: Optional[str],
    credentials_by_id: dict[str, CredentialRecord],
    *,
    key_shown_elsewhere: bool = False,
) -> tuple[str, str, str, Optional[CredentialRecord]]:
    """Return (cred_type, identity, target_identity, root) for a node's credential."""
    record = credentials_by_id.get(credential_id) if credential_id else None
    if record is None:
        return "—", "—", "—", None
    if record.role == "originating":
        return (
            _cred_type_code(record),
            _identity_display(record, key_shown_elsewhere=key_shown_elsewhere),
            _originating_target_display(record),
            record,
        )


    from cloudbasher.core.node_ids import originating_root_record

    root = originating_root_record(credential_id, credentials_by_id)
    return (
        _cred_type_code(root),
        _identity_display(root, key_shown_elsewhere=key_shown_elsewhere),
        _il.target_identity_display(record),
        root,
    )


def _originating_target_display(record: CredentialRecord) -> str:
    """What the Target Identity column shows for a node still pointing at an ORIGINATING credential -- i.e. one with no recorded derivation."""


    if record._resolved_identity_arn:
        return _il.resolved_arn_display(record._resolved_identity_arn)
    extra = getattr(getattr(record, "raw", None), "extra", None) or {}
    if (
        record.provider == "azure"
        and (extra.get("refresh_token") or extra.get("access_token"))
    ) or _il.is_gcp_oauth_credential(record):


        return _il.identity_cell(record, extra)
    if record.kind == "console":


        extra = getattr(getattr(record, "raw", None), "extra", None) or {}


        return _il.short_identity(extra) or "console"
    if record.kind == "temporary":


        if getattr(record, "_identity_rejected", None):
            return "(unresolved)"
        return "(pending)"


    from cloudbasher.csp.aws.act_as import DIRECT_MODES
    from cloudbasher.csp.aws.provision_request import act_as_mode

    mode = act_as_mode(record)
    if mode in DIRECT_MODES:
        return f"({mode} — no derivation)"
    return "(resolving…)"


def _cred_id_column_present() -> bool:
    """Does the credential row's layout carry a `Cred ID` column?"""
    from cloudbasher.core.tui.widgets.node_subtable import block_enabled

    return block_enabled()


def _identity_display(record: CredentialRecord, *, key_shown_elsewhere: bool = False) -> str:
    """The Identity column must show the credential's real AWS/GCP/Azure identity (e.g. an IAM user ARN via sts:GetCallerIdentity, resolved asynchronously by tui_mode.py's _resolve_and_push_multi_node_identities -- a real API round trip, not something available at file-parse time), never the raw credential material itself (access key, etc). Falls back to the file-parsing label (record.label) until that resolution completes or for CSPs/credential kinds it doesn't cover yet."""
    extra = getattr(getattr(record, "raw", None), "extra", None) or {}
    if _il.is_gcp_oauth_credential(record):


        return _il.identity_cell(record, extra)
    return _il.identity_cell(
        record,
        extra,
        resolved_arn=record._resolved_identity_arn or "",


        rejected=bool(getattr(record, "_identity_rejected", None)),
        key_shown_elsewhere=key_shown_elsewhere,
    )


def _drop_year(ts: str) -> str:
    """Trim a leading "YYYY-" from an ISO-shaped timestamp to save table width (user-reported: Created/Last made the row too wide) -- storage (NodeRecord.created_at/last_activity_at, session._last_heartbeat_at) keeps the full timestamp; only display is shortened. Also swaps the ISO "T" date/time separator for a space (user-reported: "07-29T07:46: 13Z" is harder to read than "07-29 07:46:13Z" in an already-narrow column). No-op for anything not shaped like our own _now_iso() output, e.g. the "—" placeholder."""
    if len(ts) >= 5 and ts[4] == "-" and ts[:4].isdigit():
        ts = ts[5:]
    return ts.replace("T", " ", 1)


def _control_plane_state(node: NodeRecord) -> str:
    """Render the latest normalized control-plane observation for this node."""
    identity = normalize_control_plane_evidence(
        node._runtime_control_plane_evidence or control_plane_identity(node)
    )
    if identity == "rejected":
        return "NoIdentity"
    if identity == "authorization-denied":
        return "AuthorizationDenied"
    if 0 < node._heartbeat_retry_count < get_heartbeat_max_retries():
        return "Retrying"
    if identity == "accepted":
        return "Signing"
    if identity == "inconclusive":
        return "Inconclusive"
    return "Unasked"


def _connection_state(node: NodeRecord) -> str:
    """Derive the connection-liveness axis -- never stored on NodeRecord itself (see core/types.py's _connecting field comment), always computed fresh from the live, in-process handles."""


    if node._disconnecting:
        return "Disconnected"


    activity = activity_of(node)
    if activity is not None:
        state = activity.connection_state()
        if state is not None:
            return state


    if node_socket_is_dead(node):
        return "Disconnected"
    if node._runtime_session is not None:
        return "Connected"
    if node._connecting:
        return "Connecting"
    return "Disconnected"


def credential_group_key(row: "NodeDisplayRow") -> str:
    """The credential a display row belongs to, as the selection model spells it."""
    return row.root_credential_id or f"{row.csp}|{row.cred_type}|{row.identity}"


def build_node_display_rows(
    credentials_by_id: dict[str, CredentialRecord],
    nodes_by_id: dict[str, NodeRecord],
    selected_ids: Optional[set[str]] = None,
) -> list[NodeDisplayRow]:
    """Adapt the live registry into display rows, one per NodeRecord."""
    selected_ids = selected_ids or set()


    account_by_credential = {
        cid: _account_from_credential(rec) for cid, rec in credentials_by_id.items()
    }


    from cloudbasher.core.node_ids import build_id_map

    display_ids, _cred_numbers = build_id_map(credentials_by_id, nodes_by_id)


    _now = time.time()


    _now_mono = time.monotonic()
    rows: list[NodeDisplayRow] = []
    for node in nodes_by_id.values():
        cred_type, identity, target_identity, root = resolve_credential_display(
            node.credential_id, credentials_by_id
        )


        record = credentials_by_id.get(node.credential_id)
        if record is not None and record.role == "target" and root is not None:
            target_identity_full = _il.target_identity_full_arn(record, root)
        elif record is not None:


            target_identity_full = _originating_target_display(record)
        else:
            target_identity_full = "—"


        if _il.is_verbose_identity() and target_identity_full not in ("", "—"):
            target_identity = target_identity_full
        target_acct = _target_account_of(record) if record is not None else ""
        if not target_acct and root is not None:


            target_acct = _account_from_credential(root) or ""
        csp = _provider_display_code(root.provider) if root else "—"
        can_procreate = bool(root and root.provider == "aws" and root.kind == "permanent")
        cred_unbound = _is_unbound_credential(root)


        failure_label = _fl.label_for(node._last_failure_class)


        if node._last_failure_class == _fl.CREDENTIALS_NOT_PROJECTED:
            container_unbound = "failed"
        elif cred_unbound:
            container_unbound = "declared"
        else:
            container_unbound = ""
        ip = node.session.ip_address if node.session else "—"
        host = node.session.hostname if node.session else "—"


        last_heartbeat = getattr(node._runtime_session, "_last_heartbeat_at", None)
        if not isinstance(last_heartbeat, str):
            last_heartbeat = None


        _user_stamp = node.last_activity_at or ""
        _machine_stamp = last_heartbeat or ""


        _won = max(filter(None, (_user_stamp, _machine_stamp)), default="")
        last = _won or "—"
        last_kind = _last_kind(node, won=_won, user_stamp=_user_stamp)


        supervisor_note = getattr(node, "_runtime_supervisor_abandoned", "") or ""
        activity = activity_of(node)
        row_kwargs: dict[str, Any] = dict(
            node_id=node.id,
            credential_id=node.credential_id,
            root_credential_id=root.id if root else "",
            target_acct=redact_field(target_acct, "account") if target_acct else "—",
            seq=node.seq,
            display_id=display_ids.get(node.id, UNADDRESSABLE_DISPLAY_ID),
            environment_id=node.environment_id or "—",
            csp=csp,
            cred_type=cred_type,
            identity=redact_field(identity, "identity"),
            target_identity=redact_field(target_identity, "identity"),


            target_identity_full=redact_field(target_identity_full, "identity"),
            can_procreate=can_procreate,
            cred_unbound=cred_unbound,
            container_unbound=container_unbound,
            failure_label=failure_label,
            last_kind=last_kind,
            idle_remaining=session_idle_remaining(node, _now_mono),
            supervisor_note=supervisor_note,
            container_status=node.container_status,
            connection=_connection_state(node),
            control_plane=_control_plane_state(node),
            queued=node._runtime_queued,
            working=node._runtime_working,
            ip=redact_field(ip, "ip") or "—",
            host=redact_field(host, "hostname") or "—",
            region=node.region or "—",
            selected=node.id in selected_ids,
            exit_code="—" if node._last_exit_code is None else str(node._last_exit_code),
            command_output_preview=_first_line_preview(node.last_command_summary()),
            created=_drop_year(node.created_at) if node.created_at else "—",
            last=_drop_year(last) if last != "—" else "—",
            activity_detail=activity.detail() if activity is not None else "",
            heartbeat_retry_count=node._heartbeat_retry_count,
            heartbeat_max_retries=(
                get_heartbeat_max_retries() if node._heartbeat_retry_count > 0 else 0
            ),
        )


        account = None
        if root is not None:


            account = root._resolved_account or account_by_credential.get(root.id)
        if account:
            row_kwargs["acct"] = redact_field(account, "account")
        rows.append(NodeDisplayRow(**row_kwargs))


    seen: dict[tuple[str, str], int] = {}
    for r in rows:
        if r.environment_id and r.environment_id != "—":
            seen[(r.environment_id, r.region)] = seen.get((r.environment_id, r.region), 0) + 1
    for r in rows:
        if seen.get((r.environment_id, r.region), 0) > 1:
            r.shared_env = True
    return rows


def _account_from_credential(root: Any) -> Optional[str]:
    """The account/tenant display metadata for a credential without API calls."""
    provider = getattr(root, "provider", None)
    extra = getattr(getattr(root, "raw", None), "extra", None) or {}
    if provider == "azure":
        from cloudbasher.core.identity_listing import azure_tenant_id_display

        return azure_tenant_id_display(extra) or None
    if provider == "gcp":
        from cloudbasher.core.identity_listing import gcp_account_display

        value = gcp_account_display(root)
        return value if value != "-" else None
    if provider != "aws":
        return None
    from cloudbasher.csp.aws.account_id import account_for_credential

    return account_for_credential(extra)


def _sso_portal_identity_for(root: Any) -> str:
    """Compact/verbose SSO origin identity for a credential row, else ""."""
    from cloudbasher.core.identity_listing import sso_start_url_display

    return sso_start_url_display(getattr(getattr(root, "raw", None), "extra", None) or {})


def _first_line_preview(text: Optional[str]) -> str:
    """The Cmd Out cell's CONTENT: one redacted line, at its natural length."""
    if not text:
        return "—"
    raw_first_line = text.splitlines()[0] if text else ""


    has_more = raw_first_line != text
    first_line = redact_text(raw_first_line)
    return first_line + "…" if has_more else first_line


_IDENTITY_TRUNCATE_LIMIT = 48

_ARN_ACCOUNT_PREFIX_RE = re.compile(r"^arn:aws:(?:iam|sts)::\d{12}:")


def _strip_arn_account_prefix(text: str) -> str:
    """Drop a leading arn:aws:{iam,sts}::<ACCOUNT>: prefix -- the Account column already shows the account number, so repeating it in an already-narrow Identity/Target Identity column just wastes space. A no-op on non-ARN text (e.g. "(resolving…)", a group's "(N targets)" summary), so callers don't need to guard the input's shape."""
    return _ARN_ACCOUNT_PREFIX_RE.sub("", text)


def _truncate_middle(text: str, limit: int = _IDENTITY_TRUNCATE_LIMIT) -> str:
    """Middle-ellipsis truncation for ARNs/long identifiers."""
    text = _strip_arn_account_prefix(text)
    if len(text) <= limit or limit <= 1:
        return text
    keep = limit - 1
    head = keep - keep // 2
    tail = keep // 2
    return f"{text[:head]}…{text[len(text) - tail:]}"


_ARN_HEAD_RE = re.compile(r"^(arn:[^:]*:[^:]*:[^:]*:[^:]*:)(.+)$")


def _elide_arn(text: str, limit: int = _IDENTITY_TRUNCATE_LIMIT) -> str:
    """Middle-elide an ARN while keeping BOTH ends readable."""
    if len(text) <= limit:
        return text
    m = _ARN_HEAD_RE.match(text)
    if not m:
        return _truncate_middle(text, limit)
    resource = m.group(2)
    short = f"arn:…:{resource}"
    if len(short) <= limit:
        return short


    keep = max(limit - len("arn:…:") - 1, 2)
    head = keep - keep // 2
    tail = keep // 2
    return f"arn:…:{resource[:head]}…{resource[len(resource) - tail:]}"


def _summarize(values: list[str], noun: str) -> str:
    """A group summary row shows one value if every member agrees, else a count."""
    uniq = list(dict.fromkeys(values))
    if len(uniq) == 1:
        return uniq[0]
    return f"({len(uniq)} {noun})"


def _target_account_of(record: Any) -> str:
    """The account a derivation lands IN, which is not always its own."""
    from cloudbasher.core.identity_listing import (
        _target_account,
        azure_tenant_id_display,
        gcp_account_display,
    )

    extra = getattr(getattr(record, "raw", None), "extra", None) or {}
    if getattr(record, "provider", None) == "azure":
        return azure_tenant_id_display(extra)
    if getattr(record, "provider", None) == "gcp":
        return gcp_account_display(record)
    own = _target_account(extra)
    if own:
        return own

    ref = str(getattr(record, "target_ref", "") or "")
    parts = ref.split(":")
    return parts[4] if len(parts) > 4 and parts[4] else ""


def _declared_target_display(record: Any) -> str:
    """What an ORIGINATING credential row shows in Target Identity."""
    extra = getattr(getattr(record, "raw", None), "extra", None) or {}
    from cloudbasher.csp.aws.act_as import act_as_mode_of

    mode = act_as_mode_of(extra)
    if mode == "role":
        return str(extra.get("role_arn") or "role")
    if mode == "federated":


        from cloudbasher.core.identity_listing import derived_principal_arn

        name = str(extra.get("federation_name") or "")
        arn = derived_principal_arn(
            kind="federation_token",
            ref=name,
            session_name=None,
            account=_account_from_credential(record) or "",
        )
        if arn:
            return arn
        return f"federated/{name}" if name else "federated"


    return _originating_target_display(record) if record is not None else "—"


class CredGroupKey(NamedTuple):
    """One loaded originating credential, as the tree groups and renders it."""

    record_id: str
    display: tuple[str, str, str]
    cred_num: int
    unbound: bool


    node_ceiling: int
    account: str
    target_account: str
    target_identity: str


    acts_as: str = "—"
    regions: str = "—"


    declared_region: str = ""
    declared_index: str = ""
    declared_name: str = ""
    description: str = "—"


    cred_id: str = "—"
    cred_id_redaction_type: str = "identity"


    invalid: bool = False


    verified: bool = False


@dataclass
class UnmanagedViewRow:
    """One row of the UNMANAGED view -- `#504`."""

    key: str
    index: int
    provenance: str
    principal: str
    region: str
    environment: str
    state: str
    note: str


    deleted: bool = False


DEFAULT_VIEW_MODE = "tree"


VIEW_MODES = ("tree", "flat", "unmanaged")


def _originating_count(credentials_by_id: dict) -> int:
    """How many credentials the Credential View actually lists."""
    from cloudbasher.core.types import numbered_originating_records

    return len(list(numbered_originating_records(credentials_by_id or {})))


def view_pane_title(
    view_mode: str,
    node_count: int,
    cred_count: int = 0,
    *,
    redacted: bool = False,
    unmanaged_count: Optional[int] = None,
    unmanaged_age: str = "",
) -> Text:
    """The Nodes pane title: BOTH views, the active one emphasised."""


    active_key, active_label = "bold underline", "bold"
    idle_key = "underline dim not bold default on default"
    idle_label = "dim not bold default on default"
    title = Text()


    tabs = [
        ("1", "Credentials", str(cred_count), "tree"),
        ("2", "Nodes", str(node_count), "flat"),
        ("3", "Unmanaged", "-" if unmanaged_count is None else str(unmanaged_count), "unmanaged"),
    ]
    for key, label, count, mode in tabs:
        if title.plain:
            title.append(" │ ", style=idle_label)
        active = view_mode == mode
        title.append(key, style=active_key if active else idle_key)
        title.append(f" {label} ({count})", style=active_label if active else idle_label)


    if unmanaged_age and view_mode == "unmanaged":
        title.append(f" [{unmanaged_age}]", style=idle_label)
    if redacted:
        title.append(" [redacted]")


    from cloudbasher.core.identity_listing import is_verbose_identity

    if is_verbose_identity():
        title.append(" [verbose]")
    return title


def credential_group_keys(
    credentials_by_id: dict[str, CredentialRecord],
    nodes_by_id: Optional[dict[str, NodeRecord]] = None,
) -> list[CredGroupKey]:
    """Every LOADED originating credential: record id, display triple, `<cred#>`, unbound."""
    from cloudbasher.core.identity_listing import credential_facts_by_id
    from cloudbasher.core.types import numbered_originating_records


    facts = credential_facts_by_id(credentials_by_id, nodes_by_id)
    out: list[CredGroupKey] = []
    for n, rec in numbered_originating_records(credentials_by_id):
        cred_type, identity, _target, root = resolve_credential_display(
            rec.id,
            credentials_by_id,


            key_shown_elsewhere=_cred_id_column_present(),
        )
        csp = _provider_display_code(root.provider) if root else "—"
        out.append(
            CredGroupKey(
                record_id=rec.id,
                display=(csp, cred_type, identity),
                cred_num=n,
                unbound=_is_unbound_credential(root),
                node_ceiling=_node_ceiling(root),


                account=(
                    _account_from_credential(rec)
                    or _sso_portal_identity_for(rec)
                    or ""
                ),
                target_account=_target_account_of(rec),
                target_identity=_declared_target_display(rec),
                invalid=_il.credential_is_invalid(root) if root else False,
                verified=_il.credential_is_verified(root) if root else False,
                acts_as=_fact(facts, rec.id, "acts_as"),
                regions=_fact(facts, rec.id, "regions"),


                declared_region=_fact(facts, rec.id, "declared_region"),
                declared_index=_fact(facts, rec.id, "declared_index"),
                declared_name=_fact(facts, rec.id, "declared_name"),
                description=_fact(facts, rec.id, "description"),
                cred_id=_fact(facts, rec.id, "cred_id"),
                cred_id_redaction_type=_fact(facts, rec.id, "cred_id_redaction_type"),
            )
        )
    return out


def _fact(facts: dict, record_id: str, name: str) -> str:
    """One merged cell, or the table's own em-dash when the record has none."""
    entry = facts.get(record_id)
    return (getattr(entry, name, "") or "—") if entry is not None else "—"


def build_display_rows(
    rows: list[NodeDisplayRow],
    expanded_groups: set[str],
    *,
    flat: bool = False,
    credential_keys: Optional[list["CredGroupKey"]] = None,
) -> list[dict[str, Any]]:
    """Build the table's display-row list in one of two modes."""
    if flat:
        return [{"kind": "single", "node": m, "row_key": m.node_id, "group_id": None} for m in rows]

    groups: dict[str, list[NodeDisplayRow]] = {}


    group_display: dict[str, tuple[str, str, str]] = {}
    cred_numbers: dict[str, int] = {}


    cred_unbound_by_key: dict[str, bool] = {}


    cred_facts: dict[str, "CredGroupKey"] = {}
    for entry in credential_keys or []:
        groups.setdefault(entry.record_id, [])
        group_display[entry.record_id] = entry.display
        cred_numbers[entry.record_id] = entry.cred_num
        cred_unbound_by_key[entry.record_id] = entry.unbound
        cred_facts[entry.record_id] = entry
    for row in rows:
        key = credential_group_key(row)
        groups.setdefault(key, []).append(row)
        group_display.setdefault(key, (row.csp, row.cred_type, row.identity))

    display: list[dict[str, Any]] = []
    for key, members in groups.items():
        csp, cred_type, identity = group_display[key]


        if csp != "—":
            group_id = group_row_key(key)


            facts = cred_facts.get(key)
            display.append(
                {
                    "kind": "parent",
                    "members": members,
                    "row_key": group_id,


                    "record_id": key,
                    "csp": csp,
                    "cred_type": cred_type,


                    "identity": redact_field(identity, "identity"),
                    "cred_num": cred_numbers.get(key),
                    "node_ceiling": getattr(facts, "node_ceiling", 1),


                    "can_mint": _mints_principals(facts),
                    "cred_invalid": bool(getattr(facts, "invalid", False)),
                    "cred_verified": bool(getattr(facts, "verified", False)),
                    "account": redact_field(getattr(facts, "account", ""), "account"),
                    "target_account": redact_field(getattr(facts, "target_account", ""), "account"),
                    "target_identity": redact_field(
                        getattr(facts, "target_identity", ""), "identity"
                    ),


                    "acts_as": redact_field(getattr(facts, "acts_as", ""), "identity"),
                    "regions": getattr(facts, "regions", ""),


                    "declared_region": getattr(facts, "declared_region", ""),
                    "declared_index": getattr(facts, "declared_index", ""),


                    "declared_name": redact_field(
                        getattr(facts, "declared_name", ""), "principal_name"
                    ),
                    "description": getattr(facts, "description", ""),


                    "cred_id": redact_field(
                        getattr(facts, "cred_id", ""),
                        getattr(facts, "cred_id_redaction_type", "identity"),
                    ),


                    "cred_unbound": (
                        cred_unbound_by_key.get(key, False) or any(m.cred_unbound for m in members)
                    ),
                }
            )
            if group_id in expanded_groups and members:


                display.append({"kind": "header", "row_key": f"hdr:{key}", "group_id": group_id})
            if group_id in expanded_groups:
                for m in members:
                    display.append(
                        {"kind": "child", "node": m, "row_key": m.node_id, "group_id": group_id}
                    )
        else:
            for m in members:
                display.append(
                    {"kind": "single", "node": m, "row_key": m.node_id, "group_id": None}
                )
    return display


_SEL_CHECKED = Text("☑", style="bold cyan")
_SEL_UNCHECKED = Text("☐", style="dim")


_SEL_PARTIAL = Text("⊟", style="bold cyan")


_EXPAND_COLLAPSED = "▸"
_EXPAND_EXPANDED = "▾"
_EXPAND_NONE = "·"
_EXPAND_GLYPHS = (_EXPAND_COLLAPSED, _EXPAND_EXPANDED, _EXPAND_NONE)


_EXPAND_COLLAPSED_GLYPH = Text(_EXPAND_COLLAPSED, style="bold cyan")
_EXPAND_EXPANDED_GLYPH = Text(_EXPAND_EXPANDED, style="bold cyan")
_EXPAND_NONE_GLYPH = Text(_EXPAND_NONE, style="dim")


_BLANK_GLYPH = Text("")


def _tri_state(selected: int, total: int) -> Text:
    """The three-state selection glyph, in ONE place. `#555`."""
    if not selected or not total:
        return _SEL_UNCHECKED
    return _SEL_CHECKED if selected >= total else _SEL_PARTIAL


_STATUS_SLOT_WIDTH = 2


_TRANSITION = "⧗"


_IN_PROGRESS_HUE = "#00D7FF"
_IN_PROGRESS = f"bold {_IN_PROGRESS_HUE}"


_QUEUED = "·"
_QUEUED_GLYPH = Text(_QUEUED, style="dim")


_IN_PROGRESS_GLYPH = Text(_TRANSITION, style=_IN_PROGRESS)


_ACTIVITY_GLYPH_DEFAULT = Text("")

_CONTAINER_SETTLED = {


    "Running": Text("●", style="bold green"),


    "Suspended": Text("▲", style="bold #FFEE00"),
    "Failed": Text("✗", style="bold red"),
    "Unknown": Text("?", style="dim"),


    "CredentialInvalid": Text("⊘", style="bold red"),
}


_CONTAINER_GLYPH_DEFAULT = Text("–", style="dim")

_CONN_SETTLED = {
    "Connected": Text("✓", style="bold green"),


    "Disconnected": Text("–", style="dim"),
}
_CONN_GLYPH_DEFAULT = Text("–", style="dim")


_CP_SETTLED = {
    "Signing": Text("✓", style="bold green"),
    "Retrying": Text("↻", style="bold #FFEE00"),
    "NoIdentity": Text("✗", style="bold red"),
    "AuthorizationDenied": Text("!", style="bold #FFAA00"),
    "Inconclusive": Text("?", style="bold #AAAAAA"),
}


_CP_GLYPH_DEFAULT = Text("–", style="dim")


def _toward_background(hue: str, fraction: float) -> str:
    """One hue, taken to a background lightness."""
    r, g, b = Color.parse(hue).get_truecolor()
    return f"#{int(r * fraction):02X}{int(g * fraction):02X}{int(b * fraction):02X}"


_BACKGROUND_FRACTION = 0.22


_WIP_TINT = _toward_background(_IN_PROGRESS_HUE, _BACKGROUND_FRACTION)


def _changing(settled: Text) -> Text:
    """A settled glyph, still drawn, on the mid-change tint."""
    return Text(settled.plain, style=f"{settled.style} on {_WIP_TINT}")


def _with_changing(
    settled: "dict[str, Text]",
    default: Text,
    leaving: "Mapping[str, str | None]",
    *,
    tint: bool,
) -> "dict[str, Text]":
    """A finished glyph map: the settled entries, plus one entry per transitional status built from the state that status has not left."""
    return {
        **settled,
        **{
            status: (
                _changing(settled[prior] if prior else default)
                if tint
                else (settled[prior] if prior else default)
            )
            for status, prior in leaving.items()
        },
    }


_CONTAINER_LEAVING: "dict[str, str | None]" = {
    name: t.leaving for name, t in CONTAINER_TRANSITIONS.items()
}


_CONN_LEAVING: "dict[str, str | None]" = {
    "Connecting": "Disconnected",
    "Recovering": "Connected",
}


_CONTAINER_GLYPH_WORKED = _with_changing(
    _CONTAINER_SETTLED, _CONTAINER_GLYPH_DEFAULT, _CONTAINER_LEAVING, tint=True
)
_CONN_GLYPH_WORKED = _with_changing(_CONN_SETTLED, _CONN_GLYPH_DEFAULT, _CONN_LEAVING, tint=True)
_CONTAINER_GLYPH = _with_changing(
    _CONTAINER_SETTLED, _CONTAINER_GLYPH_DEFAULT, _CONTAINER_LEAVING, tint=False
)
_CONN_GLYPH = _with_changing(_CONN_SETTLED, _CONN_GLYPH_DEFAULT, _CONN_LEAVING, tint=False)


_CP_GLYPH = dict(_CP_SETTLED)


def status_legend_lines() -> list[str]:
    """The Status and Last columns explained, as plain lines for `.help` and `?`."""
    container = _CONTAINER_GLYPH
    conn = _CONN_GLYPH


    worked = _CONTAINER_GLYPH_WORKED
    last = _LAST_GLYPH
    cp = _CP_GLYPH

    def g(mapping: dict, key: str) -> str:
        """The glyph with its own colour, as ANSI."""
        return rich_to_ansi(mapping[key])

    def _t(style: str) -> str:
        """The transition square in a destination's colour."""
        return rich_to_ansi(Text(_TRANSITION, style=style))

    return [
        "Status column — three independent slots: [container] [connection] [control plane]",
        "",
        f"  Container    {g(container, 'Running')}   Running        up and usable",
        f"               {g(container, 'Suspended')}   Suspended      .start resumes it",
        f"               {g(container, 'Failed')}   Failed         ERROR/DELETED, or bootstrap failed",
        f"               {g(container, 'CredentialInvalid')}   CredentialInvalid  heartbeat found the credential dead",
        f"               {g(container, 'Unknown')}   Unknown        the CSP reported a status we don't map",
        f"               {rich_to_ansi(_CONTAINER_GLYPH_DEFAULT)}   (none)         no status on record",
        "",
        f"  Connection   {g(conn, 'Connected')}   Connected      a live session is held",
        f"               {g(conn, 'Recovering')}   Recovering     shell stopped executing; sockets being rebuilt",
        f"               {g(conn, 'Disconnected')}   Disconnected   no session in this process",
        "",


        f"  Ctl plane    {g(cp, 'Signing')}   Signing/Accepted  latest control-plane request authenticated",
        f"               {g(cp, 'Retrying')}   Retrying       heartbeat mid-retry; may settle",
        f"               {g(cp, 'NoIdentity')}   NoIdentity/Rejected  latest request explicitly rejected authentication",
        f"               {g(cp, 'AuthorizationDenied')}   AuthorizationDenied/Denied  authenticated principal lacks permission",
        f"               {g(cp, 'Inconclusive')}   Inconclusive  request failed without an auth verdict",
        f"               {rich_to_ansi(_CP_GLYPH_DEFAULT)}   (none)         not asked yet",
        "",


        f"  Changing     {g(worked, 'Suspending')}{g(worked, 'Starting')}  either of the two "
        f"slots above on a TINTED background: THAT axis is the one moving,",
        f"                   and the glyph under the tint is the state it has NOT left yet. "
        f"{g(worked, 'Suspending')} is Running",
        f"                   and going down; {g(worked, 'Starting')} is Suspended and coming "
        f"up. The Status column's word names where",
        "                   it is heading. Only ever while a worker is on the row, so on a "
        "NODE row the tint",
        "                   and the hourglass always appear together (`#760`). Not shown on "
        "the cursor row",
        "",


        "Activity column — the narrow column left of the checkbox.",
        "  What a COMMAND is doing, not what the node is. `.bulk` and `.delete` change no",
        "  status at all, so this is their whole progress signal.",
        "",
        f"  On a node    {_t(_IN_PROGRESS)}   a fan-out worker is on this node RIGHT NOW",


        f"               {rich_to_ansi(_QUEUED_GLYPH)}   Queued -- waiting for a worker; the "
        f"command has this node, nothing has started on it",
        "               (blank) no command is touching this node",
        "",


        f"  On a cred    {rich_to_ansi(_EXPAND_COLLAPSED_GLYPH)}"
        f"{rich_to_ansi(_EXPAND_EXPANDED_GLYPH)}  the expand triangle instead — this row has "
        f"its own use for the column",
        f"               {rich_to_ansi(_changing(_EXPAND_COLLAPSED_GLYPH))}   the SAME triangle, "
        f"tinted: work is outstanding somewhere under it",
        "               (queued or running — a summary row does not separate them; Enter does)",
        "",


        "Last column — what moved the timestamp. NO glyph means a real command did.",
        "",
        f"  Last         {g(last, 'machine')}   keepalive    layers 1-3; session clock still runs",
        f"               {g(last, 'held')}   held         layer 4 moved it; session really is held",
        f"               {g(last, 'off')}   policy off   keepalive off; column has stopped",
    ]


_ARMOR_SLOT_WIDTH = 2
_ARMOR_LOCK_ON = Text("\U0001f512", style="bold red")
_ARMOR_SHIELD_ON = Text("\U0001f6e1", style="bold cyan")
_ARMOR_OFF = Text("·", style="dim")
_ARMOR_NA = Text("–", style="dim")


_LAST_GLYPH = {


    "machine": Text("~", style="dim"),


    "held": Text("✓", style="dim cyan"),


    "off": _ARMOR_OFF,
}


def _last_cell(stamp: Any, kind: str) -> Any:
    """The `Last` timestamp with its provenance glyph appended, or unchanged."""
    glyph = _LAST_GLYPH.get(kind)
    if glyph is None:
        return stamp
    cell = stamp.copy() if isinstance(stamp, Text) else Text(str(stamp))
    cell.append(" ")
    cell.append_text(glyph)
    return cell


def _last_kind(node: Any, *, won: str, user_stamp: str) -> str:
    """Which stamp won `Last`, as one of `_LAST_GLYPH`'s keys or `""`."""
    if policy_of(node) == "off":
        return "off"
    if not won:
        return ""
    if won == user_stamp:
        return "user"


    return "held" if layer_is_live(node, 4) else "machine"


_BEACON_GLYPH = {
    "yes": Text("◉", style="bold green"),
    "no": Text("○", style="dim"),
}
_BEACON_GLYPH_DEFAULT = Text("–", style="dim")


_CSP_STYLE = {
    "AWS": "bold #FF9900",
    "AZR": "bold #00BFFF",
}
_GCP_LETTER_STYLES = ("bold #34A853", "bold #EA4335", "bold #FBBC04")


_CRED_META = _il.CRED_META
_CRED_USER_GLYPH = _il.CRED_USER_GLYPH
_CRED_API_GLYPH = _il.CRED_API_GLYPH
_CRED_PERM_GLYPH = _il.CRED_PERM_GLYPH
_CRED_TEMP_GLYPH = _il.CRED_TEMP_GLYPH
_CRED_LIFETIME_TEXT = _il.CRED_LIFETIME_TEXT
_CRED_FLAGS = _il.CRED_FLAGS


def _dim_pending_cell(value: str, status: str) -> Text | str:
    """4z item 2: the Pending status icon alone (dim yellow "○") is too subtle per user feedback -- dim the row's plain-text columns too so a still-bootstrapping node visibly recedes next to ready ones, instead of relying on a single small glyph to carry that signal. Only plain-string columns go through this (identity/ip/host/etc.); glyph columns keep their own deliberate color coding (CSP letters, cred-type icon, beacon) since those already mean something independent of readiness."""
    if status != "Pending":
        return value
    return Text(str(value), style="dim white")


def _compose_glyph_cell(*glyphs: Text, width: int) -> Text:
    """Safely combine one or more independently-styled glyph slots into a single cell, padding each to `width`."""
    cell = Text()
    for glyph in glyphs:
        cell.append(glyph.plain, style=glyph.style)
        pad = width - cell_len(glyph.plain)
        if pad > 0:
            cell.append(" " * pad)
    return cell


def _armor_cell(row: NodeDisplayRow) -> Text:
    if row.container_status != "Running":
        return _compose_glyph_cell(_ARMOR_NA, width=_ARMOR_SLOT_WIDTH * 2)
    lock = _ARMOR_LOCK_ON if row.armor_locked else _ARMOR_OFF
    shield = _ARMOR_SHIELD_ON if row.armor_shielded else _ARMOR_OFF
    return _compose_glyph_cell(lock, shield, width=_ARMOR_SLOT_WIDTH)


def _status_cell(row: NodeDisplayRow) -> Text:
    """THREE independent, fixed-position glyph slots -- container_status, connection and control_plane (`#790`) -- concatenated into one cell. Unlike _armor_cell, there's no "only meaningful when X" gating here: the axes are independent by construction and always render their own slot."""
    container, conn, cp, _activity, _in_flight = _status_render(row)
    return _compose_glyph_cell(container, conn, cp, width=_STATUS_SLOT_WIDTH)


def _activity_cell(row: NodeDisplayRow, *, base: Text) -> Text:
    """A NODE row's cell in the activity column. `#761`."""
    _container, _conn, _cp, activity, _in_flight = _status_render(row)
    return activity if activity.plain else base


def _group_status_cell(members: "list[NodeDisplayRow]") -> Text:
    """A CREDENTIAL row's Status cell: EMPTY, deliberately. `#761`."""
    return _compose_glyph_cell(_BLANK_GLYPH, _BLANK_GLYPH, _BLANK_GLYPH, width=_STATUS_SLOT_WIDTH)


def _group_activity_cell(members: "list[NodeDisplayRow]", *, expanded: bool) -> Text:
    """A CREDENTIAL row's cell in the activity column: the expand triangle, tinted while work is outstanding underneath it. `#761`."""
    if not members:
        return _EXPAND_NONE_GLYPH
    glyph = _EXPAND_EXPANDED_GLYPH if expanded else _EXPAND_COLLAPSED_GLYPH
    return _changing(glyph) if any(m.working or m.queued for m in members) else glyph


def _activity_state(*, queued: bool, working: bool) -> str:
    """The ACTIVITY slot as one word: `"queued"`, `"working"` or `"idle"`."""
    if queued:
        return "queued"
    if working:
        return "working"
    return "idle"


def _status_render(row: NodeDisplayRow) -> tuple[Text, Text, Text, Text, bool]:
    """All three Status glyphs AND whether this row counts as in flight."""


    activity = _activity_state(queued=row.queued, working=row.working)
    worked = activity == "working"
    container = (_CONTAINER_GLYPH_WORKED if worked else _CONTAINER_GLYPH).get(
        row.container_status, _CONTAINER_GLYPH_DEFAULT
    )
    conn = (_CONN_GLYPH_WORKED if worked else _CONN_GLYPH).get(row.connection, _CONN_GLYPH_DEFAULT)
    cp = _CP_GLYPH.get(row.control_plane, _CP_GLYPH_DEFAULT)
    if activity == "queued":
        return container, conn, cp, _QUEUED_GLYPH, False
    if worked:
        return container, conn, cp, _IN_PROGRESS_GLYPH, True
    return container, conn, cp, _ACTIVITY_GLYPH_DEFAULT, False


def _is_in_flight(row: NodeDisplayRow) -> bool:
    """Does this row DRAW as mid-change? The viewport-follow's whole question."""
    _container, _conn, _cp, _activity, in_flight = _status_render(row)
    return in_flight


_CSP_GREEN_STYLE = "bold #34A853"


def _csp_cell(csp: str, suffix: str = "", *, gcp_monocolor: bool = False) -> Text:
    """See module docstring, rendering-bug #2: always build via bare ``Text()`` + ``.append(..., style=...)``, never ``Text(string, style=...)``."""
    text = Text()
    provider = csp.upper()
    if provider == "GCP":
        letter_styles = (
            (_CSP_GREEN_STYLE,) * 3 if gcp_monocolor else _GCP_LETTER_STYLES
        )
        letters = list(zip(csp, letter_styles))
        for i, (ch, style) in enumerate(letters):
            piece = ch + (suffix if i == len(letters) - 1 else "")
            text.append(piece, style=style)
    else:
        text.append(csp + suffix, style=_CSP_STYLE.get(provider, ""))
    return text


def _configured_csp_cell(csp: str, suffix: str = " ") -> Text:
    """Render any TUI CSP label through the shared case/color preferences."""
    from cloudbasher.core.config import active_config

    config = active_config()
    case = config.get_string("ui.csp_case", "uppercase").strip().lower()
    color = config.get_string("ui.csp_color", "multicolor").strip().lower()
    provider = str(csp or "CSP").strip().upper()
    label = provider.lower() if case == "lowercase" else provider


    gcp_monocolor = provider == "GCP" and color in {"monocolor", "green"}
    return _csp_cell(label, suffix=suffix, gcp_monocolor=gcp_monocolor)


def _credential_csp_cell(csp: str) -> Text:
    """Compatibility name for the credential inventory's configured label."""
    return _configured_csp_cell(csp, suffix="")


def _cred_rich(row: dict[str, Any]) -> Text:
    """The Cred cell WITH its glyph slots -- user/api, perm/temp, unbound/invalid."""
    members = row.get("members") or []
    return _cred_cell(
        str(row.get("cred_type") or "—"),
        can_procreate=any(m.can_procreate for m in members),
        unbound=bool(row.get("cred_unbound")),
        invalid=bool(row.get("cred_invalid")),
        verified=bool(row.get("cred_verified")),
    )


_STATUS_CELL_WIDTH = len(
    _compose_glyph_cell(
        _CONTAINER_GLYPH_DEFAULT,
        _CONN_GLYPH_DEFAULT,
        _CP_GLYPH_DEFAULT,
        width=_STATUS_SLOT_WIDTH,
    ).plain
)


def _activity_cell_width() -> int:
    """Cells the activity column's cells occupy, MEASURED and over BOTH vocabularies that share the column since `#761` -- the expand glyphs a credential row draws and the activity glyphs a node row draws. They agree at one cell today; a two-cell glyph in either set then moves the pane's width budget with it instead of overflowing the row."""
    return max(
        cell_len(g) for g in (*_EXPAND_GLYPHS, _IN_PROGRESS_GLYPH.plain, _QUEUED_GLYPH.plain)
    )


def _cred_cell(
    code: str,
    can_procreate: bool = False,
    unbound: bool = False,
    invalid: bool = False,
    verified: bool = False,
) -> Text:
    """The Credential column: glyph and shorthand groups, packed."""
    groups = _il.credential_groups(code, invalid=invalid, unbound=unbound, verified=verified)

    cell = Text()
    for i, (glyph, style, text) in enumerate(groups):
        if i:


            cell.append(" ")
        cell.append(glyph, style=style)


        cell.append(text, style=style if (glyph, style, text) in _CRED_FLAGS.values() else "")


    return cell


_STICKY_FAILURE_REPORTED = False


def _report_sticky_failure() -> None:
    """Say once that the sticky block header has stopped working."""
    global _STICKY_FAILURE_REPORTED
    if _STICKY_FAILURE_REPORTED:
        return
    _STICKY_FAILURE_REPORTED = True
    try:
        import traceback

        from cloudbasher.core.utils.output import log

        log(
            "#741: the sticky node-table header is off -- falling back to the "
            f"per-block header. {traceback.format_exc()}"
        )
    except Exception:
        pass


def sticky_header_index(
    *,
    at_first_scrollable_line: bool,
    scroll_y: int,
    offset_in_row: int,
    row_index: "Optional[int]",
    header_index: "Optional[int]",
    cursor_row: int,
) -> "Optional[int]":
    """`#741`. Which block header belongs at the top of the viewport, or None to draw whatever row is really there."""
    if not at_first_scrollable_line:
        return None
    if not scroll_y:


        return None
    if offset_in_row:


        return None
    if row_index is None or header_index is None:


        return None
    if header_index >= row_index:


        return None
    if cursor_row == row_index:


        return None
    return header_index


class CredNodeTable(DataTable):
    """The multi-node/multi-credential list view. Columns beyond the leftmost three are abbreviated/color/icon-coded to compact the row."""


    _selected_credential_ids: "set[str] | frozenset[str]" = frozenset()


    _sticky_header_row: "Mapping[str, str]" = MappingProxyType({})
    _auto_selected_credential_ids: "set[str] | frozenset[str]" = frozenset()

    class CursorCredentialChanged(Message):
        """Posted whenever the cursor lands on a row, carrying the credential that row belongs to. The App mirrors it into `InteractiveState.cursor_credential_id` so a bare `.provision` -- which only ever sees `state`, never this widget -- can mean "the one I am pointing at", the same thing `p` means."""

        def __init__(self, credential_id: Optional[str]) -> None:
            super().__init__()
            self.credential_id = credential_id

    class SelectionRefused(Message):
        """Posted when a selection gesture could not do anything."""

        def __init__(self, reason: str) -> None:
            super().__init__()
            self.reason = reason

    class SelectionChanged(Message):
        """Posted whenever _selected_ids changes. The App mirrors this into InteractiveState.selected_node_ids so the .bulk dot-command -- which only ever sees `state`, never this widget -- knows which nodes to target."""

        def __init__(
            self,
            selected_ids: set[str],
            credential_ids: Optional[set[str]] = None,
            finding_ids: Optional[set[str]] = None,
        ) -> None:
            super().__init__()
            self.selected_ids = selected_ids


            self.credential_ids = credential_ids or set()


            self.finding_ids = finding_ids or set()

    class VisibleOrderChanged(Message):
        """Posted on every reload() (Phase A). The App mirrors this into InteractiveState.visible_row_node_ids so CLI range selectors ("1-3") -- which only ever see `state`, never this widget -- can resolve against the table's contiguous "Row" column. Index i holds the node id(s) shown at row-number i+1: a single id for a normal row, every member's id for a collapsed group-parent row."""

        def __init__(self, row_node_ids: list[frozenset]) -> None:
            super().__init__()
            self.row_node_ids = row_node_ids


    BINDINGS = [
        Binding(kb.key, kb.action, kb.label, show=False) for kb in node_table_bindings()
    ] + [
        Binding("G", "scroll_bottom", "Bottom", show=False),
        Binding("ctrl+f", "page_down", "Page down", show=False),
        Binding("ctrl+b", "page_up", "Page up", show=False),
    ]

    EXPAND_COLUMN_KEY = "expand"
    SEL_COLUMN_KEY = "sel"


    ID_COLUMN_KEY = "rowid"


    STATUS_COLUMN_KEY = "status"


    EXPAND_HEADER = Text(" ")
    ID_HEADER = Text("ID", style="bold")
    STATUS_HEADER = Text("◐", style="dim")


    CRED_COLUMNS = (
        "Nodes",
        "CSP",
        "ID",
        "Act|Org|Ten",
        "Cred",
        "Identity",
        "Tgt Act|Org|Ten",
        "Acts As",
        "Regions",
        "Description",
        "",
    )


    TREE_NODE_COLUMNS = (
        "",
        "",
        "ID",
        "Env ID",
        "IP",
        "Host",
        "Region",
        "Last",
        "Created",
        "$?",
        "Cmd Out",
    )


    FLAT_CHROME_COLUMNS = 3
    FLAT_FROZEN_COLUMNS = FLAT_CHROME_COLUMNS + 1


    FLAT_COLUMNS = (
        "ID",
        "CSP",
        "Tgt Act|Org|Ten",
        "Target Identity",
        "Env ID",
        "IP",
        "Host",
        "Region",
        "Last",
        "Created",
        "$?",
        "Cmd Out",
    )


    RETIRED_COLUMNS = ("Arm", "Agt", "Conn", "Up (dd:hh:mm %)")


    UNMANAGED_COLUMNS = (
        "#",
        "EDV",


        "Target Identity",
        "Region",
        "Environment",
        "State",
        "Note",
    )

    def _visible_columns(self) -> tuple[str, ...]:
        """The header the table renders, which depends on which view is on."""
        if self._view_mode == "unmanaged":
            return self.UNMANAGED_COLUMNS
        return self.FLAT_COLUMNS if self._view_mode == "flat" else self.CRED_COLUMNS

    def _cells_for(self, layout: tuple[str, ...], cells: tuple[Any, ...]) -> list[Any]:
        """Check a row builder's cells against the layout it claims to fill."""
        return [cell for _name, cell in zip(layout, cells, strict=True)]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


        self.cursor_foreground_priority = "renderable"


        self.cursor_background_priority = "css"
        self._expanded_groups: set[str] = set()


        self._followed_scroll_y: Optional[int] = None
        self._follow_suspended_at: float = 0.0


        self._follow_handoff_key: Optional[str] = None
        self._selected_ids: set[str] = set()


        self._selected_credential_ids: set[str] = set()
        self._auto_selected_credential_ids: set[str] = set()


        self._auto_selected_ids: set[str] = set()


        self._selected_finding_ids: set[str] = set()

        self._unmanaged_rows: "list[UnmanagedViewRow]" = []


        self._unmanaged_scanned_at: Optional[float] = None
        self._unmanaged_scope: str = ""


        self._view_mode: str = DEFAULT_VIEW_MODE
        self._row_number_by_key: dict[str, int] = {}


        self._display_id_by_key: dict[str, str] = {}


        self._last_credentials_by_id: dict[str, CredentialRecord] = {}
        self._last_nodes_by_id: dict[str, NodeRecord] = {}


        self._range_anchor_row_key: Optional[str] = None


        self._pending_g = False

    def on_key(self, event) -> None:
        if event.key == "g":
            if self._pending_g:
                self._pending_g = False
                self.action_scroll_top()
                event.stop()
                event.prevent_default()
            else:
                self._pending_g = True
                event.stop()
                event.prevent_default()
        elif self._pending_g:
            self._pending_g = False

    def action_page_left(self) -> None:
        self.scroll_page_left()

    def action_page_right(self) -> None:
        self.scroll_page_right()

    def reload(
        self,
        credentials_by_id: dict[str, CredentialRecord],
        nodes_by_id: dict[str, NodeRecord],
    ) -> None:


        current_key = self._current_row_key()


        if self._view_mode == "unmanaged":


            self._reload_unmanaged(current_key, credentials_by_id, nodes_by_id)
            return


        fallback_key = self._group_key_for_row(current_key)
        current_index = self.cursor_row


        added_ids = set(nodes_by_id) - set(self._last_nodes_by_id)


        newest_key = next((nid for nid in reversed(list(nodes_by_id)) if nid in added_ids), None)
        follow_tail = self.row_count == 0 or bool(added_ids)


        old_scroll_y = self.scroll_y
        old_cursor_row = self.cursor_row
        viewport_height = max(
            1,
            int(self.scrollable_content_region.height)
            - (self.header_height if self.show_header else 0),
        )
        was_visible = (
            not follow_tail
            and old_cursor_row is not None
            and old_scroll_y <= old_cursor_row < old_scroll_y + viewport_height
        )

        self._last_credentials_by_id = dict(credentials_by_id)


        self._last_nodes_by_id = dict(nodes_by_id)


        display_rows = build_node_display_rows(credentials_by_id, nodes_by_id, self._selected_ids)
        self._drop_vanished_selection(nodes_by_id, display_rows)


        self.set_reactive(DataTable.cursor_coordinate, Coordinate(0, 0))
        self.clear(columns=True)


        if self._expanded_groups:
            with_members = {
                group_row_key(dr.root_credential_id) for dr in display_rows if dr.root_credential_id
            }
            self._expanded_groups &= with_members

        if added_ids and self._view_mode != "flat":


            for dr in display_rows:
                if dr.node_id in added_ids and dr.root_credential_id:
                    self._expanded_groups.add(group_row_key(dr.root_credential_id))
        rows = build_display_rows(
            display_rows,
            self._expanded_groups,
            flat=(self._view_mode == "flat"),
            credential_keys=credential_group_keys(credentials_by_id, nodes_by_id),
        )
        self._last_display_rows_by_id = {r.node_id: r for r in display_rows}


        if self._subtable_mode():
            self.add_column(self.ID_HEADER, key=self.ID_COLUMN_KEY)
        self.add_column(self.EXPAND_HEADER, key=self.EXPAND_COLUMN_KEY)
        self.add_column(self._sel_header(display_rows), key=self.SEL_COLUMN_KEY)
        self.add_column(self.STATUS_HEADER, key=self.STATUS_COLUMN_KEY)
        if self._subtable_mode():


            self.add_column(Text(" "), key=self.CONTENT_COLUMN_KEY)


            self.fixed_columns = len(self.columns) - 1
        else:
            self.add_columns(*self._visible_columns())


            self.fixed_columns = self.FLAT_FROZEN_COLUMNS


        by_seq: dict[int, frozenset] = {}

        self._row_number_by_key = {}
        self._display_id_by_key = {}
        if self._subtable_mode():
            self._emit_subtable_rows(rows, by_seq)
        else:
            self._emit_classic_rows(rows, by_seq)


        self._flush_dimensions()
        row_node_ids: list[frozenset] = [
            by_seq.get(n + 1, frozenset()) for n in range(max(by_seq, default=0))
        ]
        self.post_message(self.VisibleOrderChanged(row_node_ids))

        if newest_key is not None:


            try:
                self.move_cursor(row=self.get_row_index(newest_key), scroll=True)
            except Exception:


                if self.row_count:
                    try:
                        self.move_cursor(row=self.row_count - 1, scroll=True)
                    except Exception:
                        pass
        elif follow_tail:
            if self.row_count:
                try:
                    self.cursor_coordinate = Coordinate(
                        self.row_count - 1, self.cursor_coordinate.column
                    )
                except Exception:
                    pass
        elif current_key is not None:


            coord = self._coord_for_key(current_key)
            if coord is None and fallback_key:
                coord = self._coord_after_deleting_a_node(current_index, fallback_key)
            if coord is None and self.row_count:
                coord = Coordinate(
                    self._nearest_selectable_row(max(0, min(current_index, self.row_count - 1))),
                    self.cursor_coordinate.column,
                )
            try:
                if coord is None:

                    raise KeyError(current_key)


                follow_y = self._follow_target_scroll_y(display_rows, old_scroll_y)
                if follow_y is None:


                    handoff = self._follow_handoff_coordinate()
                    if handoff is not None:
                        coord = handoff


                self.set_reactive(DataTable.cursor_coordinate, coord)


                self._update_node_title()
                self.refresh_status_for_cursor_row(display_rows)
                target_y = (
                    follow_y if follow_y is not None else (old_scroll_y if was_visible else None)
                )
                if target_y is not None:


                    self.scroll_y = target_y
                    if int(self.scroll_y) != int(target_y):


                        self.call_after_refresh(setattr, self, "scroll_y", target_y)
                self._followed_scroll_y = follow_y
            except Exception:
                pass


        if not self.row_count:
            from cloudbasher.core.tui.widgets.node_status_line import NodeStatusLine

            try:
                self.screen.query_one("#node-status-line", NodeStatusLine).set_row_position(
                    None, None
                )
            except Exception:
                pass

    def _group_key_for_row(self, row_key: Optional[str]) -> Optional[str]:
        """The credential-row key for the row `row_key` sits on, or None."""
        if not row_key or row_key.startswith(_GROUP_KEY_PREFIX):
            return None
        node = (self._last_nodes_by_id or {}).get(row_key)
        if node is None:
            return None
        _k, _i, _t, root = resolve_credential_display(
            getattr(node, "credential_id", None), self._last_credentials_by_id or {}
        )
        target = root.id if root is not None else getattr(node, "credential_id", None)
        return group_row_key(target) if target else None


    _CHROME_KEY_PREFIXES = ("blk:", "hdr:")

    def _is_chrome_row(self, row_key: Optional[str]) -> bool:
        return bool(row_key) and str(row_key).startswith(self._CHROME_KEY_PREFIXES)

    def _nearest_selectable_row(self, row_index: int) -> int:
        """`row_index`, moved off chrome onto the nearest real row."""
        keys = [str(key.value) for key in self.rows]
        if not keys or not self._is_chrome_row(keys[row_index]):
            return row_index
        above = range(row_index - 1, -1, -1)
        below = range(row_index + 1, len(keys))
        for candidate in (*above, *below):
            if not self._is_chrome_row(keys[candidate]):
                return candidate
        return row_index

    def _coord_after_deleting_a_node(self, old_index: int, group_key: str) -> Optional[Coordinate]:
        """Where the cursor goes when the NODE row it was on has been deleted."""
        siblings = [
            index
            for index, key in enumerate(str(k.value) for k in self.rows)
            if self._group_key_for_row(key) == group_key
        ]
        if siblings:
            nearest = min(siblings, key=lambda i: (abs(i - old_index), i > old_index))
            return Coordinate(nearest, self.cursor_coordinate.column)
        return self._coord_for_key(group_key)

    def _frontier_display_row(self, display_rows: list) -> Optional[Any]:
        """The lowest row a WORKER IS ON, or None."""
        for row in display_rows:


            if _is_in_flight(row):
                return row
        return None

    def _follow_target_scroll_y(self, display_rows: list, old_scroll_y: int) -> Optional[int]:
        """Where to scroll so the frontier sits `frontier_rows` down, or None."""
        from cloudbasher.core.utils.perf_config import (
            get_node_follow_frontier_rows,
            get_node_follow_repin_seconds,
        )

        rows_above = get_node_follow_frontier_rows()
        if rows_above <= 0:
            return None


        now = time.monotonic()
        if self._followed_scroll_y is not None:
            try:
                ours = max(0, min(self._followed_scroll_y, int(self.max_scroll_y)))
            except Exception:
                ours = self._followed_scroll_y
            if old_scroll_y != ours:
                self._follow_suspended_at = now
                self._followed_scroll_y = None


                self._follow_handoff_key = None
        if self._follow_suspended_at:
            repin = get_node_follow_repin_seconds()
            if repin <= 0 or (now - self._follow_suspended_at) < repin:
                return None
            self._follow_suspended_at = 0.0

        row = self._frontier_display_row(display_rows)
        if row is None:
            return None
        coord = self._coord_for_key(getattr(row, "node_id", None))
        if coord is None:
            return None


        self._follow_handoff_key = getattr(row, "node_id", None)
        return max(0, coord.row - rows_above)

    def _follow_handoff_coordinate(self) -> Optional[Coordinate]:
        """Where the cursor goes now the followed run is over, or None."""
        key, self._follow_handoff_key = self._follow_handoff_key, None
        return None if key is None else self._coord_for_key(key)

    def _coord_for_key(self, row_key: Optional[str]) -> Optional[Coordinate]:
        """The cursor coordinate of `row_key`, or None if no row carries it."""
        if row_key is None:
            return None
        for row_index, key in enumerate(self.rows):
            if str(key.value) == row_key:
                return Coordinate(row_index, self.cursor_coordinate.column)
        return None

    def get_cursor_coordinate_for_row_key(self, row_key: str) -> Coordinate:
        coord = self._coord_for_key(row_key)
        if coord is None:
            raise KeyError(row_key)
        return coord

    def cursor_credential_number(self) -> Optional[int]:
        """The `<cred#>` of the credential the cursor is pointing at."""
        key = self._current_row_key()
        if key is None:
            return None
        group = self._find_group(key)
        if group is not None:
            return group.get("cred_num")
        node = self._last_nodes_by_id.get(key)
        if node is None:
            return None
        for entry in credential_group_keys(self._last_credentials_by_id, self._last_nodes_by_id):
            if entry.record_id == getattr(node, "credential_id", None):
                return entry.cred_num


        _t, _i, _tg, root = resolve_credential_display(
            getattr(node, "credential_id", None), self._last_credentials_by_id
        )
        if root is None:
            return None
        for entry in credential_group_keys(self._last_credentials_by_id, self._last_nodes_by_id):
            if entry.record_id == root.id:
                return entry.cred_num
        return None

    def cursor_credential_mode(self) -> str:
        """The declared `ACT_AS` mode of the credential the cursor is on."""
        rec = self._cursor_originating_record()
        if rec is None or getattr(rec, "provider", None) != "aws":
            return ""
        extra = getattr(getattr(rec, "raw", None), "extra", None) or {}
        from cloudbasher.csp.aws.act_as import act_as_mode_of

        return act_as_mode_of(extra)

    def cursor_credential_provider(self) -> str:
        """Which CSP owns the credential the cursor is on ("" for none)."""
        rec = self._cursor_originating_record()
        if rec is None:
            return ""
        return str(getattr(rec, "provider", "") or "")

    def cursor_credential_kind(self) -> str:
        """`CredentialRecord.kind` of the credential the cursor is on."""
        rec = self._cursor_originating_record()
        if rec is None:
            return ""


        return str(getattr(rec, "kind", "") or "")

    def _cursor_originating_record(self):
        """The ORIGINATING record behind the cursor."""
        num = self.cursor_credential_number()
        if num is None:
            return None
        for entry in credential_group_keys(self._last_credentials_by_id, self._last_nodes_by_id):
            if entry.cred_num == num:
                return self._last_credentials_by_id.get(entry.record_id)
        return None

    def cursor_is_credential_row(self) -> bool:
        """Is the cursor on a credential row rather than a node row?"""
        key = self._current_row_key()
        return key is not None and self._find_group(key) is not None

    def cursor_is_childless_credential(self) -> bool:
        """Is the cursor on a credential that has provisioned nothing yet?"""
        key = self._current_row_key()
        if key is None:
            return False
        group = self._find_group(key)
        return group is not None and not group["members"]

    def _row_key_at(self, index: int) -> Optional[str]:
        """The row key at a physical index, without moving the cursor."""
        if index < 0 or index >= self.row_count:
            return None
        try:
            from textual.coordinate import Coordinate

            return str(self.coordinate_to_cell_key(Coordinate(index, 0)).row_key.value)
        except Exception:
            return None

    def cursor_row_number(self) -> Optional[int]:
        """The Row# of the node under the cursor, or None."""
        key = self._current_row_key()
        if key is None:
            return None
        return getattr(self, "_row_number_by_key", {}).get(key)

    def cursor_display_id(self) -> Optional[str]:
        """The unified `Cred#.Node#` id of the node under the cursor."""
        key = self._current_row_key()
        if key is None:
            return None
        display_id = getattr(self, "_display_id_by_key", {}).get(key) or None
        return None if display_id == UNADDRESSABLE_DISPLAY_ID else display_id

    def _current_row_key(self) -> Optional[str]:
        if self.cursor_row is None or not self.row_count:
            return None
        try:
            return str(self.coordinate_to_cell_key(self.cursor_coordinate).row_key.value)
        except Exception:
            return None

    def _find_group(
        self, row_key: str, display_rows: Optional[list] = None
    ) -> Optional[dict[str, Any]]:


        if display_rows is None:
            display_rows = build_node_display_rows(
                self._last_credentials_by_id, self._last_nodes_by_id, self._selected_ids
            )
        rows = build_display_rows(
            display_rows,
            self._expanded_groups,
            flat=(self._view_mode == "flat"),
            credential_keys=credential_group_keys(
                self._last_credentials_by_id, self._last_nodes_by_id
            ),
        )
        return next((r for r in rows if r["kind"] == "parent" and r["row_key"] == row_key), None)

    def _refresh_selection_cells(self) -> None:
        """Repaint just the checkbox column for every currently-visible row, instead of reload()'s clear()+full-rebuild -- Phase F fix for two live-testing bugs traced to the same root cause:"""
        display_rows = build_node_display_rows(
            self._last_credentials_by_id, self._last_nodes_by_id, self._selected_ids
        )
        rows = build_display_rows(
            display_rows,
            self._expanded_groups,
            flat=(self._view_mode == "flat"),
            credential_keys=credential_group_keys(
                self._last_credentials_by_id, self._last_nodes_by_id
            ),
        )
        for r in rows:
            if r["kind"] == "header":
                continue
            if r["kind"] == "parent":
                cell = self._group_sel_cell(
                    r["members"], r.get("record_id") in self._selected_credential_ids
                )
            else:
                cell = _SEL_CHECKED if r["node"].selected else _SEL_UNCHECKED
            try:
                self.update_cell(r["row_key"], self.SEL_COLUMN_KEY, cell)
            except Exception:
                pass


        try:
            self.columns[self.SEL_COLUMN_KEY].label = self._sel_header(display_rows)


            self._require_update_dimensions = True
            self._flush_dimensions()
            self.refresh()
        except Exception:
            pass

    def _is_addressable_row(self, row_key: Optional[str]) -> bool:
        """Does this row key name something a command can act on?"""
        if row_key is None:
            return False
        return self._find_group(row_key) is not None or row_key in self._last_nodes_by_id

    def _skip_unaddressable_rows(self, delta: int) -> None:
        """Step the cursor past any row a command cannot act on."""
        row = self.cursor_row
        if row is None:
            return
        for _ in range(4):
            key = self._row_key_at(row)
            if key is None or self._is_addressable_row(key):
                break
            row += delta
            if row < 0 or row >= self.row_count:
                return
        if row != self.cursor_row:
            self.move_cursor(row=row)

    def action_cursor_down(self) -> None:  # type: ignore[override]
        super().action_cursor_down()
        self._skip_unaddressable_rows(1)

    def action_cursor_up(self) -> None:  # type: ignore[override]
        super().action_cursor_up()
        self._skip_unaddressable_rows(-1)

    def action_toggle_select(self) -> None:
        if self._view_mode == "unmanaged":
            return self._toggle_unmanaged()
        row_key = self._current_row_key()
        if not self._is_addressable_row(row_key):
            return
        self._range_anchor_row_key = row_key
        group = self._find_group(row_key)
        if group is not None:
            members: list[NodeDisplayRow] = group["members"]
            record_id = group.get("record_id")


            select = not (
                record_id in self._selected_credential_ids
                if record_id
                else all(m.node_id in self._selected_ids for m in members)
            )
            if record_id:
                if select:
                    self._selected_credential_ids.add(record_id)
                else:
                    self._selected_credential_ids.discard(record_id)
            for m in members:
                if select:
                    self._selected_ids.add(m.node_id)
                else:
                    self._selected_ids.discard(m.node_id)
        elif row_key in self._selected_ids:
            self._selected_ids.discard(row_key)
        else:
            self._selected_ids.add(row_key)
        self._commit_manual_selection()

    def action_range_select(self) -> None:
        """Live-testing feedback (key remap #1): Gmail/Finder-style shift range select. 'x' (action_toggle_select) marks its row as the anchor; a later 'X' here selects every row between that anchor and the current cursor position, inclusive -- always ADDS to the selection (never toggles/clears), matching "select all rows between row1 and row2" rather than a mirrored toggle that could surprise-deselect rows outside the pressed pair."""
        if self._view_mode == "unmanaged":
            return self._range_select_unmanaged()
        current_key = self._current_row_key()
        if current_key is None:
            return
        anchor_key = self._range_anchor_row_key
        if anchor_key is None:
            self.action_toggle_select()
            return
        display_rows = build_node_display_rows(
            self._last_credentials_by_id, self._last_nodes_by_id, self._selected_ids
        )
        rows = build_display_rows(
            display_rows,
            self._expanded_groups,
            flat=(self._view_mode == "flat"),
            credential_keys=credential_group_keys(
                self._last_credentials_by_id, self._last_nodes_by_id
            ),
        )
        row_keys = [r["row_key"] for r in rows]
        try:
            anchor_index = row_keys.index(anchor_key)
            current_index = row_keys.index(current_key)
        except ValueError:
            self.action_toggle_select()
            return
        lo, hi = sorted((anchor_index, current_index))
        for r in rows[lo : hi + 1]:
            if r["kind"] == "header":
                continue
            if r["kind"] == "parent":
                if r.get("record_id"):
                    self._selected_credential_ids.add(r["record_id"])
                for m in r["members"]:
                    self._selected_ids.add(m.node_id)
            else:
                self._selected_ids.add(r["node"].node_id)
        self._commit_manual_selection()

    def action_toggle_select_all(self) -> None:
        if self._view_mode == "unmanaged":
            return self._select_all_unmanaged()
        visible = build_node_display_rows(
            self._last_credentials_by_id, self._last_nodes_by_id, self._selected_ids
        )


        cred_ids = [
            e.record_id
            for e in credential_group_keys(self._last_credentials_by_id, self._last_nodes_by_id)
        ]
        if not visible and not cred_ids:


            self.post_message(
                self.SelectionRefused("nothing to select yet -- no credentials or nodes are loaded")
            )
            return
        select = not (
            all(row.node_id in self._selected_ids for row in visible)
            and all(c in self._selected_credential_ids for c in cred_ids)
        )
        for cid in cred_ids:
            if select:
                self._selected_credential_ids.add(cid)
            else:
                self._selected_credential_ids.discard(cid)
        for row in visible:
            if select:
                self._selected_ids.add(row.node_id)
            else:
                self._selected_ids.discard(row.node_id)
        self._commit_manual_selection()

    def _toggle_unmanaged(self) -> None:
        """`x` in the UNMANAGED view."""
        key = self._current_row_key()
        if key is None:
            return
        self._range_anchor_row_key = key
        if key in self._selected_finding_ids:
            self._selected_finding_ids.discard(key)
        else:
            self._selected_finding_ids.add(key)
        self._commit_unmanaged_selection()

    def _range_select_unmanaged(self) -> None:
        """`X` in the UNMANAGED view -- always ADDS, never toggles, matching `action_range_select`'s rule: "select every row between row1 and row2" rather than a mirrored toggle that could surprise-deselect."""
        current = self._current_row_key()
        if current is None:
            return
        keys = [r.key for r in self._unmanaged_rows]
        anchor = self._range_anchor_row_key
        if anchor is None or anchor not in keys or current not in keys:


            return self._toggle_unmanaged()
        lo, hi = sorted((keys.index(anchor), keys.index(current)))
        self._selected_finding_ids |= set(keys[lo : hi + 1])
        self._commit_unmanaged_selection()

    def _select_all_unmanaged(self) -> None:
        """`a` in the UNMANAGED view."""
        keys = {r.key for r in self._unmanaged_rows}
        if not keys:


            self.post_message(
                self.SelectionRefused(
                    "nothing to select -- run .discover or .enum to find unmanaged environments"
                )
            )
            return
        self._selected_finding_ids = set() if keys <= self._selected_finding_ids else keys
        self._commit_unmanaged_selection()

    def _commit_unmanaged_selection(self) -> None:
        """Repaint the ticks and publish, without touching the node sets."""
        self._refresh_unmanaged_selection_cells()
        self.post_message(
            self.SelectionChanged(
                set(self._selected_ids),
                set(self._selected_credential_ids),
                set(self._selected_finding_ids),
            )
        )

    def _refresh_unmanaged_selection_cells(self) -> None:
        for row in self._unmanaged_rows:
            cell = _SEL_CHECKED if row.key in self._selected_finding_ids else _SEL_UNCHECKED
            try:
                self.update_cell(row.key, self.SEL_COLUMN_KEY, cell)
            except Exception:  # noqa: BLE001 - the row is not on screen; nothing to paint
                pass
        try:
            self.columns[self.SEL_COLUMN_KEY].label = self._unmanaged_sel_header()


            self._require_update_dimensions = True
            self._flush_dimensions()
            self.refresh()
        except Exception:  # noqa: BLE001 - the column set belongs to another view
            pass

    def _commit_manual_selection(self) -> None:
        """Finish a HAND selection gesture: forget any implicit selection, then repaint and publish."""
        self._auto_selected_ids = set()
        self._auto_selected_credential_ids = set()
        self._refresh_selection_cells()
        self.post_message(
            self.SelectionChanged(set(self._selected_ids), set(self._selected_credential_ids))
        )

    def select_current_row(self) -> set[str]:
        """Check the cursor row's box. Additive -- never a toggle."""
        row_key = self._current_row_key()
        if not self._is_addressable_row(row_key):
            return set()
        group = self._find_group(row_key)
        ids = {m.node_id for m in group["members"]} if group is not None else {row_key}


        cred_id = group.get("record_id") if group is not None else None
        added_creds = {cred_id} - self._selected_credential_ids if cred_id else set()
        added = ids - self._selected_ids
        if added or added_creds:
            self._auto_selected_ids = added
            self._auto_selected_credential_ids = added_creds
            self._selected_ids |= added
            self._selected_credential_ids |= added_creds
            self._refresh_selection_cells()
            self.post_message(
                self.SelectionChanged(set(self._selected_ids), set(self._selected_credential_ids))
            )
        return ids

    def clear_auto_selection(self) -> bool:
        """Undo the implicit selection select_current_row() made, if any."""
        stale = self._auto_selected_ids & self._selected_ids
        stale_creds = self._auto_selected_credential_ids & self._selected_credential_ids
        self._auto_selected_ids = set()
        self._auto_selected_credential_ids = set()
        if not stale and not stale_creds:
            return False
        self._selected_ids -= stale
        self._selected_credential_ids -= stale_creds
        self._refresh_selection_cells()
        self.post_message(
            self.SelectionChanged(set(self._selected_ids), set(self._selected_credential_ids))
        )
        return True

    def _drop_vanished_selection(
        self,
        nodes_by_id: dict[str, NodeRecord],
        current_rows: "list[NodeDisplayRow]",
    ) -> None:
        """Forget checked nodes that no longer exist."""
        vanished = self._selected_ids - set(nodes_by_id)
        if not vanished:
            return


        orphaned = {
            credential_group_key(row)
            for nid in vanished
            if (row := self._last_display_rows_by_id.get(nid)) is not None
        }
        still_populated = {credential_group_key(r) for r in current_rows}
        self._selected_credential_ids -= orphaned - still_populated
        self._auto_selected_credential_ids -= orphaned - still_populated
        self._selected_ids -= vanished
        self._auto_selected_ids -= vanished
        self.post_message(
            self.SelectionChanged(set(self._selected_ids), set(self._selected_credential_ids))
        )

    def refresh_status_for_cursor_row(self, display_rows: Optional[list] = None) -> None:
        """Repaint the sibling NodeStatusLine with the cursor row's detail."""
        self._paint_status_for_row(self._current_row_key(), display_rows)

    def get_selected_ids(self) -> set[str]:
        return set(self._selected_ids)

    def get_selected_credential_ids(self) -> set[str]:
        """Record ids of credentials checked directly (L10a)."""
        return set(self._selected_credential_ids)

    def current_node_id(self) -> Optional[str]:
        """The highlighted row's node id, or None when nothing is highlighted or the row is a group summary rather than a single node."""
        row_key = self._current_row_key()
        if row_key is None or row_key not in self._last_nodes_by_id:
            return None
        return row_key

    def action_expand_toggle(self) -> None:
        row_key = self._current_row_key()
        if row_key is None:
            return
        group = self._find_group(row_key)
        if row_key in self._expanded_groups:
            self._expanded_groups.discard(row_key)
        elif group is not None and group["members"]:
            self._expanded_groups.add(row_key)
        else:


            return
        self.reload(self._last_credentials_by_id, self._last_nodes_by_id)

    def _expandable_group_keys(self) -> set[str]:
        """Every group row that HAS members, so is worth expanding."""
        display_rows = build_node_display_rows(
            self._last_credentials_by_id, self._last_nodes_by_id, self._selected_ids
        )
        rows = build_display_rows(
            display_rows,
            self._expanded_groups,
            flat=(self._view_mode == "flat"),
            credential_keys=credential_group_keys(
                self._last_credentials_by_id, self._last_nodes_by_id
            ),
        )
        return {r["row_key"] for r in rows if r["kind"] == "parent" and r.get("members")}

    def action_expand_all_toggle(self) -> None:
        """Expand every credential's nodes, or collapse them all (#113)."""
        expandable = self._expandable_group_keys()
        if not expandable:
            return
        if expandable <= self._expanded_groups:
            self._expanded_groups -= expandable
        else:
            self._expanded_groups |= expandable
        self.reload(self._last_credentials_by_id, self._last_nodes_by_id)

    def _show_view(self, mode: str) -> None:
        """Show `mode` ("tree" | "flat"). ITEMS #13."""
        if mode == self._view_mode:
            return
        assert mode in VIEW_MODES, f"unregistered view {mode!r} -- add it to VIEW_MODES"
        self._view_mode = mode


        self._update_node_title()
        self.reload(self._last_credentials_by_id, self._last_nodes_by_id)

    def action_show_cred_view(self) -> None:
        """`1` -- the Credential View (credentials, nodes nested)."""
        self._show_view("tree")

    def action_show_node_view(self) -> None:
        """`2` -- the Node View (every node, flat)."""
        self._show_view("flat")

    def set_unmanaged(
        self,
        rows: "list[UnmanagedViewRow]",
        *,
        scanned_at: Optional[float] = None,
        scope: str = "",
    ) -> None:
        """Push the provider's UNMANAGED rows in. `#504`."""
        self._unmanaged_rows = list(rows)
        self._unmanaged_scanned_at = scanned_at
        self._unmanaged_scope = scope
        live = {r.key for r in self._unmanaged_rows}
        stale = self._selected_finding_ids - live
        if stale:
            self._selected_finding_ids -= stale
            self.post_message(
                self.SelectionChanged(
                    set(self._selected_ids),
                    set(self._selected_credential_ids),
                    set(self._selected_finding_ids),
                )
            )

    def unmanaged_row_count(self) -> Optional[int]:
        """`None` until a scan has run -- the tab's third state."""
        return None if self._unmanaged_scanned_at is None else len(self._unmanaged_rows)

    def _reload_unmanaged(
        self,
        current_key: Optional[str],
        credentials_by_id: "dict[str, CredentialRecord]",
        nodes_by_id: "dict[str, NodeRecord]",
    ) -> None:
        """Draw the UNMANAGED view: chrome, then the seven declared columns."""
        self._last_credentials_by_id = dict(credentials_by_id)
        self._last_nodes_by_id = dict(nodes_by_id)
        self.set_reactive(DataTable.cursor_coordinate, Coordinate(0, 0))
        self.clear(columns=True)
        self.add_column(self.EXPAND_HEADER, key=self.EXPAND_COLUMN_KEY)
        self.add_column(self._unmanaged_sel_header(), key=self.SEL_COLUMN_KEY)
        for name in self.UNMANAGED_COLUMNS:
            self.add_column(Text(name), key=f"um-{name}")
        for row in self._unmanaged_rows:
            checked = _SEL_CHECKED if row.key in self._selected_finding_ids else _SEL_UNCHECKED


            style = "dim strike" if row.deleted else ""
            cells = [
                Text(" "),
                checked,
                Text(str(row.index)),
                Text(row.provenance),
                Text(row.principal),
                Text(row.region),
                Text(row.environment),
                Text(row.state),
                Text(row.note),
            ]
            if style:
                for c in cells[2:]:
                    c.stylize(style)
            self.add_row(*cells, key=row.key)


        self._flush_dimensions()
        self._update_node_title()
        if current_key is not None:
            self._restore_cursor(current_key)
        self.post_message(self.VisibleOrderChanged([]))

    def _unmanaged_sel_header(self) -> Text:
        """The select-all glyph for the Unmanaged view. `#555`."""


        return _tri_state(len(self._selected_finding_ids), len(self._unmanaged_rows))

    def _restore_cursor(self, row_key: str) -> None:
        """Put the cursor back on `row_key` if it survived the rebuild."""
        try:
            self.cursor_coordinate = Coordinate(self.get_row_index(row_key), 0)
        except Exception:  # noqa: BLE001 - the row is simply gone; row 0 is right
            pass

    def action_show_unmanaged_view(self) -> None:
        """`3` -- the Unmanaged view: environments found but not tracked."""
        self._show_view("unmanaged")

    def action_toggle_view_mode(self) -> None:
        """Flip between the two views."""
        self._show_view("flat" if self._view_mode == "tree" else "tree")

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        """Push the highlighted row's detail into the sibling NodeStatusLine. Uses ``self.screen.query_one`` (not ``self.query_one``) since the status line is a sibling, not a descendant, of this table."""
        self._update_node_title()


        if event.row_key is None or event.row_key.value is None:
            return
        self._paint_status_for_row(str(event.row_key.value))

    def _paint_status_for_row(
        self, row_key: Optional[str], display_rows: Optional[list] = None
    ) -> None:
        """Render one row's detail into the sibling NodeStatusLine. Shared by the RowHighlighted handler and refresh_status_for_cursor_row()."""
        from cloudbasher.core.tui.widgets.node_status_line import NodeStatusLine

        if row_key is None:
            return
        group = self._find_group(row_key, display_rows)


        if group is not None:
            cursor_cred = group.get("record_id")
        else:
            group_key = self._group_key_for_row(row_key)
            cursor_cred = group_key[len(_GROUP_KEY_PREFIX) :] if group_key else None
        self.post_message(self.CursorCredentialChanged(cursor_cred))
        try:
            status = self.screen.query_one("#node-status-line", NodeStatusLine)
        except Exception:
            return


        status.set_row_position(
            self.cursor_row_number(),
            len(self._last_nodes_by_id),
        )
        if group is not None:
            status.show_group(group["members"], identity=group.get("identity", ""))
            return
        rows = display_rows
        if rows is None:
            rows = build_node_display_rows(
                self._last_credentials_by_id, self._last_nodes_by_id, self._selected_ids
            )
        node = next((r for r in rows if r.node_id == row_key), None)
        if node is not None:
            status.show(node)

    def on_data_table_row_label_selected(self, event: DataTable.RowLabelSelected) -> None:
        """Restore click-to-select over the row-number gutter."""
        try:
            self.move_cursor(row=event.row_index)
        except Exception:
            pass

    def _update_node_title(self) -> None:
        """Keep "#node-title" showing the plain "Nodes (N)" count."""
        from cloudbasher.core.tui.textual_app import PaneTitle
        from cloudbasher.core.utils.redact import is_redaction_enabled

        try:
            title_widget = self.screen.query_one("#node-title", PaneTitle)
        except Exception:
            return
        title_widget.update(
            view_pane_title(
                self._view_mode,
                len(self._last_nodes_by_id),
                _originating_count(self._last_credentials_by_id),
                redacted=is_redaction_enabled(),
                unmanaged_count=self.unmanaged_row_count(),
                unmanaged_age=self._unmanaged_scope,
            )
        )


    CONTENT_COLUMN_KEY = "content"

    def _subtable_mode(self) -> bool:
        """Is the nested sub-table layout in use for THIS render?"""
        from cloudbasher.core.tui.widgets.node_subtable import block_enabled

        return self._view_mode != "flat" and block_enabled()

    @staticmethod
    def _rich_cells(row: dict[str, Any], cred: Text, values: dict[str, str]) -> dict[str, Text]:
        """Per-field styled overrides for a credential row."""
        from .node_subtable import MINT_FILL, MINT_STYLE

        cells: dict[str, Text] = {"cred": cred}


        cells["csp"] = _credential_csp_cell(values.get("csp", ""))
        mints = bool(row.get("can_mint"))
        if mints:


            shown = values["nodes"]
            head, sep, tail = shown.partition("/")
            cell = Text(head)
            if sep:
                cell.append(sep)
                cell.append(tail, style=MINT_STYLE)
            cells["nodes"] = cell


            framed = cred.copy()
            framed.stylize(MINT_FILL)
            cells["cred"] = framed


        cred_id = Text(str(row.get("cred_id") or "—"))
        if row.get("cred_invalid"):
            cred_id.stylize("bold red")


        if cred_id.spans:


            cells["cred_id"] = cred_id
        return cells

    @staticmethod
    def _cred_values(row: dict[str, Any], cred: Text) -> dict[str, str]:
        """A credential row as plain strings, keyed by `CRED_COLUMNS_SPEC` field."""
        members = row.get("members") or []
        return {


            "nodes": f"{len(members)}/{row.get('node_ceiling', 1)}",
            "csp": str(row.get("csp") or "—"),
            "account": str(row.get("account") or (members[0].acct if members else "—")),


            "cred": cred.plain,
            "cred_id": str(row.get("cred_id") or "—"),
            "identity": str(row.get("identity") or "—"),
            "target_account": str(row.get("target_account") or "—"),
            "acts_as": str(row.get("acts_as") or row.get("target_identity") or "—"),


            "declared_name": str(row.get("declared_name") or ""),
            "declared_index": str(row.get("declared_index") or ""),
            "declared_region": str(row.get("declared_region") or ""),
            "regions": str(row.get("regions") or "—"),
            "description": str(row.get("description") or "—"),
        }

    def on_resize(self, event: events.Resize) -> None:
        """Re-plan the columns when the pane's width actually changes. #41."""
        planned = getattr(self, "_planned_content_width", None)
        if planned is None:
            return
        if self._content_width(self._planned_id_gutter) == planned:
            return
        self.reload(self._last_credentials_by_id, self._last_nodes_by_id)

    def _content_width(self, id_width: int = 2) -> int:
        """Columns available to the content column."""
        width = int(getattr(self.size, "width", 0) or 0)


        own_padding = 2 * int(getattr(self, "cell_padding", 1))
        return max(40, (width or 120) - self._chrome_width(id_width) - own_padding)

    def _chrome_cell_widths(self, id_width: int) -> dict[str, int]:
        """How wide each chrome column's CELLS are, keyed by column key."""
        return {

            self.ID_COLUMN_KEY: id_width,


            self.EXPAND_COLUMN_KEY: _activity_cell_width(),
            self.SEL_COLUMN_KEY: max(
                cell_len(g.plain) for g in (_SEL_CHECKED, _SEL_UNCHECKED, _SEL_PARTIAL)
            ),
            self.STATUS_COLUMN_KEY: _STATUS_CELL_WIDTH,
        }

    def _chrome_width(self, id_width: int) -> int:
        """Cells the four chrome columns occupy, padding included."""
        pad = 2 * int(getattr(self, "cell_padding", 1))
        return sum(w + pad for w in self._chrome_cell_widths(id_width).values())

    def _flush_dimensions(self) -> None:
        """Measure the columns NOW, instead of waiting for Textual's idle tick."""
        flush = DataTable._on_idle(self, events.Idle())
        try:
            flush.send(None)
        except StopIteration:
            return
        flush.close()
        raise RuntimeError(
            "DataTable._on_idle now awaits -- driving it synchronously would run only "
            "part of it. Re-derive the eager flush against the new body (`#707`)."
        )

    @staticmethod
    def _id_gutter_width(rows: list[dict[str, Any]]) -> int:
        """Widest id the gutter will hold, header included."""
        widest = len("ID")
        for row in rows:
            if row["kind"] == "parent":
                num = row.get("cred_num")
                if num is not None:
                    widest = max(widest, len(str(num)))
            node = row.get("node")
            display_id = getattr(node, "display_id", "") if node is not None else ""
            if display_id:
                widest = max(widest, len(str(display_id)))
        return widest

    def _emit_subtable_rows(self, rows: list[dict[str, Any]], by_seq: dict) -> None:
        """Credential rows and nested node blocks, both into ONE content column."""


        from cloudbasher.core.tui.widgets.node_subtable import (
            CRED_COLUMNS_SPEC,
            MINT_FRAME_BUDGET,
            SUB_COLUMNS,
            block_lead,
            block_natural,
            group_rail_budget,
            natural_widths,
            pane_span,
            plan_node_block,
            plan_widths,
            render_node_block,
            shared_budget,
        )

        id_gutter = self._id_gutter_width(rows)
        width = self._content_width(id_gutter)


        self._planned_content_width = width
        self._planned_id_gutter = id_gutter


        cred_chrome = group_rail_budget(CRED_COLUMNS_SPEC) + MINT_FRAME_BUDGET
        parents = [r for r in rows if r["kind"] == "parent"]
        cred_cells = {id(r): _cred_rich(r) for r in parents}
        values = {id(r): self._cred_values(r, cred_cells[id(r)]) for r in parents}
        cred_natural = natural_widths(
            CRED_COLUMNS_SPEC,
            [SimpleNamespace(**v) for v in values.values()],
            lambda r, f: str(getattr(r, f, "") or "—"),
        )


        sticky: dict[str, str] = {}
        block_rows: list[Any] = []
        for r in rows:
            if r["kind"] == "parent":
                if r["row_key"] in self._expanded_groups:
                    block_rows.extend(r.get("members") or [])
            elif r["kind"] not in ("header", "child"):

                block_rows.append(r["node"])
        sub_natural = block_natural(block_rows)


        demands = [pane_span(CRED_COLUMNS_SPEC, cred_natural, extra=cred_chrome)]
        if block_rows:
            demands.append(pane_span(SUB_COLUMNS, sub_natural, lead=block_lead()))
        target = shared_budget(width, *demands)
        plan = plan_widths(CRED_COLUMNS_SPEC, cred_natural, max(20, target - cred_chrome))


        sub_plan = plan_node_block(sub_natural, target) if block_rows else None

        line = partial(compose_row_line, plan)


        header = line({c.field: c.header for c, _w in plan})
        header.stylize("bold")
        content_column = self.columns[self.CONTENT_COLUMN_KEY]  # type: ignore[index]
        content_column.label = header


        self.fixed_rows = 0
        for r in rows:
            if r["kind"] == "header":


                continue
            if r["kind"] == "parent":
                self._add_parent_content_row(
                    r,
                    line(
                        values[id(r)],
                        self._rich_cells(r, cred_cells[id(r)], values[id(r)]),
                        frame=bool(r.get("can_mint")),
                    ),
                )
                members = r.get("members") or []
                if r["row_key"] in self._expanded_groups and members:
                    self._add_block(
                        render_node_block(members, width, plan=sub_plan), by_seq, sticky
                    )
                continue
            if r["kind"] == "child":


                continue


            node = r["node"]
            self._add_block(render_node_block([node], width, plan=sub_plan), by_seq, sticky)
        self._sticky_header_row = MappingProxyType(sticky)

    def _add_parent_content_row(self, row: dict[str, Any], content: Text) -> None:
        members = row.get("members") or []
        expand_glyph = _group_activity_cell(
            members, expanded=row["row_key"] in self._expanded_groups
        )
        cred_num = row.get("cred_num")
        self.add_row(
            Text(str(cred_num) if cred_num is not None else "", style="bold"),
            expand_glyph,
            self._group_sel_cell(members, row.get("record_id") in self._selected_credential_ids),
            _group_status_cell(members),
            content,
            key=row["row_key"],
        )

    def render_line(self, y: int) -> Strip:
        """`#741`. The node column header STICKS to the top of the viewport for as long as its own block is on screen."""
        sticky = self._sticky_header_strip(y)
        return sticky if sticky is not None else super().render_line(y)

    def _sticky_header_strip(self, y: int) -> "Strip | None":
        """Gather what `sticky_header_index` needs, then draw its answer."""
        if not self._sticky_header_row:


            return None
        try:


            top = self._get_fixed_offset().top
            at_top_line = y == top
            row_index: Optional[int] = None
            header_index: Optional[int] = None
            offset_in_row = 0
            scroll_y = self.scroll_offset.y if at_top_line else 0
            if at_top_line and scroll_y:
                row_key, offset_in_row = self._get_offsets(y + scroll_y)
                row_index = self._row_locations.get(row_key)
                header_key = self._sticky_header_row.get(row_key.value or "")
                if header_key is not None:


                    header_index = self._row_locations.get(header_key)  # type: ignore[arg-type]
            resolved = sticky_header_index(
                at_first_scrollable_line=at_top_line,
                scroll_y=scroll_y,
                offset_in_row=offset_in_row,
                row_index=row_index,
                header_index=header_index,
                cursor_row=self.cursor_row,
            )
            if resolved is None:
                return None


            header_y = self._get_row_region(resolved).y
            scroll_x = self.scroll_offset.x
            return self._render_line(
                header_y, scroll_x, scroll_x + self.size.width, self.rich_style
            )
        except Exception:


            _report_sticky_failure()
            return None

    def _add_block(self, lines: "list[SubTableLine]", by_seq: dict, sticky: dict) -> None:
        """One credential's whole block, plus its sticky-header entries."""
        keys = [self._add_block_line(sub, by_seq) for sub in lines]


        header_key = next(key for key, sub in zip(keys, lines) if sub.role == "header")
        for key in keys:
            sticky[key] = header_key

    def _add_block_line(self, sub: "SubTableLine", by_seq: dict) -> str:
        """One line of a rendered block: a rule, the header, or a node. RETURNS the row key it was added under."""
        from cloudbasher.core.tui.widgets.node_subtable import BLOCK_ID_STYLE

        if sub.node_id is None:
            self._block_rule_seq = getattr(self, "_block_rule_seq", 0) + 1
            key = f"blk:{self._block_rule_seq}"
            self.add_row(
                Text(" "),
                Text(" "),
                Text(" "),
                Text(" "),
                sub.text,
                key=key,
            )
            return key
        node = self._last_display_rows_by_id.get(sub.node_id)
        self.add_row(
            Text(getattr(node, "display_id", "") or "", style=BLOCK_ID_STYLE),


            _activity_cell(node, base=Text(" ")) if node is not None else Text(" "),
            _SEL_CHECKED if (node is not None and node.selected) else _SEL_UNCHECKED,
            _status_cell(node) if node is not None else Text(" "),
            sub.text,
            key=sub.node_id,
        )
        if node is not None and node.seq:
            self._row_number_by_key[sub.node_id] = node.seq
            self._display_id_by_key[sub.node_id] = str(node.display_id or "")
            by_seq[node.seq] = by_seq.get(node.seq, frozenset()) | {sub.node_id}
        return sub.node_id

    def _emit_classic_rows(self, rows: list[dict[str, Any]], by_seq: dict) -> None:
        """The original shared-column layout, moved here UNCHANGED."""


        last_child_by_key: dict[str, bool] = {}
        for idx, entry in enumerate(rows):
            if entry["kind"] != "child":
                continue
            nxt = rows[idx + 1] if idx + 1 < len(rows) else None
            last_child_by_key[entry["row_key"]] = not (
                nxt is not None
                and nxt["kind"] == "child"
                and nxt.get("group_id") == entry.get("group_id")
            )
        for r in rows:
            if r["kind"] == "header":
                self._add_subheader_row(r)
                continue
            if r["kind"] == "parent":


                self._add_parent_row(r, 0)
                continue
            node = r["node"]
            if r["kind"] == "child":
                glyph = "└" if last_child_by_key.get(r["row_key"], True) else "├"
            else:
                glyph = " "
            connector = Text(glyph, style="dim")
            self._add_node_row(node, connector=connector, row_number=node.seq)
            if node.seq:
                self._row_number_by_key[r["row_key"]] = node.seq
                self._display_id_by_key[r["row_key"]] = str(node.display_id or "")
                by_seq[node.seq] = by_seq.get(node.seq, frozenset()) | {node.node_id}

    def _add_parent_row(self, row: dict[str, Any], row_number: int) -> None:
        members: list[NodeDisplayRow] = row["members"]


        expand_glyph = _group_activity_cell(
            members, expanded=row["row_key"] in self._expanded_groups
        )
        status_icon = _group_status_cell(members)


        cred_num = row.get("cred_num")


        cred_num_cell = f"[{cred_num}]" if cred_num is not None else "—"
        identity_cell = row["identity"]


        target_cell = row.get("target_identity") or _summarize(
            [m.target_identity for m in members], "targets"
        )
        self.add_row(
            expand_glyph,
            self._group_sel_cell(members, row.get("record_id") in self._selected_credential_ids),
            status_icon,


            *self._cells_for(
                self.CRED_COLUMNS,
                (
                    f"({len(members)})",
                    _credential_csp_cell(row["csp"]),
                    cred_num_cell,


                    row.get("account") or (members[0].acct if members else "—"),
                    _cred_rich(row),
                    _elide_arn(identity_cell),
                    row.get("target_account") or "—",


                    row.get("acts_as") or _elide_arn(target_cell),
                    row.get("regions") or "—",
                    row.get("description") or "—",
                    "",
                ),
            ),
            key=row["row_key"],
        )

    def _add_subheader_row(self, row: dict[str, Any]) -> None:
        """The child-column header, repeated under each expanded credential."""
        self.add_row(


            Text("│", style="dim"),
            Text(" "),
            Text(" "),
            *self._cells_for(
                self.TREE_NODE_COLUMNS,
                tuple(Text(h, style="dim italic") for h in self.TREE_NODE_COLUMNS),
            ),
            key=row["row_key"],
        )

    def _add_node_row(self, node: NodeDisplayRow, connector: Text, row_number: int) -> None:
        """One node, in whichever layout the current view uses."""
        dim = lambda v: _dim_pending_cell(v, node.container_status)  # noqa: E731


        row_no = dim(node.display_id or "—")
        container = (


            dim(node.environment_id or "—"),
            dim(node.ip),
            dim(node.host),
            dim(node.region),
            _last_cell(dim(node.last), node.last_kind),
            dim(node.created),
            dim(node.exit_code),
            dim(node.command_output_preview),
        )
        layout: tuple[str, ...]
        cells: tuple[Any, ...]
        if self._view_mode == "flat":
            layout, cells = self.FLAT_COLUMNS, (
                row_no,
                _configured_csp_cell(node.csp, suffix=""),
                dim(node.target_acct),


                dim(node.target_identity),
                *container,
            )
        else:
            layout, cells = self.TREE_NODE_COLUMNS, ("", "", row_no, *container)
        self.add_row(


            _activity_cell(node, base=connector),
            _SEL_CHECKED if node.selected else _SEL_UNCHECKED,
            _status_cell(node),
            *self._cells_for(layout, cells),
            key=node.node_id,
        )

    @staticmethod
    def _sel_header(visible_rows: list[NodeDisplayRow]) -> Text:
        return _tri_state(sum(1 for r in visible_rows if r.selected), len(visible_rows))

    @staticmethod
    def _group_sel_cell(members: list[NodeDisplayRow], cred_selected: bool = False) -> Text:
        if not members:


            return _SEL_CHECKED if cred_selected else _SEL_UNCHECKED
        if all(m.selected for m in members):
            return _SEL_CHECKED
        if any(m.selected for m in members):
            return _SEL_PARTIAL
        return _SEL_UNCHECKED
