"""THE renderer for "which identities are loaded, and what does each act as"."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NamedTuple, Optional
from urllib.parse import urlsplit

from cloudbasher.core.node_ids import originating_root_id
from cloudbasher.core.types import CredentialRecord, numbered_originating_records
from cloudbasher.core.utils.output import obfuscate_secret

if TYPE_CHECKING:  # pragma: no cover
    from cloudbasher.csp.aws.act_as import ActAs


def declared_name_for(entry: "ActAs", extra: dict) -> str:
    """The name this derivation would use, or "" if the block declares none."""
    key = "role_session_name" if entry.mode == "role" else "federation_name"
    return str(extra.get(key) or "").strip()


_COLUMNS = (


    "#",


    "blk",
    "Nodes",
    "CSP",
    "Act|Org|Ten",
    "Identity",
    "Cred Type",
    "Cred ID",
    "Tgt Act|Org|Ten",
    "Acts As",
    "Regions",
    "Description",
)


_UNKNOWN = "-"


_TARGET_ACCOUNT_MARK = "->"


_INVALID_CREDENTIAL_MARK = "!"


def _own_account(extra: dict) -> str:
    """The account this credential itself belongs to."""
    from cloudbasher.csp.aws.account_id import account_for_credential

    return account_for_credential(extra) or ""


def _target_account(extra: dict) -> str:
    """The account this credential's declared derivation lands in."""
    parts = str(extra.get("role_arn") or "").split(":")

    if len(parts) > 4 and parts[4]:
        return parts[4]
    from cloudbasher.csp.aws.credentials import is_sso_extra

    if is_sso_extra(extra):
        return str(extra.get("account_id") or "").strip()


    from cloudbasher.csp.aws.act_as import DIRECT_MODES, act_as_mode_of

    mode = act_as_mode_of(extra)
    if mode in ("federated",) + DIRECT_MODES:
        return _own_account(extra)


    if not str(extra.get("access_key") or "").strip() and not mode:
        return _own_account(extra)
    return ""


def _account_cell(extra: dict) -> str:
    """The AWS account for this row, marked with WHOSE account it is."""
    own = _own_account(extra)
    target = _target_account(extra)
    if own and target and own != target:
        return f"{own}{_TARGET_ACCOUNT_MARK}{target}"
    if own:
        return own


    if str(extra.get("sso_start_url") or "").strip():
        return sso_start_url_display(extra) or _UNKNOWN
    if target:
        return f"{_TARGET_ACCOUNT_MARK}{target}"
    return _UNKNOWN


_verbose = False


def set_verbose_identity(enabled: bool) -> None:
    global _verbose
    _verbose = bool(enabled)


def toggle_verbose_identity() -> bool:
    """Flip it, and report the new state for the status line."""
    set_verbose_identity(not _verbose)
    return _verbose


def is_verbose_identity() -> bool:
    return _verbose


def target_identity_display(record: CredentialRecord) -> str:
    """A "<type>/<name>" label identifying *how* this target identity was derived, e.g. "federated/clb-1" or "role/deploy-session" -- more legible than the bare federation name/role ARN alone, and consistent across every derivation path."""
    return identity_display(
        record.target_kind, record.target_ref, record.target_session_name, record.label
    )


def identity_display(
    kind: Optional[str],
    ref: Optional[str],
    session_name: Optional[str],
    fallback: str = "",
) -> str:
    """THE short display form for a derived principal: `role/<session>` or `federated/<name>`."""
    if kind == "federation_token":
        return f"federated/{ref}" if ref else "federated"
    if kind == "assume_role":
        return f"role/{session_name}" if session_name else "role"
    return fallback


def derived_principal_arn(
    *, kind: Optional[str], ref: Optional[str], session_name: Optional[str], account: str
) -> str:
    """The full ARN a derivation lands on, assembled CLIENT-SIDE. `#532`."""
    if kind == "federation_token":
        return f"arn:aws:sts::{account}:federated-user/{ref}" if ref and account else ""
    if kind == "assume_role":
        role_arn = ref or ""
        parts = role_arn.split(":")
        if len(parts) > 4 and parts[4]:
            account = parts[4]
        from cloudbasher.csp.aws.act_as import role_name_from_arn

        role_name = role_name_from_arn(role_arn)
        if not role_name or not session_name or not account:
            return ""
        return f"arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}"
    return ""


def is_gcp_oauth_credential(record: CredentialRecord) -> bool:
    """Whether a GCP record is a user OAuth AT/RT rather than another kind."""
    if record.provider != "gcp":
        return False
    extra = record.raw.extra or {}
    data = extra.get("data") if isinstance(extra.get("data"), dict) else {}
    return bool(
        extra.get("access_token")
        or extra.get("refresh_token")
        or data.get("access_token")
        or data.get("refresh_token")
    )


def gcp_account_display(record: CredentialRecord) -> str:
    """GCP organization display name/number for the shared account columns."""
    organization_id = str(getattr(record, "_resolved_account", "") or "").strip()
    organization_name = str(
        getattr(record, "_resolved_organization_name", "") or ""
    ).strip()
    if not organization_id:

        organization_id = str(getattr(record, "_resolved_subject", "") or "").strip()
    if not organization_id:
        return _UNKNOWN
    if not organization_name:
        return organization_id
    return (
        f"{organization_name} {organization_id}"
        if is_verbose_identity()
        else organization_name
    )


def target_identity_full_arn(record: CredentialRecord, root: CredentialRecord) -> str:
    """Full ARN of a target (derived) identity, for the Info-pane Status line (NodeStatusLine) -- user-reported: the table's short "role/A" / "federated/cloudbasher" form (target_identity_display above, kept as-is for the table's narrow column) doesn't tell you WHICH AWS account/identity a federated or assumed-role session actually resolves to. AWS's assumed-role/federated-user ARN formats are fixed by AWS, not something STS varies per call, so this is constructed client-side from data already on hand -- no extra STS call needed: assumed-role: arn:aws:sts::<account>:assumed-role/<role-name>/<session-name> federated-user: arn:aws:sts::<account>:federated-user/<name> Falls back to the short form until ``root._resolved_account`` is known (same cache-until-resolved pattern as _identity_display/the resume- Identity-flash fix -- the account is only known once sts:GetCallerIdentity has resolved, or immediately on --resume now that it's persisted)."""
    account = root._resolved_account
    if not account:
        return target_identity_display(record)


    arn = derived_principal_arn(
        kind=record.target_kind,
        ref=record.target_ref,
        session_name=record.target_session_name,
        account=account,
    )


    return arn or target_identity_display(record)


def principal_arn_for(record: CredentialRecord, root: CredentialRecord) -> str:
    """The ARN of the principal this record SIGNS AS, or "" if not yet known."""
    if record.role == "target":
        return target_identity_full_arn(record, root)
    return str(getattr(record, "_resolved_identity_arn", "") or "")


def credential_is_verified(record: CredentialRecord) -> bool:
    """Whether this process has observed successful authentication for it."""
    if credential_is_invalid(record):
        return False
    return bool(
        getattr(record, "_resolved_identity_arn", None)
        or getattr(record, "_credential_verified", False)
    )


def credential_is_invalid(record: CredentialRecord) -> bool:
    """Whether a provider explicitly refused this credential in this process."""
    return bool(
        getattr(record, "status", "") == "invalid"
        or getattr(record, "_identity_rejected", None)
    )


def mark_credential_invalid(
    record: CredentialRecord, records: Optional[dict[str, CredentialRecord]] = None
) -> CredentialRecord:
    """Mark the originating credential invalid without changing node state."""
    if records:
        from cloudbasher.core.node_ids import originating_root_record

        root = originating_root_record(record.id, records) or record
    else:
        root = record
    root.status = "invalid"
    root._credential_verified = False
    return root


def mark_credential_verified(
    record: CredentialRecord, records: Optional[dict[str, CredentialRecord]] = None
) -> CredentialRecord:
    """Mark the originating credential after a successful auth operation."""
    if records:
        from cloudbasher.core.node_ids import originating_root_record

        root = originating_root_record(record.id, records) or record
    else:
        root = record
    root.status = "valid"
    root._identity_rejected = None
    root._credential_verified = True
    return root


def cred_type_code(record: CredentialRecord) -> str:
    """Best-effort SPEC-taxonomy code (User|Perm|Temp|RT|AT|SA|SP) from the coarser kind (console|permanent|temporary) core/credential_file.py's parser already classifies. Falls back to "—" rather than guessing wrong -- this is a heuristic pending refinement, not a finished classifier."""
    if record.kind == "console":
        return "User"
    extra = record.raw.extra or {}
    if record.provider == "aws":
        return "Perm" if record.kind == "permanent" else "Temp"
    if record.provider == "gcp":
        if record.kind == "permanent":
            data = extra.get("data") or {}
            if isinstance(data, dict) and data.get("type") == "service_account":
                return "SA"
            return "RT"
        return "AT"
    if record.provider == "azure":
        if extra.get("refresh_token"):
            return "RT"
        if extra.get("access_token"):
            return "AT"
        if record.kind == "permanent":
            if extra.get("client_secret"):
                return "SP"
            return "—"
        return "—"
    return "—"


_PROVIDER_CODE = {"aws": "AWS", "gcp": "GCP", "azure": "AZR"}


def provider_display_code(provider: str) -> str:
    """The short code for a CSP, shared by every surface that shows one."""
    return _PROVIDER_CODE.get(provider, str(provider).upper())


def _csp_cell(rec: CredentialRecord) -> str:
    return provider_display_code(rec.provider)


def is_unbound_credential(rec: Optional[CredentialRecord]) -> bool:
    """Does this credential declare that the container gets NO AWS identity?"""
    if rec is None or rec.provider != "aws":
        return False
    from cloudbasher.csp.aws.act_as import act_as_from_extra, skips_projection

    return skips_projection(act_as_from_extra(rec.raw.extra or {}))


CRED_META = {
    "User": (True, True),
    "Perm": (False, True),
    "Temp": (False, False),
    "RT": (False, True),
    "AT": (False, False),
    "SA": (False, True),
    "SP": (False, True),
}
CRED_USER_GLYPH = ("☺", "bold cyan")
CRED_API_GLYPH = ("⚙", "dim")
CRED_PERM_GLYPH = ("∞", "bold green")
CRED_TEMP_GLYPH = ("◔", "bold yellow")


CRED_LIFETIME_TEXT = {"User": "PRM", "Perm": "PRM", "Temp": "TMP"}


CRED_FLAGS = {
    "valid": ("✔", "bold green", "V"),
    "invalid": ("✖", "bold red", "I"),
    "denied": ("⊘", "bold yellow", "A"),
    "unbound": ("⊙", "bold yellow", "U"),


    "unknown": (" ", "", " "),
}


CRED_LIFETIME_CHAR = {
    "User": "P",
    "Perm": "P",
    "Temp": "T",
    "RT": "R",
    "AT": "A",
    "SA": "P",
    "SP": "P",
}


CRED_CELL_WIDTH = 8


def credential_groups(
    code: str, *, invalid: bool = False, unbound: bool = False, verified: bool = False
) -> list[tuple[str, str, str]]:
    """The Credential cell as exactly THREE (glyph, style, char) groups."""
    is_user, is_permanent = CRED_META.get(code, (False, True))


    validity = (
        CRED_FLAGS["invalid"]
        if invalid
        else (
            CRED_FLAGS["unbound"]
            if unbound
            else CRED_FLAGS["valid"] if verified else CRED_FLAGS["unknown"]
        )
    )
    return [
        validity,
        (*(CRED_USER_GLYPH if is_user else CRED_API_GLYPH), "U" if is_user else "A"),
        (
            *(CRED_PERM_GLYPH if is_permanent else CRED_TEMP_GLYPH),
            CRED_LIFETIME_CHAR.get(code, "P"),
        ),
    ]


def _assert_cell_width(cell: str) -> str:
    """The fixed-width promise, enforced rather than merely documented."""
    from rich.cells import cell_len

    width = cell_len(cell)
    if width != CRED_CELL_WIDTH:
        raise AssertionError(
            f"Credential cell is {width} cells, not {CRED_CELL_WIDTH}: {cell!r}. "
            "A glyph wider than one cell, or a text longer than one character, "
            "breaks the fixed width the column's alignment depends on."
        )
    return cell


def credential_text(
    code: str, *, invalid: bool = False, unbound: bool = False, verified: bool = False
) -> str:
    """The same cell as plain text, for `.creds`."""
    return _assert_cell_width(
        " ".join(
            g + t
            for g, _style, t in credential_groups(
                code, invalid=invalid, unbound=unbound, verified=verified
            )
        )
    )


_SSO_ROLE_PREFIX = "AWSReservedSSO_"


def sso_permission_set(role_name: str) -> str:
    """The permission set inside an Identity Center role name, or `""`."""
    if not role_name.startswith(_SSO_ROLE_PREFIX):
        return ""
    return role_name[len(_SSO_ROLE_PREFIX) :].rsplit("_", 1)[0]


def arn_tail(value: str) -> str:
    """An ARN reduced to the part that identifies WHO, not where."""
    if not value.startswith("arn:"):
        return value
    resource = value.rsplit(":", 1)[-1]
    if resource.startswith("assumed-role/"):
        parts = resource.split("/")
        if len(parts) <= 1:
            return resource
        role = parts[1]


        role = sso_permission_set(role) or role
        return f"role/{role}"
    return resource


def resolved_arn_display(arn: str) -> str:
    """How a resolved `sts:GetCallerIdentity` ARN is shown: whole under verbose, otherwise its tail."""
    return arn if is_verbose_identity() else arn_tail(arn)


def short_identity(extra: dict, resolved_arn: str = "") -> str:
    """The Identity column's value, short enough to read across a row."""
    if resolved_arn:
        return resolved_arn_display(resolved_arn)
    from cloudbasher.csp.aws.credentials import is_sso_extra

    if is_sso_extra(extra):
        user = str(extra.get("sso_username") or extra.get("username") or "").strip()
        if user:
            return f"sso/{user}"
    username = str(extra.get("username") or "").strip()
    if not username:
        username = str(extra.get("email") or "").strip() if extra.get("tenant_id") else ""
    if not username and extra.get("access_token") and extra.get("tenant_id"):
        username = azure_username_hint(extra)
    if username:
        return f"user/{username}"
    return ""


def azure_username_hint(extra: dict[str, Any]) -> str:
    """Best-effort user hint from declared metadata or an AT JWT payload."""
    declared = str(extra.get("username") or extra.get("email") or "").strip()
    if declared:
        return declared
    token = extra.get("access_token")
    if not isinstance(token, str):
        return ""
    parts = token.split(".")
    if len(parts) < 2 or not parts[1]:
        return ""
    try:
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return ""
    if not isinstance(claims, dict):
        return ""
    for key in ("preferred_username", "upn", "email"):
        value = claims.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def sso_portal_host(extra: dict) -> str:
    """`ssosandbox.awsapps.com` from a start URL, or ""."""
    start_url = str(extra.get("sso_start_url") or "").strip()
    if not start_url:
        return ""
    return start_url.split("//", 1)[-1].split("/", 1)[0] or start_url


def sso_start_url_display(extra: dict) -> str:
    """Compact SSO origin in normal mode; preserve the declared URL in verbose."""
    start_url = str(extra.get("sso_start_url") or "").strip()
    if not start_url:
        return ""
    if is_verbose_identity():
        return start_url
    try:
        host = urlsplit(start_url).hostname or ""
    except ValueError:
        return ""
    return host.split(".", 1)[0] if host else ""


def azure_tenant_id_display(extra: dict[str, Any]) -> str:
    """Format the display-only Azure tenant hint for credential rows."""
    tenant_id = azure_tenant_id_hint(extra)
    tenant_name = str(
        extra.get("tenant_name") or extra.get("tenant_domain") or ""
    ).strip()
    if not tenant_name:


        principal = str(extra.get("username") or extra.get("email") or "")
        if "@" in principal:
            tenant_name = principal.rsplit("@", 1)[1].strip()
    if tenant_name:
        if is_verbose_identity() and tenant_id:
            return f"{tenant_name} {tenant_id}"
        return tenant_name
    if not tenant_id or is_verbose_identity() or len(tenant_id) <= 12:
        return tenant_id
    return f"{tenant_id[:5]}…{tenant_id[-6:]}"


_DESCRIPTION_MODE_NAMES = {"federated": "fed"}


def derive_description(extra: dict) -> str:
    """What kind of credential this is, derived rather than typed by hand."""
    data = extra.get("data") if isinstance(extra.get("data"), dict) else {}
    if extra.get("refresh_token") or data.get("refresh_token"):
        return "OAuth RT"
    if extra.get("access_token") or data.get("access_token"):
        return "OAuth AT"

    from cloudbasher.csp.aws.credentials import is_sso_extra

    if is_sso_extra(extra):
        return "SSO"
    access_key = str(extra.get("access_key") or "").strip()
    if not access_key:


        return "USER" if str(extra.get("username") or "").strip() else _UNKNOWN
    prefix = access_key[:4].upper()
    from cloudbasher.csp.aws.act_as import act_as_mode_of

    mode = act_as_mode_of(extra) or "direct"
    name = _DESCRIPTION_MODE_NAMES.get(mode, mode)
    out = f"{prefix}-{name}"


    role = " ".join(str(extra.get(k) or "") for k in ("role_arn", "role_name", "identity"))
    if "AWSReservedSSO" in role:
        out += " (SSO)"
    return out


def description_cell(extra: dict) -> str:
    """The declared description, else the derived one."""
    return str(extra.get("description") or "").strip() or derive_description(extra)


def identity_cell(
    rec: CredentialRecord,
    extra: dict,
    *,
    resolved_arn: str = "",
    rejected: bool = False,
    key_shown_elsewhere: bool = False,
) -> str:
    """WHO this credential is -- the value BOTH the `.creds` listing and the Nodes pane's Identity column show, from one fallback chain."""
    short = short_identity(extra, resolved_arn)
    if short:
        return short


    if rec.provider == "azure" and extra.get("refresh_token"):
        return "(unknown)"
    if is_gcp_oauth_credential(rec):

        return "(unknown)"
    if rejected:


        return "(unknown)"
    host = sso_portal_host(extra)
    if host:
        return host
    from cloudbasher.csp.aws.account_id import looks_like_access_key

    label = str(rec.label or "").strip()
    if label and not looks_like_access_key(label):
        return label
    if label and not key_shown_elsewhere:


        return obfuscate_secret(label)
    return _UNKNOWN


def _key_cell(extra: dict) -> str:
    """What IDENTIFIES this credential, whatever kind it is."""
    access_key = str(extra.get("access_key") or "").strip()
    if access_key:


        return access_key
    from cloudbasher.csp.aws.credentials import is_sso_extra

    if is_sso_extra(extra):
        sso_user = str(extra.get("sso_username") or extra.get("username") or "").strip()
        if sso_user:
            return f"sso/{sso_user}"
    user = str(extra.get("username") or "").strip()
    return f"user/{user}" if user else _UNKNOWN


def _tui_credential_id_cell(extra: dict) -> tuple[str, str]:
    """TUI-only OAuth token fingerprint; `.creds` keeps bearer material out."""
    data = extra.get("data") if isinstance(extra.get("data"), dict) else {}
    has_refresh_token = bool(extra.get("refresh_token") or data.get("refresh_token"))
    token_key = "refresh_token" if has_refresh_token else "access_token"
    token = str(extra.get(token_key) or data.get(token_key) or "").strip()
    if token:
        return f"{token[:8]}…{token[-8:]}", "oauth_token_fingerprint"
    return _key_cell(extra), "identity"


def declared_name(act_as: Optional["ActAs"], extra: dict) -> str:
    """The derived principal's NAME, on its own. ITEMS #141 (owner, 2026-08-27)."""
    from cloudbasher.csp.aws.act_as import DERIVING_MODES


    if act_as is None or act_as.mode not in DERIVING_MODES:
        return ""
    name = declared_name_for(act_as, extra)


    return f"[{name}]" if name else ""


def _acts_as_cell(entry: "ActAs", extra: dict, *, with_name: bool = True) -> tuple[str, bool]:
    """The principal this derivation produces, in one cell."""
    name = declared_name_for(entry, extra)

    if entry.mode == "direct":
        return "direct", False
    if entry.mode == "direct-unbound":
        return "direct unbound IAM", False


    shown = f"[{name}]" if name else ""
    shown = shown or "(name it per action)"


    if entry.mode == "role":
        if is_verbose_identity() and entry.role_arn:
            return (f"{entry.role_arn}/{shown}" if with_name else entry.role_arn), False
        from cloudbasher.csp.aws.act_as import role_name_from_arn

        role_short = role_name_from_arn(entry.role_arn, missing="<role>")
        return (f"role/{role_short}/{shown}" if with_name else f"role/{role_short}"), False
    return (f"federated/{shown}" if with_name else "federated"), False


def declared_region(rec: CredentialRecord) -> str:
    """The region this credential DECLARED in its `-F` block, or ""."""
    if rec.provider != "aws" or rec.role != "originating":
        return ""
    return str((getattr(rec.raw, "extra", None) or {}).get("provision_region") or "")


def declared_index(act_as: Optional["ActAs"], extra: dict) -> str:
    """The declared `INDEX=`, or "" when it would not be applied."""
    from cloudbasher.csp.aws.act_as import DERIVING_MODES

    value = str(extra.get("provision_index") or "").strip()
    if not value:
        return ""
    if act_as is None or act_as.mode not in DERIVING_MODES:
        return ""
    return value


def _with_declared_index(acts_as: str, act_as: Optional["ActAs"], extra: dict) -> str:
    """Append a declared `INDEX=` to the acts-as cell. ITEMS #73."""
    declared = declared_index(act_as, extra)
    if not declared or not acts_as:
        return acts_as
    return f"{acts_as} \u2192{declared}"


def _no_derivation_cell(rec: CredentialRecord, extra: dict) -> str:
    """The `acts as` cell for a record with no ACT_AS -- which is not always a fault. See `_no_act_as_reason` for why the console/SSO case must not be reported as a refusal."""
    if rec.provider == "azure" and rec.kind == "console":


        return "user"
    if rec.provider == "gcp" and rec.kind == "console":


        return "user"
    if rec.provider == "azure" and (extra.get("refresh_token") or extra.get("access_token")):
        return "user"
    if is_gcp_oauth_credential(rec):
        return "user"
    if rec.provider != "aws":
        return "n/a (this CSP has no derivation model)"
    from cloudbasher.csp.aws.credentials import is_sso_extra

    if not extra.get("access_key"):
        if is_sso_extra(extra):
            role_name = str(extra.get("role_name") or "").strip()


            return role_name if role_name else "SSO (portal login)"


        if is_verbose_identity():
            resolved = str(getattr(rec, "_resolved_identity_arn", "") or "").strip()
            if resolved:
                return resolved
        return "user"
    return "NO ACT_AS -- every derivation refused"


def _format_table(header: tuple[str, ...], cells: list[list[str]]) -> str:
    """Left-aligned columns as ONE marked block -- see `core/utils/table_block`."""
    from cloudbasher.core.utils.table_block import format_table_block


    return format_table_block([list(header), *cells], lead_blank=True)


def _nodes_cell(rec: CredentialRecord, nodes_by_id: Optional[dict], counts: dict[str, int]) -> str:
    """How many nodes are running on this credential."""
    if nodes_by_id is None:
        return _UNKNOWN
    return str(counts.get(rec.id, 0))


def regions_ratio(rec: CredentialRecord, registered: dict[str, set]) -> str:
    """`used/available` regions, WITHOUT the declared-region suffix."""
    if rec.role != "originating":
        return _UNKNOWN
    if rec.provider in {"azure", "gcp"}:
        return f"{min(len(registered.get(rec.id, ())), 1)}/1"
    if rec.provider != "aws":
        return _UNKNOWN
    from cloudbasher.csp.aws.multi_region import _ALL_REGIONS

    return f"{len(registered.get(rec.id, ()))}/{len(_ALL_REGIONS)}"


def _regions_cell(rec: CredentialRecord, registered: dict[str, set]) -> str:
    """`used/available` regions, for the shapes where that is a real ratio."""
    if rec.provider not in {"aws", "azure", "gcp"} or rec.role != "originating":
        return _UNKNOWN

    cell = regions_ratio(rec, registered)


    declared = declared_region(rec)
    return f"{cell} \u2192{declared}" if declared else cell


class CredentialFacts(NamedTuple):
    """The cells the identity listing and the Nodes table BOTH show."""

    acts_as: str
    regions: str
    description: str
    nodes: str


    cred_id: str
    cred_id_redaction_type: str = "identity"


    declared_region: str = ""
    declared_index: str = ""
    declared_name: str = ""


def credential_facts_by_id(
    credentials_by_id: dict[str, CredentialRecord],
    nodes_by_id: Optional[dict] = None,
) -> dict[str, CredentialFacts]:
    """`{originating record id: CredentialFacts}`."""
    from cloudbasher.csp.aws.act_as import act_as_from_extra

    nodes_per_root, regions_per_root = _per_root_counts(credentials_by_id, nodes_by_id)

    facts: dict[str, CredentialFacts] = {}
    for _n, rec in numbered_originating_records(credentials_by_id):
        extra = rec.raw.extra or {}
        act_as = act_as_from_extra(extra) if rec.provider == "aws" else None
        if act_as is not None:


            acts_as = _acts_as_cell(act_as, extra, with_name=False)[0]
        else:
            acts_as = _no_derivation_cell(rec, extra)
        cred_id, cred_id_redaction_type = _tui_credential_id_cell(extra)
        facts[rec.id] = CredentialFacts(
            acts_as=acts_as,
            regions=regions_ratio(rec, regions_per_root),
            description=description_cell(extra),
            nodes=_nodes_cell(rec, nodes_by_id, nodes_per_root),
            cred_id=cred_id,
            cred_id_redaction_type=cred_id_redaction_type,
            declared_region=declared_region(rec),
            declared_index=declared_index(act_as, extra),
            declared_name=declared_name(act_as, extra),
        )
    return facts


def _per_root_counts(
    credentials_by_id: dict[str, CredentialRecord], nodes_by_id: Optional[dict]
) -> tuple[dict[str, int], dict[str, set]]:
    """Node counts and region sets per originating record, in one walk."""


    nodes_per_root: dict[str, int] = {}
    regions_per_root: dict[str, set] = {}
    for node in (nodes_by_id or {}).values():
        root_id = originating_root_id(getattr(node, "credential_id", None), credentials_by_id)
        if root_id is None:
            continue
        nodes_per_root[root_id] = nodes_per_root.get(root_id, 0) + 1
        if getattr(node, "region", None):
            regions_per_root.setdefault(root_id, set()).add(node.region)
    return nodes_per_root, regions_per_root


@dataclass(frozen=True)
class CredentialCells:
    """The per-RECORD cells of a credential table, computed once. `#532`."""

    csp: str
    account: str
    identity: str
    cred_type: str
    cred_id: str
    target_account: str
    acts_as: str
    acts_as_plain: str
    name: str
    region: str
    description: str
    invalid: bool
    account_is_decoded: bool


    account_is_cross_account: bool


def azure_tenant_id_hint(extra: dict[str, Any]) -> str:
    """Return Azure tenant display metadata from a declaration or token claim."""
    declared = str(extra.get("tenant_id") or extra.get("tenant_hint") or "").strip()
    if declared:
        return declared
    token = extra.get("access_token")
    if not isinstance(token, str):
        return ""
    parts = token.split(".")
    if len(parts) < 2 or not parts[1]:
        return ""
    try:
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return ""
    tenant_id = claims.get("tid") if isinstance(claims, dict) else None
    return tenant_id.strip() if isinstance(tenant_id, str) else ""


def credential_cells(rec: CredentialRecord) -> CredentialCells:
    """One record's cells, by the rules this module owns. `#532`."""
    from cloudbasher.csp.aws.act_as import act_as_from_extra

    extra = rec.raw.extra or {}


    act_as = act_as_from_extra(extra) if rec.provider == "aws" else None
    if act_as is not None:
        acts_as = _with_declared_index(_acts_as_cell(act_as, extra)[0], act_as, extra)


        plain = _acts_as_cell(act_as, extra, with_name=False)[0]
    else:
        plain = acts_as = _no_derivation_cell(rec, extra)

    account = _account_cell(extra)
    target_account = _target_account(extra) or _UNKNOWN
    if rec.provider == "azure":


        tenant_id = azure_tenant_id_display(extra)
        account = tenant_id or _UNKNOWN
        target_account = tenant_id or _UNKNOWN
    elif is_gcp_oauth_credential(rec) or (
        rec.provider == "gcp" and bool(getattr(rec, "_resolved_account", None))
    ):


        account = gcp_account_display(rec)
        target_account = account
    return CredentialCells(
        csp=_csp_cell(rec),
        account=account,


        identity=identity_cell(
            rec,
            extra,
            resolved_arn=str(getattr(rec, "_resolved_identity_arn", "") or ""),
            rejected=credential_is_invalid(rec),
            key_shown_elsewhere=True,
        ),
        cred_type=credential_text(
            cred_type_code(rec),
            invalid=credential_is_invalid(rec),
            unbound=is_unbound_credential(rec),
            verified=credential_is_verified(rec),
        ),
        cred_id=_key_cell(extra),
        target_account=target_account,
        acts_as=acts_as,
        acts_as_plain=plain,
        name=declared_name(act_as, extra),


        region=declared_region(rec),
        description=description_cell(extra),


        invalid=rec.status == "invalid",


        account_is_decoded=bool(extra.get("access_key"))
        and not (extra.get("account") or extra.get("account_id")),
        account_is_cross_account=_TARGET_ACCOUNT_MARK in account,
    )


def build_identity_rows(
    credentials_by_id: dict[str, CredentialRecord],
    *,
    nodes_by_id: Optional[dict] = None,
) -> list[tuple[str, str]]:
    """Every loaded originating identity and its declared derivation, as a table."""


    nodes_per_root, regions_per_root = _per_root_counts(credentials_by_id, nodes_by_id)
    cells: list[list[str]] = []
    saw_target_account = False
    saw_invalid = False
    saw_decoded_account = False

    for n, rec in numbered_originating_records(credentials_by_id):


        c = credential_cells(rec)


        saw_target_account = saw_target_account or _TARGET_ACCOUNT_MARK in c.account
        saw_invalid = saw_invalid or c.invalid
        saw_decoded_account = saw_decoded_account or c.account_is_decoded

        cells.append(
            [


                str(n) + (_INVALID_CREDENTIAL_MARK if c.invalid else ""),
                str(rec.source_block) if rec.source_block is not None else _UNKNOWN,
                _nodes_cell(rec, nodes_by_id, nodes_per_root),
                c.csp,
                c.account,
                c.identity,
                c.cred_type,
                c.cred_id,
                c.target_account,
                c.acts_as,
                _regions_cell(rec, regions_per_root),
                c.description,
            ]
        )

    if not cells:
        return []


    rows: list[tuple[str, str]] = [("info", _format_table(_COLUMNS, cells))]
    if saw_invalid:
        rows.append(
            (
                "info",
                f"  {_INVALID_CREDENTIAL_MARK} a heartbeat could not authenticate "
                "this credential, so its nodes were disconnected -- it clears itself "
                "the moment anything reconnects with it successfully, and it is not "
                "carried across a restart",
            )
        )
    if saw_target_account:
        rows.append(
            (
                "info",
                f"  account: own{_TARGET_ACCOUNT_MARK}target -- the value after "
                f"{_TARGET_ACCOUNT_MARK} is the account of the ROLE being assumed, "
                "not the account the credential itself lives in",
            )
        )
    if saw_decoded_account:
        rows.append(
            (
                "debug",
                "  an account shown for a raw access key is DECODED FROM THE KEY ID "
                "(offline, no API call): it names the account that minted the key, "
                "and is not proof the key still works. The PRINCIPAL is not "
                "recoverable the same way -- only sts:GetCallerIdentity resolves "
                "that, an API call this listing deliberately does not make.",
            )
        )
    return rows


def emit_identity_rows(
    rows: list[tuple[str, str]],
    *,
    emit: Any,
    detail: Any,
) -> None:
    """Flush `build_identity_rows()`'s pairs to two sinks, in order."""
    for channel, row in rows:
        (emit if channel == "info" else detail)(row)
