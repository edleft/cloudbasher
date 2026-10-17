"""CloudShell environment DISCOVERY -- the engine behind `.discover` and `cloudshell-sweep.py`."""

from __future__ import annotations

import json
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, NamedTuple, Optional

from cloudbasher.core.browser_options import BrowserOptions


from cloudbasher.core.identity_listing import _SSO_ROLE_PREFIX, sso_permission_set
from cloudbasher.core.session.failure import label_for
from cloudbasher.core.utils.output import eprint, log
from cloudbasher.core.utils.perf_config import pool_width
from cloudbasher.csp.aws.act_as import (
    DIRECT_MODES,
    act_as_mode_of,
    can_derive,
    derives_nothing_because,
)
from cloudbasher.csp.aws.api import AWSCloudShellAPI
from cloudbasher.csp.aws.control_plane import (
    ControlPlaneSource,
    _SigV4Source,
    has_remembered_login_failure,
)
from cloudbasher.csp.aws.credentials import (
    EXPLICIT,
    AwsSessionCreds,
    CredentialError,
    TargetIdentity,
    derive_target_credentials,
    is_sso_extra,
    resolve_identity_name,
    resolve_target_identity,
)
from cloudbasher.csp.aws.failure import explain_failure, refusal_detail
from cloudbasher.csp.aws.provision_request import IndexChoice, asks_derivation
from cloudbasher.csp.aws.provision_request import effective_index as _effective_index_for_record
from cloudbasher.csp.aws.signing import api_detail
from cloudbasher.csp.aws.sts import sts_get_caller_identity


detail_sink: Any = log
warn_sink: Any = eprint


EVENT_SOURCE = "cloudshell.amazonaws.com"


CREATE_EVENTS = {"createEnvironment", "CreateEnvironment"}


TOUCH_EVENTS = {
    "startEnvironment",
    "StartEnvironment",
    "stopEnvironment",
    "StopEnvironment",
    "createSession",
    "CreateSession",
    "putCredentials",
    "PutCredentials",
    "getEnvironmentStatus",
    "GetEnvironmentStatus",
}


DELETE_EVENTS = {"deleteEnvironment", "DeleteEnvironment"}


_EVENTS_KEPT = 12


@dataclass
class Finding:
    """One environment, as reconstructed from CloudTrail."""

    region: str
    principal_arn: str
    environment_id: Optional[str]


    issuer_arn: str = ""
    created_at: Optional[str] = None
    last_event: Optional[str] = None
    last_event_at: Optional[str] = None
    deleted_seen: bool = False
    live_status: Optional[str] = None


    probe_failure_class: Optional[str] = None
    note: str = ""


    found_by: str = "discover"

    cred_num: Optional[int] = None


    observed_at: Optional[str] = None


    events: list[dict] = field(default_factory=list)


@dataclass
class Identity:
    """A principal ARN decomposed into something STS can reconstruct."""

    arn: str


    kind: Optional[str] = None
    ref: Optional[str] = None
    session_name: Optional[str] = None


    issuer_arn: str = ""
    reason: str = ""
    findings: list[Finding] = field(default_factory=list)


    deriver: Optional[Any] = None

    @property
    def account(self) -> str:
        """The account this principal lives in, or `""`."""
        return _account_of(self.arn)

    @property
    def reconstructable(self) -> bool:
        """The ARN decomposes into an STS call. Says nothing about whether we hold a credential that can MAKE that call -- that is `actionable`."""
        return self.kind is not None

    @property
    def why_blocked(self) -> str:
        """Why this identity cannot be acted on, in one sentence."""
        return self.reason or "no named credential can become this principal"

    @property
    def actionable(self) -> bool:
        """Reconstructable AND we hold a credential that can become it."""
        return self.kind is not None and self.deriver is not None

    def target(self) -> TargetIdentity:
        return TargetIdentity(
            kind=self.kind or "",
            ref=self.ref or "",
            session_name=self.session_name,
            name_source=EXPLICIT,
        )


def creds_for(ident: Identity, creds: AwsSessionCreds) -> AwsSessionCreds:
    """Credentials that act AS `ident`."""
    if ident.kind == "self":
        return creds
    return derive_target_credentials(creds, ident.target())


def creds_acting_as(ident: Identity) -> AwsSessionCreds:
    """Credentials that act AS `ident`, via the credential matched to it."""
    if ident.deriver is None:
        raise RuntimeError(f"no credential matched to {ident.arn}")


    return creds_for(ident, ident.deriver.cred.keys)


class _EnvRecord:
    """A stand-in record for the no-`-F` path, where credentials come from the environment and there is no file block to describe them."""

    provider = "aws"
    label = "AWS_* environment"


    id = "env"
    role = "originating"
    parent_id = None
    status = "valid"
    source_block = None


    kind = ""

    class _Raw:


        def __init__(self) -> None:
            self.extra: dict = {}

    def __init__(self) -> None:
        self.raw = self._Raw()


ENUMERATE = "enumerate"
READ_CLOUDTRAIL = "read_cloudtrail"
SIGN_STS = "sign_sts"


_CLOUDTRAIL_IS_OUR_PLUMBING = (
    "this tool's CloudTrail pass signs with keys. That is our plumbing, not an "
    "AWS limit: presign signs whatever the descriptor names, and the "
    "routing through it is simply unbuilt"
)


_STRUCTURAL_REASON = {
    ENUMERATE: (
        "no CloudShell control-plane gateway -- it was never opened for this "
        "credential, or opening it failed"
    ),
    READ_CLOUDTRAIL: f"no signing keys, and {_CLOUDTRAIL_IS_OUR_PLUMBING}",
    SIGN_STS: "no signing keys, so STS cannot be called as this credential",
}


CAPABILITIES = tuple(_STRUCTURAL_REASON)


@dataclass
class Cred:
    """One addressable credential from the `-F` file, and what it can do."""

    num: int
    record: Any
    label: str


    source: Any = None


    keys: Optional[AwsSessionCreds] = None


    reasons: dict = field(default_factory=dict)


    own_arn: str = ""


    derived_arn: str = ""
    account: str = ""

    @property
    def principal_key(self) -> str:
        """How this credential is ADDRESSED as a principal. One writer"""
        return self.acts_as_arn or self.label

    @property
    def acts_as_arn(self) -> str:
        """The principal this credential acts as, by the best evidence held."""
        return self._acts_as()[1]

    @property
    def acts_as_tier(self) -> str:
        """WHICH of ``acts_as_arn``'s three sources answered."""
        return self._acts_as()[0]

    def _acts_as(self) -> "tuple[str, str]":
        """`(tier, arn)` from the best evidence held. THE one ladder."""
        if self.derived_arn:
            return "derived", self.derived_arn
        if self.own_arn:
            return "measured", self.own_arn
        extra = self.declared_extra()
        account = declared_account(self).strip()
        user = str(extra.get("username") or "").strip()
        if account and user and extra.get("password"):
            return "declared", f"arn:aws:iam::{account}:user/{user}"
        return "", ""

    def deny(self, capability: str, reason: str) -> None:
        """Record WHY `capability` is unavailable"""
        assert capability in CAPABILITIES, f"not a capability: {capability!r}"
        self.reasons[capability] = reason

    def deny_all(self, reason: str) -> None:
        """One reason that genuinely kills every capability -- an expired key, a `GetCallerIdentity` that refused, a source that would not open."""
        for capability in CAPABILITIES:
            self.deny(capability, reason)

    def why_not(self, capability: str) -> str:
        """The reason `capability` is unavailable, or `""` if it IS available."""
        assert capability in CAPABILITIES, f"not a capability: {capability!r}"
        if self.can(capability):
            return ""
        return self.reasons.get(capability) or _STRUCTURAL_REASON[capability]

    def failed(self, capability: str) -> bool:
        """Was a reason RECORDED for `capability` -- did something try and refuse?"""
        assert capability in CAPABILITIES, f"not a capability: {capability!r}"
        return bool(self.reasons.get(capability))

    def can(self, capability: str) -> bool:
        """The predicate, by name -- for the callers that hold a capability in a variable. The three properties below are what ordinary code reads."""
        assert capability in CAPABILITIES, f"not a capability: {capability!r}"


        return bool(getattr(self, f"can_{capability}"))

    @property
    def can_enumerate(self) -> bool:
        """Can reach the CloudShell control plane -- describe, create, delete."""


        return self.source is not None and self.source.enumerates

    @property
    def _has_key_material(self) -> bool:
        """`keys` holds something that can actually sign"""
        return self.keys is not None and bool(self.keys.access_key)

    @property
    def can_read_cloudtrail(self) -> bool:
        """Only a locally-signing credential can -- FOR NOW, and the stated reason was wrong."""
        return self._has_key_material

    @property
    def can_sign_sts(self) -> bool:
        """Can call STS as this credential -- `AssumeRole` or, with the extra condition below, `GetFederationToken`."""
        return self._has_key_material

    @property
    def long_term(self) -> bool:
        """A permanent AKIA. `GetFederationToken` refuses anything else."""
        return self.keys is not None and self.keys.is_akia()

    def declared(self, key: str) -> str:
        return str(self.record.raw.extra.get(key) or "")

    def declared_extra(self) -> dict:
        """The flattened `extra` itself, for the shared readers that take one -- `act_as_mode_of()` above all. Named rather than reached through, so this is the one place that knows where a record keeps its declarations."""
        return self.record.raw.extra or {}


class LedgerCells(NamedTuple):
    """One credential's cells, derived once for every surface that draws it."""

    num: str
    csp: str
    account: str
    cred_id: str
    identity: str
    target_account: str
    declared_target: str
    acts_as_measured: str
    tier: str
    used_by: str
    name: str
    region: str
    cross_account: bool


def credential_ledger_rows(
    creds: "Iterable[Cred]", *, used_by: "Mapping[int, str]"
) -> "list[LedgerCells]":
    """THE credential row builder."""
    from cloudbasher.core.identity_listing import credential_cells

    out: "list[LedgerCells]" = []
    for c in creds:
        cells = credential_cells(c.record)
        tier, measured = c._acts_as()
        out.append(
            LedgerCells(
                num=str(c.num),
                csp=cells.csp,
                account=cells.account,
                cred_id=cells.cred_id,
                identity=cells.identity,
                target_account=cells.target_account,
                declared_target=cells.acts_as_plain,
                acts_as_measured=measured,
                tier=tier,
                used_by=used_by.get(c.num, ""),
                name=cells.name,
                region=cells.region,
                cross_account=cells.account_is_cross_account,
            )
        )
    return out


USE_DISCOVER = "D"
USE_INVALID = "X"


def glyph_cell(legend: "Iterable[tuple[str, str]]", state: "Mapping[str, bool]") -> str:
    """The glyphs from `legend` whose state is true, concatenated IN LEGEND ORDER."""
    return "".join(glyph for glyph, _why in legend if state[glyph])


def glyph_key_line(legend: "Iterable[tuple[str, str]]") -> str:
    """`Key: D=... | A=... | X=...` -- a legend as its own printed key."""
    return "Key: " + " | ".join(f"{glyph}={text}" for glyph, text in legend)


class Deriver(NamedTuple):
    """Which credential will act as a discovered identity, and how sure we are."""

    cred: "Cred"


    rule: str = ""


    equals: tuple = ()

    why: str = ""


def kind_of_arn(arn: str) -> str:
    """The `userIdentity.type` an ARN corresponds to. Pure string shape."""
    if ":user/" in arn:
        return "IAMUser"
    if ":assumed-role/" in arn:
        return "AssumedRole"
    if ":federated-user/" in arn:
        return "FederatedUser"
    return ""


def declared_kind(c: "Cred") -> str:
    """What this credential's FILE BLOCK says it is or becomes."""
    extra = c.declared_extra()
    mode = act_as_mode_of(extra)
    if mode == "federated":
        return "FederatedUser"
    if mode == "role":
        return "AssumedRole"
    if mode in DIRECT_MODES:
        return kind_of_arn(c.own_arn)
    if is_sso_extra(extra):
        return "AssumedRole"
    if extra.get("username") and extra.get("password"):
        return "IAMUser"
    return ""


def _rank(c: "Cred", kind: str) -> tuple:
    """Preference among credentials that are ALL correct. Not a correctness test."""
    return (
        0 if declared_kind(c) == kind else 1,
        0 if c._has_key_material else 1,
        0 if c.long_term else 1,
        c.num,
    )


def _tie_why(ordered: "list[Cred]", kind: str) -> str:
    """One line saying why the winner won. ALWAYS returned, never suppressed."""
    won = ordered[0]
    if len(ordered) == 1:
        return f"#{won.num} is the only credential that can become this principal"
    runner = ordered[1]
    equal = " ".join(f"#{c.num}" for c in ordered)
    reasons = (
        f"declares {kind}, which is what this principal is",
        f"API key; #{runner.num} needs a browser sign-in",
        f"long-term key; #{runner.num} is an expiring token",
        "ARBITRARY -- lowest number, they are interchangeable",
    )
    won_rank, runner_rank = _rank(won, kind), _rank(runner, kind)
    for term, why in enumerate(reasons):
        if won_rank[term] != runner_rank[term]:
            if term == 0:
                kinds = " ".join(f"#{c.num}={declared_kind(c) or '?'}" for c in ordered)
                return f"tie: {kinds} -> #{won.num}: {why}"
            return f"tie: {equal} are one principal -> #{won.num}: {why}"


    raise AssertionError(f"two credentials ranked identically: {equal}")


def _won(hits: "list[Cred]", kind: str, rule: str) -> "Deriver":
    """Rank, choose, and record the reason -- in one place, for every rule."""
    ordered = sorted(hits, key=lambda c: _rank(c, kind))
    return Deriver(cred=ordered[0], rule=rule, equals=tuple(ordered), why=_tie_why(ordered, kind))


def sso_key_of_cred(c: "Cred") -> "Optional[tuple[str, str, str]]":
    """`(account, permission_set, username)` for an Identity Center block."""
    extra = c.declared_extra()
    if not is_sso_extra(extra):
        return None
    permset = str(extra.get("role_name") or "").strip()
    user = str(extra.get("sso_username") or extra.get("username") or "").strip()
    account = declared_account(c).strip()
    if not permset or not user or not account:
        return None
    return (account, permset, user)


def sso_key_of_identity(ident: "Identity") -> "Optional[tuple[str, str, str]]":
    """The same key, read off a DISCOVERED `assumed-role` principal."""
    if ":assumed-role/" not in ident.arn:
        return None
    role_name = ident.arn.split(":assumed-role/", 1)[1].split("/")[0]


    if "_" not in role_name[len(_SSO_ROLE_PREFIX) :]:
        return None
    permset = sso_permission_set(role_name)
    account = ident.account
    if not permset or not account or not ident.session_name:
        return None
    return (account, permset, ident.session_name)


_RULES: "tuple[tuple[str, str, str], ...]" = (
    ("by_arn", "", "1-identity"),
    ("by_sso", "AssumedRole", "1-identity/sso"),
    ("by_role", "AssumedRole", "2-assume"),
    ("by_issuer", "FederatedUser", "3-federate"),
)


_LABEL = {attr: label for attr, _kind, label in _RULES}


@dataclass
class PrincipalIndex:
    """WHICH CREDENTIAL BECOMES WHICH PRINCIPAL, DECIDED ONCE"""


    by_arn: "dict[str, Deriver]" = field(default_factory=dict)

    by_sso: "dict[tuple[str, str, str], Deriver]" = field(default_factory=dict)

    by_role: "dict[str, Deriver]" = field(default_factory=dict)

    by_issuer: "dict[str, Deriver]" = field(default_factory=dict)

    def report(
        self, account: str = "", rules: "tuple[str, ...]" = (), kind: str = ""
    ) -> "list[str]":
        """Every resolution, one line each. NEVER FILTERED BY IMPORTANCE."""
        rows: list[str] = []
        for attr, _kind, _label in _RULES:


            if rules and _label not in rules:
                continue
            bucket = getattr(self, attr)
            for key in sorted(bucket, key=str):
                if account and _account_of_key(key) != account:
                    continue


                if kind and (_kind or kind_of_arn(key)) != kind:
                    continue
                d = bucket[key]
                shown = key if isinstance(key, str) else "/".join(key)
                rows.append(f"  {d.rule:<15} {shown}  ->  {cred_tag(d.cred)}  {d.why}")
        return rows


def explain_unmatched(ident: "Identity", index: PrincipalIndex) -> "list[str]":
    """WHY THIS PRINCIPAL MATCHED NOTHING, as lines. CONTENT, not layout."""


    tried = attempt_derivation(ident, index).tried
    if not tried:


        return ["this ARN names no principal shape we resolve, so no rule applies."]


    prefix = f"rules attempted: {', '.join(tried)}."
    if not ident.account:
        return [
            f"{prefix} This principal's ARN carries no account, so the pool "
            f"cannot be scoped against it."
        ]
    near = index.report(account=ident.account, rules=tried, kind=kind_of_arn(ident.arn))
    if not near:
        return [
            f"{prefix} Under those rules the pool resolves to nothing in "
            f"account {ident.account} -- a credential that is missing, not one "
            f"that is scoped wrong."
        ]
    return [f"{prefix} In account {ident.account} the pool holds:"] + near


def resolution_heading() -> str:
    """The sentence introducing a `PrincipalIndex.report()`. CONTENT ONLY."""
    return "Principal resolution -- which credential becomes which principal:"


def resolve_principals(creds: "Iterable[Cred]") -> PrincipalIndex:
    """Build the index. ONE PASS over the credentials, at parse."""
    index = PrincipalIndex()
    pool = [c for c in creds if c.can_sign_sts and c.account]
    buckets: "dict[str, dict[Any, list[Cred]]]" = {attr: {} for attr, _, _ in _RULES}

    def put(bucket: str, key: Any, c: "Cred") -> None:
        """Index `c` under `key`, SAME ACCOUNT ONLY."""
        want = _account_of_key(key)
        if want and c.account != want:
            return
        buckets[bucket].setdefault(key, []).append(c)

    for c in pool:
        if c.acts_as_arn:
            put("by_arn", c.acts_as_arn, c)
        sso = sso_key_of_cred(c)
        if sso:
            put("by_sso", sso, c)
        role_arn = c.declared("role_arn")
        if role_arn:
            put("by_role", role_arn, c)


        if c.own_arn and c.long_term:
            put("by_issuer", c.own_arn, c)

    for attr, kind, label in _RULES:
        target = getattr(index, attr)
        for key, hits in buckets[attr].items():
            target[key] = _won(hits, kind or kind_of_arn(key), label)
    return index


def lookup_deriver(ident: Identity, index: PrincipalIndex) -> Optional[Deriver]:
    """The credential that can act AS `ident`, or None. FIVE RULES, IN ORDER."""
    return attempt_derivation(ident, index).deriver


class Attempt(NamedTuple):
    """What a derivation lookup DID: the winner, and the rules it ran."""

    deriver: "Optional[Deriver]"
    tried: "tuple[str, ...]"


def attempt_derivation(ident: Identity, index: PrincipalIndex) -> Attempt:
    """`lookup_deriver`, REPORTING WHICH RULES IT RAN. The one implementation."""
    tried: "list[str]" = []

    def probe(attr: str, key: "Any") -> "Optional[Deriver]":
        """Read one map under one key, RECORDING that the rule ran."""
        if not key:
            return None
        label = _LABEL[attr]
        if label not in tried:
            tried.append(label)
        bucket: "dict[Any, Deriver]" = getattr(index, attr)
        return bucket.get(key)


    kind = kind_of_arn(ident.arn)
    if not kind:
        return Attempt(None, ())


    found = probe("by_arn", ident.arn)
    if found:
        return Attempt(found, tuple(tried))
    found = probe("by_sso", sso_key_of_identity(ident))
    if found:
        return Attempt(found, tuple(tried))


    if kind == "AssumedRole":
        for wanted in (ident.issuer_arn, ident.ref or ""):
            found = probe("by_role", wanted)
            if found:
                return Attempt(found, tuple(tried))
        return Attempt(None, tuple(tried))


    if kind == "FederatedUser":
        return Attempt(probe("by_issuer", ident.issuer_arn), tuple(tried))


    return Attempt(None, tuple(tried))


def deriver_for(ident: Identity, creds: list[Cred]) -> Optional[Deriver]:
    """`lookup_deriver` for a caller that has no index. ONE credential list, one identity."""
    return lookup_deriver(ident, resolve_principals(creds))


def _account_of(arn: str) -> str:
    """The account id out of an ARN, or "" when it has no recognisable one."""
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4].isdigit() else ""


def _account_of_key(key: "Any") -> str:
    """The ACCOUNT an index key belongs to, whatever shape the key is."""
    return key[0] if isinstance(key, tuple) else _account_of(key)


def _now() -> str:
    """UTC, second precision, the shape CloudTrail uses -- so one TIMESTAMP column can hold an event time and an observation time without the reader having to know which."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def short_principal(arn: str) -> str:
    """``user/example-user`` from a full ARN -- the part that identifies WHO. NOT THE IN-TOOL DISPLAY FORM: ``core/identity_listing.arn_tail()`` is, and the two deliberately disagree on one case. ``arn_tail`` folds an SSO ``assumed-role`` ARN to ``role/<PermissionSet>``, which is what every TUI surface shows; this keeps the ARN whole, because a sweep's reader is matching rows against CloudTrail and wants it as recorded."""
    for marker in (":federated-user/", ":assumed-role/", ":user/"):
        if marker in arn:
            return marker[1:] + arn.split(marker, 1)[1]
    return arn


def cred_tag(cred: "Cred") -> str:
    """THE RENDERER OF `[cred#N]` FROM A `Cred`"""
    return f"[cred#{cred.num}]"


def cred_label(cred: "Cred") -> str:
    """THE RENDERER OF `[cred#N] <label>` -- the tag and the credential's own name, the prefix nearly every per-credential message opens with"""
    return f"{cred_tag(cred)} {cred.label}"


def acting_as_label(cred: "Cred") -> str:
    """What a DIRECT-route target is acted as, for the same column `identity_label` fills for a matched one"""
    return f"{cred_tag(cred)} {short_principal(cred.principal_key)}"


def identity_label(ident: "Identity") -> str:
    """What an identity is ACTED AS, for a human reading a plan."""
    if ident.kind == "self":
        return short_principal(ident.arn) or "self"
    base = f"{ident.kind}:{ident.ref}"
    return base + (f"/{ident.session_name}" if ident.session_name else "")


def parse_principal(arn: str, own_arn: "str | set[str]" = "", issuer_arn: str = "") -> Identity:
    """Decompose an STS/IAM ARN into the STS call that reproduces it."""
    if ":federated-user/" in arn:
        return Identity(
            arn=arn,
            kind="federation_token",
            ref=arn.split("/", 1)[1],
            issuer_arn=issuer_arn,
        )
    if ":assumed-role/" in arn:
        tail = arn.split(":assumed-role/", 1)[1]
        parts = tail.split("/")
        if len(parts) >= 2:
            role_name, session = parts[0], "/".join(parts[1:])


            account = _account_of(arn)
            return Identity(
                arn=arn,
                kind="assume_role",
                ref=f"arn:aws:iam::{account}:role/{role_name}",
                session_name=session,
                issuer_arn=issuer_arn,
            )
        return Identity(arn=arn, reason="assumed-role ARN missing a session name")
    if ":user/" in arn:


        mine = {own_arn} if isinstance(own_arn, str) else set(own_arn)
        if arn in mine and arn:
            return Identity(arn=arn, kind="self")
        return Identity(arn=arn, reason="IAM user (not derivable; use that user's own key)")
    if ":root" in arn:
        return Identity(arn=arn, reason="account root (cannot be assumed)")
    return Identity(arn=arn, reason="unrecognised principal shape")


def boto_kwargs(creds: AwsSessionCreds) -> dict[str, Any]:
    kw = {
        "aws_access_key_id": creds.access_key,
        "aws_secret_access_key": creds.secret_key,
    }
    if creds.session_token:
        kw["aws_session_token"] = creds.session_token
    return kw


_ID_KEYS_SEEN: Counter = Counter()


def id_keys_seen_line() -> "Optional[str]":
    """Which id key CloudTrail used, as one renderable clause, or None"""
    seen = id_keys_seen()
    if not seen:
        return None
    return ", ".join(f"{k}={n}" for k, n in sorted(seen.items()))


def events_summary(findings: "list[Finding]") -> "tuple[int, int, Optional[str], Optional[str]]":
    """`(events, findings_with_events, first_seen, last_seen)`"""
    total = 0
    with_events = 0
    first: "Optional[str]" = None
    last: "Optional[str]" = None
    for f in findings:
        if not f.events:
            continue
        with_events += 1
        total += len(f.events)
        for when in (f.created_at, f.last_event_at):
            if not when:
                continue
            if first is None or when < first:
                first = when
            if last is None or when > last:
                last = when
    return total, with_events, first, last


def reset_id_keys_seen() -> None:
    """Start a fresh census"""
    _ID_KEYS_SEEN.clear()


def id_keys_seen() -> "dict[str, int]":
    """The census, as plain data"""
    return dict(_ID_KEYS_SEEN)


_GONE_IDS_LISTED = 8

_ENV_ID_KEYS = ("EnvironmentId", "environmentId")


_ENV_ID_SECTIONS = ("responseElements", "requestParameters")


def _ci_get(mapping: Any, *names: str, record: bool = False, section: str = "") -> Optional[Any]:
    """First present key of `names`. AWS casing is not knowable in advance."""
    if not isinstance(mapping, dict):
        return None
    for name in names:
        value = mapping.get(name)
        if value:
            if record:
                _ID_KEYS_SEEN[f"{section}.{name}" if section else name] += 1
            return value
    return None


def extract_environment_id(detail: dict) -> Optional[str]:
    """The environment id from one CloudTrail event, whatever it is called."""
    for section in _ENV_ID_SECTIONS:
        found = _ci_get(detail.get(section), *_ENV_ID_KEYS, record=True, section=section)
        if found:
            return str(found)
    return None


def keep_event(f: Finding, detail: dict, name: str) -> None:
    """Retain one raw CloudTrail record against its environment, bounded."""
    if len(f.events) < _EVENTS_KEPT:
        f.events.append(detail)
        return
    pivotal = name in CREATE_EVENTS or name in DELETE_EVENTS
    if pivotal and not any(e.get("eventName") == name for e in f.events):
        f.events.append(detail)


def _noop(*_a: Any, **_k: Any) -> None:
    return None


def sweep_region(
    region: str,
    creds: AwsSessionCreds,
    days: int,
    *,
    on_page: Any = _noop,
) -> list[Finding]:
    """CloudTrail LookupEvents for CloudShell activity in one region."""
    import boto3
    from botocore.config import Config


    ct = boto3.client(
        "cloudtrail",
        region_name=region,
        config=Config(retries={"mode": "adaptive", "max_attempts": 10}),
        **boto_kwargs(creds),
    )
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)


    by_env: dict[str, Finding] = {}
    principals_seen: set[str] = set()

    issuer_by_principal: dict[str, str] = {}


    api_detail(creds, f"API request: GET cloudtrail.{region} Action=LookupEvents days={days}")
    paginator = ct.get_paginator("lookup_events")
    pages = 0
    events = 0
    window = max((end - start).total_seconds(), 1.0)
    oldest: Optional[datetime] = None
    for page in paginator.paginate(
        LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": EVENT_SOURCE}],
        StartTime=start,
        EndTime=end,
    ):
        pages += 1
        evs = page.get("Events", [])
        events += len(evs)


        if evs:
            got = evs[-1].get("EventTime")
            if isinstance(got, datetime):
                oldest = got
        covered = 1.0 if oldest is None else min(1.0, (end - oldest).total_seconds() / window)
        on_page(region, pages, events, covered, oldest)
        for ev in evs:
            try:
                ev_detail = json.loads(ev.get("CloudTrailEvent", "{}"))
            except (ValueError, TypeError):
                continue
            name = ev_detail.get("eventName", "")
            ui = ev_detail.get("userIdentity") or {}
            arn = ui.get("arn") or "(unknown principal)"


            issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn") or ""
            principals_seen.add(arn)
            issuer_by_principal.setdefault(arn, issuer)
            when = ev_detail.get("eventTime")
            env_id = extract_environment_id(ev_detail)
            if not env_id:
                continue
            f = by_env.get(env_id)
            if f is None:
                f = Finding(
                    region=region,
                    principal_arn=arn,
                    issuer_arn=issuer,
                    environment_id=env_id,
                )
                by_env[env_id] = f
            keep_event(f, ev_detail, name)
            if name in CREATE_EVENTS:
                f.created_at = when
                f.principal_arn = arn
                f.issuer_arn = issuer
            if name in DELETE_EVENTS:
                f.deleted_seen = True

            if f.last_event is None:
                f.last_event, f.last_event_at = name, when

    findings = list(by_env.values())


    with_findings = {f.principal_arn for f in findings}
    for arn in principals_seen:
        if arn not in with_findings:
            findings.append(
                Finding(
                    region=region,
                    principal_arn=arn,
                    issuer_arn=issuer_by_principal.get(arn, ""),
                    environment_id=None,
                    note="activity seen, no env id in window -- use --validate",
                )
            )
    return findings


def probe_identity(ident: Identity, region: str) -> dict[str, str]:
    """Re-derive `ident` and ask CloudShell what it owns in `region` right now."""
    derived = creds_acting_as(ident)
    api = AWSCloudShellAPI(region=region, credentials=derived)
    resp = api.describe_environments()
    out: dict[str, str] = {}
    for env in _ci_get(resp, "environments", "Environments") or []:


        eid = _ci_get(env, *_ENV_ID_KEYS, record=True, section="describeEnvironments")
        if not eid:
            continue
        try:
            out[str(eid)] = str(api.get_environment_status(str(eid)).get("status") or "Unknown")
        except Exception as e:  # noqa: BLE001 - one bad env must not lose the rest
            out[str(eid)] = f"status-error:{type(e).__name__}"
    return out


class Target(NamedTuple):
    """One environment queued for deletion, and how it will be reached."""

    region: str
    env_id: str
    acting_as: str
    ident: Optional[Identity] = None
    cred: Optional["Cred"] = None


def dedupe_targets(targets: list["Target"]) -> list["Target"]:
    """One delete per (region, environment id), first route wins."""
    seen: set[tuple[str, str]] = set()
    unique: list["Target"] = []
    for t in targets:
        if (t.region, t.env_id) in seen:
            continue
        seen.add((t.region, t.env_id))
        unique.append(t)
    return unique


def delete_target(t: Target) -> None:
    """Delete one environment by whichever route found it."""
    if t.cred is not None:
        t.cred.source.client_for(t.region).delete_environment(t.env_id)
        return
    assert t.ident is not None
    delete_environment(t.ident, t.region, t.env_id)


def delete_environment(ident: Identity, region: str, env_id: str) -> None:
    derived = creds_acting_as(ident)
    api = AWSCloudShellAPI(region=region, credentials=derived)
    api.delete_environment(env_id)


def group_by_identity(
    findings: list[Finding], own_arn: "str | set[str]" = ""
) -> dict[tuple[str, str], Identity]:
    """Key on (region, principal) -- an identity's environments are per-region."""
    groups: dict[tuple[str, str], Identity] = {}
    for f in findings:
        key = (f.region, f.principal_arn)
        ident = groups.get(key)
        if ident is None:
            ident = parse_principal(f.principal_arn, own_arn, f.issuer_arn)
            groups[key] = ident
        elif not ident.issuer_arn and f.issuer_arn:


            ident.issuer_arn = f.issuer_arn
        ident.findings.append(f)
    return groups


def unvalidated_reason(f: "Finding") -> str:
    """WHY `--validate` could not answer for `f`, as a human label -- or `""` when it was never asked, or answered."""
    return label_for(f.probe_failure_class) if f.probe_failure_class else ""


def live_findings(findings: list[Finding], *, probed: bool) -> list[Finding]:
    """The environments that still EXIST. One definition, because it was three."""
    return [
        f
        for f in findings
        if f.environment_id
        and not f.deleted_seen
        and (not probed or f.live_status not in ("gone",))
    ]


def _days_back(oldest: "Optional[datetime]") -> int:
    """Whole days between `oldest` and now, floored at 0."""
    if oldest is None:
        return 0
    return max(0, int((datetime.now(timezone.utc) - oldest).total_seconds() // 86400))


def scan_progress_line(snapshot: "list[tuple[int, Optional[datetime]]]", *, days: int) -> str:
    """The mid-scan line, describing THE SCAN rather than one worker"""
    events = sum(n for n, _ in snapshot)
    dated = [d for _, d in snapshot if d is not None]
    scans = f"{len(snapshot)} region scan(s)"
    if not dated:
        return f"CloudTrail: {events:,} event(s) read across {scans}"
    watermark = max(dated)
    return (
        f"CloudTrail: {events:,} event(s) read across {scans}, "
        f"all read back to {watermark:%Y-%m-%d} ({_days_back(watermark)} of {days} days)"
    )


def region_done_line(
    region: str,
    fresh: "list[Finding]",
    events: int,
    oldest: "Optional[datetime]",
    *,
    days: int,
) -> str:
    """The per-region line, with a unit on every number"""
    envs = len([f for f in fresh if f.environment_id])


    found = (
        f"{len(fresh)} new finding(s): {envs} environment(s) + {len(fresh) - envs} "
        f"principal(s) with activity but no environment id"
        if fresh
        else "nothing new"
    )
    if oldest is None:
        return f"{region}: no CloudShell activity in the last {days} days; {found}"


    back = _days_back(oldest)
    if back >= days:
        shown, why = days, f"reached the {days}-day window edge"
    else:
        shown, why = back, "no CloudShell activity older than that"
    return (
        f"{region}: {events:,} event(s) read back to {oldest:%Y-%m-%d} "
        f"({shown} of {days} days) -- {why}; {found}"
    )


def discover_all(
    sweepers: "dict[str, Cred]",
    regions: "list[str]",
    findings: "list[Finding]",
    errors: "list[str]",
    seen_direct: set,
    *,
    days: int,
    workers: Optional[int] = None,
    on_tick: Any = _noop,
    on_progress: Any = _noop,
) -> "list[Finding]":
    """PASS `discover`. CloudTrail, once per account, dropping anything `enumerate` already returned -- that is the same environment, and counting it twice makes a cleanup tool report more remnants than exist."""
    from concurrent.futures import ThreadPoolExecutor, as_completed


    reset_id_keys_seen()

    work = [(acct, c, r) for acct, c in sweepers.items() for r in regions]
    mine: list[Finding] = []


    total = len(work)
    done = 0


    live: "dict[tuple, tuple[int, Optional[datetime]]]" = {}
    live_lock = threading.Lock()

    def _page(key: tuple, events: int, oldest: "Optional[datetime]") -> None:
        """Progress DURING a region's scan"""
        with live_lock:
            live[key] = (events, oldest)
            snapshot = list(live.values())
        on_progress(scan_progress_line(snapshot, days=days), done, total)

    def _page_for(key: tuple) -> Any:
        """`_page` bound to ONE work item, dropping what it does not report."""
        return lambda region, pages, events, covered=1.0, oldest=None: _page(key, events, oldest)

    with ThreadPoolExecutor(max_workers=pool_width(len(work), workers)) as pool:
        futs = {
            pool.submit(sweep_region, r, c.keys, days, on_page=_page_for((acct, r))): (acct, r)
            for acct, c, r in work
        }
        for fut in as_completed(futs):
            acct, region = futs[fut]


            done += 1
            try:
                got = fut.result()
                fresh = [
                    f
                    for f in got
                    if not (f.environment_id and (f.region, f.environment_id) in seen_direct)
                ]
                findings.extend(fresh)
                mine.extend(fresh)
                with live_lock:
                    read, oldest = live.get((acct, region), (0, None))
                on_tick(region_done_line(region, fresh, read, oldest, days=days), done, total)
            except Exception as e:  # noqa: BLE001 - one bad region must not kill the sweep


                _, label, _ = explain_failure(e)


                note = failure_note(e, label, what="FAILED")
                errors.append(f"{acct}/{region}: {note}")
                on_tick(f"{region} {note}", done, total)
    return mine


def match_identities(
    findings: "list[Finding]",
    creds: "list[Cred]",
    own_arns: "set[str]",
    index: "Optional[PrincipalIndex]" = None,
) -> "dict[tuple[str, str], Identity]":
    """Group discovered findings by principal, then match each principal to the credential that can BECOME it."""


    groups = match = group_by_identity(
        [f for f in findings if f.found_by in _MATCHED_ROUTE], own_arns
    )


    index = index if index is not None else resolve_principals(creds)
    for ident in match.values():
        if ident.reconstructable:
            ident.deriver = lookup_deriver(ident, index)
            if ident.deriver is None:
                ident.reason = (
                    "no credential in this source can become this principal "
                    f"(account {ident.account or 'unknown'})"
                )
    return groups


_PROBE_RETRY_CLASS = "dns_unresolvable"
_PROBE_ATTEMPTS = 2


def probe_identity_with_dns_retry(ident: Identity, region: str) -> dict[str, str]:
    """`probe_identity`, re-asked once when the RESOLVER was what failed."""
    for attempt in range(1, _PROBE_ATTEMPTS + 1):
        try:
            return probe_identity(ident, region)
        except Exception as e:  # noqa: BLE001 - re-raised below; class decides
            cls, _, _ = explain_failure(e)
            e.cb_failure_class = cls  # type: ignore[attr-defined]
            e.cb_probe_attempts = attempt  # type: ignore[attr-defined]
            if attempt >= _PROBE_ATTEMPTS or cls != _PROBE_RETRY_CLASS:
                raise
    raise AssertionError("unreachable: the loop returns or raises")  # pragma: no cover


def failure_note(exc: BaseException, label: str, *, what: str = "probe failed") -> str:
    """The NOTE cell for a pass that could not answer."""
    attempts = getattr(exc, "cb_probe_attempts", None)
    if attempts is None:
        return f"{what} [{label}]: {type(exc).__name__}: {exc}"
    asked = "asked once" if attempts == 1 else f"asked {attempts}x"
    return f"{what} [{label}], {asked}: {type(exc).__name__}: {exc}"


def probe_all(
    worklist: "list[tuple[str, str, Identity]]",
    findings: "list[Finding]",
    seen_direct: set,
    *,
    workers: Optional[int] = None,
    on_tick: Any = _noop,
) -> int:
    """PASS `probe`. Re-derive each discovered identity and ask CloudShell what it owns RIGHT NOW. Returns the error count."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    errors = 0
    with ThreadPoolExecutor(max_workers=pool_width(len(worklist), workers)) as pool:
        futs = {
            pool.submit(probe_identity_with_dns_retry, ident, region): (region, arn, ident)
            for region, arn, ident in worklist
        }
        for fut in as_completed(futs):
            region, arn, ident = futs[fut]
            try:
                live = fut.result()
            except Exception as e:  # noqa: BLE001
                errors += 1


                cls, label, _ = explain_failure(e)
                note = failure_note(e, label)
                for f in ident.findings:
                    f.note = note
                    f.probe_failure_class = cls
                on_tick(f"{region} FAILED ({label})")
                continue
            known = {f.environment_id for f in ident.findings}
            for f in ident.findings:
                if f.environment_id:
                    f.live_status = live.get(f.environment_id, "gone")
                    f.observed_at = _now()


            gone = [
                f.environment_id
                for f in ident.findings
                if f.live_status == "gone" and f.environment_id
            ]
            if gone:
                shown = ", ".join(gone[:_GONE_IDS_LISTED])
                more = len(gone) - _GONE_IDS_LISTED
                detail_sink(
                    f"[validate] {region} {len(gone)} gone for "
                    f"{identity_label(ident)} ({arn}) -- AWS did not list "
                    f"{shown}{f' +{more} more' if more > 0 else ''}. "
                    f"A verdict about THIS principal; may be live for another."
                )

            for eid, status in live.items():


                if eid not in known and (region, eid) not in seen_direct:
                    extra = Finding(
                        region=region,
                        principal_arn=arn,
                        environment_id=eid,
                        live_status=status,
                        observed_at=_now(),
                        note="found by validate only (older than the CloudTrail window)",
                    )
                    findings.append(extra)
                    ident.findings.append(extra)
            on_tick(f"{region} ({len(live)} env)")
    return errors


_DIRECT_ROUTE = ("enumerate",)


_MATCHED_ROUTE = ("discover", "unregistered")


def delete_router(creds: "Iterable[Cred]") -> "dict[tuple[int, str], Cred]":
    """Route a finding to the credential that can BECOME the principal that owns it."""
    creds = list(creds)
    per_num = Counter(c.num for c in creds)
    router: dict[tuple[int, str], Cred] = {}
    for c in creds:
        if c.principal_key:
            router[(c.num, c.principal_key)] = c
        if per_num[c.num] == 1:
            router[(c.num, "")] = c
    return router


def route_finding(router: "dict[tuple[int, str], Cred]", f: "Finding") -> "Optional[Cred]":
    """The credential that owns `f`, or None. The ONE reader of `delete_router`."""
    num = f.cred_num or -1
    return router.get((num, f.principal_arn)) or router.get((num, ""))


def build_delete_targets(
    findings: "list[Finding]",
    groups: "dict[tuple[str, str], Identity]",
    by_principal: "dict[tuple[int, str], Cred]",
) -> "tuple[list[Target], int]":
    """Everything deletable, and how many duplicates were suppressed."""
    targets: list[Target] = []
    for f in findings:
        if f.found_by not in _DIRECT_ROUTE or not f.environment_id:
            continue
        if f.deleted_seen or f.live_status in ("gone",):
            continue


        c = route_finding(by_principal, f)
        if c is None:
            continue
        targets.append(
            Target(
                region=f.region,
                env_id=f.environment_id,


                acting_as=acting_as_label(c),
                cred=c,
            )
        )
    for (region, _arn), ident in sorted(groups.items()):
        if not ident.reconstructable:
            continue


        if not ident.actionable:
            continue
        if ident.kind == "federation_token" and not ident.deriver.cred.long_term:
            continue
        acting = identity_label(ident)
        for f in ident.findings:
            if f.environment_id and not f.deleted_seen and f.live_status not in ("gone",):
                targets.append(
                    Target(region=region, env_id=f.environment_id, acting_as=acting, ident=ident)
                )
    unique = dedupe_targets(targets)
    return unique, len(targets) - len(unique)


def delete_receipt(t: "Target", outcome: str, why: str) -> "tuple[list[str], bool]":
    """One delete, rendered. Returns `(lines, to_stderr)`"""
    if outcome == "deleted":
        return [f"  deleted {t.region} {t.env_id}  as {t.acting_as}"], False
    if outcome == "already-gone":
        return [f"  already gone {t.region} {t.env_id}  as {t.acting_as} ({why})"], False
    lines = [f"  FAILED  {t.region} {t.env_id}  as {t.acting_as}: {why}"]


    if "AccessDenied" in why:
        lines.append(f"          {access_denied_note(t)}")
    return lines, True


def delete_all(
    targets: "list[Target]", *, on_result: Any = _noop
) -> "tuple[list[tuple[str, str]], int]":
    """Delete every target. Returns `(deleted, failed_count)`."""
    deleted_ok: set[tuple[str, str]] = set()
    failed = 0
    for t in targets:
        region, eid = t.region, t.env_id
        try:
            delete_target(t)
        except Exception as e:  # noqa: BLE001


            if "AccessDenied" in str(e) and (region, eid) in deleted_ok:
                on_result(t, "already-gone", "deleted earlier in this run")
                continue
            failed += 1
            on_result(t, "failed", f"{type(e).__name__}: {e}{refusal_detail(e)}")
            continue
        deleted_ok.add((region, eid))
        on_result(t, "deleted", "")
    return sorted(deleted_ok), failed


def open_source(cred: Cred, *, pool: Any, browser: "Optional[BrowserOptions]" = None) -> None:
    """Open this credential's control-plane gateway, or record why not."""
    from cloudbasher.csp.aws.control_plane import (
        ControlPlaneUnavailable,
        control_plane_source,
    )

    def _build() -> Any:


        return control_plane_source(cred.record, browser=browser)

    try:
        cred.source = pool.source_for(cred.record.id, _build)
    except ControlPlaneUnavailable as exc:


        cred.deny(ENUMERATE, str(exc))
        return
    except Exception as exc:  # noqa: BLE001 - a surprise is still that credential's problem
        cred.deny(ENUMERATE, f"{type(exc).__name__}: {exc}")
        return


    keys = getattr(cred.source, "credentials", None)
    cred.keys = keys if keys is not None and keys.access_key else None


def declared_account(cred: Cred) -> str:
    """The account this credential SAYS it is in, before STS is asked."""
    return str(cred.account or cred.declared("account") or cred.declared("account_id") or "")


def identify_cred(cred: Cred) -> None:
    """Fill `own_arn` and `account` from GetCallerIdentity. Never raises."""


    if cred.source is None:
        return
    if cred.keys is None:


        cred.account = declared_account(cred)
        if not cred.account:
            warn_sink(
                f"[creds] [{cred.num}] {cred.label}: no ACCOUNT declared and no key to "
                "ask STS with -- it can still enumerate and delete, but it cannot be "
                "matched to CloudTrail findings.",
            )
        return
    try:
        arn, account, _user_id = sts_get_caller_identity(creds=cred.keys)
    except Exception as e:  # noqa: BLE001
        cred.source = None
        cred.keys = None


        cred.deny_all(f"GetCallerIdentity failed: {type(e).__name__}: {e}")
        return
    cred.own_arn, cred.account = arn, account


def effective_index(cred: "Cred", requested: "Optional[str]") -> "IndexChoice":
    """`provision_request.effective_index` for a sweep `Cred`"""
    return _effective_index_for_record(cred.record, requested, selector=str(cred.num))


def principal_cell(arn: str, *, verbose: bool) -> str:
    """`role/example_sso_admin`, or the whole ARN in verbose mode."""
    from cloudbasher.core.identity_listing import identity_display

    if not arn:
        return "?"
    if verbose:
        return arn
    ident = parse_principal(arn)
    return identity_display(ident.kind, ident.ref, ident.session_name, short_principal(arn) or arn)


def named_identity_creds(
    cred: Cred,
    *,
    requested_name: Optional[str] = None,
    index_arg: Optional[str] = None,
    errors: list[str],
) -> list[Cred]:
    """`cred`, expanded into ONE `Cred` per principal in its name series"""


    from cloudbasher.core.identity_listing import derived_principal_arn
    from cloudbasher.csp.aws.commands import _basename_series

    _choice = effective_index(cred, index_arg)
    index_spec, refusal = _choice.spec, _choice.refusal
    if refusal:


        errors.append(f"{cred_label(cred)}: {refusal}")


    if requested_name is None and _choice.nothing_asked:
        return [cred]
    declared = cred.declared_extra()
    if not can_derive(declared):


        if not asks_derivation(_choice, requested_name):
            return [cred]


        if cred.keys is None:
            errors.append(
                f"{cred_label(cred)}: --as/--index name a principal to DERIVE, "
                "and a console credential has no signing key to derive with. It enumerates "
                "as whatever principal the console session lands on."
            )
        else:
            errors.append(
                f"{cred_label(cred)}: --as/--index name a principal to DERIVE, "
                f"and this credential {derives_nothing_because(declared)} -- there is "
                "nothing to derive from it. Drop them to enumerate as the principal it "
                "already is."
            )
        return []

    try:
        basename, name_source = resolve_identity_name(
            cred.keys, requested_name, where="--enumerate"
        )
    except CredentialError as exc:
        errors.append(f"{cred_label(cred)}: {exc}")
        return []

    series: list[Cred] = []
    for name in _basename_series(basename, index_spec):
        try:


            target = resolve_target_identity(cred.keys, name=name, name_source=name_source)
            derived = derive_target_credentials(cred.keys, target)
        except Exception as exc:  # noqa: BLE001 - one name must not kill the series
            errors.append(f"{cred_label(cred)} as {name}: {type(exc).__name__}: {exc}")
            continue


        one = Cred(
            num=cred.num,
            record=cred.record,
            label=f"{cred.label} as {name}",
            keys=derived,
            source=_SigV4Source(derived),
            account=cred.account,


            own_arn=cred.own_arn,
        )


        one.derived_arn = derived_principal_arn(
            kind=target.kind,
            ref=target.ref,
            session_name=target.session_name,
            account=cred.account,
        )
        if not one.derived_arn:


            errors.append(
                f"{cred_label(cred)} as {name}: derived, but the "
                f"{target.kind} it describes does not name a principal"
            )
            continue
        series.append(one)
    return series


def enumerate_direct(cred: Cred, regions: list[str], errors: list[str]) -> list[Finding]:
    """PASS 1. What this credential can see RIGHT NOW, per region."""
    found: list[Finding] = []
    for region in regions:


        t0 = time.monotonic()
        try:
            client = cred.source.client_for(region)
            resp = client.describe_environments()
        except Exception as exc:  # noqa: BLE001 - one region must not kill the credential


            detail_sink(
                f"[enumerate] {cred_tag(cred)} {region} FAILED after "
                f"{time.monotonic() - t0:.1f}s: {type(exc).__name__}: {exc}"
            )
            errors.append(f"{cred_label(cred)} {region}: {type(exc).__name__}: {exc}")
            continue
        envs = _ci_get(resp, "environments", "Environments") or []


        detail_sink(
            f"[enumerate] {cred_tag(cred)} {region} ok in {time.monotonic() - t0:.1f}s: "
            f"{len(envs)} environment(s)"
        )
        for env in envs:
            eid = _ci_get(env, *_ENV_ID_KEYS, record=True, section="describeEnvironments")
            if not eid:
                continue
            try:
                status = str(client.get_environment_status(str(eid)).get("status") or "Unknown")
            except Exception as exc:  # noqa: BLE001
                status = f"status-error:{type(exc).__name__}"
            found.append(
                Finding(
                    region=region,
                    principal_arn=cred.principal_key,
                    environment_id=str(eid),
                    live_status=status,
                    found_by="enumerate",
                    cred_num=cred.num,
                    observed_at=_now(),
                )
            )
    return found


def close_sources(creds: list[Cred], *, why: str = "atexit") -> None:
    """Release every credential's control-plane source. Never raises, and SAYS WHAT IT DID"""
    from cloudbasher.csp.aws.control_plane import (
        blocked_write_urls_of,
        clear_blocked_write_urls_of,
    )


    live = [c for c in creds if c.source is not None and not getattr(c.source, "_closed", False)]
    if not live:
        return


    for c in live:


        attempts = blocked_write_urls_of(c.source)


        clear_blocked_write_urls_of(c.source)
        if not attempts:
            continue
        warn_sink(
            f"  ! {cred_tag(c)} BLOCKED {len(attempts)} provisioning attempt(s) by the "
            f"CloudShell widget during a read-only pass -- no environment was created. "
            f"See #495/#497."
        )
        for url in attempts:
            detail_sink(f"[blocked] {cred_tag(c)} {url}")


    mine = [c for c in live if not getattr(c.source, "pooled", False)]
    borrowed = len(live) - len(mine)
    if borrowed:
        detail_sink(
            f"[teardown] leaving {borrowed} pooled control-plane source(s) open ({why}) "
            "-- the session owns those logins"
        )
    if not mine:
        return
    detail_sink(f"[teardown] closing {len(mine)} control-plane source(s) ({why})")
    for c in mine:
        kind = getattr(c.source, "kind", "?")


        held = "browser" if getattr(c.source, "_browser", None) is not None else "nothing"
        try:
            c.source.close()
            detail_sink(f"[teardown] {cred_tag(c)} {kind} source closed (held {held})")


            c.source._closed = True
        except Exception as exc:  # noqa: BLE001 - teardown must not mask the run's result


            warn_sink(
                f"  ! teardown: {cred_tag(c)} {kind} source failed to close (held {held}): "
                f"{type(exc).__name__}: {exc}"
            )


class KeysOnlySource(ControlPlaneSource):
    """A credential's SIGNING KEYS, without a control-plane gateway"""

    kind = "keys-only"


    enumerates = False

    def __init__(self, credentials: Any) -> None:
        self.credentials = credentials


        self.blocked_write_urls: list[str] = []

    def client_for(self, region: str) -> Any:
        raise RuntimeError(
            f"this credential was loaded for CloudTrail and STS only, not as a "
            f"CloudShell gateway (asked for {region})."
        )

    def close(self) -> None:
        return None


def keys_only_cred(num: int, record: Any, *, label: str = "") -> "Optional[Cred]":
    """A `Cred` carrying signing keys off `record`, or None if it has none."""
    extra = record.raw.extra or {}
    if not extra.get("access_key"):
        return None
    from cloudbasher.csp.aws.commands import _session_creds_for

    c = Cred(num=num, record=record, label=label or getattr(record, "label", "") or f"[{num}]")
    c.keys = _session_creds_for(record)
    c.source = KeysOnlySource(c.keys)
    return c


def is_sso_block(cred: "Cred") -> bool:
    """An Identity Center block, which has KEYS AVAILABLE for one portal login."""
    from cloudbasher.csp.aws.credentials import is_sso_extra

    return is_sso_extra(cred.declared_extra())


def sso_self_serving(cred: "Cred") -> bool:
    """`credentials.sso_self_serving` for this module's unit"""
    from cloudbasher.csp.aws.credentials import sso_self_serving as _self_serving

    return _self_serving(cred.declared_extra())


def no_keys_reason(cred: "Cred", *, enumerate_cmd: str, discover_cmd: str) -> str:
    """Why this credential has no signing keys, AND what it can still do."""
    if is_sso_block(cred):
        return (
            "SSO credential -- not resolved to keys for this run, which costs a "
            f"portal sign-in. It can ENUMERATE (`{enumerate_cmd}`), and "
            f"`{discover_cmd}` resolves it automatically if no other selected "


            "credential can read CloudTrail in its account."
        )


    return (
        f"console credential -- no signing keys, and {_CLOUDTRAIL_IS_OUR_PLUMBING}, "
        f"so it cannot be a reader HERE. It CAN ENUMERATE: `{enumerate_cmd}`."
    )


def deny_keyless(cred: "Cred", *, enumerate_cmd: str, discover_cmd: str) -> str:
    """Record `no_keys_reason` against the TWO capabilities keys gate"""
    reason = no_keys_reason(cred, enumerate_cmd=enumerate_cmd, discover_cmd=discover_cmd)
    cred.deny(READ_CLOUDTRAIL, reason)
    cred.deny(SIGN_STS, reason)
    return reason


def _rehome(cred: "Cred", frm: str, to: "tuple[str, ...]") -> None:
    """Move a recorded reason from one capability to others"""
    reason = cred.reasons.pop(frm, "")
    if not reason:
        return
    for cap in to:
        cred.deny(cap, reason)


def resolve_sso_to_reader(
    cred: "Cred", *, pool: Any, browser: "Optional[BrowserOptions]" = None
) -> bool:
    """Resolve an SSO credential to real keys, in place"""
    if not is_sso_block(cred):
        return False


    open_source(cred, pool=pool, browser=browser)
    if cred.source is None:


        _rehome(cred, ENUMERATE, (READ_CLOUDTRAIL, SIGN_STS))
        return False


    if cred.keys is None:
        cred.source = None


        for cap in (READ_CLOUDTRAIL, SIGN_STS):
            cred.deny(cap, "SSO portal returned no usable key material")
        return False


    cred.reasons = {}
    identify_cred(cred)


    return cred.can_read_cloudtrail


def pick_sweepers(signers: "list[Cred]", *, on_choice: Any = None) -> "dict[str, Cred]":
    """The one credential per account that will READ CLOUDTRAIL"""
    sweepers: dict[str, Cred] = {}
    others: dict[str, list[Cred]] = {}
    for c in signers:
        if not (c.can_read_cloudtrail and c.account):
            continue
        if c.account in sweepers:
            others.setdefault(c.account, []).append(c)
            continue
        sweepers[c.account] = c


    if on_choice is not None:
        for account, chosen in sorted(sweepers.items()):
            on_choice(account, chosen, others.get(account, []))
    return sweepers


def ensure_account_readers(
    eligible: "list[Cred]",
    *,
    pool: Any,
    browser: "Optional[BrowserOptions]" = None,
    on_attempt: Any = None,
    on_outcome: Any = None,
) -> "list[Cred]":
    """Resolve SSO credentials until every account here has a CloudTrail reader."""
    covered = set(pick_sweepers(eligible))
    for cred in eligible:


        if cred.can_read_cloudtrail or not sso_self_serving(cred):
            continue
        account = declared_account(cred)

        if account in covered:
            continue
        if not account and covered:
            continue


        if on_attempt is not None and not has_remembered_login_failure(cred.record.id):
            on_attempt(cred, account)
        ok = resolve_sso_to_reader(cred, pool=pool, browser=browser)
        if on_outcome is not None:
            on_outcome(cred, ok)
        if ok:


            covered = set(pick_sweepers(eligible)) | covered | ({account} - {""})


def sso_last_resort_note(cred: "Cred", account: str) -> str:
    """Why a portal sign-in is about to happen"""
    where = f"account {account}" if account else "this run"
    return (
        f"{cred_label(cred)}: nothing selected can read CloudTrail for "
        f"{where} -- resolving this SSO credential (one portal sign-in)"
    )


def sso_resolved_note(cred: "Cred") -> str:
    """The other half: it worked, and the credential is now a reader."""
    return f"{cred_label(cred)}: resolved -- can now read CloudTrail"


def sso_unresolved_note(cred: "Cred") -> str:
    """THE THIRD SIBLING, and it was missing"""
    return f"{cred_label(cred)}: {cred.why_not(READ_CLOUDTRAIL)}"


NO_CLOUDTRAIL_REASON = (
    f"no credential here can read CloudTrail: {_CLOUDTRAIL_IS_OUR_PLUMBING}, and "
    "a console credential has none. Name a key-based credential, or use `.enum` "
    "for what the held credentials can see directly."
)


def access_denied_note(target: "Target") -> str:
    """Why a delete was refused, when the refusal is ambiguous"""
    who = target.acting_as
    return (
        f"NOTE: deletion authorizes on the CALLING principal, and CloudShell scopes "
        f"environments to it. This ran as {who}. If that is not the identity "
        f"that CREATED {target.env_id}, the refusal is about OWNERSHIP, not "
        f"permission -- and the two are indistinguishable in the response. Check "
        f"ACT_AS (role AND session name: `assumed-role/<role>/<session>` is the "
        f"whole principal)."
    )
