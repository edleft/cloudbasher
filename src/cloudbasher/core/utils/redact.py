"""Demo obfuscation layer: a runtime-toggleable mask over PII/secret-shaped values shown in the Nodes table and command output, for screen-sharing a live demo without exposing real account numbers, IPs, hostnames, usernames, or object ids."""

from __future__ import annotations

import re
from typing import Optional

_enabled: bool = False
_mode: str = "partial"

_VALID_MODES = ("partial", "pseudonym")


FIELD_TYPES = (
    "account",
    "username",
    "rolename",
    "identity",
    "object_id",
    "secret",
    "ip",
    "hostname",
)


_FIELD_FIXED_MODE = {
    "identity": "pseudonym",


    "principal_name": "pseudonym",


    "access_key": "partial",
}

_field_mode_overrides: dict[str, str] = {}
_VALID_FIELD_MODES = ("off", "partial", "pseudonym")


def set_field_mode_override(field_type: str, mode: str) -> None:
    """Per-field-type rc override (``[redact] field.<type> = off|partial|pseudonym``)."""
    if mode not in _VALID_FIELD_MODES:
        return
    _field_mode_overrides[field_type] = mode


def _effective_mode(field_type: str) -> str:
    return _field_mode_overrides.get(field_type) or _FIELD_FIXED_MODE.get(field_type) or _mode


def set_redaction_enabled(enabled: bool) -> None:
    """Master on/off switch. False (the default) means every redact_* function is a no-op passthrough, regardless of ``mode``."""
    global _enabled
    _enabled = bool(enabled)


def is_redaction_enabled() -> bool:
    return _enabled


def set_redaction_mode(mode: str) -> None:
    """Set how values are obscured once enabled. Invalid values are ignored (keeps the previous mode) rather than raising -- this is fed from user-editable rc-file text and a TUI toggle key, neither of which should be able to crash the process on a typo."""
    global _mode
    if mode in _VALID_MODES:
        _mode = mode


def get_redaction_mode() -> str:
    return _mode


def toggle_redaction() -> bool:
    """Flip the master on/off switch for the TUI's single keybind."""
    global _enabled
    _enabled = not _enabled
    return _enabled


_PSEUDONYM_WORDS = (
    "falcon",
    "harbor",
    "cedar",
    "maple",
    "otter",
    "comet",
    "willow",
    "delta",
    "granite",
    "meadow",
    "sparrow",
    "canyon",
    "juniper",
    "quartz",
    "heron",
    "boulder",
    "clover",
    "ember",
    "frost",
    "lagoon",
    "marble",
    "nectar",
    "oasis",
    "pebble",
    "ridge",
    "summit",
    "tundra",
    "violet",
    "walnut",
    "zephyr",
)


_POOL_KINDS = ("generic", "username", "role", "company")
_pseudonym_pools: dict[str, dict[str, str]] = {k: {} for k in _POOL_KINDS}


_pseudonym_map = _pseudonym_pools["generic"]
_username_pseudonym_map = _pseudonym_pools["username"]

_PSEUDONYM_POOLS = tuple(_pseudonym_pools.values())


def reset_pseudonyms() -> None:
    """Forget every assigned pseudonym. Test-support, and the only supported way to clear them -- see `_PSEUDONYM_POOLS`."""
    for pool in _PSEUDONYM_POOLS:
        pool.clear()


_POOL_BY_TOKEN = {

    "user": "username",
    "sso": "username",


    "console": "username",
    "federated": "username",
    "federated-user": "username",
    "role": "role",
    "assumed-role": "role",

    "username": "username",
    "federation_name": "username",
    "role_session_name": "username",
    "origin": "username",
    "role_name": "role",


    "sts_userid": "username",
}


_IDENTITY_PREFIXES = (
    "user",
    "sso",
    "console",
    "federated",
    "federated-user",
    "role",
    "assumed-role",
)


def _pool_kind_for_prefix(prefix: str) -> str:
    """Which pseudonym pool an identity's name half belongs to."""
    return _POOL_BY_TOKEN.get(prefix, "generic")


_EMAIL_IDENTITY_RE = re.compile(
    r"([A-Za-z0-9._%+\-]+)@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)" r"(?:\.[A-Za-z0-9-]+)+"
)


_NAME_CHARS_RE = re.compile(r"[A-Za-z0-9_+=,.@\-]+")


def _mask_segment(value: str, *, kind: str) -> tuple[str, bool]:
    """Mask the leading NAME in one `/`-separated segment."""
    if value.startswith("["):
        end = value.find("]")


        if end <= 1:
            return value, False
        inner = _pseudonym_name(value[1:end], kind=kind)
        return f"[{inner}]{value[end + 1:]}", end + 1 == len(value)
    match = _NAME_CHARS_RE.match(value)
    if match is None:
        return value, False
    masked = _pseudonym_name(match.group(0), kind=kind)
    return masked + value[match.end() :], match.end() == len(value)


def _mask_identity_name(name: str, prefix: str) -> str:
    """Pseudonym an identity's name half, by kind, preserving its structure."""
    kind = _pool_kind_for_prefix(prefix)


    email = _EMAIL_IDENTITY_RE.fullmatch(name)
    if email is not None:
        return _mask_email_like(email.group(1), email.group(2))


    portal = _mask_sso_portal_in(name)
    if portal is not None:
        return portal
    segments = name.split("/")


    out: list[str] = []
    for index, segment in enumerate(segments):
        masked, whole = _mask_segment(segment, kind=kind if index == 0 else "username")
        out.append(masked)
        if not whole:


            out.extend(segments[index + 1 :])
            break
    return "/".join(out)


def _generic_word(idx: int) -> str:
    """The original nature-word pool, for values that are not a person, a role or an organisation -- session names, project codenames, hostnames."""
    word = _PSEUDONYM_WORDS[idx % len(_PSEUDONYM_WORDS)]
    suffix = idx // len(_PSEUDONYM_WORDS)
    return word if suffix == 0 else f"{word}{suffix}"


def _pseudonym_for(value: str, *, kind: str = "generic") -> str:
    """Allocate a stable pseudonym for `value`, from the pool for `kind`."""
    table = _pseudonym_pools[kind]
    existing = table.get(value)
    if existing is not None:
        return existing
    from cloudbasher.core.utils import pseudonym_names as _names

    generator = {
        "generic": _generic_word,
        "username": _names.username_for,
        "role": _names.role_for,
        "company": _names.company_for,
    }[kind]
    name = generator(len(table))
    table[value] = name
    return name


_SEQ_SUFFIX_RE = re.compile(r"^(?P<base>.*?)-(?P<seq>\d+)$")


def _pseudonym_name(value: str, *, kind: str = "generic") -> str:
    """Pseudonym the identifying part of a name, keeping any fleet index."""
    m = _SEQ_SUFFIX_RE.match(value)
    if m is None or not m.group("base"):
        return _pseudonym_for(value, kind=kind)

    return f"{_pseudonym_for(m.group('base'), kind=kind)}" f"-{m.group('seq')}"


_IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _partial_generic(value: str) -> str:
    """Default shape for secret/object_id-like values: keep a short prefix/suffix, mask the middle -- same convention as output.py's obfuscate_secret(), reused here rather than duplicated."""
    from cloudbasher.core.utils.output import obfuscate_secret

    return obfuscate_secret(value)


def _partial_oauth_token_fingerprint(value: str) -> str:
    """Mask a pre-truncated token ID again when the TUI redaction toggle is on."""
    if "…" not in value:
        return _partial_generic(value)
    return f"{value[:2]}…{value[-2:]}"


def _partial_ip(value: str) -> str:
    m = _IP_RE.match(value)
    if not m:
        return _partial_generic(value)
    a, _b, _c, d = m.groups()
    return f"{a}.**.**.{d}"


_HOSTNAME_IP_LABEL_RE = re.compile(r"^([A-Za-z]+)-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})$")


def _partial_hostname_label(label: str) -> str:
    """Mask one dot-separated hostname label octet-style when it matches AWS CloudShell's ``ip-A-B-C-D`` internal-hostname convention, whose first label embeds a real private IP address. Falls back to generic masking for any other label shape."""
    m = _HOSTNAME_IP_LABEL_RE.match(label)
    if not m:
        return _partial_generic(label)
    prefix, a, _b, _c, d = m.groups()
    return f"{prefix}-{a}-**-**-{d}"


def _partial_hostname(value: str) -> str:
    """Mask a dotted hostname's IP-shaped first label plus every interior label, keeping only the trailing domain suffix (e.g. ``ip-A-B-C-D.<region>.compute.internal``). The suffix alone is low-sensitivity; everything before it can carry a real address or region detail worth hiding on a shared screen."""
    labels = value.split(".")
    first = _partial_hostname_label(labels[0])
    if len(labels) == 1:
        return first
    if len(labels) == 2:
        return f"{first}.{labels[-1]}"
    return ".".join([first] + ["***"] * (len(labels) - 2) + [labels[-1]])


def _partial_username_like(value: str) -> str:
    """Short identifiers (usernames, role session names) -- obfuscate_secret()'s 8-char threshold would leave most of these untouched, so use a tighter keep-first-2/last-1 shape instead."""
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * (len(value) - 3) + value[-1:]


def _mask_sso_portal_in(value: str) -> Optional[str]:
    """`ssosandbox.awsapps.com` -> `acme.awsapps.com`, anywhere in `value`."""
    if not _SSO_PORTAL_RE.search(value):
        return None
    return _SSO_PORTAL_RE.sub(
        lambda m: f"{_pseudonym_for(m.group(1).lower(), kind='company')}.awsapps.com",
        value,
    )


def _partial_account(value: str) -> str:
    """Length-preserving middle mask: keep 3 chars on each side, mask everything between (e.g. a 12-digit AWS account# -> ``055***9579``[sic, 6 stars] rather than the generic obfuscate_secret() shape, which pads the mask to a fixed 8 characters regardless of input length and (user-reported) visibly changes the value's length -- throwing off the Nodes table's column alignment and losing the "still looks like an account number" realism partial masking is supposed to preserve."""


    if not _TEXT_ACCOUNT_RE.fullmatch(value) and _TEXT_ACCOUNT_RE.search(value):
        return _TEXT_ACCOUNT_RE.sub(lambda m: _partial_middle(m.group(0)), value)
    return _partial_middle(value)


def _partial_middle(value: str) -> str:
    """Keep 3 chars each side, mask the rest, preserving length."""
    if len(value) <= 6:
        return _partial_generic(value)
    return value[:3] + "*" * (len(value) - 6) + value[-3:]


_ARN_ACCOUNT_PREFIX_RE = re.compile(r"^(arn:aws:(?:iam|sts)::)(\d{12})(:)")


_IDENTITY_PLACEHOLDERS = frozenset(


    {"—", "(pending)", "(unresolved)", "(resolving…)", "(resolving identity…)"}
)


_BARE_DERIVATION_TYPES = frozenset(
    {
        "federated",
        "role",
        "direct",
        "assumed-role",


        "user",
    }
)


def _identity_pseudonym(value: str) -> str:
    """Pseudonym-substitute an identity label while preserving its "kind" prefix (e.g. ``user/example_user`` -> ``user/falcon``, ``federated/cloudbasher`` -> ``federated/otter``) -- user-reported: a plain whole-string pseudonym swap (the fallback below) throws away whether the row is a user/role/federated identity, which is useful, low-sensitivity context worth keeping even when the name itself is masked."""
    if value in _IDENTITY_PLACEHOLDERS:
        return value


    _arn = _ARN_ACCOUNT_PREFIX_RE.match(value)
    if _arn is not None:
        arn_prefix = f"{_arn.group(1)}{_partial_account(_arn.group(2))}{_arn.group(3)}"
        stripped = value[_arn.end() :]
    else:
        arn_prefix = ""
        stripped = value
    if "/" in stripped:


        prefix, _, name = stripped.partition("/")
        return f"{arn_prefix}{prefix}/{_mask_identity_name(name, prefix)}"
    if not _HAS_LETTER_RE.search(stripped):


        return stripped
    if _access_key_re().fullmatch(stripped):


        return _partial_generic(stripped)
    if _WRITE_MASKED_RE.search(stripped):


        return stripped


    if " " in stripped:
        return value
    if stripped in _BARE_DERIVATION_TYPES:


        return stripped


    return f"{arn_prefix}{stripped}"


_PARTIAL_BY_FIELD = {
    "ip": _partial_ip,
    "hostname": _partial_hostname,
    "username": _partial_username_like,
    "rolename": _partial_username_like,
    "identity": _partial_username_like,


    "principal_name": _partial_username_like,
    "account": _partial_account,
    "object_id": _partial_generic,
    "secret": _partial_generic,
    "oauth_token_fingerprint": _partial_oauth_token_fingerprint,


    "access_key": _partial_generic,
}


def _username_pseudonym(value: str) -> str:
    """`redact_field(..., "username")` -- a human account, so the human pool."""
    return _pseudonym_name(value, kind="username")


def _principal_name_pseudonym(value: str) -> str:
    """The derived principal's NAME, on its own. ITEMS #141."""
    masked, _whole = _mask_segment(value, kind="username")
    return masked


_PSEUDONYM_FN_BY_FIELD = {
    "identity": _identity_pseudonym,
    "username": _username_pseudonym,
    "principal_name": _principal_name_pseudonym,
}


class RedactRule:
    __slots__ = ("name", "pattern", "mode", "scope")

    def __init__(self, name: str, pattern: "re.Pattern[str]", mode: str, scope: Optional[str]):
        self.name = name
        self.pattern = pattern
        self.mode = mode
        self.scope = scope


_redact_rules: list[RedactRule] = []


def clear_redact_rules() -> None:
    """Drop every registered regex rule -- called before re-parsing rc (keeps repeated calls, e.g. in tests, idempotent rather than accumulating duplicate rules)."""
    _redact_rules.clear()


def add_redact_rule(name: str, pattern: str, mode: str, scope: Optional[str] = None) -> None:
    """Register one named regex rule. ``scope`` is ``"field:<type>"`` to apply only to that Nodes-table column, ``"text"`` to apply only during the free-text sweep (redact_text), or ``None`` to apply to both."""
    if mode not in _VALID_FIELD_MODES:
        return
    try:
        compiled = re.compile(pattern)
    except re.error:
        return
    _redact_rules.append(RedactRule(name, compiled, mode, scope))


_MIN_REGISTERABLE_NAME = 4


_IDENTITY_RULE_PREFIX = "identity-name:"


def register_identity_name(name: str, *, group: str = "identity") -> bool:
    """Teach the sweeps one literal identity name. Returns True if registered."""
    cleaned = (name or "").strip()
    if len(cleaned) < _MIN_REGISTERABLE_NAME:
        return False
    rule_name = _IDENTITY_RULE_PREFIX + cleaned
    if any(rule.name == rule_name for rule in _redact_rules):
        return False
    add_redact_rule(
        rule_name,
        r"(?P<%s>\b%s\b)" % (group, re.escape(cleaned)),
        "pseudonym",
    )
    return True


def register_identity_names_from(credentials_by_id: dict) -> int:
    """Register every identity name the loaded credentials declare."""
    registered = 0
    for record in (credentials_by_id or {}).values():
        extra = getattr(getattr(record, "raw", None), "extra", None) or {}


        for key in (
            "username",
            "federation_name",
            "role_session_name",
            "origin",
            "role_name",
        ):


            group = _POOL_BY_TOKEN[key]
            if register_identity_name(str(extra.get(key) or ""), group=group):
                registered += 1
    return registered


def _substitute_named_groups(match: "re.Match[str]", mode: str) -> str:
    text = match.group(0)
    groups = {k: v for k, v in match.groupdict().items() if v is not None}
    if mode == "off" or not groups:
        return text
    match_start = match.start()
    spans = sorted(
        (
            (name, (match.start(name) - match_start, match.end(name) - match_start, value))
            for name, value in groups.items()
        ),
        key=lambda item: item[1],
        reverse=True,
    )
    for name, (start, end, value) in spans:
        if mode != "pseudonym":
            replacement = _partial_generic(value)
        else:


            replacement = _pseudonym_for(value, kind=_POOL_BY_TOKEN.get(name, "generic"))
        text = text[:start] + replacement + text[end:]
    return text


def _is_rule_exempt(value: str, *, scope: str) -> bool:
    """Does an ``off`` rule claim this RAW value, exempting it from redaction?"""
    for rule in _redact_rules:
        if rule.scope not in (None, scope):
            continue
        if rule.mode == "off" and rule.pattern.search(value):
            return True
    return False


def _apply_rules(value: str, *, scope: str) -> Optional[str]:
    """First matching rule's substitution, or None if no rule applies (the caller falls through to the field-type/global-mode default)."""
    for rule in _redact_rules:
        if rule.scope not in (None, scope):
            continue
        if rule.mode == "off":
            continue
        if rule.pattern.search(value):
            return rule.pattern.sub(lambda m: _substitute_named_groups(m, rule.mode), value)
    return None


def redact_field(value: Optional[str], field_type: str) -> Optional[str]:
    """Redact one structured field value (a table cell, not free text)."""
    if not value or not _enabled:
        return value


    mode = _effective_mode(field_type)
    if mode == "off":
        return value


    if _is_rule_exempt(value, scope=f"field:{field_type}"):
        return value


    portal = _mask_sso_portal_in(value)
    if portal is not None:
        return portal
    if mode == "pseudonym":
        out = _PSEUDONYM_FN_BY_FIELD.get(field_type, _pseudonym_for)(value)
    else:
        out = _PARTIAL_BY_FIELD.get(field_type, _partial_generic)(value)
    ruled = _apply_rules(out, scope=f"field:{field_type}")
    return ruled if ruled is not None else out


_TEXT_IP_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


_TEXT_HOSTNAME_RE = re.compile(
    r"\b([A-Za-z]+-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}(?:\.[A-Za-z0-9-]+){2,})\b"
)


_TEXT_BARE_INTERNAL_HOST_RE = re.compile(r"\b((?:ip|ec2)-\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3})\b")


_TEXT_ACCOUNT_RE = re.compile(r"\b\d{12}\b")


_WRITE_MASKED_RE = re.compile(r"\*{4,}")


_HAS_LETTER_RE = re.compile(r"[^\W\d_]")


def _access_key_re():
    from cloudbasher.core.utils.output import _AWS_ACCESS_KEY_RE

    return _AWS_ACCESS_KEY_RE


_TEXT_IDENTITY_RE = re.compile(


    r"\b(" + "|".join(sorted(_IDENTITY_PREFIXES, key=len, reverse=True)) + r")/"


    r"((?:\[[^\]]+\]|[A-Za-z0-9_+=,.@\-]+)"
    r"(?:/(?:\[[^\]]+\]|[A-Za-z0-9_+=,.@\-]+))*)"


    r"(?![A-Za-z0-9_+=,.@:\-])"
)


_SSO_PORTAL_RE = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9-]*)\.awsapps\.com\b")


_EMAIL_RE = re.compile(
    r"(?<![/A-Za-z0-9._%+\-])([A-Za-z0-9._%+\-]+)"
    r"@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)"
    r"(?:\.[A-Za-z0-9-]+)+\b"
)


def _mask_email_like(local: str, domain: str) -> str:
    """`joe.user@realcompany.com` -> `jsmith@acme.org`. The ONE implementation."""
    return (
        f"{_pseudonym_for(local.lower(), kind='username')}@"
        f"{_pseudonym_for(domain.lower(), kind='company')}.org"
    )


_TEXT_STS_USERID_RE = re.compile(r"\b(\d{12}):([A-Za-z0-9_+=,.@\-]+)(?![A-Za-z0-9_+=,.@\-]*/)")


_TEXT_PRINCIPAL_ID_RE = re.compile(r"\b((?:AIDA|AROA|AGPA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16,})\b")


_TEXT_ARN_TAIL_RE = re.compile(
    r"\b(arn:aws[a-z0-9-]*:)(?!iam|sts)([a-z0-9-]+:[a-z0-9-]*:\d{0,12}:)([^\s\"',;]+)"
)


from cloudbasher.core.utils.table_block import (  # noqa: E402
    is_table_block,
    render_table_block,
)


def redact_text(text: str) -> str:
    """Best-effort sweep over free-text command output."""
    if text and is_table_block(text):
        return render_table_block(text, _redact_plain_text if _enabled else None)
    if not text or not _enabled:
        return text
    return _redact_plain_text(text)


def _redact_plain_text(text: str) -> str:
    """``redact_text``'s sweep over one span of flat text -- see its docstring."""


    ident_mode = _effective_mode("identity")
    if ident_mode == "pseudonym":


        text = _SSO_PORTAL_RE.sub(
            lambda m: f"{_pseudonym_for(m.group(1).lower(), kind='company')}.awsapps.com",
            text,
        )
        text = _EMAIL_RE.sub(lambda m: _mask_email_like(m.group(1), m.group(2)), text)

    if ident_mode != "off":

        def _mask_name(name: str, prefix: str = "") -> str:
            if ident_mode != "pseudonym":
                return _partial_generic(name)


            return _mask_identity_name(name, prefix)

        text = _TEXT_IDENTITY_RE.sub(
            lambda m: f"{m.group(1)}/{_mask_name(m.group(2), m.group(1))}", text
        )


        text = _TEXT_STS_USERID_RE.sub(
            lambda m: f"{m.group(1)}:{_mask_name(m.group(2), 'sts_userid')}", text
        )

    obj_mode = _effective_mode("object_id")
    if obj_mode != "off":

        def _mask_obj(value: str) -> str:
            return _pseudonym_for(value) if obj_mode == "pseudonym" else _partial_generic(value)


        text = _TEXT_PRINCIPAL_ID_RE.sub(lambda m: _mask_obj(m.group(1)), text)
        text = _TEXT_ARN_TAIL_RE.sub(
            lambda m: f"{m.group(1)}{m.group(2)}{_mask_obj(m.group(3))}", text
        )

    key_mode = _effective_mode("access_key")
    if key_mode != "off":


        text = _access_key_re().sub(lambda m: _partial_generic(m.group(1)), text)

    acct_mode = _effective_mode("account")
    if acct_mode != "off":


        text = _TEXT_ACCOUNT_RE.sub(
            lambda m: redact_field(m.group(0), "account") or m.group(0), text
        )

    host_mode = _effective_mode("hostname")
    if host_mode != "off":
        if host_mode == "pseudonym":
            text = _TEXT_HOSTNAME_RE.sub(lambda m: _pseudonym_for(m.group(1)), text)
            text = _TEXT_BARE_INTERNAL_HOST_RE.sub(lambda m: _pseudonym_for(m.group(1)), text)
        else:
            text = _TEXT_HOSTNAME_RE.sub(lambda m: _partial_hostname(m.group(1)), text)
            text = _TEXT_BARE_INTERNAL_HOST_RE.sub(lambda m: _partial_hostname(m.group(1)), text)

    ip_mode = _effective_mode("ip")
    if ip_mode == "pseudonym":
        text = _TEXT_IP_RE.sub(lambda m: _pseudonym_for(m.group(0)), text)
    elif ip_mode != "off":
        text = _TEXT_IP_RE.sub(lambda m: f"{m.group(1)}.**.**.{m.group(4)}", text)


    for rule in _redact_rules:
        if rule.scope not in (None, "text"):
            continue
        text = rule.pattern.sub(lambda m: _substitute_named_groups(m, rule.mode), text)

    return text
