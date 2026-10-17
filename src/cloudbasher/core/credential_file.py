"""Self-identifying multi-CSP credential-file parser."""

from __future__ import annotations

import re
from dataclasses import asdict, is_dataclass
from typing import Any, NamedTuple, Optional

from cloudbasher.core.exceptions import CredentialError
from cloudbasher.core.types import CredentialRecord, Credentials
from cloudbasher.core.utils.output import masked_key_id
from cloudbasher.csp.aws import credentials as aws_credentials
from cloudbasher.csp.azure import credentials as azure_credentials
from cloudbasher.csp.gcp import credentials as gcp_credentials


_OVERRIDE_RE = re.compile(
    r"^\s*(?:export\s+)?(?:csp|provider)\s*[:=]\s*(aws|gcp|azure)\s*(?:#.*)?$",
    re.IGNORECASE,
)


_COMMENT_LINE_RE = re.compile(r"^\s*(?:#|$)")


_ANNOTATION_KEYWORDS = ("DESCRIPTION",)

_ANNOTATION_RE = re.compile(
    r"^\s*#+\s*(%s)\s*[:=]\s*(\S.*?)\s*$" % "|".join(_ANNOTATION_KEYWORDS),
    re.IGNORECASE,
)


def extract_annotation(block: str, keyword: str) -> Optional[str]:
    """The block's `# <KEYWORD>: ...` text, or None."""
    wanted = keyword.upper()
    for line in block.splitlines():
        m = _ANNOTATION_RE.match(line)
        if m and m.group(1).upper() == wanted:
            return m.group(2)
    return None


def extract_description(block: str) -> Optional[str]:
    """The block's `# DESCRIPTION:` text -- a free-text label for the listing."""
    return extract_annotation(block, "DESCRIPTION")


def _is_comment_only(block: str) -> bool:
    """True when every line in ``block`` is blank or a ``#`` comment."""
    return all(_COMMENT_LINE_RE.match(line) for line in block.splitlines())


_MATERIAL_KV_RE = re.compile(r"""^\s*(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]""")


_MATERIAL_KEY_SLOTS: dict[str, str] = {

    "AWS_ACCESS_KEY_ID": "AWS access key id",
    "AWS_ACCESS_KEY": "AWS access key id",
    "ACCESS_KEY_ID": "AWS access key id",
    "ACCESSKEYID": "AWS access key id",
    "AK": "AWS access key id",
    "AWS_SECRET_ACCESS_KEY": "AWS secret access key",
    "AWS_SECRET_KEY": "AWS secret access key",
    "SECRET_ACCESS_KEY": "AWS secret access key",
    "SECRETACCESSKEY": "AWS secret access key",
    "SK": "AWS secret access key",
    "AWS_SESSION_TOKEN": "AWS session token",
    "SESSION_TOKEN": "AWS session token",
    "SESSIONTOKEN": "AWS session token",

    "AWS_CONSOLE_USERNAME": "console username",
    "USERNAME": "console username",
    "AWS_CONSOLE_PASSWORD": "console password",
    "PASSWORD": "console password",
    "AWS_CONSOLE_ACCOUNT": "console account",
    "ACCOUNT": "console account",


    "SSO_START_URL": "SSO start URL",
    "ACCOUNT_ID": "SSO account id",
    "ROLE_NAME": "SSO role name",
    "SSO_USERNAME": "SSO username",
    "SSO_PASSWORD": "SSO password",

    "CLIENT_EMAIL": "service-account client_email",
    "PRIVATE_KEY": "service-account private_key",
    "CLIENT_ID": "OAuth client id",
    "CLIENT_SECRET": "OAuth client secret",
    "REFRESH_TOKEN": "OAuth refresh token",
    "RAPT_TOKEN": "OAuth reauthentication proof",
    "RAPT": "OAuth reauthentication proof",
}


def _mfa_slot_rows() -> "dict[str, str]":
    """The MFA rows of ``_MATERIAL_KEY_SLOTS``, generated from the families."""
    from cloudbasher.core import mfa_keys

    rows: "dict[str, str]" = {}
    for family in mfa_keys.FAMILIES:
        slot = "MFA code or secret" if family is mfa_keys.CONSOLE else "SSO MFA code or secret"
        for key in family.keys:
            for spelling in mfa_keys.spellings(key, prefixes=family.prefixes):
                rows[spelling] = slot
    return rows


_MATERIAL_KEY_SLOTS.update(_mfa_slot_rows())


_MATERIAL_SHAPE_FAMILIES: dict[str, frozenset[str]] = {
    "IAM access key": frozenset(
        {"AWS access key id", "AWS secret access key", "AWS session token"}
    ),
    "console username/password": frozenset(
        {"console username", "console password", "MFA code or secret"}
    ),
    "SSO": frozenset(
        {
            "SSO start URL",
            "SSO account id",
            "SSO role name",
            "SSO username",
            "SSO password",
            "SSO MFA code or secret",
        }
    ),
    "service account": frozenset({"service-account client_email", "service-account private_key"}),
}

_BLOCKS_ARE_BLANK_LINE_DELIMITED = (
    "Blocks in a -F file are separated by a BLANK line -- a comment line (#) "
    "does not separate them. Put an empty line between each credential. See "
    "creds.rc.example for a correctly separated template."
)


def _material_slots_in(block: str) -> dict[str, int]:
    """``{canonical material slot: how many times the block names it}``."""
    seen: dict[str, int] = {}
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = _MATERIAL_KV_RE.match(line)
        if m is None:
            continue
        slot = _MATERIAL_KEY_SLOTS.get(m.group(1).strip().upper())
        if slot is not None:
            seen[slot] = seen.get(slot, 0) + 1
    return seen


def merged_blocks_error(block: str) -> Optional[str]:
    """The message if ``block`` looks like several credentials run together."""
    seen = _material_slots_in(block)
    repeated = sorted(f"{slot} (x{n})" for slot, n in seen.items() if n > 1)
    if repeated:
        return (
            "This looks like several credentials merged into one block: "
            + ", ".join(repeated)
            + " appear more than once, and a single credential has one of each. "
            + _BLOCKS_ARE_BLANK_LINE_DELIMITED
        )

    families = sorted(
        name for name, slots in _MATERIAL_SHAPE_FAMILIES.items() if slots & seen.keys()
    )
    if len(families) > 1:
        return (
            "This looks like several credentials merged into one block: it "
            f"carries {' and '.join(families)} material at once, and a single "
            "credential is exactly one of those shapes. " + _BLOCKS_ARE_BLANK_LINE_DELIMITED
        )
    return None


def _split_blocks(text: str, *, strict: bool = True) -> list[str]:
    """Split a file into blank-line-delimited blocks."""
    blocks: list[str] = []
    current: list[str] = []
    depth = 0
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped and depth == 0:
            if current:
                blocks.append("\n".join(current))
                current = []
            continue
        current.append(raw_line)
        depth += stripped.count("{") + stripped.count("[")
        depth -= stripped.count("}") + stripped.count("]")
    if current:
        blocks.append("\n".join(current))
    kept = [b for b in blocks if b.strip() and not _is_comment_only(b)]
    if strict:
        for block in kept:
            message = merged_blocks_error(block)
            if message is not None:
                raise CredentialError(message)
    return kept


def merged_blocks_error_in_text(text: str) -> Optional[str]:
    """``merged_blocks_error()`` for a whole file's text; first problem wins."""
    for block in _split_blocks(text, strict=False):
        message = merged_blocks_error(block)
        if message is not None:
            return message
    return None


def _extract_override(block: str) -> tuple[str, Optional[str]]:
    """Pull the directive lines out of a block: ``csp=``/``provider=``, and ``# DESCRIPTION:``."""
    kept: list[str] = []
    declared: list[str] = []
    for line in block.splitlines():
        m = _OVERRIDE_RE.match(line)
        if m:
            declared.append(m.group(1).lower())
            continue
        if _ANNOTATION_RE.match(line):
            continue
        kept.append(line)


    if len(set(declared)) > 1:
        raise CredentialError(
            f"a credential block declares its cloud twice, and disagrees: "
            f"{', '.join(f'csp={d}' for d in dict.fromkeys(declared))}.\n"
            f"  block starts: {_block_excerpt(block)}\n"
            "Keep one `csp=` line, or split the block in two."
        )
    return "\n".join(kept), (declared[0] if declared else None)


_CSP_PARSERS: dict[str, Any] = {
    "gcp": gcp_credentials.parse_creds_text,
    "azure": azure_credentials.parse_creds_text,
}


_ORPHAN_DECLARATION_KEYS = ("ACT_AS", "FEDERATION_NAME", "ROLE_SESSION_NAME")


_AWS_ONLY_PROVISION_KEYS = ("REGION", "INDEX")


def _reject_misplaced_provision_keys(provider: str, text: str) -> None:
    """Raise if a CSP block declares a provisioning hint it cannot honour."""
    allowed = set(_AWS_ONLY_PROVISION_KEYS if provider == "aws" else ())
    if provider == "azure":
        allowed.add("REGION")
    found = sorted(
        {
            line.strip().split("=", 1)[0].strip().upper()
            for line in text.splitlines()
            if not line.lstrip().startswith("#")
            for key in _AWS_ONLY_PROVISION_KEYS
            if key not in allowed
            if line.strip().upper().startswith(f"{key}=")
            or line.strip().upper().startswith(f"EXPORT {key}=")
        }
    )
    if not found:
        return
    keys = ", ".join(found)
    detail = (
        " GCP Cloud Shell has no selectable region -- Google assigns the zone."
        if provider == "gcp" and "REGION" in found
        else ""
    )
    raise CredentialError(
        f"a {provider} credential block declares {keys}, which this CSP does not support."
        f"{detail} Remove the line"
        + (", or add `csp=aws` if this block was meant to be an AWS credential." if provider != "azure" else ".")
    )


def _reject_orphaned_declaration(text: str) -> None:
    """Raise if a block declares an identity but carries no credential to apply it to."""
    if _material_slots_in(text):
        return
    declared = [
        (n, line.strip())
        for n, line in enumerate(text.splitlines(), 1)
        if not line.lstrip().startswith("#")
        and any(
            line.strip().upper().startswith(k) or line.strip().upper().startswith(f"EXPORT {k}")
            for k in _ORPHAN_DECLARATION_KEYS
        )
    ]
    if not declared:
        return
    shown = "; ".join(f"{s.split('=', 1)[0].strip()}" for _n, s in declared)
    raise CredentialError(
        f"a credential block declares an identity ({shown}) but contains no "
        "credential for it to apply to.\n"
        "The usual cause is a BLANK LINE inside what was meant to be one block -- "
        "blank lines separate blocks, so the keys ended up in the block above and "
        "this declaration was left stranded. Comment lines do NOT split a block, "
        "so remove the blank line and keep the comments.\n"
        "Declarations that must travel with their key material: "
        f"{', '.join(_ORPHAN_DECLARATION_KEYS)}."
    )


def _block_excerpt(block: str) -> str:
    """The line to quote back when refusing ``block``, trimmed to 60 chars."""
    for line in block.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped[:60]
    return block.strip()[:60]


def _undeclared_block_error(block: str) -> CredentialError:
    """THE refusal for a block that does not name its cloud"""
    return CredentialError(
        "this credential block does not say which cloud it is for.\n"
        f"  block starts: {_block_excerpt(block)}\n"
        "Add a `csp=` line to it -- one of `csp=aws`, `csp=gcp`, `csp=azure` "
        "(`provider=` is accepted as the same thing, in any case).\n"
        "It is required rather than guessed because the shapes overlap: a "
        "bare username/password block parses under all three, and a block "
        "guessed wrong is attributed to the wrong cloud in silence."
    )


def _reject_undeclarable_block(block: str, text: str, declared: Optional[str]) -> None:
    """Raise unless ``block`` is a credential that names its cloud"""
    _reject_orphaned_declaration(text)
    if not text.strip():
        raise CredentialError(
            "this credential block declares a cloud but holds no credential.\n"
            f"  block starts: {_block_excerpt(block)}\n"
            "Put the key material in the block, or delete it. A block that is "
            "only comments is fine and is skipped -- this one is not."
        )
    if declared is None:
        raise _undeclared_block_error(block)


def _try_parse_block(block: str) -> tuple[str, Any]:
    """Parse one block against the CSP it DECLARES"""
    text, override = _extract_override(block)
    _reject_undeclarable_block(block, text, override)
    assert override is not None


    _reject_misplaced_provision_keys(override, text)

    if override == "aws":
        parsed = aws_credentials.parse_creds_text(text)
        if parsed is None:
            raise CredentialError(
                "csp=aws was declared for this block, but AWS's parser found "
                "no recognizable credential shape in it. Check the block's "
                "format against creds.rc.example"
            )
        return "aws", parsed

    try:
        parsed = _CSP_PARSERS[override](text)
    except CredentialError as exc:
        raise CredentialError(
            f"csp={override} was declared for this block, but {override}'s "
            f"parser could not make sense of it: {exc}"
        ) from exc
    return override, parsed


class ParsedBlock(NamedTuple):
    """One successfully parsed block of a multi-CSP credential file."""

    provider: str
    parsed: Any
    block: int


    description: Optional[str] = None


def parse_multi_creds_file(path: str) -> list[ParsedBlock]:
    """Parse a multi-CSP credential file into ``ParsedBlock`` triples."""
    from cloudbasher.core.secret_refs import read_credential_file

    return parse_multi_creds_text(read_credential_file(path))


def split_blocks_by_declared_csp(text: str) -> list[tuple[str, str]]:
    """Block-split only: ``[(block_text_without_csp_line, declared_csp)]``."""
    out: list[tuple[str, str]] = []
    for block in _split_blocks(text):
        body, declared = _extract_override(block)
        _reject_undeclarable_block(block, body, declared)
        assert declared is not None
        out.append((body, declared))
    return out


def stamp_cred_ref(parsed: object, number: int) -> None:
    """Bind a parsed credential to its BLOCK POSITION in the file."""
    if isinstance(parsed, aws_credentials.AwsSessionCreds):
        parsed.cred_ref = f"cred#{number}"


def parse_multi_creds_text(text: str) -> list[ParsedBlock]:
    """The same parse, from text already in hand and WITHOUT resolving anything."""


    results: list[ParsedBlock] = []
    for number, block in enumerate(_split_blocks(text), 1):
        provider, parsed = _try_parse_block(block)


        stamp_cred_ref(parsed, number)
        results.append(ParsedBlock(provider, parsed, number, extract_description(block)))
    return results


def _derivation_slug(extra: dict[str, Any]) -> str:
    """The id fragment naming this block's derivation, with a trailing ``:``, or ``""`` when there is nothing to name."""
    from cloudbasher.csp.aws.act_as import act_as_mode_of, role_name_from_arn

    mode = act_as_mode_of(extra)
    if not mode:
        return ""
    if mode != "role":
        return f"{mode}:"
    return f"role/{role_name_from_arn(extra.get('role_arn'), missing='role')}:"


def build_credential_records(
    provider: str,
    parsed: Any,
    *,
    role: str = "originating",
    source_block: Optional[int] = None,
    description: Optional[str] = None,
) -> CredentialRecord:
    """Wrap one parsed per-CSP dataclass into **exactly one record**."""
    base: dict[str, Any] = {}
    if is_dataclass(parsed) and not isinstance(parsed, type):
        if provider == "aws":


            base = aws_credentials.extra_from_creds(parsed)
        else:
            base = asdict(parsed)
    if description:
        base["description"] = description
    return _record_from_extra(provider, base, role=role, source_block=source_block)


def build_credential_records_for_credentials(
    provider: str,
    credentials: Credentials,
    *,
    role: str = "originating",
    source_block: Optional[int] = None,
) -> CredentialRecord:
    """The same build, from an already-loaded ``Credentials`` rather than a parsed dataclass -- i.e. the ``--creds-env`` and post-``load()`` shape."""
    return _record_from_extra(
        provider, dict(credentials.extra or {}), role=role, source_block=source_block
    )


def _record_from_extra(
    provider: str,
    base: dict[str, Any],
    *,
    role: str,
    source_block: Optional[int],
) -> CredentialRecord:
    """The one place a ``CredentialRecord``'s id is built."""
    label = _label_for(provider, base)
    suffix = "orig" if role == "originating" else "target"
    return CredentialRecord(
        id=f"{provider}:{_id_label(base, label)}:{_derivation_slug(base)}{suffix}",
        provider=provider,
        kind=_kind_for(base),
        role=role,
        parent_id=None,
        label=label,
        raw=Credentials(provider=provider, extra=base),
        source_block=source_block,
    )


def _id_label(extra: dict[str, Any], label: str) -> str:
    """The label as it may appear in a record ID, with key material masked."""
    access_key = str(extra.get("access_key") or "")
    if not access_key or label != access_key:
        return label
    return masked_key_id(access_key)


def _label_for(provider: str, extra: dict[str, Any]) -> str:
    """Best-effort display identity from parsed fields — no API calls."""
    for key in (
        "access_key",
        "client_email",
        "client_id",
        "username",
        "sso_start_url",
        "tenant_id",
    ):
        val = extra.get(key)
        if val:
            return str(val)
    return f"{provider}-credential"


def _kind_for(extra: dict[str, Any]) -> str:
    """Best-effort Console/Permanent/Temporary classification of one credential block."""
    if extra.get("username") and extra.get("password"):
        return "console"


    if aws_credentials.is_sso_extra(extra):
        return "console"
    if extra.get("session_token") or extra.get("access_token") or extra.get("refresh_token"):
        return "temporary"
    return "permanent"
