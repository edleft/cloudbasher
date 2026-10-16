#!/usr/bin/env python3
"""AWS credential handling for CloudShell runner."""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import MISSING, dataclass, field, fields
from pathlib import Path
from typing import Any, Optional, get_type_hints

from cloudbasher.core import mfa_keys
from cloudbasher.core.exceptions import CredentialError
from cloudbasher.core.keyed_locks import KeyedLocks
from cloudbasher.core.secret_refs import read_credential_file
from cloudbasher.core.types import CredentialRecord, Credentials, carry_aws_identity_keys
from cloudbasher.core.utils.output import detail, masked_key_id
from cloudbasher.core.utils.perf_config import get_credential_refresh_fraction
from cloudbasher.core.utils.timestamps import iso_to_epoch
from cloudbasher.csp.aws.act_as import (
    ActAs,
    act_as_from_extra,
    parse_act_as_declaration,
    require_act_as_permits,
)
from cloudbasher.csp.base import CredentialProvider


@dataclass
class AwsSessionCreds:
    """AWS session credentials for SigV4 signing."""

    access_key: str
    secret_key: str
    session_token: Optional[str] = None


    role_arn: Optional[str] = None


    federation_name: Optional[str] = None


    role_session_name: Optional[str] = None


    act_as: Optional["ActAs"] = None


    principal_arn: Optional[str] = None


    cred_ref: str = ""
    expiration: Optional[str] = None


    issued_at: Optional[float] = None


    provision_region: str = ""
    provision_index: str = ""

    def __post_init__(self) -> None:
        """Keep `role_arn` in step with `act_as`. `#477`."""
        if self.act_as is not None:
            self.role_arn = self.act_as.role_arn

    def lifetime_fraction_elapsed(self) -> Optional[float]:
        """How far through its life this credential is, 0.0-1.0+, or None."""
        if self.issued_at is None or not self.expiration:
            return None
        exp = self._expiration_epoch()
        if exp is None:
            return None
        lifetime = exp - self.issued_at
        if lifetime <= 0:
            return None
        return (time.time() - self.issued_at) / lifetime

    def _expiration_epoch(self) -> Optional[float]:
        """`expiration` as a Unix epoch, accepting both shapes STS returns."""
        return iso_to_epoch(self.expiration)

    @property
    def identity_label(self) -> str:
        """WHAT WE CALL THIS CREDENTIAL'S ACTING PRINCIPAL. `#850`."""
        return self.principal_arn or masked_key_id(self.access_key)

    @property
    def identity_axis(self) -> str:
        """WHOSE line this is, for `#435`'s repeat suppression. `#843`."""
        return f"{self.cred_ref}|{self.identity_label}"

    def is_akia(self) -> bool:
        """Return True if these are permanent (AKIA) IAM keys with no session token."""
        return not bool(self.session_token)

    def is_expired(self, margin_seconds: int = 120) -> bool:
        """Return True if ``expiration`` is unset, unparseable, or within ``margin_seconds`` of now. A cache we can't verify is treated as expired -- never trust an upgrade we can't confirm is still good."""
        exp = self._expiration_epoch()
        if exp is None:


            return True
        return time.time() + margin_seconds >= exp

    def to_dict(self) -> dict[str, str]:
        """Convert to dict for boto3/botocore compatibility."""
        return {
            "AccessKeyId": self.access_key,
            "SecretAccessKey": self.secret_key,
            "SessionToken": self.session_token or "",
        }

    def to_cache_dict(self) -> dict[str, Any]:
        """Serialize for persistence in state.bin's cached_upgrade slot."""
        return {
            "access_key": self.access_key,
            "secret_key": self.secret_key,
            "session_token": self.session_token,
            "cred_ref": self.cred_ref,
            "principal_arn": self.principal_arn,
            "expiration": self.expiration,
            "issued_at": self.issued_at,
        }

    @classmethod
    def from_cache_dict(cls, d: dict[str, Any]) -> "AwsSessionCreds":
        """Inverse of to_cache_dict()."""
        return cls(
            access_key=d.get("access_key", ""),
            secret_key=d.get("secret_key", ""),
            session_token=d.get("session_token") or None,
            cred_ref=str(d.get("cred_ref") or ""),
            principal_arn=d.get("principal_arn"),
            expiration=d.get("expiration"),
            issued_at=d.get("issued_at"),
        )


def credential_is_verifiable(cached: "AwsSessionCreds") -> bool:
    """Can this credential's validity be CONFIRMED at all? `#502`."""
    return bool(cached.expiration)


def credential_refresh_reason(cached: "AwsSessionCreds") -> Optional[str]:
    """Why this cached credential must be re-derived, or None to keep it."""
    if cached.expiration and cached.is_expired():
        return f"the cached credential has expired (expiry {cached.expiration})"
    elapsed = cached.lifetime_fraction_elapsed()


    fraction = get_credential_refresh_fraction()
    if elapsed is not None and elapsed >= fraction:
        return (
            f"{elapsed:.0%} of its lifetime has elapsed, at or past the "
            f"{fraction:.0%} refresh point "
            f"(expiry {cached.expiration})"
        )
    return None


@dataclass
class CloudShellBrowserAuthContext:
    """PKCE OAuth auth context captured during CloudShell credential projection."""

    region: str
    environment_id: Optional[str] = None
    auth_code: Optional[str] = None
    code_verifier: Optional[str] = None
    redirect_uri: Optional[str] = None
    key_base: Optional[str] = None
    refresh_token: Optional[str] = None
    captured_at: Optional[str] = None
    source: str = "unknown"
    redeem_code_request_id: Optional[str] = None
    put_credentials_request_id: Optional[str] = None
    redeem_code_artifact: Optional[dict[str, Any]] = None
    put_credentials_artifact: Optional[dict[str, Any]] = None
    session_creds: Optional["AwsSessionCreds"] = None
    captured_stream_url: Optional[str] = None
    captured_token_value: Optional[str] = None

    def has_redeem_inputs(self) -> bool:
        return bool(self.auth_code and self.code_verifier and self.redirect_uri and self.key_base)

    def has_put_credentials_inputs(self) -> bool:
        return bool(self.refresh_token and self.key_base)

    def export_state(self, *, include_secrets: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "region": self.region,
            "environment_id": self.environment_id,
            "captured_at": self.captured_at,
            "source": self.source,
            "redeem_code_request_id": self.redeem_code_request_id,
            "put_credentials_request_id": self.put_credentials_request_id,
            "redeem_code_artifact": self.redeem_code_artifact,
            "put_credentials_artifact": self.put_credentials_artifact,
            "has_auth_code": bool(self.auth_code),
            "has_code_verifier": bool(self.code_verifier),
            "has_redirect_uri": bool(self.redirect_uri),
            "has_key_base": bool(self.key_base),
            "has_refresh_token": bool(self.refresh_token),
        }
        if include_secrets:
            payload.update(
                {
                    "auth_code": self.auth_code,
                    "code_verifier": self.code_verifier,
                    "redirect_uri": self.redirect_uri,
                    "key_base": self.key_base,
                    "refresh_token": self.refresh_token,
                    "captured_stream_url": self.captured_stream_url,
                    "captured_token_value": self.captured_token_value,
                    "session_creds": (
                        {
                            "access_key": self.session_creds.access_key,
                            "secret_key": self.session_creds.secret_key,
                            "session_token": self.session_creds.session_token,
                        }
                        if self.session_creds is not None
                        else None
                    ),
                }
            )
        return payload

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "CloudShellBrowserAuthContext":
        sc_raw = payload.get("session_creds")
        session_creds: Optional[AwsSessionCreds] = None
        if isinstance(sc_raw, dict):
            session_creds = signing_creds_from_extra(sc_raw)
        return cls(
            region=str(payload.get("region") or "").strip(),
            environment_id=str(payload.get("environment_id") or "").strip() or None,
            auth_code=str(payload.get("auth_code") or "").strip() or None,
            code_verifier=str(payload.get("code_verifier") or "").strip() or None,
            redirect_uri=str(payload.get("redirect_uri") or "").strip() or None,
            key_base=str(payload.get("key_base") or "").strip() or None,
            refresh_token=str(payload.get("refresh_token") or "").strip() or None,
            captured_at=str(payload.get("captured_at") or "").strip() or None,
            source=str(payload.get("source") or "unknown").strip() or "unknown",
            redeem_code_request_id=str(payload.get("redeem_code_request_id") or "").strip() or None,
            put_credentials_request_id=str(payload.get("put_credentials_request_id") or "").strip()
            or None,
            redeem_code_artifact=(
                payload.get("redeem_code_artifact")
                if isinstance(payload.get("redeem_code_artifact"), dict)
                else None
            ),
            put_credentials_artifact=(
                payload.get("put_credentials_artifact")
                if isinstance(payload.get("put_credentials_artifact"), dict)
                else None
            ),
            session_creds=session_creds,
            captured_stream_url=str(payload.get("captured_stream_url") or "").strip() or None,
            captured_token_value=str(payload.get("captured_token_value") or "").strip() or None,
        )

    def merge(self, other: "CloudShellBrowserAuthContext") -> "CloudShellBrowserAuthContext":
        """Fold a freshly observed context over a cached one, newest wins."""
        from cloudbasher.core.exceptions import CloudShellAutomationError

        if self.region != other.region:
            raise CloudShellAutomationError(
                f"Cannot merge browser auth contexts across regions: {self.region} != {other.region}"
            )
        return CloudShellBrowserAuthContext(
            region=self.region,
            environment_id=other.environment_id,
            auth_code=other.auth_code or self.auth_code,
            code_verifier=other.code_verifier or self.code_verifier,
            redirect_uri=other.redirect_uri or self.redirect_uri,
            key_base=other.key_base or self.key_base,
            refresh_token=other.refresh_token or self.refresh_token,
            captured_at=other.captured_at or self.captured_at,
            source=other.source or self.source,
            redeem_code_request_id=other.redeem_code_request_id or self.redeem_code_request_id,
            put_credentials_request_id=other.put_credentials_request_id
            or self.put_credentials_request_id,
            redeem_code_artifact=other.redeem_code_artifact or self.redeem_code_artifact,
            put_credentials_artifact=other.put_credentials_artifact
            or self.put_credentials_artifact,
            session_creds=other.session_creds or self.session_creds,
            captured_stream_url=other.captured_stream_url or self.captured_stream_url,
            captured_token_value=other.captured_token_value or self.captured_token_value,
        )


CONSOLE_MFA_KEYS = mfa_keys.CONSOLE
SSO_MFA_KEYS = mfa_keys.SSO


@dataclass
class AwsConsoleCreds:
    """Username/password credentials for AWS console login via Playwright."""

    username: str
    password: str
    account: str = ""


    mfa_secret: str = ""


    mfa_ref: str = ""


    provision_region: str = ""
    provision_index: str = ""

    @property
    def identity_axis(self) -> str:
        """WHOSE line this is, for `#435`'s repeat suppression. `#843`."""
        return f"{self.account}|{self.username}"


_PROVISION_REGION_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-*?[],")


def _validated_provision_region(value: Optional[str]) -> str:
    """`REGION=` from a -F block, or "" when absent."""
    text = (value or "").strip()
    if not text:
        return ""
    if text.upper() == "ALL":
        return "ALL"
    if not set(text.lower()) <= _PROVISION_REGION_CHARS:
        raise CredentialError(
            f"REGION={value!r} is not a region selector. Use one region "
            "(us-west-2), a comma-list (us-east-1,us-west-2), a glob (us-*), "
            "or ALL."
        )
    return text.lower()


def _validated_provision_index(value: Optional[str]) -> str:
    """`INDEX=` from a -F block, or "" when absent."""
    text = (value or "").strip()
    if not text:
        return ""
    parts = text.split("-")
    if len(parts) > 2 or not all(p.isdigit() and p for p in parts):
        raise CredentialError(
            f"INDEX={value!r} is not a position. Use N (a single suffixed "
            "name) or N-M (an inclusive range)."
        )


    if any(int(p) < 1 for p in parts):
        raise CredentialError(f"INDEX={value!r} starts below 1 -- positions are 1-based.")
    if len(parts) == 2 and int(parts[0]) > int(parts[1]):
        raise CredentialError(
            f"INDEX={value!r} runs backwards -- N-M is inclusive and needs N <= M."
        )
    return text


def _normalise_sso_flow(value: Any) -> str:
    """Fold a declared `SSO_FLOW` to one of `SSO_FLOWS`, or raise."""
    text = str(value or "").strip().lower()
    if not text:
        return SSO_FLOW_BROWSER
    if text not in SSO_FLOWS:
        raise CredentialError(
            f"SSO_FLOW={value!r} is not recognised. Use one of: "
            f"{', '.join(SSO_FLOWS)} (browser = type 4, drives the portal in "
            "Playwright; device = type 5, the OIDC device-code grant)."
        )
    return text


SSO_FLOW_BROWSER = "browser"
SSO_FLOW_DEVICE = "device"
SSO_FLOWS = (SSO_FLOW_BROWSER, SSO_FLOW_DEVICE)


@dataclass
class AwsSSOCreds:
    """An IAM Identity Center block -- credential type 4 or 5, per `flow`."""

    sso_start_url: str
    account_id: str = ""
    role_name: str = ""
    sso_flow: str = SSO_FLOW_BROWSER
    sso_region: str = ""


    sso_username: str = ""
    sso_password: str = ""


    provision_region: str = ""
    provision_index: str = ""


    sso_mfa_secret: str = ""


    sso_mfa_ref: str = ""


_NO_SSO_LOGIN = (
    "Add SSO_USERNAME and SSO_PASSWORD -- the Identity Center PORTAL login "
    "(<company>.awsapps.com), which is not the same principal as an AWS console "
    "username/password.\n"
    "  Or SSO_FLOW=device, which needs no login here at all: you approve a code "
    "in a browser you already have open."
)


def _first_of(view: dict, keys: "tuple[str, ...]") -> str:
    """The first non-empty value among ``keys``, stripped, or ``""``."""
    for key in keys:
        value = str(view.get(key) or "").strip()
        if value:
            return value
    return ""


def is_sso_extra(extra: "dict") -> bool:
    """Is this flattened credential block an Identity Center (SSO) one? `#531`."""
    return bool(str(extra.get("sso_start_url") or "").strip())


def sso_self_serving(extra: "dict") -> bool:
    """An SSO block that declares a way to authenticate UNATTENDED. `#531`."""
    from cloudbasher.csp.aws.commands import browser_credential_shape

    parsed = browser_credential_shape(extra)
    return isinstance(parsed, AwsSSOCreds) and not sso_cannot_self_serve(parsed)


def sso_cannot_self_serve(sso: "AwsSSOCreds") -> bool:
    """True when this block declares no way to authenticate unattended."""
    return sso.sso_flow != SSO_FLOW_DEVICE and not (sso.sso_username and sso.sso_password)


_DERIVED_FROM_EXTRA: "dict[str, Any]" = {
    "act_as": act_as_from_extra,
}

_FIELD_TYPES: "dict[type, dict[str, Any]]" = {}


def _field_types(cls: type) -> "dict[str, Any]":
    """Resolved annotations for ``cls``, cached per class."""
    hints = _FIELD_TYPES.get(cls)
    if hints is None:
        hints = get_type_hints(cls)
        _FIELD_TYPES[cls] = hints
    return hints


def _value_from_extra(name: str, hint: "Any", extra: dict) -> "tuple[bool, Any]":
    """One field's value out of ``extra``, or ``(False, None)`` meaning OMIT."""
    reader = _DERIVED_FROM_EXTRA.get(name)
    if reader is not None:
        return True, reader(extra)
    raw = extra.get(name)
    if hint is str:
        text = str(raw or "")
        return (True, text) if text else (False, None)
    if hint == Optional[str]:


        return True, (str(raw) if raw else None)
    if hint == Optional[float]:
        if raw is None or raw == "":
            return True, None
        try:
            return True, float(raw)
        except (TypeError, ValueError):


            return True, None
    raise CredentialError(
        f"internal: {name} is declared as {hint!r}, which the extra<->dataclass "
        f"boundary does not know how to carry. Add a rule to _value_from_extra() "
        f"or a reader to _DERIVED_FROM_EXTRA -- do NOT hand-list the field at a "
        f"call site, which is `#580`/`#587`."
    )


def creds_from_extra(cls: type, extra: dict) -> "Any":
    """Rebuild a credential dataclass from a flattened ``extra``, BY ITS OWN DECLARED FIELDS. The single reassembly point, for every AWS shape. `#589`."""
    hints = _field_types(cls)
    kwargs: "dict[str, Any]" = {}
    for f in fields(cls):
        present, value = _value_from_extra(f.name, hints[f.name], extra)
        if not present and f.default is MISSING and f.default_factory is MISSING:


            present, value = True, ("" if hints[f.name] is str else None)
        if present:
            kwargs[f.name] = value
    return cls(**kwargs)


def browser_creds_class(extra: dict) -> "Optional[type]":
    """Which browser-login dataclass this flattened block describes, or None."""
    if is_sso_extra(extra):
        return AwsSSOCreds
    if extra.get("username") and extra.get("password"):
        return AwsConsoleCreds
    return None


def browser_creds_from_extra(extra: dict) -> "Optional[Any]":
    """The flattened console/SSO block as its dataclass again, or None if the block is neither shape."""
    cls = browser_creds_class(extra)
    return None if cls is None else creds_from_extra(cls, extra)


def browser_extra_to_persist(extra: dict) -> "Optional[dict]":
    """The ``extra`` subset a browser (console/SSO) credential must carry across a save, keyed by the dataclass's OWN field names. `#587`."""
    cls = browser_creds_class(extra)
    if cls is None:
        return None
    return {f.name: extra[f.name] for f in fields(cls) if extra.get(f.name)}


def _act_as_to_extra(value: "ActAs") -> dict:
    """`act_as` -> the extra keys it is stored as."""
    return {"act_as_mode": value.mode}


_DERIVED_TO_EXTRA: "dict[str, Any]" = {
    "act_as": _act_as_to_extra,
}


def extra_from_creds(obj: "Any") -> dict:
    """A credential dataclass -> the flat ``extra`` it is stored as, BY ITS OWN DECLARED FIELDS. The forward half of the boundary. `#589`."""
    out: dict = {}
    for f in fields(obj):
        value = getattr(obj, f.name)
        writer = _DERIVED_TO_EXTRA.get(f.name)
        if writer is not None:
            if value is not None:
                out.update(writer(value))
            continue
        if value or (f.default is MISSING and f.default_factory is MISSING):
            out[f.name] = value
    return out


def key_extra_to_persist(extra: dict) -> dict:
    """The key-pair credential as ``state.bin``'s ``credentials`` slot. `#594`."""
    out = extra_from_creds(session_creds_from_extra(extra))


    out.setdefault("session_token", "")
    if extra.get("cached_upgrade"):
        out["cached_upgrade"] = extra["cached_upgrade"]
    return out


def signing_creds_from_extra(extra: dict) -> "AwsSessionCreds":
    """Key material ONLY, for signing a call whose identity is already decided."""
    return AwsSessionCreds(
        access_key=str(extra.get("access_key") or "").strip(),
        secret_key=str(extra.get("secret_key") or "").strip(),
        session_token=str(extra.get("session_token") or "").strip() or None,


        cred_ref=str(extra.get("cred_ref") or "").strip(),
        principal_arn=extra.get("principal_arn") or None,
    )


def session_creds_from_extra(extra: dict) -> "AwsSessionCreds":
    """``extra`` -> `AwsSessionCreds`, declared rather than enumerated. `#589`."""
    return creds_from_extra(AwsSessionCreds, extra)


def resolve_sso_to_keys(
    sso: "AwsSSOCreds",
    *,
    headless: bool = True,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> dict:
    """Turn an Identity Center block into real `ASIA` key material."""
    from cloudbasher.core.mfa import declared_note, mfa_source
    from cloudbasher.csp.aws.sso_oidc import resolve_device_credentials
    from cloudbasher.csp.aws.sso_portal import resolve_console_credentials


    sso_mfa = mfa_source(
        ref=sso.sso_mfa_ref,
        seed=sso.sso_mfa_secret,
        where="SSO credential block",
    )


    note = declared_note(SSO_MFA_KEYS, ref=sso.sso_mfa_ref, seed=sso.sso_mfa_secret)
    detail(f"SSO credential block: second factor {note}")

    if sso.sso_flow == SSO_FLOW_DEVICE:
        return resolve_device_credentials(
            region=sso.sso_region,
            start_url=sso.sso_start_url,
            account_id=sso.account_id,
            role_name=sso.role_name,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        )
    if sso_cannot_self_serve(sso):
        raise CredentialError(
            f"{sso.sso_start_url} is an SSO block with no way to sign itself in.\n"
            f"  {_NO_SSO_LOGIN}"
        )
    return resolve_console_credentials(
        start_url=sso.sso_start_url,
        username=sso.sso_username,
        mfa=sso_mfa,
        secret=sso.sso_password,
        region=sso.sso_region,
        account_id=sso.account_id,
        role_name=sso.role_name,
        headless=headless,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )


def merge_sso_keys(extra: dict, resolved: dict) -> dict:
    """Fold resolved SSO key material into a credential's flattened `extra`."""
    extra.update(resolved)
    extra.setdefault("act_as_mode", "direct")
    return extra


def sso_preflight_error(path: str) -> Optional[str]:
    """What is missing from any Identity Center block in this file, or None."""
    from cloudbasher.core.credential_file import split_blocks_by_declared_csp
    from cloudbasher.core.secret_refs import read_credential_file

    try:
        text = read_credential_file(path)


        blocks = split_blocks_by_declared_csp(text)
    except Exception:
        return None

    for index, (block, declared) in enumerate(blocks, start=1):
        if declared != "aws":
            continue
        try:
            parsed = parse_creds_text(block)
        except CredentialError:
            continue
        if not isinstance(parsed, AwsSSOCreds):
            continue
        device = parsed.sso_flow == SSO_FLOW_DEVICE


        if sso_cannot_self_serve(parsed):
            return (
                f"block {index} is an SSO block with no way to sign itself in.\n"
                f"  {_NO_SSO_LOGIN}"
            )
        flow = "SSO_FLOW=device" if device else "an SSO portal login"
        missing = [
            name
            for name, value in (
                ("SSO_REGION", parsed.sso_region),
                ("ACCOUNT_ID", parsed.account_id),
                ("ROLE_NAME", parsed.role_name),
            )
            if not value
        ]
        if missing:
            return (
                f"block {index} declares {flow} but is missing "
                f"{', '.join(missing)}.\n"
                "  SSO_REGION is the region of the Identity Center INSTANCE "
                "(not the region the shell runs in) -- it cannot be derived, "
                "because a start URL carries no region.\n"
                "  ACCOUNT_ID and ROLE_NAME are the arguments to "
                "sso:GetRoleCredentials, so without them the flow has nothing "
                "to ask for."
            )
    return None


def parse_first_aws_block(
    text: str,
) -> "AwsSessionCreds | AwsConsoleCreds | AwsSSOCreds | None":
    """The first AWS credential in ``text``, treating it as a MULTI-block file."""

    from cloudbasher.core.credential_file import split_blocks_by_declared_csp, stamp_cred_ref


    for number, (block, declared) in enumerate(split_blocks_by_declared_csp(text), 1):
        if declared != "aws":
            continue
        parsed = parse_creds_text(block)
        if parsed is not None:
            stamp_cred_ref(parsed, number)
            return parsed
    return None


def parse_creds_file(path: str) -> "AwsSessionCreds | AwsConsoleCreds | AwsSSOCreds | None":
    """Parse a credentials file and return the most specific credential type found."""
    p = Path(path).expanduser()
    if not p.exists():
        return None
    try:


        content = read_credential_file(str(p)).strip()
    except Exception:
        return None
    return parse_first_aws_block(content)


def parse_creds_text(content: str) -> "AwsSessionCreds | AwsConsoleCreds | AwsSSOCreds | None":
    """Same format detection as parse_creds_file(), but from an in-memory string."""
    content = content.strip()
    if content.startswith("{"):
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return None


        sso_view = {str(k).lower().replace("_", ""): v for k, v in data.items()}
        sso_url = sso_view.get("ssostarturl") or ""
        if sso_url:
            return AwsSSOCreds(
                sso_start_url=str(sso_url).strip(),
                account_id=str(sso_view.get("accountid") or "").strip(),
                role_name=str(sso_view.get("rolename") or "").strip(),
                sso_flow=_normalise_sso_flow(sso_view.get("ssoflow")),
                sso_region=str(sso_view.get("ssoregion") or "").strip(),
                sso_username=str(sso_view.get("ssousername") or "").strip(),
                sso_password=str(sso_view.get("ssopassword") or "").strip(),


                sso_mfa_secret=_first_of(sso_view, mfa_keys.SSO.normalised_seed_keys),
                sso_mfa_ref=_first_of(sso_view, mfa_keys.SSO.normalised_code_keys),
            )

        username = _first_of(data, ("AWS_CONSOLE_USERNAME", "username"))
        password = _first_of(data, ("AWS_CONSOLE_PASSWORD", "password"))
        if username and password:
            return AwsConsoleCreds(
                username=username,
                password=password,
                account=_first_of(data, ("AWS_CONSOLE_ACCOUNT", "account")),


                mfa_secret=_first_of(sso_view, mfa_keys.CONSOLE.normalised_seed_keys),
                mfa_ref=_first_of(sso_view, mfa_keys.CONSOLE.normalised_code_keys),
            )

        creds_block = data.get("Credentials")
        flat = creds_block if isinstance(creds_block, dict) else data


        access_key = _first_of(flat, ("AccessKeyId", "access_key_id", "aws_access_key_id"))
        secret_key = _first_of(
            flat, ("SecretAccessKey", "secret_access_key", "aws_secret_access_key")
        )
        if access_key and secret_key:


            session_token = (
                _first_of(flat, ("SessionToken", "session_token", "aws_session_token")) or None
            )


            lower = {str(k).lower(): v for k, v in flat.items()}
            if flat is not data:


                lower = {**{str(k).lower(): v for k, v in data.items()}, **lower}
            for retired in ("target_identity", "role_arn"):
                if retired in lower:
                    raise CredentialError(
                        f"{retired!r} is no longer supported; use "
                        f"ACT_AS=role:<role-arn> (or ACT_AS=federated). "
                        "The mode is now stated explicitly rather than inferred "
                        "from whether the value happens to look like an ARN."
                    )


            json_act_as = lower.get("act_as")
            if not isinstance(json_act_as, (list, tuple)):
                json_act_as = str(json_act_as or "").strip()
            act_as = parse_act_as_declaration(json_act_as) if json_act_as else None
            federation_name = str(lower.get("federation_name") or "").strip() or None
            role_session_name = str(lower.get("role_session_name") or "").strip() or None
            return AwsSessionCreds(
                access_key=access_key,
                secret_key=secret_key,
                session_token=str(session_token).strip() or None if session_token else None,
                act_as=act_as,
                **({"federation_name": federation_name} if federation_name else {}),
                **({"role_session_name": role_session_name} if role_session_name else {}),
            )
        return None


    access_key = secret_key = session_token = None
    federation_name = role_session_name = None


    act_as_raw: list[str] = []


    console_username = console_password = console_account = console_mfa_secret = None
    console_mfa_ref = None


    sso_start_url = sso_account_id = sso_role_name = None
    sso_flow = sso_region = None
    sso_login_user = sso_login_secret = sso_login_mfa = None
    sso_login_mfa_ref = None


    provision_region = provision_index = None
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if line.startswith("export "):
            line = line[7:]
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip().upper()
        v = v.strip().strip('"').strip("'")
        if k == "AWS_ACCESS_KEY_ID":
            access_key = v
        elif k == "AWS_SECRET_ACCESS_KEY":
            secret_key = v
        elif k == "AWS_SESSION_TOKEN":
            session_token = v
        elif k in ("AWS_ACCESS_KEY", "AK"):
            access_key = access_key or v
        elif k in ("AWS_SECRET_KEY", "SK"):
            secret_key = secret_key or v
        elif k in ("TARGET_IDENTITY", "ROLE_ARN"):
            raise CredentialError(
                f"{k} is no longer supported; use ACT_AS=role:<role-arn> (or "
                "ACT_AS=federated). The mode is now stated explicitly rather "
                "than inferred from whether the value happens to look like an "
                "ARN."
            )
        elif k == "ACT_AS":
            act_as_raw.append(v)
        elif k == "FEDERATION_NAME":
            federation_name = v
        elif k == "ROLE_SESSION_NAME":
            role_session_name = v
        elif k in ("AWS_CONSOLE_USERNAME", "USERNAME"):
            console_username = v
        elif k in ("AWS_CONSOLE_PASSWORD", "PASSWORD"):
            console_password = v
        elif k in ("AWS_CONSOLE_ACCOUNT", "ACCOUNT"):
            console_account = v
        elif k in mfa_keys.CONSOLE.seed_spellings:
            console_mfa_secret = v
        elif k in mfa_keys.CONSOLE.code_spellings:


            console_mfa_ref = v
        elif k == "SSO_START_URL":
            sso_start_url = v
        elif k == "ACCOUNT_ID":
            sso_account_id = v
        elif k == "ROLE_NAME":
            sso_role_name = v
        elif k == "SSO_FLOW":
            sso_flow = v
        elif k == "SSO_REGION":
            sso_region = v
        elif k == "SSO_USERNAME":
            sso_login_user = v
        elif k == "SSO_PASSWORD":
            sso_login_secret = v
        elif k in mfa_keys.SSO.seed_spellings:
            sso_login_mfa = v
        elif k in mfa_keys.SSO.code_spellings:
            sso_login_mfa_ref = v
        elif k == "REGION":


            provision_region = v
        elif k == "INDEX":
            provision_index = v


    if sso_start_url:
        return AwsSSOCreds(
            sso_start_url=sso_start_url,
            account_id=sso_account_id or "",
            role_name=sso_role_name or "",
            sso_flow=_normalise_sso_flow(sso_flow),
            sso_region=(sso_region or "").strip(),
            sso_username=str(sso_login_user or "").strip(),
            sso_password=str(sso_login_secret or "").strip(),
            sso_mfa_secret=str(sso_login_mfa or "").strip(),
            sso_mfa_ref=str(sso_login_mfa_ref or "").strip(),
            provision_region=_validated_provision_region(provision_region),
            provision_index=_validated_provision_index(provision_index),
        )

    if console_username and console_password:
        return AwsConsoleCreds(
            username=console_username,
            password=console_password,
            account=console_account or "",
            mfa_secret=console_mfa_secret or "",
            mfa_ref=console_mfa_ref or "",
            provision_region=_validated_provision_region(provision_region),
            provision_index=_validated_provision_index(provision_index),
        )

    act_as = parse_act_as_declaration(act_as_raw) if act_as_raw else None

    if access_key and secret_key:
        return AwsSessionCreds(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token or None,
            act_as=act_as,
            **({"federation_name": federation_name} if federation_name else {}),
            **({"role_session_name": role_session_name} if role_session_name else {}),
            provision_region=_validated_provision_region(provision_region),
            provision_index=_validated_provision_index(provision_index),
        )
    return None


@dataclass(frozen=True)
class TargetIdentity:
    """The STS derivation an AKIA (permanent) credential will undergo, and the name that derivation will carry -- i.e. exactly what the in-container ``aws sts get-caller-identity`` will report."""

    kind: str
    ref: str
    session_name: Optional[str] = None
    duration_seconds: Optional[int] = None


    name_source: str = field(kw_only=True)


EXPLICIT = "explicit"


def resolve_identity_name(
    creds: AwsSessionCreds,
    requested: Optional[str],
    *,
    where: str,
    derives: Optional[str] = None,
    role_arn: Optional[str] = None,
) -> tuple[str, str]:
    """Decide the derived principal's NAME for one action, and say where it came from."""


    if derives:
        require_act_as_permits(
            creds.act_as,
            derives=derives,
            role_arn=role_arn,
            where=where,
        )

    if requested and requested.strip():
        return requested.strip(), EXPLICIT

    from cloudbasher.csp.aws.act_as import DIRECT_MODES

    kind = derives or (creds.act_as.mode if creds.act_as else "")
    if kind in DIRECT_MODES:


        raise CredentialError(
            f"ACT_AS={kind} has no derivation, so there is no identity name to "
            "resolve -- the supplied credential IS the identity."
        )


    declared = creds.role_session_name if kind == "role" else creds.federation_name
    if declared and declared.strip():
        return declared.strip(), "declared"

    declared_key = "ROLE_SESSION_NAME" if kind == "role" else "FEDERATION_NAME"
    other_key = "FEDERATION_NAME" if kind == "role" else "ROLE_SESSION_NAME"
    other_declared = (creds.federation_name if kind == "role" else creds.role_session_name) or ""
    other_derived = (
        f"federated-user/{other_declared}"
        if kind == "role"
        else f"assumed-role/<role>/{other_declared}"
    )


    example = ".provision <ID> as <name>"

    if other_declared.strip():


        headline = (
            f"{where} has no {declared_key.lower().replace('_', '-')} to use.\n"
            f"The block declares {other_key}={other_declared.strip()}, but that name "
            f"authorises {other_derived} only -- a different principal from the one "
            f"this action derives, with its own private view of which environments "
            f"exist. A declared name is scoped to the derivation it names, and the "
            f"key's name says which.\n"
            f"  name it per action:  `{example}`\n"
            f"  declare a default:   add {declared_key}=<name> to the same block "
            f"({other_key} stays as it is)"
        )
    else:
        headline = (
            f"{where} needs an identity name, and none was given.\n"
            "The name is what makes a distinct principal, and CloudShell shows each "
            "principal only its own environments -- so there is no safe default. A "
            "name CloudBasher picked would silently decide which environments you "
            "can see.\n"
            f"  name it per action:  `{example}`\n"
            f"  declare a default:   {declared_key}=<name> in the credential block"
        )


    raise CredentialError(
        headline + "\n  or set it per run:   --as <name> on the command line (-c/--run)"
    )


def describe_name_source(name_source: str, *, key: str) -> str:
    """One-line provenance sentence for a name resolve_identity_name() just resolved -- shared by every display site (cli/main.py's _emit_target_identity() and the four .provision command handlers in csp/aws/commands.py) so "explicit" and "declared" read as one feature instead of being retyped, and inevitably drifting, at each call site."""
    if name_source == EXPLICIT:
        return "name source: explicitly set for this action (`as <name>`)"
    return (
        f"name source: declared in the credential block ({key}). This name is a "
        f"namespace -- CloudShell only shows environments created under it. Edit "
        f"{key} in the credential block to use a different one."
    )


def resolve_target_identity(
    creds: AwsSessionCreds, *, name: str, name_source: str
) -> TargetIdentity:
    """Decide which STS derivation ``creds`` gets upgraded through, carrying the NAME (and its provenance) the caller already resolved via resolve_identity_name(). THE single decision point for the derivation KIND -- see the module comment above."""
    if creds.act_as is None:
        raise CredentialError(
            "This AWS credential has no ACT_AS declaration -- declare it in "
            "the -F credentials file (ACT_AS=role:<arn> | ACT_AS=federated | "
            "ACT_AS=direct) or load it through a named source (-F, "
            "--creds-env, --resume) that enforces the declaration.\n"
            "(internal: resolve_target_identity() must never be reached with "
            "act_as=None -- the source boundary at cli/main.py:_require_act_as "
            "should have rejected this credential already.)"
        )
    from cloudbasher.csp.aws.act_as import DIRECT_MODES

    if creds.act_as.mode in DIRECT_MODES:
        raise CredentialError(
            f"ACT_AS={creds.act_as.mode} has no derivation -- the supplied "
            "credential IS the identity. Callers must not ask for a target "
            "identity here."
        )
    if creds.act_as.mode == "role":


        return TargetIdentity(
            kind="assume_role",
            ref=creds.act_as.role_arn or "",
            session_name=name,
            name_source=name_source,
        )
    if creds.act_as.mode == "federated":
        return TargetIdentity(
            kind="federation_token",
            ref=name,
            name_source=name_source,
        )


    raise CredentialError(
        f"resolve_target_identity() has no mapping for ACT_AS={creds.act_as.mode!r}. "
        "This is a code gap, not a user error: a mode was added to "
        "act_as.parse_act_as() without deciding what it derives."
    )


_DERIVED: "dict[tuple, AwsSessionCreds]" = {}


_DERIVE_MAP_LOCK = threading.Lock()


_DERIVE_LOCKS = KeyedLocks()


_UNCACHEABLE: "set[tuple]" = set()


derive_notice_sink: Any = detail


def _derive_cache_key(creds: "AwsSessionCreds", identity: "TargetIdentity") -> Optional[tuple]:
    """The identity of a derivation, or None if it must not be cached."""
    if not creds.access_key or not identity.kind:
        return None
    return (
        creds.access_key,
        identity.kind,
        identity.ref or "",
        identity.session_name,
        identity.duration_seconds,
    )


def _cached_derivation(key: tuple) -> "tuple[Optional[AwsSessionCreds], Optional[str]]":
    """`(usable entry, why-it-is-stale)`. Both None means a plain miss. `#502`."""
    with _DERIVE_MAP_LOCK:
        hit = _DERIVED.get(key)
        if hit is None:
            return None, None
        why = credential_refresh_reason(hit)
        if why is None:
            return hit, None


        _DERIVED.pop(key, None)
    return None, why


def reset_derive_cache() -> None:
    """Forget every memoised derivation."""
    with _DERIVE_MAP_LOCK:
        _DERIVED.clear()
        _DERIVE_LOCKS.forget()
        _UNCACHEABLE.clear()


def derive_target_credentials(
    creds: AwsSessionCreds,
    identity: TargetIdentity,
    *,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> AwsSessionCreds:
    """Execute the one STS call ``identity`` describes, returning ASIA creds."""
    key = _derive_cache_key(creds, identity)
    if key is None:

        return _derive_target_credentials_uncached(
            creds, identity, proxy_url=proxy_url, proxy_insecure=proxy_insecure
        )

    got, stale_reason = _cached_derivation(key)
    if got is not None:
        return got
    if stale_reason is not None:


        derive_notice_sink(f"[derive] re-deriving {identity.kind}:{identity.ref}: {stale_reason}")
    if key in _UNCACHEABLE:


        return _derive_target_credentials_uncached(
            creds, identity, proxy_url=proxy_url, proxy_insecure=proxy_insecure
        )


    with _DERIVE_LOCKS.lock_for(key):


        got, _ = _cached_derivation(key)
        if got is not None:
            return got
        fresh = _derive_target_credentials_uncached(
            creds, identity, proxy_url=proxy_url, proxy_insecure=proxy_insecure
        )


        with _DERIVE_MAP_LOCK:
            if credential_is_verifiable(fresh):
                _DERIVED[key] = fresh
            else:


                _UNCACHEABLE.add(key)


                _DERIVE_LOCKS.retire(key)
        return fresh


def _derive_target_credentials_uncached(
    creds: AwsSessionCreds,
    identity: TargetIdentity,
    *,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> AwsSessionCreds:
    """`derive_target_credentials()` with the memo removed -- the STS call itself."""
    from cloudbasher.csp.aws.sts import sts_assume_role, sts_get_federation_token

    duration = (
        {} if identity.duration_seconds is None else {"duration_seconds": identity.duration_seconds}
    )
    if identity.kind == "assume_role":


        if not duration:
            from cloudbasher.csp.aws.sts import role_max_session_duration

            discovered = role_max_session_duration(
                creds=creds,
                role_arn=identity.ref,
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
            )
            if discovered:
                duration = {"duration_seconds": discovered}


        return sts_assume_role(
            creds=creds,
            role_arn=identity.ref,
            role_session_name=identity.session_name or "",
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
            **duration,
        )
    if identity.kind == "federation_token":
        return sts_get_federation_token(
            creds=creds,
            name=identity.ref,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
            **duration,
        )
    raise CredentialError(f"unknown target identity kind {identity.kind!r}")


_CHAIN_DERIVE_LOCK = threading.Lock()


def resolve_credential_chain(
    record: CredentialRecord,
    registry: dict[str, CredentialRecord],
    *,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> AwsSessionCreds:
    """Walk record.parent_id back to the AKIA root, then re-derive forward hop-by-hop via sts_assume_role/sts_get_federation_token."""
    chain: list[CredentialRecord] = []
    seen: set[str] = set()
    cur: Optional[CredentialRecord] = record
    while cur is not None:
        if cur.id in seen:
            raise CredentialError(f"Credential chain cycle detected at {cur.id}")
        seen.add(cur.id)
        chain.append(cur)
        cur = registry.get(cur.parent_id) if cur.parent_id else None
    chain.reverse()

    root = chain[0]


    current = session_creds_from_extra(root.raw.extra)

    with _CHAIN_DERIVE_LOCK:
        for hop in chain[1:]:
            if hop.derived is not None:
                cached = AwsSessionCreds.from_cache_dict(hop.derived)


                stale = credential_refresh_reason(cached)
                verifiable = credential_is_verifiable(cached)
                if cached.access_key and cached.secret_key and verifiable and stale is None:
                    current = cached
                    continue


                detail(
                    f"[chain] re-deriving hop {hop.id}: "
                    + (
                        stale
                        or "the cached credential carries no expiry, so it "
                        "cannot be confirmed still valid"
                    )
                )
            if not hop.target_kind:
                raise CredentialError(f"Credential chain hop {hop.id} has no target_kind set")


            current = derive_target_credentials(
                current,
                TargetIdentity(
                    kind=hop.target_kind,
                    ref=hop.target_ref or "",
                    session_name=hop.target_session_name,
                    duration_seconds=hop.target_duration_seconds,


                    name_source="declared",
                ),
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
            )
            hop.derived = current.to_cache_dict()

    return current


_ENV_REQUIRED = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")


def preflight_env_error() -> Optional[str]:
    """Why `--creds-env` cannot work for AWS right now, or None if it can."""
    missing = [name for name in _ENV_REQUIRED if not os.getenv(name)]
    if not missing:
        return None
    return (
        f"--creds-env: {' and '.join(missing)} "
        f"{'is' if len(missing) == 1 else 'are'} not set in this environment.\n"
        "\n"
        "--creds-env is a valid source -- it reads this identity from the "
        "environment, so set the variables:\n"
        "  export AWS_ACCESS_KEY_ID=AKIA...\n"
        "  export AWS_SECRET_ACCESS_KEY=...\n"
        "  export AWS_SESSION_TOKEN=...     # temporary (ASIA) keys only\n"
        "  export ACT_AS=federated          # or role:<role-arn>, or direct\n"
        "\n"
        "Or read the identity from a file instead: -F/--creds-file PATH.\n"
        "There is no ambient fallback -- ~/.aws/credentials, the ECS container "
        "role and EC2 IMDS are not consulted."
    )


class AWSCredentialProvider(CredentialProvider):
    """AWS credential loader."""

    def __init__(
        self,
        *,
        credential_file: Optional[str] = None,
        device_code: bool = False,
        region: Optional[str] = None,
        saved_state: Optional[dict] = None,
        source: str = "file",
    ) -> None:
        self.credential_file = credential_file
        self.device_code = device_code


        self.region = region or ""
        self.saved_state: dict = saved_state or {}
        self.source = source
        self._cached_creds: Optional[Credentials] = None

    def load(self) -> Credentials:
        """Load AWS credentials from exactly the one named source."""
        if self._cached_creds:
            return self._cached_creds

        if self.device_code:
            raise CredentialError(
                "AWS does not support --device-code; use --creds-file, "
                "--creds-env, or --resume instead."
            )


        if self.source == "resume" or self.saved_state:
            creds = self._load_from_saved_state()
            if creds:
                detail("credential_source=saved_state")
                self._cached_creds = creds
                return creds
            if self.source == "resume":
                raise CredentialError(
                    "--resume: no saved credentials in the state file. Start with "
                    "--creds-file or --creds-env."
                )

        if self.source == "file":
            if not self.credential_file:
                raise CredentialError(
                    "credential source is 'file' but no path was given; pass "
                    "-F/--creds-file PATH."
                )
            creds = self._load_from_file(self.credential_file)
            if creds:
                detail(f"credential_source=file path={self.credential_file}")
                self._cached_creds = creds
                return creds


            raise CredentialError(
                f"{self.credential_file}: no AWS credential block could be loaded."
            )

        if self.source == "env":
            creds = self._load_from_env()
            if creds:
                detail("credential_source=environment_variables")
                self._cached_creds = creds
                return creds


            raise CredentialError(
                preflight_env_error()
                or "--creds-env: no usable AWS credentials in the environment."
            )

        raise CredentialError(f"unknown credential source {self.source!r}")

    def refresh(self) -> Credentials:
        """Refresh credentials (for temporary credentials)."""
        self._cached_creds = None
        return self.load()

    @staticmethod
    def _console_creds_from_saved_state(cred: dict) -> Optional[Credentials]:
        """A console identity restored from saved state, or None."""
        username = cred.get("username", "")
        password = cred.get("password", "")
        if not (username and password):
            return None
        detail("credential_source=saved_state kind=console")


        return Credentials(
            provider="aws",
            email=username,
            extra=browser_extra_to_persist(cred) or {},
        )

    def _load_from_saved_state(self) -> Optional[Credentials]:
        """Load credentials from decrypted saved state (--resume)."""
        cred = self.saved_state.get("credentials", {})
        access_key = cred.get("access_key", "")
        secret_key = cred.get("secret_key", "")
        if not (access_key and secret_key):


            console = self._console_creds_from_saved_state(cred)
            if console is not None:
                return console
            return None
        session_token = cred.get("session_token") or None

        cached_upgrade = cred.get("cached_upgrade")
        if cached_upgrade:
            upgraded = AwsSessionCreds.from_cache_dict(cached_upgrade)
            if upgraded.access_key and upgraded.secret_key and not upgraded.is_expired():
                detail("credential_source=saved_state cached_upgrade=valid")
                access_key, secret_key, session_token = (
                    upgraded.access_key,
                    upgraded.secret_key,
                    upgraded.session_token,
                )

        extra: dict[str, Any] = {
            "access_key": access_key,
            "secret_key": secret_key,
            "session_token": session_token,
            "region": self.region,
        }


        carry_aws_identity_keys(cred, extra)
        return Credentials(
            provider="aws",
            access_token=None,
            session_id=None,
            extra=extra,
        )

    def _load_from_env(self) -> Optional[Credentials]:
        """Load credentials from environment variables."""
        access_key = os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        session_token = os.getenv("AWS_SESSION_TOKEN")

        if not (access_key and secret_key):
            return None


        env_act_as = os.getenv("ACT_AS")
        act_as = parse_act_as_declaration(env_act_as) if env_act_as else None
        federation_name = os.getenv("FEDERATION_NAME") or None
        role_session_name = os.getenv("ROLE_SESSION_NAME") or None


        parsed = AwsSessionCreds(
            cred_ref="env",
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token or None,
            act_as=act_as,
            **({"federation_name": federation_name} if federation_name else {}),
            **({"role_session_name": role_session_name} if role_session_name else {}),
        )
        return self._session_creds_to_credentials(parsed)

    def _session_creds_to_credentials(self, parsed: "AwsSessionCreds") -> Credentials:
        """The parsed `-F` block -> the `extra` everything downstream reads."""
        extra: dict[str, Any] = extra_from_creds(parsed)
        extra["region"] = self.region
        return Credentials(
            provider="aws",
            access_token=None,
            session_id=None,
            extra=extra,
        )

    def _load_from_file(self, path: str) -> Optional[Credentials]:
        """Load credentials from an explicit `-F`/`--credentials` file."""
        p = Path(path).expanduser()
        if not p.exists():
            raise CredentialError(f"Credentials file not found: {path}")


        from cloudbasher.core.secret_refs import read_credential_file

        try:
            content = read_credential_file(str(p))
        except CredentialError:
            raise
        except Exception as e:
            raise CredentialError(f"Failed to read credentials file {path}: {e}")


        parsed = parse_first_aws_block(content)
        if isinstance(parsed, AwsSessionCreds):
            return self._session_creds_to_credentials(parsed)
        if isinstance(parsed, (AwsConsoleCreds, AwsSSOCreds)):


            return Credentials(provider="aws", extra=extra_from_creds(parsed))

        raise CredentialError(
            f"Could not parse AWS credentials from {path} -- expected an "
            f"access key (JSON, or shell `export AWS_ACCESS_KEY_ID=...` / "
            f"INI lines), a console username/password JSON block, or an "
            f"SSO start-URL JSON block. See creds.rc.example for the "
            f"supported shapes."
        )
