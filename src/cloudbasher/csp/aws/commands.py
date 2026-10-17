"""AWS-specific dot commands registered via AWSProvider.register_dot_commands()."""

from __future__ import annotations

import csv
import os
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Callable, Iterator, NamedTuple, Optional

from cloudbasher.core.browser_options import browser_options
from cloudbasher.core.cancel import (
    OperationCancelled,
    in_flight,
    report_cancellation,
    skip_if_cancelled,
)
from cloudbasher.core.cli.command_spec import (
    CommandSpec,
    Effects,
    Flag,
    Keyword,
    ParseResult,
    Positional,
    Rest,
    Slot,
    SlotKind,
    Verb,
    usage,
)
from cloudbasher.core.config import switch
from cloudbasher.core.exceptions import CloudBasherError, CredentialError
from cloudbasher.core.utils.output import (
    detail,
    eprint,
    log,
    log_file_only,
    log_scope,
    mask_secrets,
    out,
)
from cloudbasher.core.utils.perf_config import pool_width


from cloudbasher.csp.aws.act_as import (
    DERIVING_MODES,
    DIRECT_MODES,
    PROVISION_KEYWORDS,
    DerivationState,
    act_as_from_extra,
    act_as_permits,
    can_derive,
    derivation_state,
    derives_nothing_because,
    require_act_as_permits,
)
from cloudbasher.csp.aws.credentials import describe_name_source, resolve_identity_name
from cloudbasher.csp.aws.failure import (
    note_node_failure,
    probe_verdict,
    refusal_detail,
)
from cloudbasher.csp.aws.provision_request import (
    DECLARED,
    INDEX_NONE,
    PROVISION_REGION_CAP,
    TYPED,
    TYPED_NONE,
    PlannedTarget,
    ProvisionRequest,
    act_as_mode,
    all_derived_targets,
    asks_derivation,
    dedup_credential_ids,
    effective_index,
    is_index_none,
    plan_targets,
    provisioned_regions,
    render_plan,
    resolve_defaults,
    validate_duration,
    validate_name,
)

if TYPE_CHECKING:


    from cloudbasher.core.cli.dispatcher import Guard
    from cloudbasher.core.types import (
        CredentialRecord,
        InteractiveState,
        NodeRecord,
    )
    from cloudbasher.csp.aws.credentials import AwsSessionCreds


BROWSER_COST_ONE_LOGIN = "one-login"
BROWSER_COST_PER_REGION = "login-per-region"


def cmd_region(r: "ParseResult", state: "InteractiveState") -> bool:
    """.region [selector] — show or set the active AWS region."""
    selector = r.positionals.get("selector")
    if selector is None:
        region = state.session.region if state.session else "unknown"
        out(f"Region: {region}")
        return True


    try:
        from cloudbasher.csp.aws.multi_region import resolve_regions

        regions = resolve_regions(selector)
    except Exception as e:
        eprint(f"region: could not resolve {selector!r}: {e}")
        return True

    if not regions:
        eprint(f"region: no regions matched {selector!r}")
        return True

    if len(regions) > 1:
        out(f"Matched {len(regions)} regions: {', '.join(regions)}")
        out("(Use .region <single-region> to switch to one region)")
        return True

    new_region = regions[0]
    if state.session:
        state.session.region = new_region

    api_client = getattr(state, "api_client", None)
    if api_client is not None and hasattr(api_client, "region"):
        api_client.region = new_region


    old_session = getattr(state, "_session_obj", None)
    if old_session is not None:
        try:
            old_session.close()
        except Exception:
            pass
        state._session_obj = None
        state.in_shell_mode = False
        out(
            "Shell session closed (was bound to the previous region) — "
            "reconnect to use the shell in the new region."
        )

    out(f"Active region set to: {new_region}")
    log(f"[region] set region={new_region}")
    return True


GETUPLOADURLS_SPEC = CommandSpec(
    name="getuploadurls",
    summary="Get an S3 pre-signed upload URL for a path",
    effects=Effects.READ_ONLY,
    terminals=(Positional("remote_path", required=True, kind="path"),),
)

GETDOWNLOADURLS_SPEC = CommandSpec(
    name="getdownloadurls",
    summary="Get an S3 pre-signed download URL for a path",
    effects=Effects.READ_ONLY,
    terminals=(Positional("remote_path", required=True, kind="path"),),
)


def _presign_target(state: "InteractiveState", verb: str) -> "Optional[tuple[Any, str]]":
    """`(api_client, environment_id)` for a presign probe, or None if refused."""
    from cloudbasher.core.cli.dispatcher import resolve_node_for_action

    target = resolve_node_for_action(state.csp_provider, state, verb)
    return None if target is None else (target[0], target[1])


def _emit_presign(verb: str, env_id: str, remote_path: str, pairs: "list[tuple[str, str]]") -> None:
    """Print a presign result to the terminal AND record it in the log."""
    for label, value in pairs:
        out(f"{label:<13}: {value}")
    log(
        f"[{verb}] env_id={env_id} path={remote_path} "
        + " ".join(f"{k.lower().replace(' ', '_')}={v}" for k, v in pairs)
    )


def cmd_getuploadurls(r: "ParseResult", state: "InteractiveState") -> bool:
    """.getuploadurls <remote_path> — show presigned upload URL details."""

    target = _presign_target(state, "getuploadurls")
    if target is None:
        return True
    api, env_id = target
    remote_path = r.positionals["remote_path"]
    try:
        result = api.get_file_upload_urls(env_id, remote_path)
    except Exception as e:
        eprint(f"getuploadurls failed: {e}")
        return True
    pairs = [
        ("Upload URL", result.get("upload_url", "N/A")),
        ("Download URL", result.get("download_url", "N/A")),
        ("Download key", result.get("download_key", "N/A")),
    ]
    _emit_presign("getuploadurls", env_id, remote_path, pairs)
    fields = result.get("upload_fields", {})
    if fields:
        out("Upload fields:")
        for k, v in fields.items():
            out(f"  {k}: {v}")
    return True


def cmd_getdownloadurls(r: "ParseResult", state: "InteractiveState") -> bool:
    """.getdownloadurls <remote_path> — show presigned download URL details."""

    target = _presign_target(state, "getdownloadurls")
    if target is None:
        return True
    api, env_id = target
    remote_path = r.positionals["remote_path"]
    try:
        result = api.get_file_download_urls(env_id, remote_path)
    except Exception as e:
        eprint(f"getdownloadurls failed: {e}")
        return True
    _emit_presign(
        "getdownloadurls",
        env_id,
        remote_path,
        [
            ("Download URL", result.get("download_url", "N/A")),
            ("Download key", result.get("download_key", "N/A")),
            ("Upload URL", result.get("upload_url", "N/A")),
        ],
    )
    return True


def _originating_for_node(
    state: "InteractiveState", node_id: Optional[str]
) -> Optional["CredentialRecord"]:
    """The AWS originating record behind one node, walking a target back to it."""
    from cloudbasher.core.selection import originating_for_node

    return originating_for_node(state, node_id, provider="aws")


def _node_aws_credential(state: "InteractiveState") -> Optional["CredentialRecord"]:
    """The AWS originating record the user means by "the current node"."""
    recs = _credentials_behind_selection(state)
    if len(recs) == 1:
        return recs[0]
    if len(recs) > 1:
        return None
    return _originating_for_node(state, getattr(state, "active_node_id", None))


def _credentials_behind_selection(state: "InteractiveState") -> list["CredentialRecord"]:
    """Distinct AWS originating records behind the currently ticked rows."""
    from cloudbasher.core.selection import selected_credential_records

    return selected_credential_records(state, provider="aws")


def _record_permits(
    rec: "CredentialRecord", derives: Optional[str], role_arn: Optional[str]
) -> bool:

    if derives is None:
        return True


    return act_as_permits(act_as_from_extra(rec.raw.extra), derives, role_arn)


def _derivation_refusal(
    rec: "CredentialRecord",
    derives: Optional[str],
    role_arn: Optional[str],
    *,
    verb: str,
) -> Optional[str]:
    """`_record_permits` as a MESSAGE -- the same question, said out loud."""
    if derives is None:
        return None
    declared = act_as_from_extra(rec.raw.extra)
    if declared is None:


        wanted = "assume a role" if derives == "role" else "federate"
        return (
            f"{verb}: credential [{rec.label}] signs in through the browser, so "
            f"there is no key to {wanted} with. A console or SSO block declares "
            "no ACT_AS -- it IS the identity. Drop "
            f"`{'role' if derives == 'role' else 'federation'}` and name the "
            "region(s) instead."
        )
    try:
        require_act_as_permits(declared, derives=derives, role_arn=role_arn, where=verb)
    except CredentialError as exc:
        return str(exc)
    return None


def cmd_creds_refresh(
    args: list[str], state: "InteractiveState", *, extra: Optional[list[str]] = None
) -> bool:
    """`.creds <ID>|selected refresh` -- re-derive, then re-install (I7)."""
    if extra:
        eprint(f"creds refresh: unexpected argument(s) {' '.join(extra)!r}")
        return True
    selector = args[0] if args else "selected"

    rec, err = _resolve_aws_originating_credential(state, selector=selector)
    if err is not None:
        eprint(f"creds refresh: {err}")
        return True
    assert rec is not None

    mode = act_as_mode(rec)
    if mode not in DERIVING_MODES:


        how = derives_nothing_because(rec.raw.extra, kind=getattr(rec, "kind", ""))
        eprint(
            f"creds refresh: credential [{selector}] {how} -- there is nothing "
            "to re-derive. Only ACT_AS=role and ACT_AS=federated mint a new "
            "token from a longer-lived one."
        )
        return True

    nodes = [
        n
        for n in (getattr(state, "nodes_by_id", None) or {}).values()
        if _originating_for_node(state, n.id) is not None
        and _originating_for_node(state, n.id).id == rec.id
    ]
    if not nodes:
        eprint(
            f"creds refresh: credential [{selector}] has no nodes -- there is "
            "no client holding a derived token and no container to install one "
            "into. Provision it first."
        )
        return True

    out(f"Refreshing credential [{selector}] across {len(nodes)} node(s)...")
    rederived = reprojected = 0
    unprojectable: list[str] = []
    for node in nodes:
        api = getattr(node, "_runtime_api_client", None)
        if api is not None and hasattr(api, "_cached_api_creds"):


            api._cached_api_creds = None
            rederived += 1
        reproject = getattr(node, "_runtime_reprojector", None)
        if reproject is None:
            unprojectable.append(str(getattr(node, "id", "?")))
            continue
        try:
            reproject()
            reprojected += 1
        except Exception as exc:  # noqa: BLE001 -- reported per node, never fatal
            eprint(f"creds refresh: {node.id}: re-projection failed: {exc}")

    out(
        f"creds refresh: re-derivation armed on {rederived} client(s); "
        f"re-projected into {reprojected} container(s)."
    )
    if unprojectable:


        eprint(
            "creds refresh: no credential is projected into "
            f"{', '.join(unprojectable)} -- their shells keep whatever they "
            "had. ACT_AS=direct-unbound declares this deliberately."
        )
    return True


def _refused_credential_error(rec: "CredentialRecord", selector: Any) -> Optional[str]:
    """Refuse a credential already OBSERVED to be dead, or None to proceed."""
    if getattr(rec, "status", "valid") != "invalid":
        return None
    return (
        f"credential [{selector}] was refused by AWS earlier in this session "
        f"({rec.label}) -- it is expired or revoked, so this would fail the "
        "same way. Supply a fresh one, or `.creds` to see the state. A "
        "credential that starts working again clears on its next successful "
        "connect."
    )


def _resolve_aws_originating_credential(
    state: "InteractiveState",
    *,
    derives: Optional[str] = None,
    role_arn: Optional[str] = None,
    selector: Optional[str] = None,
) -> tuple[Optional["CredentialRecord"], Optional[str]]:
    """Resolve which AWS originating credential an action acts FROM."""
    from cloudbasher.core.types import numbered_originating_records

    numbered = numbered_originating_records(state.credentials_by_id)

    if selector is not None and selector.strip().lower() != "selected":
        token = selector.strip()
        if not token.isdigit():
            return None, (
                f"{token!r} is not a credential selector -- use `selected` for the "
                "active node's credential, or an <ID> from the Nodes pane / identity listing"
            )
        want = int(token)
        match = [rec for n, rec in numbered if n == want]
        if not match:
            return None, (
                f"no credential [{want}] is loaded -- the identity listing numbers "
                f"1..{len(numbered)}"
            )
        if match[0].provider != "aws":
            return None, (
                f"credential [{want}] is {match[0].provider}, not AWS -- " f"{match[0].label}"
            )
        refused = _refused_credential_error(match[0], want)
        if refused is not None:
            return None, refused


        return match[0], None

    aws = [(n, rec) for n, rec in numbered if rec.provider == "aws"]
    if not aws:
        return None, "no AWS credential is loaded"

    node_rec = _node_aws_credential(state)
    if selector is not None:
        if node_rec is None:
            spanning = _credentials_behind_selection(state)
            if len(spanning) > 1:


                names = "; ".join(
                    f"[{n}] {rec.label}"
                    for n, rec in numbered
                    if any(rec.id == s.id for s in spanning)
                )
                return None, (
                    f"the selected row(s) span {len(spanning)} credentials, so "
                    f"`selected` has no single answer -- name one: {names}"
                )
            return None, (
                "`selected` means the credential behind the selected row(s) (or the "
                "active node) -- nothing is selected and no node is active. Tick a "
                "row, or name an <ID> from the Nodes pane / identity listing."
            )
        return node_rec, None

    eligible = [(n, rec) for n, rec in aws if _record_permits(rec, derives, role_arn)]
    if node_rec is not None and any(rec is node_rec for _n, rec in eligible):
        return node_rec, None
    if len(eligible) == 1:
        return eligible[0][1], None

    if not eligible:

        mode_only = [rec for _n, rec in aws if _record_permits(rec, derives, None)]
        fallback = mode_only[0] if mode_only else node_rec
        if fallback is None and len(aws) == 1:
            fallback = aws[0][1]
        if fallback is not None:
            return fallback, None
        return None, (
            "no loaded AWS credential declares "
            f"{'ACT_AS=role' if derives == 'role' else 'ACT_AS=federated'}"
        )

    listing = "; ".join(f"[{n}] {rec.label}" for n, rec in eligible)
    return None, (
        f"more than one AWS credential could do this and no node is active to "
        f"choose one -- name it: {listing}"
    )


def _session_creds_for(rec: "CredentialRecord") -> "AwsSessionCreds":
    """The rec.raw.extra -> AwsSessionCreds hop, in one place. Three sites in this module hand-rolled it before; a fourth copy is how identity keys got silently dropped at three earlier persistence hops."""
    from cloudbasher.csp.aws.credentials import session_creds_from_extra


    return session_creds_from_extra(rec.raw.extra)


def _resolve_aws_identity_or_report(
    state: "InteractiveState",
    verb: str,
    *,
    derives: Optional[str] = None,
    role_arn: Optional[str] = None,
    selector: Optional[str] = None,
) -> Optional["CredentialRecord"]:
    """_resolve_aws_originating_credential(), printing its error for the caller."""
    rec, error = _resolve_aws_originating_credential(
        state, derives=derives, role_arn=role_arn, selector=selector
    )
    if error is not None:
        eprint(f"{verb}: {error}")
        return None
    from cloudbasher.core.credential_validation import known_invalid_credential_error

    invalid = known_invalid_credential_error(
        rec, verb, label=f"AWS credential {selector or 'selected identity'}"
    )
    if invalid:
        eprint(invalid)
        return None


    if rec is not None:
        refusal = _derivation_refusal(rec, derives, role_arn, verb=verb)
        if refusal is not None:
            eprint(refusal)
            return None
    return rec


def _activate_signing(
    state: "InteractiveState",
    rec: "CredentialRecord",
    *,
    verb: str,
    region_hint: Optional[str] = None,
    browser_cost: str = BROWSER_COST_PER_REGION,
) -> bool:
    """THE EXPENSIVE HALF, called explicitly and last. True to proceed."""
    activation_error = _ensure_signing_creds(
        state, rec, verb=verb, region_hint=region_hint, browser_cost=browser_cost
    )
    if activation_error is not None:
        eprint(f"{verb}: {activation_error}")
        return False
    return True


def _how_to_name_a_region(verb: str) -> str:
    """How to name a region **for this command**, spelled the way it takes one."""
    head = verb.strip().lstrip(".").split()
    if head and head[0].lower() == "enum":
        return "`.enum <ID> <region-selector>`."
    return "`.provision <ID> region <selector>`."


def _browser_cost_sentence(rec: Any, spanned: "list[str]", cost: str) -> str:
    """Say what a multi-region browser action costs, truthfully"""
    where = f"({len(spanned)}: {_first_few(spanned)})"
    if cost == BROWSER_COST_ONE_LOGIN:
        return (
            f"{rec.label} signs in via the browser ONCE, then visits each "
            f"region's console {where} -- one sign-in for all of them; the "
            "per-region step is the console page visit that lets that region "
            "presign."
        )
    return (
        f"{rec.label} signs in via the browser once per region {where} -- "
        "browser credentials are region-scoped, so each region gets its own "
        "sign-in."
    )


def _ensure_signing_creds(
    state: "InteractiveState",
    rec: "CredentialRecord",
    *,
    verb: str,
    region_hint: Optional[str] = None,
    browser_cost: str = BROWSER_COST_PER_REGION,
) -> Optional[str]:
    """Check that this credential can sign SOMETHING, without signing in."""
    if rec.provider != "aws":
        return None
    args = getattr(state, "args", None)
    extra = rec.raw.extra or {}
    if extra.get("access_key"):


        if args is not None:
            args.pw_creds = None
        return None

    pw_creds = _browser_creds_for(extra)
    if pw_creds is None:


        return (
            f"credential [{rec.label}] has no access key and no console/SSO login "
            "to obtain one with -- nothing can be signed with it."
        )

    from cloudbasher.csp.aws.credentials import AwsSSOCreds

    if isinstance(pw_creds, AwsSSOCreds):


        return _resolve_sso_record(state, rec, pw_creds, verb=verb)


    if args is not None:
        args.pw_creds = pw_creds
    region = _activation_region(state, region_hint)
    if region is None:


        spanned = _regions_spanned(region_hint)
        if spanned:
            out(f"{verb}: {_browser_cost_sentence(rec, spanned, browser_cost)}")
            return None
        return (
            f"credential [{rec.label}] signs in through the browser, and a "
            "console sign-in targets ONE region -- name it: "
            f"{_how_to_name_a_region(verb)}"
        )
    out(f"{verb}: {rec.label} signs in via the browser ({region})...")
    return None


def _resolve_sso_record(
    state: "InteractiveState",
    rec: "CredentialRecord",
    sso: Any,
    *,
    verb: str,
) -> Optional[str]:
    """Turn an Identity Center credential into a key-based one, in place."""
    from cloudbasher.core.exceptions import CredentialError
    from cloudbasher.csp.aws.credentials import (
        SSO_FLOW_DEVICE,
        merge_sso_keys,
        resolve_sso_to_keys,
    )

    args = getattr(state, "args", None)
    where = sso.sso_region or "no SSO_REGION declared"
    how = (
        f"the Identity Center device code ({where})"
        if sso.sso_flow == SSO_FLOW_DEVICE
        else f"the Identity Center portal ({where})"
    )
    out(f"{verb}: {rec.label} signs in via {how}...")

    _browser = browser_options(getattr(state, "args", None))
    try:
        resolved = resolve_sso_to_keys(
            sso,


            headless=_browser.headless,
            proxy_url=_browser.proxy_url,
            proxy_insecure=_browser.proxy_insecure,
        )
    except CredentialError as exc:


        return str(exc)

    rec.raw.extra = merge_sso_keys(rec.raw.extra or {}, resolved)


    rec.kind = "temporary"
    if args is not None:


        args.pw_creds = None


    _resolve = getattr(state, "resolve_credential_identity", None)
    if _resolve is not None:
        try:
            _resolve(rec.id)
        except Exception:

            pass
    return None


def _browser_creds_for(extra: dict) -> Optional[Any]:
    """Rebuild the parsed console/SSO dataclass from a record's flattened ``extra``, or None if this record is neither shape."""
    from cloudbasher.csp.aws.credentials import browser_creds_from_extra

    return browser_creds_from_extra(extra)


def console_login_for(extra: dict) -> Optional[Any]:
    """The browser login this credential still needs, or None if it needs none."""
    from cloudbasher.csp.aws.credentials import AwsConsoleCreds

    shape = browser_credential_shape(extra)
    return shape if isinstance(shape, AwsConsoleCreds) else None


def _first_few(items: list[str], limit: int = 4) -> str:
    """`a, b, c, d, +12 more` -- `ALL` is 16 regions and naming them all turns a one-line refusal into a paragraph nobody reads to the end of."""
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f", +{len(items) - limit} more"


def _regions_spanned(hint: Optional[str]) -> list[str]:
    """The regions `hint` expands to, but ONLY when that is more than one."""
    if not hint or not isinstance(hint, str):
        return []
    if not _spans_many_regions(hint):
        return []
    try:
        from cloudbasher.csp.aws.multi_region import resolve_regions

        regions = resolve_regions(hint, None)
    except Exception:
        return []
    return list(regions) if len(regions) > 1 else []


def _spans_many_regions(sel: str) -> bool:
    """Is this selector capable of naming more than one region?"""
    return "," in sel or "*" in sel or sel.upper() == "ALL"


def _activation_region(
    state: "InteractiveState", region_hint: Optional[str] = None
) -> Optional[str]:
    """Which region's console to sign in to."""
    if isinstance(region_hint, str) and _spans_many_regions(region_hint):
        return None
    for candidate in (
        region_hint,
        getattr(getattr(state, "args", None), "region", None),
        getattr(state, "region", None),
    ):
        if not candidate or not isinstance(candidate, str):
            continue
        if _spans_many_regions(candidate):
            continue
        return candidate


    return None


def _already_derived_target(
    state: "InteractiveState", rec: "CredentialRecord"
) -> Optional["CredentialRecord"]:
    """A target identity already derived from ``rec``, preferring the active node's, if one exists at all."""
    targets = all_derived_targets(state, rec)
    return targets[0] if targets else None


def _resolve_fanout_identity(
    state: "InteractiveState", rec: "CredentialRecord"
) -> "CredentialRecord":
    """The identity a plain `.provision region` fan-out should run under."""
    existing = _already_derived_target(state, rec)
    if existing is not None:
        return existing


    derived = derivation_state(rec.raw.extra, kind=rec.kind)
    if derived is DerivationState.OWES_A_NAME:


        resolve_identity_name(_session_creds_for(rec), None, where=".provision region")
    elif derived is DerivationState.DECLARED_DIRECT:


        return rec

    from cloudbasher.cli.main import _activate_target_identity

    target_id = _activate_target_identity(rec, state.credentials_by_id, out)
    return state.credentials_by_id.get(target_id, rec)


_PROVISION_KEYWORDS = PROVISION_KEYWORDS


def _cli_flag_hint(tok: str) -> str:
    """`  -- <flag> is a startup flag...` for a token that looks like one."""
    if not tok.startswith("-"):
        return ""
    return (
        f" {tok} is a startup flag, not a command argument -- it goes on the "
        "run.sh/cloudbasher command line, so it needs a restart."
    )


_SELECTOR_SEGMENT = "selector"


_PROVISION_KEYWORD_SPELLINGS = {
    "region": "region",


    "as": "as",


    "duration": "duration",


    "index": "index",
}


def _index_spec_error(raw: str) -> str:
    return (
        f"provision: invalid index {raw!r} -- expected N or N-M with M >= N >= 1"
        " (e.g. 33, or 44-46). Note this is an index, not a count: omit it"
        " entirely for an unsuffixed name."
    )


def _positional_name_error(raw: str) -> str:
    """The index error, plus the `as` remedy when the token looks like the name the positional form used to accept."""
    if _parse_index_spec(raw) is None and not raw[:1].isdigit():


        return (
            f"provision: {raw!r} is not an index. Either name the identity with "
            f"`as` -- `.provision <ID> as {raw}` -- or, if you meant NO index, "
            f"the word is `index {INDEX_NONE}`. (The positional name form is gone.)"
        )
    return _index_spec_error(raw)


def _index_spec_or_error(raw: Optional[str]) -> tuple[Optional[tuple[int, int]], bool]:
    """The typed index, parsed ONCE, for every branch of both commands."""


    if not raw or is_index_none(raw):
        return None, False
    spec = _parse_index_spec(raw)
    if spec is None:
        eprint(_positional_name_error(raw))
        return None, True
    return spec, False


def is_credential_selector(token: str) -> bool:
    low = token.strip().lower()
    if low == "selected":
        return True
    parts = [p.strip() for p in low.split(",") if p.strip()]
    return bool(parts) and all(p.isdigit() for p in parts)


PROVISION_SPEC = CommandSpec(
    name="provision",
    summary=(
        "Create, start, and connect to CloudShell environment(s) for one or more " "credential(s)"
    ),
    effects=Effects.CREATES_CLOUD | Effects.MUTATES_REGISTRY,
    terminals=(
        Slot(
            SlotKind.CRED,
            name="credential",
            accepts=is_credential_selector,


            usage_label="<ID>|selected|1,3,5",
        ),


        Keyword("region", min_arity=1, value_help="<selector>"),


        Keyword("as", min_arity=1, value_help="<name>", hands_back=True),
        Keyword("duration", min_arity=1, value_help="<seconds>"),


        Keyword("index", min_arity=1, value_help="<index|start-end>"),
        Flag("yes", help="skip the environment-count confirmation"),
        Flag("gcp-console-confirmed", usage_hidden=True),
    ),
    notes=(
        "The credential already says what it derives -- ACT_AS decides, and "
        "there is no keyword for it.\n"
        "Keywords may appear in ANY order, and an unambiguous prefix works "
        "(`reg` -> `region`, `i` -> `index`).\n"
        "Bulk (`selected` or `1,3,5`) refuses terms that would give several "
        "credentials ONE shared name: as, duration. An index is allowed -- it "
        "suffixes each row's own name.\n"


        "NAMING: `as <name>`, or the block's declared "
        "ROLE_SESSION_NAME/FEDERATION_NAME. There is NO invented default -- "
        "the name decides which CloudShell environments that principal can "
        "see, so a chosen one would silently pick which environments exist.\n"
        "`as` is a preposition, not a subcommand: `.provision 1 as clb 1-3` "
        "and `.provision 1 1-3 as clb` are the same command.\n"


        "The index is a POSITION, not a count: `as clb` names the principal "
        "clb; `as clb 33` makes it clb-33; `as clb 44-46` makes clb-44, "
        "clb-45, clb-46.\n"
        "duration <seconds> sets the token lifetime (default 129600 = 36h, "
        "max); only the derivations that accept one will take it, and the "
        "command refuses it on the others."
    ),
)


def _session_region(state: "InteractiveState") -> str:
    """The region this session is actually operating in, or "" if unknown."""
    session = getattr(state, "session", None)
    return (getattr(session, "region", "") or "").strip() if session else ""


_PER_CREDENTIAL_TERMS = ("as", "duration")


def _bulk_credentials(
    state: "InteractiveState", selector: Optional[str]
) -> Optional[tuple[list[tuple[int, Any]], Optional[str]]]:
    """Resolve a MULTI-credential selector, or None if this is not one."""
    from cloudbasher.core.types import numbered_originating_records

    if not selector:
        return None
    token = selector.strip()
    numbered = numbered_originating_records(state.credentials_by_id)


    by_id = {rec.id: (n, rec) for n, rec in numbered}

    if token.lower() == "selected":


        from cloudbasher.core.selection import (
            nothing_selected_message,
            selected_credential_records,
        )

        chosen = selected_credential_records(state, provider="aws")
        if not chosen:


            if _node_aws_credential(state) is not None:
                return None
            return [], nothing_selected_message()
        picked = [by_id[rec.id] for rec in chosen if rec.id in by_id]
        if not picked:
            return [], (
                "the checked credentials are no longer loaded -- re-check them " "in the Nodes pane"
            )


        return sorted(picked, key=lambda p: p[0]), None

    if "," not in token:
        return None


    from cloudbasher.core.selection import resolve_numbered_selector

    picked, unknown, malformed = resolve_numbered_selector(numbered, token)


    if unknown or malformed:
        return [], (
            f"no credential {', '.join(repr(m) for m in unknown + malformed)} is loaded -- "
            f"the identity listing numbers 1..{len(numbered)}"
        )
    return picked, None


_ENUM_CONFIRM_ABOVE = 5


def _cursor_credential_number(state: "InteractiveState") -> Optional[int]:
    """The `<cred#>` of the credential the Nodes-pane cursor is on, or None."""
    from cloudbasher.core.types import numbered_originating_records

    cursor_id = getattr(state, "cursor_credential_id", None)
    if not cursor_id:
        return None
    for number, rec in numbered_originating_records(state.credentials_by_id):
        if rec.id == cursor_id:
            return number
    return None


def _confirm_gate(r: "ParseResult") -> Optional[str]:
    """The re-run a confirmation offers: the line as typed, plus `--yes`."""
    if "yes" in r.flags:
        return None
    typed = " ".join(w for w in r.raw.split() if w != "--yes")
    return f"{typed} --yes"


def _confirm_derivation_count(
    state: "InteractiveState",
    total: int,
    *,
    gate: Optional[str],
    noun: str,
    verb: str,
) -> bool:
    """Ask before `.enum` performs more than `_ENUM_CONFIRM_ABOVE` derivations."""
    if total <= _ENUM_CONFIRM_ABOVE or gate is None:
        return False


    state.pending_confirm = (f"{verb} ~{total} {noun}(s) [Y/n]", gate)
    return True


def _confirm_provision_plan(
    state: "InteractiveState",
    targets: "list[PlannedTarget]",
    *,
    gate: Optional[str],
    announce: bool = True,
) -> bool:
    """Show every environment `.provision` is about to create, then ALWAYS ask."""


    if not targets:
        return False


    if not announce:
        return False


    for line in render_plan(targets):
        out(line)


    worst_region, worst = Counter(t.region for t in targets).most_common(1)[0]
    if worst > PROVISION_REGION_CAP:
        eprint(
            f"provision: this plan puts {worst} environment(s) in {worst_region} "
            f"and the cap is {PROVISION_REGION_CAP} per region -- "
            f"{worst - PROVISION_REGION_CAP} of them will be refused by AWS."
        )
    if gate is None:
        return False


    state.pending_confirm = (f"provision {len(targets)} environment(s) [Y/n]", gate)
    return True


def _bulk_plan_targets(
    plan: list,
    state: Optional[Any] = None,
    *,
    index_source: str = DECLARED,
    region_source: str = DECLARED,
) -> "list[PlannedTarget]":
    """A bulk plan's rows, expanded to ONE `PlannedTarget` per environment."""
    from cloudbasher.csp.aws.multi_region import resolve_regions

    targets: list[PlannedTarget] = []
    for _num, rec, region, index in plan:
        try:
            regions = resolve_regions(region, None) or [region]
        except Exception:
            regions = [region]
        if state is not None and rec is not None:


            already = provisioned_regions(state, dedup_credential_ids(state, rec))
            regions = [r for r in regions if r not in already]


        spec = _parse_index_spec(index) if index else None
        names: list[str] = []
        source = DECLARED
        if rec is not None:
            mode = act_as_mode(rec)


            names, _base, source, _err = _planned_identity_names(
                rec,
                requested_name=None,
                index_spec=spec,
                derives="role" if mode == "role" else "federated",
                role_arn=(rec.raw.extra or {}).get("role_arn"),
            )
        if not names:


            base = getattr(rec, "label", f"[{_num}]")
            names = _basename_series(base, spec) if spec else [base]
            source = DECLARED
        targets.extend(
            plan_targets(
                names,
                regions,
                name_source=source,
                index_source=index_source,
                region_source=region_source,
            )
        )
    return targets


def _provision_bulk(
    picked: list[tuple[int, Any]],
    state: "InteractiveState",
    *,
    region_args: Optional[list[str]],
    offending_terms: list[str],
    typed_index: Optional[str] = None,
    confirmed: bool = False,
    gate: Optional[str] = None,
) -> bool:
    """`.provision selected` / `.provision 1,3,5` -- one command, N nodes."""
    if offending_terms:
        eprint(
            f"provision: `{'`, `'.join(offending_terms)}` would give "
            f"{len(picked)} credentials ONE shared identity name, and the name "
            "decides which CloudShell environments exist -- two rows deriving "
            "the same principal makes their environments indistinguishable. "
            "Declare it per credential in the -F file (FEDERATION_NAME=, "
            "ROLE_SESSION_NAME=), or provision one at a time.\n"
            "  (An `index` is fine here: it SUFFIXES each row's own name, so a "
            "selection stays distinct.)"
        )
        return True

    from cloudbasher.csp.aws.multi_region import resolve_regions

    typed_region = region_args[0] if region_args else None
    plan: list[tuple[int, Any, str, str]] = []
    not_aws: list[str] = []
    no_region: list[str] = []
    index_typed_na: list[str] = []
    index_declared_na: list[str] = []
    bad_region: list[str] = []
    for num, rec in picked:
        if rec.provider != "aws":


            not_aws.append(f"[{num}] {rec.label} ({rec.provider})")
            continue


        d = resolve_defaults(
            ((num, rec),), region=typed_region, index=typed_index, selector=str(num)
        )
        region = d.region
        if not region:
            no_region.append(f"[{num}] {rec.label}")
            continue


        try:
            resolve_regions(region, None)
        except ValueError as exc:
            bad_region.append(f"[{num}] {rec.label} -- {exc}")
            continue

        index = d.index


        if d.index_unusable:
            (index_typed_na if typed_index else index_declared_na).append(f"[{num}] {rec.label}")
            index = None
        plan.append((num, rec, region, index))

    if index_typed_na:
        out(
            f"provision: index not applied to {', '.join(index_typed_na)} -- an "
            "index suffixes a DERIVED principal's name and ACT_AS=direct (or a "
            "console/SSO login) IS the identity, so there is no name to suffix. "
            "Those rows provision as themselves; the rest take the index."
        )
    if index_declared_na:
        out(
            f"provision: INDEX= declared by {', '.join(index_declared_na)} does "
            "not apply -- those credentials derive no principal for it to name, "
            "so they provision as themselves."
        )
    if bad_region:
        eprint("provision: " + "\n           ".join(bad_region))
        return True
    if not_aws:
        eprint(
            f"provision: {', '.join(not_aws)} -- this AWS fan-out path cannot "
            "provision those provider types. Provision each through its "
            "provider-specific command path."
        )
        return True
    if no_region:
        eprint(
            f"provision: no region for {', '.join(no_region)}. Either add "
            "`region <selector>` to this command (it applies to every selected "
            "credential), or declare `REGION=` on each in the -F file so a bare "
            "`.provision selected` knows where each one goes."
        )
        return True
    if not plan:
        eprint("provision: nothing selected.")
        return True


    _targets = _bulk_plan_targets(
        plan,
        state,
        index_source=TYPED if typed_index else DECLARED,
        region_source=TYPED if typed_region else DECLARED,
    )


    if _confirm_provision_plan(state, _targets, gate=None if confirmed else gate):
        return True

    def req_for(
        num: int, rec: Any, *, region: Optional[str] = None, index: Optional[str] = None
    ) -> ProvisionRequest:
        """This credential's own request."""
        return ProvisionRequest(
            records=((num, rec),),
            selector=str(num),
            gate=None,


            plan_shown=True,
            region=region,
            index=index,
        )

    failed = 0
    for num, rec, region, index in plan:


        mode = act_as_mode(rec)
        try:
            if not index:
                _provision_region(state, request=req_for(num, rec, region=region))
            elif mode == "role":
                _provision_region_and_role(
                    state, request=req_for(num, rec, region=region, index=index)
                )
            else:
                _provision_region_and_federation(
                    state, request=req_for(num, rec, region=region, index=index)
                )
        except CloudBasherError as exc:
            failed += 1


            eprint(f"provision: credential [{num}] failed: {exc}{refusal_detail(exc)}")
    if failed:
        eprint(f"provision: {failed} of {len(plan)} credential(s) failed")
    return True


def _declared_mode(state: "InteractiveState", selector: Optional[str]) -> tuple[str, Optional[str]]:
    """The credential's declared ``ACT_AS`` mode, or an error string to print."""
    rec, err = _resolve_aws_originating_credential(state, selector=selector)
    if err is not None:
        return "", err
    assert rec is not None
    return act_as_mode(rec), None


def _no_derivation_for_index(
    state: "InteractiveState",
    selector: str,
    mode: str,
    index_args: list[str],
    region: str,
) -> str:
    """Why an index cannot apply to a credential that derives nothing."""
    index = " ".join(index_args)
    rec, _err = _resolve_aws_originating_credential(state, selector=selector)


    how = derives_nothing_because(
        getattr(getattr(rec, "raw", None), "extra", None),
        kind=getattr(rec, "kind", ""),
    )
    return (
        f"provision: credential [{selector}] {how} -- the index {index!r} "
        f"suffixes a DERIVED principal's name and there is none to suffix. "
        f"Drop it: `.provision {selector} region {region}`."
    )


def _reprovision_as(line: str, state: "InteractiveState") -> bool:
    """Re-enter `cmd_provision` through the REAL grammar."""
    from cloudbasher.core.cli.command_spec import parse

    result = parse(PROVISION_SPEC, line)
    if not result.ok:
        eprint(result.error)
        return True
    return cmd_provision(result, state)


def _route_non_aws_provision(r: "ParseResult", state: "InteractiveState") -> Optional[bool]:
    """Route a homogeneous Azure/GCP `.provision` request before AWS parsing."""
    from cloudbasher.core.selection import implicit_credential_records, selected_credential_records
    from cloudbasher.core.types import numbered_originating_records

    numbered = numbered_originating_records(state.credentials_by_id)
    selector = r.selector
    candidates: list["CredentialRecord"] = []
    if selector is None:
        candidates = implicit_credential_records(state)
        if not candidates:
            cursor_id = getattr(state, "cursor_credential_id", None)
            candidates = [rec for _number, rec in numbered if rec.id == cursor_id]
    elif selector.strip().lower() == "selected":
        candidates = selected_credential_records(state)
    elif selector.replace(",", "").isdigit():
        wanted = {int(part) for part in selector.split(",") if part}
        candidates = [rec for number, rec in numbered if number in wanted]

    if not candidates or all(rec.provider == "aws" for rec in candidates):
        return None
    providers = {rec.provider for rec in candidates}
    if len(providers) == 1 and providers <= {"azure", "gcp"}:
        from cloudbasher.csp.azure.commands import cmd_provision as non_aws_provision

        return non_aws_provision(r, state)

    kinds = ", ".join(sorted({rec.provider for rec in candidates}))
    eprint(
        "provision: one request must use a single cloud provider "
        f"({kinds}). Provision each through its provider-specific command path."
    )
    return True


def cmd_provision(r: "ParseResult", state: "InteractiveState") -> bool:
    """.provision [<ID>|selected|1,3,5] [region <selector>] [as <name>] [duration <seconds>] [index <index|start-end>] [--yes] — provision new nodes on demand. THE CREDENTIAL ALREADY SAYS WHAT IT DERIVES, so there is no keyword for the derivation: `.provision 5 region us-east-* index 1-3` federates or assumes a role according to that credential's own ACT_AS, and the keywords may appear in any order. <ID> is the credential number in the Nodes pane's ID column (also [N] in the identity listing); `selected` is the credentials checked in the pane, and a comma-list provisions several at once. Bulk (`selected` or `1,3,5`) REFUSES terms that would give several credentials ONE SHARED identity name (`as`, `duration`) — an index is ALLOWED because it suffixes each row's own name, and a typed one overrides a declared INDEX= on every selected row. EVERY provision prints its plan -- one row per environment, with the derived identity, the region, and whether each value came from this command line or the credential block -- and then asks, whatever the count: `.provision 1 region ALL` is 16 and `.provision 1 region ALL index 1-3` is 48, but `.provision 1` against a block declaring INDEX=1-3 is 3, and that is the one you cannot see in what you typed. `--yes` skips the question and still prints the plan. The derived principal is named by `as <name>` or by the credential's declared ROLE_SESSION_NAME/FEDERATION_NAME; there is no invented default, because the name decides which CloudShell environments exist. The index is a POSITION, not a count: omit it for a bare name, `index N` for a single suffixed name, `index N-M` for an inclusive range."""
    routed = _route_non_aws_provision(r, state)
    if routed is not None:
        return routed


    confirmed = "yes" in r.flags


    typed = " ".join(w for w in r.raw.split() if w != "--yes")
    gate = None if confirmed else f"{typed} --yes"

    if r.is_bare():


        _yes = " --yes" if confirmed else ""


        from cloudbasher.core.selection import implicit_credential_records
        from cloudbasher.core.types import numbered_originating_records

        ticked = implicit_credential_records(state, provider="aws")
        if ticked:
            numbers = [
                str(n)
                for n, rec in numbered_originating_records(state.credentials_by_id)
                if any(rec.id == t.id for t in ticked)
            ]
            if numbers:
                out(
                    "provision: no credential named, using the "
                    f"{'one' if len(numbers) == 1 else len(numbers)} ticked in the "
                    f"pane: [{'], ['.join(numbers)}]"
                )
                return _reprovision_as(f".provision {','.join(numbers)}{_yes}", state)

        cursor_number = _cursor_credential_number(state)
        if cursor_number is not None:
            out(
                f"provision: no credential named, using the one under the "
                f"cursor: [{cursor_number}]"
            )
            return _reprovision_as(f".provision {cursor_number}{_yes}", state)


        rec = _resolve_aws_identity_or_report(state, "provision")
        if rec is None:
            return True
        session_region = _session_region(state)
        if not session_region:
            eprint(
                "provision: no region. Name one: "
                "`.provision <ID> region <selector>` "
                "(ALL | us-east-1,us-west-2 | us-east-* | us-east-1)."
            )
            return True
        out(f"provision: no region specified, using the session region {session_region!r}")


        return _provision_region(
            state,
            request=ProvisionRequest(
                records=(),
                region=session_region,
                region_source=DECLARED,
                gate=gate,
            ),
        )


    segments: dict[str, list[str]] = {k: list(v) for k, v in r.segments.items()}
    if r.selector:
        segments[_SELECTOR_SEGMENT] = [r.selector]
    if not segments:
        eprint(
            "provision: nothing to do -- name a region, a derivation, or a "
            "credential.\n" + usage(PROVISION_SPEC)
        )
        return True

    region_args = segments.get("region")
    duration_args = segments.get("duration")
    as_args = segments.get("as")
    selector_args = segments.get(_SELECTOR_SEGMENT)
    selector = selector_args[0] if selector_args else None


    bulk = _bulk_credentials(state, selector)
    if bulk is not None:
        picked, bulk_err = bulk
        if bulk_err:
            eprint(f"provision: {bulk_err}")
            return True


        _, name_err = validate_name(as_args, where="provision", rows=len(picked))
        if name_err is not None:
            eprint(name_err)
            return True
        offending = [
            name
            for name, seg in (("duration", duration_args),)
            if seg is not None and name in _PER_CREDENTIAL_TERMS
        ]


        return _provision_bulk(
            picked,
            state,
            region_args=region_args,
            typed_index=(segments.get("index") or [None])[0],
            offending_terms=offending,
            confirmed=confirmed,


            gate=gate,
        )


    requested_name, name_err = validate_name(as_args, where="provision")
    if name_err is not None:
        eprint(name_err)
        return True


    duration_override, duration_err = validate_duration(


        duration_args,
        derives_federation=(selector is not None),
    )
    if duration_err is not None:
        eprint(duration_err)
        return True


    index_args = segments.get("index") or []


    declared_rec, declared_err = _resolve_aws_originating_credential(state, selector=selector)


    region_source, index_source = TYPED, TYPED


    if declared_err is None and declared_rec is not None:
        defaults = resolve_defaults(
            ((0, declared_rec),),
            region=region_args[0] if region_args else None,
            index=index_args[0] if index_args else None,
            selector=selector,
        )


        region_source, index_source = defaults.region_source, defaults.index_source
        if defaults.region is not None:
            region_args = [defaults.region]
        if defaults.index_source == TYPED_NONE:


            index_args = []
        elif defaults.index is not None:
            index_args = [defaults.index]


        for note in defaults.announcements:
            out(note)


    explicit_arn = None


    index_val = index_args[0] if index_args else None


    request = ProvisionRequest(
        records=(),
        selector=selector,
        region=region_args[0] if region_args else None,
        region_source=region_source,
        index=index_val,
        index_source=index_source,
        name=requested_name,
        duration=duration_override,
        gate=gate,
        explicit_role_arn=explicit_arn,
    )

    if region_args is None and selector is not None:
        rec, err = _resolve_aws_originating_credential(state, selector=selector)
        if err is not None:
            eprint(f"provision: {err}")
            return True
        assert rec is not None
        mode = act_as_mode(rec)
        if mode == "role":
            if duration_override is not None:
                eprint("provision: duration only applies to federation")
                return True


            return _provision_role(state, request=request)
        if mode == "federated":
            return _provision_federation(state, request=request)

        if mode in DIRECT_MODES:


            if requested_name:
                eprint(
                    f"provision: ACT_AS={mode} has no derived principal to name, "
                    f"so `as {requested_name}` cannot apply -- the principal IS "
                    "the credential's own identity. Drop `as`."
                )
                return True
            eprint(
                f"provision: credential [{selector}] declares ACT_AS={mode}, so there "
                "is no principal to derive -- it acts as itself. Name the region(s) "
                f"you want it in: `.provision region <regions> {selector}`."
            )
            return True
        if getattr(rec, "kind", "") == "console":


            if requested_name:
                eprint(
                    f"provision: credential [{selector}] signs in through the "
                    f"browser, so there is no derived principal for `as "
                    f"{requested_name}` to name. Drop `as`."
                )
                return True
            eprint(
                f"provision: credential [{selector}] signs in through the browser, "
                "so there is no principal to derive. Name the region(s) you want "
                f"it in: `.provision {selector} region <regions>`."
            )
            return True
        eprint(
            f"provision: credential [{selector}] declares ACT_AS={mode or '?'}, which "
            "derives nothing -- name `role` or `federation` explicitly"
        )
        return True


    if region_args and (index_args or requested_name is not None or duration_override is not None):
        mode, mode_err = _declared_mode(state, selector)
        if mode_err is not None:
            eprint(f"provision: {mode_err}")
            return True
        if mode == "role":
            if duration_override is not None:


                eprint("provision: duration only applies to federation")
                return True
            return _provision_region_and_role(state, request=request)
        if mode == "federated":
            return _provision_region_and_federation(state, request=request)
        eprint(_no_derivation_for_index(state, selector, mode, index_args, region_args[0]))
        return True

    if index_args and region_args is not None:
        eprint(
            f"provision: {' '.join(index_args)!r} has nothing to index. An index "
            "suffixes a DERIVED principal's name, so it needs a credential that "
            "derives one -- name the credential: "
            f"`.provision <ID> region {region_args[0]} index {' '.join(index_args)}`."
        )
        return True

    if region_args is not None:
        return _provision_region(state, request=request)

    eprint(usage(PROVISION_SPEC))
    return True


_ENUM_PROBE_TIMEOUT = 10


_NOT_A_REGION = frozenset(set(_PROVISION_KEYWORD_SPELLINGS) | {"role", "federation", "federated"})


ENUM_SPEC = CommandSpec(
    name="enum",
    summary="Find CloudShell environments for one or more credentials across regions",


    effects=Effects.CREATES_CLOUD | Effects.MUTATES_REGISTRY,
    terminals=(
        Slot(
            SlotKind.CRED,
            name="credential",
            accepts=is_credential_selector,


            usage_label="<ID>|selected|1,3,5",
        ),


        Keyword("region", min_arity=1, value_help="<selector>", usage_hidden=True),


        Keyword("as", min_arity=1, value_help="<name>", hands_back=True),
        Keyword("index", min_arity=1, value_help="<index|start-end>"),
        Positional(
            "region_selector",
            required=False,


            usage_label="[region] <selector>",


            accepts=lambda t: t.lower() not in _NOT_A_REGION,
            reject_hint=lambda t: (
                f"enum: {t!r} is a .provision keyword, not an .enum region "
                f"selector -- .enum takes an optional credential, a region "
                f"selector, and optionally `register`."
            ),
        ),


        Verb("register", aliases=()),
        Verb("reconcile"),
        Flag("yes", help="skip the derivation-count confirmation"),
    ),
    notes=(
        "region-selector: ALL | us-east-1 | us-east-1,us-west-2 | us-east-*\n"
        "  REQUIRED unless a node is active -- the brackets in the usage line\n"
        "  mean 'inherited from the active node', and there is no other\n"
        "  fallback. With nothing active, `.enum 1` has no region to use.\n"
        "`region` is an optional keyword, so `.provision`'s spelling also works.\n"
        "`register` also ADOPTS what is found, as nodes; it never connects.\n"
        "`reconcile` DIFFS what AWS reports against what this tool recorded\n"
        "  creating -- it adopts nothing and deletes nothing, it answers\n"
        "  'does the cloud match what I think I have'.\n"
        "<credential> is the [N] of the identity listing. Omitted means `selected`."
    ),
)


def _discovery_identity(
    state: "InteractiveState",
    rec: "CredentialRecord",
    *,
    verb: str,
    requested_name: Optional[str] = None,
) -> Optional[tuple[str, Any, Any]]:
    """`(node_credential_id, probe_rec, api_creds)` for discovery, or None if refused."""
    api_creds = _session_creds_for(rec)


    if requested_name is None:


        derived_rec = _already_derived_target(state, rec)
        if derived_rec is not None:
            return derived_rec.id, derived_rec, api_creds
        if derivation_state(rec.raw.extra, kind=rec.kind) is DerivationState.OWES_A_NAME:
            try:
                resolve_identity_name(api_creds, None, where=verb)
            except CredentialError as exc:
                eprint(str(exc))
                return None
        else:


            return rec.id, rec, api_creds
    from cloudbasher.cli.main import _activate_target_identity

    node_credential_id = _activate_target_identity(
        rec, state.credentials_by_id, out, requested_name=requested_name
    )
    return node_credential_id, state.credentials_by_id.get(node_credential_id, rec), api_creds


class _EnumScope(NamedTuple):
    """One selected credential, and the principal scope `.enum` resolved for it."""

    num: int
    rec: "CredentialRecord"
    choice: Any


    planned: int


def _enum_scopes(
    records: list[tuple[int, Any]], typed_index: Optional[str], *, verb: str
) -> list[_EnumScope]:
    """Resolve every selected record's index scope, once, in selection order."""
    scopes = []
    for num, rec in records:
        choice = effective_index(rec, typed_index, selector=str(num))
        for note in choice.notes:
            out(note)
        if choice.refusal:


            out(f"{verb}: [{rec.label}] {choice.refusal}")


        planned = _planned_name_count(choice.spec) if can_derive(rec.raw.extra) else 0
        scopes.append(_EnumScope(num=num, rec=rec, choice=choice, planned=planned))
    return scopes


def _scope_refusal(scope: "_EnumScope", requested_name: Optional[str], *, verb: str) -> str:
    """What `.enum` will refuse this scope with, or "" if it has work to do."""
    rec = scope.rec
    if can_derive(rec.raw.extra) or not asks_derivation(scope.choice, requested_name):
        return ""
    return (
        f"{verb}: `as`/`index` name a principal to DERIVE, and [{rec.label}] "
        f"{derives_nothing_because(rec.raw.extra, kind=rec.kind)} -- there is "
        "nothing to derive from it. Drop them to enumerate as itself."
    )


def _enum_has_work(scopes: list["_EnumScope"], requested_name: Optional[str]) -> bool:
    """True if ANY selected record will get as far as a probe"""
    return any(not _scope_refusal(sc, requested_name, verb="enum") for sc in scopes)


def _discovery_identities(
    state: "InteractiveState",
    scope: "_EnumScope",
    *,
    verb: str,
    requested_name: Optional[str] = None,
) -> Optional[list[tuple[str, Any, Any]]]:
    """Every principal ``rec`` can enumerate as, for THIS command's scope."""
    rec = scope.rec
    spec = scope.choice.spec

    if not can_derive(rec.raw.extra):


        refusal = _scope_refusal(scope, requested_name, verb=verb)
        if refusal:
            eprint(refusal)
            return None
        one = _discovery_identity(state, rec, verb=verb)
        return None if one is None else [one]


    try:
        basename, _src = resolve_identity_name(_session_creds_for(rec), requested_name, where=verb)
    except CredentialError as exc:


        if spec is None and _already_derived_target(state, rec) is not None:
            return _discovery_identity_row(state, rec, verb=verb)
        eprint(str(exc))
        return None
    rows: list[tuple[str, Any, Any]] = []
    for name in _basename_series(basename, spec):
        one = _discovery_identity(state, rec, verb=verb, requested_name=name)
        if one is None:
            return None
        rows.append(one)
    return rows


def _discovery_identity_row(
    state: "InteractiveState", rec: "CredentialRecord", *, verb: str
) -> Optional[list[tuple[str, Any, Any]]]:
    """`_discovery_identity` as a one-row list, or None. The two non-series exits."""
    one = _discovery_identity(state, rec, verb=verb)
    return None if one is None else [one]


def _out_of_scope(
    state: "InteractiveState", rec: "CredentialRecord", rows: list[tuple[str, Any, Any]]
) -> list[Any]:
    """Derived principals of ``rec`` that ``rows`` does NOT cover."""
    covered = {row[0] for row in rows}
    return [d for d in all_derived_targets(state, rec) if d.id not in covered]


def out_of_scope_note(outside: list[Any], *, verb: str) -> str:
    """The advisory line for `_out_of_scope`'s union, or "" when nothing was excluded."""
    from cloudbasher.core.identity_listing import target_identity_display

    if not outside:
        return ""
    names = ", ".join(sorted(target_identity_display(d) for d in outside))
    return (
        f"{verb}: note -- {len(outside)} principal(s) derived this session are outside "
        f"this scope and were not probed: {names}. Name them with `as`/`index` to "
        f"include them."
    )


class _EnumSelection(NamedTuple):
    """Which credentials `.enum` will work as, and which one still owes activation."""

    records: list[tuple[int, "CredentialRecord"]]


    owes_activation: Optional["CredentialRecord"] = None


def _enum_credentials(
    state: "InteractiveState", selector: Optional[str]
) -> Optional[_EnumSelection]:
    """Which credentials to enumerate as. None means the caller already printed why."""
    bulk = _bulk_credentials(state, selector or "selected")
    if bulk is not None:
        picked, err = bulk
        if err is not None:
            if selector is not None:
                eprint(f"enum: {err}")
                return None
        elif picked:

            return _EnumSelection(picked)
    rec = _resolve_aws_identity_or_report(state, "enum", selector=selector)
    if rec is None:
        return None
    from cloudbasher.core.types import numbered_originating_records

    num = next(
        (n for n, r in numbered_originating_records(state.credentials_by_id) if r.id == rec.id), 0
    )
    return _EnumSelection([(num, rec)], owes_activation=rec)


def _enum_status(exc: Optional[BaseException] = None, *, reason: str = "") -> str:
    """A short status for the table -- from `classify_failure`, not from prose."""
    from cloudbasher.csp.aws.failure import classify_failure

    if exc is not None:
        return classify_failure(exc).upper()
    low = (reason or "").lower()
    if "timed out" in low or "timeout" in low:
        return "TIMEOUT"
    return "ERROR"


def _cancellable(fn: Any) -> Any:
    """`fn`, but it skips instead of running once Ctrl-C has landed."""

    def _guarded(*args: Any, **kwargs: Any) -> Any:
        if skip_if_cancelled():
            raise OperationCancelled()
        with in_flight():
            return fn(*args, **kwargs)

    return _guarded


def _map_probes(fn: Any, work: list) -> Iterator[tuple]:
    """Run `fn` over `work` concurrently, bounded, results in completion order."""
    if len(work) <= 1:
        for item in work:
            if skip_if_cancelled():
                return
            with in_flight():
                yield fn(item)
        return


    with ThreadPoolExecutor(max_workers=pool_width(len(work))) as pool:
        futures = [pool.submit(_cancellable(fn), item) for item in work]
        for f in as_completed(futures):
            yield f.result()


def _adopt_or_fill_placeholder(
    state: "InteractiveState",
    rec: Any,
    node_credential_id: str,
    region: str,
    env_id: str,
    container_status: str,
) -> Any:
    """The node that will hold `env_id` -- filling the credential's REGISTER-ONLY placeholder when there is one, rather than registering a second row beside it. `58-K3`."""
    from cloudbasher.cli.main import _find_primary_node
    from cloudbasher.core.types import NodeRecord

    placeholder = _find_primary_node(state.nodes_by_id, node_credential_id)
    if (
        placeholder is not None
        and not placeholder.environment_id
        and placeholder.region in (None, "", region)
    ):
        placeholder.region = region
        placeholder.environment_id = env_id
        placeholder.container_status = container_status
        return placeholder

    return NodeRecord(


        id=f"{rec.id}:{region}:{env_id}",
        credential_id=node_credential_id,
        region=region,
        environment_id=env_id,
        session=None,
        container_status=container_status,
    )


def _enum_finding(num: int, region: str, env_id: str, raw: str, probe_rec: Any, root: Any) -> Any:
    """One `.enum` result, as the `Finding` the Unmanaged set is made of"""
    from cloudbasher.core.identity_listing import principal_arn_for
    from cloudbasher.csp.aws.discovery import Finding, _now


    arn = principal_arn_for(probe_rec, root)
    return Finding(
        region=region,
        principal_arn=arn,
        environment_id=env_id,
        live_status=raw,
        found_by="enumerate",
        cred_num=num,
        observed_at=_now(),
    )


def note_unregistered_nodes(state: "InteractiveState", nodes: "list[Any]") -> None:
    """Move just-unregistered nodes into the UNMANAGED set"""
    rows = [f for f in (_finding_from_node(state, n) for n in nodes) if f is not None]
    if not rows:
        return
    unmanaged_store(state).merge(rows)
    request_table_refresh(state)


def _finding_from_node(state: "InteractiveState", node: Any) -> "Optional[Any]":
    """One `Finding` for a node we have just stopped tracking"""
    from cloudbasher.core.identity_listing import principal_arn_for
    from cloudbasher.core.node_ids import originating_root_record
    from cloudbasher.csp.aws.discovery import Finding, _now
    from cloudbasher.csp.aws.unmanaged import UNREGISTERED

    env_id = getattr(node, "environment_id", None)
    if not env_id:
        return None
    cred_id = getattr(node, "credential_id", "") or ""
    rec = state.credentials_by_id.get(cred_id)
    if rec is None:
        return None


    root = originating_root_record(cred_id, state.credentials_by_id)


    principal = principal_arn_for(rec, root)
    if not principal:
        return None
    return Finding(
        region=getattr(node, "region", "") or "",
        principal_arn=principal,
        environment_id=env_id,
        live_status=getattr(node, "container_status", None) or None,
        found_by=UNREGISTERED,
        observed_at=_now(),
    )


def cmd_enum(r: "ParseResult", state: "InteractiveState") -> bool:
    """`.enum [<ID>|selected|1,3,5] [region] <region-selector> [register]` -- find, then adopt."""


    selector = r.selector
    adopt = r.verb == "register"


    reconcile = r.verb == "reconcile"


    _kw_region = r.value("region")
    _pos_region = r.positionals.get("region_selector")
    if _kw_region and _pos_region:
        eprint(
            f"enum: two region selectors -- `region {_kw_region}` and "
            f"{_pos_region!r}. They are two spellings of ONE argument; give "
            f"one."
        )
        return True
    region_selector = _kw_region or _pos_region


    typed_index = r.value("index")


    if _index_spec_or_error(typed_index)[1]:
        return True
    derivation_gate = _confirm_gate(r)

    if region_selector:
        try:
            from cloudbasher.csp.aws.multi_region import resolve_regions

            regions = resolve_regions(region_selector)
        except Exception as exc:
            eprint(f"enum: could not resolve {region_selector!r}: {exc}")
            return True
        if not regions:
            eprint(f"enum: no regions matched {region_selector!r}")
            return True
    else:
        current = _session_region(state)
        if not current:


            eprint(
                "enum: no region available -- name one. The region is optional "
                "ONLY while a node is active, because that is where the "
                "fallback comes from; nothing is active now.\n"
                f"{usage(ENUM_SPEC)}"
            )
            return True
        regions = [current]


    selection = _enum_credentials(state, selector)
    if selection is None:
        return True
    records = selection.records


    requested_name, name_err = validate_name(r.segments.get("as"), where="enum", rows=len(records))
    if name_err is not None:
        eprint(name_err)
        return True


    scopes = _enum_scopes(records, typed_index, verb="enum")
    indexed = requested_name is not None or any(sc.choice.spec is not None for sc in scopes)
    if indexed and _confirm_derivation_count(
        state,
        sum(sc.planned for sc in scopes),
        gate=derivation_gate,
        noun="principal",
        verb="derive",
    ):
        return True


    if selection.owes_activation is not None and _enum_has_work(scopes, requested_name):


        if not _activate_signing(
            state,
            selection.owes_activation,
            verb="enum",
            region_hint=regions[0] if len(regions) == 1 else region_selector,
            browser_cost=BROWSER_COST_ONE_LOGIN,
        ):
            return True

    from cloudbasher.core.cli.dispatcher import _AWS_STATUS_MAP, _fmt_table, _get_term_width
    from cloudbasher.core.identity_listing import (
        principal_arn_for,
        target_identity_display,
    )
    from cloudbasher.csp.aws.multi_region import (
        close_credential_client,
        resolve_credential_client,
        resolve_sso_if_needed,
    )

    already_ids = {n.environment_id for n in state.nodes_by_id.values() if n.environment_id}


    nodes_by_env: dict[str, Any] = {
        n.environment_id: n for n in state.nodes_by_id.values() if n.environment_id
    }


    seen_by_scope: dict[tuple[str, str], set[str]] = {}
    swept_scopes: set[tuple[str, str]] = set()
    on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)
    rows: list[list[str]] = []
    registered: list[str] = []
    skipped: list[str] = []


    unmanaged_found: list[Any] = []


    _browser = browser_options(getattr(state, "args", None))


    _capture = getattr(getattr(state, "api_client", None), "_artifact_capture", None)


    from cloudbasher.csp.aws.control_plane import session_console_pool

    _console_sources = session_console_pool(state)

    def _probe(item: tuple) -> tuple:
        """One credential x one region. Pure probe -- it must not touch state."""
        num, rec, ident, region = item
        _node_cred_id, probe_rec, _api_creds = ident
        with log_scope(region):
            client = None
            try:


                client, err = resolve_credential_client(
                    state,
                    probe_rec,
                    region,
                    verb="enum",
                    http_timeout=_ENUM_PROBE_TIMEOUT,
                    proxy_url=_browser.proxy_url,
                    proxy_insecure=_browser.proxy_insecure,
                    headless=_browser.headless,
                    ui_wait_timeout=_browser.ui_wait_timeout,
                    artifact_capture=_capture,
                    console_sources=_console_sources,
                )
                if err is not None:


                    log(f"[enum] cred={num} region={region} error={err}", axis=probe_rec.id)
                    return item, [], _enum_status(reason=err), err


                log(


                    f"[enum] cred={num} region={region} "
                    f"signing_as={principal_arn_for(probe_rec, rec) or '?'} "
                    f"record={probe_rec.id}",


                    axis=probe_rec.id,
                )
                envs = client.describe_environments().get("environments", [])
                found = []
                for env in envs:
                    env_id = env.get("EnvironmentId")
                    if not env_id:
                        continue
                    try:
                        raw = client.get_environment_status(env_id).get("status", "UNKNOWN")
                    except Exception:
                        raw = "UNKNOWN"
                    log(
                        f"[enum] cred={num} region={region} environment_id={env_id} status={raw}",
                        axis=probe_rec.id,
                    )
                    found.append((env_id, raw))
                if not found:
                    log(f"[enum] cred={num} region={region} status=NO_ENV", axis=probe_rec.id)
                    return item, [], "NO_ENV", ""
                return item, found, "", ""
            except Exception as exc:


                error = mask_secrets(str(exc))
                log(f"[enum] cred={num} region={region} error={error}", axis=probe_rec.id)
                return item, [], _enum_status(exc), error
            finally:


                if client is not None:
                    close_credential_client(client)


    work: list[tuple] = []


    outside: list[Any] = []
    for scope_ in scopes:
        num, rec = scope_.num, scope_.rec


        idents = _discovery_identities(state, scope_, verb="enum", requested_name=requested_name)
        if idents is None:
            rows.append([str(num), "-", "-", "REFUSED", ""])
            continue
        outside.extend(_out_of_scope(state, rec, idents))
        for ident in idents:


            sso_error = resolve_sso_if_needed(state, ident[1], verb="enum")
            if sso_error is not None:
                rows.append(
                    [str(num), target_identity_display(ident[1]), "-", "REFUSED", sso_error]
                )
                continue
            for region in regions:
                work.append((num, rec, ident, region))


    try:
        for item, found, status, reason in _map_probes(_probe, work):
            num, rec, ident, region = item
            node_credential_id = ident[0]


            signed_as = target_identity_display(ident[1])
            if status:


                rows.append([str(num), signed_as, region, status, reason])


                out(
                    f"[enum] {num} {signed_as} {region}: "
                    f"{status}{' -- ' + reason if reason else ''}"
                )
                continue
            if reconcile:


                swept_scopes.add((node_credential_id, region))
            for env_id, raw in found:
                if reconcile:
                    seen_by_scope.setdefault((node_credential_id, region), set()).add(env_id)
                out(f"[enum] {num} {signed_as} {region}: {raw} {env_id}")


                if env_id in already_ids:
                    out(f"[enum] {num} {region} {env_id}: node is already being managed")
                elif not adopt:
                    unmanaged_found.append(_enum_finding(num, region, env_id, raw, ident[1], rec))


                note = "-"
                if adopt:
                    if env_id in already_ids:


                        node = nodes_by_env[env_id]
                        fresh = _AWS_STATUS_MAP.get(raw, "Unknown")
                        was = node.container_status
                        skipped.append(env_id)
                        if fresh != "Unknown" and fresh != was:
                            node.container_status = fresh
                            on_node_change(node)
                            note = f"refreshed {was or '?'} -> {fresh}"
                        else:
                            note = "already"
                    else:
                        node = _adopt_or_fill_placeholder(
                            state,
                            rec,
                            node_credential_id,
                            region,
                            env_id,
                            _AWS_STATUS_MAP.get(raw, "Unknown"),
                        )
                        state.register_node(node)
                        on_node_change(node)
                        already_ids.add(env_id)
                        nodes_by_env[env_id] = node
                        registered.append(env_id)
                        note = "registered"
                rows.append(
                    [str(num), signed_as, region, raw, note]
                    if adopt
                    else [str(num), signed_as, region, raw, env_id]
                )
    finally:


        for _key, _urls in _console_sources.drain_blocked_writes().items():
            eprint(
                f"[enum] BLOCKED {len(_urls)} provisioning attempt(s) by the CloudShell "
                f"widget during a read-only enumeration ({_key}) -- no environment was "
                f"created. See #495/#496."
            )
            for _u in _urls:
                log(f"[enum] blocked {_u}")


    rows.sort(key=lambda row: (int(row[0]) if row[0].isdigit() else 0, row[1], row[2], row[4]))


    if unmanaged_found:
        unmanaged_store(state).merge(unmanaged_found)


        request_table_refresh(state)


    headers = ["cred", "signed as", "region", "status", "adopted" if adopt else "environment_id"]


    if adopt:
        for row in rows:
            if row[4] == "":
                row[4] = "-"
    out(_fmt_table(headers, rows, max_width=_get_term_width()))


    _note = out_of_scope_note(list({d.id: d for d in outside}.values()), verb="enum")
    if _note:
        out(_note)
    if adopt:


        if registered:
            out(f"Registered {len(registered)} node(s): {', '.join(registered)}")
        elif not skipped:
            out("Registered nothing -- no environment was found to adopt.")
        if skipped:
            out(f"Already registered, skipped: {', '.join(skipped)}")
    if reconcile:
        _print_reconciliation(seen_by_scope, swept_scopes)
    log(
        f"[enum] csp=aws creds={[n for n, _ in records]} regions={','.join(regions)} "
        f"adopt={adopt} reconcile={reconcile}"
    )
    return True


def _print_reconciliation(
    seen_by_scope: dict[tuple[str, str], set[str]],
    swept_scopes: set[tuple[str, str]],
) -> None:
    """Diff what AWS reported against what this tool recorded creating."""
    from cloudbasher.core import env_journal
    from cloudbasher.core.cli.dispatcher import _fmt_table, _get_term_width

    path = env_journal.journal_path()
    open_created, unresolved = env_journal.unclosed_per_journal()

    if path is None:
        eprint(
            "reconcile: no journal is configured for this run, so there is "
            "nothing to compare against. Only a run started normally keeps "
            "one; a probe script or `-c` does not."
        )
        return

    rows: list[list[str]] = []
    journal_by_scope: dict[tuple[str, str], set[str]] = {}
    for record in open_created:
        scope = (str(record.get("principal") or ""), str(record.get("region") or ""))
        journal_by_scope.setdefault(scope, set()).add(str(record.get("env") or ""))

    for scope in sorted(set(seen_by_scope) | set(journal_by_scope)):
        principal, region = scope
        in_aws = seen_by_scope.get(scope, set())
        in_journal = journal_by_scope.get(scope, set())
        for env_id in sorted(in_aws & in_journal):
            rows.append([principal, region, env_id, "tracked", "-"])
        for env_id in sorted(in_aws - in_journal):
            rows.append(
                [principal, region, env_id, "UNTRACKED", "not in the journal -- `register` adopts"]
            )
        for env_id in sorted(in_journal - in_aws):
            if scope in swept_scopes:
                note = "deleted elsewhere, OR belongs to a principal this sweep did not sign as"
            else:


                note = "this sweep did not cover that region -- re-run with it"
            rows.append([principal, region, env_id, "MISSING", note])

    for record in sorted(unresolved, key=lambda r: str(r.get("at") or "")):
        rows.append(
            [
                str(record.get("principal") or "?"),
                str(record.get("region") or "?"),
                "(no id)",
                "UNRESOLVED",
                f"killed mid-create at {record.get('at') or '?'} -- check CloudTrail",
            ]
        )

    out("")
    if not rows:


        if not open_created and not unresolved and not seen_by_scope:
            out(f"reconcile: nothing found in AWS and nothing outstanding in {path}.")
        else:
            out(f"reconcile: AWS matches the journal exactly ({path}).")
        return

    out(
        _fmt_table(
            ["principal", "region", "environment_id", "verdict", "what it means"],
            rows,
            max_width=_get_term_width(),
        )
    )
    counts: dict[str, int] = {}
    for row in rows:
        counts[row[3]] = counts.get(row[3], 0) + 1
    summary = ", ".join(f"{n} {verdict}" for verdict, n in sorted(counts.items()))
    out(f"reconcile: {summary} (journal: {path})")
    if counts.get("UNRESOLVED"):


        out(
            "  UNRESOLVED has no id by construction. `scripts/aws/cloudshell-sweep.py` "
            "reads CloudTrail, which is the only ACCOUNT-WIDE view -- "
            "`describeEnvironments` is scoped to the calling principal. "
            "CloudTrail history is 90 days."
        )
    log(f"[reconcile] rows={len(rows)} counts={counts} journal={path}")


def _provision_region(
    state: "InteractiveState",
    *,
    request: "ProvisionRequest",
) -> bool:
    """One identity fanned across regions."""
    selector, gate = request.selector, request.gate
    region_selector = request.region
    if not region_selector:
        eprint(usage(PROVISION_SPEC))
        return True


    rec = _resolve_aws_identity_or_report(
        state,
        "provision",
        selector=selector,
    )
    if rec is None:
        return True

    try:
        from cloudbasher.csp.aws.multi_region import resolve_regions

        regions = resolve_regions(region_selector, getattr(state, "api_client", None))
    except Exception as e:
        eprint(f"provision: could not resolve {region_selector!r}: {e}")
        return True

    if not regions:
        eprint(f"provision: no regions matched {region_selector!r}")
        return True


    already_live = provisioned_regions(state, dedup_credential_ids(state, rec))
    to_ask = [r for r in regions if r not in already_live]


    if _confirm_provision_plan(
        state,
        plan_targets(
            [rec.label],
            to_ask,
            name_source=DECLARED,
            index_source=request.index_source,
            region_source=request.region_source,
        ),
        gate=gate,
        announce=not request.plan_shown,
    ):
        return True

    if not _activate_signing(state, rec, verb="provision", region_hint=region_selector):
        return True

    try:
        fanout_rec = _resolve_fanout_identity(state, rec)
    except CredentialError as exc:
        eprint(str(exc))
        return True


    accepted_credential_ids = {fanout_rec.id, rec.id}
    already = provisioned_regions(state, accepted_credential_ids)
    to_provision = [r for r in regions if r not in already]
    skipped = [r for r in regions if r in already]
    if skipped:
        out(f"Already provisioned, skipping: {', '.join(skipped)}")
    if not to_provision:
        out("Nothing to provision.")
        return True

    out(f"Provisioning {len(to_provision)} region(s): {', '.join(to_provision)}...")

    from cloudbasher.csp.aws.multi_region import provision_nodes_for_regions
    from cloudbasher.csp.aws.provider import AWSProvider

    on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)
    try:
        nodes = provision_nodes_for_regions(
            state,
            fanout_rec.id,
            fanout_rec.raw,
            AWSProvider(),
            to_provision,
            on_node_change=on_node_change,
        )
    except Exception as e:

        eprint(f"provision: fan-out failed: {e}{refusal_detail(e)}")
        return True


    succeeded_regions = [n.region or "" for n in nodes]
    out(f"Provisioned {len(nodes)} node(s): {', '.join(succeeded_regions)}")
    failed = [r for r in to_provision if r not in succeeded_regions]
    if failed:
        eprint(f"Failed to provision: {', '.join(failed)}")
    log(
        f"[provision] region fan-out credential_id={fanout_rec.id} "
        f"requested={to_provision} succeeded={succeeded_regions}"
    )
    return True


def _parse_index_spec(raw: str) -> Optional[tuple[int, int]]:
    """Parse a .provision index argument into an INCLUSIVE (start, end). None (caller reports the usage error) for anything invalid."""
    raw = raw.strip()
    if "-" in raw:
        start_s, end_s = raw.split("-", 1)
        try:
            start, end = int(start_s), int(end_s)
        except ValueError:
            return None
        return (start, end) if start >= 1 and end >= start else None
    try:
        index = int(raw)
    except ValueError:
        return None
    return (index, index) if index >= 1 else None


def _planned_identity_names(
    rec: Any,
    *,
    requested_name: Optional[str],
    index_spec: Optional[tuple[int, int]],
    derives: str,
    role_arn: Optional[str] = None,
    where: str = ".provision",
) -> "tuple[list[str], str, str, Optional[str]]":
    """The names this provision WILL derive, resolved OFFLINE, for the preflight."""
    try:
        basename, source = resolve_identity_name(
            _session_creds_for(rec),
            requested_name,
            where=where,
            derives=derives,
            role_arn=role_arn,
        )
    except CredentialError as exc:
        return [], "", "", str(exc)
    return _basename_series(basename, index_spec), basename, source, None


def _confirm_derived_plan(
    state: "InteractiveState",
    rec: Any,
    request: "ProvisionRequest",
    *,
    derives: str,
    regions: "list[str]",
    requested_name: Optional[str],
    index_spec: Optional[tuple[int, int]],
    role_arn: Optional[str] = None,
    where: str = ".provision",
    gate: Optional[str],
) -> "tuple[list[str], str, str, bool]":
    """Resolve this provision's names offline, show the plan, ask. ONE copy."""
    names, basename, source, error = _planned_identity_names(
        rec,
        requested_name=requested_name,
        index_spec=index_spec,
        derives=derives,
        role_arn=role_arn,
        where=where,
    )
    if error is not None:
        eprint(error)
        return [], "", "", True
    asked = _confirm_provision_plan(
        state,
        plan_targets(
            names,
            regions,
            name_source=source,
            index_source=request.index_source,
            region_source=request.region_source,
        ),
        gate=gate,
        announce=not request.plan_shown,
    )
    return names, basename, source, asked


def _planned_name_count(spec: Optional[tuple[int, int]]) -> int:
    """How many names a spec expands to, WITHOUT needing the basename."""
    if spec is None:
        return 1
    start, end = spec
    return end - start + 1


def _basename_series(basename: str, spec: Optional[tuple[int, int]]) -> list[str]:
    """Expand a basename over an inclusive index spec."""
    if spec is None:
        return [basename]
    start, end = spec
    return [f"{basename}-{i}" for i in range(start, end + 1)]


_ROLE_ARN_USAGE = (
    "provision: this credential declares ACT_AS=role but no role ARN, so there is "
    "nothing to assume. The ARN is part of the DECLARATION, not the command: add "
    "`ACT_AS=role:arn:aws:iam::<account>:role/<RoleName>` to its block in the -F "
    "file (see creds.rc.example), then `.provision <ID>` again."
)


def _resolve_role_arn(
    explicit: Optional[str],
    state: "InteractiveState",
    *,
    selector: Optional[str] = None,
) -> Optional[str]:
    """Returns the explicit role ARN if given, else the role ARN declared via ACT_AS=role:<arn> in the -F file. None if neither is available."""
    if explicit:
        return explicit


    rec, _err = _resolve_aws_originating_credential(state, derives="role", selector=selector)
    if rec is not None:
        stored = rec.raw.extra.get("role_arn")
        if stored:
            return str(stored)
    return None


def _provision_role(
    state: "InteractiveState",
    *,
    request: "ProvisionRequest",
) -> bool:
    selector, requested_name, gate = request.selector, request.name, request.gate


    explicit_arn = request.explicit_role_arn
    role_arn = _resolve_role_arn(explicit_arn, state, selector=selector)
    if not role_arn:


        if request.index:
            eprint(
                f"{request.index!r} cannot name a role -- this credential block "
                f"declares no ACT_AS=role:<arn>. The ARN belongs in the credential "
                f"file, not the command: add "
                f"`ACT_AS=role:arn:aws:iam::<account>:role/<RoleName>` to its block."
            )
        eprint(_ROLE_ARN_USAGE)
        return True


    rec = _resolve_aws_identity_or_report(
        state,
        ".provision",
        derives="role",
        role_arn=role_arn,
        selector=selector,
    )
    if rec is None:
        return True


    index_spec, index_failed = _index_spec_or_error(request.index)
    if index_failed:
        return True


    session_names, _session_basename, name_source, stop = _confirm_derived_plan(
        state,
        rec,
        request,
        derives="role",


        regions=[request.region or "(detected)"],
        requested_name=requested_name,
        index_spec=index_spec,
        role_arn=role_arn,
        gate=gate,
    )
    if stop:
        return True

    if not _activate_signing(state, rec, verb=".provision"):
        return True

    from cloudbasher.csp.aws.sts import sts_assume_role


    out(f"  {describe_name_source(name_source, key='ROLE_SESSION_NAME')}")

    def derive(raw: Any, spec: _TargetSpec) -> Any:
        return sts_assume_role(creds=raw, role_arn=role_arn, role_session_name=spec.name)

    provisioned, failed = _provision_target_identity_series(
        state,
        parent_rec=rec,
        target_kind="assume_role",
        specs=[
            _TargetSpec(
                name=session_name,
                target_ref=role_arn,
                label=f"{role_arn} [{session_name}]",
            )
            for session_name in session_names
        ],
        derive=derive,
    )

    if len(session_names) > 1 or index_spec is not None:
        out(f"Provisioned {provisioned}/{len(session_names)} role identities for {role_arn}")
        if failed:
            eprint(f"Failed: {', '.join(failed)}")
    return True


def _provision_federation(
    state: "InteractiveState",
    *,
    request: "ProvisionRequest",
) -> bool:
    selector, requested_name, gate = request.selector, request.name, request.gate
    duration_override = request.duration


    rec = _resolve_aws_identity_or_report(
        state,
        ".provision",
        derives="federated",
        selector=selector,
    )
    if rec is None:
        return True

    index_spec, index_failed = _index_spec_or_error(request.index)
    if index_failed:
        return True


    names, name_basename, name_source, stop = _confirm_derived_plan(
        state,
        rec,
        request,
        derives="federated",
        regions=[request.region or "(detected)"],
        requested_name=requested_name,
        index_spec=index_spec,
        gate=gate,
    )
    if stop:
        return True

    if not _activate_signing(state, rec, verb=".provision"):
        return True

    from cloudbasher.csp.aws.sts import (
        FEDERATION_TOKEN_MAX_SECONDS,
        sts_get_federation_token,
    )


    if duration_override is not None:
        duration_seconds = duration_override
    else:


        duration_seconds = FEDERATION_TOKEN_MAX_SECONDS


    out(f"  {describe_name_source(name_source, key='FEDERATION_NAME')}")

    def derive(raw: Any, spec: _TargetSpec) -> Any:
        return sts_get_federation_token(
            creds=raw, name=spec.name, duration_seconds=duration_seconds
        )

    provisioned, failed = _provision_target_identity_series(
        state,
        parent_rec=rec,
        target_kind="federation_token",
        specs=[_TargetSpec(name=name, target_ref=name, label=name) for name in names],
        derive=derive,
        duration_seconds=duration_seconds,
    )

    if len(names) > 1 or index_spec is not None:
        out(f"Provisioned {provisioned}/{len(names)} federation identities named {name_basename}-*")
        if failed:
            eprint(f"Failed: {', '.join(failed)}")
    return True


def _resolve_provision_regions(selector: str, state: "InteractiveState") -> Optional[list[str]]:
    """Resolve a region selector for .provision, printing an error and returning None on failure -- callers should ``return True`` immediately when this returns None (error already reported)."""
    try:
        from cloudbasher.csp.aws.multi_region import resolve_regions

        regions = resolve_regions(selector, getattr(state, "api_client", None))
    except Exception as e:
        eprint(f"provision: could not resolve {selector!r}: {e}")
        return None
    if not regions:
        eprint(f"provision: no regions matched {selector!r}")
        return None
    return regions


def _provision_region_and_role(
    state: "InteractiveState",
    *,
    request: "ProvisionRequest",
) -> bool:
    selector, requested_name, gate = request.selector, request.name, request.gate
    region_selector = request.region
    if not region_selector:
        eprint(usage(PROVISION_SPEC))
        return True


    role_arn = _resolve_role_arn(request.explicit_role_arn, state, selector=selector)
    if not role_arn:
        eprint(_ROLE_ARN_USAGE)
        return True


    rec = _resolve_aws_identity_or_report(
        state,
        ".provision region ... role",
        derives="role",
        role_arn=role_arn,
        selector=selector,
    )
    if rec is None:
        return True

    index_spec, index_failed = _index_spec_or_error(request.index)
    if index_failed:
        return True

    regions = _resolve_provision_regions(region_selector, state)
    if regions is None:
        return True


    names, _basename, name_source, stop = _confirm_derived_plan(
        state,
        rec,
        request,
        derives="role",
        regions=regions,
        requested_name=requested_name,
        index_spec=index_spec,
        role_arn=role_arn,
        where=".provision region ... role",
        gate=gate,
    )
    if stop:
        return True

    if not _activate_signing(
        state,
        rec,
        verb=".provision region ... role",
        region_hint=region_selector,
    ):
        return True

    from cloudbasher.csp.aws.sts import sts_assume_role


    out(f"  {describe_name_source(name_source, key='ROLE_SESSION_NAME')}")

    provisioned, total = _provision_target_identity_across_regions(
        state,
        parent_rec=rec,
        target_kind="assume_role",
        names=names,
        regions=regions,
        derive_for_name=lambda raw, name: sts_assume_role(
            creds=raw, role_arn=role_arn, role_session_name=name
        ),
        target_ref_for_name=lambda _name: role_arn,
        label_for_name=lambda name: f"{role_arn} [{name}]",
    )
    out(f"Provisioned {provisioned}/{total} node(s)")
    return True


def _provision_region_and_federation(
    state: "InteractiveState",
    *,
    request: "ProvisionRequest",
) -> bool:
    selector, requested_name, gate = request.selector, request.name, request.gate
    duration_override = request.duration
    region_selector = request.region
    if not region_selector:
        eprint(usage(PROVISION_SPEC))
        return True

    rec = _resolve_aws_identity_or_report(
        state,
        ".provision region ... federation",
        derives="federated",
        selector=selector,
    )
    if rec is None:
        return True

    index_spec, index_failed = _index_spec_or_error(request.index)
    if index_failed:
        return True
    from cloudbasher.csp.aws.sts import (
        FEDERATION_TOKEN_MAX_SECONDS,
        sts_get_federation_token,
    )

    if duration_override is not None:
        duration_seconds = duration_override
    else:

        duration_seconds = FEDERATION_TOKEN_MAX_SECONDS

    regions = _resolve_provision_regions(region_selector, state)
    if regions is None:
        return True


    names, _basename, name_source, stop = _confirm_derived_plan(
        state,
        rec,
        request,
        derives="federated",
        regions=regions,
        requested_name=requested_name,
        index_spec=index_spec,
        where=".provision region ... federation",
        gate=gate,
    )
    if stop:
        return True

    if not _activate_signing(
        state,
        rec,
        verb=".provision region ... federation",
        region_hint=region_selector,
    ):
        return True


    out(f"  {describe_name_source(name_source, key='FEDERATION_NAME')}")

    provisioned, total = _provision_target_identity_across_regions(
        state,
        parent_rec=rec,
        target_kind="federation_token",
        names=names,
        regions=regions,
        derive_for_name=lambda raw, name: sts_get_federation_token(
            creds=raw, name=name, duration_seconds=duration_seconds
        ),
        target_ref_for_name=lambda name: name,
        label_for_name=lambda name: name,
        duration_seconds=duration_seconds,
    )
    out(f"Provisioned {provisioned}/{total} node(s)")
    return True


def _provision_target_identity_across_regions(
    state: "InteractiveState",
    *,
    parent_rec: "CredentialRecord",
    target_kind: str,
    names: list[str],
    regions: list[str],
    derive_for_name: Any,
    target_ref_for_name: Any,
    label_for_name: Any,
    duration_seconds: Optional[int] = None,
) -> tuple[int, int]:
    """Shared body for region+role / region+federation combined provisioning."""
    import concurrent.futures

    from cloudbasher.cli.main import (
        _apply_bootstrap_result,
        _bootstrap_aws_session,
        _publish_bootstrapped_node,
    )
    from cloudbasher.core.types import (
        NodeRecord,
        record_env_id_for,
    )
    from cloudbasher.csp.aws.provider import AWSProvider

    total = len(names) * len(regions)


    from cloudbasher.csp.aws.credentials import signing_creds_from_extra

    parent_raw = signing_creds_from_extra(parent_rec.raw.extra)
    on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)
    args_ns = getattr(state, "args", None)
    provider = AWSProvider()
    failed: list[str] = []

    def _resolve_identity(
        name: str,
    ) -> tuple[str, str, Optional["CredentialRecord"], list[str]]:
        """Derive (or reuse) one name's target identity. Returns (label, target_id, target_rec, to_provision) -- target_rec is None if derivation failed or nothing new needs provisioning."""
        target_ref = target_ref_for_name(name)
        label = label_for_name(name)


        target_id = derived_target_id(parent_rec.id, target_kind, target_ref, name)


        if skip_if_cancelled():
            return label, target_id, None, []


        already = provisioned_regions(state, {target_id})
        to_provision = [r for r in regions if r not in already]
        if not to_provision:
            return label, target_id, None, []

        target_rec = state.credentials_by_id.get(target_id)
        if target_rec is None:
            out(f"Deriving {target_kind} identity: {label}...")
            try:


                with in_flight():
                    upgraded = derive_for_name(parent_raw, name)
            except Exception as e:
                eprint(f"provision: identity derivation failed for {label}: {e}")
                return label, target_id, None, to_provision
            target_rec = derived_target_record(
                parent_rec=parent_rec,
                target_id=target_id,
                label=label,
                upgraded=upgraded,
                target_kind=target_kind,
                target_ref=target_ref,
                target_session_name=derived_session_name(target_kind, name),
                target_duration_seconds=duration_seconds,
            )
            state.credentials_by_id[target_id] = target_rec
        return label, target_id, target_rec, to_provision

    identity_workers = pool_width(len(names))


    work: list[tuple[str, str, CredentialRecord, "NodeRecord"]] = []


    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=identity_workers) as executor:
        futures = [executor.submit(_resolve_identity, name) for name in names]
        for future in concurrent.futures.as_completed(futures):
            label, target_id, target_rec, to_provision = future.result()
            done += 1
            if target_rec is not None:
                out(f"  [{done}/{len(names)}] {label}: derived")
            elif to_provision:
                out(f"  [{done}/{len(names)}] {label}: derivation FAILED")
            else:
                out(f"  [{done}/{len(names)}] {label}: already provisioned, nothing to do")
            if target_rec is None:
                if to_provision:
                    failed.extend(f"{label}[{r}]" for r in to_provision)
                continue
            for region in to_provision:
                node = NodeRecord(
                    id=f"{target_id}:{region}",
                    credential_id=target_id,
                    region=region,
                    environment_id=None,
                    session=None,
                    container_status="Pending",
                )
                state.register_node(node)
                on_node_change(node)
                node.begin_connect("provision region + role/federation")
                on_node_change(node)
                work.append((label, region, target_rec, node))

    provisioned = 0

    work_by_id = {node.id: (label, region, rec, node) for label, region, rec, node in work}
    fan_labels = {node.id: f"{label}[{region}]" for label, region, _rec, node in work}


    nodes_by_id = {node.id: node for _label, _region, _rec, node in work}
    bootstrapped: dict[str, Any] = {}

    def _connect_one(node_id: str, _ctx: Any) -> tuple[bool, list[str]]:
        """ON the shared primitive. ``skip_if_cancelled()``, ``in_flight()``, exception isolation, the pool bound and the admission gate all belong to the primitive -- the gate being what made this migration worth doing rather than merely tidy."""
        _label, region, target_rec, node = work_by_id[node_id]


        def _emit(msg: str) -> None:
            log(f"[provision] {msg}")

        result = _bootstrap_aws_session(
            args=args_ns,
            provider=provider,
            credentials=target_rec.raw,
            env_id=None,
            region=region,
            emit=_emit,


            credential_record=target_rec,
            credential_registry=state.credentials_by_id,


            on_environment_known=record_env_id_for(node),
        )


        _apply_bootstrap_result(node, result, region=region, emit=_emit)


        bootstrapped[node_id] = result
        return True, []

    cancelled_labels: list[str] = []

    def _note_failure(node: "NodeRecord", exc: BaseException) -> None:
        """#111. Recorded HERE and not only on reconnect. A provision is where a node's first and most consequential failure happens -- hitting the region cap, above all -- and `_last_failure_class` was written only by `_reconnect_node`, so a node that never connected in the first place carried no class at all and the TUI had nothing to show but a glyph."""
        label, region, _rec, _node = work_by_id[node.id]
        _label, _why = note_node_failure(node, exc, on_node_change)
        log(f"[provision] region+{target_kind} failed name={label} region={region}: {_why}")
        log(f"[provision]   raw: {exc}")


        failed.append(f"{fan_labels[node.id]} ({_label})")

    def _finish_one(node_id: str) -> None:
        """Everything a provisioned node still needs, on the COLLECTING thread."""
        nonlocal provisioned
        node = nodes_by_id[node_id]
        result = bootstrapped[node_id]


        node._runtime_api_client = result.api_client


        _publish_bootstrapped_node(node, result)


        on_node_change(node)
        provisioned += 1

    if work:


        from cloudbasher.core.cli.dispatcher import fan_out_over_nodes as _fan_out


        try:


            outcome = _fan_out(
                "provision",
                nodes_by_id,
                fan_labels,
                _connect_one,
                state,
                refresh=False,
                on_failure=_note_failure,
                on_success=_finish_one,
            )


            for node_id in outcome.cancelled:
                label, region, _rec, _node = work_by_id[node_id]
                log(f"[provision] skipped -- cancelled: name={label} region={region}")
                cancelled_labels.append(f"{label}[{region}]")
        finally:

            for _lbl, _rgn, _rec, _claimed in work:
                if _claimed.end_connect():
                    on_node_change(_claimed)

    if failed:
        eprint(f"Failed: {', '.join(failed)}")
    if cancelled_labels:


        eprint(f"Cancelled before start ({len(cancelled_labels)}): {', '.join(cancelled_labels)}")
    report_cancellation(out)
    return provisioned, total


def derived_session_name(target_kind: str, name: str) -> Optional[str]:
    """The STS ``RoleSessionName`` for a derived target -- or None."""
    return name if target_kind == "assume_role" else None


def derived_target_id(parent_id: str, target_kind: str, target_ref: str, name: str) -> str:
    """THE record id of a derived target principal. One implementation."""
    target_id = f"{parent_id}:{target_kind}:{target_ref}"
    if target_kind == "assume_role":
        return f"{target_id}:{name}"
    return target_id


def derived_target_record(
    *,
    parent_rec: "CredentialRecord",
    target_id: str,
    label: str,
    upgraded: "AwsSessionCreds",
    target_kind: str,
    target_ref: str,
    target_session_name: Optional[str],
    target_duration_seconds: Optional[int],
) -> "CredentialRecord":
    """THE record for a derived target principal. One implementation."""

    from cloudbasher.core.credential_file import _kind_for
    from cloudbasher.core.types import CredentialRecord, Credentials

    cached = upgraded.to_cache_dict()
    return CredentialRecord(
        id=target_id,
        provider="aws",
        kind=_kind_for(cached),
        role="target",
        parent_id=parent_rec.id,
        label=label,
        raw=Credentials(provider="aws", extra=cached),
        target_kind=target_kind,
        target_ref=target_ref,
        target_session_name=target_session_name,
        target_duration_seconds=target_duration_seconds,
        derived=cached,
    )


class _TargetSpec(NamedTuple):
    """One member of a `.provision role|federation` name series."""

    name: str
    target_ref: str
    label: str
    target_session_name: Optional[str] = None

    def target_id(self, parent_id: str, target_kind: str) -> str:
        """The credential id this name derives to -- see `derived_target_id`."""
        return derived_target_id(parent_id, target_kind, self.target_ref, self.name)


def _provision_target_identity_series(
    state: "InteractiveState",
    *,
    parent_rec: "CredentialRecord",
    target_kind: str,
    specs: list[_TargetSpec],
    derive: Any,
    duration_seconds: Optional[int] = None,
) -> tuple[int, list[str]]:
    """Shared body for .provision role/.provision federation."""
    from cloudbasher.cli.main import (
        _bootstrap_primary_node_for_credential,
        _probe_after_bootstrap,
    )
    from cloudbasher.core.types import NodeRecord

    on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)
    args_ns = getattr(state, "args", None)


    from cloudbasher.csp.aws.credentials import signing_creds_from_extra

    parent_raw = signing_creds_from_extra(parent_rec.raw.extra)
    provisioned = 0
    failed: list[str] = []

    def _derive_one(
        spec: _TargetSpec,
    ) -> tuple[_TargetSpec, Optional["CredentialRecord"], bool]:
        """Derive one name. Returns (spec, target_rec, derivation_failed); target_rec is None both when it failed and when the identity is already provisioned, which the bool distinguishes."""
        target_id = spec.target_id(parent_rec.id, target_kind)


        if provisioned_regions(state, {target_id}):
            out(f"Already provisioned: {spec.label}")
            return spec, None, False
        out(f"Deriving {target_kind} identity: {spec.label}...")
        try:
            upgraded = derive(parent_raw, spec)
        except Exception as e:
            eprint(f"provision: identity derivation failed for {spec.label}: {e}")
            return spec, None, True
        target_rec = derived_target_record(
            parent_rec=parent_rec,
            target_id=target_id,
            label=spec.label,
            upgraded=upgraded,
            target_kind=target_kind,
            target_ref=spec.target_ref,
            target_session_name=(
                spec.target_session_name or derived_session_name(target_kind, spec.name)
            ),
            target_duration_seconds=duration_seconds,
        )
        state.credentials_by_id[target_id] = target_rec
        return spec, target_rec, False


    derivations = [_derive_one(spec) for spec in specs]


    work: list[tuple[_TargetSpec, "CredentialRecord", "NodeRecord"]] = []
    for spec, target_rec, derivation_failed in derivations:
        if derivation_failed:
            failed.append(spec.name)
            continue
        if target_rec is None:
            provisioned += 1
            continue
        node = NodeRecord(
            id=f"{target_rec.id}:primary",
            credential_id=target_rec.id,
            region=None,
            environment_id=None,
            session=None,
            container_status="Pending",
        )
        state.register_node(node)


        if node.begin_connect("provision (primary node bootstrap)"):
            on_node_change(node)
        work.append((spec, target_rec, node))

    work_by_id = {node.id: (spec, rec, node) for spec, rec, node in work}
    series_labels = {node.id: spec.label for spec, _rec, node in work}


    stubs_by_id = {node.id: node for _spec, _rec, node in work}
    bootstrapped_nodes: dict[str, "NodeRecord"] = {}

    def _bootstrap_one(node_id: str, _ctx: Any) -> tuple[bool, list[str]]:
        """ON the shared primitive, which owns ``skip_if_cancelled()``, ``in_flight()``, the pool, its bound, exception isolation and the admission gate."""
        _spec, target_rec, node = work_by_id[node_id]


        try:


            bootstrapped_nodes[node_id] = _bootstrap_primary_node_for_credential(
                args=args_ns,
                rec=target_rec,
                emit=out,
                gcp_wait_mode=getattr(args_ns, "gcp_wait_mode", "poll"),
                node=node,
                on_node_change=on_node_change,
                credential_registry=state.credentials_by_id,
            )


            _probe_after_bootstrap(bootstrapped_nodes[node_id], out)
            return True, []
        finally:

            if node.end_connect():
                on_node_change(node)

    def _note_failure(node: "NodeRecord", exc: BaseException) -> None:
        """The site that HAD the ordering backwards -- mark-then-publish belongs to ``note_node_failure`` now, not to this function, so it cannot regress here or anywhere else."""
        spec, _rec, _node = work_by_id[node.id]
        _label, _why = note_node_failure(node, exc, on_node_change)
        eprint(f"provision: node bootstrap failed for {spec.label}: {_why}")
        log(f"provision:   raw: {exc}")
        failed.append(f"{spec.name} ({_label})")

    def _finish_one(node_id: str) -> None:
        """`on_success`, run on the collecting thread as each node lands."""
        nonlocal provisioned
        spec, _rec, _stub = work_by_id[node_id]
        node = bootstrapped_nodes[node_id]
        state.register_node(node)
        provisioned += 1
        out(f"Provisioned target identity {spec.label} -> node {node.id}")
        log(
            f"[provision] target identity kind={target_kind} "
            f"ref={spec.target_ref} node_id={node.id}"
        )

    from cloudbasher.core.cli.dispatcher import fan_out_over_nodes as _fan_out


    try:
        outcome = _fan_out(
            "provision",
            stubs_by_id,
            series_labels,
            _bootstrap_one,
            state,
            refresh=False,
            on_failure=_note_failure,
            on_success=_finish_one,
        )
    finally:

        for _spec, _rec, _claimed in work:
            if _claimed.end_connect():
                on_node_change(_claimed)


    for node_id in outcome.cancelled:
        eprint(f"provision: {series_labels[node_id]}: skipped -- cancelled")

    report_cancellation(out)
    return provisioned, failed


DIAG_SPEC = CommandSpec(
    name="diag",
    summary="Reliability harness: provision, reconnect, verify or tear down a named fleet",


    hidden=True,
    effects=Effects.CREATES_CLOUD | Effects.DESTROYS_CLOUD | Effects.MUTATES_REGISTRY,
    terminals=(Verb("run"), Verb("reconnect"), Verb("verify"), Verb("teardown")),
    subcommands={
        "run": CommandSpec(
            name="diag run",
            summary="Provision a small identifiably-named fleet",
            effects=Effects.CREATES_CLOUD | Effects.MUTATES_REGISTRY,
            terminals=(
                Positional("regions", required=True, usage_label="region1,region2,..."),
                Positional("count_per_region", required=True, kind="int"),
                Positional("run_id", required=False),
            ),
        ),
        "reconnect": CommandSpec(
            name="diag reconnect",
            summary="Force a real reconnect fan-out",
            terminals=(
                Positional("selector", required=True),
                Positional("label", required=False),
            ),
        ),
        "verify": CommandSpec(
            name="diag verify",
            summary="Check output parsing against a known value",
            terminals=(
                Positional("target", required=True, usage_label="run_id|selector"),
                Rest("command"),
            ),
        ),
        "teardown": CommandSpec(
            name="diag teardown",
            summary="Delete the fleet a run created",
            effects=Effects.DESTROYS_CLOUD | Effects.MUTATES_REGISTRY,
            terminals=(Positional("run_id", required=True),),
        ),
    },
    notes=(
        "AWS caps CloudShell at 10 environments per region per account, and this "
        "command does NOT check quota for you -- pick regions and counts with "
        "headroom.\n"
        "When every region is already at that cap, use `reconnect`/`verify "
        "<selector>` against the EXISTING fleet rather than `run`."
    ),
)


def cmd_diag(r: "ParseResult", state: "InteractiveState") -> bool:
    """.diag run|reconnect|verify|teardown -- reliability and performance test harness: provisions a small, identifiably-named fleet, or forces a real reconnect fan-out against an existing selector."""


    if r.verb is None or r.sub is None:
        eprint(f"diag: name a subcommand.\n{usage(DIAG_SPEC)}")
        return True
    sub, sp = r.verb, r.sub


    if sub == "run":
        rest = [sp.positionals["regions"], sp.positionals["count_per_region"]]
        if sp.positionals.get("run_id"):
            rest.append(sp.positionals["run_id"])
    elif sub == "reconnect":
        rest = [sp.positionals["selector"]]
        if sp.positionals.get("label"):
            rest.append(sp.positionals["label"])
    elif sub == "verify":
        rest = [sp.positionals["target"]]
        if sp.rest:
            rest.append(sp.rest)
    else:
        rest = [sp.positionals["run_id"]]

    if sub == "run":
        return _diag_run(rest, state)
    if sub == "reconnect":
        return _diag_reconnect(rest, state)
    if sub == "verify":
        return _diag_verify(rest, state)
    if sub == "teardown":
        return _diag_teardown(rest, state)
    eprint(f"diag: unknown subcommand {sub!r} (expected: run, reconnect, verify, teardown)")
    return True


def _diag_nodes(state: "InteractiveState", run_id: str) -> dict[str, "NodeRecord"]:
    """Every node a given `.diag run <run_id>` created, keyed by node id."""
    marker = f":federation_token:diag-{run_id}"
    nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
    return {nid: n for nid, n in nodes_by_id.items() if marker in nid}


def _diag_csv_path(run_id: str, step: str) -> str:
    out_dir = os.path.join(os.getcwd(), "diag-runs")
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, f"{run_id}-{step}.csv")


def _write_diag_csv(run_id: str, step: str, rows: list[dict], fieldnames: list[str]) -> str:
    path = _diag_csv_path(run_id, step)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    out(f"diag {step}: telemetry written to {path}")
    return path


def _diag_run(args: list[str], state: "InteractiveState") -> bool:
    if len(args) < 2:
        eprint(usage(DIAG_SPEC))
        return True
    regions = args[0]
    try:
        count = int(args[1])
    except ValueError:
        eprint(f"diag run: count_per_region must be an integer, got {args[1]!r}")
        return True
    run_id = args[2] if len(args) > 2 else str(int(time.time()))

    log(f"[diag] run_id={run_id} START region={regions} count_per_region={count}")
    started = time.time()


    _reprovision_as(f".provision region {regions} as diag-{run_id} index 1-{count} --yes", state)
    elapsed = time.time() - started
    log(f"[diag] run_id={run_id} END elapsed={elapsed:.1f}s")

    nodes = _diag_nodes(state, run_id)
    succeeded = sum(1 for n in nodes.values() if n.container_status == "Running")
    failed = sum(1 for n in nodes.values() if n.container_status == "Failed")
    out(
        f"diag run {run_id}: {succeeded}/{len(nodes)} node(s) Running, "
        f"{failed} Failed, elapsed={elapsed:.1f}s"
    )
    _write_diag_csv(
        run_id,
        "run",
        rows=[
            {
                "node_id": nid,
                "region": n.region,
                "status": n.container_status,
                "seq": n.seq,
                "created_at": n.created_at,
            }
            for nid, n in sorted(nodes.items())
        ],
        fieldnames=["node_id", "region", "status", "seq", "created_at"],
    )
    return True


def _resolve_diag_target_nodes(
    state: "InteractiveState", identifier: str
) -> dict[str, "NodeRecord"]:
    """Resolve `identifier` to a node set two ways, in order: (1) a prior `.diag run <run_id>`'s own nodes, (2) if none match, `identifier` treated as a plain selector (.bulk/.delete grammar) over the EXISTING fleet. (2) is what makes `.diag verify`/`reconnect` usable with zero new CloudShell capacity -- when every region is already at its 10-environment cap, there is no fresh fleet to fall back to (1) for."""
    nodes = _diag_nodes(state, identifier)
    if nodes:
        return nodes
    from cloudbasher.core.cli.dispatcher import resolve_node_selector

    nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
    selected_node_ids = getattr(state, "selected_node_ids", None) or set()
    node_ids, err = resolve_node_selector(identifier, nodes_by_id, selected_node_ids)
    if err or not node_ids:
        return {}


    from cloudbasher.core.cli.dispatcher import display_order

    return {
        nid: nodes_by_id[nid]
        for nid in display_order(state, sorted(node_ids))
        if nid in nodes_by_id
    }


def _rows_in_dispatch_order(rows: list[dict], nodes: dict) -> list[dict]:
    """`rows` re-ordered to follow `nodes`, which IS the dispatch order."""
    from cloudbasher.core.node_ids import order_like

    by_id: dict[str, dict] = {}
    for row in rows:
        by_id.setdefault(row["node_id"], row)
    return [by_id[nid] for nid in order_like(nodes, by_id)]


def _diag_reconnect(args: list[str], state: "InteractiveState") -> bool:
    """.diag reconnect <selector> [label] — force-disconnect (close any live session/heartbeat) then concurrently reconnect every matched EXISTING node, measuring per-node success/failure and elapsed time."""
    if not args:
        eprint(usage(DIAG_SPEC))
        return True
    selector = args[0]
    label = args[1] if len(args) > 1 else str(int(time.time()))

    from cloudbasher.core.cli.dispatcher import (
        Guard,
        _node_ref_labels,
        disconnect_node,
        ensure_node_session,
        filter_busy_nodes,
        resolve_node_selector,
    )

    nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
    selected_node_ids = getattr(state, "selected_node_ids", None) or set()
    node_ids, err = resolve_node_selector(selector, nodes_by_id, selected_node_ids)
    if err:
        eprint(f"diag reconnect: {err}")
        return True
    if not node_ids:
        eprint(f"diag reconnect: no nodes matched selector {selector!r}")
        return True


    credentials_by_id = getattr(state, "credentials_by_id", {}) or {}
    nodes, _skipped = filter_busy_nodes(
        "diag reconnect",
        node_ids,
        nodes_by_id,
        _node_ref_labels(set(node_ids), nodes_by_id, credentials_by_id),
        credentials_by_id=credentials_by_id,
        guard=Guard.SUSPENDING,
    )
    if not nodes:
        eprint("diag reconnect: every matched node was skipped; nothing to measure")
        return True


    for node in nodes.values():
        disconnect_node(node, scope="session")

    def _reconnect_one(node_id: str, node: "NodeRecord") -> dict:
        started = time.time()
        session, err = ensure_node_session(state.csp_provider, state, node)
        return {
            "node_id": node_id,
            "region": node.region,
            "success": session is not None,
            "elapsed_s": round(time.time() - started, 2),
            "error": err,
        }

    log(f"[diag] reconnect label={label} START selector={selector!r} count={len(nodes)}")
    started = time.time()
    results: list[dict] = []
    workers = pool_width(len(nodes))
    cancelled = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_cancellable(_reconnect_one), nid, n): nid for nid, n in nodes.items()
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except OperationCancelled:


                cancelled += 1
        if cancelled:
            eprint(f"diag reconnect: {cancelled} node(s) skipped -- cancelled")
    results = _rows_in_dispatch_order(results, nodes)
    total_elapsed = time.time() - started
    log(f"[diag] reconnect label={label} END elapsed={total_elapsed:.1f}s")

    succeeded = sum(1 for r in results if r["success"])
    out(
        f"diag reconnect {label}: {succeeded}/{len(results)} node(s) reconnected, "
        f"elapsed={total_elapsed:.1f}s"
    )
    for r in results:
        if not r["success"]:
            eprint(f"diag reconnect: [{r['node_id']}] {r['error']}")

    last_node = next(iter(nodes.values()), None)
    if last_node is not None:
        on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)
        on_node_change(last_node)

    _write_diag_csv(
        label,
        "reconnect",
        rows=results,
        fieldnames=["node_id", "region", "success", "elapsed_s", "error"],
    )
    return True


def _diag_verify(args: list[str], state: "InteractiveState") -> bool:
    """Runs a per-node command whose correct output the harness already knows (a unique echo token by default), so a mismatch is unambiguous parsing-layer evidence rather than something that needs a human to judge "does this look right" -- directly targets 4z item 1's ~10% unexplained parse-failure rate. A caller-supplied command skips the correctness check (no known-good value to compare against) and only records success/failure/timing, since this codebase never fabricates a verdict it can't actually verify."""
    if not args:
        eprint(usage(DIAG_SPEC))
        return True
    run_id = args[0]
    custom_command = " ".join(args[1:]) if len(args) > 1 else None
    nodes = _resolve_diag_target_nodes(state, run_id)
    if not nodes:
        eprint(f"diag verify: no nodes found for {run_id!r} " f"(checked diag run_id and selector)")
        return True

    from cloudbasher.core.cli.dispatcher import ensure_node_session
    from cloudbasher.core.session.exit_code_spike import CaptureUntrusted, exec_with_exit_code

    def _check_one(node_id: str, node: "NodeRecord") -> dict:
        token = f"HARNESS_{uuid.uuid4().hex[:12]}"
        command = custom_command or f"echo {token}"
        session, err = ensure_node_session(state.csp_provider, state, node)
        if session is None:
            return {
                "node_id": node_id,
                "region": node.region,
                "expected": token,
                "actual": None,
                "exit_code": None,
                "error": err,
                "untrusted": None,
                "match": False,
            }
        try:
            output, exit_code = exec_with_exit_code(session, command)
        except CaptureUntrusted as untrusted:


            return {
                "node_id": node_id,
                "region": node.region,
                "expected": token,
                "actual": untrusted.raw_output,
                "exit_code": untrusted.exit_code,
                "error": None,
                "untrusted": untrusted.reason,
                "match": False,
            }
        except Exception as e:
            return {
                "node_id": node_id,
                "region": node.region,
                "expected": token,
                "actual": None,
                "exit_code": None,
                "error": str(e),
                "untrusted": None,
                "match": False,
            }
        actual = (output or "").strip()
        match = (actual == token) if custom_command is None else None
        return {
            "node_id": node_id,
            "region": node.region,
            "expected": token,
            "actual": actual,
            "exit_code": exit_code,
            "error": None,
            "untrusted": None,
            "match": match,
        }

    log(f"[diag] verify run_id={run_id!r} START count={len(nodes)}")
    started = time.time()
    results: list[dict] = []
    workers = pool_width(len(nodes))
    cancelled = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_cancellable(_check_one), nid, n): nid for nid, n in nodes.items()}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except OperationCancelled:


                cancelled += 1
        if cancelled:
            eprint(f"diag verify: {cancelled} node(s) skipped -- cancelled")
    results = _rows_in_dispatch_order(results, nodes)
    elapsed = time.time() - started
    log(f"[diag] verify run_id={run_id!r} END elapsed={elapsed:.1f}s")

    if custom_command is None:
        matched = sum(1 for r in results if r["match"])
        out(
            f"diag verify {run_id}: {matched}/{len(results)} node(s) parsed correctly, "
            f"elapsed={elapsed:.1f}s"
        )
        for r in results:
            if not r["match"]:
                eprint(
                    f"diag verify: [{r['node_id']}] MISMATCH "
                    f"expected={r['expected']!r} actual={r['actual']!r} "
                    f"error={r['error']} untrusted={r['untrusted']}"
                )
    else:


        succeeded = sum(1 for r in results if r["error"] is None and r["untrusted"] is None)
        out(
            f"diag verify {run_id}: {succeeded}/{len(results)} node(s) "
            f"ran {custom_command!r} without error, elapsed={elapsed:.1f}s"
        )

    _write_diag_csv(
        run_id,
        "verify",
        rows=results,
        fieldnames=[
            "node_id",
            "region",
            "expected",
            "actual",
            "exit_code",
            "error",
            "untrusted",
            "match",
        ],
    )
    return True


def _diag_teardown(args: list[str], state: "InteractiveState") -> bool:
    if not args:
        eprint(usage(DIAG_SPEC))
        return True
    run_id = args[0]
    nodes = _diag_nodes(state, run_id)
    if not nodes:
        eprint(f"diag teardown: no nodes found for run_id {run_id!r}")
        return True

    from cloudbasher.core.cli.dispatcher import delete_nodes

    deleted, failed = delete_nodes(state.csp_provider, state, set(nodes.keys()))
    out(f"diag teardown {run_id}: deleted {len(deleted)}/{len(nodes)} node(s)")
    if failed:
        eprint(f"diag teardown {run_id}: failed to delete: {', '.join(failed)}")
    log(f"[diag] run_id={run_id} TEARDOWN deleted={deleted} failed={failed}")
    return True


_PROBE_NAME = "clb-perms-probe"


def browser_credential_shape(extra: dict) -> Optional[Any]:
    """The console/SSO dataclass for a record that has NO long-term key, else None."""
    if str(extra.get("access_key") or "").strip():
        return None
    return _browser_creds_for(extra)


def _probe_browser_credential(rec: Any) -> Optional[list[tuple[str, str, str]]]:
    """Validate a console/SSO credential, or None if this record is key-based."""
    extra = getattr(getattr(rec, "raw", None), "extra", None) or {}
    pw_creds = browser_credential_shape(extra)
    if pw_creds is None:
        return None

    from cloudbasher.csp.aws.credentials import AwsSSOCreds

    if isinstance(pw_creds, AwsSSOCreds):


        import copy
        from types import SimpleNamespace

        probe_rec = copy.deepcopy(rec)
        try:
            err = _resolve_sso_record(SimpleNamespace(args=None), probe_rec, pw_creds, verb="perms")
        except Exception as exc:
            return [("SSO login", "invalid", f"portal sign-in failed: {_probe_reason(exc)}")]
        if err:
            return [("SSO login", "invalid", str(err)[:140])]
        return [
            (
                "SSO login",
                "allowed",
                "portal sign-in + GetRoleCredentials succeeded -- the credential is "
                "VALID and would resolve to an ASIA triple. Resolved on a copy, so "
                "this record is unchanged; `.provision <ID>` is what commits it",
            )
        ]

    from cloudbasher.csp.aws.playwright_login import validate_console_login

    try:
        validate_console_login(pw_creds)
        return [
            (
                "console login",
                "allowed",
                "signed in to the AWS Console -- the credential is VALID. CloudShell "
                "permissions are not probeable without a browser session (Path B; "
                "design-aws.md:967)",
            )
        ]
    except Exception as exc:
        return [("console login", "invalid", f"sign-in failed: {_probe_reason(exc)}")]


def probe_record_permissions(
    rec: Any, *, extra_arns: Optional[list[str]] = None
) -> list[tuple[str, str, str]]:
    """Which derivations this credential can actually perform, as verdict rows."""
    from cloudbasher.csp.aws.sts import sts_assume_role, sts_get_federation_token


    browser_rows = _probe_browser_credential(rec)
    if browser_rows is not None:
        return browser_rows

    declared = act_as_from_extra(rec.raw.extra)
    creds = _session_creds_for(rec)
    if creds.session_token:


        return [("(already derived)", "n/a", "carries a session token — ACT_AS=direct fits it")]

    rows: list[tuple[str, str, str]] = []
    try:
        sts_get_federation_token(creds=creds, name=_PROBE_NAME)
        rows.append(("GetFederationToken", "allowed", "federated-user/<name>"))
    except Exception as exc:


        rows.append(("GetFederationToken", *probe_verdict(exc)))


    arns = list(
        dict.fromkeys(
            list(extra_arns or [])
            + ([declared.role_arn] if declared is not None and declared.role_arn else [])
        )
    )
    if not arns:
        rows.append(
            (
                "AssumeRole",
                "not probed",
                "no role ARN declared -- probe one with `.creds <n> perms role <arn>`",
            )
        )
    for arn in arns:
        try:
            sts_assume_role(creds=creds, role_arn=arn, role_session_name=_PROBE_NAME)
            rows.append(("AssumeRole", "allowed", arn))
        except Exception as exc:
            verdict, why = probe_verdict(exc)
            rows.append(("AssumeRole", verdict, f"{arn} ({why})"))
    return rows


def _probe_reason(exc: Exception) -> str:
    """One short line from a failure, for DETAIL text only."""
    text = str(exc).replace("\n", " ")
    for code in (
        "AccessDenied",
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "ExpiredToken",
        "MalformedPolicyDocument",
        "ValidationError",
    ):
        if code in text:
            return code
    return text[:80]


DISCOVER_SPEC = CommandSpec(
    name="discover",
    summary="Find CloudShell environments account-wide via CloudTrail, including "
    "ones no held credential can see",


    effects=Effects.CREATES_CLOUD | Effects.DESTROYS_CLOUD,
    terminals=(
        Slot(
            SlotKind.CRED,
            name="credential",
            accepts=is_credential_selector,


            usage_label="<ID>|selected|1,3,5",
        ),


        Keyword("region", min_arity=1, value_help="<selector>", usage_hidden=True),
        Keyword("days", min_arity=1, value_help="<n>"),
        Positional(
            "region_selector",
            required=False,
            usage_label="[region] <selector>",
            accepts=lambda t: t.lower() not in _NOT_A_REGION,
            reject_hint=lambda t: (
                f"discover: {t!r} is a .provision keyword, not a region selector."
            ),
        ),


        Flag("validate", help="re-derive each identity and ask CloudShell directly"),
        Flag("delete", help="list what would be removed (add --yes to remove it)"),


        Flag("yes", help="with --delete, actually delete. Irreversible."),
    ),
    notes=(
        "WHAT THIS FINDS THAT `.enum` CANNOT: `.enum` asks each credential you\n"
        "  HOLD what it owns. `.discover` reads CloudTrail, so it finds\n"
        "  environments owned by principals you cannot become -- which is the\n"
        "  case that matters when cleaning up after a run that used a name you\n"
        "  no longer pass. It is capped at 90 days and sees activity only.\n"
        "--validate re-derives each discovered identity and asks CloudShell\n"
        "  directly. That is the only pass that catches an environment OLDER\n"
        "  than the CloudTrail window, and the only one that reports live state.\n"
        "--delete lists what it would remove; `--delete --yes` removes it.\n"
        "  Irreversible, and deletion authorizes on the CALLING principal --\n"
        "  an identity this source cannot become is one it cannot delete.\n"
        "region-selector: ALL | us-east-1 | us-east-1,us-west-2 | us-east-*\n"
        "\n"
        "THE SELECTOR NAMES WHO READS CLOUDTRAIL -- and nothing else.\n"
        "  ONE credential per ACCOUNT does the read (the log is account-wide,\n"
        "  so a second in the same account adds nothing), and the run SAYS\n"
        "  which one it used. Needs signing keys: a console credential has none.\n"
        "  Name one credential to use a key you know works, or several to\n"
        "  choose the reader per account across several accounts in one command.\n"
        "  Omitted means every credential is eligible.\n"
        "--validate / --delete ARE NOT RESTRICTED by the selector. Every loaded\n"
        "  credential is available, and the DISCOVERED ARN decides which one\n"
        "  applies -- everything is available, not everything is tried. A\n"
        "  credential is matched to an identity by what your -F file DECLARES\n"
        "  (`federation_name`, `role:<arn>`), same account only, so an\n"
        "  undeclared role -- which may be someone else's SSO session -- is\n"
        "  reported and never actioned.\n"
        "  The run reports how many discovered identities are actionable, so a\n"
        "  short delete plan explains itself."
    ),
)


def _discover_cred(state: "InteractiveState", num: int, rec: Any) -> Any:
    """One credential as a `discovery.Cred`, keys only"""
    from cloudbasher.csp.aws import discovery as disc

    c = disc.keys_only_cred(num, rec, label=rec.label or f"[{num}]")
    if c is not None:
        disc.identify_cred(c)
        return c


    stub = disc.Cred(num=num, record=rec, label=rec.label or f"[{num}]")


    disc.deny_keyless(stub, enumerate_cmd=".enum <ID>", discover_cmd=".discover")
    return stub


def _throttled(emit: "Callable[[str], None]", *, every: float = 1.0) -> "Callable[..., None]":
    """Rate-limit a progress sink to at most one line per `every` seconds."""


    state: "dict[str, Optional[float]]" = {"last": None}

    def _emit(msg: str, *_rest: Any) -> None:
        now = time.monotonic()
        last = state["last"]
        if last is not None and now - last < every:
            return
        state["last"] = now
        emit(msg)

    return _emit


def _discover_pools(
    state: "InteractiveState", selector: "Optional[str]"
) -> "tuple[list[Any], list[Any]]":
    """`(readers, pool)` -- the TWO ROLES a credential can play here"""
    from cloudbasher.core.types import numbered_originating_records

    numbered = numbered_originating_records(state.credentials_by_id)
    pool = [_discover_cred(state, num, rec) for num, rec in numbered]
    by_num = {c.num: c for c in pool}

    if not selector:


        return list(pool), pool

    rows = _bulk_credentials(state, selector)
    if rows is not None:
        picked, err = rows
        if err:
            eprint(f"discover: {err}")
            return [], pool
        wanted = [num for num, _rec in picked]
    else:


        from cloudbasher.core.selection import resolve_numbered_selector

        onepicked, unknown, malformed = resolve_numbered_selector(numbered, selector)
        if malformed:
            eprint(f"discover: {selector!r} is not a credential selector.")
            return [], pool
        if unknown:
            eprint(
                f"discover: no credential {', '.join(unknown)} is loaded -- "
                f"the identity listing numbers 1..{len(numbered)}."
            )
            return [], pool
        wanted = [num for num, _rec in onepicked]
    return [by_num[n] for n in wanted if n in by_num], pool


def cmd_discover(r: "ParseResult", state: "InteractiveState") -> bool:
    """`.discover [<ID>|selected|ALL|1,3,5] [region] <selector> [days <n>] [--validate] [--delete [--yes]]` -- the sweep, as a dot command"""
    from cloudbasher.core.cli.dispatcher import _AWS_STATUS_MAP, _fmt_table, _get_term_width
    from cloudbasher.core.identity_listing import is_verbose_identity
    from cloudbasher.csp.aws import discovery as disc


    probe = "validate" in r.flags


    _kw_region = r.value("region")
    _pos_region = r.positionals.get("region_selector")
    if _kw_region and _pos_region:
        eprint(
            f"discover: two region selectors -- `region {_kw_region}` and "
            f"{_pos_region!r}. They are two spellings of ONE argument; give one."
        )
        return True
    region_selector = _kw_region or _pos_region or "ALL"
    try:
        from cloudbasher.csp.aws.multi_region import resolve_regions

        regions = resolve_regions(region_selector)
    except Exception as exc:  # noqa: BLE001 - a bad selector is the user's, not ours
        eprint(f"discover: could not resolve {region_selector!r}: {exc}")
        return True

    days_raw = r.value("days")
    try:
        days = int(days_raw) if days_raw else 90
    except ValueError:
        eprint(f"discover: days must be a number, got {days_raw!r}")
        return True

    readers, pool = _discover_pools(state, r.selector)
    if not readers and not pool:
        eprint("discover: no credential is loaded.")
        return True


    _browser = browser_options(getattr(state, "args", None))
    from cloudbasher.csp.aws.control_plane import session_console_pool

    console_sources = session_console_pool(state)
    try:
        disc.ensure_account_readers(
            readers,
            pool=console_sources,


            browser=_browser,


            on_attempt=lambda c, account: out(f"discover: {disc.sso_last_resort_note(c, account)}"),
            on_outcome=lambda c, ok: (
                out(f"discover: {disc.sso_resolved_note(c)}")
                if ok
                else eprint(f"discover: {disc.sso_unresolved_note(c)}")
            ),
        )


        derivers = [c for c in pool if c.can_sign_sts]
        index = disc.resolve_principals(derivers)
        _report_resolution(index)


        blocked_readers = [c for c in readers if not c.can_read_cloudtrail]
        for c in blocked_readers:
            eprint(
                f"discover: {disc.cred_label(c)}: cannot read CloudTrail -- "
                f"{c.why_not(disc.READ_CLOUDTRAIL)}"
            )
        signers = [c for c in readers if c.can_read_cloudtrail]


        def _say_reader(account: str, chosen: Any, others: "list[Any]") -> None:
            """NAME THE READER, always: say which credential was selected for an account and which were passed over, so the choice is visible rather than inferred."""
            extra = (
                f" (also eligible: {', '.join(f'[{o.num}]' for o in others)}, unused "
                f"-- CloudTrail is account-wide, so one read covers the account)"
                if others
                else ""
            )
            out(
                f"discover: account {account}: reading CloudTrail as {disc.cred_tag(chosen)}{extra}"
            )

        sweepers = disc.pick_sweepers(signers, on_choice=_say_reader)


        _report_credential_ledger(
            pool,
            reading=list(sweepers.values()),
            deriving=derivers,
            invalid=blocked_readers,
        )


        if not sweepers:
            eprint(f"discover: {disc.NO_CLOUDTRAIL_REASON}")
            return True

        findings: list[Any] = []
        errors: list[str] = []
        out(
            f"discover: CloudTrail, {len(regions)} region(s) x {len(sweepers)} account(s), "
            f"last {days} day(s)"
        )


        mine = disc.discover_all(
            sweepers,
            regions,
            findings,
            errors,
            set(),
            days=days,


            on_tick=lambda msg, done, total: log(f"[discover] {msg} [{done}/{total} region scans]"),


            on_progress=_throttled(lambda msg: out(f"discover: {msg}")),
        )
        envs = len([f for f in mine if f.environment_id])
        out(
            f"discover: {envs} environment(s) + {len(mine) - envs} principal(s) with "
            f"activity but no environment id, {len(errors)} region error(s)"
        )


        keys_line = disc.id_keys_seen_line()
        if keys_line:
            out(f"discover: environment id read from {keys_line}")
        elif envs == 0 and mine:


            out(
                "discover: NO environment id was parsed from any event -- either the "
                "window genuinely holds no creates, or CloudTrail used a field "
                "spelling we do not read (see #458)."
            )


        ev_total, ev_findings, ev_first, ev_last = disc.events_summary(mine)
        if ev_total:
            span = f"{ev_first} .. {ev_last}" if ev_first else "no timestamps"
            out(
                f"discover: {ev_total} CloudTrail event(s) retained across "
                f"{ev_findings} finding(s), {span}"
            )


        groups = disc.match_identities(
            findings,
            derivers,
            {c.acts_as_arn for c in derivers if c.acts_as_arn},
            index=index,
        )
        _report_actionable_gap(groups, derivers, index=index)

        if probe:
            worklist = [
                (region, arn, ident)
                for (region, arn), ident in sorted(groups.items())
                if ident.actionable
            ]
            out(f"discover: probing {len(worklist)} identity/region pair(s)")
            probe_errors = disc.probe_all(
                worklist,
                findings,
                set(),
                on_tick=lambda msg: log(f"[probe] {msg}"),
            )
            if probe_errors:
                eprint(f"discover: {probe_errors} probe error(s) -- see the log")


        _verbose = is_verbose_identity()
        rows = [
            [
                disc.principal_cell(f.principal_arn, verbose=_verbose) or "?",
                f.region,
                f.environment_id or "(no id)",
                (
                    _AWS_STATUS_MAP.get(f.live_status, f.live_status)
                    if f.live_status


                    else ("deleted" if f.deleted_seen else (disc.unvalidated_reason(f) or "-"))
                ),
                f.note or "-",
            ]
            for f in disc.live_findings(findings, probed=probe)
        ]
        if rows:
            out(
                _fmt_table(


                    ["Target IdentityARN", "region", "environment", "state", "note"],
                    rows,
                    max_width=_get_term_width(),
                )
            )
        else:
            out("discover: nothing found.")


        unmanaged_store(state).replace(
            disc.live_findings(findings, probed=probe),
            regions=regions,
            days=days,
            accounts=len(sweepers),
            errors=errors,
        )
        if "delete" in r.flags:


            deleted = _discover_delete(
                r, findings, groups, disc.delete_router(derivers), state=state
            )
            unmanaged_store(state).mark_deleted(set(deleted))


        request_table_refresh(state)
    finally:


        disc.close_sources(pool, why=".discover finished")
    return True


_GAP_HEAD = 5


def _overflow_notice(total: int, limit: int, *, pad: str) -> bool:
    """*"... and N more (see the log)"* -- THE SENTENCE, and nothing else."""
    if total <= limit:
        return False
    out(f"{pad}... and {total - limit} more (see the log)")
    return True


def _out_overflow(rows: "list[str]", limit: int) -> None:
    """The overflow sentence, then the remainder to the log file."""
    if not rows:
        return
    head = rows[0]
    pad = head[: len(head) - len(head.lstrip())]


    _overflow_notice(len(rows), limit, pad=pad)
    for line in rows[limit:]:
        log_file_only(line)


def _out_capped(rows: "list[str]", limit: int) -> None:
    """A bounded head to the console, the whole list to the log file."""
    for line in rows[:limit]:
        out(line)
    _out_overflow(rows, limit)


def _report_resolution(index: "Any") -> None:
    """Print which credential becomes which principal, before any pass runs."""


    from cloudbasher.csp.aws import discovery as disc


    if not switch("aws.log_resolution"):
        return
    rows = index.report()
    if not rows:


        return
    out(f"discover: {disc.resolution_heading()}")


    _out_capped(rows, _GAP_HEAD)


_LEDGER_COLUMNS = (
    "Use",
    "ID",
    "Act|Org|Ten",
    "Cred ID",
    "Identity",
    "Acts As",
    "Acts As (resolved)",
    "Tier",
)


from cloudbasher.csp.aws.discovery import (  # noqa: E402
    USE_DISCOVER,
    USE_INVALID,
    glyph_cell,
    glyph_key_line,
)


USE_DERIVE = "A"


_LEDGER_LEGEND = (
    (USE_DISCOVER, "read CloudTrail for its account"),
    (USE_DERIVE, "available to act as a discovered identity"),
    (USE_INVALID, "cannot read CloudTrail"),
)


_LEDGER_INDENT = "  "


def _ledger_used_by(
    *,
    reading: "list[Any]",
    deriving: "list[Any]",
    invalid: "list[Any]",
) -> "dict[int, str]":
    """`{cred num: glyph cell}` for `credential_ledger_rows`'s `used_by`."""
    read = {c.num for c in reading}
    derive = {c.num for c in deriving}
    bad = {c.num for c in invalid}
    return {
        num: glyph_cell(
            _LEDGER_LEGEND,
            {
                USE_DISCOVER: num in read,
                USE_DERIVE: num in derive,
                USE_INVALID: num in bad,
            },
        )
        for num in read | derive | bad
    }


def _report_credential_ledger(
    pool: "list[Any]",
    *,
    reading: "list[Any]",
    deriving: "list[Any]",
    invalid: "list[Any]",
) -> None:
    """What every loaded credential IS, and what this run used it for."""
    from cloudbasher.core.identity_listing import _UNKNOWN
    from cloudbasher.core.utils.table_block import format_table_block
    from cloudbasher.csp.aws import discovery as disc

    if not pool or not switch("aws.log_resolution"):
        return
    cells = disc.credential_ledger_rows(
        pool,
        used_by=_ledger_used_by(reading=reading, deriving=deriving, invalid=invalid),
    )
    header = list(_LEDGER_COLUMNS)
    data = [
        [
            cell.used_by,
            cell.num,
            cell.account,
            cell.cred_id,
            cell.identity,
            cell.declared_target,
            cell.acts_as_measured or _UNKNOWN,
            cell.tier or _UNKNOWN,
        ]
        for cell in cells
    ]
    out(f"discover: credential ledger -- {len(data)} loaded")


    out(format_table_block([header] + data[:_GAP_HEAD], indent=_LEDGER_INDENT, lead_blank=True))


    if _overflow_notice(len(data), _GAP_HEAD, pad=_LEDGER_INDENT):
        log_file_only(format_table_block([header] + data, indent=_LEDGER_INDENT, lead_blank=True))


    out(_LEDGER_INDENT + glyph_key_line(_LEDGER_LEGEND))


def _report_actionable_gap(groups: dict, derivers: "list[Any]", index: "Any" = None) -> None:
    """Say how many discovered identities the NAMED credentials can act on."""
    from cloudbasher.core.identity_listing import arn_tail
    from cloudbasher.csp.aws import discovery as disc

    if not groups:
        return
    blocked = [i for i in groups.values() if not i.actionable]
    if not blocked:
        return
    named = ", ".join(f"[{c.num}]" for c in derivers) or "none"
    out(
        f"discover: {len(groups) - len(blocked)}/{len(groups)} discovered "
        f"identity/ies can be acted on with the credential(s) you named ({named}). "
        f"A CloudTrail read is account-wide, but --validate and --delete need a "
        f"credential that can BECOME each identity."
    )


    show_rules = index is not None and switch("aws.log_resolution")

    def _line(i: "Any") -> str:
        """One blocked identity. ONE SPELLING -- the console and the log file printed two, and the log one dropped the fallback, so an identity with no `reason` logged a blank where the screen said why."""
        return f"  - {arn_tail(i.arn) or i.arn}: {i.why_blocked}"

    for i in blocked[:_GAP_HEAD]:
        out(_line(i))
        if show_rules:
            _out_capped([f"      {line}" for line in disc.explain_unmatched(i, index)], 4)


    _out_overflow([_line(i) for i in blocked], _GAP_HEAD)


def _drop_targets_a_build_owns(
    targets: "list[Any]", state: "Optional[InteractiveState]", *, label: str, guard: "Guard"
) -> "list[Any]":
    """THE ENV-ID-KEYED DELETE PATH, GUARDED AT THE CHOKEPOINT."""
    from cloudbasher.core.cli.dispatcher import guard_reasons_by_env_id

    reasons = guard_reasons_by_env_id(getattr(state, "nodes_by_id", None) or {}, guard=guard)


    kept = []
    for t in targets:
        why = reasons.get(t.env_id)
        if why is None:
            kept.append(t)
            continue
        eprint(f"{label}: skipping {t.region} {t.env_id} -- {why}")
    if targets and not kept:


        eprint(
            f"{label}: every environment matched is owned by a running build; "
            "nothing to delete. Use `.delete <selector> --force` to override one."
        )
    return kept


def _retire_targets_the_registry_still_holds(
    targets: "list[Any]", state: "Optional[InteractiveState]", *, label: str
) -> None:
    """Retire the server-side sessions of any target that IS a node."""
    from cloudbasher.core.cli.dispatcher import nodes_by_env_id

    by_env = nodes_by_env_id(getattr(state, "nodes_by_id", None) or {})
    for t in targets:
        node = by_env.get(t.env_id)
        if node is None:
            continue
        detail(f"{label}: {t.env_id} is registered as node {node.id}; retiring its sessions")
        node.retire_server_sessions()


def delete_found_environments(
    findings: "list[Any]",
    groups: dict,
    by_principal: dict,
    *,
    confirmed: bool,
    label: str,
    state: "Any",
) -> "list[str]":
    """Plan the deletion, and carry it out only when `confirmed`. Returns the environment ids actually deleted."""
    from cloudbasher.core.cli.dispatcher import Guard
    from cloudbasher.csp.aws import discovery as disc

    targets, duplicates = disc.build_delete_targets(findings, groups, by_principal)


    targets = _drop_targets_a_build_owns(targets, state, label=label, guard=Guard.BUILD)
    if not targets:
        out(f"{label}: nothing to delete.")
        return []


    direct = len([t for t in targets if t.cred is not None])
    out(
        f"{label}: would delete {len(targets)} environment(s) ({direct} enumerated "
        f"directly, {len(targets) - direct} matched by declaration"
        + (f", {duplicates} duplicate(s) suppressed" if duplicates else "")
        + "):"
    )
    for t in targets:
        out(f"  {t.region}  {t.env_id}  as {t.acting_as}")
    if not confirmed:
        out(f"{label}: add --yes to actually delete. (Irreversible.)")
        return []

    def _report(t: Any, outcome: str, why: str) -> None:
        """This surface's SINKS for one delete. The LINES come from ``disc.delete_receipt()``: they were previously duplicated byte-for-byte in the sweep helper, both copies had to be edited in lockstep, and the AccessDenied note was gated on a field the direct route never sets."""
        lines, to_stderr = disc.delete_receipt(t, outcome, why)
        for line in lines:
            (eprint if to_stderr else out)(line)


    _retire_targets_the_registry_still_holds(targets, state, label=label)
    deleted, failed = disc.delete_all(targets, on_result=_report)
    out(f"{label}: deleted {len(deleted)}/{len(targets)}, {failed} failure(s).")


    return [env_id for _region, env_id in deleted]


_UNMANAGED_KEY = "aws_unmanaged"


def request_table_refresh(state: "InteractiveState") -> None:
    """Ask the Nodes pane to repaint"""
    hook = getattr(state, "request_table_refresh", None)
    if hook is None:
        return
    try:
        hook()
    except Exception:  # noqa: BLE001 - a failed repaint must not fail the command
        pass


def unmanaged_store(state: "InteractiveState") -> "Any":
    """THE `UnmanagedStore` for this session, created on first use."""
    from cloudbasher.csp.aws.unmanaged import UnmanagedStore

    if state.extra is None:
        state.extra = {}
    got = state.extra.get(_UNMANAGED_KEY)
    if not isinstance(got, UnmanagedStore):
        got = UnmanagedStore()
        state.extra[_UNMANAGED_KEY] = got
    return got


UNMANAGED_SPEC = CommandSpec(
    name="unmanaged",
    summary="Act on what `.discover`/`.enum` found but cloudbasher is not tracking",


    effects=Effects.DESTROYS_CLOUD | Effects.MUTATES_REGISTRY,
    terminals=(Verb("delete"), Verb("register")),
    subcommands={
        "delete": CommandSpec(
            name="unmanaged delete",
            summary="Delete found environments. Dry run unless --yes.",
            effects=Effects.DESTROYS_CLOUD,
            terminals=(
                Positional(
                    "selector", required=False, usage_label="<envID>|<#>|selected|ALL|1,3,5"
                ),
                Flag("yes", help="actually delete. Irreversible."),
            ),
        ),
        "register": CommandSpec(
            name="unmanaged register",
            summary="Start tracking found environments as nodes",
            effects=Effects.MUTATES_REGISTRY,
            terminals=(
                Positional(
                    "selector", required=False, usage_label="<envID>|<#>|selected|ALL|1,3,5"
                ),
            ),
        ),
    },
    notes=(
        "THE SET IT ACTS ON is whatever `.discover` or `.enum` last found --\n"
        "  this command NEVER scans. That is the point: a CloudTrail sweep\n"
        "  takes minutes, and acting on its result should not re-run it.\n"
        "  Run `.discover` first; `.unmanaged` on an empty set says so.\n"
        "THE `#` IS THIS SET'S OWN INDEX, not a cred# and not a Nodes Row# --\n"
        "  those address the registry and these rows are not in it. An\n"
        "  environment id works too, and is what you will have from a log line.\n"
        "REGISTER means START TRACKING: it writes a node into the registry so\n"
        "  the environment appears in the Nodes pane and `.connect`/`.start`\n"
        "  can reach it. It does not connect, and it creates nothing in the\n"
        "  cloud. It needs an environment id AND a loaded credential that can\n"
        "  BECOME the owning principal -- deletion and connection both\n"
        "  authorize on the calling principal, so a row we cannot become is a\n"
        "  row we could register and then never use.\n"
        "DELETE lists what it would remove; `delete --yes` removes it.\n"
        "  Irreversible, and it routes exactly as `.discover --delete` does --\n"
        "  the same engine, so the two cannot disagree about what is deletable.\n"
    ),
)


def _unmanaged_flags(r: "ParseResult") -> "set[str]":
    """The sub-command's flags. `--yes` is declared on `unmanaged delete`, not on `unmanaged`, so it arrives in `r.sub.flags` and `r.flags` is empty."""
    return set(r.sub.flags) if r.sub is not None else set()


def _unmanaged_pick(
    r: "ParseResult", state: "InteractiveState", verb: str
) -> "Optional[tuple[Any, list[Any]]]":
    """`(store, picked rows)`, or None once a refusal has been printed."""
    from cloudbasher.csp.aws.unmanaged import resolve_unmanaged_selector

    store = unmanaged_store(state)
    if store.never_run:
        eprint(
            f"unmanaged {verb}: no discovery has run this session. "
            "`.discover` reads CloudTrail; `.enum` asks the credentials you hold."
        )
        return None
    rows = store.rows()
    if not rows:
        eprint(f"unmanaged {verb}: the last scan found nothing ({store.scope_sentence()}).")
        return None


    sub = r.sub
    token = (sub.positionals.get("selector") if sub is not None else None) or "selected"


    picked, unknown = resolve_unmanaged_selector(
        rows, token, set(getattr(state, "selected_finding_ids", set()) or set())
    )
    if unknown:


        eprint(
            f"unmanaged {verb}: no such row: {', '.join(sorted(unknown))}. "
            f"The set has {len(rows)} row(s), numbered 1..{len(rows)}."
        )
        return None
    if not picked:
        eprint(
            f"unmanaged {verb}: nothing selected. Tick rows in the Unmanaged tab, "
            f"or name them: `.unmanaged {verb} 1,3` / `.unmanaged {verb} ALL`."
        )
        return None
    return store, picked


def cmd_unmanaged(r: "ParseResult", state: "InteractiveState") -> bool:
    """`.unmanaged delete|register <envID>|<#>|selected|ALL|1,3,5`"""
    from cloudbasher.csp.aws import discovery as disc

    verb = r.verb or ""
    got = _unmanaged_pick(r, state, verb)
    if got is None:
        return True
    store, picked = got


    _readers, pool = _discover_pools(state, None)
    if not pool:
        eprint(f"unmanaged {verb}: no credential is loaded.")
        return True


    derivers = [c for c in pool if c.can_sign_sts]
    try:


        index = disc.resolve_principals(derivers)
        groups = disc.match_identities(
            picked,
            derivers,
            {c.acts_as_arn for c in derivers if c.acts_as_arn},
            index=index,
        )


        router = disc.delete_router(derivers)
        if verb == "delete":
            deleted = delete_found_environments(
                picked,
                groups,
                router,
                confirmed="yes" in _unmanaged_flags(r),
                label="unmanaged delete",
                state=state,
            )
            store.mark_deleted(set(deleted))
        else:
            _unmanaged_register(state, picked, groups, router)
    finally:
        disc.close_sources(pool, why=".unmanaged finished")


    request_table_refresh(state)
    return True


def _owning_principal_name(arn: str) -> "Optional[str]":
    """The STS name a derived principal must be re-derived under, off its ARN."""
    from cloudbasher.csp.aws.discovery import parse_principal

    if not arn:
        return None
    ident = parse_principal(arn)
    if ident.kind == "assume_role":
        return ident.session_name or None
    if ident.kind == "federation_token":
        return ident.ref or None
    return None


def _unmanaged_register(
    state: "InteractiveState", picked: "list[Any]", groups: dict, router: dict
) -> None:
    """Start TRACKING each picked environment -- to register is to have found an environment and decided to see, track or manage it again."""
    from cloudbasher.cli.main import _activate_target_identity
    from cloudbasher.core.cli.dispatcher import _AWS_STATUS_MAP
    from cloudbasher.csp.aws import discovery as disc

    by_arn = {ident.arn: ident for ident in groups.values()}
    registered: "list[str]" = []
    skipped: "list[str]" = []
    for f in picked:
        if not f.environment_id:
            skipped.append(f"{f.region} {disc.short_principal(f.principal_arn)}: no environment id")
            continue
        ident = by_arn.get(f.principal_arn)
        cred = None
        if ident is not None and ident.deriver is not None:
            cred = ident.deriver.cred
        elif f.cred_num is not None:


            cred = disc.route_finding(router, f)
        if cred is None:
            skipped.append(
                f"{f.region} {f.environment_id}: no loaded credential can become "
                f"{disc.short_principal(f.principal_arn)}"
            )
            continue


        requested = _owning_principal_name(f.principal_arn)
        if requested is None:


            skipped.append(
                f"{f.region} {f.environment_id}: cannot tell which principal owns it "
                f"from {f.principal_arn!r} -- re-run `.discover --validate` or `.enum` "
                "so the full ARN is recorded"
            )
            continue
        try:
            node_credential_id = _activate_target_identity(
                cred.record, state.credentials_by_id, out, requested_name=requested
            )
        except Exception as exc:  # noqa: BLE001 - one row must not kill the batch
            skipped.append(f"{f.region} {f.environment_id}: {type(exc).__name__}: {exc}")
            continue
        node = _adopt_or_fill_placeholder(
            state,
            cred.record,
            node_credential_id,
            f.region,
            f.environment_id,


            _AWS_STATUS_MAP.get(f.live_status or "", "Unknown"),
        )
        state.register_node(node)
        registered.append(f.environment_id)
        out(f"  registered {f.region} {f.environment_id} as {node.id}")


    out(f"unmanaged register: registered {len(registered)}, skipped {len(skipped)}.")
    for s in skipped:
        eprint(f"  skipped {s}")


def _discover_delete(
    r: "ParseResult", findings: "list[Any]", groups: dict, by_principal: dict, *, state: "Any"
) -> "list[str]":
    """`.discover`'s spelling of the shared delete pass. Returns the ids deleted."""
    return delete_found_environments(
        findings, groups, by_principal, confirmed="yes" in r.flags, label="discover", state=state
    )
