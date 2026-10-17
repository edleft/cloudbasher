#!/usr/bin/env python3
"""Account-wide AWS CloudShell environment sweep: discover, probe, delete."""

from __future__ import annotations

import argparse
import atexit
import contextlib
import io
import json
import os
import sys
from collections import defaultdict
from typing import Any, Optional

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))


import cloudbasher.csp.aws.credentials as _credentials  # noqa: E402
import cloudbasher.csp.aws.discovery as _discovery  # noqa: E402
from cloudbasher.core.exceptions import CredentialError  # noqa: E402
from cloudbasher.core.utils.output import mask_secrets  # noqa: E402
from cloudbasher.csp.aws.credentials import (  # noqa: E402
    AwsSessionCreds,
)
from cloudbasher.csp.aws.discovery import (  # noqa: E402
    _EVENTS_KEPT,
    ENUMERATE,
    USE_DISCOVER,
    USE_INVALID,
    Cred,
    Finding,
    Identity,
    Target,
    _EnvRecord,
    build_delete_targets,
    close_sources,
    cred_label,
    cred_tag,
    delete_all,
    delete_receipt,
    delete_router,
    deny_keyless,
    discover_all,
    effective_index,
    ensure_account_readers,
    enumerate_direct,
    glyph_cell,
    glyph_key_line,
    id_keys_seen,
    identify_cred,
    keys_only_cred,
    live_findings,
    match_identities,
    named_identity_creds,
    open_source,
    pick_sweepers,
    probe_all,
    resolution_heading,
    resolve_principals,
    short_principal,
    sso_last_resort_note,
    sso_resolved_note,
    sso_unresolved_note,
    unvalidated_reason,
)


from cloudbasher.csp.aws.provision_request import (  # noqa: E402
    DECLARED,
    INDEX_NONE,
    TYPED_NONE,
    source_word,
)


def _claim_engine_sinks() -> None:
    """Point the engine's diagnostics at THIS script's log and stderr."""
    _discovery.detail_sink = log_only
    _discovery.warn_sink = _say_err


    _credentials.derive_notice_sink = _say_err


def _say_err(line: str) -> None:
    say(line, stream=sys.stderr)


from cloudbasher.core.browser_options import browser_options  # noqa: E402
from cloudbasher.csp.aws.control_plane import ConsoleSourcePool  # noqa: E402
from cloudbasher.csp.aws.multi_region import _ALL_REGIONS, resolve_regions  # noqa: E402

_INLINE_LIST = 10


_LOG_FH: Any = None


def open_detail_log(path: Optional[str]) -> Optional[str]:
    """Start the detail log, or return None if it cannot be written."""
    global _LOG_FH
    if not path:
        return None
    try:
        _LOG_FH = open(path, "w", encoding="utf-8")
    except OSError as exc:
        print(f"  ! cannot write {path}: {exc}", file=sys.stderr)
        return None
    return path


def close_detail_log() -> None:
    global _LOG_FH
    if _LOG_FH:
        _LOG_FH.close()
        _LOG_FH = None


def say(line: str = "", *, stream: Any = None) -> None:
    """Print, and log. The one call for anything a user is meant to read."""
    print(line, file=stream or sys.stdout, flush=True)
    log_only(line)


def log_only(line: str = "") -> None:
    if _LOG_FH:
        _LOG_FH.write(line + "\n")


class Progress:
    """One-line m/n progress for a stage."""

    def __init__(self, total: int, label: str, *, every_pct: int = 10) -> None:
        self.total = max(total, 0)
        self.label = label
        self.n = 0
        self.tty = sys.stderr.isatty()
        self._next_milestone = every_pct
        self._every_pct = every_pct
        if self.total and not self.tty:
            print(f"{label}: 0/{self.total}", file=sys.stderr, flush=True)

    def tick(self, detail: str = "") -> None:
        self.n += 1
        if not self.total:
            return
        pct = int(self.n * 100 / self.total)
        if self.tty:


            self.note(detail)
        elif pct >= self._next_milestone or self.n == self.total:
            print(f"  {self.label}: {self.n}/{self.total} ({pct}%)", file=sys.stderr, flush=True)
            while self._next_milestone <= pct:
                self._next_milestone += self._every_pct

    def note(self, detail: str = "") -> None:
        """Redraw with a detail WITHOUT advancing the counter"""
        if not self.tty or not self.total:
            return
        pct = int(self.n * 100 / self.total)
        suffix = f"  {detail}" if detail else ""
        print(
            f"\r  {self.label}: {self.n}/{self.total} ({pct}%){suffix}\x1b[K",
            end="",
            file=sys.stderr,
            flush=True,
        )

    def done(self, summary: str = "") -> None:
        tail = f"  {summary}" if summary else ""


        log_only(f"  {self.label}: {self.n}/{self.total} done{tail}")
        if self.tty and self.total:
            print(
                f"\r  {self.label}: {self.n}/{self.total} done{tail}\x1b[K",
                file=sys.stderr,
                flush=True,
            )
        elif summary:
            print(f"  {self.label}: done{tail}", file=sys.stderr, flush=True)


_NUMBERED_CACHE: "dict[str, list[tuple[int, Any]]]" = {}


def numbered_creds(path: str) -> list[tuple[int, Any]]:
    """`(cred#, record)` for a `-F` file, numbered as the TUI numbers them."""
    import types

    from cloudbasher.cli.main import records_from_creds_file
    from cloudbasher.core.types import numbered_originating_records


    cached = _NUMBERED_CACHE.get(path)
    if cached is not None:
        return cached
    records = records_from_creds_file(types.SimpleNamespace(creds_file=path))
    if not records:


        raise SystemExit(f"{path}: no credential records (missing, unreadable or empty).")


    numbered = numbered_originating_records({r.id: r for r in records})
    _NUMBERED_CACHE[path] = numbered
    return numbered


def reset_numbered_cache() -> None:
    """TEST-ONLY. The cache is keyed by path and a test suite reuses `tmp_path` filenames across cases, so one case's file would answer for another's."""
    _NUMBERED_CACHE.clear()


def narrow_to_selector(creds: list[Cred], creds_file: "Optional[str]", selector: str) -> list[Cred]:
    """The loaded credentials `selector` picks. ONE narrowing, every caller."""
    if not creds_file:
        return list(creds)
    nums = {c.num for c in select_creds(creds_file, selector)}
    return [c for c in creds if c.num in nums]


def select_creds(path: str, selector: str) -> list[Cred]:
    """Resolve `ALL` / `3` / `1,3,5` against the file's numbering."""
    numbered = numbered_creds(path)
    if not numbered:
        raise SystemExit(f"{path}: no credentials parsed.")
    by_num = dict(numbered)
    token = (selector or "ALL").strip()

    if token.lower() == "selected":
        raise SystemExit(
            "`selected` is a TUI gesture (ticked rows in the Nodes pane) and "
            "means nothing here. Use ALL, or a number from the listing."
        )
    if token.lower() == "all":
        wanted = [n for n, _ in numbered]
    else:


        from cloudbasher.core.selection import resolve_numbered_selector

        picked, unknown, malformed = resolve_numbered_selector(numbered, token)


        if malformed:
            raise SystemExit(f"{token!r}: expected ALL, a number, or 1,3,5")
        if unknown:
            raise SystemExit(
                f"no credential {', '.join(unknown)} in {path} -- "
                f"the listing numbers 1..{len(numbered)}"
            )
        wanted = [n for n, _ in picked]
    return [Cred(num=n, record=by_num[n], label=by_num[n].label or f"[{n}]") for n in wanted]


def load_creds() -> AwsSessionCreds:
    """The AWS_* environment as one credential. A `-F` file goes elsewhere."""
    ak, sk = os.getenv("AWS_ACCESS_KEY_ID"), os.getenv("AWS_SECRET_ACCESS_KEY")
    if not ak or not sk:
        raise SystemExit(
            "No credentials. Pass -F <file>, or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY."
        )
    return AwsSessionCreds(
        access_key=ak, secret_key=sk, session_token=os.getenv("AWS_SESSION_TOKEN")
    )


def report_derivation_gap(groups: dict[tuple[str, str], Identity], index: "Any" = None) -> int:
    """Say up front which identities this run cannot act on, and why."""


    blocked_fed = [
        i
        for i in groups.values()
        if i.kind == "federation_token" and (i.deriver is None or not i.deriver.cred.long_term)
    ]
    unreconstructable = [i for i in groups.values() if not i.reconstructable]


    already = {i.arn for i in blocked_fed}
    unreachable: dict[str, Identity] = {}
    for i in groups.values() if index is not None else ():
        if i.reconstructable and not i.actionable and i.arn not in already:
            unreachable.setdefault(i.arn, i)
    if not blocked_fed and not unreconstructable and not unreachable:
        return 0


    say("")
    say("IDENTITIES THIS RUN CANNOT ACT ON:")
    if blocked_fed:
        names = sorted({i.ref or "?" for i in blocked_fed})
        say(
            f"  CANNOT reconstruct {len(blocked_fed)} federated identity/region pair(s) "
            f"({len(names)} distinct name(s)) with temporary credentials:"
        )
        say(f"    {', '.join(names[:12])}{' ...' if len(names) > 12 else ''}")
        say(
            "  sts:GetFederationToken rejects ASIA keys. Re-run with the long-term "
            "AKIA key\n  that created these environments to probe or delete them."
        )


    if unreconstructable:
        names = sorted({i.arn for i in unreconstructable})
        say(
            f"  {len(names)} identity/ies cannot be reconstructed from their ARN shape "
            f"({len(unreconstructable)} identity/region pair(s)):"
        )
        for arn in names[:_INLINE_LIST]:
            say(f"    {arn}")
        if len(names) > _INLINE_LIST:
            say(
                f"    ... and {len(names) - _INLINE_LIST} more -- every one of them, with "
                f"its reason, under NOT PROBED in the detail log."
            )
    if unreachable:


        by_answer: dict[tuple[str, ...], list[str]] = {}
        for arn, ident in sorted(unreachable.items()):


            by_answer.setdefault(tuple(_discovery.explain_unmatched(ident, index)), []).append(arn)
        say(
            f"  {len(unreachable)} identity/ies can be reconstructed, and no loaded "
            f"credential can become them ({len(by_answer)} distinct answer(s)):"
        )
        for lines, arns in by_answer.items():
            for arn in arns[:_INLINE_LIST]:
                say(f"    {arn}")
            if len(arns) > _INLINE_LIST:
                say(
                    f"    ... and {len(arns) - _INLINE_LIST} more with the SAME answer "
                    f"-- every one of them under NOT PROBED in the detail log."
                )


            for line in lines:
                say(f"      {line}")


    return len(blocked_fed) + len(unreconstructable) + len(unreachable)


def _rows_for(findings: list[Finding], how: str) -> list[Finding]:
    return [f for f in findings if f.found_by == how and f.environment_id]


_COLS = ("PRINCIPAL", "REGION", "ENVIRONMENT", "STATE", "TIMESTAMP", "NOTE")


def aligned(
    headers: "tuple[str, ...]", rows: list[tuple], *, emit: Any, indent: str = "  "
) -> None:
    """A table whose columns are sized to the DATA. NOTHING IS EVER TRUNCATED."""
    from cloudbasher.core.utils.table_block import format_table_block, strip_table_marks

    block = format_table_block([list(headers)] + [[str(c) for c in r] for r in rows], indent=indent)
    for line in strip_table_marks(block).splitlines():
        emit(line)


def _row_state(f: Finding) -> str:
    """The STATE cell. A live status outranks an event name, because it was measured rather than inferred -- and an unvalidated row says so in words rather than leaving the reader to infer it from an event name."""
    if f.live_status:
        return f.live_status
    if f.deleted_seen:
        return f"deleted ({f.last_event or 'deleteEnvironment'})"
    if why := unvalidated_reason(f):
        return f"UNVALIDATED ({why})"
    return f"UNVALIDATED (last event {f.last_event or '-'})"


def _print_findings(rows: list[Finding], *, emit: Any) -> None:
    """One line per environment, with the PRINCIPAL AS A FULL ARN."""
    if not rows:
        emit("  (none)")
        return


    notes = any(f.note for f in rows)
    cols = _COLS if notes else _COLS[:-1]
    aligned(
        cols,
        [
            (
                f.principal_arn or "-",
                f.region,
                f.environment_id or "-",
                _row_state(f),
                (f.observed_at or f.last_event_at or f.created_at or "-")[:19],
            )
            + ((f.note or "",) if notes else ())
            for f in sorted(rows, key=lambda x: (short_principal(x.principal_arn), x.region))
        ],
        emit=emit,
    )


_RULE = "-" * 96


def rule() -> None:
    say(_RULE)


USE_SELECTED, USE_ENUMERATE = "*", "E"


CRED_COLUMNS = (
    "Use",
    "ID",
    "CSP",
    "Act|Org|Ten",
    "Identity",
    "Cred ID",
    "Tgt Act|Org|Ten",
    "Acts As",
    "Name",
    "Index",
    "Region",
)


from cloudbasher.core.identity_listing import _UNKNOWN as _EM  # noqa: E402


USE_LEGEND = (
    (USE_SELECTED, "selected credential (command line)"),
    (USE_ENUMERATE, "enumerate"),
    (USE_DISCOVER, "discovery (CloudTrail account)"),
    (USE_INVALID, "invalid -- reason follows"),
)


def use_cell(*, named: bool, enumerating: bool, reading: bool, invalid: bool) -> str:
    """The `Use` cell for one credential: what it does IN THIS RUN"""
    state = {
        USE_SELECTED: named,
        USE_ENUMERATE: enumerating,
        USE_DISCOVER: reading,
        USE_INVALID: invalid,
    }


    return glyph_cell(USE_LEGEND, state)


def _selector_phrase(raw: "Optional[str]", active: bool) -> str:
    """How a selector reads in the `Parsing ...` line"""
    if not active:
        return "not run"
    if not raw or raw == "ALL":
        return "ALL"


    many = "," in raw or "-" in raw
    return f"with cred{'s' if many else ''} #{raw}"


def name_and_index_provenance(
    cred: "Cred", requested_name: "Optional[str]", requested_index: "Optional[str]"
) -> str:
    """`name X (declared), index 4 (declared)` -- where each half came from."""
    from cloudbasher.csp.aws.credentials import CredentialError, resolve_identity_name

    if cred.keys is None:
        return ""
    try:
        name, name_source = resolve_identity_name(cred.keys, requested_name, where="--enumerate")
    except CredentialError:


        return ""


    _choice = effective_index(cred, requested_index)
    spec, index_source = _choice.spec, _choice.source
    if spec is None:
        index = INDEX_NONE if index_source == TYPED_NONE else "(none)"
    else:
        index = index_text(spec)


    said = source_word(index_source)
    return f"name {name} ({name_source}), index {index} ({said})"


def index_text(spec: "Optional[tuple[int, int]]") -> str:
    """`4`, `11-12`, or "" -- the ONE place a spec becomes text"""
    if spec is None:
        return ""
    start, end = spec
    return str(start) if start == end else f"{start}-{end}"


def index_cell(cred: "Cred", requested: "Optional[str]") -> str:
    """The `Index` cell: the index THIS RUN will use, and where it came from."""
    _choice = effective_index(cred, requested)
    spec, source = _choice.spec, _choice.source
    if source == TYPED_NONE:
        return INDEX_NONE
    if spec is None:
        return _EM
    text = index_text(spec)


    return f"[{text}]" if source == DECLARED else text


def credentials_table(
    cred_set: "list[Cred]",
    *,
    named_nums: "set[int]",
    enum_nums: "set[int]",
    reader_nums: "set[int]",
    broken_nums: "set[int]",
    cli_name: str = "",
    cli_index: str = "",
    cli_region: str = "",
) -> str:
    """The credentials block as ONE table, like the TUI's Creds pane"""
    from cloudbasher.core.utils.table_block import format_table_block, strip_table_marks
    from cloudbasher.csp.aws.discovery import credential_ledger_rows


    ledger = credential_ledger_rows(cred_set, used_by={})
    rows: "list[list[str]]" = [list(CRED_COLUMNS)]
    cross_account = any(cell.cross_account for cell in ledger)
    for c, cell in zip(cred_set, ledger):
        named = c.num in named_nums
        rows.append(
            [
                use_cell(
                    named=named,
                    enumerating=c.num in enum_nums,
                    reading=c.num in reader_nums,
                    invalid=c.num in broken_nums,
                ),
                cell.num,
                cell.csp,
                cell.account,


                cell.acts_as_measured or cell.identity,
                cell.cred_id,
                cell.target_account,


                cell.declared_target,
                (cli_name if named and cli_name else cell.name) or _EM,
                index_cell(c, cli_index if named else None),
                (cli_region if named and cli_region else cell.region) or _EM,
            ]
        )


    block = strip_table_marks(format_table_block(rows, lead_blank=True))


    block += "\n\n  " + glyph_key_line(USE_LEGEND)
    if cross_account:


        block += (
            "\n  account: own->target -- the value after -> is the account of the "
            "ROLE being assumed, not the account the credential itself lives in"
        )
    return block


_DOC_ENUMERATE = (
    "  Asks each credential what it owns now, via describeEnvironments +",
    "  getEnvironmentStatus. Authoritative, and not limited to any time window.",
)
_DOC_DISCOVER = (
    "  Reads CloudTrail LookupEvents (EventSource=cloudshell.amazonaws.com). The",
    "  environment id comes from responseElements/requestParameters.EnvironmentId;",
    "  createEnvironment sets the owner, deleteEnvironment marks it gone. No live status.",
)
_DOC_VALIDATE = (
    "  Re-derives each identity DISCOVER found and asks IT what it owns now.",
    "  The only way to see environments older than the CloudTrail window.",
)


def begin_step(
    n: int | None,
    total: int,
    name: str,
    *,
    tagline: str = "",
    doc: tuple = (),
    ran: bool = True,
    extra: tuple = (),
) -> None:
    """Open a numbered step: rule, `[n/total] NAME`, then what it does."""
    rule()
    say(f"[{n}/{total}] {name.upper()}" if n is not None else f"{name.upper()}")
    if not ran:
        say("  (not run)")
        return
    if tagline:
        say(f"  {tagline}")
    for line in doc:
        say(line)
    for line in extra:
        say(line)
    say("")


def build_plan(
    enumerate_: bool, discover: bool, validate: bool, delete: bool
) -> tuple[list[str], int, dict[str, int]]:
    """The named steps, the denominator, and each step's number."""
    plan = ["Credentials"]
    if enumerate_:
        plan.append("Enumerate")
    if discover:
        plan.append("Discover")
    if validate:
        plan.append("Validate")
    if delete:
        plan.append("Delete")
    return plan, len(plan), {name: i for i, name in enumerate(plan, start=1)}


def print_header(argv: list[str], steps: list[str]) -> None:
    """The invocation, and the steps it will take, before anything runs."""
    rule()
    say(" ".join(argv))
    say("")
    say("Processing steps:")
    for i, name in enumerate(steps, start=1):
        say(f"  {i}. {name}")


def pass_findings(rows: list[Finding], *, emit: Any) -> None:
    """A pass's findings, under the section that produced them."""
    if not rows:
        return
    emit("  FINDINGS:")
    _print_findings(rows, emit=emit)


def report_validate(groups: dict, probed: list, *, emit: Any) -> None:
    """Which identities VALIDATE reached, and which it did not and why."""
    by_arn: dict[str, Any] = {}
    for _region, _arn, ident in probed:
        by_arn.setdefault(ident.arn, ident)

    emit(f"  PROBED ({len(by_arn)} identity/ies, {len(probed)} identity/region pair(s)):")
    if not by_arn:
        emit("    (none)")
    else:


        aligned(
            ("IDENTITY (probed as)", "VIA", "CREDENTIAL SIGNS AS", "RULE"),
            [
                (
                    arn,
                    cred_tag(i.deriver.cred) if i.deriver else "[cred#?]",
                    (i.deriver.cred.acts_as_arn or "(identity unknown)") if i.deriver else "?",


                    i.deriver.rule if i.deriver else "?",
                )
                for arn, i in sorted(by_arn.items())
            ],
            emit=emit,
            indent="    ",
        )


    skipped = sorted(
        {(i.arn, i.reason or "not actionable") for i in groups.values() if i.arn not in by_arn}
    )
    if skipped:


        emit(f"  NOT PROBED ({len(skipped)}):")
        aligned(
            ("IDENTITY", "WHY NOT"),
            list(skipped),
            emit=emit,
            indent="    ",
        )


def report_summary(
    findings: list[Finding],
    *,
    enumerated: bool,
    discovered: bool,
    validated: int,
    probed: bool,
    log_path: Optional[str],
    incomplete_regions: int = 0,
) -> None:
    """The last thing on screen, and the only thing on screen by default."""

    def row(label: str, count: Optional[int], desc: str, indent: int = 2) -> None:
        left = " " * indent + label
        num = "" if count is None else str(count)
        say(f"{left:<21}{num:>5} {desc}".rstrip())

    e = _rows_for(findings, "enumerate")
    d = _rows_for(findings, "discover")
    with_id = [f for f in findings if f.environment_id]


    open_ = live_findings(findings, probed=probed)
    gone = [f for f in with_id if f.deleted_seen or f.live_status == "gone"]


    confirmed = [f for f in open_ if f.live_status]
    unvalidated = [f for f in open_ if not f.live_status]


    unanswered = [f for f in unvalidated if f.probe_failure_class]


    say("SUMMARY")
    row(
        "enumerate",
        len(e) if enumerated else None,
        "environment(s)" if enumerated else "not run",
    )
    row(
        "discover",
        len(d) if discovered else None,
        "environment(s) (CloudTrail, historical)" if discovered else "not run",
    )
    row(
        "validate",
        validated if probed else None,
        "environment(s) validated" if probed else "not run",
        indent=4,
    )
    say("  ---")
    say(
        f"  {len(with_id)} environment record(s) = {len(confirmed)} confirmed live · "
        f"{len(gone)} already deleted · {len(unvalidated)} unvalidated"
    )


    if unanswered:
        say(
            f"  of those, {len(unanswered)} were PROBED AND COULD NOT BE ANSWERED "
            "-- see the STATE column for why; the rest were never asked."
        )


    say("")
    say(f"  OPEN {len(open_)} -- confirmed live plus unvalidated; this is what --delete targets.")


    if incomplete_regions:
        say(
            f"  ** INCOMPLETE: CloudTrail failed in {incomplete_regions} region(s), so the "
            f"figures above are a FLOOR, not a count. Environments in those regions are "
            f"missing from every line of this summary."
        )


    if open_:
        say("")
        _print_findings(open_, emit=say)
    if log_path:
        say("")
        say(f"  detail (incl. the full CloudTrail record behind each OPEN row): {log_path}")


RUNNING_STATES = {"running"}
CONCURRENT_SHELL_QUOTA = 10


def summarise_regions(findings: list[Finding], *, probed: bool, emit: Any) -> None:
    """Per-region environment counts, and running shells against the real quota."""
    per_region: dict[str, list[Finding]] = defaultdict(list)
    for f in live_findings(findings, probed=probed):
        per_region[f.region].append(f)
    if not per_region:
        return

    if not probed:
        emit(
            "\nPer-region OPEN environment count (records; NOT quota-bounded -- "
            "re-run with --validate for running counts):"
        )
        for region in sorted(per_region):
            emit(f"  {region:<16} {len(per_region[region]):>3}")
        return


    emit(
        f"\nPer-region OPEN environments, and running shells vs the real quota "
        f"({CONCURRENT_SHELL_QUOTA} CONCURRENT shells per region per account)."
    )
    emit("Suspended/stopped environments do NOT consume that quota.")


    emit("STATES: `?` means UNVALIDATED -- either no credential in this run could ask")
    emit("that identity, or the probe ran and could not answer (the STATE column says")
    emit("which). Counted as open on CloudTrail's word alone either way.\n")
    hdr = f"  {'REGION':<16}{'ENVS':>5}{'RUNNING':>9}  STATES"
    emit(hdr)
    emit("  " + "-" * (len(hdr) - 2))
    for region in sorted(per_region):
        items = per_region[region]
        states: dict[str, int] = defaultdict(int)
        for f in items:
            states[(f.live_status or "?")] += 1
        running = sum(n for s, n in states.items() if s.split(":")[0].lower() in RUNNING_STATES)
        flag = "  <-- AT CONCURRENT-SHELL QUOTA" if running >= CONCURRENT_SHELL_QUOTA else ""
        breakdown = ", ".join(f"{k}={v}" for k, v in sorted(states.items()))
        emit(f"  {region:<16}{len(items):>5}{running:>9}  {breakdown}{flag}")
    total = sum(len(v) for v in per_region.values())
    emit(
        f"\n  {total} OPEN environment record(s) across {len(per_region)} region(s) -- the "
        f"same {total}\n  the SUMMARY counts as OPEN and lists by principal."
    )
    emit(
        "  Environment records are not quota-capped, but each holds up to 1 GB of "
        "persistent\n  storage per region and is only reclaimed by AWS after 120 days unused."
    )


def report_id_keys_seen(*, emit: Any) -> None:
    """Which payload key CloudTrail actually used for the environment id."""
    seen_keys = id_keys_seen()
    if not seen_keys:
        return
    seen = ", ".join(f"{k}={n}" for k, n in sorted(seen_keys.items()))
    emit(f"  environment id read from: {seen}")


def report_idless(findings: list[Finding], *, probed: bool = False, emit: Any) -> None:
    """Principals CloudTrail saw, whose events carry no environment id."""
    idless = [f for f in findings if not f.environment_id]
    if not idless:
        return
    emit(f"\nPRINCIPALS WITH ACTIVITY BUT NO ENVIRONMENT ID ({len(idless)}):")
    emit("  Normal for list-shaped calls (describeEnvironments carries no id).")


    if probed:
        emit(
            "  --validate ALREADY asked these identities directly; anything they still "
            "own\n  appears in the tables above. A principal listed here and nowhere "
            "else owns nothing\n  reachable, or could not be reconstructed (see NOT PROBED)."
        )
    else:
        emit("  Nothing here is actionable -- run --validate to ask these identities directly.")
    aligned(
        ("PRINCIPAL", "REGION"),
        [
            (f.principal_arn or "-", f.region)
            for f in sorted(idless, key=lambda x: (short_principal(x.principal_arn), x.region))
        ],
        emit=emit,
        indent="    ",
    )


def report_environment_records(rows: list[Finding], *, emit: Any) -> None:
    """The FULL CloudTrail record behind every environment that is still open."""
    if not rows:
        return
    emit("")
    emit(f"OPEN ENVIRONMENTS -- FULL CLOUDTRAIL RECORDS ({len(rows)}):")
    emit("  Every environment the summary counts as OPEN, with the raw events behind it.")
    emit(
        f"  Up to {_EVENTS_KEPT} records per environment (newest first), plus every "
        "create/delete event."
    )
    for f in sorted(rows, key=lambda x: (short_principal(x.principal_arn), x.region)):
        emit("")
        emit(f"  ENVIRONMENT {f.environment_id}  ({f.region})")
        emit(f"    principal   : {f.principal_arn}")
        emit(f"    state       : {_row_state(f)}")
        emit(f"    created     : {f.created_at or '- (no createEnvironment in the window)'}")
        emit(f"    last event  : {f.last_event or '-'}  {f.last_event_at or ''}".rstrip())
        emit(f"    found by    : {f.found_by}")
        if f.note:
            emit(f"    note        : {f.note}")
        if not f.events:


            emit(
                "    records     : none retained -- this environment was found by "
                "describeEnvironments,\n                  not by CloudTrail, so its events "
                "are outside the lookback window."
            )
            continue
        emit(f"    records     : {len(f.events)}")
        for ev in f.events:
            emit("")
            for line in json.dumps(ev, indent=2, sort_keys=True, default=str).split("\n"):
                emit("      " + line)


def enumerate_breakdown(
    principals: "list[Cred]",
    regions: "list[str]",
    findings: "list[Finding]",
    provenance: "Optional[dict[int, str]]" = None,
) -> "list[str]":
    """What each credential found, per TARGET IDENTITY per REGION"""
    from cloudbasher.core.utils.table_block import format_table_block, strip_table_marks

    provenance = provenance or {}
    counted: "dict[tuple[int, str, str], int]" = {}
    for f in findings:
        if f.found_by != "enumerate" or not f.environment_id:
            continue
        key = (f.cred_num or 0, f.principal_arn, f.region)
        counted[key] = counted.get(key, 0) + 1

    out: "list[str]" = []
    for num in sorted({c.num for c in principals}):
        mine = [c for c in principals if c.num == num]
        total = sum(n for (cred_num, _arn, _region), n in counted.items() if cred_num == num)


        out.append(
            f"  [cred#{num}]: {total} environment(s) from {len(mine)} principal(s) "
            f"x {len(regions)} region(s)"
            + (f" -- {provenance[num]}" if provenance.get(num) else "")
        )
        rows = [["# environments", "Target Identity", "Region"]]
        for c in mine:


            arn = c.principal_key
            for region in regions:
                rows.append([f"{counted.get((num, arn, region), 0)} environment(s)", arn, region])


        grid = strip_table_marks(format_table_block(rows, lead_blank=False))
        out.append("\n".join("  " + ln for ln in grid.splitlines()))
    return out


def _enumerate_all(
    principals: list[Cred], regions: list[str], findings: list[Finding], errors: list[str]
) -> None:
    """PASS `enumerate`, lifted out of main() so the pipeline reads as a pipeline."""
    prog = Progress(len(principals), "principals enumerated")
    for c in principals:
        try:
            got = enumerate_direct(c, regions, errors)
        except Exception as e:  # noqa: BLE001 - one credential must not kill the run
            got = []
            errors.append(f"{cred_label(c)}: {type(e).__name__}: {e}")
        findings.extend(got)
        prog.tick(f"{cred_label(c)} (+{len([f for f in got if f.environment_id])})")
    prog.done()
    for e in errors:
        print(f"  ! enumerate failed {e}", file=sys.stderr)


def _discover_all(
    sweepers: dict[str, Cred],
    regions: list[str],
    findings: list[Finding],
    errors: list[str],
    seen_direct: set,
    *,
    days: int,
    workers: int,
) -> None:
    """PASS `discover`, with this script's progress bar around the shared pass."""
    prog = Progress(len(sweepers) * len(regions), "account/regions swept")
    mine = discover_all(
        sweepers,
        regions,
        findings,
        errors,
        seen_direct,
        days=days,
        workers=workers,


        on_tick=lambda msg, _done, _total: prog.tick(msg),

        on_progress=lambda msg, _done, _total: prog.note(msg),
    )
    envs = len([f for f in mine if f.environment_id])
    prog.done(
        f"{envs} environment(s) + {len(mine) - envs} principal(s) with activity but no "
        f"environment id, {len(errors)} region error(s)"
    )
    for e in errors:
        print(f"  ! discover failed {e}", file=sys.stderr)


def main(argv: Optional[list[str]] = None) -> int:


    _claim_engine_sinks()
    ap = argparse.ArgumentParser(
        prog="cloudshell-sweep.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Find and remove AWS CloudShell environments account-wide.\n"
            "\n"
            "A PIPELINE: one or more SOURCES produce a list of environments, then an\n"
            "ACTION is applied to it.\n"
            "\n"
            "SOURCES\n"
            "  --enumerate   Ask the credentials you HOLD what they own\n"
            "                (describeEnvironments). State is CURRENT -- it hits the\n"
            "                API -- and there is no time window.\n"
            "  --discover    Read CloudTrail (LookupEvents) per ACCOUNT over --days.\n"
            "                Finds identities you may hold no credential for. State is\n"
            "                HISTORICAL: what the events said, not what is true now.\n"
            "  --validate    Applies to --discover only. Re-derives each discovered\n"
            "                identity and asks IT what it owns, upgrading those rows to\n"
            "                current state. --enumerate needs no validation; it is\n"
            "                already live.\n"
            "\n"
            "ACTIONS\n"
            "  (default)     report only\n"
            "  --delete      delete every environment the sources produced. --yes required.\n"
            "\n"
            "With no source, --enumerate and --discover both run.\n"
            "\n"
            "EXAMPLES\n"
            "  %(prog)s -F creds.rc --enumerate 6\n"
            "  %(prog)s -F creds.rc --discover ALL --validate\n"
            "  %(prog)s -F creds.rc --enumerate 6 --discover 6 --delete --yes\n"
            "  %(prog)s -F creds.rc --enumerate 4 --as foo --index 1-10\n"
        ),
    )


    ap.add_argument(
        "--enumerate",
        nargs="?",
        const="ALL",
        default=None,
        metavar="SELECTOR",
        help="SOURCE: ask credentials we hold. Optional selector: ALL (default), "
        "a number, or 1,3,5 -- which credentials to ask.",
    )
    ap.add_argument(
        "--discover",
        nargs="?",
        const="ALL",
        default=None,
        metavar="SELECTOR",
        help="SOURCE: read CloudTrail. Optional selector: ALL (default), a number, "
        "or 1,3,5 -- which credentials are ELIGIBLE to read. One per account is "
        "used and the run says which.",
    )


    ap.add_argument(
        "--as",
        dest="as_name",
        metavar="NAME",
        help="Enumerate as principal NAME instead of the name the -F block declares. "
        "--enumerate only.",
    )
    ap.add_argument(
        "--index",
        metavar="N-M",
        help="Enumerate as NAME-N .. NAME-M (inclusive), the series .provision creates. "
        "Uses the block's declared name unless --as is given. DEFAULTS TO THE BLOCK'S "
        "declared INDEX=; pass `none` to enumerate the un-suffixed name instead. "
        "--enumerate only.",
    )
    ap.add_argument(
        "--validate",
        action="store_true",
        help="Re-derive identities --discover found and ask them for current state.",
    )
    ap.add_argument(
        "--delete", action="store_true", help="ACTION: delete what the sources produced"
    )
    ap.add_argument(
        "--detail", action="store_true", help="Print the full per-pass tables to stdout too."
    )
    ap.add_argument(
        "--log",
        help="Detail log path. Default ./cloudshell-sweep.log, OVERWRITTEN each run -- "
        "pass --log to keep one.",
    )
    ap.add_argument("--no-log", action="store_true", help="Do not write a detail log.")
    ap.add_argument("-F", "--creds-file", help="CloudBasher-format credential file (AWS block)")
    ap.add_argument(
        "--region",
        help=f"ALL (case-insensitive), a glob like us-*, a comma list, or one region. "
        f"Default: all {len(_ALL_REGIONS)} CloudShell regions. Same grammar as the "
        f"product's `region` selector.",
    )
    ap.add_argument("--days", type=int, default=90, help="CloudTrail lookback, max 90 (default 90)")

    ap.add_argument(
        "--ignore-sweep-errors",
        action="store_true",
        help="Proceed even if the CloudTrail pass had region errors. Without this, "
        "`delete` ABORTS on any -- a partial identity picture is not a safe basis "
        "for deletion.",
    )


    ap.add_argument(
        "--cred",
        metavar="SELECTOR",
        help=argparse.SUPPRESS,
    )


    ap.add_argument(
        "--show-browser",
        action="store_true",
        help="Run any SSO portal login visibly instead of headless (debugging only).",
    )
    ap.add_argument("--yes", action="store_true", help="Required for `delete` to act")
    ap.add_argument("--workers", type=int, default=8, help="Parallel region sweeps (default 8)")


    raw = list(sys.argv[1:] if argv is None else argv)


    def _retired(token: str, message: str) -> None:
        if any(a == token or a.startswith(token + "=") for a in raw):
            raise SystemExit(message)

    for legacy, replacement in (
        ("discover", "--discover (CloudTrail) and/or --enumerate (credentials you hold)"),
        ("delete", "--delete, plus a source: --enumerate and/or --discover"),
    ):
        _retired(
            legacy,
            f"`{legacy}` is no longer a positional mode. Use {replacement}.\n"
            f"  See --help: SOURCES produce a list, an ACTION is applied to it.",
        )
    _retired("--probe", "`--probe` is now `--validate`, and it applies to --discover.")


    _retired(
        "--regions",
        "`--regions` is now `--region`, singular, to match `.enum` and `.provision`.\n"
        "  The grammar is unchanged: ALL, a glob like us-*, a comma list, or one region.",
    )


    _retired(
        "--allow-console-provisioning",
        "`--allow-console-provisioning` is gone, and you do not need it.\n"
        "  It opted in to console credentials back when reaching the control plane\n"
        "  through a console session was believed to CREATE an environment per region.\n"
        "  Discovery through the Console session is read-only; Console credentials\n"
        "  are accepted by default.",
    )

    args = ap.parse_args(argv)


    if args.validate and args.enumerate is not None and args.discover is None:
        raise SystemExit(
            "--validate applies to --discover only. --enumerate already returns "
            "current state -- it asks the API directly, so there is nothing to validate."
        )


    if args.region:
        try:
            regions = sorted(resolve_regions(args.region))
        except ValueError as exc:
            raise SystemExit(f"--region {args.region!r}: {exc}") from None
    else:
        regions = sorted(_ALL_REGIONS)


    if args.cred is not None:
        raise SystemExit(
            "--cred is gone. It set ONE selector for every role a credential "
            "can play -- who reads CloudTrail, who is asked directly, and (through "
            "the derivation pool) what could be deleted -- so narrowing it silently "
            "narrowed cleanup.\n"
            f"  reading CloudTrail:  --discover {args.cred}\n"
            f"  asking directly:     --enumerate {args.cred}\n"
            "  deleting:            unrestricted by design; a discovered ARN decides "
            "which credential applies."
        )

    neither = args.enumerate is None and args.discover is None
    do_enumerate = args.enumerate is not None or neither
    do_discover = args.discover is not None or neither
    enum_selector = args.enumerate or "ALL"
    discover_selector = args.discover or "ALL"
    probe = args.validate


    if (args.as_name is not None or args.index is not None) and not do_enumerate:
        raise SystemExit(
            "--as/--index name which principals to ENUMERATE as, and this run has no "
            "--enumerate pass. CloudTrail yields principal ARNs on its own, so "
            "--discover needs no names. Add --enumerate, or drop --as/--index."
        )


    from cloudbasher.csp.aws.commands import _index_spec_or_error


    _, index_failed = _index_spec_or_error(args.index)
    if index_failed:


        raise SystemExit(2)

    plan, total_steps, step_no = build_plan(do_enumerate, do_discover, probe, args.delete)

    log_path = None if args.no_log else open_detail_log(args.log or "./cloudshell-sweep.log")

    print_header(["venv/bin/python"] + sys.argv, plan)
    begin_step(step_no["Credentials"], total_steps, "Credentials")


    source_pool = ConsoleSourcePool()


    enum_nums: "set[int]" = set()
    named_nums: "set[int]" = set()
    if args.creds_file:


        _enum_phrase = _selector_phrase(args.enumerate, do_enumerate)
        _disc_phrase = _selector_phrase(args.discover, do_discover)
        say(
            f"Parsing {args.creds_file} -- enumerate={_enum_phrase}, "
            f"discover={_disc_phrase}, delete/validate=unrestricted"
        )
        say("")
        try:


            with contextlib.redirect_stdout(io.StringIO()):
                cred_set = select_creds(args.creds_file, "ALL")
        except OSError as exc:


            raise SystemExit(f"{args.creds_file}: {exc.strerror or exc}") from None
        except CredentialError as exc:


            raise SystemExit(str(exc)) from None


        enum_nums = (
            {c.num for c in narrow_to_selector(cred_set, args.creds_file, enum_selector)}
            if do_enumerate
            else set()
        )


        for _raw, _active in ((args.enumerate, do_enumerate), (args.discover, do_discover)):
            if _active and _raw and _raw != "ALL":
                named_nums |= {c.num for c in select_creds(args.creds_file, _raw)}
        for c in cred_set:
            if c.num in enum_nums:
                open_source(c, browser=browser_options(args), pool=source_pool)
            else:
                keys = keys_only_cred(c.num, c.record, label=c.label)
                if keys is None:


                    deny_keyless(c, enumerate_cmd="--enumerate <n>", discover_cmd="--discover")
                    continue
                c.keys, c.source = keys.keys, keys.source
            identify_cred(c)
    else:

        from cloudbasher.csp.aws.control_plane import _SigV4Source

        cred_set = [Cred(num=1, record=_EnvRecord(), label="AWS_* environment")]
        cred_set[0].source = _SigV4Source(load_creds())
        cred_set[0].keys = cred_set[0].source.credentials
        identify_cred(cred_set[0])


    atexit.register(close_detail_log)


    atexit.register(close_sources, cred_set)


    if do_discover:
        may_read = narrow_to_selector(cred_set, args.creds_file, discover_selector)
        ensure_account_readers(
            may_read,
            pool=source_pool,
            browser=browser_options(args),


            on_attempt=lambda c, account: say(f"  {sso_last_resort_note(c, account)}"),
            on_outcome=lambda c, ok: (
                say(f"  {sso_resolved_note(c)}")
                if ok
                else say(f"  ! {sso_unresolved_note(c)}", stream=sys.stderr)
            ),
        )


    signers = [c for c in cred_set if c.can_read_cloudtrail]
    enumerators = [c for c in cred_set if c.can_enumerate]


    principals: list[Cred] = []
    derivers = [c for c in cred_set if c.can_sign_sts]


    for_enum = (
        narrow_to_selector(enumerators, args.creds_file, enum_selector) if do_enumerate else []
    )
    enum_nums = {c.num for c in for_enum}


    broken_nums = {c.num for c in cred_set if c.failed(ENUMERATE)}


    discoverable = narrow_to_selector(cred_set, args.creds_file, discover_selector)
    eligible = [c for c in discoverable if c.can_read_cloudtrail]
    reader_nums = {c.num for c in pick_sweepers(eligible).values()}


    say(
        f"  {len(cred_set)} credential(s) parsed"
        + (f" -- {len(broken_nums)} invalid ({USE_INVALID})" if broken_nums else "")
    )
    say(
        credentials_table(
            cred_set,
            named_nums=named_nums,
            enum_nums=enum_nums,
            reader_nums=reader_nums,
            broken_nums=broken_nums,
            cli_name=args.as_name or "",
            cli_index=args.index or "",
            cli_region=args.region or "",
        )
    )


    if broken_nums:


        say("")
    for c in cred_set:
        if c.num in broken_nums:
            say(f"  {cred_label(c)}: {c.why_not(ENUMERATE)}", stream=sys.stderr)


    resolution = resolve_principals(cred_set)
    report = resolution.report()
    if report:
        say("")
        say(f"  {resolution_heading()}")
        for line in report:
            say(line)


    if not (enumerators or signers):
        log_only("No usable credential. Nothing can be swept.")
        raise SystemExit("No usable credential. Nothing can be swept.")


    if probe and not any(c.long_term for c in signers):
        print(
            "NOTE: every credential holding keys is temporary (ASIA). sts:GetFederationToken "
            "requires a long-term key, so `federated-user/*` identities cannot be "
            "reconstructed -- they will be reported and skipped. `assumed-role/*` "
            "identities are unaffected (role chaining works from ASIA).",
            file=sys.stderr,
        )


    def emit(line: str = "") -> None:
        """Detail. Always to the log; to the screen only on --detail."""
        if args.detail:
            print(line)
        log_only(line)

    findings: list[Finding] = []
    errors: list[str] = []


    begin_step(
        step_no.get("Enumerate"),
        total_steps,
        "Enumerate",
        doc=_DOC_ENUMERATE,
        ran=do_enumerate,
    )
    if do_enumerate:


        for c in for_enum:
            principals.extend(
                named_identity_creds(
                    c, requested_name=args.as_name, index_arg=args.index, errors=errors
                )
            )


        say(
            f"Enumerate: {len(for_enum)} credential(s) -> {len(principals)} principal(s) "
            f"x {len(regions)} region(s)"
        )
        _enumerate_all(principals, regions, findings, errors)


        provenance = {
            c.num: name_and_index_provenance(c, args.as_name, args.index) for c in for_enum
        }
        for line in enumerate_breakdown(principals, regions, findings, provenance):
            say(line)
        pass_findings(_rows_for(findings, "enumerate"), emit=emit)
    seen_direct = {(f.region, f.environment_id) for f in findings if f.environment_id}


    readers: "list[tuple[str, int, str]]" = []

    def _say_reader(account: str, chosen: Cred, others: list) -> None:
        """Name the reader for every account, always -- owner"""
        extra = (
            f"  (also eligible: {', '.join(f'[{o.num}]' for o in others)}, unused)"
            if others
            else ""
        )
        readers.append((account, chosen.num, extra))

    sweepers = pick_sweepers(eligible, on_choice=_say_reader)


    console_only = [c for c in discoverable if not c.can_read_cloudtrail]
    skipped_accounts = len(eligible) - len(sweepers)

    if console_only:
        print(
            f"  note: {len(console_only)} console credential(s) enumerated and can delete, "
            "but this script's CloudTrail pass is boto3-on-keys and has no console route "
            "yet, so they add nothing to the unmanaged inventory. (presign WILL sign "
            "cloudtrail -- measured 2026-09-13, #488; the gap is our plumbing.)",
            file=sys.stderr,
        )
    errors = []
    read_as = (
        tuple(
            f"  READ AS: {short_principal(c.own_arn) or '?'}  (account {acct})"
            for acct, c in sorted(sweepers.items())
        )
        if sweepers
        else ("  READ AS: (nobody here can read CloudTrail)",)
    )
    begin_step(
        step_no.get("Discover"),
        total_steps,
        "Discover",
        tagline="What CloudTrail says happened, including identities we may not hold",
        doc=_DOC_DISCOVER,
        ran=do_discover,
        extra=read_as if do_discover else (),
    )


    for account, num, extra in readers:
        say(
            f"  account {account}: "
            f"{'reading' if do_discover else 'would read'} CloudTrail as [cred#{num}]{extra}"
        )
    if not do_discover:
        sweepers = {}
    else:
        say(
            f"Discover (CloudTrail): {len(regions)} region(s) x "
            f"{len(sweepers)} account(s), last {args.days} day(s)"
            + (
                f" ({skipped_accounts} credential(s) share an already-swept account)"
                if skipped_accounts
                else ""
            )
        )
        _discover_all(
            sweepers,
            regions,
            findings,
            errors,
            seen_direct,
            days=args.days,
            workers=args.workers,
        )
        pass_findings(_rows_for(findings, "discover"), emit=emit)
        report_id_keys_seen(emit=emit)


    if errors:
        if args.delete and not args.ignore_sweep_errors:
            log_only(f"ABORTED: CloudTrail failed in {len(errors)} region(s).")
            raise SystemExit(
                f"\nABORTED before deleting anything: the CloudTrail pass failed in "
                f"{len(errors)} region(s), so the identity inventory is INCOMPLETE and a "
                f"deletion plan built on it could miss environments or name the wrong "
                f"owner.\n  Fix the access (cloudtrail:LookupEvents) and re-run, or pass "
                f"--ignore-sweep-errors to proceed on a partial picture."
            )
        print(
            f"  WARNING: inventory INCOMPLETE -- CloudTrail failed in {len(errors)} region(s).",
            file=sys.stderr,
        )


    groups = match_identities(
        findings,
        derivers,
        {c.acts_as_arn for c in derivers if c.acts_as_arn},
        index=resolution,
    )


    report_derivation_gap(groups, resolution)

    worklist: list[tuple[str, str, Identity]] = []
    if probe:
        begin_step(step_no["Validate"], total_steps, "Validate", doc=_DOC_VALIDATE)
        for (region, arn), ident in sorted(groups.items()):
            if not ident.reconstructable:
                for f in ident.findings:
                    f.note = f.note or f"not reconstructable: {ident.reason}"
                continue
            if not ident.actionable:


                for f in ident.findings:
                    f.note = f.note or ident.reason
                continue


            if ident.kind == "federation_token" and not ident.deriver.cred.long_term:
                for f in ident.findings:
                    f.note = f.note or "needs a long-term AKIA key (GetFederationToken)"
                continue
            worklist.append((region, arn, ident))

        say(
            f"Probing {len(worklist)} of {len(groups)} identity/region pair(s) "
            f"(1 STS derive + describeEnvironments + 1 status call per environment)"
        )
        prog = Progress(len(worklist), "identities probed")


        probe_errors = probe_all(
            worklist, findings, seen_direct, workers=args.workers, on_tick=prog.tick
        )
        prog.done(f"{probe_errors} probe error(s)")


    if probe:
        report_validate(groups, worklist, emit=emit)
        pass_findings(
            [f for f in findings if f.found_by == "discover" and f.live_status], emit=emit
        )
    report_idless(findings, probed=probe, emit=emit)
    summarise_regions(findings, probed=probe, emit=emit)
    report_environment_records(live_findings(findings, probed=probe), emit=emit)

    validated_n = len([f for f in _rows_for(findings, "discover") if f.live_status])
    rule()
    report_summary(
        findings,
        enumerated=do_enumerate,
        discovered=do_discover,
        validated=validated_n,
        probed=probe,
        log_path=log_path,
        incomplete_regions=len(errors) if do_discover else 0,
    )

    if not args.delete:


        close_sources(cred_set, why="end of run")
        return 0

    targets: list[Target] = []


    by_principal = delete_router(principals)


    targets, duplicate_targets = build_delete_targets(findings, groups, by_principal)

    if not targets:
        print("\nNothing to delete.")
        return 0

    direct_n = len([t for t in targets if t.cred is not None])
    print(
        f"\nWould delete {len(targets)} environment(s) "
        f"({direct_n} enumerated directly, {len(targets) - direct_n} via CloudTrail"
        + (f", {duplicate_targets} duplicate(s) suppressed" if duplicate_targets else "")
        + "):"
    )
    for t in targets:
        print(f"  {t.region}  {t.env_id}  as {t.acting_as}")
    skipped = [
        i
        for i in groups.values()
        if not i.reconstructable
        and any(f.environment_id and not f.deleted_seen for f in i.findings)
    ]
    if skipped:
        print(f"\nSKIPPING {len(skipped)} identity/ies this key cannot reconstruct:")
        for i in skipped:
            print(f"  {i.arn}: {i.reason}")

    if not args.yes:
        print("\nRe-run with --yes to actually delete. (Irreversible.)")
        return 0

    begin_step(step_no["Delete"], total_steps, "Delete")
    say(f"Deleting {len(targets)} environment(s)")


    prog = Progress(len(targets), "deleted")


    _TICK_SUFFIX = {"deleted": "", "already-gone": " dup", "failed": " FAILED"}

    def _report(t: Target, outcome: str, why: str) -> None:
        """This script's SINKS for one delete"""
        lines, to_stderr = delete_receipt(t, outcome, why)
        for line in lines:
            print(mask_secrets(line), file=sys.stderr if to_stderr else sys.stdout)
        prog.tick(t.region + _TICK_SUFFIX.get(outcome, " FAILED"))

    _deleted, failed = delete_all(targets, on_result=_report)
    prog.done(f"{failed} failure(s)")
    print(f"\nDeleted {len(targets) - failed}/{len(targets)}.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
