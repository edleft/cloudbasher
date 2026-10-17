"""The UNMANAGED result set, and the two things you can do to it"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from cloudbasher.core.utils.timestamps import iso_to_epoch


UNREGISTERED = "unregistered"


PROVENANCE_SLOTS = "UEDV"


@dataclass
class UnmanagedStore:
    """One result set from `.discover` or `.enum`, plus what has happened to it."""

    findings: "list[Any]" = field(default_factory=list)


    regions: "list[str]" = field(default_factory=list)
    days: int = 0
    accounts: int = 0
    errors: "list[str]" = field(default_factory=list)
    completed_at: Optional[float] = None


    deleted_env_ids: "set[str]" = field(default_factory=set)


    _provenance: "dict[tuple[str, str], set[str]]" = field(default_factory=dict)


    @staticmethod
    def _flags_for(f: Any) -> "set[str]":
        """Which passes this ONE finding represents."""
        found = getattr(f, "found_by", "")
        if found == UNREGISTERED:


            return {"U"}
        if found == "enumerate":
            return {"E"}
        return {"D", "V"} if getattr(f, "live_status", None) else {"D"}

    def _note(self, findings: "list[Any]") -> None:
        for f in findings:
            if f.environment_id:
                key = (f.region, f.environment_id)
                self._provenance.setdefault(key, set()).update(self._flags_for(f))

    def provenance_of(self, f: Any) -> str:
        """`UEDV`: `-EDV` / `-ED-` / `--DV` / `-E--` / `U---` -- fixed slots."""
        got = self._provenance.get((f.region, f.environment_id or ""), set())
        return "".join(c if c in got else "-" for c in PROVENANCE_SLOTS)

    def replace(
        self,
        findings: "list[Any]",
        *,
        regions: "list[str]",
        days: int,
        accounts: int,
        errors: "list[str]",
        now: Optional[float] = None,
    ) -> None:
        """A `.discover` pass replaces what it LOOKED AT"""
        fresh = list(findings)
        fresh_keys = {(f.region, f.environment_id) for f in fresh if f.environment_id}
        scanned = set(regions)
        cutoff = (now if now is not None else time.time()) - days * 86400
        kept = [
            f
            for f in self.findings
            if (f.region, f.environment_id) not in fresh_keys
            and not _within_scan(f, scanned, cutoff)
        ]
        self.findings = kept + fresh
        self.regions = list(regions)
        self.days = days
        self.accounts = accounts
        self.errors = list(errors)
        self.deleted_env_ids = set()


        live = {(f.region, f.environment_id or "") for f in self.findings}
        refreshed = {(f.region, f.environment_id or "") for f in fresh}
        self._provenance = {
            k: v for k, v in self._provenance.items() if k in live and k not in refreshed
        }
        self._note(fresh)
        self.completed_at = now if now is not None else time.time()

    def merge(self, findings: "list[Any]") -> None:
        """An `.enum` pass MERGES"""
        covered = {(f.region, f.environment_id) for f in findings if f.environment_id}
        kept = [
            f
            for f in self.findings
            if not (f.environment_id and (f.region, f.environment_id) in covered)
        ]
        self.findings = kept + list(findings)


        self._note(findings)
        self.completed_at = time.time()

    def mark_deleted(self, env_ids: "set[str]") -> None:
        self.deleted_env_ids |= set(env_ids)

    def drop(self, env_ids: "set[str]") -> None:
        """Remove rows outright -- what REGISTER does."""
        gone = set(env_ids)
        self.findings = [f for f in self.findings if f.environment_id not in gone]
        self._provenance = {k: v for k, v in self._provenance.items() if k[1] not in gone}


    _PERSISTED_FIELDS = (
        "region",
        "principal_arn",
        "environment_id",
        "created_at",
        "last_event",
        "last_event_at",
        "deleted_seen",
        "live_status",


        "probe_failure_class",
        "note",
        "found_by",
        "cred_num",
        "observed_at",
    )

    def to_dict(self) -> "dict[str, Any]":
        """The set, as JSON `save_registry` can hold"""
        return {
            "findings": [{k: getattr(f, k) for k in self._PERSISTED_FIELDS} for f in self.findings],
            "regions": list(self.regions),
            "days": self.days,
            "accounts": self.accounts,
            "errors": list(self.errors),
            "completed_at": self.completed_at,
            "provenance": {f"{r}|{e}": sorted(v) for (r, e), v in self._provenance.items()},
        }

    @classmethod
    def from_dict(cls, data: "dict[str, Any]") -> "UnmanagedStore":
        """Inverse of `to_dict`, and TOLERANT BY CONSTRUCTION."""
        from cloudbasher.csp.aws.discovery import Finding

        store = cls()
        for raw in data.get("findings") or []:
            if not isinstance(raw, dict):
                continue
            try:
                store.findings.append(
                    Finding(**{k: raw.get(k) for k in cls._PERSISTED_FIELDS if k in raw})
                )
            except TypeError:


                continue
        store.regions = list(data.get("regions") or [])
        store.days = int(data.get("days") or 0)
        store.accounts = int(data.get("accounts") or 0)
        store.errors = list(data.get("errors") or [])
        store.completed_at = data.get("completed_at")
        for key, flags in (data.get("provenance") or {}).items():
            region, _, env = str(key).partition("|")
            store._provenance[(region, env)] = set(flags or ())
        return store


    @property
    def never_run(self) -> bool:
        return self.completed_at is None

    def rows(self) -> "list[Any]":
        """The result set in display order -- and THE numbering."""
        return sorted(
            self.findings, key=lambda f: (f.region, f.environment_id or "", f.principal_arn)
        )

    def scope_sentence(self) -> str:
        """What was looked at, for the line beside an empty result."""
        if self.never_run:
            return "no scan has run"
        return f"{len(self.regions)} region(s), {self.days} day(s), {self.accounts} account(s)"


def _row_timestamp(f: Any) -> Optional[float]:
    """When this row was last known to be real, as epoch seconds"""
    for raw in (
        getattr(f, "last_event_at", None),
        getattr(f, "observed_at", None),
        getattr(f, "created_at", None),
    ):


        got = iso_to_epoch(raw)
        if got is not None:
            return got
    return None


def _within_scan(f: Any, scanned_regions: "set[str]", cutoff: float) -> bool:
    """Could the scan just run have returned this row?"""
    if f.region not in scanned_regions:
        return False
    when = _row_timestamp(f)
    if when is None:
        return False
    return when >= cutoff


def resolve_unmanaged_selector(
    rows: "list[Any]", token: str, selected_env_ids: "set[str]"
) -> "tuple[list[Any], list[str]]":
    """`(picked, unknown)` for `<envID>|<#>|selected|ALL|1,3,5`."""
    token = (token or "").strip()
    if not token:
        return [], []
    low = token.lower()
    if low == "all":
        return list(rows), []
    if low == "selected":
        picked = [f for f in rows if f.environment_id in selected_env_ids]


        return picked, []
    if "," in token:
        picked, unknown = [], []
        seen: "set[int]" = set()
        for part in token.split(","):
            got, miss = resolve_unmanaged_selector(rows, part, selected_env_ids)
            unknown.extend(miss)
            for f in got:
                if id(f) not in seen:
                    seen.add(id(f))
                    picked.append(f)
        return picked, unknown
    by_env = [f for f in rows if f.environment_id == token]
    if by_env:
        return by_env, []
    if token.isdigit():
        n = int(token)
        if 1 <= n <= len(rows):
            return [rows[n - 1]], []
    return [], [token]


def display_rows(store: UnmanagedStore, *, redacted: bool = False) -> "list[Any]":
    """`UnmanagedViewRow`s for the Nodes pane's third view"""
    from cloudbasher.core.cli.dispatcher import _AWS_STATUS_MAP
    from cloudbasher.core.identity_listing import is_verbose_identity
    from cloudbasher.core.tui.widgets.node_table import UnmanagedViewRow
    from cloudbasher.csp.aws.discovery import principal_cell, unvalidated_reason

    verbose = is_verbose_identity()
    rows = []
    for i, f in enumerate(store.rows(), start=1):
        env = f.environment_id or "(no id)"


        state = (
            _AWS_STATUS_MAP.get(f.live_status, f.live_status)
            if f.live_status
            else ("deleted" if f.deleted_seen else (unvalidated_reason(f) or "-"))
        )
        note = f.note or ""
        if not f.environment_id and not note:


            note = "activity seen, no environment id -- reportable, not actionable"
        rows.append(
            UnmanagedViewRow(
                key=f.environment_id or f"{f.region}|{f.principal_arn}",
                index=i,
                provenance=store.provenance_of(f),
                principal=principal_cell(f.principal_arn, verbose=verbose),
                region=f.region,
                environment=env,
                state=state,
                note=note or "-",
                deleted=bool(f.environment_id and f.environment_id in store.deleted_env_ids),
            )
        )
    return rows


def scope_age(store: UnmanagedStore, *, now: Optional[float] = None) -> str:
    """`"14m ago"` for the tab title, or `""` when no scan has run."""
    if store.completed_at is None:
        return ""
    secs = max(0, int((now if now is not None else time.time()) - store.completed_at))
    if secs < 60:
        return "just now" if secs < 10 else f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"
