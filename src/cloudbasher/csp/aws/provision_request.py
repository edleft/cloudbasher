"""Every per-command fact `.provision` needs, resolved ONCE, before any branch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, NamedTuple, Optional

from cloudbasher.core.utils.table_block import format_table_block
from cloudbasher.csp.aws.act_as import DERIVING_MODES, can_derive


from cloudbasher.csp.aws.credentials import EXPLICIT


TYPED = "typed"
DECLARED = "declared"


TYPED_NONE = "typed-none"


UNUSABLE = "unusable"


TYPED_UNUSABLE = "typed-unusable"


NO_INDEX = "none"


@dataclass(frozen=True)
class ProvisionRequest:
    """One `.provision` invocation, fully resolved."""


    records: tuple[tuple[int, Any], ...]


    selector: Optional[str] = None

    region: Optional[str] = None


    region_source: str = NO_INDEX
    index: Optional[str] = None
    index_source: str = NO_INDEX
    name: Optional[str] = None
    duration: Optional[int] = None


    explicit_role_arn: Optional[str] = None


    keyword: str = ""


    gate: Optional[str] = None


    plan_shown: bool = False


    announcements: tuple[str, ...] = ()

    @property
    def is_bulk(self) -> bool:
        return len(self.records) > 1

    @property
    def mode(self) -> str:
        """The declared `ACT_AS` mode of the FIRST record."""
        return act_as_mode(self.records[0][1]) if self.records else ""

    def modes(self) -> set[str]:
        return {act_as_mode(rec) for _n, rec in self.records}

    @property
    def derives(self) -> bool:
        """Does every record actually derive a target identity?"""
        return bool(self.records) and self.modes() <= set(DERIVING_MODES)


def _declared(rec: Any, key: str) -> str:
    """Read one declared value off a record, "" when absent."""
    return str(rec.raw.extra.get(key) or "")


def act_as_mode(rec: Any) -> str:
    """The declared `ACT_AS` mode of one record: "" | "role" | "federated" | ..."""
    from cloudbasher.csp.aws.act_as import act_as_mode_of

    return act_as_mode_of(rec.raw.extra)


@dataclass(frozen=True)
class Defaults:
    """What one credential declares, plus whether its `INDEX=` can be used."""

    region: Optional[str]
    region_source: str
    index: Optional[str]
    index_source: str
    announcements: tuple[str, ...]
    index_unusable: bool


def resolve_defaults(
    records: tuple[tuple[int, Any], ...],
    *,
    region: Optional[str],
    index: Optional[str],
    selector: Optional[str],
) -> Defaults:
    """Fill `region`/`index` from what the credential DECLARES, if not typed."""
    notes: list[str] = []


    if len(records) != 1:
        return Defaults(
            region,
            TYPED if region is not None else NO_INDEX,
            index,
            TYPED if index is not None else NO_INDEX,
            (),
            False,
        )
    _num, rec = records[0]
    region_source = TYPED if region is not None else NO_INDEX
    index_source = TYPED if index is not None else NO_INDEX
    index_unusable = False

    declared_region = _declared(rec, "provision_region")
    if region is None and declared_region:
        region = declared_region
        region_source = DECLARED
        notes.append(f"provision: using REGION={region} declared by credential [{selector}]")


    if is_index_none(index):


        return Defaults(region, region_source, None, TYPED_NONE, tuple(notes), False)

    declared_index = _declared(rec, "provision_index")


    derives = can_derive(rec.raw.extra)
    if index is None and declared_index:
        if derives:
            index = declared_index
            index_source = DECLARED
            notes.append(f"provision: using INDEX={index} declared by credential [{selector}]")
        else:


            index_unusable = True
    elif index and not derives:


        index_unusable = True

    return Defaults(region, region_source, index, index_source, tuple(notes), index_unusable)


INDEX_NONE = "none"


def is_index_none(requested: "Optional[str]") -> bool:
    """Did the caller ask for NO index? `#532`."""
    return (requested or "").strip().lower() == INDEX_NONE


class IndexChoice(NamedTuple):
    """What `effective_index` decided, and everything a caller must say about it."""


    spec: "Optional[tuple[int, int]]"


    source: str

    refusal: str


    notes: "tuple[str, ...]" = ()

    @property
    def typed_positions(self) -> bool:
        """The user TYPED an index naming POSITIONS. `#563`."""
        return self.source in (TYPED, TYPED_UNUSABLE)

    @property
    def nothing_asked(self) -> bool:
        """NOTHING was said about an index -- not typed, not declared. `#563`."""
        return self.source == NO_INDEX


def source_word(source: str) -> str:
    """The word a READER should see for where an index came from. `#563`."""
    if source in (TYPED, TYPED_NONE, TYPED_UNUSABLE, "invalid", EXPLICIT):
        return "typed"
    if source in (DECLARED, UNUSABLE):
        return "declared"
    if source == NO_INDEX:
        return "none"
    return source


def asks_derivation(choice: IndexChoice, requested_name: "Optional[str]") -> bool:
    """The user ASKED to derive: a name, or an index naming positions. `#563`."""
    return requested_name is not None or choice.typed_positions


def effective_index(rec: Any, requested: "Optional[str]", *, selector: str) -> IndexChoice:
    """`(spec, source, refusal)` -- the index THIS RUN will use. `#532`, `#542`."""


    from cloudbasher.csp.aws.commands import _index_spec_or_error

    raw = (requested or "").strip()
    defaults = resolve_defaults(((0, rec),), region=None, index=raw or None, selector=selector)
    if defaults.index_unusable:


        if raw:
            return IndexChoice(None, TYPED_UNUSABLE, "")
        return IndexChoice(
            None,
            UNUSABLE,
            f"INDEX={_declared(rec, 'provision_index')} is declared but this credential "
            "derives nothing, so there is no name to suffix -- it enumerates as itself",
        )
    if not defaults.index:


        return IndexChoice(
            None, TYPED_NONE if defaults.index_source == TYPED_NONE else NO_INDEX, ""
        )
    spec, failed = _index_spec_or_error(defaults.index)
    if failed:
        return IndexChoice(None, "invalid", f"INDEX={defaults.index} is not a position")
    return IndexChoice(
        spec,
        TYPED if defaults.index_source == TYPED else DECLARED,
        "",
        defaults.announcements,
    )


PROVISION_REGION_CAP = 10


PLAN_ROWS_SHOWN = 10


class PlannedTarget(NamedTuple):
    """ONE environment a `.provision` is about to create, and where each value in it came from. `#612` Q4, owner-asked 2026-09-18."""

    identity: str
    region: str
    name_source: str = TYPED
    index_source: str = TYPED
    region_source: str = TYPED


_FROM_WORDS = {
    TYPED: "cmd",
    TYPED_NONE: "cmd",
    TYPED_UNUSABLE: "cmd",
    EXPLICIT: "cmd",
    "invalid": "cmd",
    DECLARED: "file",
    UNUSABLE: "file",
    NO_INDEX: "unset",
}


def _from_word(source: str) -> str:
    """`cmd`, `file` or `unset` -- where a value came from, in the user's terms."""
    return _FROM_WORDS.get(source, "?")


def plan_targets(
    names: "list[str]",
    regions: "list[str]",
    *,
    name_source: str,
    index_source: str,
    region_source: str,
) -> "list[PlannedTarget]":
    """The (names x regions) cross product, in ONE order, with provenance."""
    return [
        PlannedTarget(
            identity=name,
            region=region,
            name_source=name_source,
            index_source=index_source,
            region_source=region_source,
        )
        for region in regions
        for name in names
    ]


def render_plan(targets: "list[PlannedTarget]", *, limit: int = PLAN_ROWS_SHOWN) -> "list[str]":
    """The lines a `.provision` preflight prints. ONE renderer, for every path."""
    if not targets:
        return []


    rows = [["identity", "region", "from"]]
    for t in targets[:limit]:
        rows.append(
            [
                t.identity,
                t.region,
                f"name {_from_word(t.name_source)}"
                f" · index {_from_word(t.index_source)}"
                f" · region {_from_word(t.region_source)}",
            ]
        )
    hidden = len(targets) - limit


    lines = [format_table_block(rows)]
    if hidden > 0:


        lines.append(f"  ... and {hidden} more (showing the first {limit} of {len(targets)})")
    lines.append(
        "  from: `cmd` = this command line, `file` = the credential block, "
        "`unset` = neither said so. ACT_AS is always the file's."
    )
    return lines


def validate_name(
    as_args: Optional[list[str]],
    *,
    where: str = "provision",
    rows: int = 1,
) -> tuple[Optional[str], Optional[str]]:
    """`as <name>` -> (name, error). THE ONE PLACE `as` IS JUDGED. `#650`."""
    if as_args is None:
        return None, None
    if len(as_args) != 1:
        return None, f"{where}: `as` takes exactly one name"
    name = as_args[0]
    if not name.strip():
        return None, (
            f"{where}: `as` takes a NAME and this one is empty. It used to be "
            "accepted and silently ignored, which is indistinguishable from "
            "not typing `as` at all -- and the name decides which CloudShell "
            "environments exist. Drop the term to use the block's declared "
            "FEDERATION_NAME/ROLE_SESSION_NAME, or give a name."
        )
    if rows > 1:
        return None, (
            f"{where}: `as` would give {rows} credentials ONE shared identity "
            "name, and the name decides which CloudShell environments exist -- "
            "two rows deriving the same principal makes their environments "
            "indistinguishable. Declare it per credential in the -F file "
            "(FEDERATION_NAME=, ROLE_SESSION_NAME=), or name one credential at "
            "a time.\n"
            "  (An `index` is fine here: it SUFFIXES each row's own name, so a "
            "selection stays distinct.)"
        )
    return name, None


def validate_duration(
    duration_args: Optional[list[str]], *, derives_federation: bool
) -> tuple[Optional[int], Optional[str]]:
    """`duration <seconds>` -> (seconds, error)."""
    if duration_args is None:
        return None, None
    if not derives_federation:
        return None, "provision: duration only applies to federation"
    if len(duration_args) != 1:
        return None, "provision: duration takes exactly one value, in seconds"
    try:
        seconds = int(duration_args[0])
    except ValueError:
        return None, f"provision: invalid duration {duration_args[0]!r} (expected seconds)"
    if seconds < 1:
        return None, f"provision: invalid duration {duration_args[0]!r} (must be positive)"
    return seconds, None


def active_target_identity_for(state: Any, parent_rec: Any) -> Optional[Any]:
    """The target CredentialRecord already derived from parent_rec for the active node, if any -- whatever ``.provision role`` or ``.provision federation`` most recently derived onto it."""
    node = state.nodes_by_id.get(state.active_node_id) if state.active_node_id else None
    if node is None:
        return None
    cred = state.credentials_by_id.get(node.credential_id)
    if cred is not None and cred.role == "target" and cred.parent_id == parent_rec.id:
        return cred
    return None


def derived_targets(state: Any, rec: Any) -> list[Any]:
    """Every target derived from ``rec``, in registry order."""
    return [
        cred
        for cred in state.credentials_by_id.values()
        if cred.role == "target" and cred.parent_id == rec.id
    ]


def all_derived_targets(state: Any, rec: Any) -> list[Any]:
    """EVERY target derived from ``rec``, the active node's first (#106)."""
    derived = derived_targets(state, rec)


    active = active_target_identity_for(state, rec)
    if active is not None:
        derived.remove(active)
        derived.insert(0, active)
    return derived


def node_is_live(node: Any) -> bool:
    """Is this node up? THE liveness test -- see `provisioned_regions` below for the three-way disagreement that made "one predicate" a rule here."""
    return getattr(node, "_runtime_session", None) is not None or node.container_status == "Running"


def provisioned_regions(state: Any, credential_ids: set[str] | frozenset[str]) -> set[str]:
    """Regions where these credential ids ALREADY have a live node."""
    return {
        node.region
        for node in state.nodes_by_id.values()
        if node.credential_id in credential_ids and node_is_live(node)
    }


def dedup_credential_ids(state: Any, rec: Any) -> set[str]:
    """Every credential id whose nodes count as "this one is already done"."""


    return {rec.id} | {t.id for t in derived_targets(state, rec)}
