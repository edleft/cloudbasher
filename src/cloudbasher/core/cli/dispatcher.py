"""Interactive command dispatcher."""

from __future__ import annotations

import enum
import fnmatch
import os
import re
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Literal, Optional, Sequence

from ...csp.base import (
    CSPProvider,
    SupportsEnvironmentDeletion,
    SupportsEnvironmentLifecycle,
    SupportsEnvironmentSuspension,
    SupportsNodeReconnect,
)
from ..credential_validation import known_invalid_credential_error
from ..exceptions import CloudShellAutomationError
from ..interactive.repl_shared import (
    CONFIRM_NO,
    CONFIRM_YES,
    pending_confirm_pair,
    quit_command_help,
)
from ..session.activity import activity_from, activity_of
from ..session.exit_code_spike import CaptureUntrusted, exec_with_exit_code
from ..session.failure import is_environment_wide, label_for
from ..session.shell import ShellModeHandler
from ..types import (
    CONTAINER_TRANSITIONS,
    InteractiveState,
    NodeRecord,
    node_socket_is_dead,
)
from ..utils.output import detail, eprint, log, mask_secrets, out
from ..utils.perf_config import (
    get_env_start_expected_seconds,
    get_env_stop_expected_seconds,
    pool_width,
    status_poll_wait,
)
from ..utils.timeline import mark as timeline_mark
from ..utils.timeline import record_span
from .command_spec import CommandSpec, ParseResult, parse, terse_usage, usage
from .command_specs import CORE_SPECS


def notify_node_change(state: Any, node: NodeRecord) -> None:
    """Publish a node-row state transition through the app's shared refresh hook."""
    callback = getattr(state, "on_node_change", None)
    if callback is not None:
        callback(node)


def reject_invalid_node_credentials(
    state: InteractiveState, node_ids: Iterable[str], action: str
) -> bool:
    """Atomically refuse a cloud lifecycle action if any target auth is known invalid."""
    nodes = getattr(state, "nodes_by_id", {}) or {}
    credentials = getattr(state, "credentials_by_id", {}) or {}
    rejected: list[str] = []
    for node_id in node_ids:
        node = nodes.get(node_id)
        if node is None:
            continue
        credential = credentials.get(node.credential_id)
        message = known_invalid_credential_error(
            credential, action, label=f"credential for node {node.id}"
        )
        if message:
            rejected.append(message)
    if rejected:
        for message in rejected:
            eprint(message)
        return True
    return False


def begin_node_activity(
    state: Any,
    node: NodeRecord,
    *,
    connecting: bool = False,
    working: bool = True,
    clear_queued: bool = False,
    publish: bool = True,
) -> None:
    """Begin the shared row-activity transition used by direct and fan-out work."""
    if connecting:
        node.begin_connect()
    if working:
        node.mark_working()
    if clear_queued:
        node.clear_queued()
    if publish:
        notify_node_change(state, node)


def end_node_activity(
    state: Any,
    node: NodeRecord,
    *,
    connecting: bool = False,
    working: bool = True,
    publish: bool = True,
) -> None:
    """Clear the shared row-activity transition, including failure paths."""
    if connecting:
        node.end_connect()
    if working:
        node.clear_working()
    if publish:
        notify_node_change(state, node)


_AWS_STATUS_MAP = {
    "RUNNING": "Running",
    "SUSPENDED": "Suspended",


    "SUSPENDING": "Suspending",
    "STOPPED": "Suspended",
    "ERROR": "Failed",
    "DELETED": "Failed",
}


_HOLDING_STATUS_FOR_TARGET = {
    t.heading: name
    for name, t in CONTAINER_TRANSITIONS.items()
    if t.leaving is not None and t.heading is not None
}


_STATUS_SETTLE_TIMEOUT_SECONDS = 30.0


_TERMINAL_FAILURE_STATUSES = frozenset({"Failed", "CredentialInvalid"})


@dataclass(frozen=True)
class BatchDispatchOutcome:
    """A machine result for one explicitly batch-approved dot command."""

    ok: bool
    detail: str


def _expected_seconds_for_target(target_status: str) -> float:
    """How long the transition to `target_status` is expected to take, for the poll schedule's benefit only (core/utils/poll_schedule.py)."""
    if target_status == "Running":
        return get_env_start_expected_seconds()
    if target_status == "Suspended":
        return get_env_stop_expected_seconds()
    return 0.0


def _poll_until_status(
    api_client: Any,
    node: NodeRecord,
    environment_id: str,
    target_status: str,
    on_node_change: Callable[[NodeRecord], None],
    settled_raw: Optional[tuple[str, ...]] = None,
    concurrency: int = 1,
) -> str:
    """Poll get_environment_status() until it maps to target_status, a _TERMINAL_FAILURE_STATUSES value, or _STATUS_SETTLE_TIMEOUT_SECONDS is exhausted."""


    poll_t0 = time.monotonic()
    poll_count = 0


    with status_poll_wait(floor=concurrency) as schedule_for:
        schedule = schedule_for(_expected_seconds_for_target(target_status))
        holding = _HOLDING_STATUS_FOR_TARGET.get(target_status, "Transitioning")
        previous_status = node.container_status
        if previous_status != holding:
            node.container_status = holding
            on_node_change(node)
        mapped_status = holding
        deadline = time.monotonic() + _STATUS_SETTLE_TIMEOUT_SECONDS
        try:
            while True:
                status_result = api_client.get_environment_status(environment_id)
                poll_count += 1
                raw_status = status_result.get("status", "")


                elapsed = time.monotonic() - poll_t0
                timeline_mark(
                    "env.status",
                    loop="settle",
                    status=raw_status,
                    polls=poll_count,
                    since_anchor_s=round(elapsed, 3),
                    phase=schedule.phase_at(elapsed),
                    target=target_status,
                )
                new_mapped = _AWS_STATUS_MAP.get(raw_status, "Unknown")
                reached_target = new_mapped == target_status


                if settled_raw is not None and reached_target:
                    reached_target = raw_status in settled_raw
                terminal_failure = new_mapped in _TERMINAL_FAILURE_STATUSES


                out_of_time = time.monotonic() >= deadline
                if reached_target or terminal_failure or out_of_time:
                    mapped_status = new_mapped
                    node.container_status = mapped_status
                    on_node_change(node)
                    break


                schedule = schedule_for(_expected_seconds_for_target(target_status))
                time.sleep(schedule.delay_after(time.monotonic() - poll_t0))
        except Exception:
            node.container_status = previous_status
            on_node_change(node)
            raise
        finally:


            record_span(
                "env.settle_poll",
                (time.monotonic() - poll_t0) * 1000,
                target=target_status,
                polls=poll_count,
                budget_s=_STATUS_SETTLE_TIMEOUT_SECONDS,
            )
    return mapped_status


@dataclass(frozen=True)
class FanOutContext:
    """What a fan-out worker is allowed to know about the fan-out."""

    workers: int
    total: int


@dataclass(frozen=True)
class FanOutResult:
    """What the pool produced."""

    ok: list[str]
    failed: list[str]
    messages: dict[str, list[str]]


    cancelled: list[str] = field(default_factory=list)


    cancellation_report: str = ""


class Guard(enum.Flag):
    """WHICH signals a caller wants a node refused on. `#621`."""

    NONE = 0
    BUILD = enum.auto()
    CONTAINER = enum.auto()
    CONNECTING = enum.auto()
    PENDING = enum.auto()
    SESSION = enum.auto()


    SUSPENDING = BUILD | CONTAINER
    BUSY = CONNECTING | PENDING | SESSION | BUILD | CONTAINER


def _connecting_reason(node: NodeRecord) -> Optional[str]:
    """`Guard.CONNECTING` on its own."""
    if getattr(node, "_connecting", False):
        return "still connecting -- a connect or provision is already in flight on this node"
    return None


def _pending_reason(node: NodeRecord) -> Optional[str]:
    """`Guard.PENDING` on its own."""
    if node.container_status == "Pending":
        return "still provisioning -- the environment does not exist yet"
    return None


def _require_clauses(guard: Guard, where: str) -> None:
    """Refuse an empty guard. `Guard.NONE` refuses nothing, which is `#619`'s `guard="none"` by another name."""
    if not guard:
        raise ValueError(
            f"{where}() needs at least one clause: an empty guard refuses nothing, "
            "which is how `#619`'s three unguarded destructive commands shipped. "
            "Name the clauses this caller means, e.g. Guard.BUILD."
        )


def guard_reason(node: NodeRecord, guard: Guard) -> Optional[str]:
    """Why `guard`'s clauses refuse `node`, or None. THE one evaluator."""
    _require_clauses(guard, "guard_reason")
    for clause, predicate in _CLAUSES:
        if clause & guard:
            reason = predicate(node)
            if reason is not None:
                return reason
    return None


def nodes_by_env_id(nodes_by_id: dict[str, NodeRecord]) -> dict[str, NodeRecord]:
    """environment id → the node holding it, for the env-id-keyed paths."""
    by_env: dict[str, NodeRecord] = {}
    for node in nodes_by_id.values():
        env_id = node.environment_id
        if env_id:
            by_env[env_id] = node
    return by_env


def guard_reasons_by_env_id(nodes_by_id: dict[str, NodeRecord], *, guard: Guard) -> dict[str, str]:
    """environment id → why `guard` refuses the node holding it. The env-id keyed sibling of `filter_busy_nodes`."""
    _require_clauses(guard, "guard_reasons_by_env_id")
    reasons: dict[str, str] = {}
    for env_id, node in nodes_by_env_id(nodes_by_id).items():
        reason = guard_reason(node, guard)
        if reason is not None:
            reasons[env_id] = reason
    return reasons


def _is_wrong_state_refusal(exc: BaseException) -> bool:
    """Did the service refuse because the environment is in the wrong STATE?"""
    return _classify_guarded(exc) == "environment_suspended"


def _mark_failed_best_effort(node: NodeRecord, exc: BaseException) -> None:
    """Record WHY a node failed, without importing a CSP into shared core."""
    try:
        from cloudbasher.csp.aws.failure import note_node_failure


        note_node_failure(node, exc)
    except Exception:
        node._last_failure_class = "unknown"


from cloudbasher.core.cancel import (  # noqa: E402
    begin_operation,
    declaring_fanout,
    end_operation,
    in_flight,
    report_cancellation,
    skip_if_cancelled,
    was_cancelled,
)
from cloudbasher.core.node_ids import in_display_order, order_like  # noqa: E402


def _operation_label(line: str, resolve: Optional[Callable[[str], str]] = None) -> str:
    """What a cancellation message calls the running command."""
    stripped = (line or "").strip()
    if not stripped:
        return ""
    first = stripped.split()[0]
    if resolve is None:
        return first
    try:
        return resolve(first.lower())
    except Exception:


        return first


def display_order(state: Any, node_ids: Iterable[str]) -> list[str]:
    """`in_display_order` bound to `state`. `#772`."""
    return in_display_order(node_ids, state.credentials_by_id, state.nodes_by_id)


def filter_busy_nodes(
    verb: str,
    node_ids: Sequence[str],
    nodes_by_id: dict[str, NodeRecord],
    labels: dict[str, str],
    *,
    credentials_by_id: dict[str, Any],
    guard: Guard = Guard.BUSY,
) -> tuple[dict[str, NodeRecord], dict[str, str]]:
    """Split a resolved selection into (ready, skipped-with-reason)."""

    _require_clauses(guard, "filter_busy_nodes")
    ready: dict[str, NodeRecord] = {}
    skipped: dict[str, str] = {}


    for node_id in in_display_order(node_ids, credentials_by_id, nodes_by_id):
        node = nodes_by_id.get(node_id)
        if node is None:


            skipped[node_id] = "unknown node"
            eprint(f"{verb}: {labels.get(node_id, node_id)}: skipped -- unknown node")
            continue
        reason = guard_reason(node, guard)
        if reason is None:
            ready[node_id] = node
        else:
            skipped[node_id] = reason
            eprint(f"{verb}: {labels.get(node_id, node_id)}: skipped -- {reason}")
    return ready, skipped


def fan_out_over_nodes(
    verb: str,
    nodes: dict[str, NodeRecord],
    labels: dict[str, str],
    worker: Callable[[str, FanOutContext], tuple[bool, list[str]]],
    state: InteractiveState,
    *,
    refresh: bool = True,
    on_failure: Optional[Callable[[NodeRecord, BaseException], None]] = None,
    on_success: Optional[Callable[[str], None]] = None,
) -> FanOutResult:
    """Run `worker` over `nodes` concurrently. Prints nothing."""
    on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)
    workers = pool_width(len(nodes))
    ctx = FanOutContext(workers=workers, total=len(nodes))
    mark_failed = on_failure or _mark_failed_best_effort

    def _label(node_id: str) -> str:
        """This node's display name, or its id. `labels` MAY BE EMPTY."""
        return labels.get(node_id, node_id)

    def _guarded(node_id: str) -> tuple[str, bool, list[str], str, bool]:
        """A worker that raises is one node's problem, never the fan-out's."""


        node = nodes[node_id]
        begin_node_activity(state, node, clear_queued=True, publish=False)


        on_node_change(node)


        try:


            if skip_if_cancelled():
                return (
                    node_id,
                    False,
                    [f"{verb}: {_label(node_id)}: skipped -- cancelled"],
                    "",
                    True,
                )
            with in_flight():
                succeeded, lines = worker(node_id, ctx)
            return node_id, succeeded, lines, "", False
        except BaseException as exc:  # noqa: BLE001 -- isolation is the job


            if was_cancelled(exc):
                return (
                    node_id,
                    False,
                    [f"{verb}: {_label(node_id)}: skipped -- cancelled"],
                    "",
                    True,
                )
            mark_failed(nodes[node_id], exc)


            return (
                node_id,
                False,
                [f"{verb}: {_label(node_id)}: {exc}"],
                _classify_guarded(exc),
                False,
            )
        finally:
            end_node_activity(state, node, publish=False)

    ok: list[str] = []
    failed: list[str] = []
    cancelled: list[str] = []
    messages: dict[str, list[str]] = {}


    consecutive_env_wide = 0
    halted = False


    token = begin_operation(verb)
    report: list[str] = []


    order: list[str] = []


    with declaring_fanout(ctx.total, verb):
        try:


            if nodes:
                for node in nodes.values():
                    node.mark_queued()
                on_node_change(next(iter(nodes.values())))
                with ThreadPoolExecutor(max_workers=workers) as executor:


                    order = display_order(state, nodes)
                    futures = [executor.submit(_guarded, nid) for nid in order]
                    for future in as_completed(futures):
                        node_id, succeeded, lines, failure_class, was_skipped = future.result()
                        messages[node_id] = lines
                        (ok if succeeded else failed).append(node_id)
                        if was_skipped:
                            cancelled.append(node_id)
                        if succeeded or not is_environment_wide(failure_class):
                            consecutive_env_wide = 0
                        else:
                            consecutive_env_wide += 1
                            if consecutive_env_wide >= _ADMISSION_HALT_AFTER and not halted:
                                halted = True
                                _halt_admission(verb, failure_class)


                        if succeeded and on_success is not None:


                            try:
                                on_success(node_id)
                            except Exception as exc:  # noqa: BLE001 -- isolation
                                label = _label(node_id)
                                messages[node_id] = lines + [
                                    f"{verb}: {label}: finished with errors: {exc}"
                                ]
                                log(f"[{verb}] on_success failed for {node_id}: {exc}")


                        if refresh or not succeeded:
                            on_node_change(nodes[node_id])
        finally:


            swept = [
                node
                for node in nodes.values()


                if node.clear_queued() | node.clear_working()
            ]
            for node in swept:
                on_node_change(node)


            report_cancellation(report.append)
            end_operation(token)


    return FanOutResult(
        ok=order_like(order, ok),
        failed=order_like(order, failed),
        messages={node_id: messages[node_id] for node_id in order_like(order, messages)},
        cancelled=order_like(order, cancelled),
        cancellation_report=" ".join(report),
    )


_ADMISSION_HALT_AFTER = 5


def _classify_guarded(exc: BaseException) -> str:
    """The failure class the admission gate reads, or "" if none is available."""
    try:
        from cloudbasher.csp.aws.failure import classify_failure

        return classify_failure(exc) or ""
    except Exception:
        return ""


def _halt_admission(verb: str, failure_class: str) -> None:
    """Stop admitting work, and say why. `#466`."""
    from cloudbasher.core.cancel import request_cancel

    did, message = request_cancel(
        f"{_ADMISSION_HALT_AFTER} consecutive nodes failed with "
        f"'{label_for(failure_class)}' and nothing has succeeded since"
    )
    if message:
        eprint(message)
    log(
        f"[fanout] {verb}: admission halted after {_ADMISSION_HALT_AFTER} "
        f"consecutive {failure_class} failures (cancel_taken={did})"
    )


def summarise_fan_out(
    verb: str,
    past: str,
    matched: int,
    labels: dict[str, str],
    result: FanOutResult,
    skipped: dict[str, str],
    *,
    selector: str = "",
) -> None:
    """Replay the workers' messages in NODE order, then one summary line."""


    for node_id in result.messages:
        for line in result.messages[node_id]:
            eprint(line)
    ok_refs = ", ".join(labels.get(nid, nid) for nid in result.ok)
    tail = f" ({len(skipped)} skipped)" if skipped else ""
    out(f"{past} {len(result.ok)}/{matched} node(s): {ok_refs}{tail}")
    if result.failed:
        eprint(f"Failed: {', '.join(labels.get(nid, nid) for nid in result.failed)}")


    if result.cancellation_report:
        out(result.cancellation_report)
    else:


        report_cancellation(out)
    log(
        f"[{verb}] selector={selector!r} ok={ok_refs} "
        f"failed={list(result.failed)} skipped={list(skipped)}"
    )


def _open_shell_or_fail(node: NodeRecord, session: Any) -> Optional[str]:
    """Force `session`'s transport genuinely open. Returns None on success or an error string on failure (after tearing the node's session down)."""
    try:
        session.open_shell()
    except Exception as e:
        disconnect_node(node)
        return f"handshake failed: {e}"
    return None


def _fresh_session_for_batch_line(state: InteractiveState) -> Optional[Any]:
    """The session to run one batch line on, re-resolved rather than remembered."""
    node = getattr(state, "_dispatch_node", None)
    if node is not None and getattr(state, "csp_provider", None) is not None:
        session, _err = ensure_node_session(state.csp_provider, state, node)
        if session is not None:
            return session


    return getattr(state, "_session_obj", None)


def resolve_bound_node(state: InteractiveState, verb: str) -> Optional[NodeRecord]:
    """Return the one node bound to a session command, or report refusal."""
    nodes = getattr(state, "nodes_by_id", {}) or {}
    dispatch_node = getattr(state, "_dispatch_node", None)
    if dispatch_node is not None:
        return dispatch_node

    shell_node_id = getattr(state, "shell_node_id", None)
    shell_node = nodes.get(shell_node_id) if shell_node_id else None
    if shell_node is not None:
        return shell_node

    active_node_id = getattr(state, "active_node_id", None)
    active_node = nodes.get(active_node_id) if active_node_id else None
    if active_node is not None:
        return active_node
    if len(nodes) == 1:
        return next(iter(nodes.values()))

    eprint(
        f"{verb}: no active node"
        + (
            f" ({len(nodes)} to choose from -- select one first)"
            if nodes
            else " -- provision or connect one first"
        )
    )
    return None


def resolve_bound_session(csp: CSPProvider, state: InteractiveState, verb: str) -> Optional[Any]:
    """Return the live session for one legacy session command."""
    nodes = getattr(state, "nodes_by_id", {}) or {}
    if not nodes:
        session = getattr(state, "_session_obj", None)
        if session is None:
            eprint(f"{verb}: No session available")
        return session

    node = resolve_bound_node(state, verb)
    if node is None:
        return None
    session, err = ensure_node_session(csp, state, node)
    if session is None:
        eprint(f"{verb}: {err or 'no live session'}")
    return session


def run_explicit_session_action(
    csp: CSPProvider,
    state: InteractiveState,
    verb: str,
    selector: str,
    action: Callable[[Any], str],
) -> Optional[tuple[int, dict[str, str], dict[str, str], FanOutResult, dict[str, str]]]:
    """Run one session action for an explicit multi-node selector."""
    node_ids = _resolve_nodes_or_report(verb, selector, state)
    if node_ids is None:
        return None
    nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
    credentials_by_id = getattr(state, "credentials_by_id", {}) or {}
    labels = _node_ref_labels(node_ids, nodes_by_id, credentials_by_id)
    ready, skipped = filter_busy_nodes(
        verb, node_ids, nodes_by_id, labels, credentials_by_id=credentials_by_id
    )
    if not ready:
        eprint(f"{verb}: no ready nodes in selection")
        return None

    results: dict[str, str] = {}

    def run_one(node_id: str, _ctx: FanOutContext) -> tuple[bool, list[str]]:
        session, err = ensure_node_session(csp, state, ready[node_id])
        if session is None:
            return False, [f"{verb}: {labels[node_id]}: {err or 'no live session'}"]
        results[node_id] = action(session)
        return True, []

    result = fan_out_over_nodes(verb, ready, labels, run_one, state, refresh=False)
    return len(node_ids), labels, skipped, result, results


def node_busy_reason(node: NodeRecord) -> Optional[str]:
    """Why `node` cannot be given a shell *right now*, or None if it can."""


    return guard_reason(node, Guard.BUSY)


def node_suspending_reason(node: NodeRecord) -> Optional[str]:
    """The subset of node_busy_reason() that NO caller sets on its own behalf."""


    return guard_reason(node, Guard.SUSPENDING)


def build_owner_reason(node: NodeRecord) -> Optional[str]:
    """`#599`'s clause on its own, so ONE tier can decline it."""
    owner = getattr(node, "_runtime_build_owner", "")
    if owner:
        return f"a build owns this node right now -- {owner} is still finishing it"
    return None


def container_teardown_reason(node: NodeRecord) -> Optional[str]:
    """The container half of `node_suspending_reason`, without `#599`'s clause."""
    if getattr(node, "_disconnecting", False) or node.container_status == "Suspending":
        return "environment is suspending -- wait for it to reach Suspended, then .start it"
    return None


def session_busy_reason(node: NodeRecord) -> Optional[str]:
    """Why ANOTHER thread's work on this node's live session blocks new work."""
    activity = activity_of(node)
    if activity is None:
        return None
    return activity.busy_reason(caller_thread=threading.get_ident())


_CLAUSES: tuple[tuple[Guard, Callable[[NodeRecord], Optional[str]]], ...] = (
    (Guard.CONNECTING, _connecting_reason),
    (Guard.PENDING, _pending_reason),
    (Guard.SESSION, session_busy_reason),
    (Guard.BUILD, build_owner_reason),
    (Guard.CONTAINER, container_teardown_reason),
)


def _bind_activity_poke(state: InteractiveState, node: NodeRecord, session: Any) -> None:
    """Give ``session`` a way to ask for a repaint, without telling it what a node is."""
    if not hasattr(session, "on_activity_change"):
        return
    on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)
    session.on_activity_change = lambda: on_node_change(node)


def ensure_node_session(
    csp: CSPProvider, state: InteractiveState, node: NodeRecord
) -> tuple[Optional[Any], Optional[str]]:
    """Return (session, None) on success or (None, error_message) on failure."""
    with node._recovery_lock:
        from cloudbasher.core.session.liveness import node_session_is_condemned

        needs_reconnect = (
            node._runtime_session is None
            or node_socket_is_dead(node)
            or node_session_is_condemned(node)
        )
        if needs_reconnect:
            credential = (getattr(state, "credentials_by_id", None) or {}).get(node.credential_id)
            invalid = known_invalid_credential_error(
                credential, "connect", label=f"credential for node {node.id}"
            )
            if invalid:
                return None, invalid


        own_connect = needs_reconnect and not node._connecting
        own_working = needs_reconnect and not node._runtime_working
        if own_connect or own_working:
            begin_node_activity(
                state,
                node,
                connecting=own_connect,
                working=own_working,
            )
        try:
            return _ensure_node_session_locked(csp, state, node)
        finally:
            if own_connect or own_working:
                end_node_activity(
                    state,
                    node,
                    connecting=own_connect,
                    working=own_working,
                )


def _ensure_node_session_locked(
    csp: CSPProvider, state: InteractiveState, node: NodeRecord
) -> tuple[Optional[Any], Optional[str]]:
    """``ensure_node_session``'s body, run with that node's recovery lock held."""
    session = getattr(node, "_runtime_session", None)
    from cloudbasher.core.session.liveness import node_session_is_condemned

    if session is not None and (
        node_socket_is_dead(node) or node_session_is_condemned(node)
    ):


        reason = getattr(session, "condemned_reason", None)
        evidence = (
            f"session condemned ({reason})"
            if reason
            else f"socket marked dead after {node._socket_ping_failures} failed pings"
        )
        log(f"[recover] {evidence}; rebuilding the session for {node.id}")
        disconnect_node(node, scope="session")
        session = None
    if session is not None:


        err = _open_shell_or_fail(node, session)
        if err is not None:
            return None, err


        node.mark_real_traffic()
        _bind_activity_poke(state, node, session)


        _fill_prompt_info_once(node, session)
        return session, None


    suspending = node_suspending_reason(node)
    if suspending is not None:
        return None, suspending
    reconnect_provider = csp
    rec = (getattr(state, "credentials_by_id", None) or {}).get(node.credential_id)
    if rec is not None and rec.provider == "azure" and getattr(csp, "name", None) != "azure":


        from ...csp.azure.provider import AzureProvider

        reconnect_provider = AzureProvider()
    elif rec is not None and rec.provider == "gcp" and getattr(csp, "name", None) != "gcp":
        from ...csp.gcp.provider import GCPProvider

        reconnect_provider = GCPProvider()
    if not isinstance(reconnect_provider, SupportsNodeReconnect):
        return None, "not connected (no live session in this process)"
    try:
        session = reconnect_provider.reconnect_node(state, node)
    except Exception as e:


        node._last_failure_class = _classify_guarded(e) or "unknown"
        return None, f"reconnect failed: {e}"
    node._runtime_session = session
    _bind_activity_poke(state, node, session)
    err = _open_shell_or_fail(node, session)
    if err is not None:
        return None, err


    node.container_status = "Running"
    node.end_connect()


    node._socket_ping_failures = 0
    node.mark_real_traffic()


    node._last_failure_class = ""


    revalidate = getattr(state, "revalidate_credential", None)
    if revalidate is not None:
        revalidate(node.credential_id, reason="a reconnect handshake authenticated with it")


    resolve_identity = getattr(state, "resolve_credential_identity", None)
    if resolve_identity is not None:
        resolve_identity(node.credential_id)


    node.mark_activity()
    _fill_prompt_info_once(node, session)
    return session, None


def _fill_prompt_info_once(node: NodeRecord, session: Any) -> None:
    """Probe IP/Host for `node` if nothing has, ONCE per session object."""
    if node.session is None or node.session.ip_address:
        return
    if node._runtime_prompt_probed_session is session:
        return
    try:
        from cloudbasher.cli.main import _probe_node_prompt_info

        _probe_node_prompt_info(node, lambda _msg: None)
    except Exception:
        pass


def ensure_node_api_client(
    csp: CSPProvider, state: InteractiveState, node: NodeRecord
) -> tuple[Optional[Any], Optional[str]]:
    """Return (api_client, None) on success or (None, error_message) on failure -- the control-plane-only counterpart to ensure_node_session() above, for .delete/.start/.stop, which only need to call REST endpoints (delete_environment/start_environment/stop_environment/ get_environment_status), not an interactive shell session."""
    credential = (getattr(state, "credentials_by_id", None) or {}).get(node.credential_id)
    invalid = known_invalid_credential_error(
        credential, "lifecycle action", label=f"credential for node {node.id}"
    )
    if invalid:
        return None, invalid
    api_client = getattr(node, "_runtime_api_client", None)


    if api_client is not None:
        _usable = getattr(csp, "node_client_is_usable", None)
        if _usable is None or _usable(state, node, api_client):
            return api_client, None


        node._runtime_api_client = None
        api_client = None
    if not isinstance(csp, SupportsNodeReconnect):
        return None, "not connected (no live session in this process)"
    try:
        api_client = csp.reconnect_node_api_client(state, node)
    except Exception as e:
        return None, f"reconnect failed: {e}"
    node._runtime_api_client = api_client
    return api_client, None


def resolve_node_for_action(
    csp: CSPProvider, state: InteractiveState, verb: str
) -> Optional[tuple[Any, str, NodeRecord]]:
    """`(api_client, environment_id, node)` for a command that acts on ONE node, or None after printing why not."""
    nodes = getattr(state, "nodes_by_id", {}) or {}
    active_id = getattr(state, "active_node_id", None)
    node = nodes.get(active_id) if active_id else None
    if node is None:
        if len(nodes) == 1:
            node = next(iter(nodes.values()))
        else:
            eprint(
                f"{verb}: no active node"
                + (
                    f" ({len(nodes)} to choose from -- select one first)"
                    if nodes
                    else " -- provision or connect one first"
                )
            )
            return None
    if not node.environment_id:
        eprint(f"{verb}: node {node.id} has no environment yet")
        return None
    api, err = ensure_node_api_client(csp, state, node)
    if api is None:
        eprint(f"{verb}: {err}")
        return None
    return api, node.environment_id, node


def _park_browser_for_reuse(
    node: NodeRecord, where: str, why: str, *, shell_survives: bool
) -> None:
    """Take the session's browser without closing it and park it on the node."""
    session = getattr(node, "_runtime_session", None)
    detach = getattr(session, "detach_browser", None)
    if not callable(detach):
        return
    handles = detach()
    if not handles:
        return
    node._runtime_parked_browser = handles
    node._runtime_parked_shell_is_dead = not shell_survives
    detail(f"{where}: keeping the console browser -- {why}")


def close_parked_browser(node: NodeRecord) -> None:
    """Close a browser parked by `_park_browser_for_reuse`, if any."""
    handles = getattr(node, "_runtime_parked_browser", None)
    if not handles:
        return
    node._runtime_parked_browser = None
    try:
        from cloudbasher.csp.aws.browser import close_playwright_browser

        close_playwright_browser(
            handles.get("browser"), handles.get("context"), handles.get("page")
        )
    except Exception as exc:
        detail(f"could not close the parked browser: {exc}")


def disconnect_node(node: NodeRecord, *, scope: Literal["node", "session"] = "node") -> None:
    """Stop this node's heartbeat and close its live WebSocket session, if any -- purely local, in-process teardown."""


    if node._runtime_session is not None or node._runtime_heartbeat_thread is not None:
        node.mark_activity()


    loops = node.loops_for_scope(scope)
    node.signal_background_loops(loops)


    node.join_background_loops(names=loops, where="disconnect")

    node.release_background_loops(loops)
    if node._runtime_session is not None:
        try:
            node._runtime_session.close()
        except Exception:
            pass
    node._runtime_session = None


    node._runtime_prompt_probed_session = None


    node._disconnecting = False


def delete_nodes(
    csp: CSPProvider, state: InteractiveState, node_ids: set, *, force: bool = False
) -> tuple[list[str], list[str]]:
    """Apply each provider's delete/reset behavior, then drop successful nodes from the registry. Returns (deleted, failed) node-id lists, sorted."""
    nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
    selected_node_ids = getattr(state, "selected_node_ids", None) or set()
    on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)


    refs = _node_display_refs(node_ids, nodes_by_id, getattr(state, "credentials_by_id", {}) or {})


    if force:
        for _nid in node_ids:
            _n = nodes_by_id.get(_nid)
            if _n is None:
                continue
            _credential = state.credentials_by_id.get(_n.credential_id)
            if getattr(_credential, "provider", None) == "gcp":


                continue
            _owner = getattr(_n, "_runtime_build_owner", "")
            if not _owner:
                continue


            if not getattr(_n, "environment_id", None):
                eprint(
                    f"delete: {refs.get(_nid, _nid)}: --force cannot help yet -- {_owner} has "
                    f"not created an environment for this node, so there is nothing to delete. "
                    f"Use .unregister to drop the record."
                )
                continue
            eprint(
                f"delete: {refs.get(_nid, _nid)}: --force overriding a build claim -- "
                f"{_owner} was still finishing this node"
            )
            _n.end_connect()
    ready, _skipped = filter_busy_nodes(
        "delete",
        node_ids,
        nodes_by_id,
        refs,
        credentials_by_id=state.credentials_by_id,
        guard=Guard.BUILD,
    )

    def _delete_one(node_id: str, ctx: FanOutContext) -> tuple[bool, list[str]]:
        """The API call and the teardown. NOT the registry mutation."""
        node = nodes_by_id[node_id]
        credential = state.credentials_by_id.get(node.credential_id)
        if getattr(credential, "provider", None) == "gcp":
            api_client, err = ensure_node_api_client(csp, state, node)
            if err:
                return False, [f"delete: [{refs[node_id]}] {err}"]
            from cloudbasher.csp.gcp.private_api import GCSPrivateAPI

            if not isinstance(api_client, GCSPrivateAPI):
                return False, [
                    f"delete: [{refs[node_id]}] GCP `.delete` applies only to Console "
                    "credential nodes. The public OAuth API has no environment-delete method."
                ]


            disconnect_node(node)
            try:


                api_client.new_token()
                api_client.abandon()
            except Exception as exc:


                failure = (
                    str(exc)
                    if isinstance(exc, CloudShellAutomationError)
                    else type(exc).__name__
                )
                return False, [
                    f"delete: [{refs[node_id]}] GCP Console delete failed; "
                    f"the node remains registered for a delete retry, but its terminal "
                    f"was disconnected to match native Restart ordering. {failure}"
                ]
            close_parked_browser(node)
            return True, [
                f"delete: [{refs[node_id]}] GCP Console session abandoned and local "
                "node record removed; this does not delete persistent Cloud Shell "
                "user data or prove permanent environment deletion."
            ]
        api_client, err = ensure_node_api_client(csp, state, node)
        if err:
            return False, [f"delete: [{refs[node_id]}] {err}"]
        if not isinstance(api_client, SupportsEnvironmentDeletion):
            return False, [
                f"delete: [{refs[node_id]}] this CSP doesn't support environment deletion"
            ]
        if not node.environment_id:
            return False, [f"delete: [{refs[node_id]}] no environment_id on record"]

        warnings: list[str] = []


        node.retire_server_sessions()
        try:
            api_client.delete_environment(node.environment_id)
        except Exception as exc:
            if not _is_wrong_state_refusal(exc):
                return False, [f"delete: [{refs[node_id]}] {exc}"]


            warnings.append(
                f"delete: [{refs[node_id]}] environment is mid-transition, "
                "waiting for it to settle"
            )


            _poll_until_status(
                api_client,
                node,
                node.environment_id,
                "Suspended",
                on_node_change,
                settled_raw=("SUSPENDED", "STOPPED"),
                concurrency=ctx.workers,
            )
            try:
                api_client.delete_environment(node.environment_id)
            except Exception as retry_exc:
                return False, warnings + [f"delete: [{refs[node_id]}] {retry_exc}"]

        disconnect_node(node)


        close_parked_browser(node)
        return True, warnings

    result = fan_out_over_nodes("delete", ready, refs, _delete_one, state)
    for node_id in result.messages:
        for line in result.messages[node_id]:
            eprint(line)


    last_node = None
    destroyed = []
    for node_id in result.ok:
        last_node = nodes_by_id.get(node_id)
        last_credential = (
            (getattr(state, "credentials_by_id", None) or {}).get(last_node.credential_id)
            if last_node is not None
            else None
        )
        if (
            last_node is not None
            and getattr(last_node, "environment_id", None)
            and getattr(last_credential, "provider", None) != "gcp"
        ):
            destroyed.append(last_node.environment_id)
        nodes_by_id.pop(node_id, None)


        if last_node is not None:
            last_node.mark_destroyed()
        selected_node_ids.discard(node_id)
        if getattr(state, "active_node_id", None) == node_id:
            state.active_node_id = None


    mark = getattr(csp, "note_deleted", None)
    if mark is not None and destroyed:
        mark(state, destroyed)

    if last_node is not None:


        on_node_change(last_node)


    return result.ok, result.failed


_ROW_RANGE_RE = re.compile(r"^(\d+)-(\d+)$")
_ROW_SINGLE_RE = re.compile(r"^(\d+)$")


def resolve_node_selector(
    selector: str,
    nodes_by_id: Dict[str, NodeRecord],
    selected_node_ids: set,
    visible_row_node_ids: Sequence[frozenset] = (),
    credentials_by_id: Optional[Dict[str, Any]] = None,
) -> tuple[set, Optional[str]]:
    """Resolve a .bulk/.output selector into a set of node ids."""
    selector = selector.strip()
    if not selector:
        return set(), "empty selector"
    if selector.lower() == "selected":
        return set(selected_node_ids), None
    if selector.upper() == "ALL":
        return set(nodes_by_id.keys()), None
    if "," in selector:
        matched: set = set()
        for part in selector.split(","):
            part = part.strip()
            if not part:
                continue
            part_matched, err = resolve_node_selector(
                part,
                nodes_by_id,
                selected_node_ids,
                visible_row_node_ids,
                credentials_by_id=credentials_by_id,
            )
            if err:
                return set(), err
            matched |= part_matched
        return matched, None


    if selector in nodes_by_id:
        return {selector}, None


    if credentials_by_id:
        from cloudbasher.core.node_ids import resolve_id_selector

        by_id = resolve_id_selector(selector, credentials_by_id, nodes_by_id)
        if by_id is not None:
            return by_id, None
    row_match = _ROW_RANGE_RE.match(selector) or _ROW_SINGLE_RE.match(selector)
    if row_match:
        groups = row_match.groups()
        lo, hi = (int(groups[0]), int(groups[1])) if len(groups) == 2 else (int(groups[0]),) * 2
        lo, hi = max(1, min(lo, hi)), max(lo, hi)
        matched = set()
        for position in range(lo, hi + 1):
            if 1 <= position <= len(visible_row_node_ids):
                matched |= set(visible_row_node_ids[position - 1])
        return matched, None
    if any(ch in selector for ch in "*?["):
        return {
            nid
            for nid, node in nodes_by_id.items()
            if node.region and fnmatch.fnmatch(node.region, selector)
        }, None
    exact_region = {
        nid for nid, node in nodes_by_id.items() if getattr(node, "region", None) == selector
    }
    if exact_region:
        return exact_region, None


    needle = selector.lower()
    return {
        nid
        for nid, node in nodes_by_id.items()
        if needle in nid.lower()
        or needle in (node.region or "").lower()
        or needle in (node.credential_id or "").lower()
    }, None


def _node_ref_labels(
    node_ids: set,
    nodes_by_id: Dict[str, NodeRecord],
    credentials_by_id: Dict[str, Any],
) -> Dict[str, str]:
    """Live-testing feedback: lifecycle commands (.start/.stop/.disconnect/ .delete/.unregister) used to report results as a bare comma-list of raw node ids (e.g. "aws:AKIAFAKE000000004YUR:orig:federation_token:clb-1: ap-northeast-2") -- accurate, but there was no fast way to tell which on-screen row that corresponded to. Prefixes each id with its addressable ID -- `[ID 1.2]` -- which is what the Nodes pane's gutter shows AND what every selector accepts."""


    from cloudbasher.core.node_ids import display_id_for

    labels: Dict[str, str] = {}
    for node_id in node_ids:
        display = display_id_for(node_id, credentials_by_id, nodes_by_id)
        labels[node_id] = f"[ID {display or '?'}] {node_id}"
    return labels


def _node_display_refs(
    node_ids,
    nodes_by_id: Dict[str, NodeRecord],
    credentials_by_id: Dict[str, Any],
) -> Dict[str, str]:
    """Just `<cred#>.<node#>` per node -- the COMPACT form, for a per-line prefix. Falls back to the raw node id when there is none."""
    from cloudbasher.core.node_ids import build_id_map

    display_ids, _creds = build_id_map(credentials_by_id, nodes_by_id)
    return {node_id: display_ids.get(node_id, node_id) for node_id in node_ids}


def _get_term_width() -> int:
    """Return terminal column count, or 9999 when no terminal is attached."""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 9999


def _shrink_columns_to_fit(widths: list[int], max_width: int) -> list[int]:
    """Proportionally reduce column widths so the table fits within max_width columns."""
    total = 1 + sum(w + 3 for w in widths)
    if total <= max_width:
        return list(widths)
    n = len(widths)
    available = max_width - 1 - 3 * n
    if available <= n:
        return [1] * n
    s = sum(widths)
    new_widths = [max(4, int(w * available / s)) for w in widths]

    diff = available - sum(new_widths)
    for i in sorted(range(n), key=lambda i: -widths[i])[: max(0, diff)]:
        new_widths[i] += 1
    return new_widths


def _fmt_table(headers: list[str], rows: list[list[str]], max_width: Optional[int] = None) -> str:
    """Format rows as an ASCII +---+ bordered table. Cells may contain newlines."""
    n = len(headers)
    col_widths = [len(h) for h in headers]


    row_cell_lines: list[list[list[str]]] = []
    for row in rows:
        cell_lines = [str(cell).split("\n") for cell in row]
        row_cell_lines.append(cell_lines)
        for i, lines in enumerate(cell_lines):
            if i < n:
                col_widths[i] = max(col_widths[i], max(len(l) for l in lines))

    if max_width is not None:
        col_widths = _shrink_columns_to_fit(col_widths, max_width)

    def _trunc(s: str, w: int) -> str:
        return s if len(s) <= w else s[: w - 1] + "…"

    def _divider() -> str:
        return "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"

    def _row_str(cells: list[str]) -> str:
        parts = [
            f" {_trunc(cells[i] if i < len(cells) else '', col_widths[i]):<{col_widths[i]}} "
            for i in range(n)
        ]
        return "|" + "|".join(parts) + "|"

    out_lines = [_divider(), _row_str(headers), _divider()]
    for cell_lines in row_cell_lines:
        n_sub = max((len(cl) for cl in cell_lines), default=1)
        for sub in range(n_sub):
            sub_cells = [
                (
                    (cell_lines[i][sub] if sub < len(cell_lines[i]) else "")
                    if i < len(cell_lines)
                    else ""
                )
                for i in range(n)
            ]
            out_lines.append(_row_str(sub_cells))
    out_lines.append(_divider())
    return "\n".join(out_lines)


def _explain_no_match(selector: str, state: Any) -> str:
    """Why a selector matched nothing, appended to the eight commands' message."""
    try:
        from cloudbasher.core.node_ids import explain_no_match

        return explain_no_match(
            selector,
            getattr(state, "credentials_by_id", None) or {},
            getattr(state, "nodes_by_id", None) or {},
        )
    except Exception:
        return ""


def _resolve_nodes_or_report(cmd: str, selector: str, state: Any) -> Optional[list]:
    """Resolve a node selector, or print why it matched nothing."""
    node_ids, err = resolve_node_selector(
        selector,
        getattr(state, "nodes_by_id", {}) or {},
        getattr(state, "selected_node_ids", None) or set(),
        getattr(state, "visible_row_node_ids", None) or [],
        credentials_by_id=getattr(state, "credentials_by_id", None),
    )
    if err:
        eprint(f"{cmd}: {err}")
        return None
    if not node_ids:
        eprint(
            f"{cmd}: no nodes matched selector {selector!r}" + _explain_no_match(selector, state)
        )
        return None
    return display_order(state, sorted(node_ids))


_HELP_TEXT_COLUMN = 29


_HELP_NAME_COLUMN = 20


def _spec_help_lines(
    dispatcher: Any, name: str, *, omit_notes: tuple[str, ...] = (), terse: bool = False
) -> list[str]:
    """`.help` lines for a migrated command, GENERATED from its spec (E2)."""
    spec = dispatcher.specs.get(name)
    if spec is None:
        return []


    _u = "  " + usage(spec).removeprefix("Usage: ")
    lines = []
    if terse:


        _t = "  " + terse_usage(spec)
        gap = max(_HELP_TEXT_COLUMN - len(_t), 2)
        return [(_t + " " * gap + (spec.summary or "")).rstrip()]
    if spec.summary and len(_u) < _HELP_TEXT_COLUMN:
        lines.append(_u.ljust(_HELP_TEXT_COLUMN) + spec.summary)
    else:
        lines.append(_u)
        if spec.summary:
            lines.append(" " * _HELP_TEXT_COLUMN + spec.summary)
    for note in (spec.notes or "").splitlines():
        note = note.strip()
        if not note:
            continue


        if any(note.startswith(prefix) for prefix in omit_notes):
            continue
        lines.append(" " * 29 + note)
    return lines


def _keys_help() -> list[str]:
    """`.help keys` -- the Nodes-pane keybindings, WITHOUT a heading."""
    from ..tui.keymap import nodes_help_lines

    return list(nodes_help_lines())


def _status_help() -> list[str]:
    """`.help status` -- the Status column's two glyph slots, no heading."""
    from ..tui.widgets.node_table import status_legend_lines

    body = list(status_legend_lines())
    return body[1:] if body and body[0].startswith("Status column") else body


_HELP_TOPICS = {
    "keys": _keys_help,
    "status": _status_help,
}


_HELP_DIVIDER = "─" * 78


_HELP_SECTION_ORDER = ("status", "keys")


_HELP_TOPIC_TITLES = {
    "keys": "Keys — Nodes pane",
    "status": "Status — the two glyph slots: [container] [connection]",
}

_HELP_TOPIC_BLURBS = {
    "keys": "Nodes-pane keybindings",
    "status": "The Status column's glyphs",
}

assert set(_HELP_SECTION_ORDER) == set(_HELP_TOPICS) == set(_HELP_TOPIC_BLURBS), (
    "every help topic needs a section position, a title and a blurb -- "
    f"order={sorted(_HELP_SECTION_ORDER)} topics={sorted(_HELP_TOPICS)} "
    f"blurbs={sorted(_HELP_TOPIC_BLURBS)}"
)


class CommandDispatcher:
    """Routes and dispatches interactive dot commands."""

    def __init__(self, csp: CSPProvider):
        """Initialize dispatcher."""
        self.csp = csp
        self._csp_help: Dict[str, str] = {}
        self.commands: Dict[str, Callable] = {
            ".help": self._cmd_help,
            ".command": self._cmd_command,
            ".upload": self._cmd_upload,
            ".download": self._cmd_download,
            ".enum": self._cmd_enum,
            ".creds": self._cmd_creds,
            ".state": self._cmd_state,
            ".history": self._cmd_history,
            ".heartbeat": self._cmd_heartbeat,
            ".ping": self._cmd_heartbeat,
            ".echo": self._cmd_echo,
            ".sleep": self._cmd_sleep,
            ".clear": self._cmd_clear,
            ".verbose": self._cmd_verbose,
            ".ui": self._cmd_ui,


            ".quit": self._cmd_quit,
            ".jobs": self._cmd_jobs,
            ".bg": self._cmd_bg,
            ".fg": self._cmd_fg,
            ".kill": self._cmd_kill,
            ".run": self._cmd_run,
            ".loop": self._cmd_loop,
            ".ls": self._cmd_ls,
            ".bulk": self._cmd_bulk,
            ".output": self._cmd_output,
            ".unregister": self._cmd_deregister,
            ".deregister": self._cmd_deregister,
            ".forget": self._cmd_deregister,
            ".delete": self._cmd_delete,
            ".disconnect": self._cmd_disconnect,
            ".connect": self._cmd_connect,
            ".start": self._cmd_start,
            ".stop": self._cmd_stop,
            ".suspend": self._cmd_stop,
        }


        self.specs: Dict[str, CommandSpec] = dict(CORE_SPECS)
        self._batch_active = False
        self._batch_outcome: Optional[BatchDispatchOutcome] = None

    def dispatch_batch(self, line: str, state: InteractiveState) -> BatchDispatchOutcome:
        """Run one result-aware batch line, refusing unscorable commands."""
        try:
            parts = shlex.split(line)
        except ValueError as exc:
            return BatchDispatchOutcome(False, f"invalid quoting: {exc}")
        if not parts or not parts[0].startswith("."):
            return BatchDispatchOutcome(False, "batch lines must be dot commands")
        try:
            command = self._resolve_command(parts[0].lower())
        except CloudShellAutomationError as exc:
            return BatchDispatchOutcome(False, str(exc))
        if command not in {".bulk", ".stop", ".connect", ".delete"}:
            return BatchDispatchOutcome(False, f"{command} is not batch-approved")
        if command == ".delete" and "--yes" not in parts:
            return BatchDispatchOutcome(False, ".delete requires --yes in a batch file")
        self._batch_active = True
        self._batch_outcome = None
        try:
            self.dispatch(line, state)
            return self._batch_outcome or BatchDispatchOutcome(
                False, f"{command} did not return a batch outcome"
            )
        finally:
            self._batch_active = False

    def _record_batch_fan_out(
        self, verb: str, result: FanOutResult, skipped: dict[str, str], *, extra_failed: int = 0
    ) -> None:
        """Record the existing fan-out truth; never derive it from output text."""
        if not self._batch_active:
            return
        failed = len(result.failed) + len(skipped) + extra_failed
        self._batch_outcome = BatchDispatchOutcome(
            failed == 0,
            f"{verb}: {len(result.ok)} succeeded, {failed} failed or skipped",
        )

    def _record_batch_counts(self, verb: str, succeeded: int, expected: int, failed: int) -> None:
        if self._batch_active:
            self._batch_outcome = BatchDispatchOutcome(
                failed == 0 and succeeded == expected,
                f"{verb}: {succeeded}/{expected} succeeded, {failed} failed",
            )

    def register(
        self,
        name: str,
        handler: Callable,
        help: str = "",
        spec: Optional[CommandSpec] = None,
    ) -> None:
        """Register a CSP-specific dot command."""
        self.commands[name] = handler
        if spec is not None:
            self.specs[name] = spec
        if help:
            self._csp_help[name] = help

    def spec_for(self, cmd: str) -> Optional[CommandSpec]:
        """The grammar for `cmd`, or None while it is still hand-parsed."""
        return self.specs.get(cmd)

    def dispatch(self, line: str, state: InteractiveState) -> bool:
        """Dispatch a command line. Returns True to continue, False to exit."""
        token = begin_operation(_operation_label(line, self._resolve_command))
        try:
            return self._dispatch_inner(line, state)
        finally:
            end_operation(token)

    def _dispatch_inner(self, line: str, state: InteractiveState) -> bool:


        if (line or "").strip():
            log(f"[cmd] {line.strip()}")


        pending = pending_confirm_pair(state)
        if pending is not None:
            state.pending_confirm = None
            prompt, on_yes = pending
            answer = (line or "").strip().lower()
            if answer in CONFIRM_YES:
                return self.dispatch(on_yes, state)
            out(f"{prompt}: cancelled")
            if answer in CONFIRM_NO:
                return True


            return self.dispatch(line, state)

        parts = shlex.split(line) if line else []
        if not parts:
            return True

        raw_cmd = parts[0].lower()


        try:
            cmd = self._resolve_command(raw_cmd)
        except CloudShellAutomationError as e:
            eprint(str(e))
            return True

        args = parts[1:]


        handler = self.commands.get(cmd)
        if handler:
            spec = self.specs.get(cmd)
            try:
                if spec is not None:


                    result = parse(spec, line)
                    if not result.ok:
                        eprint(result.error)
                        eprint(usage(spec))


                        for note in (spec.notes or "").splitlines():
                            if note.strip():
                                eprint("  " + note.strip())
                        return True
                    return handler(result, state)
                return handler(args, state)
            except Exception as e:
                eprint(f"Error: {e}")
                return True
        else:
            eprint(f"Unknown command: {cmd}. Type .help for help.")
            return True

    def _resolve_command(self, cmd: str) -> str:
        """Resolve abbreviated commands."""
        if not cmd.startswith("."):
            return cmd


        if cmd in self.commands:
            return cmd


        matches = [c for c in self.commands if c.startswith(cmd)]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            raise CloudShellAutomationError(
                f"Ambiguous command {cmd!r}; matches: {', '.join(matches)}"
            )
        return cmd


    def _cmd_help(self, r: "ParseResult", state: InteractiveState) -> bool:
        """Show help -- the terse listing, or one command in full."""
        out("\n".join(self.help_lines(state, topic=r.positionals.get("cmd", ""))))
        return True

    def command_help_lines(self, topic: str) -> list[str]:
        """Tier two (ITEMS #75): ONE command, in full, and nothing else."""
        name = topic.strip()
        if not name:
            return []


        reserved = name.lstrip(".").lower()
        if reserved in _HELP_TOPICS:
            return [_HELP_TOPIC_TITLES[reserved], ""] + _HELP_TOPICS[reserved]()
        if not name.startswith("."):
            name = "." + name
        try:
            resolved = self._resolve_command(name)
        except CloudShellAutomationError as exc:


            return [str(exc)]


        if resolved not in self.commands:
            return [f"No such command: {topic}. Run .help for the list."]
        if resolved not in self.specs:
            return [f"{resolved} has no grammar to describe yet."]


        if getattr(self.specs[resolved], "hidden", False):
            return [f"{resolved} is undocumented in this release."]
        return [f"{resolved}:", *_spec_help_lines(self, resolved)]

    def full_help_lines(self, state: InteractiveState) -> list[str]:
        """EVERY help surface, in order, with dividers and titles (`#389`)."""
        out: list[str] = list(self.help_lines(state))
        for topic in _HELP_SECTION_ORDER:
            out += ["", _HELP_DIVIDER, "", _HELP_TOPIC_TITLES[topic], ""]
            out += list(_HELP_TOPICS[topic]())
        return out

    def help_lines(self, state: InteractiveState, topic: str = "") -> list[str]:
        """The `.help` text, as lines, without printing it."""
        from ..branding import get_app_name


        if topic.strip():
            return self.command_help_lines(topic)

        multi_node = bool(getattr(getattr(state, "args", None), "multi_node", False))


        _SHARED_SELECTOR = "selector: selected | ALL"

        def _cmds(*names: str) -> list[str]:
            """TIER ONE IS A TWO-COLUMN TABLE: name, then one line of prose."""
            rows: list[str] = []
            for n in names:
                spec = self.specs.get(n)
                if spec is None or getattr(spec, "hidden", False):
                    continue
                rows.append("  " + n.ljust(_HELP_NAME_COLUMN) + (spec.summary or ""))
            return rows

        lines = [


            "",
            f"{get_app_name()} - Interactive Commands",
            "",


            *[
                "  " + form.ljust(_HELP_NAME_COLUMN) + blurb
                for form, blurb in [
                    (".help", "This help"),
                    (".help <command>", "Full help for one command -- arguments, notes, examples"),
                    *[(f".help {k}", v) for k, v in _HELP_TOPIC_BLURBS.items()],
                ]
            ],
            "",


            "Node lifecycle:",
            *_cmds(
                ".connect",
                ".disconnect",
                ".provision",
                ".start",
                ".stop",
                ".delete",
                ".unregister",
            ),


            " " * (_HELP_NAME_COLUMN + 2)
            + "(a session starts with ZERO registered nodes -- .provision, or",
            " " * (_HELP_NAME_COLUMN + 2) + ".enum <region> register to adopt existing ones)",
            "",
        ]

        if multi_node:
            lines += [


                "Commands:",
                *_cmds(".bulk", ".output"),
                "",


            ]

        lines += [
            "Shell / terminal:",
            *_cmds(".command", ".ls", ".upload", ".download"),
            "",
            "Session info:",


            *_cmds(".enum", ".discover", ".unmanaged", ".creds", ".state", ".history"),
            "",
            "Housekeeping:",

            *_cmds(".heartbeat", ".echo", ".sleep", ".verbose", ".ui", ".run"),
            "",
            "Job control:",
            *_cmds(".loop", ".jobs", ".fg", ".bg", ".kill"),
            "",


            "Interrupt:",
            "  "
            + "Ctrl-C".ljust(_HELP_NAME_COLUMN)
            + "Stop the running command. Nothing further is started; work "
            "already in flight is left to finish (never killed), so anything "
            "created is still recorded. Press again for what is still running",
            "",


            "Exit:",
        ]


        if multi_node:
            lines += [
                "  "
                + "exit / .exit / Ctrl-D".ljust(_HELP_NAME_COLUMN)
                + "LEAVE this pane. Side terminal hides (session stays live), "
                "command bar closes. Nothing is torn down",
                "  "
                + ".quit / Q / Ctrl-Q".ljust(_HELP_NAME_COLUMN)
                + "QUIT CloudBasher, from anywhere. Always asks first. "
                + f"Also: {quit_command_help()}",
                "  "
                + "Ctrl-C".ljust(_HELP_NAME_COLUMN)
                + "CANCEL. Clears a typed line, or stops the running command. "
                "Never exits",
            ]
        else:
            lines += [
                "  "
                + "exit / .exit".ljust(_HELP_NAME_COLUMN)
                + "Leave shell mode (in shell) or quit (at top-level)",
                "  "
                + ".quit".ljust(_HELP_NAME_COLUMN)
                + f"Quit CloudBasher. Also: {quit_command_help()}",
            ]

        csp = self.csp.name
        if csp == "aws":
            lines += [
                "",


                "AWS-specific:",


                *_cmds(".region", ".getuploadurls", ".getdownloadurls"),
            ]
        elif csp == "gcp":
            lines += [
                "",
                "GCP-specific (--gcp):",
                "  .token                     Generate/refresh access JWT for file service",
                "  .quota                     Show CloudShell weekly usage quota",
                "  .fsls [path]               List remote directory via HTTP file service",
                "  .fsupload <local> <dir>    Upload via HTTP file service",
                "  .fsdownload <remote> <local>  Download via HTTP file service",
                "  (.fs* commands use a separately-minted JWT over HTTP — no SSH",
                "   session required; .upload/.download need an active session)",
            ]
        elif csp == "azure":
            if self._csp_help:
                lines += ["", "Azure-specific (--azure):"]
                for cmd, hlp in sorted(self._csp_help.items()):
                    lines.append(f"  {cmd:<30} {hlp}")
            else:
                lines += [
                    "",
                    "Azure-specific (--azure):",
                    "  .creds [show|configure]    Show or configure Azure credentials",
                    "  .region [REGION]           Show or set Azure region",
                    "  .enum                      List Azure CloudShell console status + public IP",
                ]

        lines.append("")
        return lines

    def _cmd_command(self, r: ParseResult, state: InteractiveState) -> bool:
        """Execute command or enter shell mode. Migrated (41.4)."""
        nodes = getattr(state, "nodes_by_id", {}) or {}
        if (
            not r.rest
            and nodes
            and getattr(state, "_dispatch_node", None) is None
            and not getattr(state, "shell_node_id", None)
        ):
            eprint(
                "command: use a node terminal; "
                "global shell mode is not available in multi-node mode"
            )
            return True
        session = resolve_bound_session(self.csp, state, "command")
        if session is None:
            return True


        if not r.rest:
            detail("command: entering shell mode")
            state.in_shell_mode = True
            try:
                state.shell_prompt_info = ShellModeHandler(session).setup_prompt_info()
            except Exception as _e:
                detail(f"command: context gather failed (best-effort): {_e}")


            out("Type 'exit' or '.exit' (or press Ctrl-D) to return to command mode")
            return True


        cmd = r.rest
        detail(f"command: executing command={cmd[:80]}")
        try:
            output = session.exec_command(cmd)
            if output:
                out(output)
            log(f"[command] cmd={cmd[:80]} output_bytes={len(output or '')}")
            state.add_history(cmd)
        except Exception as e:
            eprint(f"Error executing command: {e}")
        return True

    def _cmd_upload(self, r: ParseResult, state: InteractiveState) -> bool:
        """Upload file: .upload <local> <remote>"""

        local_path = r.positionals["local_path"]
        remote_path = r.positionals["remote_path"]


        import os as _os

        if not _os.path.exists(local_path):
            eprint(f"Upload error: local file not found: {local_path}")
            return True
        if _os.path.isdir(local_path):
            eprint(f"Upload error: {local_path} is a directory, not a file")
            return True
        if r.selector:
            outcome = run_explicit_session_action(
                self.csp,
                state,
                "upload",
                r.selector,
                lambda session: session.upload_file(local_path, remote_path) or "",
            )
            if outcome is None:
                return True
            matched, labels, skipped, result, _results = outcome
            summarise_fan_out(
                "upload", "Uploaded", matched, labels, result, skipped, selector=r.selector
            )
            return True
        session = resolve_bound_session(self.csp, state, "upload")
        if session is None:
            return True
        detail(f"upload: local={local_path} remote={remote_path}")
        try:
            session.upload_file(local_path, remote_path)
            out(f"Uploaded {local_path} → {remote_path}")
            log(f"[upload] local={local_path} remote={remote_path}")
        except Exception as e:
            eprint(f"Upload error: {e}")
        return True

    def _cmd_download(self, r: ParseResult, state: InteractiveState) -> bool:
        """Download file: .download <remote> <local>"""
        remote_path = r.positionals["remote_path"]
        local_path = r.positionals["local_path"]


        import os as _os

        dest_dir = _os.path.dirname(_os.path.abspath(local_path))
        if not _os.path.isdir(dest_dir):
            eprint(f"Download error: destination directory does not exist: {dest_dir}")
            return True
        if r.selector:
            node_ids = _resolve_nodes_or_report("download", r.selector, state)
            if node_ids is None:
                return True
            if len(node_ids) != 1:
                eprint(
                    "download: selector must resolve to exactly one node "
                    "to avoid overwriting local files"
                )
                return True
            node_id = node_ids[0]
            node = (getattr(state, "nodes_by_id", {}) or {}).get(node_id)
            if node is None:
                eprint("download: selected node is no longer available")
                return True
            session, err = ensure_node_session(self.csp, state, node)
            if session is None:
                eprint(f"download: {err or 'no live session'}")
                return True
        else:
            session = resolve_bound_session(self.csp, state, "download")
            if session is None:
                return True
        detail(f"download: remote={remote_path} local={local_path}")
        try:
            session.download_file(remote_path, local_path)
            out(f"Downloaded {remote_path} → {local_path}")
            log(f"[download] remote={remote_path} local={local_path}")
        except Exception as e:
            eprint(f"Download error: {e}")
        return True

    def _cmd_bulk(self, r: ParseResult, state: InteractiveState) -> bool:
        """.bulk <selector> <command> — run a command across every node matched by <selector>."""


        selector = r.selector or ""
        command = r.rest

        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
        selected_ids = _resolve_nodes_or_report("bulk", selector, state)
        if selected_ids is None:
            return True


        matched_ids = selected_ids
        labels = _node_ref_labels(matched_ids, nodes_by_id, state.credentials_by_id)
        refs = _node_display_refs(matched_ids, nodes_by_id, state.credentials_by_id)
        ready, skipped = filter_busy_nodes(
            "bulk", matched_ids, nodes_by_id, labels, credentials_by_id=state.credentials_by_id
        )
        if not ready:
            eprint("bulk: no ready nodes in selection")
            return True

        on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)


        results: dict[str, tuple[Optional[str], Optional[int]]] = {}


        failures: dict[str, str] = {}

        def run_one(node_id: str, _ctx: FanOutContext) -> tuple[bool, list[str]]:
            """Runs on a worker thread; must not touch the widget tree (`on_node_change` is applied back on the calling thread, in the results loop below). `exit_code` is None if the exit-code marker was not found in otherwise-successful output -- never fabricated."""
            node = nodes_by_id.get(node_id)
            if node is None:
                return False, [f"bulk: {labels[node_id]}: unknown node"]
            session, err = ensure_node_session(self.csp, state, node)
            if session is None:
                return False, [f"bulk: {labels[node_id]}: {err}"]
            try:
                output, exit_code = exec_with_exit_code(session, command)


                node.mark_activity()
                results[node_id] = (output, exit_code)
                return True, []
            except CaptureUntrusted as untrusted:


                node.mark_activity()
                failures[node_id] = untrusted.reason
                return False, [f"bulk: {labels[node_id]}: {untrusted.reason}"]
            except Exception as e:


                if was_cancelled(e):
                    raise
                failures[node_id] = f"error: {e}"
                return False, [f"bulk: {labels[node_id]}: error: {e}"]


        result = fan_out_over_nodes("bulk", ready, labels, run_one, state, refresh=False)

        for node_id in result.ok:
            raw_output, exit_code = results.get(node_id, (None, None))
            node = nodes_by_id.get(node_id)


            masked = mask_secrets((raw_output or "").lstrip("\r\n"))
            if node is not None:
                node.record_command_result(masked, exit_code)
                on_node_change(node)


            timeline_mark(
                "cmd.bulk.result",
                node=node_id,
                exit_code=exit_code,
                argv0=(command.split() or [""])[0],
                region=getattr(node, "region", "") if node is not None else "",
            )
            preview = masked.splitlines()[0] if masked else ""


            out(f"[{refs[node_id]}] {preview}")


        _cancelled = set(result.cancelled)
        for node_id in (nid for nid in result.failed if nid not in _cancelled):
            node = nodes_by_id.get(node_id)
            if node is None:
                continue
            node.record_command_failure(failures.get(node_id, "the node did not report a result"))
            on_node_change(node)


        summarise_fan_out(
            "bulk", "Bulk applied", len(matched_ids), labels, result, skipped, selector=selector
        )
        bad_exit_codes = sum(
            exit_code is None or exit_code != 0
            for _node_id, (_output, exit_code) in results.items()
        )
        self._record_batch_fan_out("bulk", result, skipped, extra_failed=bad_exit_codes)
        log(f"[bulk] command={command!r} selected={matched_ids} succeeded={len(result.ok)}")
        return True

    def _cmd_output(self, r: ParseResult, state: InteractiveState) -> bool:
        """.output <selector> -- full text of the last ``.bulk`` output for every node matched by <selector>; the table's Cmd Out column shows only a truncated preview. Same selector grammar as ``.bulk``."""
        selector = r.selector or ""

        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
        node_ids = _resolve_nodes_or_report("output", selector, state)
        if node_ids is None:
            return True


        refs = _node_display_refs(node_ids, nodes_by_id, state.credentials_by_id)
        for node_id in node_ids:
            self._output_one(node_id, nodes_by_id, refs)
        return True

    def _output_one(self, node_id: str, nodes_by_id: dict, refs: Dict[str, str]) -> None:
        node = nodes_by_id.get(node_id)
        ref = refs.get(node_id, node_id)
        if node is None:
            eprint(f"output: unknown node {node_id!r}")
            return


        text = node.last_command_summary()
        if not text:
            out(f"[{ref}] no command output yet — run .bulk first")
            return
        out(f"--- {ref} ---")
        out(text)

    def _cmd_deregister(self, r: ParseResult, state: InteractiveState) -> bool:
        """.unregister <selector> (aliases: .deregister, .forget) -- drop matched nodes from the Nodes table and registry, stopping each node's heartbeat and closing its live session, WITHOUT touching the underlying cloud resource."""
        selector = r.selector or ""

        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}


        selected_node_ids = getattr(state, "selected_node_ids", None) or set()
        node_ids = _resolve_nodes_or_report("unregister", selector, state)
        if node_ids is None:
            return True
        labels = _node_ref_labels(node_ids, nodes_by_id, state.credentials_by_id)


        matched_ids = node_ids
        ready, skipped = filter_busy_nodes(
            "unregister",
            matched_ids,
            nodes_by_id,
            labels,
            credentials_by_id=state.credentials_by_id,
            guard=Guard.CONTAINER,
        )

        def _unregister_one(node_id: str, _ctx: FanOutContext) -> tuple[bool, list[str]]:
            """The TEARDOWN only. The registry mutation is NOT here."""
            node = nodes_by_id[node_id]
            disconnect_node(node)


            close_parked_browser(node)
            return True, []

        result = fan_out_over_nodes("unregister", ready, labels, _unregister_one, state)


        last_node = None
        dropped = []
        for node_id in result.ok:
            last_node = nodes_by_id.get(node_id)
            if last_node is not None:
                dropped.append(last_node)
            state.nodes_by_id.pop(node_id, None)
            selected_node_ids.discard(node_id)
            if getattr(state, "active_node_id", None) == node_id:
                state.active_node_id = None


        note = getattr(getattr(state, "csp_provider", None), "note_unregistered", None)
        if note is not None and dropped:
            note(state, dropped)

        if last_node is not None:


            on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)
            on_node_change(last_node)
        summarise_fan_out(
            "unregister",
            "Unregistered",
            len(matched_ids),
            labels,
            result,
            skipped,
            selector=selector,
        )
        return True

    def _cmd_delete(self, r: ParseResult, state: InteractiveState) -> bool:
        """.delete <selector> [--yes] [--force] — 4s (4z harness prerequisite): permanently delete matched nodes' underlying cloud environments, then drop them from the registry (equivalent to .deregister, but for real this time -- .deregister deliberately never touches the cloud resource, see its own docstring). AWS permanently deletes environments; Azure resets its console and userSettings while retaining backing storage; unsupported providers report a per-node failure. Mixed-CSP selections are confirmed once and dispatched through each provider's existing behavior. Irreversible -- there is still no *blocking* interactive prompt, matching every other dot-command's non-interactive contract (this must also work from .run batch scripts, including the 4z test harness's own teardown step). Instead, a selector resolving to more than one node is bounced once with its blast radius listed, and offering that same selector again is the confirmation -- so the interactive gesture is arm-then-confirm (the TUI's `d` key pre-arms, making its Enter the confirm), with no --yes token to type by hand. --yes still short-circuits the confirm for batch scripts, keeping this usable from .run. A selector matching exactly one node proceeds unconfirmed regardless of how it was spelled (the gate is on actual blast radius, not on whether the selector happens to say "ALL"). .deregister intentionally keeps its own zero-friction UX -- it's reversible, local-only bookkeeping, unlike this. Same selector grammar as .bulk/.output/ .deregister."""


        confirmed = "yes" in r.flags
        forced = "force" in r.flags
        selector = r.selector or ""

        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
        node_ids = _resolve_nodes_or_report("delete", selector, state)
        if node_ids is None:
            return True
        if reject_invalid_node_credentials(state, node_ids, "delete"):
            return True
        labels = _node_ref_labels(node_ids, nodes_by_id, state.credentials_by_id)


        providers = {
            getattr(state.credentials_by_id.get(nodes_by_id[nid].credential_id), "provider", None)
            for nid in node_ids
            if nid in nodes_by_id
        }


        if "azure" in providers and forced:
            eprint("delete: --force has no Azure reset meaning; no action was taken.")
            return True

        if len(providers) == 1 and providers == {"azure"}:
            from cloudbasher.csp.azure.commands import cmd_delete as azure_delete

            result = azure_delete(r, state)
            if self._batch_active:
                succeeded = sum(nid not in nodes_by_id for nid in node_ids)
                self._record_batch_counts(
                    "delete", succeeded, len(node_ids), len(node_ids) - succeeded
                )
            return result

        provider_names = {name for name in providers if isinstance(name, str)}
        dispatcher_provider = getattr(self.csp, "name", None)
        if provider_names and (
            len(provider_names) > 1 or provider_names != {dispatcher_provider}
        ):
            armed = getattr(state, "delete_armed_selector", None)
            if len(node_ids) > 1 and not confirmed and armed != selector:
                eprint(
                    f"delete: selector {selector!r} matches {len(node_ids)} node(s): "
                    f"{', '.join(labels[nid] for nid in node_ids)}"
                )
                question = f"delete {selector} [Y/n]"
                again = f".delete {selector} --yes" + (" --force" if forced else "")
                state.pending_confirm = (question, again)
                return True

            state.delete_armed_selector = None
            provider_types = {
                "aws": None,
                "azure": None,
                "gcp": None,
            }
            for name in sorted(provider_names):
                if name == dispatcher_provider:
                    provider_types[name] = self.csp
                elif name == "aws":
                    from cloudbasher.csp.aws.provider import AWSProvider

                    provider_types[name] = AWSProvider()
                elif name == "azure":
                    from cloudbasher.csp.azure.provider import AzureProvider

                    provider_types[name] = AzureProvider()
                elif name == "gcp":
                    from cloudbasher.csp.gcp.provider import GCPProvider

                    provider_types[name] = GCPProvider()

            grouped: dict[str, set[str]] = {name: set() for name in sorted(provider_names)}
            unclassified: set[str] = set()
            for node_id in node_ids:
                node = nodes_by_id.get(node_id)
                credential = state.credentials_by_id.get(node.credential_id) if node else None
                provider_name = getattr(credential, "provider", None)
                if provider_name in grouped:
                    grouped[provider_name].add(node_id)
                else:
                    unclassified.add(node_id)

            deleted: list[str] = []
            failed: list[str] = list(unclassified)
            if unclassified:
                eprint(
                    "delete: cannot resolve the credential provider for "
                    f"{', '.join(labels[nid] for nid in node_ids if nid in unclassified)}; "
                    "no action was taken for those nodes."
                )
            from cloudbasher.csp.azure.commands import cmd_delete as azure_delete

            for name, ids in grouped.items():
                if not ids:
                    continue
                provider = provider_types.get(name)
                if name == "azure":
                    azure_delete(
                        r,
                        state,
                        node_ids=ids,
                        emit_summary=False,
                        confirmed=confirmed or armed == selector,
                    )
                    deleted.extend(node_id for node_id in ids if node_id not in state.nodes_by_id)
                    failed.extend(node_id for node_id in ids if node_id in state.nodes_by_id)
                elif provider is None:
                    failed.extend(ids)
                    eprint(
                        f"delete: unsupported cloud provider {name!r}; "
                        "no action taken for its nodes."
                    )
                else:
                    provider_deleted, provider_failed = delete_nodes(
                        provider, state, ids, force=forced
                    )
                    deleted.extend(provider_deleted)
                    failed.extend(provider_failed)

            deleted = [node_id for node_id in node_ids if node_id in set(deleted)]
            failed = [node_id for node_id in node_ids if node_id in set(failed)]
            summary = f"Deleted {len(deleted)}/{len(node_ids)} node(s)"
            out(f"{summary}: {', '.join(labels[nid] for nid in deleted)}")
            if failed:
                eprint(f"Failed: {', '.join(labels[nid] for nid in failed)}")
            state.last_node_action_message = (
                summary if not failed else f"{summary} · {len(failed)} failed"
            )
            log(
                f"[delete] selector={selector!r} deleted="
                f"{', '.join(labels[nid] for nid in deleted)} failed={failed}"
            )
            self._record_batch_counts("delete", len(deleted), len(node_ids), len(failed))
            return True


        log(
            f"[delete] selector={selector!r} matched={len(node_ids)} "
            f"confirmed={confirmed} armed={getattr(state, 'delete_armed_selector', None)!r} "
            f"state_id={id(state):#x}"
        )

        armed = getattr(state, "delete_armed_selector", None)
        if len(node_ids) > 1 and not confirmed and armed != selector:


            eprint(
                f"delete: selector {selector!r} matches {len(node_ids)} node(s): "
                f"{', '.join(labels[nid] for nid in node_ids)}"
            )


            question = f"delete {selector} [Y/n]"


            _again = f".delete {selector} --yes" + (" --force" if forced else "")
            state.pending_confirm = (question, _again)
            return True
        state.delete_armed_selector = None

        deleted, failed = delete_nodes(self.csp, state, node_ids, force=forced)


        deleted_refs = ", ".join(labels[nid] for nid in deleted)
        summary = f"Deleted {len(deleted)}/{len(node_ids)} node(s)"
        out(f"{summary}: {deleted_refs}")
        if failed:
            eprint(f"Failed: {', '.join(labels[nid] for nid in failed)}")


        state.last_node_action_message = (
            summary if not failed else f"{summary} · {len(failed)} failed"
        )
        log(f"[delete] selector={selector!r} deleted={deleted_refs} failed={failed}")
        self._record_batch_counts("delete", len(deleted), len(node_ids), len(failed))
        return True

    def _cmd_disconnect(self, r: ParseResult, state: InteractiveState) -> bool:
        """.disconnect <selector> — close each matched node's live WebSocket session and stop its heartbeat, without touching container_status, without deregistering, and without any CSP API call. The connection axis (core/tui/widgets/node_table.py's _connection_state()) is purely derived from _runtime_session, so once this closes it the Nodes table shows "Disconnected" on its own -- there's no separate flag to flip here. The atomic counterpart to .connect. Same selector grammar as .bulk/.output/.deregister/.delete."""
        selector = r.selector or ""

        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
        node_ids = _resolve_nodes_or_report("disconnect", selector, state)
        if node_ids is None:
            return True
        labels = _node_ref_labels(node_ids, nodes_by_id, state.credentials_by_id)


        matched_ids = node_ids
        ready, skipped = filter_busy_nodes(
            "disconnect",
            matched_ids,
            nodes_by_id,
            labels,
            credentials_by_id=state.credentials_by_id,
            guard=Guard.SUSPENDING,
        )

        def _disconnect_one(node_id: str, _ctx: FanOutContext) -> tuple[bool, list[str]]:
            node = nodes_by_id[node_id]


            _park_browser_for_reuse(
                node,
                f"disconnect: {labels[node_id]}",
                "the WebSocket is dropped, the console session " "is not",
                shell_survives=True,
            )
            disconnect_node(node)
            return True, []


        result = fan_out_over_nodes("disconnect", ready, labels, _disconnect_one, state)
        summarise_fan_out(
            "disconnect",
            "Disconnected",
            len(matched_ids),
            labels,
            result,
            skipped,
            selector=selector,
        )
        return True

    def _cmd_connect(self, r: ParseResult, state: InteractiveState) -> bool:
        """.connect <selector> — bring each matched node's WebSocket session live, concurrently. Promotes ensure_node_session()'s existing reconnect-on-demand behavior (previously only reachable indirectly via .bulk) to a standalone command -- the atomic counterpart to .disconnect. Each node's _connecting flag flips True and is broadcast immediately, before this node's own reconnect starts (not just after), so the Nodes table shows "Connecting" for the full duration of a possibly-slow handshake rather than only at the end."""
        selector = r.selector or ""

        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
        node_ids = _resolve_nodes_or_report("connect", selector, state)
        if node_ids is None:
            return True
        if reject_invalid_node_credentials(state, node_ids, "connect"):
            return True


        labels = _node_ref_labels(node_ids, nodes_by_id, state.credentials_by_id)

        on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)


        nodes, skipped = filter_busy_nodes(
            "connect",
            node_ids,
            nodes_by_id,
            labels,
            credentials_by_id=state.credentials_by_id,
            guard=Guard.BUSY,
        )
        if not nodes:
            eprint("connect: no connectable nodes in selection")
            return True


        for node in nodes.values():
            begin_node_activity(state, node, connecting=True, working=False)

        def _settle_after_connect(node: NodeRecord, *, rolled_back: bool) -> None:
            """Release `.connect`'s claim on one node. `#735`."""
            del rolled_back
            end_node_activity(state, node, connecting=True, working=False, publish=False)

        def _connect_one(node_id: str, _ctx: FanOutContext) -> tuple[bool, list[str]]:
            node = nodes[node_id]


            timeline_mark("cmd.connect.begin", node=node_id, region=node.region)
            _session, conn_err = ensure_node_session(self.csp, state, node)
            timeline_mark("cmd.connect.end", node=node_id, region=node.region, ok=conn_err is None)
            if conn_err is not None:


                _settle_after_connect(node, rolled_back=True)
                return False, [f"connect: {labels[node_id]}: {conn_err}"]
            return True, []


        result = fan_out_over_nodes("connect", nodes, labels, _connect_one, state, refresh=True)


        for node_id in nodes:
            node = nodes[node_id]
            _settle_after_connect(node, rolled_back=node_id in result.failed)
            on_node_change(node)

        summarise_fan_out(
            "connect",
            "Connected",
            len(node_ids),
            labels,
            result,
            skipped,
            selector=selector,
        )
        self._record_batch_fan_out("connect", result, skipped)
        return True

    def _cmd_start(self, r: ParseResult, state: InteractiveState) -> bool:
        """.start <selector> — resume each matched node's underlying environment (Suspended/Stopped -> Running). CSP-generic (SupportsEnvironmentLifecycle is satisfied by AWS and GCP -- see csp/base.py), so this lives in the shared dispatcher rather than an AWS-only register_dot_commands() module, unlike .register (AWS's 1:N region model has no GCP/Azure equivalent). Sets container_status from real, freshly observed getEnvironmentStatus calls -- never hardcoded to "Running" -- via the shared _AWS_STATUS_MAP. _poll_until_status() holds the node on "Transitioning" and re-checks a few times (env-status poll interval) rather than trusting a single snapshot taken right after calling start_environment(): starting is asynchronous, so that one snapshot almost always still reads the pre-start value (live-testing bug -- the row looked stuck until an unrelated .connect happened to overwrite it via ensure_node_session()'s own status write). Does not touch connection liveness at all. Same selector grammar as .bulk/.output/.deregister/.delete."""
        selector = r.selector or ""

        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
        node_ids = _resolve_nodes_or_report("start", selector, state)
        if node_ids is None:
            return True
        if reject_invalid_node_credentials(state, node_ids, "start"):
            return True
        labels = _node_ref_labels(node_ids, nodes_by_id, state.credentials_by_id)

        on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)

        def _start_one(node_id: str, ctx: FanOutContext) -> tuple[bool, list[str]]:
            """Start one node. Returns (started?, lines for stderr)."""
            node = nodes_by_id[node_id]
            api_client, err = ensure_node_api_client(self.csp, state, node)
            if err:
                return False, [f"start: {labels[node_id]}: {err}"]
            if not isinstance(api_client, SupportsEnvironmentLifecycle):
                return (
                    False,
                    [f"start: {labels[node_id]}: this CSP doesn't support environment start"],
                )
            if not node.environment_id:
                return False, [f"start: {labels[node_id]}: no environment_id on record"]
            try:
                timeline_mark("cmd.start.begin", node=node_id, region=node.region)
                api_client.start_environment(node.environment_id)
                mapped_status = _poll_until_status(
                    api_client,
                    node,
                    node.environment_id,
                    "Running",
                    on_node_change,
                    concurrency=ctx.workers,
                )
                timeline_mark("cmd.start.end", node=node_id, region=node.region)
            except Exception as e:
                return False, [f"start: {labels[node_id]}: {e}"]
            warnings: list[str] = []
            if mapped_status in _TERMINAL_FAILURE_STATUSES:
                warnings.append(
                    f"start: {labels[node_id]}: entered {mapped_status!r} while starting"
                )
            elif mapped_status != "Running":
                warnings.append(
                    f"start: {labels[node_id]}: still {mapped_status!r} after "
                    f"{_STATUS_SETTLE_TIMEOUT_SECONDS:.0f}s -- it may finish starting shortly"
                )


            node.mark_activity()
            return True, warnings


        ready, skipped = filter_busy_nodes(
            "start",
            node_ids,
            nodes_by_id,
            labels,
            credentials_by_id=state.credentials_by_id,
            guard=Guard.BUILD,
        )
        result = fan_out_over_nodes(
            "start",
            ready,
            labels,
            _start_one,
            state,


            refresh=True,
        )
        summarise_fan_out(
            "start",
            "Started",
            len(node_ids),
            labels,
            result,
            skipped,
            selector=selector,
        )
        return True

    def _cmd_stop(self, r: ParseResult, state: InteractiveState) -> bool:
        """.stop <selector> -- suspend each matched node's underlying environment (Running -> Suspended); the counterpart to ``.start``."""
        selector = r.selector or ""

        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}
        node_ids = _resolve_nodes_or_report("stop", selector, state)
        if node_ids is None:
            return True
        if reject_invalid_node_credentials(state, node_ids, "stop"):
            return True
        labels = _node_ref_labels(node_ids, nodes_by_id, state.credentials_by_id)

        on_node_change = getattr(state, "on_node_change", None) or (lambda _n: None)

        def _stop_one(node_id: str, ctx: FanOutContext) -> tuple[bool, list[str]]:
            """Stop one node. Returns (stopped?, lines for stderr)."""
            node = nodes_by_id[node_id]
            credential = (getattr(state, "credentials_by_id", None) or {}).get(node.credential_id)
            credential_provider = getattr(credential, "provider", None)
            if credential_provider in {"azure", "gcp"}:
                cloud_shell = (
                    "Azure Cloud Shell"
                    if credential_provider == "azure"
                    else "GCP Cloud Shell"
                )
                return False, [
                    f"stop: {labels[node_id]}: warning: {cloud_shell} has no "
                    "stop/suspend operation; no action taken"
                ]
            api_client, err = ensure_node_api_client(self.csp, state, node)
            if err:
                return False, [f"stop: {labels[node_id]}: {err}"]
            if not isinstance(api_client, SupportsEnvironmentSuspension):
                return (
                    False,
                    [f"stop: {labels[node_id]}: this CSP doesn't support environment stop"],
                )
            if not node.environment_id:
                return False, [f"stop: {labels[node_id]}: no environment_id on record"]
            try:


                timeline_mark("cmd.stop.begin", node=node_id, region=node.region)


                node.retire_server_sessions()
                api_client.stop_environment(node.environment_id)


                node._disconnecting = True
                on_node_change(node)


                mapped_status = _poll_until_status(
                    api_client,
                    node,
                    node.environment_id,
                    "Suspended",
                    on_node_change,


                    settled_raw=("SUSPENDED", "STOPPED"),
                    concurrency=ctx.workers,
                )


                _park_browser_for_reuse(
                    node,
                    f"stop: {labels[node_id]}",
                    "the environment is suspended, the console " "session is not",
                    shell_survives=False,
                )
                disconnect_node(node)


                on_node_change(node)
                timeline_mark("cmd.stop.end", node=node_id, region=node.region)
            except Exception as e:


                node._disconnecting = False
                on_node_change(node)
                return False, [f"stop: {labels[node_id]}: {e}"]
            warnings: list[str] = []
            if mapped_status in _TERMINAL_FAILURE_STATUSES:
                warnings.append(
                    f"stop: {labels[node_id]}: entered {mapped_status!r} while stopping"
                )
            elif mapped_status != "Suspended":
                warnings.append(
                    f"stop: {labels[node_id]}: still {mapped_status!r} after "
                    f"{_STATUS_SETTLE_TIMEOUT_SECONDS:.0f}s -- it may finish stopping shortly"
                )
            node.mark_activity()
            return True, warnings


        ready, skipped = filter_busy_nodes(
            "stop",
            node_ids,
            nodes_by_id,
            labels,
            credentials_by_id=state.credentials_by_id,
            guard=Guard.BUILD,
        )
        result = fan_out_over_nodes(
            "stop",
            ready,
            labels,
            _stop_one,
            state,


            refresh=True,
        )
        summarise_fan_out(
            "stop",
            "Stopped",
            len(node_ids),
            labels,
            result,
            skipped,
            selector=selector,
        )
        self._record_batch_fan_out("stop", result, skipped)
        return True

    def _cmd_enum(self, _r: "ParseResult", state: InteractiveState) -> bool:
        """List CloudShell environments. **Non-AWS only.**"""
        api = getattr(state, "api_client", None)
        if api is None:
            eprint("No API client available (run with a CSP flag to connect first)")
            return True


        try:
            env = api.get_environment()
            _fields = [
                ("ssh_host", env.get("ssh_host", "")),
                ("ssh_port", env.get("ssh_port", "")),
                ("ssh_username", env.get("ssh_username", "")),
                ("web_host", env.get("web_host", "")),
                ("docker_image", env.get("docker_image", "")),
            ]
            _kw = max(len(k) for k, _ in _fields)
            meta = "\n".join(f"{k:<{_kw}}: {v}" for k, v in _fields)
            out(
                _fmt_table(
                    ["Name", "Metadata", "Status"],
                    [[env.get("name", ""), meta, env.get("state", "")]],
                    max_width=_get_term_width(),
                )
            )
            log(f"[enum] csp={self.csp.name}")
        except Exception as e:
            eprint(f"Error: {e}")
        return True

    def _cmd_creds(self, r: ParseResult, state: InteractiveState) -> bool:
        """Show credentials. The active single-node credential's Provider/ Email lines are unchanged from before this method grew multi-node awareness. Additionally, for each AWS permanent/originating identity in state.credentials_by_id (the multi-node registry) -- the only shape that has a 1:N region relationship worth surfacing, unlike GCP/Azure's 1:1 model or an AWS target/derived identity, which has no regions or further derivations of its own -- prints a capability line: how many of AWS's known regions are already registered vs. still provisionable, and how many federation/ assume-role identities have already been derived from it. Reuses data already computed elsewhere (resolve_credential_display()'s parent-walk, csp.aws.multi_region's region catalog) rather than a new aggregation pass."""


        args = [r.selector] if r.selector else []
        extra = r.sub.rest.split() if r.sub is not None and r.sub.rest else []
        if r.selector and r.verb is None:


            eprint(f".creds: unknown subcommand {r.selector!r}")
            eprint(usage(r.spec))
            return True
        if r.verb == "perms":
            return self._cmd_creds_perms(args, state, extra=extra)
        if r.verb == "refresh":


            handler = getattr(self.csp, "refresh_credential", None)
            if handler is None:
                eprint(
                    f".creds refresh is not supported for {self.csp.name} -- "
                    "it re-derives an AWS ACT_AS=role/federated credential."
                )
                return True
            return handler(args, state, extra=extra)


        if r.sub is not None and r.sub.rest:
            eprint(f".creds show takes no arguments (got {r.sub.rest!r})")
            return True

        if state.credentials is None:
            eprint("No credentials loaded")
            return True
        out(f"Provider: {state.credentials.provider}")
        out(f"Email: {state.credentials.email or 'N/A'}")

        credentials_by_id = getattr(state, "credentials_by_id", None) or {}
        if not credentials_by_id:
            return True


        from cloudbasher.core.identity_listing import (
            build_identity_rows,
            emit_identity_rows,
        )


        rows = build_identity_rows(
            credentials_by_id, nodes_by_id=getattr(state, "nodes_by_id", None) or {}
        )
        if rows:
            out("Identities loaded:")
            emit_identity_rows(rows, emit=out, detail=detail)
        return True


    PERMS_CONFIRM_THRESHOLD = 10

    def _cmd_creds_perms(
        self, args: list[str], state: InteractiveState, *, extra: Optional[list[str]] = None
    ) -> bool:
        """`.creds <cred#>|selected|ALL perms` -- what may these credentials do."""
        credentials_by_id = getattr(state, "credentials_by_id", None) or {}
        if not credentials_by_id:
            eprint(".creds perms: no credentials are loaded.")
            return True


        extra_arns: list[str] = []
        rest = list(extra or [])
        while rest:
            token = rest.pop(0)
            if token.lower() == "role" and rest:
                extra_arns.append(rest.pop(0))
            elif token.startswith("arn:"):
                extra_arns.append(token)
            else:
                eprint(
                    f".creds perms: unexpected argument {token!r} -- after `perms` "
                    "the only extra is a role to probe (`role <arn>` or a bare "
                    "`arn:...`)."
                )
                return True

        selector = (args[0].strip() if args else "").lower()
        if not selector:


            from cloudbasher.core.selection import implicit_credential_records

            if implicit_credential_records(state, provider="aws"):
                selector = "selected"
            elif getattr(state, "cursor_credential_id", None):
                selector = "cursor"
            else:
                eprint(
                    ".creds perms needs to know WHICH credential: " ".creds <ID>|selected|ALL perms"
                )
                return True

        from cloudbasher.core.types import numbered_originating_records

        numbered = list(numbered_originating_records(credentials_by_id))
        if selector == "all":
            chosen = [rec for _n, rec in numbered]
        elif selector == "cursor":
            cursor_id = getattr(state, "cursor_credential_id", None)
            chosen = [rec for _n, rec in numbered if rec.id == cursor_id]
        elif selector == "selected":
            chosen = self._records_behind_selection(state, numbered)
            if not chosen:
                eprint(
                    ".creds perms: nothing is selected. Tick a row, or name a " "credential number."
                )
                return True
        else:


            from cloudbasher.core.selection import resolve_numbered_selector

            picked, unknown, malformed = resolve_numbered_selector(numbered, selector)
            if malformed:
                eprint(
                    f".creds perms: {args[0]!r} is not a credential selector. "
                    "Use a number from the listing, `1,3,5`, `selected`, or `ALL`."
                )
                return True
            if unknown:
                eprint(
                    f".creds perms: no credential {', '.join(unknown)} -- the listing "
                    f"numbers 1..{len(numbered)}."
                )
                return True
            chosen = [rec for _n, rec in picked]


        if len(chosen) > self.PERMS_CONFIRM_THRESHOLD:
            out(
                f".creds perms: this probes {len(chosen)} credentials with "
                f"{len(chosen) * 2} live STS calls. Continue? [y/N] "
            )
            try:
                answer = input().strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = ""
            if answer not in ("y", "yes"):
                out("Cancelled.")
                return True

        prober = getattr(self.csp, "probe_permissions", None)
        if prober is None:
            eprint(
                f".creds perms: permission probing is not implemented for "
                f"{getattr(self.csp, 'name', 'this provider')}."
            )
            return True


        api_probes = self._control_plane_probe_names()

        headers = ["#", "credential", "action", "verdict", "detail"]
        table_rows: list[list[str]] = []
        by_id = {rec.id: n for n, rec in numbered}
        for rec in chosen:
            try:
                verdicts = prober(rec, extra_arns=extra_arns)
            except Exception as exc:
                verdicts = [("(probe failed)", "error", str(exc).replace("\n", " ")[:120])]
            verdicts = list(verdicts) + self._probe_control_plane(rec, api_probes)
            for action, verdict, why in verdicts:
                table_rows.append(
                    [str(by_id.get(rec.id, "-")), rec.label or rec.id, action, verdict, why]
                )
        if not table_rows:
            out("No probes ran.")
            return True
        out(_fmt_table(headers, table_rows, max_width=_get_term_width()))
        return True

    def _control_plane_probe_names(self) -> list[tuple[str, str]]:
        """The control-plane calls `.perms` probes. **READ-ONLY, all of them.**"""
        if self.csp.name == "aws":
            return [("describe_environments", "POST /describeEnvironments")]
        return [("get_environment", "GET /v1/users/me/environments/default")]

    @staticmethod
    def _classify_probe_failure(exc: Exception) -> tuple[str, str]:
        """Delegates to `csp.aws.failure.probe_verdict`, which owns the words."""
        from cloudbasher.csp.aws.failure import probe_verdict

        return probe_verdict(exc)

    def _browser_only_credential(self, rec: Any) -> Optional[str]:
        """Why this record's control plane is not probeable without a browser."""
        if self.csp.name != "aws":
            return None
        try:
            from cloudbasher.csp.aws.commands import browser_credential_shape
        except Exception:
            return None
        extra = getattr(getattr(rec, "raw", None), "extra", None) or {}
        if browser_credential_shape(extra) is None:
            return None
        return (
            "console/SSO: signed by an in-browser presign oracle, and not a "
            "Path B step (design-aws.md:967) -- needs a browser login"
        )

    def _probe_control_plane(self, rec: Any, probes: list) -> list[tuple[str, str, str]]:
        """Can THIS record call the control plane?"""
        browser_only = self._browser_only_credential(rec)
        if browser_only is not None:


            return [(name, "n/a", f"{endpoint} — {browser_only}") for name, endpoint in probes]
        try:
            api = self.csp.create_api_client(rec.raw)
        except Exception as exc:
            return [("(api client)", "error", str(exc).replace("\n", " ")[:120])]
        rows: list[tuple[str, str, str]] = []
        for name, endpoint in probes:
            method = getattr(api, name, None)
            if method is None:
                rows.append((name, "n/a", f"{endpoint} — not implemented for this CSP"))
                continue
            try:
                method()
                rows.append((name, "allowed", endpoint))
            except Exception as exc:
                verdict, why = self._classify_probe_failure(exc)
                rows.append((name, verdict, f"{endpoint} — {why}"))
        return rows

    def _records_behind_selection(self, state: InteractiveState, numbered: list) -> list:
        """The originating credentials the user has ticked, by EITHER gesture."""
        from cloudbasher.core.selection import selected_credential_ids

        roots = selected_credential_ids(state)
        return [rec for _n, rec in numbered if rec.id in roots]

    def _cmd_state(self, _r: "ParseResult", state: InteractiveState) -> bool:
        """Show session state."""
        out(f"Provider : {self.csp.name}")
        out(f"UI mode  : {state.ui_mode}")
        if state.credentials:
            out(f"Creds    : {state.credentials.provider} / {state.credentials.email or 'N/A'}")
        if state.session:
            s = state.session
            out(f"Env ID   : {s.environment_id or 'N/A'}")
            out(f"Region   : {s.region or 'N/A'}")
            out(f"User     : {s.user or 'N/A'}")
            out(f"Host     : {s.hostname or 'N/A'}")
            out(f"IP       : {s.ip_address or 'N/A'}")
        return True

    def _cmd_history(self, _r: "ParseResult", state: InteractiveState) -> bool:
        """Show command history."""
        history = state.get_history()
        if not history:
            out("No history")
            return True
        for i, cmd in enumerate(history, 1):
            out(f"  {i:4d}  {cmd}")
        return True


    @staticmethod
    def _layer_state(node: Any, layer: int, live: list[str]) -> str:
        """`on`, `-` (policy excludes it) or `DEAD` (policy wants it, nothing runs)."""
        from ..session.keepalive_policy import layer_loop_name, runs_layer

        if not runs_layer(node, layer):
            return "-"


        return "on" if layer_loop_name(layer) in live else "DEAD"

    def _cmd_heartbeat(self, r: "ParseResult", state: InteractiveState) -> bool:
        """`.heartbeat [<sel>] [session|container|native|off|now]` (`#601`)."""
        from ..session.keepalive_policy import KEEPALIVE_POLICIES

        action = (r.verb or "").lower()
        selector = r.selector or ""
        nodes_by_id = getattr(state, "nodes_by_id", {}) or {}

        if not selector and not action:
            node_ids = set(nodes_by_id)
            if not node_ids:


                eprint("heartbeat: no active node -- provision or connect one first")
                return True
        else:
            resolved = _resolve_nodes_or_report("heartbeat", selector, state)
            if resolved is None:
                return True
            node_ids = resolved


        ordered = [nodes_by_id[nid] for nid in node_ids]

        if action in KEEPALIVE_POLICIES:
            return self._heartbeat_set_policy(ordered, state, action)
        if action == "now":
            return self._heartbeat_beat_now(ordered, state)
        return self._heartbeat_show(ordered)

    def _heartbeat_show(self, nodes: list[Any]) -> bool:
        """Policy plus live layer state, one row per node."""
        from ..session.keepalive_policy import policy_of

        head = f"{'Node':>5}  {'Policy':<10}" + "".join(
            f"  {label:>6}" for _layer, label, _mech in self.csp.KEEPALIVE_LAYERS
        )
        out(head)
        for node in nodes:
            live = node.live_background_loops()
            out(
                f"{getattr(node, 'seq', 0):>5}  {policy_of(node):<10}"
                + "".join(
                    f"  {self._layer_state(node, layer, live):>6}"
                    for layer, _label, _mech in self.csp.KEEPALIVE_LAYERS
                )
            )
        out(
            "layers: "
            + "  ".join(
                f"{layer} {label}={mech}" for layer, label, mech in self.csp.KEEPALIVE_LAYERS
            )
        )
        out("'-' = this policy does not run that layer.  DEAD = it should and nothing is.")
        return True

    def _heartbeat_set_policy(self, nodes: list[Any], state: InteractiveState, policy: str) -> bool:
        """Write the policy. NOTHING is started or stopped here."""
        from ..utils.output import log

        on_node_change = getattr(state, "on_node_change", None)
        for node in nodes:
            was = node.keepalive_policy or "(default)"
            node.keepalive_policy = policy
            log(f"[keepalive] policy {node.id}: {was} -> {policy}")
            if on_node_change is not None:
                try:
                    on_node_change(node)
                except Exception:


                    pass
        out(f"Keepalive policy set to {policy} on {len(nodes)} node(s).")
        return True

    def _heartbeat_beat_now(self, nodes: list[Any], state: InteractiveState) -> bool:
        """Beat every layer this node's policy arms, and say what was sent."""
        from ..utils.output import log

        by_id = {node.id: node for node in nodes}
        labels = {node.id: f"node {getattr(node, 'seq', 0)}" for node in nodes}

        def _beat_one(node_id: str, _ctx: FanOutContext) -> tuple[bool, list[str]]:
            node = by_id[node_id]
            sent, skipped = self.csp.beat_node_now(node, state)
            label = labels[node_id]
            lines = [f"{label}: sent {', '.join(sent) if sent else 'nothing'}"]
            if skipped:
                lines.append(f"{' ' * len(label)}  not sent: {'; '.join(skipped)}")
            log(f"[keepalive] .heartbeat now {node_id}: sent={sent} skipped={skipped}")
            return bool(sent), lines


        result = fan_out_over_nodes("heartbeat", by_id, labels, _beat_one, state, refresh=True)
        for node in nodes:
            for line in result.messages.get(node.id, []):
                out(line)
        return True

    def _cmd_echo(self, r: ParseResult, state: InteractiveState) -> bool:
        """Echo message. Migrated to the grammar engine (41.4)."""


        out(r.rest)
        return True

    def _cmd_sleep(self, r: "ParseResult", state: InteractiveState) -> bool:
        """Sleep."""
        _sec = r.positionals.get("seconds")
        if _sec is not None:


            import time

            time.sleep(float(_sec))
        return True

    def _cmd_clear(self, _r: "ParseResult", state: InteractiveState) -> bool:
        """Clear the terminal screen (readline). A NO-OP in the TUI -- `#354`."""
        if state.ui_mode != "tui":
            import os

            os.system("clear" if os.name != "nt" else "cls")
        return True

    def _cmd_verbose(self, r: "ParseResult", state: InteractiveState) -> bool:
        """Toggle verbose mode."""
        from ..utils.output import is_log_console_echo_enabled, set_log_console_echo

        _mode = str(r.positionals.get("mode") or "").lower()
        if _mode == "off":
            set_log_console_echo(False)
            out("Verbose mode: OFF")
        elif _mode == "on":
            set_log_console_echo(True)
            out("Verbose mode: ON")
        else:
            mode = "ON" if is_log_console_echo_enabled() else "OFF"
            out(f"Verbose mode: {mode}")
        return True

    def _cmd_ui(self, r: "ParseResult", state: InteractiveState) -> bool:
        """Switch UI mode."""
        mode = r.positionals.get("mode")
        if mode is None:
            out(f"Current mode: {state.ui_mode}")
            return True


        mode = mode.lower()
        if mode == state.ui_mode:
            out(f"Already in {mode} mode")
            return True
        state.ui_mode = mode
        out(f"Switching to {mode} mode...")

        return True

    def _cmd_quit(self, _r: "ParseResult", state: InteractiveState) -> bool:
        """Signal exit intent. The calling REPL handles confirmation."""
        return False

    def _cmd_jobs(self, _r: "ParseResult", state: InteractiveState) -> bool:
        """List background jobs."""
        if not state.jobs:
            out("No jobs")
            return True
        for jid, job in sorted(state.jobs.items()):
            if job.status == "stopped":
                status_label = "stopped"
            elif job.thread.is_alive():
                status_label = "running"
            else:
                job.status = "done"
                status_label = "done"
            out(f"  [{jid}] {status_label:8s}  {job.name}")
        return True

    def _cmd_bg(self, _r: "ParseResult", state: InteractiveState) -> bool:
        """Unsuspend a stopped job in background: .bg [job_id]"""
        eprint("bg: job suspension not yet supported (jobs run in background by default)")
        return True

    def _cmd_fg(self, r: ParseResult, state: InteractiveState) -> bool:
        """Wait for a background job: .fg <job_id>"""


        jid = int(r.positionals["job_id"])
        job = state.jobs.get(jid)
        if job is None:
            eprint(f"No such job: {jid}")
            return True
        out(f"Waiting for job [{jid}] {job.name} ...")
        try:
            job.thread.join()
        except KeyboardInterrupt:
            out(f"^C — job [{jid}] still running in background")
        return True

    def _cmd_kill(self, r: ParseResult, state: InteractiveState) -> bool:
        """Kill a background job: .kill <job_id>"""


        jid = int(r.positionals["job_id"])
        job = state.jobs.get(jid)
        if job is None:
            eprint(f"No such job: {jid}")
            return True
        job.stop_event.set()
        job.status = "stopped"
        out(f"Job [{jid}] {job.name} killed")
        log(f"[kill] job_id={jid} name={job.name!r}")
        return True

    def _cmd_run(self, r: ParseResult, state: InteractiveState) -> bool:
        """Execute a selected-node shell file, with dot commands mixed in."""


        from .batch_runner import read_batch_lines

        lines = read_batch_lines(r.rest, error_label="Cannot open file")
        if lines is None:
            return True

        log(f"[run] file={r.rest} lines={len(lines)}")
        for lineno, line in enumerate(lines, 1):
            if not line or line.startswith("#"):
                continue
            if line.startswith("."):
                if not self.dispatch(line, state):
                    return False
                continue


            session = _fresh_session_for_batch_line(state)
            if session is None:
                eprint(f"[run:{lineno}] No session for shell command: {line}")
                continue
            log(f"[run] lineno={lineno} line={line[:80]}")
            try:
                output = session.exec_command(line)
                if output:
                    out(output)
                state.add_history(line)
            except Exception as exc:
                eprint(f"[run:{lineno}] Error: {exc}")
        return True

    def _cmd_loop(self, r: ParseResult, state: InteractiveState) -> bool:
        """Run a shell command in a background loop: .loop <seconds> <command...>"""


        interval = int(r.positionals["interval_seconds"])
        cmd = r.rest


        node = getattr(state, "_dispatch_node", None)
        if node is None and getattr(state, "_session_obj", None) is None:
            eprint("No session available for loop command")
            return True

        def _current_session() -> Optional[Any]:
            """The session as it is NOW, not as it was at dispatch."""
            if node is not None:
                return getattr(node, "_runtime_session", None)
            return getattr(state, "_session_obj", None)

        import threading as _threading

        stop_event = _threading.Event()

        def _loop_worker():
            while not stop_event.is_set():
                session = _current_session()
                if session is None:
                    detail(f"[loop] cmd={cmd!r} skipped: no session on the node")
                    stop_event.wait(timeout=interval)
                    continue


                if node is not None and node_socket_is_dead(node):
                    detail(
                        f"[loop] cmd={cmd!r} skipped: socket marked dead; "
                        "the gateway rebuilds on the next user command"
                    )
                    stop_event.wait(timeout=interval)
                    continue


                activity = activity_from(session)
                if activity is not None and activity.phase == "recovering":
                    detail(f"[loop] cmd={cmd!r} skipped: shell is being rebuilt")
                    stop_event.wait(timeout=interval)
                    continue
                try:
                    output = session.exec_command(cmd, timeout=30)


                    if node is not None:
                        node.mark_real_traffic()
                    if output:
                        detail(f"[loop] cmd={cmd!r} output={output[:80]!r}")
                except Exception as e:
                    detail(f"[loop] cmd={cmd!r} error={e}")
                stop_event.wait(timeout=interval)

        thread = _threading.Thread(target=_loop_worker, daemon=True)
        thread.start()
        jid = state.add_job(f"loop: {cmd[:40]}", thread, stop_event)
        out(f"Job [{jid}] started: loop every {interval}s → {cmd}")
        log(f"[loop] job_id={jid} interval={interval}s cmd={cmd!r}")
        return True

    def _cmd_ls(self, r: ParseResult, state: InteractiveState) -> bool:
        """List remote directory via shell command. Migrated (41.4)."""


        path = r.rest or "."
        if r.selector:
            outcome = run_explicit_session_action(
                self.csp,
                state,
                "ls",
                r.selector,
                lambda session: session.exec_command(f"ls -la {path}"),
            )
            if outcome is None:
                return True
            matched, labels, skipped, result, results = outcome
            refs = _node_display_refs(
                result.ok,
                getattr(state, "nodes_by_id", {}) or {},
                getattr(state, "credentials_by_id", {}) or {},
            )
            for node_id in result.ok:
                output = results.get(node_id, "")
                if output:
                    out(f"[{refs[node_id]}] {output}")
            summarise_fan_out("ls", "Listed", matched, labels, result, skipped, selector=r.selector)
            return True
        session = resolve_bound_session(self.csp, state, "ls")
        if session is None:
            return True
        detail(f"ls: path={path}")
        try:
            output = session.exec_command(f"ls -la {path}")
            if output:
                out(output)
            log(f"[ls] path={path} method=ssh")
        except Exception as e:
            eprint(f"Error: {e}")
        return True
