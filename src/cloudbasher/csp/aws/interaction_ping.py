"""W9 -- keepalive layer 4: the interaction ping."""

from __future__ import annotations

from typing import Any

from cloudbasher.core.session.activity import activity_of
from cloudbasher.core.session.exit_code_spike import (
    parse_exit_code,
    wrap_command_with_exit_marker,
)
from cloudbasher.core.session.quiet import prime_quiet_history
from cloudbasher.core.types import session_idle_remaining
from cloudbasher.core.utils.output import detail, log


PING_LEAD_SECONDS = 4.5 * 60


PING_COMMAND = ":"


def should_ping(node: Any, now: float) -> bool:
    """Is this node close enough to its idle deadline to need a ping?"""
    remaining = session_idle_remaining(node, now)
    if remaining is None:
        return False
    return remaining <= PING_LEAD_SECONDS


def send_interaction_ping(node: Any, session: Any) -> bool:
    """Put one real command on `session` to reset its idle timer."""


    activity = activity_of(node)
    if activity is not None and activity.phase != "idle":
        detail(f"[layer4] {node.id} is {activity.phase}; no ping needed")
        return False


    prime_quiet_history(session)
    wrapped, marker = wrap_command_with_exit_marker(PING_COMMAND)

    try:


        out = session.exec_in_shell(f" {wrapped}", timeout=15, lock_wait=0, recover=False)
    except Exception as exc:


        detail(f"[layer4] ping did not complete for {node.id}: {exc}")
        return False


    _, exit_code = parse_exit_code(out or "", marker)
    if exit_code is None:
        log(f"[layer4] ping did not round-trip for {node.id}: marker absent")
        return False


    node.mark_real_traffic()
    detail(f"[layer4] session held open for {node.id}")
    return True
