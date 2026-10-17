"""Running CloudBasher's own commands without leaving them in the user's shell."""

from __future__ import annotations

import shlex
from typing import Any, Optional

from cloudbasher.core.utils.output import detail, eprint


_PRIMED_ATTR = "_cb_history_primed"


_PRIMED_OK_ATTR = "_cb_history_primed_ok"


HISTORY_OFF = "HISTFILE=/dev/null"


INTERNAL_COMMAND_TIMEOUT_SECONDS = 2


SCROLLBACK_CLEAR_TIMEOUT_SECONDS = 10


_PRIMER = f"{HISTORY_OFF}; HISTCONTROL=ignorespace"


def _primer_for_session(session: Any) -> tuple[str, str]:
    """Return (shell command, safe diagnostic) for this session's history mode."""
    history_file = getattr(session, "quiet_history_file", None)
    if not history_file:
        return _PRIMER, "[quiet] history is off for this shell (HISTFILE=/dev/null)"

    quoted_path = shlex.quote(str(history_file))
    command = (
        f"(umask 077; : >> {quoted_path} && chmod 600 {quoted_path}) && "
        f"HISTFILE={quoted_path} && HISTCONTROL=ignorespace && "
        "export HISTFILE HISTCONTROL"
    )
    return command, "[quiet] shell history uses a private session file"


def prime_quiet_history(session: Any) -> None:
    """Configure the shell history policy and ignore internal commands."""
    if getattr(session, _PRIMED_ATTR, False):
        return
    try:
        setattr(session, _PRIMED_ATTR, True)
    except Exception:
        pass
    try:
        primer, success_detail = _primer_for_session(session)
        session.exec_command(f" {primer}", timeout=INTERNAL_COMMAND_TIMEOUT_SECONDS)
        try:
            setattr(session, _PRIMED_OK_ATTR, True)
        except Exception:
            pass
        detail(success_detail)
    except Exception as exc:


        try:
            setattr(session, _PRIMED_ATTR, False)
            setattr(session, _PRIMED_OK_ATTR, False)
        except Exception:
            pass
        if getattr(session, "quiet_history_file", None):
            consequence = (
                "  The session history file remains enabled, but CloudBasher's "
                "space-prefixed commands may appear in history."
            )
        else:
            consequence = (
                "  Commands in this session may be written to ~/.bash_history "
                "inside the container."
            )
        eprint(f"WARNING: could not configure shell history: {exc}\n{consequence}")


def with_history_off(session: Any, command: str) -> str:
    """`command`, carrying `HISTFILE=/dev/null` inline unless the shell has it."""
    if getattr(session, _PRIMED_OK_ATTR, False):
        return command
    if HISTORY_OFF in command:
        return command
    return f"{HISTORY_OFF}; {command}"


def exec_quiet(
    session: Any,
    command: str,
    *,
    timeout: Optional[int] = None,
    raw: bool = False,
) -> str:
    """Run one of CloudBasher's own commands, kept out of the user's history."""
    prime_quiet_history(session)
    return session.exec_command(f" {command}", timeout=timeout, raw=raw)


def clear_terminal(session: Any) -> None:
    """Wipe the visible scrollback of CloudBasher's bootstrap probes."""
    try:
        session.exec_command(" clear", timeout=SCROLLBACK_CLEAR_TIMEOUT_SECONDS)
    except Exception as exc:
        detail(f"[quiet] could not clear the terminal: {exc}")
