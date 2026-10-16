"""Widget-free helpers shared by the readline, Textual, and prompt_toolkit REPL loops."""

from __future__ import annotations

import re
from typing import Any, Optional, Tuple


AVAILABLE_UI_MODES: Tuple[str, ...] = ("tui",)


KNOWN_UI_MODES: Tuple[str, ...] = ("tui", "readline")


SURFACE_EXIT_COMMANDS = frozenset({"exit", ".exit"})


APP_QUIT_COMMANDS = frozenset({"quit", ".quit", ":quit", ":q", ":q!", ".q"})


def quit_command_help() -> str:
    """EVERY quit verb, in the order a user would look for them."""
    rest = sorted(APP_QUIT_COMMANDS, key=lambda c: (len(c), c))
    return " / ".join(rest)


_HISTORY_BANG_RE = re.compile(r"!([1-9]\d*)")


def expand_history_bang(line: str, state: Any) -> str:
    """Expand a bare ``!N`` to the Nth (1-based) history entry."""
    m = _HISTORY_BANG_RE.fullmatch(line)
    if m is None:
        return line
    idx = int(m.group(1))
    return state.history_entry(idx)


CONFIRM_YES = ("", "y", "yes")
CONFIRM_NO = ("n", "no")


def is_quit_confirmed(answer: str) -> bool:
    """True if a typed response to ``quit [Y/n]`` means yes (default: yes)."""
    return answer.strip().lower() in CONFIRM_YES


def is_confirm_answer(line: str) -> bool:
    """True if ``line`` is a yes/no response to a pending ``[Y/n]`` question."""
    return (line or "").strip().lower() in CONFIRM_YES + CONFIRM_NO


def pending_confirm_pair(state: Any) -> Optional[Tuple[str, str]]:
    """The pending ``(question, command-to-run-on-yes)`` pair, or None."""
    pending = getattr(state, "pending_confirm", None)
    if isinstance(pending, (tuple, list)) and len(pending) == 2:
        return (str(pending[0]), str(pending[1]))
    return None


def pending_question(state: Any) -> Optional[str]:
    """The text of a pending ``[Y/n]`` question, or None."""
    pair = pending_confirm_pair(state)
    return None if pair is None else pair[0]
