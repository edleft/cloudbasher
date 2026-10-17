"""- what to show as the shell prompt, including mid-rebuild."""

from __future__ import annotations

from typing import Any, Optional


def display_prompt(session: Any) -> Optional[str]:
    """The prompt text to show for `session`, or None to use the caller's own fallback chain."""
    live = getattr(session, "_captured_prompt", None)
    if isinstance(live, str) and live:
        return live
    remembered = getattr(session, "_last_prompt_for_display", None)
    if isinstance(remembered, str) and remembered:
        return remembered
    return None
