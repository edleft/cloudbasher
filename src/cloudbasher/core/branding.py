"""User-facing branding + UI display configuration."""

from __future__ import annotations


_DEFAULT_TITLE = "<l0ud\U0001f4a5bash3r"

_title: str = _DEFAULT_TITLE


def set_title(title: str) -> None:
    """Override the default app title."""
    global _title
    _title = title if title else _DEFAULT_TITLE


def get_app_name() -> str:
    """Return the current app display title."""
    return _title


_DEFAULT_PROMPT = "cb>"

_prompt: str = _DEFAULT_PROMPT


def set_prompt_text(prompt: str) -> None:
    """Override the default top-level prompt string."""
    global _prompt
    if not prompt:
        _prompt = _DEFAULT_PROMPT
        return
    stripped = prompt.rstrip()
    _prompt = stripped if stripped.endswith(">") else stripped + ">"


def get_prompt_text() -> str:
    """Return the configured top-level prompt string (e.g. 'cb>')."""
    return _prompt


_mouse_capture: bool = False


def set_mouse_capture(enabled: bool) -> None:
    """Toggle Textual mouse capture. False = terminal-native selection."""
    global _mouse_capture
    _mouse_capture = bool(enabled)


def get_mouse_capture() -> bool:
    """Return whether the App should capture mouse events itself."""
    return _mouse_capture
