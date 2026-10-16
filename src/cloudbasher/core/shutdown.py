"""Process teardown, as something a background loop can ASK about. (`#804`)"""

from __future__ import annotations

import threading

_TEARDOWN = threading.Event()


def begin_teardown() -> None:
    """The process is leaving. Call this FIRST, before anything is closed."""
    _TEARDOWN.set()


def tearing_down() -> bool:
    """Should a background loop stop what it is doing and unwind?"""
    return _TEARDOWN.is_set()


def reset_for_tests() -> None:
    """Clear the flag. **Tests only** -- there is no production caller."""
    _TEARDOWN.clear()
