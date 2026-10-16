"""Timestamp parsing shared by every surface that reads a cloud timestamp."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

__all__ = ["iso_to_epoch"]


def iso_to_epoch(raw: Any) -> Optional[float]:
    """A cloud timestamp as Unix epoch seconds, or None if it is not one."""
    if raw is None:
        return None
    if isinstance(raw, bool):


        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    try:
        parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()
