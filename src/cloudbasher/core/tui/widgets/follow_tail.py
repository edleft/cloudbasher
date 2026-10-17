"""A `RichLog` that follows the tail only while you are already at the tail."""

from __future__ import annotations

import time
from typing import Any

from textual.widgets import RichLog


class FollowTailLog(RichLog):
    """`RichLog` whose autoscroll is decided per write, from the view position."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)


        self._last_offset_y: int = 0
        self._offset_changed_at: float = time.monotonic()

    def write(self, content: Any, *args: Any, **kwargs: Any) -> Any:
        """Append, and follow the tail ONLY if the user is already there."""
        if "scroll_end" not in kwargs and not args:
            kwargs["scroll_end"] = self._should_follow_tail()
        return super().write(content, *args, **kwargs)

    def _should_follow_tail(self) -> bool:
        from cloudbasher.core.utils.perf_config import get_log_follow_repin_seconds

        try:
            at_bottom = bool(self.is_vertical_scroll_end)
            offset_y = int(self.scroll_offset.y)
        except Exception:


            return True

        now = time.monotonic()
        if offset_y != self._last_offset_y:
            self._last_offset_y = offset_y
            self._offset_changed_at = now

        if at_bottom:
            return True


        repin = get_log_follow_repin_seconds()
        if repin <= 0:
            return False
        return (now - self._offset_changed_at) >= repin
