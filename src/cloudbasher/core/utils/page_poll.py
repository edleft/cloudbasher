"""ONE polling loop for "drive a browser page to a predicate, or to a budget"."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

__all__ = ["PollOutcome", "poll_page_until", "decayed_retry_budget"]


@dataclass(frozen=True)
class PollOutcome:
    """What the poll saw. Returned, never recomputed by the caller."""


    verdict: Any

    checks: int

    waits: int

    budget_ms: int

    tick_ms: int


    elapsed_ms: int

    @property
    def timed_out(self) -> bool:
        """The budget ran out with the predicate still false."""
        return self.verdict is None

    def observed(self) -> str:
        """One line naming WHAT WAS SEEN, for a failure message."""
        return (
            f"checks={self.checks} waits={self.waits} "
            f"elapsed={self.elapsed_ms / 1000:.1f}s of {self.budget_ms / 1000:.1f}s budget "
            f"tick={self.tick_ms}ms verdict={self.verdict if self.verdict else 'none'}"
        )


def poll_page_until(
    page: Any,
    *,
    until: Callable[[], Any],
    budget_ms: int,
    tick_ms: int,
    sleep_ms: Optional[Callable[[int], Any]] = None,
) -> PollOutcome:
    """Evaluate `until` until it returns something truthy, or the budget ends."""
    sleep = sleep_ms if sleep_ms is not None else page.wait_for_timeout
    started = time.monotonic()
    budget = max(0, budget_ms)
    tick = max(1, tick_ms)
    deadline = started + budget / 1000.0
    max_waits = -(-budget // tick)
    checks = 0
    waits = 0
    while True:
        checks += 1
        verdict = until()
        if verdict:
            break
        if waits >= max_waits or time.monotonic() >= deadline:
            verdict = None
            break
        sleep(tick)
        waits += 1
    return PollOutcome(
        verdict=verdict,
        checks=checks,
        waits=waits,
        budget_ms=budget,
        tick_ms=tick,
        elapsed_ms=int((time.monotonic() - started) * 1000),
    )


RETRY_BUDGET_DIVISOR = 3


def decayed_retry_budget(first_attempt_seconds: int, *, repeat: bool) -> int:
    """The budget for one attempt: full the first time, a third of it after."""
    if not repeat:
        return max(0, first_attempt_seconds)
    return max(1, first_attempt_seconds // RETRY_BUDGET_DIVISOR)
