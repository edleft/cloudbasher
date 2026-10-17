"""Two-tier cadence for environment-status polling."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PollSchedule:
    """How long to wait before the next status poll, by how long we have already been waiting. Immutable and pure -- it holds no clock and no counter, so the caller keeps its own elapsed time and this stays trivially testable at any point on the curve."""


    expected_seconds: float

    steady_seconds: float


    quiet_fraction: float = 0.7


    dense_seconds: float = 0.2


    dense_until_fraction: float = 1.5


    max_quiet_sleep_seconds: float = 2.5

    @property
    def quiet_until(self) -> float:
        return self.expected_seconds * self.quiet_fraction

    @property
    def dense_until(self) -> float:
        return self.expected_seconds * self.dense_until_fraction

    def phase_at(self, elapsed_seconds: float) -> str:
        """Which tier ``elapsed_seconds`` falls in: ``quiet``/``dense``/``steady``."""
        if elapsed_seconds < self.quiet_until:
            return "quiet"
        if elapsed_seconds < self.dense_until:
            return "dense"
        return "steady"

    def delay_after(self, elapsed_seconds: float) -> float:
        """Seconds to sleep before the next poll."""
        if elapsed_seconds < self.quiet_until:


            return min(self.quiet_until - elapsed_seconds, self.max_quiet_sleep_seconds)
        if elapsed_seconds < self.dense_until:
            return self.dense_seconds
        return self.steady_seconds
