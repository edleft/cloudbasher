"""Base class for interactive input modes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..types import InteractiveState


class InteractiveMode(ABC):
    """Base class for interactive input modes (TUI, readline, etc)."""

    @abstractmethod
    def run(self, state: InteractiveState) -> Optional[str]:
        """Run the interactive mode."""
        pass
