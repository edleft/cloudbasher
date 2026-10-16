"""Strict dot-command batch execution for CLI ``-f``."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..types import InteractiveState
from ..utils.output import eprint, log

if TYPE_CHECKING:
    from .dispatcher import CommandDispatcher


@dataclass(frozen=True)
class BatchRunResult:
    """Aggregate result for one command file."""

    exit_code: int
    executed: int
    failed: int


def read_batch_lines(path: str, *, error_label: str) -> list[str] | None:
    """Read one command file without deciding what its lines mean."""
    try:
        return Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        eprint(f"{error_label}: {exc}")
        return None


def run_batch_file(
    path: str, state: InteractiveState, dispatcher: "CommandDispatcher"
) -> BatchRunResult:
    """Run a strict, result-aware dot-command file without shell fallback."""
    lines = read_batch_lines(path, error_label="Cannot open batch file")
    if lines is None:
        return BatchRunResult(1, 0, 1)

    executed = failed = 0
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        executed += 1
        log(f"[batch:{lineno}] {line}")
        outcome = dispatcher.dispatch_batch(line, state)
        if not outcome.ok:
            failed += 1
            eprint(f"[batch:{lineno}] {outcome.detail}")

    return BatchRunResult(1 if failed else 0, executed, failed)
