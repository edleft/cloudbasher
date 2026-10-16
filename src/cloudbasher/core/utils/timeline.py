"""Per-operation timing instrumentation, emitted as JSONL for comparison against a reference client."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Optional

__all__ = [
    "configure_timeline",
    "close_timeline",
    "timeline_enabled",
    "record_call",
    "span",
    "mark",
]


class _Recorder:
    """Serialises records to one JSONL file."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("w", encoding="utf-8")
        self._lock = threading.Lock()
        self.path = path

    def emit(self, record: dict[str, Any]) -> None:


        record["t_epoch"] = time.time()
        record["t_mono"] = time.monotonic()
        line = json.dumps(record, default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except OSError:
                pass


_recorder: Optional[_Recorder] = None


def configure_timeline(path: str | Path) -> Path:
    """Start recording to `path`, replacing any current recorder."""
    global _recorder
    close_timeline()
    _recorder = _Recorder(Path(path))
    return _recorder.path


def close_timeline() -> None:
    global _recorder
    if _recorder is not None:
        _recorder.close()
        _recorder = None


def timeline_enabled() -> bool:
    return _recorder is not None


def record_call(
    op: str,
    *,
    signing_path: str,
    region: str,
    duration_ms: Optional[float],
    status: Optional[int] = None,
    error: Optional[str] = None,
    **attrs: Any,
) -> None:
    """One control-plane request."""
    rec = _recorder
    if rec is None:
        return
    rec.emit(
        {
            "kind": "call",
            "op": op,
            "signing_path": signing_path,
            "region": region,
            "status": status,


            "duration_ms": None if duration_ms is None else round(duration_ms, 1),
            "error": error,
            "attrs": attrs or None,
        }
    )


def mark(label: str, **attrs: Any) -> None:
    """Record an instant -- a single named point in an operation's timeline, as opposed to a span."""
    rec = _recorder
    if rec is None:
        return
    rec.emit({"kind": "mark", "label": label, "attrs": attrs or None})


def record_span(name: str, duration_ms: float, **attrs: Any) -> None:
    """A phase whose duration the caller already measured."""
    rec = _recorder
    if rec is None:
        return
    rec.emit(
        {
            "kind": "span",
            "name": name,
            "duration_ms": round(duration_ms, 1),
            "error": None,
            "attrs": attrs or None,
        }
    )


@contextmanager
def span(name: str, **attrs: Any) -> Generator[dict[str, Any]]:
    """Time a phase that is not a single HTTP call."""
    rec = _recorder
    if rec is None:
        yield dict(attrs)
        return
    live_attrs = dict(attrs)
    t0 = time.monotonic()
    error: Optional[str] = None
    try:
        yield live_attrs
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        rec.emit(
            {
                "kind": "span",
                "name": name,
                "duration_ms": round((time.monotonic() - t0) * 1000, 1),
                "error": error,
                "attrs": live_attrs or None,
            }
        )
