"""AWS CloudShell per-call API debug artifact capture."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from cloudbasher.core.utils.output import detail, log


@dataclass
class ApiCallArtifact:
    """Full record of one signed CloudShell API call."""

    timestamp: str
    region: str
    path: str
    request_body: Any
    response_status: int
    response_headers: dict[str, str]
    response_body: Any
    duration_ms: float
    request_id: str = ""
    error: Optional[str] = None


class ArtifactCapture:
    """Captures CloudShell API call artifacts to a directory."""

    def __init__(self, artifact_dir: str) -> None:
        self._dir = Path(artifact_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._counter = 0
        import threading

        self._lock = threading.Lock()

    def record(self, artifact: ApiCallArtifact) -> None:
        """Write one artifact to a timestamped JSON file."""
        with self._lock:
            self._counter += 1
            seq = self._counter

        op = artifact.path.lstrip("/").replace("/", "_")
        ts_safe = artifact.timestamp.replace(":", "").replace("-", "")
        filename = f"{ts_safe}_{seq:04d}_{op}.json"
        path = self._dir / filename

        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(asdict(artifact), fh, indent=2, default=str)
            detail(f"[artifact] wrote {filename}")
        except OSError as e:
            log(f"[artifact] failed to write {filename}: {e}")

    def wrap_request(
        self,
        region: str,
        path: str,
        body_obj: Any,
        call_fn,
    ) -> tuple[Any, dict[str, str], int]:
        """Call call_fn() and record the result as an artifact."""
        import datetime

        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        t0 = time.monotonic()
        error_msg: Optional[str] = None
        payload: Any = {}
        headers: dict[str, str] = {}
        status: int = 0

        try:
            payload, headers, status = call_fn()
        except Exception as exc:
            error_msg = str(exc)
            raise
        finally:
            duration_ms = (time.monotonic() - t0) * 1000
            artifact = ApiCallArtifact(
                timestamp=ts,
                region=region,
                path=path,
                request_body=body_obj,
                response_status=status,
                response_headers=dict(headers),
                response_body=payload,
                duration_ms=round(duration_ms, 1),
                request_id=headers.get("x-amzn-RequestId", ""),
                error=error_msg,
            )
            self.record(artifact)

        return payload, headers, status
