"""An append-only record of environments this tool asked AWS to create -- `#434`."""

from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional


_path: Optional[str] = None
_lock = threading.Lock()


INTENT = "intent"
CREATED = "created"
DELETED = "deleted"


def configure(path: Optional[str]) -> None:
    """Point the journal at `path`, or None to disable it."""
    global _path
    _path = path


def journal_path() -> Optional[str]:
    return _path


def path_beside_registry(registry_path: str) -> str:
    """`<registry>.envlog.jsonl`, so the two travel together."""
    return f"{registry_path}.envlog.jsonl"


def _append(record: dict[str, Any]) -> None:
    """One line, opened-written-closed under a lock, and never raising."""
    target = _path
    if not target:
        return
    line = json.dumps(record, separators=(",", ":"), sort_keys=True)
    try:
        with _lock:
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
            finally:
                os.close(fd)
    except Exception:
        from cloudbasher.core.utils.output import log

        log(f"[envlog] could not append to {target} -- continuing without it")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def record_intent(*, principal: str, region: str) -> str:
    """Log "about to create", and return the attempt id that links the pair."""
    attempt = uuid.uuid4().hex[:12]
    _append(
        {
            "at": _now(),
            "event": INTENT,
            "attempt": attempt,
            "principal": principal,
            "region": region,
        }
    )
    return attempt


def record_created(*, attempt: str, principal: str, region: str, environment_id: str) -> None:
    """Log the id the moment it exists."""
    _append(
        {
            "at": _now(),
            "event": CREATED,
            "attempt": attempt,
            "principal": principal,
            "region": region,
            "env": environment_id,
        }
    )


def record_deleted(*, environment_id: str, region: str = "") -> None:
    """Log a CONFIRMED delete -- the only thing that closes an entry."""
    _append({"at": _now(), "event": DELETED, "environment_id": environment_id, "region": region})


def read_records(path: Optional[str] = None) -> list[dict[str, Any]]:
    """Every parsable line, in file order. A corrupt line is SKIPPED, not fatal."""
    target = path or _path
    if not target:
        return []
    out: list[dict[str, Any]] = []
    try:
        with open(target, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:
                    continue
                if isinstance(record, dict):
                    out.append(record)
    except FileNotFoundError:
        return []
    except Exception:
        return []
    return out


def unclosed_per_journal(
    path: Optional[str] = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """`(created_not_deleted, intents_with_no_id)` -- **AS THIS JOURNAL SEES IT.**"""
    records = read_records(path)
    created: dict[str, dict[str, Any]] = {}
    deleted: set[str] = set()
    intents: dict[str, dict[str, Any]] = {}
    for record in records:
        event = record.get("event")
        if event == INTENT:
            attempt = str(record.get("attempt") or "")
            if attempt:
                intents[attempt] = record
        elif event == CREATED:
            env_id = str(record.get("env") or "")
            if env_id:
                created[env_id] = record
            intents.pop(str(record.get("attempt") or ""), None)
        elif event == DELETED:
            env_id = str(record.get("environment_id") or "")
            if env_id:
                deleted.add(env_id)
    open_created = [rec for env_id, rec in created.items() if env_id not in deleted]
    return open_created, list(intents.values())
