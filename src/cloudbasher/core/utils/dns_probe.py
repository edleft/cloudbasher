"""Which resolver answers, and what it says when asked directly"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
from typing import Any, Optional


_cached_config: Optional[dict[str, Any]] = None


def resolver_config(refresh: bool = False, with_nwi: bool = False) -> dict[str, Any]:
    """What the system will use to resolve, captured rather than assumed."""
    global _cached_config
    if _cached_config is not None and not refresh:


        if not with_nwi or "nwi" in _cached_config or "nwi_error" in _cached_config:
            return _cached_config
    out: dict[str, Any] = {"platform": sys.platform, "nameservers": [], "raw": ""}
    if shutil.which("scutil"):
        try:
            raw = subprocess.run(
                ["scutil", "--dns"], capture_output=True, text=True, timeout=10
            ).stdout
            out["raw"] = raw
            for line in raw.splitlines():
                line = line.strip()
                if line.startswith("nameserver[") and ":" in line:
                    addr = line.split(":", 1)[1].strip()
                    if addr not in out["nameservers"]:
                        out["nameservers"].append(addr)
        except Exception as exc:
            out["error"] = f"scutil failed: {exc}"
        if with_nwi:


            try:
                out["nwi"] = subprocess.run(
                    ["scutil", "--nwi"], capture_output=True, text=True, timeout=10
                ).stdout
            except Exception as exc:
                out["nwi_error"] = f"scutil --nwi failed: {exc}"
    else:
        try:
            raw = pathlib.Path("/etc/resolv.conf").read_text()
            out["raw"] = raw
            out["nameservers"] = [
                ln.split()[1] for ln in raw.splitlines() if ln.startswith("nameserver")
            ]
        except Exception as exc:
            out["error"] = f"resolv.conf unreadable: {exc}"
    _cached_config = out
    return out


def primary_nameserver() -> Optional[str]:
    """The first configured nameserver, or None."""
    servers: list[str] = list(resolver_config().get("nameservers") or [])
    for addr in servers:
        if ":" not in addr:
            return addr
    return servers[0] if servers else None


def resolve_direct(
    host: str, nameserver: Optional[str] = None, timeout: float = 5.0
) -> tuple[bool, str]:
    """One query straight at `nameserver`, bypassing the system resolver."""
    if not shutil.which("dig"):
        return False, "PROBE-UNAVAILABLE: dig not installed (NOT a resolver failure)"


    server = [f"@{nameserver}"] if nameserver else []
    try:
        proc = subprocess.run(
            [
                "dig",
                *server,
                f"+time={int(max(1, timeout))}",
                "+tries=1",
                "+short",
                host,
                "A",
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 10.0,
        )
    except Exception as exc:
        return False, f"PROBE-ERROR: {type(exc).__name__}: {exc}"
    answer = proc.stdout.strip()
    if proc.returncode != 0:
        return False, f"dig rc={proc.returncode} {proc.stderr.strip()[:80]!r}"
    if not answer:


        return False, "EMPTY ANSWER (nameserver replied with no A record)"
    return True, answer.replace("\n", ",")
