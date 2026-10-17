"""Count and attribute every `getaddrinfo` this process makes"""

from __future__ import annotations

import socket
import sys
import threading
import time
from collections import Counter
from typing import Any, Optional


_original: Optional[Any] = None
_lock = threading.Lock()


_calls: Counter = Counter()

_failures: Counter = Counter()

_by_site: Counter = Counter()
_by_site_failed: Counter = Counter()


_LATENCY_EDGES_MS = (1.0, 5.0, 20.0, 100.0, 1000.0)
_latency: Counter = Counter()


_bisect_budget: int = 0
_bisects: list[dict[str, Any]] = []


_bisect_nameserver: Optional[str] = None


_bisect_ns_reason: str = ""


_fd_high_water: int = 0


_total_calls: int = 0


_FD_SAMPLE_EVERY = 50
_fd_exhausted_at: str = ""


def _bisect_ns_error(reason: str) -> None:
    global _bisect_ns_reason
    _bisect_ns_reason = reason


_MAX_FRAMES = 24


_OURS = "/cloudbasher/"
_NOT_OURS = "/site-packages/"


def _call_site() -> str:
    """`module:lineno` of the first frame outside transport plumbing."""
    try:
        frame = sys._getframe(2)
    except ValueError:
        return "?"
    fallback = ""
    for _ in range(_MAX_FRAMES):
        if frame is None:
            break
        path = frame.f_code.co_filename
        label = f"{path.rsplit('/', 1)[-1]}:{frame.f_lineno}"
        if _OURS in path and _NOT_OURS not in path and "dns_trace.py" not in path:
            return label
        if not fallback:
            fallback = label
        frame = frame.f_back


    return fallback or "?"


def _bucket(elapsed_ms: float) -> str:
    for edge in _LATENCY_EDGES_MS:
        if elapsed_ms < edge:
            return f"<{edge:g}ms"
    return f">={_LATENCY_EDGES_MS[-1]:g}ms"


def set_bisect_budget(n: int) -> None:
    """How many failing lookups get bisected. 0 disables it."""
    global _bisect_budget, _bisect_nameserver
    with _lock:
        _bisect_budget = max(0, int(n))
    if not _bisect_budget:
        return


    try:
        from cloudbasher.core.utils.dns_probe import primary_nameserver, resolver_config

        _bisect_nameserver = primary_nameserver()
        if not _bisect_nameserver:
            cfg = resolver_config()
            _bisect_ns_error(cfg.get("error") or f"no nameservers in {cfg.get('platform')} config")
    except Exception as exc:  # noqa: BLE001
        _bisect_ns_error(f"{type(exc).__name__}: {exc}")


def _claim_bisect() -> bool:
    """Take one unit of bisect budget, or return False. MUST hold the lock."""
    global _bisect_budget
    if _bisect_budget <= 0:
        return False
    _bisect_budget -= 1
    return True


def _fd_probe() -> tuple[Optional[int], str]:
    """Delegates. `fd_limit` owns descriptor measurement; this owns DNS."""
    from cloudbasher.core.utils.fd_limit import open_descriptor_count

    return open_descriptor_count()


def _fd_accurate_count() -> Optional[int]:
    from cloudbasher.core.utils.fd_limit import accurate_descriptor_count

    return accurate_descriptor_count()


def _reset_fd_state() -> None:
    """Cleared with the counts: it IS a measurement, unlike the budget."""
    global _fd_high_water, _fd_exhausted_at
    _fd_high_water = 0
    _fd_exhausted_at = ""


def _note_fd_pressure() -> None:
    """Sample the descriptor count and keep the high-water mark."""
    global _fd_high_water, _fd_exhausted_at
    approx, note = _fd_probe()
    with _lock:
        if approx is not None:
            if approx > _fd_high_water:
                _fd_high_water = approx
        elif note and not _fd_exhausted_at:
            _fd_exhausted_at = note


def _bisect_failure(host: Any, exc: BaseException, site: str, code: Any) -> None:
    """Ask the nameserver directly, and retry locally. Never raises."""
    try:
        from cloudbasher.core.utils.dns_probe import resolve_direct
        from cloudbasher.core.utils.output import log


        ns = _bisect_nameserver
        direct_ok, direct_detail = resolve_direct(str(host), ns)
        if not ns:


            ns = f"system-default ({_bisect_ns_reason or 'nameserver not identified'})"

        retry_ok, retry_detail = False, ""
        try:
            assert _original is not None
            _original(host, 443, 0, 1)
            retry_ok, retry_detail = True, "OK"
        except BaseException as retry_exc:  # noqa: BLE001 -- the failure IS the datum
            retry_detail = f"FAILED errno={getattr(retry_exc, 'errno', None)}"

        if direct_ok and not retry_ok:
            verdict = (
                "LOCAL RESOLVER REPORTS ABSENCE for a name the nameserver can "
                "serve, and the failure is STICKY -- the negative-cache "
                "signature. #436 a3 (in-process cache) removes this path and "
                "is sufficient."
            )
        elif direct_ok and retry_ok:
            verdict = (
                "TRANSIENT: the local retry succeeded and the nameserver is "
                "healthy. Not a cached negative answer -- look at what made "
                "the single call fail, not at resolver capacity."
            )
        elif not direct_ok and "PROBE-" in direct_detail:
            verdict = (
                "INCONCLUSIVE -- the direct query could not be made, so this "
                "says nothing about the nameserver. Fix the probe, not the code."
            )
        else:
            verdict = (
                "BOTH FAILED: the ceiling is UPSTREAM of this host. a3 helps "
                "but cannot fix it; #466's admission gate is the real fix and "
                "concurrency must also be capped."
            )

        exact = _fd_accurate_count()
        approx, fd_note = _fd_probe()
        fd_text = (
            f"fds={exact if exact is not None else '?'}"
            f"{'/approx=' + str(approx) if approx is not None else ''}"
            f"{' ' + fd_note if fd_note else ''}"
        )
        log(
            f"[dns-bisect] {fd_text} host={host} site={site} "
            f"gai=FAILED errno={code} ({type(exc).__name__}) "
            f"direct@{ns}={'OK' if direct_ok else 'FAILED'}({direct_detail}) "
            f"gai_retry={retry_detail} => {verdict}"
        )
        with _lock:
            _bisects.append(
                {
                    "host": str(host),
                    "site": site,
                    "errno": str(code),
                    "nameserver": str(ns),
                    "direct_ok": direct_ok,
                    "direct_detail": direct_detail,
                    "retry_ok": retry_ok,
                    "verdict": verdict,
                }
            )
    except Exception as diag_exc:  # noqa: BLE001


        try:
            log(f"[dns-bisect] the bisect itself failed: {type(diag_exc).__name__}: {diag_exc}")
        except Exception:
            pass


def _traced(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
    global _total_calls
    assert _original is not None
    site = _call_site()
    began = time.monotonic()
    try:
        result = _original(host, port, *args, **kwargs)
    except BaseException as exc:  # noqa: BLE001 -- the failure IS the datum
        elapsed = (time.monotonic() - began) * 1000.0


        code = getattr(exc, "errno", None)
        with _lock:
            _calls[str(host)] += 1
            _failures[(str(host), str(code if code is not None else type(exc).__name__))] += 1
            _by_site[site] += 1
            _by_site_failed[site] += 1
            _latency[_bucket(elapsed)] += 1
            _total_calls += 1


            do_bisect = _claim_bisect()


        _note_fd_pressure()
        if do_bisect:


            _bisect_failure(host, exc, site, code)
        raise
    elapsed = (time.monotonic() - began) * 1000.0
    with _lock:
        _calls[str(host)] += 1
        _by_site[site] += 1
        _latency[_bucket(elapsed)] += 1
        _total_calls += 1


        sample = _total_calls % _FD_SAMPLE_EVERY == 0
    if sample:
        _note_fd_pressure()
    return result


def install() -> bool:
    """Patch `socket.getaddrinfo`. Returns False if already installed."""
    global _original
    with _lock:
        if _original is not None:
            return False
        _original = socket.getaddrinfo
    socket.getaddrinfo = _traced  # type: ignore[assignment]
    return True


def uninstall() -> None:
    """Restore the real function. For tests, and for a session boundary."""
    global _original
    with _lock:
        if _original is None:
            return
        socket.getaddrinfo = _original  # type: ignore[assignment]
        _original = None


def is_installed() -> bool:
    return _original is not None


def reset() -> None:
    """Drop every count. Process-wide state needs a reset hook, same reason `output.reset_log_repeat_state()` does."""
    global _total_calls
    with _lock:
        _calls.clear()
        _failures.clear()
        _by_site.clear()
        _by_site_failed.clear()
        _latency.clear()
        _bisects.clear()
        _reset_fd_state()
        _total_calls = 0


def snapshot() -> dict[str, Any]:
    """The counts, read under one lock so the totals are self-consistent."""
    with _lock:
        total = _total_calls
        failed = sum(_failures.values())
        return {
            "total_calls": total,
            "total_failed": failed,
            "distinct_hosts": len(_calls),
            "by_host": dict(_calls.most_common()),
            "failures": {f"{h} errno={e}": n for (h, e), n in _failures.most_common()},
            "by_call_site": {
                site: {"calls": n, "failed": _by_site_failed.get(site, 0)}
                for site, n in _by_site.most_common()
            },
            "latency": dict(_latency.most_common()),
            "bisects": list(_bisects),
            "bisect_budget_left": _bisect_budget,
            "fd_high_water": _fd_high_water,
            "fd_exhausted": _fd_exhausted_at,
        }


def report() -> list[str]:
    """The snapshot as lines. Empty when nothing was traced."""
    snap = snapshot()
    if not snap["total_calls"]:
        return []
    out = [
        f"[dns] {snap['total_calls']} getaddrinfo call(s), "
        f"{snap['total_failed']} failed, {snap['distinct_hosts']} distinct host(s)"
    ]


    if snap.get("fd_exhausted"):
        out.append(f"[dns] *** DESCRIPTOR TABLE WAS FULL: {snap['fd_exhausted']} ***")
        out.append(
            "[dns] *** The failures below are NOT DNS failures. FD exhaustion "
            "makes getaddrinfo report EAI_NONAME. ***"
        )
    if snap.get("fd_high_water"):


        from cloudbasher.core.utils.fd_limit import current_soft_limit

        limit = current_soft_limit()
        scale = f" / limit {limit} ({100.0 * snap['fd_high_water'] / limit:.1f}%)" if limit else ""
        out.append(f"[dns] open descriptors, high-water: {snap['fd_high_water']}{scale}")
    out.append(f"[dns] latency: {snap['latency']}")
    for host, n in list(snap["by_host"].items())[:25]:
        out.append(f"[dns]   {n:>5}  {host}")
    for label, n in snap["failures"].items():
        out.append(f"[dns]   FAILED {n:>5}  {label}")
    for site, counts in list(snap["by_call_site"].items())[:15]:
        out.append(f"[dns]   site {counts['calls']:>5} ({counts['failed']} failed)  {site}")


    for b in snap.get("bisects", []):
        out.append(
            f"[dns] BISECT {b['host']} ({b['site']}, errno={b['errno']}): "
            f"direct@{b['nameserver']}={'OK' if b['direct_ok'] else 'FAILED'} "
            f"({b['direct_detail']}), local_retry="
            f"{'OK' if b['retry_ok'] else 'FAILED'}"
        )
        out.append(f"[dns]        => {b['verdict']}")
    if snap.get("total_failed") and not snap.get("bisects"):


        out.append(
            "[dns] NO BISECT RAN despite failures -- budget was 0 "
            "(set `diag.net_bisect`), or every failure arrived after it was spent."
        )
    return out


DEFAULT_REPORT_PATH = "net_trace_report.txt"


def write_report(path: str) -> int:
    """Write the report to `path`. Returns the number of lines written."""
    import os

    lines = report()
    if not lines:
        return 0
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, ("\n".join(lines) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:
        return 0
    return len(lines)


def install_with_exit_report(path: Optional[str] = None) -> bool:
    """`install()` plus an `atexit` hook that writes the report to a FILE."""
    if not install():
        return False
    import atexit

    target = path or DEFAULT_REPORT_PATH

    def _emit() -> None:
        written = write_report(target)
        if written:


            sys.stderr.write(f"[diag] network trace report ({written} lines) -> {target}\n")

    atexit.register(_emit)
    return True
