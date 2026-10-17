"""Runtime-tunable concurrency and timing knobs for multi-node fan-out."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING, Callable, Iterator, Optional

if TYPE_CHECKING:
    from .poll_schedule import PollSchedule

_max_workers: int = 16


_env_status_poll_interval_seconds: float = 1.1
_reset_retry_delay_seconds: float = 2.0
_warmup_retry_delays_seconds: tuple[float, ...] = (15.0, 45.0)


def set_max_workers(n: int) -> None:
    """Ignored if ``n`` isn't a positive int -- rc-file typo tolerance, same rationale as every other setter in this codebase's rc-driven modules (redact.py, branding.py)."""
    global _max_workers
    if isinstance(n, int) and n > 0:
        _max_workers = n


def get_max_workers() -> int:
    return _max_workers


def pool_width(work: int, override: Optional[int] = None) -> int:
    """How wide a pool to run for ``work`` items. THE one place this is decided."""
    ceiling = get_max_workers() if override is None else override
    return max(1, min(ceiling, work))


def set_env_status_poll_interval_seconds(seconds: float) -> None:
    global _env_status_poll_interval_seconds
    if isinstance(seconds, (int, float)) and seconds > 0:
        _env_status_poll_interval_seconds = float(seconds)


def get_env_status_poll_interval_seconds() -> float:
    return _env_status_poll_interval_seconds


_env_start_expected_seconds: float = 6.0
_env_stop_expected_seconds: float = 13.4
_env_status_poll_dense_seconds: float = 0.2
_env_status_poll_quiet_fraction: float = 0.7


def set_env_start_expected_seconds(seconds: float) -> None:
    global _env_start_expected_seconds
    if isinstance(seconds, (int, float)) and seconds >= 0:
        _env_start_expected_seconds = float(seconds)


def get_env_start_expected_seconds() -> float:
    return _env_start_expected_seconds


def set_env_stop_expected_seconds(seconds: float) -> None:
    global _env_stop_expected_seconds
    if isinstance(seconds, (int, float)) and seconds >= 0:
        _env_stop_expected_seconds = float(seconds)


def get_env_stop_expected_seconds() -> float:
    return _env_stop_expected_seconds


def set_env_status_poll_dense_seconds(seconds: float) -> None:
    global _env_status_poll_dense_seconds
    if isinstance(seconds, (int, float)) and seconds > 0:
        _env_status_poll_dense_seconds = float(seconds)


def get_env_status_poll_dense_seconds() -> float:
    return _env_status_poll_dense_seconds


def set_env_status_poll_quiet_fraction(fraction: float) -> None:
    """Clamped to [0, 1): a fraction of 1.0 or more would keep the quiet phase open past the point the answer is expected, which is the one setting that could make this slower than the flat interval it replaces."""
    global _env_status_poll_quiet_fraction
    if isinstance(fraction, (int, float)) and 0 <= fraction < 1:
        _env_status_poll_quiet_fraction = float(fraction)


def get_env_status_poll_quiet_fraction() -> float:
    return _env_status_poll_quiet_fraction


def env_status_poll_schedule(expected_seconds: float, concurrency: int = 1) -> "PollSchedule":
    """Assemble the current knobs into a schedule for one transition."""
    from .poll_schedule import PollSchedule

    dense = _env_status_poll_dense_seconds
    if isinstance(concurrency, int) and concurrency > 1:
        dense = min(dense * concurrency, _env_status_poll_interval_seconds)

    return PollSchedule(
        expected_seconds=expected_seconds,
        steady_seconds=_env_status_poll_interval_seconds,
        quiet_fraction=_env_status_poll_quiet_fraction,
        dense_seconds=dense,
    )


_status_polls_in_flight: int = 0
_status_poll_lock = threading.Lock()


def get_status_polls_in_flight() -> int:
    """How many `status_poll_wait()` blocks are currently open."""
    with _status_poll_lock:
        return _status_polls_in_flight


@contextmanager
def status_poll_wait(*, floor: int = 1) -> Iterator[Callable[[float], "PollSchedule"]]:
    """Register one environment-status wait; yield its schedule factory."""
    global _status_polls_in_flight
    base = floor if isinstance(floor, int) and floor > 0 else 1
    with _status_poll_lock:
        _status_polls_in_flight += 1
    try:

        def schedule_for(expected_seconds: float) -> "PollSchedule":
            return env_status_poll_schedule(
                expected_seconds, concurrency=max(base, get_status_polls_in_flight())
            )

        yield schedule_for
    finally:
        with _status_poll_lock:
            _status_polls_in_flight -= 1


_node_refresh_min_interval_seconds: float = 0.5


def set_node_refresh_min_interval_seconds(seconds: float) -> None:
    """Ignored unless a non-negative number -- rc-typo tolerance, as every setter here. Zero is ALLOWED and means "no limit": it restores the old behaviour exactly, which is what a bisect or an A/B comparison needs."""
    global _node_refresh_min_interval_seconds
    if isinstance(seconds, (int, float)) and seconds >= 0:
        _node_refresh_min_interval_seconds = float(seconds)


def get_node_refresh_min_interval_seconds() -> float:
    return _node_refresh_min_interval_seconds


_log_follow_repin_seconds: float = 30.0


def set_log_follow_repin_seconds(seconds: float) -> None:
    """Ignored unless a non-negative number. Zero is ALLOWED -- see the note."""
    global _log_follow_repin_seconds
    if isinstance(seconds, (int, float)) and seconds >= 0:
        _log_follow_repin_seconds = float(seconds)


def get_log_follow_repin_seconds() -> float:
    return _log_follow_repin_seconds


_node_follow_frontier_rows: int = 3


def set_node_follow_frontier_rows(rows: int) -> None:
    """Ignored unless a non-negative int. Zero is ALLOWED and disables."""
    global _node_follow_frontier_rows
    if isinstance(rows, int) and not isinstance(rows, bool) and rows >= 0:
        _node_follow_frontier_rows = rows


def get_node_follow_frontier_rows() -> int:
    return _node_follow_frontier_rows


_node_follow_repin_seconds: float = 30.0


def set_node_follow_repin_seconds(seconds: float) -> None:
    """Ignored unless a non-negative number. Zero is ALLOWED and means never resume -- a manual scroll then holds until the fan-out ends."""
    global _node_follow_repin_seconds
    if isinstance(seconds, (int, float)) and seconds >= 0:
        _node_follow_repin_seconds = float(seconds)


def get_node_follow_repin_seconds() -> float:
    return _node_follow_repin_seconds


_log_repeat_window_seconds: float = 5.0


def set_log_repeat_window_seconds(seconds: float) -> None:
    """Ignored unless a non-negative number. Zero is ALLOWED and disables."""
    global _log_repeat_window_seconds
    if isinstance(seconds, (int, float)) and seconds >= 0:
        _log_repeat_window_seconds = float(seconds)


def get_log_repeat_window_seconds() -> float:
    return _log_repeat_window_seconds


_prompt_probe_mode: str = "eager"


PROMPT_PROBE_MODES = ("eager", "deferred")


def set_prompt_probe_mode(mode: str) -> None:
    """Ignored unless a known mode, keeping the previous one."""
    global _prompt_probe_mode
    if mode in PROMPT_PROBE_MODES:
        _prompt_probe_mode = mode


def get_prompt_probe_mode() -> str:
    """The current mode. Compared against `"eager"` at exactly ONE site."""
    return _prompt_probe_mode


def set_reset_retry_delay_seconds(seconds: float) -> None:
    global _reset_retry_delay_seconds
    if isinstance(seconds, (int, float)) and seconds >= 0:
        _reset_retry_delay_seconds = float(seconds)


def get_reset_retry_delay_seconds() -> float:
    return _reset_retry_delay_seconds


_ws_handshake_timeout_seconds: float = 5.0


def set_ws_handshake_timeout_seconds(seconds: float) -> None:
    global _ws_handshake_timeout_seconds
    if isinstance(seconds, (int, float)) and seconds > 0:
        _ws_handshake_timeout_seconds = float(seconds)


def get_ws_handshake_timeout_seconds() -> float:
    return _ws_handshake_timeout_seconds


def set_warmup_retry_delays_seconds(delays: tuple[float, ...]) -> None:
    global _warmup_retry_delays_seconds
    if delays and all(isinstance(d, (int, float)) and d >= 0 for d in delays):
        _warmup_retry_delays_seconds = tuple(float(d) for d in delays)


def get_warmup_retry_delays_seconds() -> tuple[float, ...]:
    return _warmup_retry_delays_seconds


_throttle_max_retries: int = 5
_throttle_backoff_base_seconds: float = 1.0


def set_throttle_max_retries(n: int) -> None:
    global _throttle_max_retries
    if isinstance(n, int) and n >= 0:
        _throttle_max_retries = n


def get_throttle_max_retries() -> int:
    return _throttle_max_retries


def set_throttle_backoff_base_seconds(seconds: float) -> None:
    global _throttle_backoff_base_seconds
    if isinstance(seconds, (int, float)) and seconds >= 0:
        _throttle_backoff_base_seconds = float(seconds)


def get_throttle_backoff_base_seconds() -> float:
    return _throttle_backoff_base_seconds


_heartbeat_interval_seconds: int = 270
_heartbeat_ws_ping_interval_seconds: int = 15
_heartbeat_retry_interval_seconds: int = 60
_heartbeat_max_retries: int = 3


def set_heartbeat_interval_seconds(seconds: int) -> None:
    global _heartbeat_interval_seconds
    if isinstance(seconds, int) and seconds > 0:
        _heartbeat_interval_seconds = seconds


def get_heartbeat_interval_seconds() -> int:
    return _heartbeat_interval_seconds


def set_heartbeat_ws_ping_interval_seconds(seconds: int) -> None:
    global _heartbeat_ws_ping_interval_seconds
    if isinstance(seconds, int) and seconds > 0:
        _heartbeat_ws_ping_interval_seconds = seconds


def get_heartbeat_ws_ping_interval_seconds() -> int:
    return _heartbeat_ws_ping_interval_seconds


_credential_reproject_interval_seconds = 1200


def set_credential_reproject_interval_seconds(seconds: int) -> None:
    global _credential_reproject_interval_seconds
    if isinstance(seconds, int) and seconds > 0:
        _credential_reproject_interval_seconds = seconds


def get_credential_reproject_interval_seconds() -> int:
    return _credential_reproject_interval_seconds


_credential_refresh_fraction = 0.8


def set_credential_refresh_fraction(fraction: float) -> None:


    global _credential_refresh_fraction
    if isinstance(fraction, (int, float)) and 0.0 < float(fraction) <= 1.0:
        _credential_refresh_fraction = float(fraction)


def get_credential_refresh_fraction() -> float:
    return _credential_refresh_fraction


_log_buffer_lines = 5000


def set_log_buffer_lines(lines: int) -> None:


    global _log_buffer_lines
    if isinstance(lines, int) and lines >= 50:
        _log_buffer_lines = lines


def get_log_buffer_lines() -> int:
    return _log_buffer_lines


def set_heartbeat_retry_interval_seconds(seconds: int) -> None:
    global _heartbeat_retry_interval_seconds
    if isinstance(seconds, int) and seconds > 0:
        _heartbeat_retry_interval_seconds = seconds


def get_heartbeat_retry_interval_seconds() -> int:
    return _heartbeat_retry_interval_seconds


def set_heartbeat_max_retries(n: int) -> None:
    global _heartbeat_max_retries
    if isinstance(n, int) and n >= 0:
        _heartbeat_max_retries = n


def get_heartbeat_max_retries() -> int:
    return _heartbeat_max_retries


_supervisor_poll_seconds: float = 5.0


def set_supervisor_poll_seconds(seconds: float) -> None:
    global _supervisor_poll_seconds
    if isinstance(seconds, (int, float)) and seconds > 0:
        _supervisor_poll_seconds = float(seconds)


def get_supervisor_poll_seconds() -> float:
    return _supervisor_poll_seconds


_supervisor_max_recoveries: int = 4


def set_supervisor_max_recoveries(n: int) -> None:


    global _supervisor_max_recoveries
    if isinstance(n, int) and n >= 1:
        _supervisor_max_recoveries = n


def get_supervisor_max_recoveries() -> int:
    return _supervisor_max_recoveries


_frame_trace: bool = False


def set_frame_trace(enabled: bool) -> None:
    global _frame_trace
    _frame_trace = bool(enabled)


def get_frame_trace() -> bool:
    return _frame_trace
