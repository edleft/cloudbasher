"""Utility functions."""

from .output import (
    eprint,
    is_log_console_echo_enabled,
    log,
    out,
    out_ts,
    set_console_output_sinks,
    set_log_console_echo,
    detail,
)

__all__ = [
    "out",
    "eprint",
    "out_ts",
    "log",
    "detail",
    "set_console_output_sinks",
    "set_log_console_echo",
    "is_log_console_echo_enabled",
]
