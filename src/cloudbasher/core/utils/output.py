"""Output formatting and logging utilities."""

from __future__ import annotations

import os
import re
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import IO, TYPE_CHECKING, Callable, Optional


from .redact import redact_text

_console_output_sink: Callable[[str], None] = lambda s: sys.stdout.write(s + "\n")
_console_error_sink: Callable[[str], None] = lambda s: sys.stderr.write(s + "\n")

_console_detail_sink: Optional[Callable[[str], None]] = None
_log_console_echo: bool = False

_log_file_handle: Optional[IO[str]] = None


_shutdown_started: bool = False


def begin_shutdown() -> None:
    """Silence all output sinks for the remainder of the process."""
    global _shutdown_started
    _shutdown_started = True


_ANSI_CSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_ESC_RE = re.compile(r"\x1b[@-_]")
_PROMPT_RE = re.compile(r"[\$#]\s*$", re.MULTILINE)
_ANSI_ANY_ESC_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])")


_SECRET_KEY_NAMES = (
    r"access[_-]?token|refresh[_-]?token|id[_-]?token|token[_-]?value"
    r"|secret[_-]?(?:access[_-]?)?key|session[_-]?(?:token|key)|security[_-]?token|api[_-]?key"
    r"|client[_-]?secret|auth(?:orization|[_-]?code)|redeem[_-]?code"
    r"|password|passwd"
)

_SECRET_KV_RE = re.compile(
    r"(?i)(" + _SECRET_KEY_NAMES + r")" r'(["\']?\s*[:=]\s*["\']?)' r"([A-Za-z0-9+/=._-]{8,})"
)


_SECRET_PCT_RE = re.compile(
    r"(?i)(%22(?:" + _SECRET_KEY_NAMES + r")%22(?:%20)*%3A(?:%20)*%22)"
    r"((?:[A-Za-z0-9+._~-]|%(?!22)[0-9A-Fa-f]{2}){8,})"
)
_BEARER_RE = re.compile(r"(?i)(bearer\s+)([A-Za-z0-9+/=._-]{8,})")


_AWS_ACCESS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b")


def obfuscate_secret(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "********" + value[-4:]


def masked_key_id(access_key: str) -> str:
    """A record-id token for an access key: masked, plus a short digest."""
    import hashlib

    return (
        f"{obfuscate_secret(access_key)}-"
        + hashlib.sha256(access_key.encode("utf-8")).hexdigest()[:6]
    )


def mask_secrets(text: str) -> str:
    """Mask secret values for terminal/TUI display — log file always receives raw text."""


    if "=" not in text and ":" not in text and "bearer" not in text.lower():
        return text
    text = _SECRET_KV_RE.sub(lambda m: m.group(1) + m.group(2) + obfuscate_secret(m.group(3)), text)
    text = _SECRET_PCT_RE.sub(lambda m: m.group(1) + obfuscate_secret(m.group(2)), text)
    text = _BEARER_RE.sub(lambda m: m.group(1) + obfuscate_secret(m.group(2)), text)
    return text


def scrub(text: str) -> str:
    """Both sweeps, in order -- for a surface handed text that has had neither."""
    return redact_text(mask_secrets(text))


_DEFAULT_OUT_SINK: Callable[[str], None] = lambda s: sys.stdout.write(s + "\n")
_DEFAULT_ERR_SINK: Callable[[str], None] = lambda s: sys.stderr.write(s + "\n")


def configure_output_logging(log_target: str) -> None:
    """Open a log file (or enable console echo for 'stdout'/'stderr')."""
    global _log_file_handle
    close_output_logging()
    if log_target in ("stdout", "stderr"):
        set_log_console_echo(True)
    else:
        _log_file_handle = open(log_target, "w", encoding="utf-8", buffering=1)


def close_output_logging() -> None:
    """Flush and close the log file if one is open."""
    global _log_file_handle
    if _log_file_handle is not None:
        try:
            _log_file_handle.flush()
            _log_file_handle.close()
        except Exception:
            pass
        _log_file_handle = None


from cloudbasher.core.utils.table_block import strip_table_marks  # noqa: E402


def _tee_log(message: str) -> None:
    """Write message to the log file if one is open (no-op otherwise)."""
    if _log_file_handle is not None:
        try:
            _log_file_handle.write(strip_table_marks(message) + "\n")
        except Exception:
            pass


def _redacting(sink: Optional[Callable[[str], None]]) -> Optional[Callable[[str], None]]:
    """Wrap a sink so redaction is applied on the way in."""
    if sink is None:
        return None
    return lambda s: sink(redact_text(s))


def set_console_output_sinks(
    out_sink: Optional[Callable[[str], None]] = None,
    err_sink: Optional[Callable[[str], None]] = None,
    detail_sink: Optional[Callable[[str], None]] = None,
    *,
    redacts_at_render: bool = False,
) -> None:
    """Set output sinks for TUI integration. Call with no args to reset to stdout/stderr."""
    global _console_output_sink, _console_error_sink, _console_detail_sink
    resolved_out = out_sink if out_sink is not None else _DEFAULT_OUT_SINK
    resolved_err = err_sink if err_sink is not None else _DEFAULT_ERR_SINK
    if redacts_at_render:
        _console_output_sink = resolved_out
        _console_error_sink = resolved_err
        _console_detail_sink = detail_sink
        return


    _console_output_sink = _redacting(resolved_out)  # type: ignore[assignment]
    _console_error_sink = _redacting(resolved_err)  # type: ignore[assignment]
    _console_detail_sink = _redacting(detail_sink)


def set_log_console_echo(enabled: bool) -> None:
    """Enable/disable verbose logging."""
    global _log_console_echo
    _log_console_echo = enabled


def is_log_console_echo_enabled() -> bool:
    """Check if verbose logging is enabled."""
    return _log_console_echo


def out(message: str) -> None:
    """Output to console (and tee to log file)."""
    if _shutdown_started:
        return
    _console_output_sink(mask_secrets(message))
    _tee_log(message)


def eprint(message: str) -> None:
    """Output error to console (and tee to log file)."""
    if _shutdown_started:
        return
    _console_error_sink(mask_secrets(message))
    _tee_log(message)


def out_ts(message: str) -> None:
    """Output with UTC ISO timestamp (matches log file format)."""
    out(f"[{_utc_ts()}] {message}")


def _utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_log_scope = threading.local()


@contextmanager
def log_scope(tag: str):
    """Prefix every `log()`/`detail()` line from THIS thread with `[tag]`."""
    previous = getattr(_log_scope, "tag", "")
    _log_scope.tag = f"{previous} {tag}".strip() if previous else tag
    try:
        yield
    finally:
        _log_scope.tag = previous


def _scoped(message: str) -> str:
    tag = getattr(_log_scope, "tag", "")
    return f"[{tag}] {message}" if tag else message


_REPEAT_DIGITS = re.compile(r"(?<![a-z]-)(?<![#\d])(?!\d{12}(?!\d))\d+")


_repeat_state: dict[str, tuple[float, int]] = {}
_repeat_lock = threading.Lock()


_REPEAT_KEY_SOFT_CAP = 512


_once_keys: dict[str, None] = {}


def _claim_once(key: str) -> bool:
    """True the FIRST time `key` is claimed, False afterwards. FIFO-bounded."""
    with _repeat_lock:
        if key in _once_keys:
            return False
        while len(_once_keys) >= _REPEAT_KEY_SOFT_CAP:
            _once_keys.pop(next(iter(_once_keys)), None)
        _once_keys[key] = None
        return True


def reset_log_repeat_state() -> None:
    """Forget every tracked shape AND every `once_key`. For tests, and for a session boundary."""
    with _repeat_lock:
        _repeat_state.clear()
        _once_keys.clear()


def _shape_key(message: str, axis: str = "") -> str:
    """The suppression key for `message` as seen by `axis`"""
    return f"{axis}\x00{_REPEAT_DIGITS.sub('#', message)}"


def _collapse_repeat(message: str, axis: str = "") -> Optional[str]:
    """`message` to show, annotated with what was swallowed -- or None to drop."""
    from cloudbasher.core.utils.perf_config import get_log_repeat_window_seconds

    window = get_log_repeat_window_seconds()
    if window <= 0:
        return message


    key = _shape_key(message, axis)
    now = time.monotonic()
    with _repeat_lock:


        last, swallowed = _repeat_state.pop(key, (None, 0))
        if last is not None and (now - last) < window:
            _repeat_state[key] = (last, swallowed + 1)
            return None
        while len(_repeat_state) >= _REPEAT_KEY_SOFT_CAP:
            _repeat_state.pop(next(iter(_repeat_state)), None)
        _repeat_state[key] = (now, 0)
    if swallowed:
        return (
            f"{message}   [+{swallowed} more like this in the last "
            f"{window:g}s -- the log file has every one]"
        )
    return message


def _emit_verbose(
    ts: str, level: str, message: str, once_key: Optional[str] = None, axis: str = ""
) -> None:
    """The ONE console route for `log()` and `detail()`."""


    sink = _console_detail_sink or (_console_output_sink if _log_console_echo else None)
    if sink is None:
        return


    if once_key is not None and not _claim_once(once_key):
        return


    shown = _collapse_repeat(mask_secrets(message), axis)
    if shown is None:
        return
    sink(f"[{ts}][{level}] {shown}")


def detail(message: str, *, axis: str = "") -> None:
    """Verbose/debug message → log file (DEBUG) + TUI log pane or stdout with -v."""
    if _shutdown_started:
        return
    ts = _utc_ts()
    message = _scoped(message)
    _tee_log(f"[{ts}][DEBUG] {message}")
    _emit_verbose(ts, "DEBUG", message, axis=axis)


def log(message: str, *, once_key: Optional[str] = None, axis: str = "") -> None:
    """Operational log message → log file (INFO) + TUI log pane or stdout with -v."""
    if _shutdown_started:
        return
    ts = _utc_ts()
    message = _scoped(message)
    _tee_log(f"[{ts}][INFO] {message}")
    _emit_verbose(ts, "INFO", message, once_key=once_key, axis=axis)


def log_file_only(message: str) -> None:
    """A record for the FILE and nothing else -- no TUI pane, no stdout"""
    if _shutdown_started:
        return
    _tee_log(f"[{_utc_ts()}][TRACE] {_scoped(message)}")


def _is_color_tty() -> bool:
    """Return True when stdout is a TTY that supports ANSI colors."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


if TYPE_CHECKING:  # pragma: no cover - typing only
    from rich.text import Text as RichText


def rich_to_ansi(text: "RichText") -> str:
    """A `rich.text.Text` rendered to a string carrying ANSI colour."""
    import io

    from rich.console import Console

    buf = io.StringIO()
    Console(
        file=buf,
        force_terminal=True,
        color_system="truecolor",
        width=10_000,
        soft_wrap=True,
        highlight=False,
        legacy_windows=False,
    ).print(text, end="")
    return buf.getvalue()


def strip_ansi(text: str) -> str:
    """Remove all ANSI escape sequences from text (colors, cursor movement, etc.)."""
    text = _ANSI_OSC_RE.sub("", text)
    text = _ANSI_CSI_RE.sub("", text)
    text = _ANSI_ESC_RE.sub("", text)


    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f]", "", text)
    return text


def _sgr_only(m: re.Match) -> str:
    seq = m.group(0)
    return seq if (seq.startswith("\x1b[") and seq.endswith("m")) else ""


def filter_tui_ansi(text: str) -> str:
    """Keep only SGR (color/bold) ANSI sequences; strip all others including C0 controls."""
    text = _ANSI_ANY_ESC_RE.sub(_sgr_only, text)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1a\x1c-\x1f]", "", text)
    return text


_LINE_BREAK_RE = re.compile(r"\r\n|[\r\v\f]")


def normalize_line_breaks(text: str) -> str:
    """Fold every cursor-to-next-row control into ` `, BEFORE `strip_ansi()`."""
    return _LINE_BREAK_RE.sub("\n", text)


def last_nonblank_line(text: str) -> str:
    """The last line with anything on it, or `""`. Why that matters is `prompt_terminates`'s second rule, and is stated there."""
    for line in reversed(text.splitlines()):
        if line.strip():
            return line
    return ""


def clean_pty_text(text: str) -> str:
    """Raw PTY bytes -> text safe to run line-boundary rules over."""
    return strip_ansi(normalize_line_breaks(text))


def render_pty_output(
    raw: str,
    command: str,
    *,
    color: bool = True,
    command_echo_present: bool = True,
    framed_output: bool = False,
) -> str:
    """One command's output out of a raw PTY read, ready to display"""
    folded = normalize_line_breaks(raw)
    clean = strip_ansi(folded)
    filtered = filter_tui_ansi(folded) if color else clean
    if framed_output is True:


        return filtered
    return raw_extract_output(clean, filtered, command if command_echo_present else "")


def cut_at_begin_marker(text: str, begin_marker: Optional[str]) -> str:
    """Everything AFTER the line carrying `begin_marker`. Unchanged if absent."""
    if not begin_marker:
        return text
    idx = text.find(begin_marker)
    if idx < 0:
        return text
    newline = text.find("\n", idx)
    return "" if newline < 0 else text[newline + 1 :]


def own_output_present(clean_text: str, sent_command: str, begin_marker: Optional[str]) -> bool:
    """Do these frames belong to the command we sent?"""
    if begin_marker:
        return begin_marker in clean_text
    return sent_command.strip() in clean_text


def prompt_terminates(
    clean_text: str,
    sent_command: str,
    *,
    captured_prompt: Optional[str],
    prompt_re: re.Pattern[str],
    begin_marker: Optional[str],
) -> bool:
    """Has the command finished, judged from the buffer so far? (`#754(c)`)"""
    if not own_output_present(clean_text, sent_command, begin_marker):
        return False
    last_line = last_nonblank_line(clean_text)
    if captured_prompt and captured_prompt in last_line:
        return True
    return bool(prompt_re.search(last_line))


def _find_echo_line_end(lines: list[str], sent_command: str) -> int:
    """Return the best command-echo boundary, searching the whole buffer."""
    sent_stripped = sent_command.strip()
    if not sent_stripped:
        return 0


    prompt_echo_end = 0
    exact_echo_end = 0
    suffix_echo_end = 0
    for i, line in enumerate(lines):
        candidate = line.rstrip()
        if not candidate.endswith(sent_stripped):
            continue
        prefix = candidate[: -len(sent_stripped)]
        if not prefix:
            exact_echo_end = i + 1
        elif re.search(r"[#$]\s+$", prefix):
            prompt_echo_end = i + 1
        else:
            suffix_echo_end = i + 1
    return prompt_echo_end or exact_echo_end or suffix_echo_end


def raw_extract_output(clean_text: str, raw_text: str, sent_command: str) -> str:
    """Extract command output preserving ANSI color codes."""
    clean_lines = clean_text.splitlines()
    raw_lines = raw_text.splitlines()
    start = _find_echo_line_end(clean_lines, sent_command)
    end = len(clean_lines)


    if end > start and _PROMPT_RE.search(clean_lines[end - 1]):
        end -= 1
    result = "\n".join(raw_lines[start:end])


    if not result.strip() and clean_text.strip():
        log(
            "raw_extract_output: DROPPED non-empty buffer "
            f"command_chars={len(sent_command)} start={start} end={end} "
            f"clean_lines={len(clean_lines)} raw_lines={len(raw_lines)} "
            f"clean_chars={len(clean_text)} raw_chars={len(raw_text)}"
        )
    return result


def extract_output(clean_text: str, sent_command: str) -> str:
    """Strip echoed command and trailing prompt from PTY output."""
    lines = clean_text.splitlines()
    start = _find_echo_line_end(lines, sent_command)


    end = len(lines)
    if end > start and _PROMPT_RE.search(lines[end - 1]):
        end -= 1

    return "\n".join(lines[start:end])
