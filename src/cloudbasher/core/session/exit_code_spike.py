"""Exit-code capture via marker-append + parse."""

from __future__ import annotations

import os
import re
import shlex
import threading
import time
from dataclasses import dataclass
from typing import Any, Optional

from cloudbasher.core.utils.output import strip_ansi

_MARKER_PREFIX = "__CLOUDBASHER_EXIT_"


_MARKER_LOCK = threading.Lock()
_MARKER_SEQ = 0


def command_frame_mode_enabled() -> bool:
    """Whether sessions use nonce-framed command execution."""
    mode = os.environ.get("CLOUDBASHER_COMMAND_FRAME_MODE", "framed").strip().lower()
    if mode not in {"framed", "legacy"}:
        raise ValueError(
            "CLOUDBASHER_COMMAND_FRAME_MODE must be 'framed' or 'legacy'"
        )
    return mode == "framed"


def wrap_command_with_exit_marker(command: str) -> tuple[str, str]:
    """Return (wrapped_command, marker)."""
    marker = _next_marker(_MARKER_PREFIX)
    wrapped = f'{command}; echo "{marker}$?"'
    return wrapped, marker


_LIVENESS_PREFIX = "__CLOUDBASHER_LIVE_"
_BEGIN_PREFIX = "__CLOUDBASHER_BEGIN_"
_END_PREFIX = "__CLOUDBASHER_END_"


_MARKER_SPLIT = 8


def _printf_split_literal(marker: str) -> str:
    """A command that PRINTS `marker`, written so its own echo cannot match it."""
    head, tail = marker[:_MARKER_SPLIT], marker[_MARKER_SPLIT:]
    return f' printf \'%s\\n\' "{head}""{tail}"'


def _next_marker(prefix: str) -> str:
    """A marker no other live command can be carrying."""
    global _MARKER_SEQ
    with _MARKER_LOCK:
        _MARKER_SEQ += 1
        seq = _MARKER_SEQ
    return f"{prefix}{time.time_ns()}_{seq}__"


def _build_printed_marker(prefix: str) -> tuple[str, str]:
    """Return (command, marker) for a fresh marker the shell will PRINT."""
    marker = _next_marker(prefix)
    return _printf_split_literal(marker), marker


def build_liveness_probe() -> tuple[str, str]:
    """Return (command, marker) for a probe that proves the shell EXECUTES."""
    command, marker = _build_printed_marker(_LIVENESS_PREFIX)
    return build_internal_shell_input(command), marker


def build_internal_shell_input(command: str) -> str:
    """Return one Bash input line that does not become a history entry."""
    return (
        ' if [[ ":${HISTCONTROL-}:" != *:ignorespace:* '
        '&& ":${HISTCONTROL-}:" != *:ignoreboth:* ]]; then '
        'history -d "$HISTCMD"; fi; ' + command
    )


def _build_history_state_diagnostic(marker: str, phase: str) -> str:
    """Emit history state/entry-count metadata without revealing history text."""
    return (
        "printf '%s|phase=%s|history=%s|histfile_set=%s|histfile_devnull=%s|"
        "histcontrol_ignorespace=%s|histsize_positive=%s|histcmd_numeric=%s|"
        "prompt_command_set=%s|prompt_history_append=%s|prompt_history_clear=%s|"
        "prompt_history_reload=%s|expanded_chars=%s|insert_status=%s|entries=%s\\n' "
        f"{shlex.quote(marker)} {shlex.quote(phase)} "
        '"$(set -o | awk \'$1 == "history" {print $2}\')" '
        '"$([[ -n ${HISTFILE-} ]] && printf yes || printf no)" '
        '"$([[ ${HISTFILE-} == /dev/null ]] && printf yes || printf no)" '
        '"$(case ":${HISTCONTROL-}:" in *:ignorespace:*|*:ignoreboth:*) '
        'printf yes ;; *) printf no ;; esac)" '
        '"$([[ ${HISTSIZE-} =~ ^[0-9]+$ ]] && (( HISTSIZE > 0 )) '
        '&& printf yes || printf no)" '
        '"$([[ ${HISTCMD-} =~ ^[0-9]+$ ]] && printf yes || printf no)" '
        '"$([[ -n ${PROMPT_COMMAND-} ]] && printf yes || printf no)" '
        '"$(case ${PROMPT_COMMAND-} in *\'history -a\'*) printf yes ;; *) printf no ;; esac)" '
        '"$(case ${PROMPT_COMMAND-} in *\'history -c\'*) printf yes ;; *) printf no ;; esac)" '
        '"$(case ${PROMPT_COMMAND-} in *\'history -r\'*) printf yes ;; *) printf no ;; esac)" '
        '"${#__CLOUDBASHER_HISTORY_EXPANDED_COMMAND-0}" '
        '"${__CLOUDBASHER_HISTORY_INSERT_STATUS-unknown}" '
        '"$(history | wc -l | tr -d \'[:space:]\')" >&2'
    )


def build_begin_marker() -> tuple[str, str]:
    """Return (prefix_command, marker) to put in FRONT of a real command."""
    return _build_printed_marker(_BEGIN_PREFIX)


@dataclass(frozen=True, slots=True)
class CommandFrame:
    """Wire framing and parser boundaries for one persistent-shell command."""

    wire_text: str
    begin_marker: str
    output_marker: str
    status_marker: str
    end_marker: str
    end_echo_sentinel: str
    history_state_marker: Optional[str] = None


def build_command_frame(
    command: str,
    *,
    begin: Optional[tuple[str, str]] = None,
    end_marker: Optional[str] = None,
    history_enabled: bool = False,
    history_entry: Optional[str] = None,
    diagnose_history: bool = False,
    history_file: Optional[str] = None,
) -> CommandFrame:
    """Wrap a shell command with ownership, output, status, and completion markers."""
    begin_command, begin_marker = begin or build_begin_marker()
    end_marker = end_marker or _next_marker(_END_PREFIX)
    status_marker = _next_marker(_MARKER_PREFIX)
    status_head, status_tail = status_marker[:_MARKER_SPLIT], status_marker[_MARKER_SPLIT:]
    end_head, end_tail = end_marker[:_MARKER_SPLIT], end_marker[_MARKER_SPLIT:]
    final_input_line = command.rstrip("\r\n")
    if history_entry is not None and not history_enabled:
        raise ValueError("history_entry requires history_enabled=True")
    if diagnose_history and not history_enabled:
        raise ValueError("diagnose_history requires history_enabled=True")
    if history_file is not None and not history_enabled:
        raise ValueError("history_file requires history_enabled=True")

    history_prefix: list[str] = []
    history_state_marker: Optional[str] = None
    output_marker = begin_marker
    if history_enabled:


        output_marker_command, output_marker = _build_printed_marker(_BEGIN_PREFIX)
        history_setup_command = (
            " if [[ -z ${__CLOUDBASHER_HISTORY_BRIDGE_READY+x} ]]; then "
            "set -o history; "
            "case \":${HISTCONTROL-}:\" in *:ignorespace:*|*:ignoreboth:*) ;; "
            "*) history -d \"$HISTCMD\"; "
            "HISTCONTROL=\"${HISTCONTROL:+${HISTCONTROL}:}ignorespace\" ;; esac; "
            "__CLOUDBASHER_HISTORY_BRIDGE_READY=1; "
            "elif [[ \":${HISTCONTROL-}:\" != *:ignorespace:* "
            "&& \":${HISTCONTROL-}:\" != *:ignoreboth:* ]]; then "
            "history -d \"$HISTCMD\"; fi"
        )
        if history_file:
            history_dir = history_file.rpartition("/")[0] or "."
            history_file_setup = (
                " if [[ -z ${__CLOUDBASHER_HISTORY_FILE_READY+x} ]] "
                f"&& [[ -d {shlex.quote(history_dir)} ]]; then "
                "__CLOUDBASHER_OLD_UMASK=$(umask); umask 077; "
                f"HISTFILE={shlex.quote(history_file)}; "
                ": > \"$HISTFILE\"; chmod 600 \"$HISTFILE\"; "
                "umask \"$__CLOUDBASHER_OLD_UMASK\"; "
                "unset __CLOUDBASHER_OLD_UMASK; export HISTFILE; "
                "__CLOUDBASHER_HISTORY_FILE_READY=1; fi; "
            )
            history_setup_command = history_file_setup + history_setup_command
        begin_command = f"{history_setup_command}; {begin_command}"
        if history_entry is not None:
            history_prefix.append(
                " if [[ \":${HISTCONTROL-}:\" != *:ignorespace:* "
                "&& \":${HISTCONTROL-}:\" != *:ignoreboth:* ]]; then "
                "history -d \"$HISTCMD\"; fi; "
                "__CLOUDBASHER_HISTORY_ORIGINAL_COMMAND="
                f"{shlex.quote(history_entry)}; "
                "__CLOUDBASHER_HISTORY_EXPANDED_COMMAND="
                '"$(history -p "$__CLOUDBASHER_HISTORY_ORIGINAL_COMMAND")"; '
                "if [[ -n \"$__CLOUDBASHER_HISTORY_EXPANDED_COMMAND\" ]]; then "
                "history -s \"$__CLOUDBASHER_HISTORY_EXPANDED_COMMAND\"; "
                "__CLOUDBASHER_HISTORY_INSERT_STATUS=$?; "
                "else __CLOUDBASHER_HISTORY_INSERT_STATUS=-1; fi"
            )
        if diagnose_history:
            history_state_marker = _next_marker("__CLOUDBASHER_HISTSTATE_")
            inline_diagnostic = _build_history_state_diagnostic(
                history_state_marker, "inline"
            )
            if history_prefix:
                history_prefix[-1] += "; " + inline_diagnostic
            else:
                history_prefix.append(" " + inline_diagnostic)


            history_prefix.append(
                " " + _build_history_state_diagnostic(history_state_marker, "after_prompt")
            )
    body_lines: list[str] = []
    if history_enabled:


        body_lines.append(
            "if [[ \":${HISTCONTROL-}:\" != *:ignorespace:* "
            "&& \":${HISTCONTROL-}:\" != *:ignoreboth:* ]]; then "
            "history -d \"$HISTCMD\"; fi"
        )
        if history_entry is not None:
            body_lines.append(
                "if [[ -n \"$__CLOUDBASHER_HISTORY_EXPANDED_COMMAND\" "
                "&& \"$__CLOUDBASHER_HISTORY_EXPANDED_COMMAND\" "
                '!= "$__CLOUDBASHER_HISTORY_ORIGINAL_COMMAND" ]]; then '
                "printf '%s\\n' \"$__CLOUDBASHER_HISTORY_EXPANDED_COMMAND\"; fi; "
                "unset __CLOUDBASHER_HISTORY_EXPANDED_COMMAND "
                "__CLOUDBASHER_HISTORY_ORIGINAL_COMMAND"
            )
    body_lines.append(final_input_line)


    command_group = "{\n" + "\n".join(body_lines) + "\n}"
    status_command = (
        f' printf \'%s%d\\n\' "{status_head}""{status_tail}" "$?"'
    )
    end_command = f' printf \'%s\\n\' "{end_head}""{end_tail}"'
    if history_enabled:
        wire_text = (
            f"{begin_command}\n"
            + "\n".join(history_prefix)
            + f"\n{output_marker_command}; {command_group};{status_command}\n"
            + f"{end_command}\n"
        )
    else:
        wire_text = f"{begin_command}; {command_group};{status_command}\n{end_command}\n"
    return CommandFrame(
        wire_text=wire_text,
        begin_marker=begin_marker,
        output_marker=output_marker,
        status_marker=status_marker,
        end_marker=end_marker,
        end_echo_sentinel=f'"{end_head}"',
        history_state_marker=history_state_marker,
    )


def command_frame_completed(clean_text: str, frame: CommandFrame) -> bool:
    """Return whether the independent final completion marker was observed."""
    return frame.end_marker in clean_text


def command_frame_exit_code(clean_text: str, frame: CommandFrame) -> Optional[int]:
    """Return the command's status, if its same-line status marker arrived."""
    match = re.search(re.escape(frame.status_marker) + r"(\d+)", clean_text)
    return int(match.group(1)) if match else None


def extract_command_frame(
    raw_text: str,
    command: str,
    frame: CommandFrame,
    *,
    command_echo_present: bool,
    preserve_ansi: bool = False,
    diagnostics: Optional[dict[str, Any]] = None,
) -> tuple[str, Optional[int]]:
    """Extract one command's output using the start/status/end sentinels."""
    from cloudbasher.core.utils.output import (
        _PROMPT_RE,
        normalize_line_breaks,
        raw_extract_output,
        strip_ansi,
    )

    folded_raw = normalize_line_breaks(raw_text)
    clean = strip_ansi(folded_raw)
    if not command_frame_completed(clean, frame):
        raise ValueError("command completion marker has not arrived")
    status = command_frame_exit_code(clean, frame)

    begin_at = clean.find(frame.begin_marker)
    output_at = clean.find(frame.output_marker) if begin_at >= 0 else -1
    if output_at >= 0:
        output_line_end = clean.find("\n", output_at)
        clean_start = output_line_end + 1 if output_line_end >= 0 else len(clean)
        raw_output_at = folded_raw.find(frame.output_marker)
        raw_output_end = folded_raw.find("\n", raw_output_at)
        raw_start = raw_output_end + 1 if raw_output_end >= 0 else len(folded_raw)
    elif begin_at >= 0:


        begin_line_end = clean.find("\n", begin_at)
        clean_start = begin_line_end + 1 if begin_line_end >= 0 else len(clean)
        raw_begin_at = folded_raw.find(frame.begin_marker)
        raw_begin_end = folded_raw.find("\n", raw_begin_at)
        raw_start = raw_begin_end + 1 if raw_begin_end >= 0 else len(folded_raw)
    else:


        clean_start = 0
        raw_start = 0

    end_echo_at = clean.find(frame.end_echo_sentinel, clean_start)
    end_marker_at = clean.find(frame.end_marker, clean_start)
    clean_end = end_echo_at if end_echo_at >= 0 else end_marker_at
    if clean_end < 0:
        raise ValueError("completion marker is present without its command boundary")
    raw_end_echo_at = folded_raw.find(frame.end_echo_sentinel, raw_start)
    raw_end_marker_at = folded_raw.find(frame.end_marker, raw_start)
    raw_end = raw_end_echo_at if raw_end_echo_at >= 0 else raw_end_marker_at
    if raw_end < 0:
        raise ValueError("raw completion boundary is missing")

    clean_section = clean[clean_start:clean_end]
    raw_section = folded_raw[raw_start:raw_end]


    status_match = re.search(re.escape(frame.status_marker) + r"(\d+)", clean_section)
    if status_match is not None:
        raw_status_at = raw_section.find(frame.status_marker)
        if raw_status_at < 0:
            raise ValueError("clean status marker is missing from raw completion frame")
        raw_status_end = raw_status_at + len(frame.status_marker)
        raw_status_digits = re.match(r"\d+", raw_section[raw_status_end:])
        if raw_status_digits is None:
            raise ValueError("raw status marker has no exit status")
        if int(raw_status_digits.group()) != status:
            raise ValueError("raw and clean status markers disagree")


        output_raw = raw_section[:raw_status_at]
        output_clean = clean_section[: status_match.start()]
        if begin_at < 0 and command_echo_present:
            if preserve_ansi:
                output = raw_extract_output(output_clean, output_raw, command)
            else:
                output = raw_extract_output(output_clean, output_clean, command)
        else:
            output = output_raw if preserve_ansi else output_clean


        if output.endswith("\n"):
            output = output[:-1]
        if diagnostics is not None:
            diagnostics.update(
                begin_marker_found=begin_at >= 0,
                output_marker_found=output_at >= 0,
                status_marker_found=True,
                end_marker_found=True,
                raw_frame_chars=len(raw_section),
                raw_output_region_chars=len(output_raw),
                clean_frame_chars=len(clean_section),
                clean_output_region_chars=len(output_clean),
                returned_output_chars=len(output),
            )
        return output, status


    clean_lines = clean_section.splitlines()
    raw_lines = raw_section.splitlines()


    if clean_lines and _PROMPT_RE.search(clean_lines[-1]):
        clean_lines.pop()
        if raw_lines:
            raw_lines.pop()
    clean_section = "\n".join(clean_lines)
    raw_section = "\n".join(raw_lines)

    if command_echo_present:
        if preserve_ansi:
            output = raw_extract_output(clean_section, raw_section, command)
        else:
            output = raw_extract_output(clean_section, clean_section, command)
    else:
        output = raw_section if preserve_ansi else strip_ansi(clean_section)
    return output, status


def extract_interrupted_command_frame(
    raw_text: str,
    frame: CommandFrame,
    *,
    captured_prompt: Optional[str],
    prompt_re: re.Pattern[str],
    preserve_ansi: bool = False,
) -> Optional[str]:
    """Extract partial output when ETX returned the shell to its prompt."""
    from cloudbasher.core.utils.output import normalize_line_breaks, strip_ansi

    folded_raw = normalize_line_breaks(raw_text)
    clean = strip_ansi(folded_raw)
    clean_lines = clean.splitlines(keepends=True)
    raw_lines = folded_raw.splitlines(keepends=True)
    if not clean_lines or len(clean_lines) != len(raw_lines):
        return None

    output_index = next(
        (index for index, line in enumerate(clean_lines) if frame.output_marker in line), None
    )
    if output_index is None:
        return None
    last_index = next(
        (index for index in range(len(clean_lines) - 1, -1, -1) if clean_lines[index].strip()),
        None,
    )
    if last_index is None or last_index <= output_index:
        return None

    last_line = clean_lines[last_index].strip()
    is_prompt = bool(
        (captured_prompt and captured_prompt in last_line) or prompt_re.search(last_line)
    )
    if not is_prompt:
        return None

    output_lines = (raw_lines if preserve_ansi else clean_lines)[output_index + 1 : last_index]
    output = "".join(output_lines)
    if output.endswith("\n"):
        output = output[:-1]
    return output


def parse_exit_code(raw_output: str, marker: str) -> tuple[str, Optional[int]]:
    """Return (output_with_marker_line_removed, exit_code)."""
    clean = strip_ansi(raw_output)
    match = re.search(re.escape(marker) + r"(\d+)", clean)
    if match is None:
        return raw_output, None
    exit_code = int(match.group(1))
    marker_line_re = re.compile(r"^.*" + re.escape(marker) + r"\d+.*$\n?", re.MULTILINE)
    cleaned = marker_line_re.sub("", clean)
    return cleaned.rstrip("\n"), exit_code


class CaptureUntrusted(Exception):
    """The command ran, and what came back cannot be believed. (`#754(c)`)"""

    def __init__(self, reason: str, raw_output: str, exit_code: Optional[int]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.raw_output = raw_output
        self.exit_code = exit_code


def capture_failure_reason(output: str, exit_code: Optional[int], marker: str) -> Optional[str]:
    """Why this capture cannot be trusted, or `None` if it can."""
    if exit_code is None:
        return "the exit-code marker never arrived -- the command's completion was not observed"
    if marker in output:
        return "the command echo came back as its output -- the marker survived extraction"
    return None


def exec_with_exit_code(
    session: Any, command: str, *, timeout: Optional[int] = None
) -> tuple[str, Optional[int]]:
    """Run `command` on `session` and return (output, exit_code)."""
    wrapped, marker = wrap_command_with_exit_marker(command)
    if timeout is not None:
        raw_output = session.exec_command(wrapped, timeout=timeout)
    else:
        raw_output = session.exec_command(wrapped)
    output, exit_code = parse_exit_code(raw_output, marker)
    reason = capture_failure_reason(output, exit_code, marker)
    if reason is not None:
        raise CaptureUntrusted(reason, output, exit_code)
    return output, exit_code
