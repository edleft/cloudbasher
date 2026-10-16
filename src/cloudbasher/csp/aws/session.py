#!/usr/bin/env python3
"""AWS CloudShell session management over WebSocket."""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from dataclasses import replace as _dc_replace
from typing import Any, Callable, Optional

from cloudbasher.core.exceptions import CommandOutcomeUnknown, SessionError
from cloudbasher.core.session.activity import SessionActivity
from cloudbasher.core.session.exit_code_spike import (
    build_begin_marker,
    build_command_frame,
    build_liveness_probe,
    command_frame_completed,
    command_frame_mode_enabled,
    extract_command_frame,
    extract_interrupted_command_frame,
)
from cloudbasher.core.session.quiet import with_history_off
from cloudbasher.core.shutdown import tearing_down
from cloudbasher.core.utils.output import (
    clean_pty_text,
    cut_at_begin_marker,
    detail,
    extract_output,
    log,
    mask_secrets,
    normalize_line_breaks,
    out_ts,
    own_output_present,
    prompt_terminates,
)
from cloudbasher.core.utils.timeline import mark, record_span
from cloudbasher.core.utils.timeline import span as timeline_span
from cloudbasher.csp.aws.api import DEFAULT_SESSION_TYPE, SessionRole
from cloudbasher.csp.aws.protocol import CloudShellWsSession, require_ws
from cloudbasher.csp.base import CloudShellSession

try:
    from websocket import WebSocketConnectionClosedException
except ImportError:  # pragma: no cover - matches protocol.py's optional-dependency guard
    WebSocketConnectionClosedException = ()  # type: ignore[assignment,misc]


_PROMPT_RE = re.compile(r"~\s*\$\s*$")
_PROMPT_ANY_RE = re.compile(r"[\$#]\s*$")


def _calling_frame() -> str:
    """`thread:function` for whoever drove us into a connect."""
    import threading
    import traceback

    for frame in reversed(traceback.extract_stack()[:-2]):
        if "csp/aws/session.py" not in frame.filename:
            return f"{threading.current_thread().name}:{frame.name}"
    return threading.current_thread().name


class _NoMarkedOutput(SessionError):
    """The command's own printed marker never appeared in what came back."""

    def __init__(self, message: str, *, frames: int = 0, begin_marker: str) -> None:
        super().__init__(message)
        self.frames = frames


        self.begin_marker = begin_marker


@dataclass(frozen=True, slots=True)
class RebuildKnobs:
    """The settings that legitimately differ between one kind of socket rebuild and another, resolved in ONE place."""


    prompt_budget_s: float

    create_retries: Optional[int]

    confirm_ready: bool

    name: str


def _attribution(elapsed: float, rebuild_seconds: float, probe_seconds: float) -> str:
    """Where a cold-shell recovery's seconds went, as one human-readable clause."""
    waiting = max(0.0, elapsed - rebuild_seconds - probe_seconds)
    return (
        f"{rebuild_seconds:.1f}s rebuilding, "
        f"{probe_seconds:.1f}s probing, {waiting:.1f}s waiting"
    )


class AWSSession(CloudShellSession):
    """AWS CloudShell WebSocket session."""


    raw_exec_output_has_command_echo = False

    @property
    def raw_exec_output_is_framed(self) -> bool:
        return command_frame_mode_enabled()


    PROBE_RETRY_DELAYS_SECONDS: tuple[float, ...] = (0.0, 1.0, 2.0, 4.0)


    READY_TIMEOUT_SECONDS: float = 10.0


    WARMUP_TIMEOUT_SECONDS: float = 15.0


    WARMUP_DRAIN_POLL_SECONDS: float = 0.15


    PRE_SEND_DRAIN_SECONDS: float = 0.05


    PRE_SEND_DRAIN_BUDGET_SECONDS: float = 0.5
    WARMUP_DRAIN_BUDGET_SECONDS: float = 0.5


    BOOTSTRAP_PROBE_ENABLED: bool = True


    _NAP_SLICE_SECONDS: float = 0.25


    COLD_SHELL_BUDGET_SECONDS: float = 300.0


    COLD_SHELL_REBUILD_SECONDS: float = 30.0


    COLD_SHELL_WARMUP_SECONDS: float = 3.0


    COLD_SHELL_CREATE_RETRIES: int = 1

    COLD_SHELL_POLL_SECONDS: float = 5.0
    HEARTBEAT_SECONDS: int = 15


    WARMUP_RETRY_DELAYS_SECONDS: tuple[float, ...] = (15.0, 45.0)
    RESET_RETRY_DELAY_SECONDS: float = 2.0

    def __init__(
        self,
        *,
        stream_url: str,
        token_value: str,
        environment_id: str,
        timeout: int = 60,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
        api_client: Any = None,
        session_id: Optional[str] = None,
        session_type: Optional[str] = None,
        bootstrap_probe: Optional[bool] = None,
    ) -> None:


        self._set_session_type(session_type)


        if bootstrap_probe is not None:
            self.BOOTSTRAP_PROBE_ENABLED = bootstrap_probe
        self.stream_url = stream_url
        self.token_value = token_value
        self.environment_id = environment_id
        self.timeout = timeout
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure
        self.api_client = api_client


        self.session_id: Optional[str] = session_id
        self.ws = None
        self._seq_counter: int = 0
        self._captured_prompt: Optional[str] = None
        self._pending_command_frame: Optional[Any] = None


        self._last_prompt_for_display: Optional[str] = None


        self._retired: bool = False
        self._page: Optional[Any] = None
        self._pw_browser: Optional[Any] = None
        self._pw_context: Optional[Any] = None
        self._websocket_dead: bool = False
        self._warmup_saw_prompt: bool = False


        self._ready_evidence: dict[str, Any] = {}


        self._connect_lock = threading.RLock()
        self._generation: int = 0
        self._generation_at_send: int = 0


        self._exec_lock = threading.RLock()


        self._input_send_lock = threading.Lock()


        self.activity: SessionActivity = SessionActivity.IDLE
        self.on_activity_change: Callable[[], None] = lambda: None


        self._activity_depth: int = 0


    def _take_ws(self) -> Any:
        """Remove the handle, then close what was there. Returns it, or None."""
        ws, self.ws = self.ws, None
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        return ws

    def _require_ws(self) -> Any:
        """`self.ws`, or a failure that says the socket is gone. `#442`."""
        return require_ws(self.ws, where="AWSSession.ws")

    def ensure_connected(self) -> None:
        """The public name for `_ensure_connected`. See `CloudShellSession`."""
        self._ensure_connected()

    def _ensure_connected(self) -> None:
        """Serialised entry point; the work is in _ensure_connected_locked()."""


        if self._retired:


            who = _calling_frame()
            mark("ws.connect_refused", caller=who, reason="retired")
            log(f"[session] refused a connect on a retired session, from {who}")
            raise SessionError(
                "this session was retired because its environment is being "
                "stopped; reconnect after .start rather than reusing it"
            )
        with self._connect_lock:
            if self.ws is not None:


                return
            self._ensure_connected_locked()
            self._generation += 1
            self.clear_shell_command_uncertainty()
            self.clear_shell_interrupt_request()

    def _set_session_type(self, session_type: Optional[str]) -> None:
        """Normalise and store the socket's `SessionType`. ONE definition."""
        self.session_type = (session_type or DEFAULT_SESSION_TYPE).upper()

    def adopt_stream_info(self, info: Any) -> None:
        """Take on the socket an `open_stream()` result describes."""
        from cloudbasher.csp.aws.api import session_kwargs_from_stream_info

        fields = session_kwargs_from_stream_info(info)
        self.stream_url = fields["stream_url"]
        self.token_value = fields["token_value"]
        self.session_id = fields["session_id"]


        self._set_session_type(fields["session_type"] or self.session_type)

    def _ensure_connected_locked(self) -> None:
        """Lazy-initialize WebSocket and validate the shell is actually responsive."""
        if self.ws is not None:
            return

        if not self.stream_url or not self.token_value:
            raise SessionError(
                "WebSocket connection requires stream_url and token_value from create_session API"
            )


        _WARMUP_RETRY_DELAYS = self.WARMUP_RETRY_DELAYS_SECONDS
        _RESET_RETRY_DELAY_SECONDS = self.RESET_RETRY_DELAY_SECONDS
        _warmup_exc: Optional[Exception] = None
        for _w_attempt in range(len(_WARMUP_RETRY_DELAYS) + 1):
            if _w_attempt > 0:
                if isinstance(_warmup_exc, WebSocketConnectionClosedException):
                    _delay = _RESET_RETRY_DELAY_SECONDS
                else:
                    _delay = _WARMUP_RETRY_DELAYS[_w_attempt - 1]
                log(
                    f"WebSocket: {getattr(self, '_ws_phase', 'warmup')} "
                    f"attempt={_w_attempt} failed; sleeping "
                    f"{_delay:.0f}s then refreshing token"
                )
                self._take_ws()
                time.sleep(_delay)
                if self.api_client is not None and self.environment_id:


                    from cloudbasher.csp.aws.api import (
                        retire_session_in_background,
                    )

                    _abandoned = getattr(self, "session_id", None)
                    if _abandoned:
                        retire_session_in_background(
                            self.api_client, self.environment_id, _abandoned
                        )


                    self.adopt_stream_info(
                        self.api_client.open_stream(
                            self.environment_id, session_type=self.session_type
                        )
                    )
            try:
                self._open_and_warmup()
                _warmup_exc = None
                break
            except Exception as exc:
                _warmup_exc = exc
                log(
                    f"WebSocket: {getattr(self, '_ws_phase', 'warmup')} "
                    f"attempt={_w_attempt + 1} failed error={exc}"
                )


                from cloudbasher.core.session.transport_faults import (
                    is_dns_resolution_failure,
                    is_fd_exhaustion,
                )


                if is_fd_exhaustion(exc):


                    exc.cb_failure_class = "local_resource_exhausted"  # type: ignore[attr-defined]
                    log(
                        "WebSocket: out of file descriptors -- not retrying "
                        "(every attempt consumes another)"
                    )
                    break
                if is_dns_resolution_failure(exc):
                    log(
                        "WebSocket: name did not resolve -- not retrying "
                        "(a backoff re-queries the same resolver)"
                    )
                    break

        if _warmup_exc is not None:


            raise SessionError(
                f"WebSocket warmup failed after {len(_WARMUP_RETRY_DELAYS) + 1} attempts "
                f"(api_client={self.api_client is not None}, "
                f"env_id={self.environment_id!r}): {_warmup_exc}"
            ) from _warmup_exc

        if not self.BOOTSTRAP_PROBE_ENABLED:


            log("WebSocket: bootstrap probe DISABLED; proceeding on warmup alone")
            return

        probe_error: Optional[Exception] = None
        probe_t0 = time.monotonic()
        probe_attempts = 0


        self._ready_evidence = {}
        for attempt, delay_seconds in enumerate(self.PROBE_RETRY_DELAYS_SECONDS, start=1):
            probe_attempts = attempt
            if delay_seconds > 0:
                time.sleep(delay_seconds)
            try:
                self._confirm_ready()
                probe_error = None
                break
            except Exception as exc:
                probe_error = exc
                log(f"WebSocket: probe attempt={attempt} failed error={exc}")
                try:
                    self._require_ws().send_ping()
                except Exception as ping_exc:


                    log(f"WebSocket: probe-retry ping failed error={ping_exc}")


        record_span(
            "ws.readiness",
            (time.monotonic() - probe_t0) * 1000,
            attempts=probe_attempts,
            confirmed=probe_error is None,
            warmup_saw_prompt=self._warmup_saw_prompt,


            **{f"ready_{k}": v for k, v in self._ready_evidence.items()},
        )

        if probe_error is not None:
            if self.api_client is not None and self.environment_id:
                log(
                    "WebSocket: all probes failed; replacing session for "
                    f"environment_id={self.environment_id}"
                )
                self._replace_probe_failed_session()
            else:
                raise SessionError(
                    f"WebSocket probe failed and session cannot be replaced "
                    f"(api_client={self.api_client is not None}, "
                    f"env_id={self.environment_id!r}): {probe_error}"
                )

        log("WebSocket: session ready")

    def _remember_prompt(self, stripped: str) -> None:
        """The ONE way `_captured_prompt` is set."""
        self._captured_prompt = stripped
        self._last_prompt_for_display = stripped

    def _open_and_warmup(self, *, prompt_budget_s: Optional[float] = None) -> None:
        """Open WebSocket, send token+resize, drain until '~ $' seen."""
        log(f"WebSocket: connecting environment_id={self.environment_id}")


        self._ws_phase = "handshake"
        self.ws = CloudShellWsSession(
            stream_url=self.stream_url,
            token_value=self.token_value,
            timeout=self.timeout,
            proxy_url=self.proxy_url,
            proxy_insecure=self.proxy_insecure,
        )


        ws = self._require_ws()
        with timeline_span("ws.handshake", caller=_calling_frame()):
            ws.connect()
        log("WebSocket: connected; sending token envelope + resize")
        self._ws_phase = "token-envelope"
        ws.send_token_envelope()


        self._seq_counter = 0
        if self.session_type == SessionRole.INTERACTIVE:
            ws.send_resize(cols=169, rows=26, sequence=self._seq_counter, flags=1)
            self._seq_counter += 1
        self._ws_phase = "warmup"


        warmup_budget = self.WARMUP_TIMEOUT_SECONDS if prompt_budget_s is None else prompt_budget_s
        warmup_deadline = time.time() + warmup_budget
        saw_output = False
        prompt_seen = False
        prompt_frame_index = 0
        warmup_chunks: list[str] = []
        warmup_t0 = time.monotonic()


        warmup_reads = 0
        warmup_bytes = 0
        warmup_exit = "deadline"
        while time.time() < warmup_deadline:


            ws = self._require_ws()
            frame = ws.receive_frame(
                timeout_seconds=self.WARMUP_DRAIN_POLL_SECONDS if prompt_seen else 1.0
            )
            warmup_reads += 1
            if frame is None:
                if prompt_seen:
                    warmup_exit = "prompt_drained"


                    break
                if not saw_output:


                    warmup_exit = "silent_no_output"


                    break


                ws.send_ping()
                continue
            if frame.message_type == "output_stream_data":
                saw_output = True
                ws.send_ack(frame)
                text = frame.payload.decode("utf-8", "replace") if frame.payload else ""
                warmup_bytes += len(frame.payload) if frame.payload else 0
                warmup_chunks.append(text)
                if not prompt_seen and "~ $" in clean_pty_text("".join(warmup_chunks)):


                    prompt_seen = True
                    prompt_frame_index = len(warmup_chunks)
                    warmup_deadline = time.time() + self.WARMUP_DRAIN_BUDGET_SECONDS
            elif frame.message_type == "acknowledge":
                continue


        self._warmup_saw_prompt = prompt_seen
        log(
            f"WebSocket: warmup={'ok' if saw_output else 'no_prompt_seen'} "
            f"prompt={'yes' if self._warmup_saw_prompt else 'no'}"
        )


        record_span(
            "ws.warmup",
            (time.monotonic() - warmup_t0) * 1000,
            saw_output=saw_output,
            saw_prompt=self._warmup_saw_prompt,
            drain_frames=len(warmup_chunks) - prompt_frame_index if prompt_seen else 0,
            timeout_budget_s=warmup_budget,
            frames=len(warmup_chunks),
            bytes=warmup_bytes,
            reads=warmup_reads,
            exit=warmup_exit,
        )


        all_warmup = clean_pty_text("".join(warmup_chunks))
        for line in reversed(all_warmup.splitlines()):
            stripped = line.strip()
            if stripped and _PROMPT_ANY_RE.search(stripped):
                self._remember_prompt(stripped)
                break


    def _collect_output_text(
        self,
        *,
        timeout_seconds: float,
        send_heartbeat: bool = True,
        stop_when: Optional[Callable[[str], bool]] = None,
    ) -> str:
        """Collect output frames for a fixed duration; return stripped clean text."""
        self._require_ws()
        started = time.time()
        next_ping = started + self.HEARTBEAT_SECONDS
        chunks: list[str] = []
        while time.time() - started < timeout_seconds:
            now = time.time()
            if send_heartbeat and now >= next_ping:
                try:
                    self._require_ws().send_ping()
                except Exception as ping_exc:


                    log(f"WebSocket: drain ping failed error={ping_exc}")
                next_ping = now + self.HEARTBEAT_SECONDS
            ws = self._require_ws()
            frame = ws.receive_frame(timeout_seconds=1.0)
            if frame is None:
                continue
            if frame.message_type == "acknowledge":
                continue
            if frame.message_type != "output_stream_data":
                continue
            ws.send_ack(frame)
            if frame.payload_type == 1 and frame.payload:
                chunks.append(frame.payload.decode("utf-8", "replace"))
                if stop_when is not None:


                    accumulated = clean_pty_text("".join(chunks))
                    if stop_when(accumulated):
                        return accumulated
        return clean_pty_text("".join(chunks))

    def _send_input_payload(self, text: str, *, payload_type: int = 1) -> None:
        """Send input bytes with the current sequence counter."""
        with self._input_send_lock:
            self._require_ws().send_input(
                text, sequence=self._seq_counter, payload_type=payload_type
            )
            self._seq_counter += 1

    def interrupt_shell_command(self) -> None:
        """Send ETX over the live CloudShell input stream."""
        self._send_input_payload("\x03")

    @staticmethod
    def _prompt_match_rule(text: str) -> Optional[str]:
        """WHICH rule accepted this text as a prompt, or None."""
        cleaned = text.rstrip()
        if not cleaned:
            return None
        if "~ $" in cleaned:
            return "tilde_prompt"
        lines = cleaned.splitlines()
        tail = lines[-1].strip() if lines else cleaned.strip()
        for suffix, rule in (("$", "tail_dollar"), ("#", "tail_hash"), ("%", "tail_percent")):
            if tail.endswith(suffix):
                return rule
        return None

    @staticmethod
    def _looks_like_shell_prompt(text: str) -> bool:
        """True when the tail of the text looks like a shell prompt."""
        return AWSSession._prompt_match_rule(text) is not None

    def _await_prompt(self, timeout_seconds: float) -> bool:
        """Wait for a prompt. **Sends nothing.** Returns on first evidence."""
        self._require_ws()
        deadline = time.time() + timeout_seconds
        next_ping = time.time() + self.HEARTBEAT_SECONDS
        chunks: list[str] = []


        await_reads = 0
        await_bytes = 0
        self._ready_evidence = {
            "by": "await",
            "frames": 0,
            "bytes": 0,
            "reads": 0,
            "rule": None,
        }
        while time.time() < deadline:
            now = time.time()
            if now >= next_ping:
                try:
                    self._require_ws().send_ping()
                except Exception as ping_exc:


                    log(f"WebSocket: read-until ping failed error={ping_exc}")
                next_ping = now + self.HEARTBEAT_SECONDS
            ws = self._require_ws()
            frame = ws.receive_frame(timeout_seconds=1.0)
            await_reads += 1
            if frame is None or frame.message_type != "output_stream_data":
                continue
            ws.send_ack(frame)
            if frame.payload_type == 1 and frame.payload:
                await_bytes += len(frame.payload)
                chunks.append(frame.payload.decode("utf-8", "replace"))
                text = clean_pty_text("".join(chunks))
                rule = self._prompt_match_rule(text)
                if rule is not None:
                    self._ready_evidence.update(
                        frames=len(chunks),
                        bytes=await_bytes,
                        reads=await_reads,
                        rule=rule,
                    )
                    for line in reversed(text.splitlines()):
                        stripped = line.strip()
                        if stripped and _PROMPT_ANY_RE.search(stripped):
                            self._remember_prompt(stripped)
                            break
                    return True
        self._ready_evidence.update(
            frames=len(chunks),
            bytes=await_bytes,
            reads=await_reads,
            rule=None,
        )
        return False

    def _confirm_ready(self) -> None:
        """Confirm the shell is ready to accept input, replacing the older multi-step warmup probe: the session is ready when the prompt is present, not when the socket opens."""
        if self._warmup_saw_prompt:


            self._ready_evidence = {"by": "warmup", "rule": "tilde_prompt"}
            return
        if not self._await_prompt(self.READY_TIMEOUT_SECONDS):
            raise SessionError(
                f"shell never produced a prompt within {self.READY_TIMEOUT_SECONDS:.0f}s "
                "of the WebSocket opening"
            )

    def _recover_cold_shell(self) -> bool:
        """Recover a shell that has a prompt but cannot yet RUN anything."""
        if self.api_client is None or not self.environment_id:


            log(
                "WebSocket: cold shell suspected but no api_client/environment_id "
                "to build a fresh session on; handing back to the reconnect"
            )
            record_span(
                "ws.cold_shell",
                0.0,
                attempts=0,
                rebuilds=0,
                executable=False,
                reason="no_api_client",
            )
            return False

        if tearing_down():


            log("WebSocket: cold shell suspected but the process is tearing down")
            record_span(
                "ws.cold_shell", 0.0, attempts=0, rebuilds=0, executable=False, reason="teardown"
            )
            return False

        if self._retired:


            log(
                "WebSocket: cold shell suspected but this session is retired "
                "(.stop is in progress); not rebuilding"
            )
            record_span(
                "ws.cold_shell", 0.0, attempts=0, rebuilds=0, executable=False, reason="retired"
            )
            return False


        t0 = time.monotonic()
        deadline = t0 + self.COLD_SHELL_BUDGET_SECONDS


        out_ts(
            "WebSocket: the shell has a prompt but is not executing yet; this "
            f"window is the container's (~130s measured) and the current socket "
            f"does not survive it, so rebuilding a fresh session every "
            f"{self.COLD_SHELL_REBUILD_SECONDS:.0f}s for up to "
            f"{self.COLD_SHELL_BUDGET_SECONDS:.0f}s"
        )
        attempts = 0
        rebuilds = 0
        rebuild_failures = 0
        last_rebuild: Optional[float] = None


        rebuild_seconds = 0.0
        probe_seconds = 0.0


        entry_activity = self.activity
        self._publish(entry_activity.recovering(deadline))
        try:
            while time.monotonic() < deadline:


                due = (
                    last_rebuild is None
                    or time.monotonic() - last_rebuild >= self.COLD_SHELL_REBUILD_SECONDS
                )
                if self._retired or tearing_down():


                    why = ".stop" if self._retired else "process teardown"
                    log(
                        f"WebSocket: session retired mid-ladder ({why}); stopping "
                        f"after {rebuilds} fresh socket(s), {attempts} probes"
                    )
                    record_span(
                        "ws.cold_shell",
                        (time.monotonic() - t0) * 1000,
                        attempts=attempts,
                        rebuilds=rebuilds,
                        rebuild_failures=rebuild_failures,
                        rebuild_seconds=round(rebuild_seconds, 1),
                        probe_seconds=round(probe_seconds, 1),
                        executable=False,
                        reason="retired_mid_ladder" if self._retired else "teardown_mid_ladder",
                    )
                    return False
                if due:
                    rebuild_started = time.monotonic()
                    try:


                        with self._connect_lock:


                            self._replace_probe_failed_session(cold_shell=True)
                        rebuilds += 1
                        rebuild_cost = time.monotonic() - rebuild_started
                        rebuild_seconds += rebuild_cost
                        record_span(
                            "ws.cold_shell.rebuild",
                            rebuild_cost * 1000,
                            ordinal=rebuilds,
                            ok=True,
                            elapsed_s=round(rebuild_started - t0, 1),
                        )


                        last_rebuild = (
                            rebuild_started
                            if rebuild_cost < self.COLD_SHELL_REBUILD_SECONDS
                            else time.monotonic()
                        )


                        self._publish(
                            _dc_replace(self.activity, rebuilds=rebuilds, attempts=attempts)
                        )


                        out_ts(
                            f"WebSocket: cold-shell rebuild {rebuilds} "
                            f"({time.monotonic() - t0:.0f}s elapsed, "
                            f"{deadline - time.monotonic():.0f}s of budget left)"
                        )
                    except Exception as exc:
                        rebuild_failures += 1
                        rebuild_seconds += time.monotonic() - rebuild_started
                        record_span(
                            "ws.cold_shell.rebuild",
                            (time.monotonic() - rebuild_started) * 1000,
                            ordinal=rebuilds + 1,
                            ok=False,
                            error=type(exc).__name__,
                            elapsed_s=round(rebuild_started - t0, 1),
                        )
                        log(
                            f"WebSocket: cold-shell rebuild failed "
                            f"({type(exc).__name__}: {exc}); next rebuild in "
                            f"{self.COLD_SHELL_REBUILD_SECONDS:.0f}s, "
                            f"{deadline - time.monotonic():.0f}s of budget left"
                        )


                        last_rebuild = time.monotonic()
                        self._nap(time.monotonic(), deadline)
                        continue

                if self.ws is None:


                    log(
                        "WebSocket: no socket to probe (last rebuild failed); "
                        f"waiting {self.COLD_SHELL_REBUILD_SECONDS:.0f}s for the next"
                    )
                    self._nap(time.monotonic(), deadline)
                    continue

                attempts += 1


                self._publish(_dc_replace(self.activity, attempts=attempts), poke=False)
                probe_started = time.monotonic()
                probe, probe_marker = build_liveness_probe()
                try:
                    self._send_input_payload(probe + "\r")


                    text = self._collect_output_text(
                        timeout_seconds=self.COLD_SHELL_POLL_SECONDS,

                        stop_when=lambda acc: probe_marker in acc,
                    )
                except Exception as exc:


                    log(
                        f"WebSocket: cold-shell probe on the new socket could not "
                        f"reach the wire ({exc})"
                    )
                    text = ""


                probe_seconds += time.monotonic() - probe_started

                if probe_marker in text:
                    elapsed = time.monotonic() - t0
                    out_ts(
                        f"WebSocket: shell became executable after {elapsed:.1f}s "
                        f"({rebuilds} fresh socket(s), {attempts} probes; "
                        f"{_attribution(elapsed, rebuild_seconds, probe_seconds)})"
                    )
                    record_span(
                        "ws.cold_shell",
                        elapsed * 1000,
                        attempts=attempts,
                        rebuilds=rebuilds,
                        rebuild_failures=rebuild_failures,
                        rebuild_seconds=round(rebuild_seconds, 1),
                        probe_seconds=round(probe_seconds, 1),
                        executable=True,
                        reason="fresh_socket",
                    )
                    return True
                self._nap(probe_started, deadline)


            out_ts(
                f"WebSocket: shell still not executing after "
                f"{self.COLD_SHELL_BUDGET_SECONDS:.0f}s "
                f"({rebuilds} fresh socket(s), {rebuild_failures} rebuild "
                f"failure(s), {attempts} probes; "
                f"{_attribution(time.monotonic() - t0, rebuild_seconds, probe_seconds)})"
                "; falling back to a reconnect"
            )
            record_span(
                "ws.cold_shell",
                (time.monotonic() - t0) * 1000,
                attempts=attempts,
                rebuilds=rebuilds,
                rebuild_failures=rebuild_failures,
                rebuild_seconds=round(rebuild_seconds, 1),
                probe_seconds=round(probe_seconds, 1),
                executable=False,
                reason="budget",
            )
            return False
        finally:


            self._publish(entry_activity.recovered(time.monotonic() - t0))

    def _nap(self, since: float, deadline: float) -> None:
        """Pace one poll interval measured from ``since``, never past ``deadline``."""
        spent = time.monotonic() - since
        nap = min(self.COLD_SHELL_POLL_SECONDS - spent, deadline - time.monotonic())


        remaining = nap
        while remaining > 0:
            if tearing_down():
                return
            slice_seconds = min(self._NAP_SLICE_SECONDS, remaining)
            time.sleep(slice_seconds)
            remaining -= slice_seconds

    def _rebuild_knobs(self, *, cold_shell: bool) -> RebuildKnobs:
        """The one place that says how the two kinds of rebuild differ."""
        if cold_shell:
            return RebuildKnobs(
                name="cold_shell",


                prompt_budget_s=self.COLD_SHELL_WARMUP_SECONDS,


                create_retries=self.COLD_SHELL_CREATE_RETRIES,


                confirm_ready=False,
            )
        return RebuildKnobs(
            name="normal",
            prompt_budget_s=self.WARMUP_TIMEOUT_SECONDS,
            create_retries=None,
            confirm_ready=True,
        )

    def _replace_probe_failed_session(self, *, cold_shell: bool = False) -> None:
        """Recreate /createSession and reconnect."""
        if self.api_client is None or not self.environment_id:
            raise SessionError("Cannot replace session: api_client or environment_id missing")


        self._take_ws()
        self._seq_counter = 0
        self._captured_prompt = None


        self._retire_session(background=True)
        knobs = self._rebuild_knobs(cold_shell=cold_shell)
        self.adopt_stream_info(
            self.api_client.open_stream(
                self.environment_id,


                session_type=self.session_type,
                max_retries=knobs.create_retries,
            )
        )
        if not self.stream_url or not self.token_value:
            raise SessionError(
                "Session replacement: /createSession did not return stream_url/token_value"
            )


        self._open_and_warmup(prompt_budget_s=knobs.prompt_budget_s)
        if knobs.confirm_ready:
            self._confirm_ready()

    def set_playwright_page(self, page: Any) -> None:
        """Store a Playwright Page for WebSocket fallback execution."""
        self._page = page

    def set_control_plane_identity(self, verdict: str) -> None:
        """Record whether this session's console can SIGN a control-plane call."""
        self.cb_control_plane_identity = verdict

    def set_playwright_handles(self, *, browser: Any, context: Any) -> None:
        """Take ownership of the browser and context backing set_playwright_page()."""
        self._pw_browser = browser
        self._pw_context = context

    def exec_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        raw: bool = False,
        *,
        recover: bool = True,
        record_history: bool = False,
    ) -> str:
        """Execute a shell command and return output."""
        if record_history:
            return self.exec_in_shell(
                command,
                timeout=timeout,
                raw=raw,
                recover=recover,
                record_history=True,
            )
        return self.exec_in_shell(command, timeout=timeout, raw=raw, recover=recover)

    def _publish(self, activity: SessionActivity, *, poke: bool = True) -> None:
        """Rebind `activity`, and optionally ask for a repaint."""
        self.activity = activity
        if poke:
            try:
                self.on_activity_change()
            except Exception:
                pass

    def exec_in_shell(
        self,
        command: str,
        timeout: Optional[int] = None,
        raw: bool = False,
        lock_wait: Optional[float] = None,
        recover: bool = True,
        record_history: bool = False,
    ) -> str:
        """Execute command in persistent shell, one at a time, with one retry."""


        if self.is_condemned:
            raise SessionError(f"this session handle is no longer usable: {self.condemned_reason}")
        self.assert_shell_command_safe()


        history_entry = command if record_history else None
        command = with_history_off(self, command)
        wait_budget = float(
            lock_wait
            if lock_wait is not None
            else (timeout if timeout is not None else self.timeout)
        )
        if not self._exec_lock.acquire(blocking=False):


            log(f"WebSocket: command queued behind a running one command={command!r}")
            if not self._exec_lock.acquire(timeout=wait_budget):
                raise SessionError(
                    f"another command is still running on this session; waited "
                    f"{wait_budget:.0f}s for it to finish"
                )


        outermost = self._activity_depth == 0
        self._activity_depth += 1
        if outermost:
            self._publish(SessionActivity.running(command))
        try:
            if history_entry is not None:
                return self._exec_in_shell_serialised(
                    command,
                    timeout=timeout,
                    raw=raw,
                    recover=recover,
                    history_entry=history_entry,
                )
            return self._exec_in_shell_serialised(
                command, timeout=timeout, raw=raw, recover=recover
            )
        finally:
            self._activity_depth -= 1
            if self._activity_depth == 0:
                self._publish(self.activity.idle())
            self._exec_lock.release()

    def _exec_in_shell_serialised(
        self,
        command: str,
        timeout: Optional[int] = None,
        raw: bool = False,
        recover: bool = True,
        history_entry: Optional[str] = None,
    ) -> str:
        """The body of exec_in_shell, run with ``_exec_lock`` held."""
        if not recover and self._websocket_dead:


            raise SessionError("websocket is dead and recovery was not requested")

        def execute_once(command_text: str, **kwargs: Any) -> str:
            if history_entry is not None:
                kwargs["history_entry"] = history_entry
            return self._exec_in_shell_once(
                command_text, timeout=timeout, raw=raw, **kwargs
            )

        def reconnect(first_exc: SessionError, *, cold_shell: bool = False) -> str:
            kwargs: dict[str, Any] = {}
            if cold_shell:
                kwargs["cold_shell"] = True
            if history_entry is not None:
                kwargs["history_entry"] = history_entry
            return self._reconnect_and_retry(
                command, timeout, raw, first_exc, **kwargs
            )

        if self._websocket_dead and self._page is not None:
            from cloudbasher.csp.aws.browser import playwright_fallback_execute

            log("[browser] WebSocket dead — routing command via playwright_fallback_execute")
            return playwright_fallback_execute(
                self._page,
                command,
                timeout=timeout or self.timeout,
            )


        try:
            return execute_once(command)
        except CommandOutcomeUnknown:


            self.mark_shell_command_uncertain()
            raise
        except _NoMarkedOutput as no_marker:
            if not recover:


                raise


            stale = self._drain_before_send()
            if no_marker.begin_marker and no_marker.begin_marker in clean_pty_text(stale):
                log(
                    "WebSocket: the output arrived late -- collecting it rather "
                    "than re-sending (the command is already running)"
                )
                mark("ws.marked_output_arrived_late", reason="no_marked_output")
                try:
                    return execute_once(
                        command,
                        send=False,
                        seed=stale,


                        begin_marker=no_marker.begin_marker,
                    )
                except SessionError as collect_exc:
                    return reconnect(collect_exc)


            if no_marker.frames == 0 and self._captured_prompt is not None:
                mark("ws.cold_shell_suspected", reason="zero_frames_after_prompt")
                if self._recover_cold_shell():
                    try:
                        return execute_once(command)
                    except SessionError as cold_exc:
                        return reconnect(cold_exc, cold_shell=True)


                log(
                    "WebSocket: cold-shell ladder exhausted; reconnecting rather "
                    "than re-sending on a socket that is not carrying traffic"
                )
                return reconnect(no_marker, cold_shell=True)
            log(
                f"WebSocket: no marked output, and the marker is not in the buffer "
                f"either; re-sending on the same socket command={command!r}"
            )
            mark("ws.resend_same_socket", reason="no_marked_output")
            try:
                return execute_once(command, seed=stale)
            except SessionError as retry_exc:
                return reconnect(retry_exc)
        except SessionError as first_exc:
            if not recover:
                raise
            return reconnect(first_exc)

    def _reconnect_and_retry(
        self,
        command: str,
        timeout: Optional[int],
        raw: bool,
        first_exc: SessionError,
        *,
        cold_shell: bool = False,
        history_entry: Optional[str] = None,
    ) -> str:
        """Rebuild the socket and try once more; the last resort."""
        if cold_shell:
            log(f"WebSocket: cold shell recovery; rebuilding the socket " f"command={command!r}")
        else:
            log(f"WebSocket: command failed; reconnecting and retrying " f"command={command!r}")
        try:
            with self._connect_lock:
                if self._generation != self._generation_at_send:


                    log(
                        "WebSocket: session already rebuilt by another caller "
                        f"(generation {self._generation_at_send} -> {self._generation}); "
                        "retrying on it rather than reconnecting again"
                    )
                else:


                    self._take_ws()
                    self._seq_counter = 0
                    self._captured_prompt = None
            if history_entry is not None:
                return self._exec_in_shell_once(
                    command,
                    timeout=timeout,
                    raw=raw,
                    history_entry=history_entry,
                )
            return self._exec_in_shell_once(command, timeout=timeout, raw=raw)
        except Exception:
            if self._page is not None:
                log(
                    "[browser] WebSocket retry failed — marking dead, "
                    "switching to playwright fallback"
                )
                self._websocket_dead = True
                from cloudbasher.csp.aws.browser import playwright_fallback_execute

                return playwright_fallback_execute(
                    self._page,
                    command,
                    timeout=timeout or self.timeout,
                )
            raise first_exc

    def _drain_before_send(self) -> str:
        """Consume anything already buffered, so this command reads only its own output. Returns the discarded TEXT, **raw** -- not folded, not stripped."""
        if self.ws is None:
            return ""
        chunks: list[str] = []
        drained_sequences: list[int] = []


        consumed = 0
        deadline = time.monotonic() + self.PRE_SEND_DRAIN_BUDGET_SECONDS
        try:
            while time.monotonic() < deadline:
                ws = self._require_ws()
                frame = ws.receive_frame(timeout_seconds=self.PRE_SEND_DRAIN_SECONDS)
                if frame is None:
                    break
                if frame.message_type == "output_stream_data":
                    ws.send_ack(frame)
                    consumed += 1


                    drained_sequences.append(frame.sequence)
                    if frame.payload_type == 1 and frame.payload:
                        chunks.append(frame.payload.decode("utf-8", "replace"))
        except Exception as exc:
            detail(f"WebSocket: pre-send drain stopped early: {exc}")
        text = "".join(chunks)
        if consumed:
            log(f"WebSocket: discarded {consumed} stale frame(s) before sending")


            detail(f"WebSocket: drained text={mask_secrets(clean_pty_text(text))[:200]!r}")
            detail(f"WebSocket: drained sequences={drained_sequences}")
            mark(
                "ws.presend_drain",
                frames=consumed,
                text_frames=len(chunks),
                sequences=",".join(str(n) for n in drained_sequences),


                redelivered=getattr(self.ws, "redelivered_output_frames", -1),
            )
        return text

    def _is_complete(self, clean_text: str, command: str, begin_marker: str) -> bool:
        """Has this command finished, on THIS buffer? (`#754(c)`)"""
        return prompt_terminates(
            clean_text,
            command,
            captured_prompt=self._captured_prompt,
            prompt_re=_PROMPT_RE,


            begin_marker=begin_marker,
        )

    def _exec_in_shell_once(
        self,
        command: str,
        timeout: Optional[int] = None,
        raw: bool = False,
        *,
        send: bool = True,
        seed: str = "",
        begin_marker: Optional[str] = None,
        history_entry: Optional[str] = None,
    ) -> str:
        """Execute command in persistent shell (single attempt)."""
        if not send and not begin_marker:
            raise SessionError(
                "internal: collecting output for a command already on the wire "
                "requires the marker that command printed (`#802`)"
            )
        if send and begin_marker:


            raise SessionError(
                "internal: the begin marker is minted HERE when sending; "
                "pass one only with `send=False` (`#802`)"
            )
        self._ensure_connected()


        self._generation_at_send = self._generation
        timeout_seconds = float(timeout if timeout is not None else self.timeout)

        self._require_ws()
        command_frame = None
        framed_mode = command_frame_mode_enabled()

        try:
            if send:


                if framed_mode:
                    command_frame = build_command_frame(
                        command,
                        begin=build_begin_marker(),
                        history_enabled=True,
                        history_entry=history_entry,
                    )
                    begin_marker = command_frame.begin_marker
                    self._pending_command_frame = command_frame
                    command_wire = command_frame.wire_text.replace("\n", "\r")
                else:
                    begin_command, begin_marker = build_begin_marker()
                    command_wire = f"{begin_command}; {command}\r"
                self._drain_before_send()
                log(f"WebSocket: send command command={command!r} seq={self._seq_counter}")
                self._send_input_payload(command_wire)
            else:
                log(
                    f"WebSocket: collecting output for a command already on the wire "
                    f"command={command!r}"
                )
                if framed_mode:
                    command_frame = self._pending_command_frame
                    if command_frame is None or command_frame.begin_marker != begin_marker:
                        raise SessionError(
                            "internal: cannot collect framed output without the "
                            "original command frame"
                        )

            raw_output_chunks: list[str] = [seed] if seed else []
            clean_text = clean_pty_text(seed) if seed else ""
            started = time.time()
            next_ping = started + self.HEARTBEAT_SECONDS
            frame_count = 0
            byte_count = 0

            log("WebSocket: receiving output frames")
            command_completed = False
            while time.time() - started < timeout_seconds:
                if self.shell_interrupt_grace_expired():
                    raise CommandOutcomeUnknown(
                        "Ctrl-C was sent, but the shell did not finish within the 5-second "
                        "interrupt grace. Command outcome is unknown; reconnect before retrying."
                    )
                now = time.time()
                if now >= next_ping:


                    self._require_ws().send_ping()
                    next_ping = now + self.HEARTBEAT_SECONDS

                ws = self._require_ws()
                frame = ws.receive_frame(timeout_seconds=1.0)
                if frame is None:
                    continue

                if frame.message_type == "output_stream_data":
                    ws.send_ack(frame)
                    if frame.payload_type == 1 and frame.payload:
                        frame_count += 1
                        byte_count += len(frame.payload)
                        piece = frame.payload.decode("utf-8", "replace")
                        raw_output_chunks.append(piece)
                        clean_text = clean_pty_text("".join(raw_output_chunks))
                        completed = (
                            command_frame_completed(clean_text, command_frame)
                            if command_frame is not None
                            else self._is_complete(clean_text, command, begin_marker)
                        )
                        if completed:
                            command_completed = True
                            break
                        if (
                            getattr(self, "_shell_interrupt_requested_at", None) is not None
                            and command_frame
                        ):
                            interrupted_output = extract_interrupted_command_frame(
                                "".join(raw_output_chunks),
                                command_frame,
                                captured_prompt=self._captured_prompt,
                                prompt_re=_PROMPT_RE,
                                preserve_ansi=raw,
                            )
                            if interrupted_output is not None:
                                self._pending_command_frame = None
                                self.clear_shell_interrupt_request()
                                detail(
                                    "WebSocket: ETX returned shell to prompt; "
                                    "completed interrupted command without end marker"
                                )
                                return interrupted_output
                elif frame.message_type == "acknowledge":
                    continue

            elapsed = time.time() - started
            detail(
                f"WebSocket: command {'completed' if command_completed else 'read deadline'} "
                f"frames={frame_count} bytes={byte_count} elapsed={elapsed:.2f}s"
            )


            if command_frame is not None:
                begin_seen = command_frame.begin_marker in clean_text
                end_seen = command_frame_completed(clean_text, command_frame)
                if not command_completed and begin_seen:
                    raise CommandOutcomeUnknown(
                        f"The shell began the command but did not return its completion marker "
                        f"within {timeout_seconds:.0f}s; its outcome is unknown and "
                        "it was not retried."
                    )
                if not command_completed and not end_seen:
                    raise _NoMarkedOutput(
                        f"command produced no start/completion marker within "
                        f"{timeout_seconds:.0f}s "
                        f"(frames={frame_count}: stale content in the read buffer, a "
                        f"shell not yet executing, or a connection dropped after "
                        f"connect) command={command!r}",
                        frames=frame_count,
                        begin_marker=begin_marker,
                    )
            else:
                if not command_completed and own_output_present(clean_text, command, begin_marker):
                    raise CommandOutcomeUnknown(
                        f"The shell began the command but did not return a prompt within "
                        f"{timeout_seconds:.0f}s; its outcome is unknown and it was not retried."
                    )

                if not own_output_present(clean_text, command, begin_marker):
                    raise _NoMarkedOutput(
                        f"command produced no marked output within {timeout_seconds:.0f}s "
                        f"(frames={frame_count}: stale content in the read buffer, a "
                        f"shell not yet executing, or a connection dropped after "
                        f"connect) command={command!r}",
                        frames=frame_count,
                        begin_marker=begin_marker,
                    )

            if command_frame is not None:
                try:
                    output, _status = extract_command_frame(
                        "".join(raw_output_chunks),
                        command,
                        command_frame,


                        command_echo_present=True,
                        preserve_ansi=raw,
                    )
                except ValueError as exc:
                    raise CommandOutcomeUnknown(
                        "the completion marker arrived, but its output frame was inconsistent; "
                        "the command was not automatically retried"
                    ) from exc
                self._pending_command_frame = None
            else:


                for line in reversed(clean_text.splitlines()):
                    stripped = line.strip()
                    if stripped and _PROMPT_ANY_RE.search(stripped):
                        self._remember_prompt(stripped)
                        break

                if raw:
                    output = cut_at_begin_marker(
                        normalize_line_breaks("".join(raw_output_chunks)), begin_marker
                    )
                else:
                    output = extract_output(cut_at_begin_marker(clean_text, begin_marker), command)
            self.clear_shell_interrupt_request()
            return output

        except SessionError:
            raise
        except Exception as e:
            raise SessionError(f"Command execution failed: {e}") from e

    def upload_file(
        self,
        local_path: str,
        remote_path: str,
    ) -> None:
        """Upload local file to CloudShell via S3 presigned URL."""
        import os as _os
        import urllib.request as _req

        if self.api_client is None:
            raise SessionError("upload_file requires api_client for presigned URLs")

        urls = self.api_client.get_file_upload_urls(self.environment_id, remote_path)
        upload_url = urls.get("upload_url", "")
        upload_fields = urls.get("upload_fields", {})

        if not upload_url:
            raise SessionError("get_file_upload_urls did not return a URL")

        file_size = _os.path.getsize(local_path)
        with open(local_path, "rb") as fh:
            data = fh.read()

        if upload_fields:

            boundary = b"----CloudShellUploadBoundary"
            body_parts: list[bytes] = []
            for k, v in upload_fields.items():
                body_parts.append(
                    b"--" + boundary + b"\r\n"
                    b'Content-Disposition: form-data; name="'
                    + k.encode()
                    + b'"\r\n\r\n'
                    + str(v).encode()
                    + b"\r\n"
                )
            body_parts.append(
                b"--"
                + boundary
                + b"\r\n"
                + b'Content-Disposition: form-data; name="file"; filename="'
                + _os.path.basename(remote_path).encode()
                + b'"\r\n'
                + b"Content-Type: application/octet-stream\r\n\r\n"
                + data
                + b"\r\n"
            )
            body_parts.append(b"--" + boundary + b"--\r\n")
            body = b"".join(body_parts)
            content_type = b"multipart/form-data; boundary=" + boundary
            upload_req = _req.Request(
                upload_url,
                data=body,
                method="POST",
                headers={"Content-Type": content_type.decode()},
            )
        else:
            upload_req = _req.Request(upload_url, data=data, method="PUT")

        with _req.urlopen(upload_req, timeout=120) as resp:
            _ = resp.read()


        from cloudbasher.csp.aws.transfer import (
            BashHelperSession,
            build_exists_check,
            build_pull_command,
        )

        download_url = urls.get("download_url", "")
        download_key = urls.get("download_key", "")
        download_key_hash = urls.get("download_key_hash", "")
        if not download_url:
            raise SessionError(
                "get_file_upload_urls returned no FileDownloadPresignedUrl; the staged "
                "object cannot be pulled into the container"
            )

        with BashHelperSession(self.api_client, self.environment_id) as helper:


            existed = helper.run_checked(build_exists_check(remote_path), what="exists-check") == 0
            code = helper.run_checked(
                build_pull_command(
                    download_url=download_url,
                    destination_path=remote_path,
                    download_key=download_key,
                    download_key_hash=download_key_hash,
                ),
                what="pull-into-container",
            )
        if code != 0:
            raise SessionError(
                f"upload staged to S3 but the container-side fetch failed "
                f"(curl exit {code}); {remote_path} was not written"
            )

        log(
            f"[upload] local={local_path} remote={remote_path} bytes={file_size} "
            f"method=s3_presigned+bash_pull overwrote={existed}"
        )

    def download_file(
        self,
        remote_path: str,
        local_path: str,
    ) -> None:
        """Download file from CloudShell via S3 presigned URL."""
        import urllib.error as _err
        import urllib.request as _req

        if self.api_client is None:
            raise SessionError("download_file requires api_client for presigned URLs")

        urls = self.api_client.get_file_download_urls(self.environment_id, remote_path)
        download_url = urls.get("download_url", "")

        if not download_url:
            raise SessionError("get_file_download_urls did not return a URL")


        from cloudbasher.csp.aws.transfer import BashHelperSession, build_push_command

        upload_url = urls.get("upload_url", "")
        upload_fields = urls.get("upload_fields", {})
        if not upload_url:
            raise SessionError(
                "get_file_download_urls returned no FileUploadPresignedUrl; the container "
                "cannot stage the file for download"
            )

        with BashHelperSession(self.api_client, self.environment_id) as helper:
            code = helper.run_checked(
                build_push_command(
                    upload_url=upload_url,
                    upload_fields=upload_fields,
                    source_path=remote_path,
                ),
                what="stage-from-container",
            )
        if code != 0:
            raise SessionError(
                f"the container could not stage {remote_path} for download "
                f"(curl exit {code}); nothing was fetched"
            )


        download_key = urls.get("download_key", "")
        download_key_hash = urls.get("download_key_hash", "")
        get_req = _req.Request(
            download_url,
            method="GET",
            headers={
                "x-amz-server-side-encryption-customer-algorithm": "AES256",
                "x-amz-server-side-encryption-customer-key": download_key,
                "x-amz-server-side-encryption-customer-key-MD5": download_key_hash,
                "Accept": "*/*",
            },
        )
        try:
            with _req.urlopen(get_req, timeout=120) as resp:
                data = resp.read()
        except _err.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:400]
            raise SessionError(f"presigned download failed: HTTP {exc.code}; body={body}") from exc

        with open(local_path, "wb") as fh:
            fh.write(data)

        log(
            f"[download] remote={remote_path} local={local_path} bytes={len(data)} "
            "method=bash_stage+s3_presigned_ssec"
        )

    def open_shell(self) -> None:
        """Ensure the session's transport is genuinely open (idempotent)."""
        if self._websocket_dead and self._page is not None:
            return
        self._ensure_connected()

    def interactive_shell(self) -> None:
        """Drop into a raw WebSocket PTY loop: stdin → WS send_input, WS frames → stdout."""
        import sys as _sys
        import threading as _threading

        self._ensure_connected()
        log("WebSocket: interactive_shell started")


        _stop = _threading.Event()

        def _stdin_reader():
            while not _stop.is_set():
                try:
                    data = _sys.stdin.buffer.read1(256)  # type: ignore[attr-defined]
                    if data:


                        self._require_ws().send_input(
                            data.decode("utf-8", "replace"),
                            sequence=self._seq_counter,
                        )
                        self._seq_counter += 1
                except Exception:
                    break

        _reader = _threading.Thread(target=_stdin_reader, daemon=True)
        _reader.start()

        try:
            while True:
                ws = self._require_ws()
                frame = ws.receive_frame(timeout_seconds=0.5)
                if frame is None:
                    continue
                if frame.message_type == "output_stream_data":
                    ws.send_ack(frame)
                    if frame.payload_type == 1 and frame.payload:
                        _sys.stdout.buffer.write(frame.payload)
                        _sys.stdout.buffer.flush()
                elif frame.message_type == "acknowledge":
                    continue

                elif frame.message_type not in ("output_stream_data", "acknowledge"):
                    log(f"WebSocket: interactive_shell got {frame.message_type}, exiting")
                    break
        except KeyboardInterrupt:
            pass
        finally:
            _stop.set()
            log("WebSocket: interactive_shell exited")

    def detach_browser(self) -> Optional[dict[str, Any]]:
        """Give up the parked browser WITHOUT closing it, and RETURN its handles."""
        if self._page is None and self._pw_browser is None:
            return None
        handles = {
            "browser": self._pw_browser,
            "context": self._pw_context,
            "page": self._page,
        }
        self._page = None
        self._pw_browser = None
        self._pw_context = None
        self._websocket_dead = True
        return handles

    def _retire_session(self, *, background: bool = False) -> None:
        """`/deleteSession` for the SessionId this object currently holds, so a dropped or rebuilt socket does not strand a session server-side."""


        session_id = getattr(self, "session_id", None)
        self.session_id = None
        api_client = getattr(self, "api_client", None)
        environment_id = getattr(self, "environment_id", None)
        if not session_id or not api_client or not environment_id:
            return

        from cloudbasher.csp.aws.api import (
            retire_session_best_effort,
            retire_session_in_background,
        )

        if background:
            retire_session_in_background(api_client, environment_id, session_id)
        else:
            retire_session_best_effort(api_client, environment_id, session_id)

    def retire_server_session(self) -> None:
        """Retire the server-side session NOW, while the environment can accept it."""
        self._retired = True
        self._retire_session()

    def close(self) -> None:
        """Close the WebSocket connection and, on the console path, the browser that owns the session -- unless detach_browser() already gave it away."""
        self._take_ws()


        self._retire_session()
        self._close_playwright()

    def _close_playwright(self) -> None:
        """Tear down a parked browser, if this session has one."""
        if self._page is None and self._pw_browser is None:
            return
        from cloudbasher.csp.aws.browser import close_playwright_browser

        close_playwright_browser(self._pw_browser, self._pw_context, self._page)
        self._page = None
        self._pw_browser = None
        self._pw_context = None
