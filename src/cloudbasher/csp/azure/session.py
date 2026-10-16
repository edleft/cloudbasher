"""Azure CloudShell WebSocket PTY session — connect, bootstrap, command execution."""

from __future__ import annotations

import json
import posixpath
import re
import shlex
import ssl
import threading
import time
import urllib.parse
import uuid
from collections import deque
from typing import Any, Optional

from cloudbasher.core.exceptions import (
    CloudShellAutomationError,
    CommandOutcomeUnknown,
    SessionError,
)
from cloudbasher.core.session.exit_code_spike import (
    build_begin_marker,
    build_command_frame,
    build_internal_shell_input,
    command_frame_completed,
    command_frame_mode_enabled,
    extract_command_frame,
    extract_interrupted_command_frame,
)
from cloudbasher.core.session.serialized_exec import SerializedExec
from cloudbasher.core.types import Credentials
from cloudbasher.core.utils.output import (
    cut_at_begin_marker,
    detail,
    filter_tui_ansi,
    log,
    mask_secrets,
    raw_extract_output,
    strip_ansi,
)
from cloudbasher.csp.azure.types import ConsoleInfo, TerminalInfo
from cloudbasher.csp.base import CloudShellSession

try:
    from websocket import (  # type: ignore[import]
        WebSocket,
        WebSocketTimeoutException,
        create_connection,
    )

    _WS_AVAILABLE = True
except ImportError:
    _WS_AVAILABLE = False
    WebSocket = None  # type: ignore[assignment,misc]
    WebSocketTimeoutException = Exception  # type: ignore[assignment,misc]
    create_connection = None  # type: ignore[assignment]


def ensure_websocket_available() -> None:
    if not _WS_AVAILABLE:
        raise SessionError(
            "websocket-client package not installed. Run: pip install websocket-client"
        )


_PROMPT_RE = re.compile(r"[\$#]\s*$")

_BANNER_DRAIN_SECONDS = 3.0
_BANNER_STEP_SECONDS = 0.5


_KNOWN_AUDIENCES = frozenset({"download", "token"})


def _safe_token_audience_label(value: str) -> str:
    """Render broker-supplied audience data as a safe, bounded log label."""
    try:
        host = urllib.parse.urlsplit(value).hostname or ""
    except (TypeError, ValueError):
        host = ""
    if host and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        return host.lower()
    return "unrecognized audience"


_MAX_CONTROL_FRAMES = 64


_DOWNLOAD_FRAME_SECONDS = 10.0
_DOWNLOAD_POLL_SECONDS = 0.25


def classify_frame(text: str) -> Optional[dict[str, Any]]:
    """Return the decoded control object if `text` is one, else None."""
    stripped = text.strip()

    if not stripped.startswith("{") or not stripped.endswith("}"):
        return None
    if '"audience"' not in stripped:
        return None
    try:
        obj = json.loads(stripped)
    except ValueError:
        return None


    if not isinstance(obj, dict) or not isinstance(obj.get("audience"), str):
        return None
    return obj


class AzureSession(SerializedExec, CloudShellSession):
    """Azure CloudShell WebSocket PTY session."""


    raw_exec_output_has_command_echo = False

    @property
    def raw_exec_output_is_framed(self) -> bool:
        return command_frame_mode_enabled()


    _EXEC_LABEL = "Azure WS"

    def __init__(
        self,
        console: ConsoleInfo,
        terminal: TerminalInfo,
        credentials: Credentials,
        *,
        timeout: float = 60.0,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
        api_client: Optional[Any] = None,
    ) -> None:
        ensure_websocket_available()
        self.console = console
        self.terminal = terminal
        self.credentials = credentials
        self.timeout = timeout
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure


        self._history_file = f"/tmp/.cloudbasher-history-{uuid.uuid4().hex}"


        self.quiet_history_file = self._history_file

        self._ws: Optional[Any] = None


        self._control_ws: Optional[Any] = None
        self._control_recv_lock = threading.Lock()


        self._send_lock = threading.Lock()
        self._captured_prompt: Optional[str] = None


        self._control_frames: deque[tuple[float, dict[str, Any]]] = deque(
            maxlen=_MAX_CONTROL_FRAMES
        )


        self._pending_text: deque[str] = deque()


        self._init_exec_serialization()


        if api_client is None:


            from cloudbasher.csp.azure.provider import AzureProvider

            api_client = AzureProvider().create_api_client(
                self.credentials,
                timeout=int(self.timeout),
                proxy_url=self.proxy_url,
                proxy_insecure=self.proxy_insecure,
            )
        self._api = api_client


    def exec_command(
        self, cmd: str, timeout: int = 60, raw: bool = False, *, record_history: bool = False
    ) -> str:
        """Execute command — delegates to exec_in_shell for Azure."""
        if record_history:
            return self.exec_in_shell(
                cmd, timeout=float(timeout), raw=raw, record_history=True
            )
        return self.exec_in_shell(cmd, timeout=float(timeout), raw=raw)

    def open_shell(self) -> None:
        """Connect and bootstrap the persistent shell."""
        if self._ws is None:
            self.connect()
        if self._captured_prompt is None:
            self.ensure_persistent_shell()

    def interactive_shell(self) -> None:
        """Not applicable for Azure: terminal is always the persistent WebSocket channel."""
        raise NotImplementedError(
            "AzureSession.interactive_shell() is not supported — "
            "use exec_in_shell() for all command execution."
        )


    def connect(self) -> None:
        """Establish WebSocket connection via Service Bus relay."""
        log("Getting Service Bus auth-token from /authorize...")
        try:
            auth_token = self._api.get_console_auth_token(self.console)
        except Exception as exc:
            raise SessionError(f"Failed to get auth-token: {exc}") from exc
        log(f"Got auth-token ({len(auth_token)} chars)")


        parsed = urllib.parse.urlparse(self.console.uri)
        relay_host = parsed.netloc
        console_path = parsed.path.strip("/")
        ws_url = f"wss://{relay_host}/$hc/{console_path}/terminals/{self.terminal.terminal_id}"
        detail(f"Connecting Service Bus WebSocket: {ws_url}")

        kwargs: dict[str, Any] = {
            "header": [
                f"Cookie: auth-token={auth_token}",
                "Origin: https://ux.console.azure.com",
            ],
            "timeout": self.timeout,
        }
        if self.proxy_url:
            parsed_proxy = urllib.parse.urlparse(self.proxy_url)
            kwargs["http_proxy_host"] = parsed_proxy.hostname
            kwargs["http_proxy_port"] = parsed_proxy.port
        if self.proxy_insecure and self.proxy_url:
            kwargs["sslopt"] = {"cert_reqs": ssl.CERT_NONE}

        try:
            self._ws = create_connection(ws_url, **kwargs)
        except Exception as exc:
            raise SessionError(f"WebSocket connect failed: {exc}") from exc
        try:
            self._control_ws = create_connection(ws_url + "/control", **kwargs)
        except Exception as exc:


            self._control_ws = None
            detail(
                "Azure control WebSocket unavailable; downloads disabled " f"({type(exc).__name__})"
            )

        self._ws.settimeout(5.0)
        if self._control_ws is not None:
            self._control_ws.settimeout(5.0)
        self.clear_shell_command_uncertainty()
        self.clear_shell_interrupt_request()
        log(f"WebSocket connected: terminal_id={self.terminal.terminal_id}")

    def close(self) -> None:
        if self._control_ws is not None:
            try:
                self._control_ws.close()
            except Exception:
                pass
            self._control_ws = None
        if self._ws is not None:
            try:
                self._ws.close()
            except Exception:
                pass
            self._ws = None
        self._captured_prompt = None


        self._pending_text.clear()

    def upload_file(self, local_path: str, remote_path: str) -> str:
        """Upload via the native endpoint, then place it at ``remote_path``."""
        response = self._api.upload_file(self.console, self.terminal, local_path, remote_path)
        upload_dir = response.get("path") if isinstance(response, dict) else None
        if not isinstance(upload_dir, str) or not upload_dir.startswith("/"):
            raise CloudShellAutomationError(
                "Azure upload succeeded without an absolute response path; refusing to claim "
                f"the requested destination {remote_path!r}"
            )
        uploaded_path = posixpath.join(upload_dir, posixpath.basename(local_path))
        target_path = (
            posixpath.normpath(remote_path)
            if remote_path.startswith("/")
            else posixpath.normpath(posixpath.join(upload_dir, remote_path))
        )
        allowed_prefix = upload_dir.rstrip("/") + "/"
        if not target_path.startswith(allowed_prefix):
            self.exec_in_shell(f"rm -f {shlex.quote(uploaded_path)}", timeout=float(self.timeout))
            raise CloudShellAutomationError(
                f"Azure native transfers support only {upload_dir!r}; use a relative path or "
                f"an absolute path below it, not {remote_path!r}"
            )
        if uploaded_path == target_path:
            return target_path
        self.exec_in_shell(
            f"mv -- {shlex.quote(uploaded_path)} {shlex.quote(target_path)}",
            timeout=float(self.timeout),
        )
        return target_path

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Download in three steps, the middle one arriving on the socket."""
        if self._ws is None:
            raise SessionError("Not connected — download needs the terminal WebSocket")
        if self._control_ws is None:
            raise CloudShellAutomationError(
                "Azure download needs the terminal control WebSocket, which was not connected"
            )


        with self._serialized_exec(f"<download {remote_path}>", _DOWNLOAD_FRAME_SECONDS):
            self._download_locked(remote_path, local_path)

    def _download_locked(self, remote_path: str, local_path: str) -> None:


        since = time.monotonic()
        self._api.request_download(self.console, self.terminal, remote_path)

        frame = self._await_download_frame(remote_path, since)
        if frame is None:
            raise CloudShellAutomationError(
                f'download of {remote_path} was accepted but no `audience: "download"` frame '
                f"named it within {_DOWNLOAD_FRAME_SECONDS:.0f}s. The socket is open and the POST "
                f"succeeded, so this is the service not announcing the file, not a transport "
                f"failure — check the path exists and is a file"
            )

        size = self._api.fetch_download(self.console, frame["fileUri"], local_path)
        detail(f"Downloaded {remote_path} → {local_path} ({size} bytes)")

    def _await_download_frame(self, remote_path: str, since: float) -> Optional[dict[str, Any]]:
        """Pump the socket until THIS download's frame arrives, or time out."""


        suffix = remote_path
        for prefix in ("./", "~/"):
            if suffix.startswith(prefix):
                suffix = suffix[len(prefix) :]

        def match() -> Optional[dict[str, Any]]:
            for f in self._control_frames_since(since, "download"):
                if not f.get("fileUri"):
                    continue
                path = str(f.get("filepath") or "")
                if path == remote_path or path.endswith("/" + suffix):
                    return f
            return None


        found = match()
        if found is not None:
            return found
        deadline = time.monotonic() + _DOWNLOAD_FRAME_SECONDS
        while time.monotonic() < deadline:
            if self._ws is None or self._control_ws is None:


                raise SessionError("connection closed while waiting for the download frame")


            self._recv_control_raw(timeout=_DOWNLOAD_POLL_SECONDS / 2)
            chunk = self._recv_raw(timeout=_DOWNLOAD_POLL_SECONDS / 2)
            if chunk:
                self._pending_text.append(chunk)
            found = match()
            if found is not None:
                return found
        return None

    def ping(self) -> None:
        """One RFC6455 ping frame -- layer 5, and the ONLY thing holding the relay."""
        if self._ws is None:
            raise SessionError("no WebSocket to ping")
        self._ws.ping()

    def send_relay_keepalive(self) -> None:
        """One empty TEXT frame (opcode 1, 0 bytes) -- the PORTAL's relay keepalive."""
        self._send_text("")

    def is_connected(self) -> bool:
        return self._ws is not None


    def ensure_persistent_shell(self) -> None:
        """Bootstrap the shell: drain banner, force colors, probe for readiness."""
        if self._captured_prompt is not None:
            return

        if self._ws is None:
            raise SessionError("Not connected — call connect() first")


        log("Draining CloudShell banner output...")
        banner_chunks: list[str] = []
        deadline = time.monotonic() + _BANNER_DRAIN_SECONDS
        while time.monotonic() < deadline:
            chunk = self._recv_text(timeout=_BANNER_STEP_SECONDS)
            if chunk:
                banner_chunks.append(chunk)

        banner_raw = "".join(banner_chunks)
        banner_clean = strip_ansi(banner_raw).replace("\r", "")
        detail(f"Banner drained: {len(banner_raw)} raw bytes")


        self._captured_prompt = ""
        for line in reversed(banner_clean.splitlines()):
            if line.strip():
                self._captured_prompt = line.rstrip()
                detail(f"Captured prompt: {self._captured_prompt!r}")
                break

        if not self._captured_prompt:
            detail("No prompt captured from banner; using regex fallback")


        self._send_text(
            build_internal_shell_input("export CLICOLOR_FORCE=1 FORCE_COLOR=1")
            + "\n"
        )


        time.sleep(0.1)
        drain_deadline = time.monotonic() + 1.0
        while time.monotonic() < drain_deadline:
            self._recv_text(timeout=0.3)


        marker = f"__AZURE_SHELL_READY_{time.time_ns()}__"
        self._send_text(
            build_internal_shell_input(f'printf "%s\\n" {shlex.quote(marker)}')
            + "\n"
        )

        probe_deadline = time.monotonic() + 10.0
        probe_buf = ""
        while time.monotonic() < probe_deadline:
            chunk = self._recv_text(timeout=1.0)
            if chunk:
                probe_buf += chunk
            if marker in strip_ansi(probe_buf):
                log("Shell probe succeeded — CloudShell shell is ready.")

                time.sleep(0.1)
                trail_deadline = time.monotonic() + 0.5
                while time.monotonic() < trail_deadline:
                    trail = self._recv_text(timeout=0.2)
                    if trail:
                        trail_clean = strip_ansi(trail).replace("\r", "")
                        for ln in reversed(trail_clean.splitlines()):
                            if ln.strip() and _PROMPT_RE.search(ln):
                                self._captured_prompt = ln.rstrip()
                                detail(f"Updated captured prompt: {self._captured_prompt!r}")
                                break
                return

        raise CloudShellAutomationError(
            f"Shell probe timed out after 10s — marker {marker!r} not seen. "
            f"Buffer: {strip_ansi(probe_buf)[-200:]!r}"
        )


    def exec_in_shell(
        self,
        command: str,
        *,
        timeout: Optional[float] = None,
        raw: bool = False,
        retry_on_session_error: bool = True,
        record_history: bool = False,
    ) -> str:
        """Execute command in the persistent shell, return output."""
        effective_timeout = timeout if timeout is not None else self.timeout
        self.assert_shell_command_safe()
        with self._serialized_exec(command, float(effective_timeout)):
            try:
                if record_history:
                    return self._exec_once(
                        command,
                        timeout=effective_timeout,
                        raw=raw,
                        record_history=True,
                    )
                return self._exec_once(command, timeout=effective_timeout, raw=raw)
            except CommandOutcomeUnknown:


                self.mark_shell_command_uncertain()
                raise
            except SessionError as exc:
                if not retry_on_session_error:
                    raise
                detail(f"exec_in_shell failed ({exc}); reconnecting and retrying")
                self.close()
                self.connect()
                self._captured_prompt = None
                self.ensure_persistent_shell()
                if record_history:
                    return self._exec_once(
                        command,
                        timeout=effective_timeout,
                        raw=raw,
                        record_history=True,
                    )
                return self._exec_once(command, timeout=effective_timeout, raw=raw)

    def _exec_once(
        self, command: str, *, timeout: float, raw: bool, record_history: bool = False
    ) -> str:
        """Dispatch through the shared frame protocol, with legacy rollback."""
        if not command_frame_mode_enabled():
            return self._exec_once_legacy(command, timeout=timeout, raw=raw)
        if record_history:
            return self._exec_once_framed(
                command, timeout=timeout, raw=raw, record_history=True
            )
        return self._exec_once_framed(command, timeout=timeout, raw=raw)

    def _exec_once_legacy(self, command: str, *, timeout: float, raw: bool) -> str:
        """Previous begin-marker + prompt completion path; rollback only."""
        if self._ws is None:
            raise SessionError("Not connected")
        self._pending_text.clear()
        begin_command, begin_marker = build_begin_marker()
        try:
            self._send_text(f"{begin_command}; {command}\n")
        except Exception as exc:
            raise CommandOutcomeUnknown(
                "command delivery is uncertain because the terminal write failed; "
                "the command was not automatically retried"
            ) from exc
        chunks: list[str] = []
        deadline = time.monotonic() + timeout
        last_ping = time.monotonic()
        while time.monotonic() < deadline:
            if self.shell_interrupt_grace_expired():
                raise CommandOutcomeUnknown(
                    "Ctrl-C was sent, but the shell did not finish within the 5-second "
                    "interrupt grace. Command outcome is unknown; reconnect before retrying."
                )
            if time.monotonic() - last_ping > 15.0:
                try:
                    self.ping()
                except Exception:
                    pass
                last_ping = time.monotonic()
            try:
                self._poll_control_during_exec()
                chunk = self._recv_text(timeout=0.99)
            except Exception as exc:
                raise CommandOutcomeUnknown(
                    "terminal connection failed before command completion was observed; "
                    "the remote command may still be running and was not retried"
                ) from exc
            if chunk:
                chunks.append(chunk)
            combined = "".join(chunks)
            if self._is_complete(
                combined, command, begin_marker=begin_marker, user_command=command
            ):
                drain_deadline = time.monotonic() + 0.4
                while time.monotonic() < drain_deadline:
                    try:
                        tail = self._recv_text(timeout=0.1)
                    except Exception:
                        break
                    if tail:
                        chunks.append(tail)
                self.clear_shell_interrupt_request()
                return self._process_output(
                    "".join(chunks), command, raw=raw, begin_marker=begin_marker
                )
        raise CommandOutcomeUnknown(
            f"No shell prompt arrived within {timeout}s; the remote command may still be "
            "running and was not automatically retried."
        )

    def _exec_once_framed(
        self,
        command: str,
        *,
        timeout: float,
        raw: bool,
        record_history: bool = False,
    ) -> str:
        """Single attempt at command execution."""
        if self._ws is None:
            raise SessionError("Not connected")


        self._pending_text.clear()
        frame = build_command_frame(
            command,
            begin=build_begin_marker(),
            history_enabled=True,
            history_entry=command if record_history else None,
            diagnose_history=record_history and bool(re.match(r"^\s*history(?:\s|$)", command)),
            history_file=self._history_file,
        )
        log(
            "Azure framed command sent "
            f"command_chars={len(command)} record_history={record_history} "
            f"wire_bytes={len(frame.wire_text.encode('utf-8'))}"
        )
        try:
            self._send_text(frame.wire_text)
        except Exception as exc:


            raise CommandOutcomeUnknown(
                "command delivery is uncertain because the terminal write failed; "
                "the command was not automatically retried"
            ) from exc

        chunks: list[str] = []
        deadline = time.monotonic() + timeout
        last_ping = time.monotonic()

        while time.monotonic() < deadline:
            if self.shell_interrupt_grace_expired():
                raise CommandOutcomeUnknown(
                    "Ctrl-C was sent, but the shell did not finish within the 5-second "
                    "interrupt grace. Command outcome is unknown; reconnect before retrying."
                )

            if time.monotonic() - last_ping > 15.0:
                try:
                    self.ping()
                except Exception:
                    pass
                last_ping = time.monotonic()


            try:
                self._poll_control_during_exec()
                chunk = self._recv_text(timeout=0.99)
            except Exception as exc:
                raise CommandOutcomeUnknown(
                    "terminal connection failed before command completion was observed; "
                    "the remote command may still be running and was not retried"
                ) from exc
            if chunk:
                chunks.append(chunk)

            combined = "".join(chunks)
            if command_frame_completed(strip_ansi(combined), frame):

                drain_deadline = time.monotonic() + 0.4
                while time.monotonic() < drain_deadline:
                    try:
                        tail = self._recv_text(timeout=0.1)
                    except Exception:
                        break
                    if tail:
                        chunks.append(tail)
                combined = "".join(chunks)
                try:
                    frame_diagnostics: dict[str, Any] = {}
                    output, status = extract_command_frame(
                        combined,
                        command,
                        frame,


                        command_echo_present=True,
                        preserve_ansi=raw,
                        diagnostics=frame_diagnostics,
                    )
                except ValueError as exc:
                    raise CommandOutcomeUnknown(
                        "the completion marker arrived, but its output frame was inconsistent; "
                        "the command was not automatically retried"
                    ) from exc
                self._last_command_exit_code = status
                self.clear_shell_interrupt_request()
                log(
                    "Azure framed command completed "
                    f"received_bytes={sum(len(chunk.encode('utf-8')) for chunk in chunks)} "
                    f"output_chars={len(output)} exit_code={status}"
                    + (
                        " parser="
                        + ",".join(f"{key}:{value}" for key, value in frame_diagnostics.items())
                        if frame_diagnostics
                        else ""
                    )
                )
                if frame.history_state_marker:
                    state_pattern = re.escape(frame.history_state_marker) + (
                        r"\|phase=(inline|after_prompt)\|history=(on|off)"
                        r"\|histfile_set=(yes|no)\|histfile_devnull=(yes|no)"
                        r"\|histcontrol_ignorespace=(yes|no)\|histsize_positive=(yes|no)"
                        r"\|histcmd_numeric=(yes|no)\|prompt_command_set=(yes|no)"
                        r"\|prompt_history_append=(yes|no)\|prompt_history_clear=(yes|no)"
                        r"\|prompt_history_reload=(yes|no)"
                        r"\|expanded_chars=(\d+)\|insert_status=(-?\d+|unknown)"
                        r"\|entries=(\d+)"
                    )
                    for state_match in re.finditer(state_pattern, strip_ansi(combined)):
                        log(
                            "Azure Bash history state "
                            + " ".join(
                                f"{name}={value}"
                                for name, value in zip(
                                    (
                                        "phase", "history", "histfile_set",
                                        "histfile_devnull", "histcontrol_ignorespace",
                                        "histsize_positive", "histcmd_numeric",
                                        "prompt_command_set", "prompt_history_append",
                                        "prompt_history_clear", "prompt_history_reload",
                                        "expanded_chars",
                                        "insert_status", "entries",
                                    ),
                                    state_match.groups(),
                                )
                            )
                        )
                    if not re.search(state_pattern, strip_ansi(combined)):
                        log("Azure Bash history state diagnostic_marker_received=False")
                return output
            if getattr(self, "_shell_interrupt_requested_at", None) is not None:
                interrupted_output = extract_interrupted_command_frame(
                    combined,
                    frame,
                    captured_prompt=self._captured_prompt,
                    prompt_re=_PROMPT_RE,
                    preserve_ansi=raw,
                )
                if interrupted_output is not None:


                    self._last_command_exit_code = None
                    self.clear_shell_interrupt_request()
                    detail(
                        "Azure terminal: ETX returned shell to prompt; "
                        "completed interrupted command without end marker"
                    )
                    return interrupted_output

        raise CommandOutcomeUnknown(
            f"No terminal completion marker arrived within {timeout}s; the remote command "
            "may still be running. It was not automatically retried."
        )

    def _is_complete(
        self,
        raw_text: str,
        command: str,
        *,
        begin_marker: Optional[str] = None,
        user_command: Optional[str] = None,
    ) -> bool:
        """Return True when the shell prompt reappears after the command."""
        clean = strip_ansi(raw_text).replace("\r", "")
        marker_seen = bool(begin_marker and begin_marker in clean)
        history_error = bool(
            begin_marker
            and not marker_seen
            and user_command is not None
            and self._history_expansion_rejected(clean, user_command)
        )
        if begin_marker and not marker_seen and not history_error:
            return False
        elif not begin_marker and command.strip() not in clean:
            return False
        last_line = ""
        for ln in reversed(clean.splitlines()):
            if ln.strip():
                last_line = ln
                break
        if not last_line:
            return False
        prompt_seen = bool(
            (self._captured_prompt and self._captured_prompt in last_line)
            or _PROMPT_RE.search(last_line)
        )
        if not prompt_seen:
            return False
        if history_error:


            return command.strip() in clean
        return True

    @staticmethod
    def _history_expansion_rejected(raw_text: str, user_command: str) -> bool:
        """Recognize only Bash's interactive history-expansion rejection."""
        clean = strip_ansi(raw_text).replace("\r", "")
        diagnostic = re.search(r"(?m)^bash: (![^\s:]+): event not found\s*$", clean)
        return bool(diagnostic and diagnostic.group(1) in user_command)

    def _process_output(
        self,
        raw_text: str,
        command: str,
        *,
        raw: bool,
        begin_marker: Optional[str] = None,
    ) -> str:
        """Extract one command's output, using its unique marker when supplied."""
        from cloudbasher.core.utils.output import extract_output

        raw_text = raw_text.replace("\r\n", "\n").replace("\r", "\n")
        if begin_marker:


            clean = strip_ansi(raw_text)
            if begin_marker not in clean:
                raise SessionError("Azure command completed without its output marker")
            clean_output = cut_at_begin_marker(clean, begin_marker)
            if raw:
                return raw_extract_output(
                    clean_output, cut_at_begin_marker(filter_tui_ansi(raw_text), begin_marker), ""
                )
            return extract_output(clean_output, "")
        if raw:
            filtered = filter_tui_ansi(raw_text)
            clean = strip_ansi(raw_text).replace("\r", "")
            output = raw_extract_output(clean, filtered, command)
        else:
            clean = strip_ansi(raw_text)
            output = extract_output(clean, command)

        return output


    def send_input(self, text: str) -> None:
        """Send raw text to the terminal (keystroke passthrough)."""
        self._send_text(text)

    def interrupt_shell_command(self) -> None:
        """Send the terminal's Ctrl-C byte without tearing down the WebSocket."""
        self._send_text("\x03")

    def receive_output(self, *, timeout: float = 5.0) -> Optional[str]:
        """Receive one chunk of terminal output. Returns None on timeout."""
        return self._recv_text(timeout=timeout)

    def resize(self, cols: int, rows: int) -> None:
        """Resize terminal via REST API call."""
        try:
            self._api.resize_terminal(self.console, self.terminal, cols, rows)
        except Exception as exc:
            detail(f"resize failed (non-fatal): {exc}")

    def _send_text(self, text: str) -> None:
        if self._ws is None:
            raise SessionError("Not connected")
        try:
            with self._send_lock:
                ws = self._ws
                if ws is None:
                    raise SessionError("Not connected")
                ws.send(text)
        except Exception as exc:
            if isinstance(exc, SessionError):
                raise
            raise SessionError(f"WebSocket send failed: {exc}") from exc

    def _recv_text(self, *, timeout: float) -> Optional[str]:
        """Receive one frame of TERMINAL text, or None."""
        if self._pending_text:
            return self._pending_text.popleft()
        return self._recv_raw(timeout=timeout)

    def _recv_raw(self, *, timeout: float) -> Optional[str]:
        """One frame off the socket, demultiplexed, ignoring pending text."""
        if self._ws is None:
            return None
        try:
            self._ws.settimeout(timeout)
            data = self._ws.recv()
            if isinstance(data, bytes):
                text = data.decode("utf-8", errors="replace")
            else:
                text = data
        except WebSocketTimeoutException:
            return None
        except Exception as exc:
            raise SessionError(f"WebSocket recv failed: {exc}") from exc

        control = classify_frame(text)
        if control is None:
            return text
        self._on_control_frame(control)
        return None

    def _recv_control_raw(self, *, timeout: float) -> None:
        """Receive and classify one companion-control frame."""
        with self._control_recv_lock:
            if self._control_ws is None:
                return
            try:
                self._control_ws.settimeout(timeout)
                data = self._control_ws.recv()
                text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
            except WebSocketTimeoutException:
                return
            except Exception as exc:
                raise SessionError(f"Azure control WebSocket recv failed: {exc}") from exc
            control = classify_frame(text)
            if control is not None:
                self._on_control_frame(control)

    def _poll_control_during_exec(self) -> None:
        """Poll optional broker control without retrying a running command."""
        try:
            self._recv_control_raw(timeout=0.01)
        except SessionError as exc:
            detail(
                "Azure control WebSocket lost during command; keeping the PTY "
                f"command live ({type(exc).__name__})."
            )
            control = self._control_ws
            self._control_ws = None
            if control is not None:
                try:
                    control.close()
                except Exception:
                    pass

    def _on_control_frame(self, frame: dict[str, Any]) -> None:
        """Record a demultiplexed control frame and trace it."""
        audience = frame["audience"]


        rendered = mask_secrets(json.dumps(frame, sort_keys=True))
        if audience in _KNOWN_AUDIENCES:
            detail(f"Azure WS control frame [{audience}]: {rendered}")
        else:
            log(f"Azure WS control frame with UNKNOWN audience: {rendered}")

        if audience == "token":
            requested = frame.get("tokenAudience")
            token_outcome = "missing_audience"
            if not isinstance(requested, str) or not requested:
                log("Azure token broker request omitted tokenAudience; cannot fulfill it.")
            else:
                audience_label = _safe_token_audience_label(requested)


                try:
                    self._api.satisfy_token_request(self.console, requested)
                    token_outcome = "fulfilled"
                    detail(f"Azure token broker request fulfilled for {audience_label}")
                except Exception as exc:
                    diagnostic = getattr(exc, "safe_diagnostic", None)
                    token_outcome = (
                        f"failed:{diagnostic}"
                        if isinstance(diagnostic, str)
                        and re.fullmatch(r"[a-z0-9_:,.-]{1,80}", diagnostic)
                        else f"failed:{type(exc).__name__}"
                    )
                    safe_reason = token_outcome.removeprefix("failed:")
                    guidance = {
                        "static_token_not_validated": (
                            "the static token has not yet been accepted by Azure in this session"
                        ),
                        "static_token_audience_mismatch": (
                            "the static token's exact audience does not match this request"
                        ),
                        "static_token_expired": "the static token has expired",
                        "audience_token_provider_unavailable": (
                            "this credential cannot acquire a token for that audience"
                        ),
                        "audience_unsupported": "that audience is not supported by this credential",
                    }.get(safe_reason)
                    if guidance:
                        remedy = (
                            " Use an OAuth refresh-token or Azure Console credential for "
                            "Graph/Key Vault requests."
                            if safe_reason in {
                                "static_token_audience_mismatch",
                                "audience_token_provider_unavailable",
                                "audience_unsupported",
                            }
                            else ""
                        )
                        log(
                            f"Azure token request for {audience_label} was not fulfilled: "
                            f"{guidance}; no token was sent.{remedy}"
                        )
                    else:
                        log(
                            f"Azure token request for {audience_label} failed "
                            f"({safe_reason}); no token was sent."
                        )


        retained = (
            {
                "audience": "token",
                "tokenAudience": frame.get("tokenAudience"),
                "tokenOutcome": token_outcome,
            }
            if audience == "token"
            else frame
        )
        self._control_frames.append((time.monotonic(), retained))

    def control_frames(self, audience: Optional[str] = None) -> list[dict[str, Any]]:
        """Control frames seen so far, oldest first, optionally one audience."""


        snapshot = list(self._control_frames)
        if audience is None:
            return [f for _t, f in snapshot]
        return [f for _t, f in snapshot if f["audience"] == audience]

    def _control_frames_since(self, since: float, audience: str) -> list[dict[str, Any]]:
        """Frames of one audience that arrived at or after `since`."""
        return [
            f for t, f in list(self._control_frames) if t >= since and f["audience"] == audience
        ]
