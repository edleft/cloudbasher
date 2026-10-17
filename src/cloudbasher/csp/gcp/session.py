#!/usr/bin/env python3
"""GCP CloudShell session management via SSH."""

from __future__ import annotations

import hashlib
import io
import os
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit

from cloudbasher.core.exceptions import CommandOutcomeUnknown, SessionError
from cloudbasher.core.session.exit_code_spike import (
    build_command_frame,
    command_frame_completed,
    command_frame_mode_enabled,
    extract_command_frame,
    extract_interrupted_command_frame,
)
from cloudbasher.core.session.serialized_exec import SerializedExec
from cloudbasher.core.utils.output import detail, extract_output, log, strip_ansi
from cloudbasher.csp.base import CloudShellSession


def _paramiko():
    """Lazy import of paramiko — deferred until first SSH use."""
    try:
        import paramiko as _p

        return _p
    except ImportError:
        raise SessionError(
            "paramiko is required for GCP SSH sessions " "(pip install 'cloudbasher[gcp]')"
        )


def generate_ssh_keypair() -> tuple[Any, str]:
    """Generate an ephemeral ECDSA-256 SSH keypair for GCP CloudShell."""
    key = _paramiko().ECDSAKey.generate(bits=256)
    pub_str = f"{key.get_name()} {key.get_base64()}"
    log("Generated ECDSA-256 SSH keypair")
    return key, pub_str


def private_key_to_pem(key: Any) -> str:
    """Serialize a paramiko key object to PEM string."""
    buf = io.StringIO()
    key.write_private_key(buf)
    return buf.getvalue()


_PROMPT_RE = re.compile(r"[\$#]\s*$", re.MULTILINE)


def _prompt_shape_matches(line: str, captured_prompt: Optional[str]) -> bool:
    """Recognize a prompt matching the captured shell's stable identity."""
    if not _PROMPT_RE.search(line):
        return False
    if not captured_prompt:
        return True

    captured = captured_prompt.strip()
    cloudshell_style = re.fullmatch(r"(\S+)\s+\[[^\]\r\n]*\]\s*[$#]", captured)
    if cloudshell_style:
        user = re.escape(cloudshell_style.group(1))
        return bool(re.fullmatch(rf"{user}\s+\[[^\]\r\n]*\]\s*[$#]", line))

    user_host_style = re.fullmatch(
        r"([^:\s]+):[^\s]+(?:\s+\([^()\r\n]+\))?[$#]", captured
    )
    if user_host_style:
        prefix = re.escape(user_host_style.group(1) + ":")
        return bool(
            re.fullmatch(rf"{prefix}[^\s]+(?:\s+\([^()\r\n]+\))?[$#]", line)
        )


    return line == captured


_DRAIN_PROMPT_RE = re.compile(r"[\$#%]\s*$", re.MULTILINE)

_WS_RE = re.compile(r"\s+")


def _collapse_ws(text: str) -> str:
    """Whitespace-free form, for comparing a command against its PTY echo."""
    return _WS_RE.sub("", text)


def _lines_after_echo(check_text: str, cmd_ws: str) -> "list[str] | None":
    """Lines strictly AFTER the command's PTY echo, or None if it is incomplete."""
    lines = check_text.splitlines()
    acc = ""
    for i, line in enumerate(lines):
        acc += _collapse_ws(line)
        if cmd_ws in acc:
            return lines[i + 1 :]
    return None


class _WebSocketTransport:
    """Adapts a websocket-client WebSocket to the socket interface paramiko expects."""

    def __init__(self, ws: Any, diagnostics_dir: Optional[Path] = None) -> None:
        self._ws = ws
        self._diagnostics_dir = diagnostics_dir
        self._recv_buf = b""
        self._timeout: Optional[float] = None
        self._closed = False
        self.last_event: dict[str, Any] = {"kind": "connected"}
        self.receive_timeout_count = 0

    def _record(self, event: dict[str, Any], *, persist: bool = True) -> dict[str, Any]:
        event = {
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "time_monotonic": time.monotonic(),
            **event,
        }
        self.last_event = event
        if persist and self._diagnostics_dir is not None:
            from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

            append_private_jsonl(self._diagnostics_dir, "websocket-events.jsonl", event)
        return event

    def _socket_state(self) -> dict[str, Any]:
        sock = getattr(self._ws, "sock", None)
        connected = getattr(sock, "connected", None)
        peer = None
        try:
            peer = sock.sock.getpeername() if sock and sock.sock else None
        except Exception:
            pass
        return {"websocket_connected": connected, "peer": peer}

    def recv(self, bufsize: int) -> bytes:
        if self._closed:
            return b""
        if self._recv_buf:
            chunk = self._recv_buf[:bufsize]
            self._recv_buf = self._recv_buf[len(chunk) :]
            return chunk
        try:
            self._ws.settimeout(self._timeout)
            opcode, data = self._ws.recv_data()
            if opcode == 0x8:
                self._closed = True
                payload = bytes(data or b"")
                close_code = int.from_bytes(payload[:2], "big") if len(payload) >= 2 else None
                close_reason = payload[2:].decode("utf-8", "replace") if len(payload) > 2 else ""
                self._record({
                    "kind": "peer_close_frame", "opcode": opcode,
                    "close_code": close_code, "close_reason": close_reason,
                    "payload_hex": payload.hex(), **self._socket_state(),
                })
                return b""
            if isinstance(data, str):
                data = data.encode("utf-8")
            frame_event = self._record(
                {
                    "kind": "receive_frame",
                    "opcode": opcode,
                    "bytes": len(data),
                    **self._socket_state(),
                },
                persist=False,
            )
            if self._diagnostics_dir is not None:
                from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

                append_private_jsonl(
                    self._diagnostics_dir,
                    "websocket-meta.jsonl",
                    {
                        "direction": "in", "opcode": opcode, "bytes": len(data),
                        "time_utc": frame_event["time_utc"],
                        "time_monotonic": frame_event["time_monotonic"],
                    },
                )
                path = self._diagnostics_dir / "websocket-in.bin"
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "ab") as stream:
                    stream.write(data)
                os.chmod(path, 0o600)
            if len(data) <= bufsize:
                return data
            self._recv_buf = data[bufsize:]
            return data[:bufsize]
        except Exception as e:
            if self._is_read_timeout(e):
                self.receive_timeout_count += 1
                self._record({
                    "kind": "receive_timeout",
                    "exception_type": type(e).__name__,
                    "errno": getattr(e, "errno", None),
                    **self._socket_state(),
                }, persist=False)
                raise socket.timeout("recv timed out")
            if self._closed:
                return b""
            self._record({
                "kind": "receive_error", "exception_type": type(e).__name__,
                "errno": getattr(e, "errno", None),
                "winerror": getattr(e, "winerror", None), **self._socket_state(),
                "ssl_reason": getattr(e, "reason", None),
                "ssl_library": getattr(e, "library", None),
                "ssl_verify_code": getattr(e, "verify_code", None),
                "ssl_verify_message": getattr(e, "verify_message", None),
            })
            raise

    @staticmethod
    def _is_read_timeout(exc: BaseException) -> bool:
        """Recognize socket and websocket-client read timeouts by type."""
        if isinstance(exc, (socket.timeout, TimeoutError)):
            return True
        try:
            from websocket import WebSocketTimeoutException
        except ImportError:
            return False
        return isinstance(exc, WebSocketTimeoutException)

    def send(self, data: bytes) -> int:
        if self._closed:
            raise OSError("WebSocket is closed")
        try:
            self._ws.send_binary(data)
        except Exception as exc:
            self._record({
                "kind": "send_error", "exception_type": type(exc).__name__,
                "errno": getattr(exc, "errno", None),
                "winerror": getattr(exc, "winerror", None), **self._socket_state(),
                "ssl_reason": getattr(exc, "reason", None),
                "ssl_library": getattr(exc, "library", None),
                "ssl_verify_code": getattr(exc, "verify_code", None),
                "ssl_verify_message": getattr(exc, "verify_message", None),
            })
            raise
        frame_event = self._record(
            {"kind": "send_frame", "opcode": 2, "bytes": len(data)}, persist=False
        )
        if self._diagnostics_dir is not None:
            from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

            append_private_jsonl(
                self._diagnostics_dir,
                "websocket-meta.jsonl",
                {
                    "direction": "out", "opcode": 2, "bytes": len(data),
                    "time_utc": frame_event["time_utc"],
                    "time_monotonic": frame_event["time_monotonic"],
                },
            )
            path = self._diagnostics_dir / "websocket-out.bin"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "ab") as stream:
                stream.write(data)
            os.chmod(path, 0o600)
        return len(data)

    sendall = send

    def close(self, reason: str = "session_cleanup") -> None:
        self._record({"kind": "local_close", "reason": reason, **self._socket_state()})
        self._closed = True
        try:
            self._ws.close()
        except Exception:
            pass

    def settimeout(self, timeout: Optional[float]) -> None:
        self._timeout = timeout

    def gettimeout(self) -> Optional[float]:
        return self._timeout

    def getpeername(self) -> tuple[str, int]:
        return ("cloudshell.dev", 22)

    def fileno(self) -> int:
        if hasattr(self._ws, "sock") and self._ws.sock:
            return self._ws.sock.fileno()
        raise OSError("WebSocket has no underlying socket fd")

    def setblocking(self, flag: bool) -> None:
        pass


def _connect_websocket(
    ws_url: str,
    *,
    session_token: Optional[str] = None,
    cookies: Optional[dict] = None,
    timeout: float = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> Any:
    """Open a WebSocket connection to the supplied Cloud Shell SSH URL."""
    try:
        import websocket as websocket_client
    except ImportError:
        raise SessionError(
            "websocket-client is required for WebSocket SSH " "(pip install 'cloudbasher[gcp]')"
        )

    headers: dict[str, str] = {}
    cookie_parts: list[str] = []
    if session_token:
        cookie_parts.append(f"session_token={session_token}")
    if cookies:
        for k, v in cookies.items():
            cookie_parts.append(f"{k}={v}")
    if cookie_parts:
        headers["Cookie"] = "; ".join(cookie_parts)

    http_proxy_host = None
    http_proxy_port = None
    if proxy_url:
        parsed = urlparse(proxy_url)
        http_proxy_host = parsed.hostname
        http_proxy_port = parsed.port

    import ssl as _ssl

    sslopt: dict[str, Any] = {}
    if proxy_insecure and proxy_url:
        sslopt = {"cert_reqs": _ssl.CERT_NONE, "check_hostname": False}

    ws = websocket_client.WebSocket(sslopt=sslopt)
    ws.connect(
        ws_url,
        header=headers,
        timeout=timeout,
        http_proxy_host=http_proxy_host,
        http_proxy_port=http_proxy_port,
    )
    safe_url = urlsplit(ws_url)
    log(f"WebSocket connected to {safe_url.netloc}{safe_url.path}")
    return ws


class GCPSession(SerializedExec, CloudShellSession):
    """GCP CloudShell SSH session via paramiko."""


    raw_exec_output_has_command_echo = True

    @property
    def raw_exec_output_is_framed(self) -> bool:
        return command_frame_mode_enabled()


    _EXEC_LABEL = "SSH"

    def __init__(
        self,
        *,
        ssh_host: str = "",
        ssh_port: int = 6000,
        ssh_username: str = "",
        ssh_key: Optional[str] = None,
        ssh_key_passphrase: Optional[str] = None,
        environment_id: str = "",
        timeout: int = 60,

        web_host: str = "",
        session_token: Optional[str] = None,
        cloudshell_access_token: Optional[str] = None,
        cookies: Optional[dict] = None,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
        diagnostics_dir: Optional[str | Path] = None,


        allow_agent: bool = False,
        look_for_keys: bool = False,
    ) -> None:
        self.ssh_host = ssh_host
        self.ssh_port = ssh_port
        self.ssh_username = ssh_username
        self.ssh_key = ssh_key
        self.ssh_key_passphrase = ssh_key_passphrase
        self.environment_id = environment_id
        self.timeout = timeout

        self.web_host = web_host
        self.session_token = session_token
        self.cloudshell_access_token = cloudshell_access_token
        self.cookies = cookies or {}
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure
        self.diagnostics_dir = Path(diagnostics_dir) if diagnostics_dir else None
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys
        self._ws_adapter: Optional[_WebSocketTransport] = None
        self._ssh_transport: Optional[Any] = None
        self.client: Optional[Any] = None
        self._shell_channel: Optional[Any] = None
        self._captured_prompt: Optional[str] = None


        self._init_exec_serialization()
        self._sftp_client: Optional[Any] = None

    def _redact_session_secrets(self, value: str) -> str:
        for secret in (
            self.cloudshell_access_token,
            self.session_token,
            self.ssh_key,
            *self.cookies.values(),
        ):
            if secret:
                value = value.replace(str(secret), "<redacted>")
        return value

    @staticmethod
    def _websocket_network_snapshot(ws: Any) -> dict[str, Any]:
        adapter = getattr(ws, "sock", None)
        sock = getattr(adapter, "sock", None)
        result: dict[str, Any] = {}
        if adapter is not None:
            result["websocket_connected"] = getattr(adapter, "connected", None)
        if sock is not None:
            try:
                result["peer"] = sock.getpeername()
            except Exception as exc:
                result["peer_error_type"] = type(exc).__name__
            for name in ("version", "cipher"):
                method = getattr(sock, name, None)
                if callable(method):
                    try:
                        result[f"tls_{name}"] = method()
                    except Exception as exc:
                        result[f"tls_{name}_error_type"] = type(exc).__name__
            try:
                cert = sock.getpeercert(binary_form=True)
                if cert:
                    result["tls_peer_cert_sha256"] = hashlib.sha256(cert).hexdigest()
            except Exception as exc:
                result["tls_peer_cert_error_type"] = type(exc).__name__
        return result

    def _record_private_ssh_event(self, event: str, **fields: Any) -> None:
        if self.diagnostics_dir is None:
            return
        from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

        append_private_jsonl(
            self.diagnostics_dir,
            "ssh-events.jsonl",
            {
                "time_utc": datetime.now(timezone.utc).isoformat(),
                "time_monotonic": time.monotonic(),
                "event": event,
                **fields,
            },
        )

    def _run_ssh_request(self, stage: str, callback: Any, **fields: Any) -> Any:
        started = time.monotonic()
        try:
            result = callback()
        except Exception as exc:
            transport = getattr(self, "_ssh_transport", None)
            channel = self._shell_channel
            self._record_private_ssh_event(
                f"{stage}_failed",
                elapsed_seconds=time.monotonic() - started,
                exception_type=type(exc).__name__,
                exception=self._redact_session_secrets(str(exc))[:1000],
                errno=getattr(exc, "errno", None),
                transport=self._ssh_transport_snapshot(transport),
                channel=(self._ssh_channel_snapshot(channel) if channel is not None else None),
                websocket_last_event=(self._ws_adapter.last_event if self._ws_adapter else None),
                **fields,
            )
            raise
        transport = getattr(self, "_ssh_transport", None)
        channel = self._shell_channel
        self._record_private_ssh_event(
            f"{stage}_complete",
            elapsed_seconds=time.monotonic() - started,
            transport=self._ssh_transport_snapshot(transport),
            channel=(self._ssh_channel_snapshot(channel) if channel is not None else None),
            **fields,
        )
        return result

    def _ssh_transport_snapshot(self, transport: Any) -> dict[str, Any]:
        if transport is None:
            return {"transport_present": False}
        result: dict[str, Any] = {"transport_present": True}
        for field in (
            "active", "authenticated", "remote_version", "local_version",
            "local_cipher", "remote_cipher", "local_mac", "remote_mac",
            "local_compression", "remote_compression", "host_key_type",
        ):
            value = getattr(transport, field, None)
            if isinstance(value, (str, int, float, bool)) or value is None:
                result[field] = value
        kex = getattr(transport, "kex_engine", None) or getattr(transport, "_kex_engine", None)
        kex_name = getattr(kex, "name", None)
        if isinstance(kex_name, str):
            result["key_exchange"] = kex_name
        for method_name, key in (("is_active", "active"), ("is_authenticated", "authenticated")):
            method = getattr(transport, method_name, None)
            if callable(method):
                try:
                    result[key] = bool(method())
                except Exception as exc:
                    result[f"{key}_probe_error"] = type(exc).__name__
        get_exception = getattr(transport, "get_exception", None)
        if callable(get_exception):
            try:
                exc = get_exception()
                if exc is not None:
                    result["transport_exception_type"] = type(exc).__name__
                    result["transport_exception"] = self._redact_session_secrets(str(exc))[:1000]
            except Exception as exc:
                result["transport_exception_probe_error"] = type(exc).__name__
        try:
            host_key = transport.get_remote_server_key()
            result["remote_host_key_type"] = host_key.get_name()
            result["remote_host_key_sha256"] = hashlib.sha256(host_key.asbytes()).hexdigest()
        except Exception:
            pass
        return result

    def _ssh_channel_snapshot(self, channel: Any) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for field in (
            "chanid", "remote_chanid", "active", "closed", "eof_received", "eof_sent",
            "exit_status",
        ):
            value = getattr(channel, field, None)
            if isinstance(value, (str, int, float, bool)) or value is None:
                result[field] = value
        for field in ("_exit_status", "_exit_signal"):
            value = getattr(channel, field, None)
            if isinstance(value, (str, int, float, bool)) or value is None:
                result[field.lstrip("_")] = value
        for method_name in ("exit_status_ready", "recv_ready", "recv_stderr_ready"):
            method = getattr(channel, method_name, None)
            if callable(method):
                try:
                    result[method_name] = bool(method())
                except Exception as exc:
                    result[f"{method_name}_probe_error"] = type(exc).__name__
        for buffer_name in ("in_buffer", "in_stderr_buffer"):
            buffer = getattr(channel, buffer_name, None)
            if buffer is not None:
                try:
                    result[f"{buffer_name}_bytes"] = len(buffer)
                except Exception:
                    pass
        return result

    def _ensure_connected(self) -> None:
        """Lazy-initialize WebSocket (private) or direct TCP (public) SSH."""
        if self.client is not None:
            return
        if self.web_host and (self.session_token or self.cloudshell_access_token):
            self._connect_via_ws()
        else:
            self._connect_direct()

    def _connect_via_ws(self) -> None:
        """Connect SSH tunneled through WebSocket (private API path)."""
        if self.cloudshell_access_token:
            query = urlencode({"_cloudshellAccessToken": self.cloudshell_access_token})
            ws_url = f"wss://{self.web_host}/_cloudshell/tcp/22?{query}"
            session_token = None
            cookies = None
        else:
            ws_url = f"wss://{self.web_host}/_cloudshell/ssh"
            session_token = self.session_token
            cookies = self.cookies
        started = time.monotonic()
        parsed_url = urlsplit(ws_url)
        query = dict(parse_qsl(parsed_url.query, keep_blank_values=True))
        request_meta = {
            "scheme": parsed_url.scheme,
            "host": parsed_url.hostname,
            "path": parsed_url.path,
            "query_keys": sorted(query),
            "access_token_present": bool(query.get("_cloudshellAccessToken")),
            "access_token_chars": len(query.get("_cloudshellAccessToken", "")),
            "cookie_names": sorted(
                list((cookies or {}).keys()) + (["session_token"] if session_token else [])
            ),
            "session_cookie_present": bool(session_token or cookies),
        }
        log(
            "SSH-over-WebSocket: connecting "
            f"{self.ssh_username}@{self.web_host}/_cloudshell/"
            f"{'tcp/22' if self.cloudshell_access_token else 'ssh'}"
        )
        try:
            ws = _connect_websocket(
                ws_url,
                session_token=session_token,
                cookies=cookies,
                timeout=self.timeout,
                proxy_url=self.proxy_url,
                proxy_insecure=self.proxy_insecure,
            )
            if self.diagnostics_dir is not None:
                from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

                response = getattr(ws, "handshake_response", None)
                headers = dict(getattr(response, "headers", {}) or {})
                allowed_headers = {
                    "date", "server", "upgrade", "connection", "sec-websocket-protocol",
                    "sec-websocket-extensions", "x-request-id", "x-goog-request-id",
                    "x-cloud-trace-context", "traceparent",
                }
                append_private_jsonl(
                    self.diagnostics_dir,
                    "websocket-handshake.jsonl",
                    {
                        **request_meta,
                        "elapsed_seconds": time.monotonic() - started,
                        "response_status": getattr(response, "status", None),
                        "response_headers": {
                            key: value for key, value in headers.items()
                            if key.lower() in allowed_headers
                        },
                        "network": self._websocket_network_snapshot(ws),
                    },
                )
            self._record_private_ssh_event(
                "websocket_upgrade_complete", elapsed_seconds=time.monotonic() - started,
                response_status=getattr(getattr(ws, "handshake_response", None), "status", None),
                network=self._websocket_network_snapshot(ws),
            )
        except Exception as e:

            if self.diagnostics_dir is not None:
                from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

                append_private_jsonl(
                    self.diagnostics_dir,
                    "websocket-handshake.jsonl",
                    {**request_meta, "error_type": type(e).__name__,
                     "errno": getattr(e, "errno", None),
                     "error": self._redact_session_secrets(str(e))[:1000],
                     "elapsed_seconds": time.monotonic() - started},
                )
            self._record_private_ssh_event(
                "websocket_upgrade_failed", exception_type=type(e).__name__,
                errno=getattr(e, "errno", None), elapsed_seconds=time.monotonic() - started,
            )
            raise SessionError(f"WebSocket connection failed ({type(e).__name__})") from e

        self._ws_adapter = _WebSocketTransport(ws, self.diagnostics_dir)

        _pk = _paramiko()
        ssh_started = time.monotonic()
        try:
            transport = _pk.Transport(self._ws_adapter)
            self._ssh_transport = transport
            self._record_private_ssh_event("ssh_transport_start")
            kex_started = time.monotonic()
            transport.start_client()
            self._record_private_ssh_event(
                "ssh_key_exchange_complete",
                elapsed_seconds=time.monotonic() - kex_started,
                **self._ssh_transport_snapshot(transport),
            )
            pkey = self._load_key() if self.ssh_key else None
            auth_started = time.monotonic()
            self._record_private_ssh_event(
                "ssh_publickey_auth_started",
                public_key_fingerprint=(
                    hashlib.sha256(pkey.asbytes()).hexdigest() if pkey is not None else None
                ),
            )
            transport.auth_publickey(self.ssh_username, pkey)
            self._record_private_ssh_event(
                "ssh_publickey_auth_complete",
                elapsed_seconds=time.monotonic() - auth_started,
                **self._ssh_transport_snapshot(transport),
            )
            self.client = _pk.SSHClient()
            self.client._transport = transport  # type: ignore[attr-defined]
        except Exception as e:
            self._record_private_ssh_event(
                "ssh_transport_setup_failed", exception_type=type(e).__name__,
                elapsed_seconds=time.monotonic() - ssh_started,
                errno=getattr(e, "errno", None),
                **self._ssh_transport_snapshot(getattr(self, "_ssh_transport", None)),
            )
            if self._ws_adapter:
                self._ws_adapter.close(reason="ssh_setup_failed")
                self._ws_adapter = None
            self.client = None
            raise SessionError(f"SSH-over-WebSocket auth failed: {e}")
        log(f"SSH-over-WebSocket: connected environment_id={self.environment_id}")

    def _connect_direct(self) -> None:
        """Connect SSH via direct TCP (public API path)."""
        log(f"SSH: connecting {self.ssh_username}@{self.ssh_host}:{self.ssh_port}")
        _pk = _paramiko()
        self.client = _pk.SSHClient()
        self.client.set_missing_host_key_policy(_pk.AutoAddPolicy())

        pkey = self._load_key() if self.ssh_key else None

        try:
            self.client.connect(
                hostname=self.ssh_host,
                port=self.ssh_port,
                username=self.ssh_username,
                pkey=pkey,
                timeout=self.timeout,


                allow_agent=self.allow_agent,
                look_for_keys=self.look_for_keys,
            )
        except Exception as e:
            self.client = None
            raise SessionError(f"SSH connection failed: {e}")
        log(f"SSH: connected environment_id={self.environment_id}")

    def _load_key(self) -> Optional[Any]:
        """Load SSH private key from PEM string."""
        if not self.ssh_key:
            return None

        _pk = _paramiko()
        try:

            return _pk.ECDSAKey.from_private_key(
                io.StringIO(self.ssh_key),
                password=self.ssh_key_passphrase,
            )
        except Exception:
            pass

        try:

            return _pk.RSAKey.from_private_key(
                io.StringIO(self.ssh_key),
                password=self.ssh_key_passphrase,
            )
        except Exception:
            pass

        try:

            return _pk.Ed25519Key.from_private_key(
                io.StringIO(self.ssh_key),
                password=self.ssh_key_passphrase,
            )
        except Exception as e:
            raise SessionError(f"Failed to load SSH key: {e}")

    def exec_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        raw: bool = False,
        *,
        record_history: bool = False,
    ) -> str:
        """Execute a shell command and return output."""
        if record_history:
            return self.exec_in_shell(
                command, timeout=timeout, raw=raw, record_history=True
            )
        return self.exec_in_shell(command, timeout=timeout, raw=raw)

    def ensure_persistent_shell(self, cols: int = 220, rows: int = 50) -> None:
        """Open PTY shell channel if not already open, drain banner through first prompt."""
        if self._shell_channel is not None:
            return
        self._ensure_connected()
        assert self.client is not None

        transport = self.client.get_transport()
        if transport is None:
            raise SessionError("SSH transport not available")

        log(f"SSH: opening PTY shell cols={cols} rows={rows}")
        shell_started = time.monotonic()
        self._shell_channel = self._run_ssh_request("channel_open", transport.open_session)
        self._run_ssh_request(
            "pty_request",
            lambda: self._shell_channel.get_pty(term="xterm-256color", width=cols, height=rows),
            term="xterm-256color", columns=cols, rows=rows,
        )
        self._run_ssh_request("shell_request", self._shell_channel.invoke_shell)


        _drain_prompt_re = _DRAIN_PROMPT_RE
        self._shell_channel.settimeout(0.5)
        banner_chunks: list[str] = []
        raw_banner = bytearray()
        received_bytes = 0
        saw_eof = False
        started = time.monotonic()
        first_data_at: Optional[float] = None
        last_data_at: Optional[float] = None
        deadline = time.time() + 15.0
        while time.time() < deadline:
            try:
                data = self._shell_channel.recv(4096)
                if data:
                    now = time.monotonic()
                    first_data_at = first_data_at or now
                    last_data_at = now
                    received_bytes += len(data)
                    raw_banner.extend(data)
                    banner_chunks.append(data.decode("utf-8", "replace"))
                    if _drain_prompt_re.search(strip_ansi("".join(banner_chunks))):
                        break
                else:
                    saw_eof = True
                    break
            except socket.timeout:


                if banner_chunks and _drain_prompt_re.search(strip_ansi("".join(banner_chunks))):
                    break


        banner_text = strip_ansi("".join(banner_chunks))
        if not _drain_prompt_re.search(banner_text):
            elapsed = time.monotonic() - started
            try:
                transport_active = bool(transport.is_active())
            except Exception:
                transport_active = False
            channel_closed = bool(getattr(self._shell_channel, "closed", False))
            try:
                transport_exception = transport.get_exception()
            except Exception as exc:
                transport_exception = exc
            self._record_private_ssh_event(
                "pty_readiness_failed",
                elapsed_since_shell_request=time.monotonic() - shell_started,
                elapsed_read_seconds=elapsed,
                first_data_after_seconds=(first_data_at - started) if first_data_at else None,
                last_data_after_seconds=(last_data_at - started) if last_data_at else None,
                received_bytes=received_bytes,
                chunks=len(banner_chunks),
                prompt_observed=False,
                eof=saw_eof,
                transport=self._ssh_transport_snapshot(transport),
                channel=self._ssh_channel_snapshot(self._shell_channel),
                websocket_last_event=(self._ws_adapter.last_event if self._ws_adapter else None),
                websocket_receive_timeout_count=(
                    self._ws_adapter.receive_timeout_count if self._ws_adapter else None
                ),
                readiness_exception_type=(
                    type(transport_exception).__name__ if transport_exception is not None else None
                ),
                readiness_exception=(
                    self._redact_session_secrets(str(transport_exception))[:1000]
                    if transport_exception is not None else None
                ),
                initial_bytes_sha256=hashlib.sha256(bytes(raw_banner)).hexdigest(),
            )
            if self.diagnostics_dir is not None:
                from cloudbasher.csp.gcp.diagnostics import write_private

                write_private(self.diagnostics_dir, "pty-initial.bin", bytes(raw_banner))
                from cloudbasher.csp.gcp.diagnostics import append_private_jsonl

                append_private_jsonl(
                    self.diagnostics_dir,
                    "pty-initial-meta.jsonl",
                    {
                        "received_bytes": received_bytes,
                        "chunks": len(banner_chunks),
                        "elapsed_seconds": elapsed,
                        "transport_active": transport_active,
                        "channel_closed": channel_closed,
                        "eof": saw_eof,
                        "prompt_observed": False,
                    },
                )
            log(
                "GCP PTY readiness failed: "
                f"received_bytes={received_bytes} chunks={len(banner_chunks)} "
                f"elapsed_seconds={elapsed:.2f} transport_active={transport_active} "
                f"channel_closed={channel_closed} eof={saw_eof} prompt_observed=False "
                f"private_capture={self.diagnostics_dir or 'disabled'}"
            )
            self._captured_prompt = None
            self._shell_channel.close()
            self._shell_channel = None
            if saw_eof or channel_closed:
                reason = "SSH channel closed"
            elif not transport_active:
                reason = "SSH transport disconnected"
            else:
                reason = "Timed out waiting for a shell prompt"
            raise SessionError(
                f"{reason} before initial Cloud Shell prompt "
                f"(received {received_bytes} bytes in {len(banner_chunks)} chunks; "
                f"SSH transport active={transport_active}, EOF={saw_eof})"
            )

        if self.diagnostics_dir is not None:
            from cloudbasher.csp.gcp.diagnostics import append_private_jsonl, write_private

            write_private(self.diagnostics_dir, "pty-initial.bin", bytes(raw_banner))
            append_private_jsonl(
                self.diagnostics_dir,
                "pty-initial-meta.jsonl",
                {
                    "received_bytes": received_bytes,
                    "chunks": len(banner_chunks),
                    "elapsed_seconds": time.monotonic() - started,
                    "eof": saw_eof,
                    "prompt_observed": True,
                },
            )
        self._record_private_ssh_event(
            "pty_readiness_succeeded",
            elapsed_read_seconds=time.monotonic() - started,
            first_data_after_seconds=(first_data_at - started) if first_data_at else None,
            received_bytes=received_bytes,
            chunks=len(banner_chunks),
            prompt_observed=True,
            transport=self._ssh_transport_snapshot(transport),
            channel=self._ssh_channel_snapshot(self._shell_channel),
        )


        lines = banner_text.splitlines()
        for line in reversed(lines):
            if line.strip():
                self._captured_prompt = line.strip()
                break

        self._shell_channel.settimeout(1.0)
        self.clear_shell_command_uncertainty()
        self.clear_shell_interrupt_request()

    def exec_in_shell(
        self,
        command: str,
        timeout: Optional[int] = None,
        raw: bool = False,
        *,
        record_history: bool = False,
    ) -> str:
        """Execute command in persistent PTY shell with automatic retry on failure."""
        timeout = timeout or self.timeout

        self.assert_shell_command_safe()
        with self._serialized_exec(command, float(timeout)):
            try:
                if record_history:
                    return self._exec_in_shell_once(
                        command, timeout, raw=raw, record_history=True
                    )
                return self._exec_in_shell_once(command, timeout, raw=raw)
            except CommandOutcomeUnknown:


                self.mark_shell_command_uncertain()
                raise
            except SessionError as first_exc:

                try:
                    self._shell_channel = None
                    self._captured_prompt = None
                    if record_history:
                        return self._exec_in_shell_once(
                            command, timeout, raw=raw, record_history=True
                        )
                    return self._exec_in_shell_once(command, timeout, raw=raw)
                except Exception:

                    raise first_exc

    def _exec_in_shell_once(
        self,
        command: str,
        timeout: int,
        raw: bool = False,
        *,
        record_history: bool = False,
    ) -> str:
        """Dispatch to the shared framed runner or the rollback implementation."""
        if not command_frame_mode_enabled():
            return self._exec_in_shell_once_legacy(command, timeout, raw=raw)
        if record_history:
            return self._exec_in_shell_once_framed(
                command, timeout, raw=raw, record_history=True
            )
        return self._exec_in_shell_once_framed(command, timeout, raw=raw)

    def _exec_in_shell_once_framed(
        self,
        command: str,
        timeout: int,
        raw: bool = False,
        *,
        record_history: bool = False,
    ) -> str:
        """Run one command bounded by the shared start/status/end frame."""
        self.ensure_persistent_shell()
        frame = build_command_frame(
            command,
            history_enabled=True,
            history_entry=command if record_history else None,
        )
        log(f"SSH: send framed command command_chars={len(command)}")
        try:
            self._shell_channel.sendall(frame.wire_text.encode("utf-8"))
        except Exception as exc:
            raise CommandOutcomeUnknown(
                "terminal write failed after command framing began; command outcome is unknown "
                "and it was not automatically retried"
            ) from exc

        chunks: list[str] = []
        self._shell_channel.settimeout(1.0)
        deadline = time.monotonic() + timeout
        started = time.monotonic()
        while time.monotonic() < deadline:
            if self.shell_interrupt_grace_expired():
                raise CommandOutcomeUnknown(
                    "Ctrl-C was sent, but the shell did not finish within the 5-second "
                    "interrupt grace. Command outcome is unknown; reconnect before retrying."
                )
            try:
                data = self._shell_channel.recv(4096)
            except socket.timeout:
                continue
            if not data:
                if getattr(self._shell_channel, "closed", False):
                    break
                continue
            chunks.append(data.decode("utf-8", "replace"))
            combined = "".join(chunks)
            if command_frame_completed(strip_ansi(combined), frame):


                self._shell_channel.settimeout(0.25)
                drain_deadline = time.monotonic() + 0.4
                while time.monotonic() < drain_deadline:
                    try:
                        tail = self._shell_channel.recv(4096)
                    except socket.timeout:
                        break
                    except Exception:
                        break
                    if not tail:
                        break
                    chunks.append(tail.decode("utf-8", "replace"))
                self._shell_channel.settimeout(1.0)
                combined = "".join(chunks)
                try:
                    output, status = extract_command_frame(
                        combined,
                        command,
                        frame,
                        command_echo_present=True,
                        preserve_ansi=raw,
                    )
                except ValueError as exc:
                    raise CommandOutcomeUnknown(
                        "the completion marker arrived, but its output frame was inconsistent; "
                        "the command was not automatically retried"
                    ) from exc
                self._last_command_exit_code = status
                self.clear_shell_interrupt_request()
                detail(
                    f"SSH: framed command completed bytes="
                    f"{sum(len(part.encode('utf-8')) for part in chunks)} "
                    f"elapsed={time.monotonic() - started:.2f}s status={status}"
                )
                return output if raw else strip_ansi(output)

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
                        "SSH: ETX returned shell to prompt; completed interrupted command "
                        "without end marker"
                    )
                    return interrupted_output if raw else strip_ansi(interrupted_output)

        detail(
            f"SSH: framed command incomplete bytes={sum(map(len, chunks))} "
            f"elapsed={time.monotonic() - started:.2f}s "
            f"completion_marker_seen={command_frame_completed(strip_ansi(''.join(chunks)), frame)}"
        )
        raise CommandOutcomeUnknown(
            f"No command completion marker arrived within {timeout}s; the remote command "
            "may still be running and was not automatically retried."
        )

    def _exec_in_shell_once_legacy(self, command: str, timeout: int, raw: bool = False) -> str:
        """Internal: execute command in persistent PTY shell once (no retry)."""
        self.ensure_persistent_shell()
        log(f"SSH: send command command={command!r}")
        self._shell_channel.sendall((command + "\n").encode("utf-8"))

        chunks: list[str] = []
        self._shell_channel.settimeout(1.0)
        deadline = time.time() + timeout
        cmd_ws = _collapse_ws(command)
        echo_seen = not cmd_ws
        matched = False
        captured_prompt_match = False
        prompt_shape_match = False
        prompt_shape_seen = False
        started = time.monotonic()

        while time.time() < deadline:
            if self.shell_interrupt_grace_expired():
                raise CommandOutcomeUnknown(
                    "Ctrl-C was sent, but the shell did not finish within the 5-second "
                    "interrupt grace. Command outcome is unknown; reconnect before retrying."
                )
            try:
                data = self._shell_channel.recv(4096)
            except socket.timeout:
                continue
            if not data:
                continue

            chunks.append(data.decode("utf-8", "replace"))
            combined = "".join(chunks).replace("\r", "")
            check_text = strip_ansi(combined)
            after_echo = (
                check_text.splitlines() if not cmd_ws else _lines_after_echo(check_text, cmd_ws)
            )
            if after_echo is None:
                continue
            echo_seen = True
            last_nonempty = ""
            for line in reversed(after_echo):
                if line.strip():
                    last_nonempty = line.strip()
                    break
            if not last_nonempty:
                continue
            captured_prompt_match = bool(
                self._captured_prompt and last_nonempty == self._captured_prompt.strip()
            )
            prompt_shape_match = _prompt_shape_matches(last_nonempty, self._captured_prompt)
            prompt_shape_seen = prompt_shape_seen or prompt_shape_match
            matched = captured_prompt_match or prompt_shape_match
            if matched:
                self._shell_channel.settimeout(0.25)
                drain_until = time.time() + 0.4
                while time.time() < drain_until:
                    try:
                        self._shell_channel.recv(4096)
                    except socket.timeout:
                        break
                self._shell_channel.settimeout(1.0)
                break

        elapsed = time.monotonic() - started
        byte_count = sum(len(chunk.encode("utf-8")) for chunk in chunks)
        if not matched:
            detail(
                f"SSH: no prompt before deadline echo_seen={echo_seen} "
                f"captured_prompt_match={captured_prompt_match} "
                f"prompt_shape_seen={prompt_shape_seen} bytes={byte_count} "
                f"elapsed={elapsed:.2f}s"
            )
            raise CommandOutcomeUnknown(
                f"No shell prompt arrived within {timeout}s (echo_seen={echo_seen}); "
                "the remote command may still be running and was not retried."
            )

        detail(
            f"SSH: command completed bytes={byte_count} elapsed={elapsed:.2f}s "
            f"captured_prompt_match={captured_prompt_match} "
            f"prompt_shape_seen={prompt_shape_seen}"
        )

        self.clear_shell_interrupt_request()
        if raw:
            return "".join(chunks).replace("\r", "")
        clean_text = strip_ansi("".join(chunks)).replace("\r", "")
        return extract_output(clean_text, command)

    def open_shell(self) -> None:
        """Ensure PTY shell channel is open (idempotent)."""
        self.ensure_persistent_shell()

    def interrupt_shell_command(self) -> None:
        """Send ETX to the existing PTY; do not close or replace the channel."""
        if self._shell_channel is None or self._shell_channel.closed:
            raise SessionError("cannot interrupt: GCP SSH PTY channel is not open")
        self._shell_channel.sendall(b"\x03")

    def interactive_shell(self) -> None:
        """Drop into a raw PTY loop: stdin → SSH channel, channel → stdout."""
        import os as _os
        import select as _select
        import sys as _sys

        self.ensure_persistent_shell()
        assert self._shell_channel is not None


        _old_tty = None
        try:
            import termios as _termios
            import tty as _tty

            _old_tty = _termios.tcgetattr(_sys.stdin)
            _tty.setraw(_sys.stdin.fileno())
            _tty.setcbreak(_sys.stdin.fileno())
        except Exception:
            pass

        self._shell_channel.settimeout(0.0)
        log("SSH: interactive_shell started")

        try:
            while True:
                r, _, _ = _select.select([self._shell_channel, _sys.stdin], [], [], 0.1)
                if self._shell_channel in r:
                    try:
                        data = self._shell_channel.recv(1024)
                        if not data:
                            break
                        _sys.stdout.buffer.write(data)
                        _sys.stdout.buffer.flush()
                    except socket.timeout:
                        pass
                if _sys.stdin in r:
                    data = _os.read(_sys.stdin.fileno(), 1024)
                    if not data:
                        break
                    self._shell_channel.send(data)
        finally:
            if _old_tty is not None:
                try:
                    import termios as _termios

                    _termios.tcsetattr(_sys.stdin, _termios.TCSADRAIN, _old_tty)
                except Exception:
                    pass
            log("SSH: interactive_shell exited")

    def _ensure_sftp(self):
        """Return a live paramiko SFTPClient, opening one if needed."""
        if not hasattr(self, "_sftp_client") or self._sftp_client is None:
            self._ensure_connected()
            assert self.client is not None
            transport = self.client.get_transport()
            if transport is None:
                raise SessionError("SSH transport not available for SFTP")
            self._sftp_client = _paramiko().SFTPClient.from_transport(transport)
        return self._sftp_client

    def upload_file(self, local_path: str, remote_path: str) -> None:
        """Upload local file to CloudShell via SFTP."""
        import os as _os

        sftp = self._ensure_sftp()
        sftp.put(local_path, remote_path)
        size = _os.path.getsize(local_path)
        log(f"[upload] local={local_path} remote={remote_path} bytes={size} method=sftp")

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Download file from CloudShell via SFTP."""
        import os as _os

        sftp = self._ensure_sftp()
        sftp.get(remote_path, local_path)
        size = _os.path.getsize(local_path)
        log(f"[download] remote={remote_path} local={local_path} bytes={size} method=sftp")

    def close(self) -> None:
        """Close the SSH connection, shell channel, SFTP client, and WebSocket adapter."""
        transport = getattr(self, "_ssh_transport", None)
        channel = self._shell_channel
        self._record_private_ssh_event(
            "session_close_started",
            transport=self._ssh_transport_snapshot(transport),
            channel=(self._ssh_channel_snapshot(channel) if channel is not None else None),
            websocket_last_event=(self._ws_adapter.last_event if self._ws_adapter else None),
        )
        if self._sftp_client:
            try:
                self._sftp_client.close()
            except Exception:
                pass
            self._sftp_client = None

        if self._shell_channel:
            try:
                self._shell_channel.close()
            except Exception:
                pass
            self._shell_channel = None

        if self.client:
            try:
                self.client.close()
            except Exception:
                pass
            self.client = None

        if self._ws_adapter:
            try:
                self._ws_adapter.close(reason="session_close")
            except Exception:
                pass
            self._ws_adapter = None
        self._ssh_transport = None

    def send_pty_keepalive(self) -> str:
        """Write one blank line to the live PTY without racing command I/O."""
        if not self._exec_lock.acquire(blocking=False):
            self._record_private_ssh_event("pty_keepalive_skipped", reason="command_busy")
            return "skipped:command_busy"
        try:
            channel = self._shell_channel
            transport = self._ssh_transport
            if channel is None:
                self._record_private_ssh_event("pty_keepalive_skipped", reason="channel_missing")
                return "unavailable:channel_missing"
            if getattr(channel, "closed", True):
                self._record_private_ssh_event("pty_keepalive_skipped", reason="channel_closed")
                return "unavailable:channel_closed"
            if transport is None:
                self._record_private_ssh_event("pty_keepalive_skipped", reason="transport_missing")
                return "unavailable:transport_missing"
            if not getattr(transport, "is_active", lambda: False)():
                self._record_private_ssh_event("pty_keepalive_skipped", reason="transport_inactive")
                return "unavailable:transport_inactive"
            channel.sendall(b"\n")
            self._record_private_ssh_event("pty_keepalive_sent", bytes=1)
            return "sent"
        except Exception as exc:
            self._record_private_ssh_event(
                "pty_keepalive_failed", exception_type=type(exc).__name__
            )
            raise
        finally:
            self._exec_lock.release()
