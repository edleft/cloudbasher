#!/usr/bin/env python3
"""AWS CloudShell WebSocket protocol implementation."""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.utils.output import log, log_file_only
from cloudbasher.core.utils.perf_config import get_frame_trace
from cloudbasher.core.utils.timeline import mark
from cloudbasher.csp.aws._ws_common import build_proxy_and_ssl_opts


TRACE_PREVIEW_BYTES = 200


class WebSocketGoneError(CloudShellAutomationError):
    """The socket we were about to write to is not there."""

    cb_failure_class = "socket_dead"


try:
    from websocket import ABNF, create_connection
except ImportError:
    ABNF = None  # type: ignore[assignment]
    create_connection = None  # type: ignore[assignment]


HEADER_LEN = 116


@dataclass
class SsmFrame:
    """A parsed SSM binary frame from the CloudShell WebSocket."""

    message_type: str
    schema_version: int
    created: int
    sequence: int
    flags: int
    message_id_bytes: bytes
    payload_type: int
    payload: bytes


    redelivered: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for backward compatibility."""
        return {
            "message_type": self.message_type,
            "schema_version": self.schema_version,
            "created": self.created,
            "sequence": self.sequence,
            "flags": self.flags,
            "message_id_bytes": self.message_id_bytes,
            "payload_type": self.payload_type,
            "payload": self.payload,
        }


def ensure_websocket_available() -> None:
    """Validate that websocket-client library is importable."""
    if create_connection is None or ABNF is None:
        raise CloudShellAutomationError(
            "websocket-client is not installed. Install with: pip install websocket-client"
        )


def encode_ack_message_id_from_header_bytes(message_id_bytes: bytes) -> str:
    """Transform 16-byte message ID via half-swap for ACK protocol."""
    if len(message_id_bytes) != 16:
        raise CloudShellAutomationError("Invalid message id length for ACK conversion")
    swapped = message_id_bytes[8:16] + message_id_bytes[0:8]
    return str(uuid.UUID(bytes=swapped))


def parse_ssm_frame(frame_bytes: bytes) -> SsmFrame:
    """Parse a binary WebSocket frame into an SsmFrame."""
    if len(frame_bytes) < 120:
        raise CloudShellAutomationError("Invalid frame: too short")

    header_len = int.from_bytes(frame_bytes[0:4], "big")
    if header_len != HEADER_LEN:
        raise CloudShellAutomationError(f"Unexpected header length: {header_len}")

    payload_type = int.from_bytes(frame_bytes[112:116], "big")
    payload_len = int.from_bytes(frame_bytes[116:120], "big")
    payload = frame_bytes[120 : 120 + payload_len]

    return SsmFrame(
        message_type=frame_bytes[4:36].replace(b"\x00", b"").decode("utf-8", "replace").strip(),
        schema_version=int.from_bytes(frame_bytes[36:40], "big"),
        created=int.from_bytes(frame_bytes[40:48], "big"),
        sequence=int.from_bytes(frame_bytes[48:56], "big"),
        flags=int.from_bytes(frame_bytes[56:64], "big"),
        message_id_bytes=frame_bytes[64:80],
        payload_type=payload_type,
        payload=payload,
    )


def build_ssm_client_frame(
    *,
    message_type: str,
    sequence: int,
    payload_type: int,
    payload: bytes,
    flags: int,
) -> bytes:
    """Build an outbound SSM binary frame (116-byte header + payload)."""
    msg_type_raw = message_type.encode("utf-8")
    if len(msg_type_raw) > 32:
        raise CloudShellAutomationError(f"message_type too long: {message_type}")
    msg_type_padded = msg_type_raw + (b" " * (32 - len(msg_type_raw)))

    created_ms = int(time.time() * 1000)
    message_id = uuid.uuid4().bytes
    digest_32_ascii = hashlib.sha256(payload).hexdigest()[:32].encode("ascii")

    header = bytearray()
    header.extend(HEADER_LEN.to_bytes(4, "big"))
    header.extend(msg_type_padded)
    header.extend((1).to_bytes(4, "big"))
    header.extend(created_ms.to_bytes(8, "big"))
    header.extend(sequence.to_bytes(8, "big"))
    header.extend(flags.to_bytes(8, "big"))
    header.extend(message_id)
    header.extend(digest_32_ascii)
    header.extend(payload_type.to_bytes(4, "big"))
    header.extend(len(payload).to_bytes(4, "big"))

    return bytes(header) + payload


def require_ws(handle: Any, *, where: str) -> Any:
    """`handle`, or a failure that SAYS the socket is gone. THE one guard."""
    if handle is None:
        raise WebSocketGoneError(
            f"{where}: WebSocket is not open (never connected, or closed by a "
            "concurrent disconnect/teardown while this call was in flight)"
        )
    return handle


class CloudShellWsSession:
    """Low-level CloudShell WebSocket session client."""

    def __init__(
        self,
        *,
        stream_url: str,
        token_value: str,
        timeout: int = 60,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
    ) -> None:
        self.stream_url = stream_url
        self.token_value = token_value
        self.timeout = timeout
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure
        self._ws: Any = None


        self._last_inbound_at: Optional[float] = None


        self._send_lock = threading.Lock()


        self._seen_output_sequences: set[int] = set()
        self._duplicate_output_frames = 0

    @property
    def redelivered_output_frames(self) -> int:
        """How many output sequences this socket has delivered more than once."""
        return self._duplicate_output_frames

    def _require_ws(self) -> Any:
        """The live raw socket, or `WebSocketGoneError`. See `require_ws`."""
        return require_ws(self._ws, where="CloudShellWsSession._ws")

    @property
    def is_connected(self) -> bool:
        """The transport's own flag. **Not evidence that the socket works.**"""
        return self._ws is not None and self._ws.connected

    @property
    def last_inbound_at(self) -> Optional[float]:
        """Monotonic time of the last frame received, or None if none has been."""
        return self._last_inbound_at

    def seconds_since_inbound(self) -> Optional[float]:
        """Seconds since the last inbound frame, or None if nothing has arrived."""
        if self._last_inbound_at is None:
            return None
        return time.monotonic() - self._last_inbound_at

    def connect(self) -> None:
        """Open the WebSocket connection to the CloudShell session endpoint."""
        ensure_websocket_available()

        proxy_settings, sslopt = build_proxy_and_ssl_opts(self.proxy_url, self.proxy_insecure)


        from ...core.utils.perf_config import get_ws_handshake_timeout_seconds

        _handshake_timeout = get_ws_handshake_timeout_seconds()
        self._ws = create_connection(
            self.stream_url,
            timeout=_handshake_timeout,
            enable_multithread=False,
            **proxy_settings,
            sslopt=sslopt,
        )
        try:
            self._ws.settimeout(5)
        except Exception:
            pass

    def close(self) -> None:
        """Close the WebSocket connection."""


        ws, self._ws = self._ws, None
        if ws is not None:
            try:
                ws.close(timeout=0)
            except Exception:
                pass

    def _trace(
        self,
        direction: str,
        kind: str,
        *,
        sequence: int,
        payload_type: int,
        payload: bytes,
        error: str = "",
    ) -> None:
        """One line per frame, to the log file, when `net.frame_trace` is on."""
        if not get_frame_trace():
            return
        preview = payload[:TRACE_PREVIEW_BYTES].decode("utf-8", "replace")
        more = "" if len(payload) <= TRACE_PREVIEW_BYTES else "..."
        log_file_only(
            f"[frame] {direction} {kind} seq={sequence} ptype={payload_type} "
            f"len={len(payload)}"
            + (f" ERROR={error}" if error else "")
            + f" payload={repr(preview + more)}"
        )

    def _send_traced(
        self,
        kind: str,
        *,
        binary: "Optional[bytes]" = None,
        text: "Optional[str]" = None,
        sequence: int,
        payload_type: int,
        payload: bytes,
    ) -> None:
        """Put one frame on the wire and record that it went"""


        error = ""
        try:
            with self._send_lock:
                ws = self._require_ws()
                if binary is not None:
                    ws.send_binary(binary)
                else:
                    ws.send(text)
        except BaseException as exc:
            error = type(exc).__name__
            raise
        finally:
            self._trace(
                "OUT",
                kind,
                sequence=sequence,
                payload_type=payload_type,
                payload=payload,
                error=error,
            )

    def _send_frame(
        self,
        kind: str,
        *,
        message_type: str,
        sequence: int,
        payload_type: int,
        payload: bytes,
        flags: int,
    ) -> None:
        """Build one binary frame and send it, spelling each field ONCE"""
        frame = build_ssm_client_frame(
            message_type=message_type,
            sequence=sequence,
            payload_type=payload_type,
            payload=payload,
            flags=flags,
        )
        self._send_traced(
            kind,
            binary=frame,
            sequence=sequence,
            payload_type=payload_type,
            payload=payload,
        )

    def send_token_envelope(self) -> None:
        """Send the initial token envelope (text JSON frame)."""
        envelope = json.dumps(
            {
                "MessageSchemaVersion": "1.0",
                "RequestId": str(uuid.uuid4()),
                "TokenValue": self.token_value,
            },
            separators=(",", ":"),
        )
        self._send_traced(
            "token_envelope",
            text=envelope,
            sequence=0,
            payload_type=0,
            payload=envelope.encode("utf-8"),
        )

    def send_resize(self, cols: int, rows: int, *, sequence: int = 0, flags: int = 1) -> None:
        """Send a terminal resize frame (binary, payload_type=3)."""
        resize_payload = json.dumps({"cols": cols, "rows": rows}, separators=(",", ":")).encode(
            "utf-8"
        )
        self._send_frame(
            "resize",
            message_type="input_stream_data",
            sequence=sequence,
            payload_type=3,
            payload=resize_payload,
            flags=flags,
        )

    def send_input(
        self, text: str, *, sequence: int, payload_type: int = 1, flags: int = 0
    ) -> None:
        """Send shell input (binary, payload_type=1)."""
        self._send_frame(
            "input",
            message_type="input_stream_data",
            sequence=sequence,
            payload_type=payload_type,
            payload=text.encode("utf-8"),
            flags=flags,
        )

    def send_ack(self, frame: SsmFrame) -> None:
        """Send an acknowledgment for a received output frame."""
        ack_payload = {
            "AcknowledgedMessageType": frame.message_type,
            "AcknowledgedMessageId": encode_ack_message_id_from_header_bytes(
                frame.message_id_bytes
            ),
            "AcknowledgedMessageSequenceNumber": frame.sequence,
            "IsSequentialMessage": True,
        }


        self._send_frame(
            "ack",
            message_type="acknowledge",
            sequence=frame.sequence,
            payload_type=1,
            payload=json.dumps(ack_payload, separators=(",", ":")).encode("utf-8"),
            flags=1 if frame.sequence == 0 else 0,
        )

    def send_ping(self) -> None:
        """Send the keepalive text frame ``__ping__``. Raises on failure."""
        self._send_traced("ping", text="__ping__", sequence=0, payload_type=0, payload=b"__ping__")

    def receive_frame(self, timeout_seconds: Optional[float] = None) -> Optional[SsmFrame]:
        """Receive and parse one binary SSM frame."""


        ws = self._require_ws()
        if timeout_seconds is not None:
            try:
                ws.settimeout(timeout_seconds)
            except Exception:
                pass

        try:
            frame = ws.recv_frame()
        except Exception as exc:
            if "timed out" in str(exc).lower():
                return None
            raise

        if frame is None:
            return None


        self._last_inbound_at = time.monotonic()


        if frame.opcode == ABNF.OPCODE_TEXT:
            return None


        if frame.opcode != ABNF.OPCODE_BINARY:
            return None

        parsed = parse_ssm_frame(frame.data)
        self._trace(
            "IN",
            parsed.message_type,
            sequence=parsed.sequence,
            payload_type=parsed.payload_type,
            payload=parsed.payload or b"",
        )
        self._suppress_if_redelivered(parsed)
        return parsed


    SEEN_SEQUENCE_CAP = 8192

    def _suppress_if_redelivered(self, frame: Optional[SsmFrame]) -> None:
        """EMPTY an output frame whose sequence this socket already delivered."""
        if frame is None or frame.message_type != "output_stream_data":
            return
        if frame.sequence in self._seen_output_sequences:
            self._duplicate_output_frames += 1
            log(
                f"WebSocket: output frame RE-DELIVERED sequence={frame.sequence} "
                f"bytes={len(frame.payload or b'')} SUPPRESSED "
                f"repeats_on_this_socket={self._duplicate_output_frames}"
            )
            mark("ws.duplicate_output_frame", sequence=frame.sequence)
            frame.redelivered = True
            frame.payload = b""
            return
        if len(self._seen_output_sequences) >= self.SEEN_SEQUENCE_CAP:


            log(
                f"WebSocket: re-delivery tracking reset at "
                f"{self.SEEN_SEQUENCE_CAP} sequences; older repeats now invisible"
            )
            self._seen_output_sequences.clear()
        self._seen_output_sequences.add(frame.sequence)
