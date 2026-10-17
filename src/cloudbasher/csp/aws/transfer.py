"""The container-side half of CloudShell file transfer."""

from __future__ import annotations

import base64
import re
import shlex
from typing import Any, Optional

from cloudbasher.core.exceptions import SessionError
from cloudbasher.core.session.quiet import HISTORY_OFF as _HISTORY_OFF
from cloudbasher.core.utils.output import log, strip_ansi
from cloudbasher.csp.aws.api import SessionRole, session_kwargs_from_stream_info


EXIT_SENTINEL = "EXIT_CODE"
_EXIT_RE = re.compile(rf"{EXIT_SENTINEL}(\d+)")


HISTORY_OFF = _HISTORY_OFF


HELPER_SESSION_TYPE = SessionRole.MACHINE


CURL_MAX_TIME = 120


def build_pull_command(
    *,
    download_url: str,
    destination_path: str,
    download_key: str,
    download_key_hash: str,
) -> str:
    """S3 staging object -> container filesystem (the second half of an upload)."""

    def _b64(value: str) -> str:
        return shlex.quote(base64.b64encode(value.encode("utf-8")).decode("ascii"))

    return (
        f"__CS_URL=$(printf %s {_b64(download_url)} | base64 -d); "
        f"__CS_DST=$(printf %s {_b64(destination_path)} | base64 -d); "
        f"__CS_KEY=$(printf %s {_b64(download_key)} | base64 -d); "
        f"__CS_KEY_MD5=$(printf %s {_b64(download_key_hash)} | base64 -d); "
        f"curl --fail --silent --show-error --location --max-time {CURL_MAX_TIME} "
        '-H "x-amz-server-side-encryption-customer-algorithm: AES256" '
        '-H "x-amz-server-side-encryption-customer-key: $__CS_KEY" '
        '-H "x-amz-server-side-encryption-customer-key-MD5: $__CS_KEY_MD5" '
        '"$__CS_URL" --output "$__CS_DST"'
    )


def build_push_command(
    *,
    upload_url: str,
    upload_fields: dict[str, Any],
    source_path: str,
) -> str:
    """Container filesystem -> S3 staging object (the first half of a download)."""
    parts = [f"curl --fail --silent --show-error --location --max-time {CURL_MAX_TIME}"]
    for key, value in upload_fields.items():
        parts.append(f"-F {shlex.quote(f'{key}={value}')}")
    parts.append(f"-F {shlex.quote(f'file=@{source_path}')}")
    parts.append(shlex.quote(upload_url))
    return " ".join(parts)


def build_exists_check(remote_path: str) -> str:
    """`[ -f path ]` -- native's pre-write existence check."""
    return f"[ -f {shlex.quote(remote_path)} ]"


def parse_exit_code(output: str) -> Optional[int]:
    """The LAST ``EXIT_CODE<n>`` in the output, or None."""
    matches = _EXIT_RE.findall(strip_ansi(output or ""))
    if not matches:
        return None
    return int(matches[-1])


class BashHelperSession:
    """A short-lived ``SessionType: BASH`` session, as the console uses."""

    def __init__(self, api_client: Any, environment_id: str, *, timeout: int = 120) -> None:
        if api_client is None:
            raise SessionError("a BASH helper session requires an api_client")
        self._api = api_client
        self._env_id = environment_id
        self._timeout = timeout
        self._session: Any = None

    def __enter__(self) -> "BashHelperSession":
        from cloudbasher.csp.aws.session import AWSSession

        info = self._api.open_stream(self._env_id, session_type=HELPER_SESSION_TYPE)
        self._session = AWSSession(
            environment_id=self._env_id,
            timeout=self._timeout,
            api_client=self._api,


            **session_kwargs_from_stream_info(info),


            bootstrap_probe=False,
        )
        self._session.open_shell()
        log(f"[transfer] BASH helper session opened env={self._env_id}")


        return self

    def __exit__(self, *exc: Any) -> None:
        try:
            if self._session is not None:
                try:


                    self._session.exec_command("exit", timeout=5, recover=False)
                except Exception:
                    pass
                self._session.close()
        finally:
            self._session = None
            log("[transfer] BASH helper session closed")

    def run(self, command: str) -> str:
        """Send one command, return its raw output. No exit-code check."""
        if self._session is None:
            raise SessionError("BashHelperSession used outside its context manager")
        return self._session.exec_command(command, timeout=self._timeout, raw=True, recover=False)

    def run_checked(self, command: str, *, what: str) -> int:
        """Run ``command`` and return ITS exit code."""
        raw = self.run(f"{command}; echo {EXIT_SENTINEL}$?")
        code = parse_exit_code(raw)
        if code is None:
            raise SessionError(
                f"{what}: no {EXIT_SENTINEL} in the helper session's output -- "
                "the command's completion could not be confirmed"
            )
        log(f"[transfer] {what} exit={code}")
        return code
