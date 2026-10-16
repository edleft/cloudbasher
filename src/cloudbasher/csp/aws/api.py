#!/usr/bin/env python3
"""AWS CloudShell REST API client implementation."""

from __future__ import annotations

import threading
import time
import uuid
from enum import StrEnum
from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.types import CredentialRecord
from cloudbasher.core.utils.output import detail
from cloudbasher.core.utils.timeline import record_call
from cloudbasher.csp.aws.credentials import (
    AwsSessionCreds,
    credential_refresh_reason,
    derive_target_credentials,
    describe_name_source,
    resolve_credential_chain,
    resolve_identity_name,
    resolve_target_identity,
)
from cloudbasher.csp.aws.signing import signed_cloudshell_post
from cloudbasher.csp.base import CloudShellAPI


_ArtifactCapture: Any = None


class SessionRole(StrEnum):
    """What a session is FOR, which is what decides its `SessionType`."""


    MACHINE = "BASH"


    INTERACTIVE = "TMUX"


    BRIDGE = "EXTENSIONS_BRIDGE"


DEFAULT_SESSION_TYPE = SessionRole.MACHINE


_STREAM_SESSION_FIELDS: dict[str, Any] = {
    "stream_url": "",
    "token_value": "",
    "session_id": None,


    "session_type": None,
}


def session_kwargs_from_stream_info(info: Any) -> dict[str, Any]:
    """The `AWSSession(...)` / `create_session(...)` kwargs an `open_stream()` result implies. Takes anything with `.get`, so a `ConsoleCloudShellAPI` result and a replayed dict both work."""
    return {key: (info.get(key) or default) for key, default in _STREAM_SESSION_FIELDS.items()}


def create_session_body(environment_id: str, session_type: str) -> dict[str, Any]:
    """The `/createSession` request body. ONE definition, deliberately."""
    body: dict[str, Any] = {
        "EnvironmentId": environment_id,
        "SessionType": session_type,
    }
    if session_type == SessionRole.INTERACTIVE:


        body["TabId"] = str(uuid.uuid4())
    return body


def is_vpc_environment(env: dict) -> bool:
    """Whether a `/describeEnvironments` entry is a VPC environment."""
    return bool(env.get("VpcConfig"))


def select_environment(envs: list) -> Optional[dict]:
    """Pick the environment to use from a `/describeEnvironments` list."""
    if not envs:
        return None
    for env in envs:
        if not is_vpc_environment(env):
            return env
    return envs[0]


def retire_session_best_effort(api_client: Any, environment_id: str, session_id: str) -> bool:
    """`/deleteSession` for a session id, swallowing everything. ONE definition."""
    if not session_id or not environment_id or api_client is None:
        return False
    deleter = getattr(api_client, "delete_session", None)
    if not callable(deleter):
        return False
    try:
        return bool(deleter(environment_id, session_id))
    except Exception as exc:
        detail(f"deleteSession raised (ignored) session_id={session_id}: {exc}")
        return False


def retire_session_in_background(api_client: Any, environment_id: str, session_id: str) -> None:
    """retire_session_best_effort(), off the caller's critical path."""
    if not session_id or not environment_id or api_client is None:
        return
    threading.Thread(
        target=retire_session_best_effort,
        args=(api_client, environment_id, session_id),
        name=f"retire-session-{session_id[:8]}",
        daemon=True,
    ).start()


_CREDENTIAL_STATE_LOG_SECONDS = 300


_credential_refresh_reason = credential_refresh_reason


class AWSCloudShellAPI(CloudShellAPI):
    """AWS CloudShell REST API client."""


    _last_cred_state_log: float = 0.0

    def __init__(
        self,
        *,
        region: str,
        credentials: AwsSessionCreds,
        timeout: int = 30,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
        artifact_capture: Optional[Any] = None,
        credential_record: Optional[CredentialRecord] = None,
        credential_registry: Optional[dict[str, CredentialRecord]] = None,
    ) -> None:
        self.region = region
        self.credentials = credentials
        self.timeout = timeout
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure
        self._artifact_capture = artifact_capture
        self._cached_api_creds: Optional[AwsSessionCreds] = None

        self._last_cred_state_log = 0.0
        self._credential_record = credential_record
        self._credential_registry = credential_registry

    def _api_creds(self) -> AwsSessionCreds:
        """Return API-ready credentials, upgrading AKIA keys to ASIA if needed."""
        if not self.credentials.is_akia():


            if self._cached_api_creds is None:
                self._cached_api_creds = self.credentials
            if self._credential_record is None or self._credential_registry is None:


                _missing = "record" if self._credential_record is None else "registry"
                self._log_cred_state(
                    f"api client: CANNOT refresh -- no credential {_missing} was "
                    "passed to this client; the session credential it holds will "
                    "be signed with until it expires "
                    f"(expiry={self._cached_api_creds.expiration or 'NONE'})"
                )
                return self._cached_api_creds


        from cloudbasher.csp.aws.act_as import DIRECT_MODES

        act_as = self.credentials.act_as
        if act_as is not None and act_as.mode in DIRECT_MODES:


            self._log_cred_state(
                f"api client: no refresh by declaration -- ACT_AS is "
                f"{act_as.mode!r}, which derives nothing; the key is used as "
                "given"
            )
            return self.credentials
        _cached = self._cached_api_creds
        if _cached is not None:
            _stale_reason = _credential_refresh_reason(_cached)
            if _stale_reason is None:


                _frac = _cached.lifetime_fraction_elapsed()
                self._log_cred_state(
                    "api client: keeping cached credentials -- "
                    f"expiry={_cached.expiration or 'NONE'} "
                    f"issued_at={'set' if _cached.issued_at else 'NONE'} "
                    f"elapsed={'%.3f' % _frac if _frac is not None else 'UNTIMEABLE'} "
                    f"(untimeable means neither rule can ever fire)"
                )
                return _cached


            detail(f"api client: re-deriving credentials -- {_stale_reason}")
            self._cached_api_creds = None
        if self._credential_record is not None and self._credential_registry is not None:
            upgraded = resolve_credential_chain(
                self._credential_record,
                self._credential_registry,
                proxy_url=self.proxy_url,
                proxy_insecure=self.proxy_insecure,
            )
        else:


            name, name_source = resolve_identity_name(
                self.credentials,
                None,
                where="this CloudShell API call",
            )
            identity = resolve_target_identity(self.credentials, name=name, name_source=name_source)


            key = "ROLE_SESSION_NAME" if identity.kind == "assume_role" else "FEDERATION_NAME"
            detail(
                f"api client derives {identity.kind} as {name} -- "
                f"{describe_name_source(name_source, key=key)}"
            )
            upgraded = derive_target_credentials(
                self.credentials,
                identity,
                proxy_url=self.proxy_url,
                proxy_insecure=self.proxy_insecure,
            )


        _frac = upgraded.lifetime_fraction_elapsed()
        detail(
            "api client: derived credentials -- "
            f"expiry={upgraded.expiration or 'NONE'} "
            f"issued_at={'set' if upgraded.issued_at else 'NONE'} "
            f"timeable={'yes' if _frac is not None else 'NO'}"
        )
        self._cached_api_creds = upgraded
        self._last_cred_state_log = 0.0
        return upgraded

    def _log_cred_state(self, message: str) -> None:
        """Throttled credential-state line -- the shared budget for EVERY exit from `_api_creds()`."""
        now = time.time()
        if now - self._last_cred_state_log < _CREDENTIAL_STATE_LOG_SECONDS:
            return
        self._last_cred_state_log = now
        detail(message)

    def get_session_creds(self) -> AwsSessionCreds:
        """Public alias for _api_creds() -- the API-ready (AKIA-upgraded) credentials, for callers outside this class that need to sign requests themselves (e.g. the browser-free OAuth PKCE flow in cli/main.py)."""
        return self._api_creds()

    def _make_request(
        self,
        path: str,
        body: Optional[dict[str, Any]] = None,
        *,
        timeline_attrs: Optional[dict[str, Any]] = None,
        max_retries: Optional[int] = None,
    ) -> tuple[dict[str, Any], dict[str, str], int]:
        """Issue a SigV4-signed POST request to CloudShell API using API-ready credentials."""
        creds = self._api_creds()

        def _call():
            return signed_cloudshell_post(
                region=self.region,
                path=path,
                body_obj=body,
                creds=creds,
                timeout=self.timeout,
                proxy_url=self.proxy_url,
                proxy_insecure=self.proxy_insecure,
                max_retries=max_retries,
            )


        t0 = time.monotonic()
        status_for_timeline: Optional[int] = None
        error_for_timeline: Optional[str] = None
        try:
            if self._artifact_capture is not None:
                result = self._artifact_capture.wrap_request(self.region, path, body, _call)
            else:
                result = _call()
            status_for_timeline = result[2]
            return result
        except Exception as exc:
            error_for_timeline = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            record_call(
                path.lstrip("/"),
                signing_path="key",
                region=self.region,
                duration_ms=(time.monotonic() - t0) * 1000,
                status=status_for_timeline,
                error=error_for_timeline,
                **(timeline_attrs or {}),
            )

    def describe_environments(self) -> dict[str, Any]:
        """List CloudShell environments in the region."""
        payload, headers, status = self._make_request("/describeEnvironments")
        if status >= 400:
            raise CloudShellAutomationError(f"describe_environments failed: {payload}")
        envs = payload.get("Environments", [])
        detail(
            f"describeEnvironments region={self.region} count={len(envs)} request_id={headers.get('x-amzn-RequestId', 'n/a')}"
        )
        return {
            "environments": envs,
            "request_id": headers.get("x-amzn-RequestId"),
        }

    def _journal_principal(self) -> str:
        """The key the journal files a created environment under (`#434`)."""
        record = self._credential_record
        if record is not None and getattr(record, "id", ""):
            return str(record.id)
        key = (self.credentials.access_key or "").strip()
        if key:
            from cloudbasher.core.utils.output import masked_key_id

            return masked_key_id(key)
        return f"unknown@{self.region}"

    def create_environment(self) -> dict[str, Any]:
        """Create a new CloudShell environment."""
        from cloudbasher.core import env_journal

        principal = self._journal_principal()
        attempt = env_journal.record_intent(principal=principal, region=self.region)
        payload, headers, status = self._make_request("/createEnvironment", {})
        if status >= 400:
            raise CloudShellAutomationError(f"create_environment failed: {payload}")
        if not payload.get("EnvironmentId"):
            raise CloudShellAutomationError("create_environment did not return EnvironmentId")
        env_id = payload["EnvironmentId"]
        env_journal.record_created(
            attempt=attempt,
            principal=principal,
            region=self.region,
            environment_id=env_id,
        )
        detail(
            f"createEnvironment region={self.region} environment_id={env_id} request_id={headers.get('x-amzn-RequestId', 'n/a')}"
        )
        return {
            "environment_id": env_id,
            "status": payload.get("Status"),
            "request_id": headers.get("x-amzn-RequestId"),
        }

    def get_environment_status(self, environment_id: str) -> dict[str, Any]:
        """Get environment status (RUNNING, SUSPENDED, STOPPED, etc.)."""
        payload, headers, status = self._make_request(
            "/getEnvironmentStatus",
            {"EnvironmentId": environment_id},
        )
        if status >= 400:
            raise CloudShellAutomationError(f"get_environment_status failed: {payload}")
        env_status = payload.get("Status", "")
        detail(
            f"getEnvironmentStatus region={self.region} environment_id={environment_id} status={env_status} request_id={headers.get('x-amzn-RequestId', 'n/a')}"
        )
        return {
            "status": env_status,
            "request_id": headers.get("x-amzn-RequestId"),
        }

    def start_environment(self, environment_id: str) -> dict[str, Any]:
        """Resume a suspended or stopped environment."""
        payload, headers, status = self._make_request(
            "/startEnvironment",
            {"EnvironmentId": environment_id},
        )
        if status >= 400:
            raise CloudShellAutomationError(f"start_environment failed: {payload}")
        detail(
            f"startEnvironment region={self.region} environment_id={environment_id} request_id={headers.get('x-amzn-RequestId', 'n/a')}"
        )
        return {"request_id": headers.get("x-amzn-RequestId")}

    def delete_environment(self, environment_id: str) -> dict[str, Any]:
        """Delete a CloudShell environment (4s, 4z harness prerequisite)."""
        payload, headers, status = self._make_request(
            "/deleteEnvironment",
            {"EnvironmentId": environment_id},
        )
        if status >= 400:
            raise CloudShellAutomationError(f"delete_environment failed: {payload}")


        from cloudbasher.core import env_journal

        env_journal.record_deleted(environment_id=environment_id, region=self.region)
        detail(
            f"deleteEnvironment region={self.region} environment_id={environment_id} request_id={headers.get('x-amzn-RequestId', 'n/a')}"
        )
        return {"request_id": headers.get("x-amzn-RequestId")}

    def stop_environment(self, environment_id: str) -> dict[str, Any]:
        """Suspend a running CloudShell environment."""
        payload, headers, status = self._make_request(
            "/stopEnvironment",
            {"EnvironmentId": environment_id},
        )
        if status >= 400:
            raise CloudShellAutomationError(f"stop_environment failed: {payload}")
        detail(
            f"stopEnvironment region={self.region} environment_id={environment_id} request_id={headers.get('x-amzn-RequestId', 'n/a')}"
        )
        return {"request_id": headers.get("x-amzn-RequestId")}

    def open_stream(
        self,
        environment_id: str,
        session_type: str = DEFAULT_SESSION_TYPE,
        *,
        max_retries: Optional[int] = None,
    ) -> dict[str, Any]:
        """Open an SSM stream (CloudShell's /createSession endpoint) and return its connection parameters. Named to avoid colliding with CSPProvider.create_session (which builds a CloudShellSession object, not a stream_url/token_value dict)."""
        payload, headers, status = self._make_request(
            "/createSession",
            create_session_body(environment_id, session_type),


            timeline_attrs={"session_type": session_type},


            max_retries=max_retries,
        )
        if status >= 400:
            raise CloudShellAutomationError(f"create_session failed: {payload}")
        if not payload.get("StreamUrl") or not payload.get("TokenValue"):
            raise CloudShellAutomationError(
                f"create_session did not return StreamUrl/TokenValue: {payload}"
            )
        req_id = headers.get("x-amzn-RequestId", "n/a")
        detail(
            f"createSession region={self.region} environment_id={environment_id} session_id={payload.get('SessionId', 'n/a')} request_id={req_id}"
        )
        return {
            "session_id": payload.get("SessionId"),
            "stream_url": payload["StreamUrl"],
            "token_value": payload["TokenValue"],
            "request_id": headers.get("x-amzn-RequestId"),


            "session_type": session_type,
        }

    def delete_session(self, environment_id: str, session_id: str) -> bool:
        """Tear down a terminal session. Returns True if the call succeeded."""
        if not session_id or not environment_id:
            return False
        try:
            _payload, headers, status = self._make_request(
                "/deleteSession",
                {"EnvironmentId": environment_id, "SessionId": session_id},
            )
        except Exception as exc:
            detail(f"deleteSession failed (ignored) session_id={session_id}: {exc}")
            return False
        req_id = headers.get("x-amzn-RequestId", "n/a")
        if status >= 400:
            detail(f"deleteSession status={status} session_id={session_id} request_id={req_id}")
            return False
        detail(f"deleteSession session_id={session_id} request_id={req_id}")
        return True

    def send_heartbeat(self, environment_id: str) -> dict[str, Any]:
        """Send a heartbeat to keep the environment alive."""
        payload, headers, status = self._make_request(
            "/sendHeartBeat",
            {"EnvironmentId": environment_id},
        )
        if status >= 400:
            raise CloudShellAutomationError(
                f"send_heartbeat failed: HTTP {status}",
                status_code=status,
                error_code=payload.get("__type") if isinstance(payload, dict) else None,
            )
        detail(
            f"sendHeartBeat region={self.region} environment_id={environment_id} request_id={headers.get('x-amzn-RequestId', 'n/a')}"
        )
        return {"request_id": headers.get("x-amzn-RequestId")}

    def get_file_upload_urls(
        self,
        environment_id: str,
        file_path: str,
    ) -> dict[str, Any]:
        """Get presigned S3 URLs for file upload."""
        payload, headers, status = self._make_request(
            "/getFileUploadUrls",
            {
                "EnvironmentId": environment_id,
                "FileUploadPath": file_path,
            },
        )
        if status >= 400:
            raise CloudShellAutomationError(f"get_file_upload_urls failed: {payload}")
        return {
            "upload_url": payload.get("FileUploadPresignedUrl", ""),
            "upload_fields": payload.get("FileUploadPresignedFields", {}),
            "download_url": payload.get("FileDownloadPresignedUrl", ""),
            "download_key": payload.get("FileDownloadPresignedKey", ""),


            "download_key_hash": payload.get("FileDownloadPresignedKeyHash", ""),
            "request_id": headers.get("x-amzn-RequestId"),
        }

    def get_file_download_urls(
        self,
        environment_id: str,
        file_path: str,
    ) -> dict[str, Any]:
        """Get presigned S3 URLs for file download."""
        payload, headers, status = self._make_request(
            "/getFileDownloadUrls",
            {
                "EnvironmentId": environment_id,
                "FileDownloadPath": file_path,
            },
        )
        if status >= 400:
            raise CloudShellAutomationError(f"get_file_download_urls failed: {payload}")
        return {
            "upload_url": payload.get("FileUploadPresignedUrl", ""),
            "upload_fields": payload.get("FileUploadPresignedFields", {}),
            "download_url": payload.get("FileDownloadPresignedUrl", ""),
            "download_key": payload.get("FileDownloadPresignedKey", ""),


            "download_key_hash": payload.get("FileDownloadPresignedKeyHash", ""),
            "request_id": headers.get("x-amzn-RequestId"),
        }

    def put_credentials(self, env_id: str, creds: dict[str, Any]) -> dict[str, Any]:
        """Put credentials into the CloudShell environment."""
        payload, headers, status = self._make_request(
            "/putCredentials",
            {
                "EnvironmentId": env_id,
                "RefreshToken": creds.get("refresh_token", ""),
                "KeyBase": creds.get("key_base", ""),
            },
        )
        if status >= 400:
            raise CloudShellAutomationError(f"put_credentials failed: {payload}")
        return {"request_id": headers.get("x-amzn-RequestId")}
