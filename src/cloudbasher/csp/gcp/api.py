#!/usr/bin/env python3
"""GCP CloudShell API client implementation."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.utils.output import detail
from cloudbasher.csp.base import CloudShellAPI
from cloudbasher.csp.gcp._http import build_opener as _build_opener_fn
from cloudbasher.csp.gcp.diagnostics import diagnose, looks_like_login_page


class GCPCloudShellAPI(CloudShellAPI):
    """GCP CloudShell API client."""

    BASE = "https://cloudshell.googleapis.com/v1"

    def __init__(
        self,
        *,
        access_token: str,
        timeout: float = 30,
        quota_project: Optional[str] = None,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
        token_refresher: Optional[Any] = None,
    ) -> None:
        self.access_token = access_token
        self.timeout = timeout
        self.quota_project = quota_project
        self.proxy_url = proxy_url
        self.proxy_insecure = proxy_insecure
        self.token_refresher = token_refresher

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """Build urllib opener with optional proxy settings."""
        return _build_opener_fn(self.proxy_url, self.proxy_insecure)

    def _headers(self) -> dict[str, str]:
        """Build request headers with OAuth2 bearer token."""
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }
        if self.quota_project:
            headers["x-goog-user-project"] = self.quota_project
        return headers

    def _request(
        self,
        method: str,
        url: str,
        body: Optional[bytes] = None,
        _is_retry: bool = False,
    ) -> tuple[Any, dict[str, str], int]:
        """Make HTTP request and return (parsed_body, headers, status)."""
        req = urllib.request.Request(url, data=body, method=method)
        for k, v in self._headers().items():
            req.add_header(k, v)

        detail(f"API request: {method} {url} body_bytes={len(body) if body else 0}")

        opener = self._build_opener()
        try:
            resp = opener.open(req, timeout=self.timeout)
            raw = resp.read()
            resp_headers = dict(resp.headers)
            status = resp.getcode()
        except urllib.error.HTTPError as e:
            raw = e.read()
            resp_headers = dict(e.headers)
            status = e.code


        if status == 401 and not _is_retry and self.token_refresher is not None:
            detail(f"API response: {method} {url} status=401 — attempting token refresh")
            try:
                new_token = self.token_refresher()
                if new_token:
                    self.access_token = new_token
                    detail("API: token refreshed; retrying original request")
                    return self._request(method, url, body, _is_retry=True)
            except Exception as refresh_exc:
                detail(f"API: token refresh failed: {refresh_exc}")


        text = raw.decode("utf-8", errors="replace")
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            parsed = text

        detail(f"API response: {method} {url} status={status}")
        return parsed, resp_headers, status

    def _check(self, method: str, path: str, status: int, body: Any) -> Any:
        """Raise with a diagnosis, or hand the body back."""
        if status >= 400 or looks_like_login_page(body):
            response_body = body if isinstance(body, str) else json.dumps(body, default=str)
            raise CloudShellAutomationError(
                diagnose(method, path, status, body),
                status_code=status,
                response_body=response_body,
            )
        return body

    def _get(self, path: str) -> Any:
        """GET request to API."""
        url = f"{self.BASE}/{path}"
        body, _, status = self._request("GET", url)
        return self._check("GET", path, status, body)

    def _post(self, path: str, payload: Optional[dict] = None) -> Any:
        """POST request to API."""
        url = f"{self.BASE}/{path}"
        data = json.dumps(payload or {}).encode() if payload is not None else None
        body, _, status = self._request("POST", url, data)
        return self._check("POST", path, status, body)

    def get_environment(self, name: str = "users/me/environments/default") -> dict[str, Any]:
        """Get environment resource."""
        resp = self._get(name)
        return {
            "name": resp.get("name", ""),
            "state": resp.get("state", ""),
            "ssh_host": resp.get("sshHost", ""),
            "ssh_port": resp.get("sshPort", 22),
            "ssh_username": resp.get("sshUsername", ""),
            "web_host": resp.get("webHost", ""),
            "docker_image": resp.get("dockerImage", ""),
        }

    def start_environment(
        self,
        environment_id: str = "default",
        *,
        access_token: Optional[str] = None,
        public_keys: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Start environment — returns long-running Operation."""
        name = f"users/me/environments/{environment_id}"
        payload: dict[str, Any] = {}
        if access_token:
            payload["accessToken"] = access_token
        if public_keys:
            payload["publicKeys"] = public_keys


        body = self._post(f"{name}:start", payload)
        resp = body if isinstance(body, dict) else {}
        return {
            "operation_name": resp.get("name", ""),
            "done": resp.get("done", False),
        }

    def authorize_environment(
        self,
        name: str = "users/me/environments/default",
        access_token: Optional[str] = None,
        id_token: Optional[str] = None,
        expire_time: Optional[str] = None,
    ) -> dict[str, Any]:
        """Authorize environment — inject OAuth credentials."""
        payload: dict[str, Any] = {}
        if access_token:
            payload["accessToken"] = access_token
        if id_token:
            payload["idToken"] = id_token
        if expire_time:
            payload["expireTime"] = expire_time
        resp = self._post(f"{name}:authorize", payload)
        return {"operation_name": resp.get("name", "")}

    def add_public_key(
        self,
        name: str = "users/me/environments/default",
        key: str = "",
    ) -> dict[str, Any]:
        """Add SSH public key to environment — returns Operation."""
        resp = self._post(f"{name}:addPublicKey", {"key": key})
        return {"operation_name": resp.get("name", "")}

    def remove_public_key(
        self,
        name: str = "users/me/environments/default",
        key: str = "",
    ) -> dict[str, Any]:
        """Remove an SSH public key from the environment — returns Operation."""
        resp = self._post(f"{name}:removePublicKey", {"key": key})
        return {"operation_name": resp.get("name", "")}

    def get_operation(self, operation_name: str) -> dict[str, Any]:
        """Get long-running operation status."""
        resp = self._get(operation_name)
        return {
            "name": resp.get("name", ""),
            "done": resp.get("done", False),
            "error": resp.get("error"),
            "response": resp.get("response"),
        }

    def wait_operation(
        self,
        operation_name: str,
        timeout: float = 120,
    ) -> dict[str, Any]:
        """Poll until operation completes."""
        deadline = time.monotonic() + timeout
        while True:
            op = self.get_operation(operation_name)
            if op["done"]:
                if op.get("error"):
                    raise CloudShellAutomationError(
                        f"Operation {operation_name} failed: {op['error']}"
                    )
                return op.get("response", op)
            if time.monotonic() > deadline:
                raise CloudShellAutomationError(
                    f"Timeout ({timeout}s) waiting for operation {operation_name}"
                )
            time.sleep(2)

    def describe_environments(self) -> dict[str, Any]:
        """List environments."""
        env = self.get_environment()
        environments = [env] if env.get("name") else []
        return {"environments": environments, "request_id": None}

    def create_environment(self) -> dict[str, Any]:
        """Create environment."""
        result = self.start_environment()
        env = self.get_environment()
        return {
            "environment_id": env.get("name", "").rsplit("/", 1)[-1] or "default",
            "status": env.get("state", ""),
            "request_id": result.get("operation_name"),
        }

    def get_environment_status(self, environment_id: str) -> dict[str, Any]:
        """Get environment status."""
        name = f"users/me/environments/{environment_id}"
        env = self.get_environment(name)
        return {
            "status": env.get("state", ""),
            "request_id": None,
        }

    def send_heartbeat(self, environment_id: str) -> dict[str, Any]:
        """Send heartbeat (GCP doesn't require explicit heartbeats)."""
        return {}

    def put_credentials(self, env_id: str, creds: dict[str, Any]) -> dict[str, Any]:
        """Put credentials into the CloudShell environment (GCP uses authorize_environment)."""
        return self.authorize_environment(
            f"users/me/environments/{env_id}",
            access_token=creds.get("access_token"),
            id_token=creds.get("id_token"),
        )
