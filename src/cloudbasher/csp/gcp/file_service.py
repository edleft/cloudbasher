"""GCP CloudShell HTTP file service client."""

from __future__ import annotations

import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.utils.output import detail, log
from cloudbasher.csp.gcp._http import build_opener as _build_opener


class GCSFileService:
    """HTTP file service on cloudshell.dev port 8080."""

    def __init__(
        self,
        web_host: str,
        jwt: str,
        *,
        timeout: float = 30,
        proxy_url: Optional[str] = None,
        proxy_insecure: bool = False,
    ) -> None:

        host = web_host.removeprefix("8080-")
        self._base_url = f"https://8080-{host}/_cloudshell"
        self._jwt = jwt
        self._timeout = timeout
        self._opener = _build_opener(proxy_url, proxy_insecure)

    def _auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._jwt}"}


    def ls(self, dir_path: str = "/") -> list[dict[str, Any]]:
        """GET /_cloudshell/ls?dir={path} — directory listing."""
        params = urllib.parse.urlencode({"dir": dir_path})
        url = f"{self._base_url}/ls?{params}"
        detail(f"[file_service] GET {url}")
        req = urllib.request.Request(url)
        for k, v in self._auth_header().items():
            req.add_header(k, v)
        try:
            resp = self._opener.open(req, timeout=self._timeout)
            import json

            raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else []
        except urllib.error.HTTPError as e:
            raise CloudShellAutomationError(
                f"File service ls returned {e.code}: {e.read().decode('utf-8', 'replace')}"
            )


    def download_file(self, remote_path: str, local_path: Optional[str] = None) -> bytes:
        """GET /_cloudshell/file?path={remote_path} — download file."""
        params = urllib.parse.urlencode({"path": remote_path})
        url = f"{self._base_url}/file?{params}"
        detail(f"[file_service] GET {url}")
        req = urllib.request.Request(url)
        for k, v in self._auth_header().items():
            req.add_header(k, v)
        try:
            resp = self._opener.open(req, timeout=self._timeout)
            data = resp.read()
        except urllib.error.HTTPError as e:
            raise CloudShellAutomationError(
                f"File service download returned {e.code}: {e.read().decode('utf-8', 'replace')}"
            )

        if local_path:
            Path(local_path).write_bytes(data)
            log(
                f"[file_service] download remote={remote_path} local={local_path} bytes={len(data)}"
            )
        return data


    def upload_file(self, local_path: str, remote_dir: str) -> None:
        """POST /_cloudshell/file?path={remote_dir} — upload via multipart form."""
        local = Path(local_path)
        if not local.exists():
            raise FileNotFoundError(f"Local file not found: {local_path}")
        data = local.read_bytes()
        filename = local.name

        params = urllib.parse.urlencode({"path": remote_dir})
        url = f"{self._base_url}/file?{params}"
        detail(f"[file_service] POST {url} filename={filename} bytes={len(data)}")

        boundary = f"----GcsRunner{int(time.time() * 1000)}"
        preamble = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="uploadFile"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
        ).encode()
        epilogue = f"\r\n--{boundary}--\r\n".encode()
        body = preamble + data + epilogue

        headers = self._auth_header()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

        req = urllib.request.Request(url, data=body, method="POST")
        for k, v in headers.items():
            req.add_header(k, v)
        try:
            resp = self._opener.open(req, timeout=self._timeout)
            resp.read()
            log(
                f"[file_service] upload ok filename={filename} bytes={len(data)} remote_dir={remote_dir}"
            )
        except urllib.error.HTTPError as e:
            raise CloudShellAutomationError(
                f"File service upload returned {e.code}: {e.read().decode('utf-8', 'replace')}"
            )


    def upload_bytes(self, data: bytes, filename: str, remote_dir: str) -> None:
        """Upload raw bytes under filename into remote_dir."""
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=f"_{filename}", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            self.upload_file(tmp_path, remote_dir)
        finally:
            os.unlink(tmp_path)
