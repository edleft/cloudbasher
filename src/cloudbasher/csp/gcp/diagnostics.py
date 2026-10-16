#!/usr/bin/env python3
"""Turn a GCP CloudShell public-API failure into a message that says what to do."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional


_USERS_SEGMENT = re.compile(r"(?:^|/)users/([^/]+)/")


_HTML_MARKERS = ("<!doctype html", "<html", "accounts.google.com/signin", "<meta ")


_NO_PERMISSION_STORY = (
    "This is not a permission problem -- Cloud Shell has no IAM role or "
    "permission of its own to grant or withhold (#631)."
)

_SERVICE_USAGE_PERMISSION_MARKERS = (
    "serviceusage.services.use",
    "serviceusage.serviceusageconsumer",
)


def is_cloudshell_api_disabled(body: Any) -> bool:
    """Recognize Google's structured SERVICE_DISABLED response for Cloud Shell."""
    if isinstance(body, dict):
        error = body.get("error")
        if isinstance(error, dict):
            details = error.get("details")
            if isinstance(details, list) and any(
                isinstance(detail, dict)
                and str(detail.get("reason") or "").upper() == "SERVICE_DISABLED"
                and str((detail.get("metadata") or {}).get("service") or "")
                == "cloudshell.googleapis.com"
                for detail in details
            ):
                return True
    text = body if isinstance(body, str) else json.dumps(body, default=str)
    lowered = text.lower()
    return "service_disabled" in lowered and "cloudshell.googleapis.com" in lowered


def is_quota_project_service_usage_denial(body: Any) -> bool:
    """Recognize only explicit Service Usage quota-project denials."""
    text = body if isinstance(body, str) else json.dumps(body, default=str)
    lowered = text.lower()
    return any(marker in lowered for marker in _SERVICE_USAGE_PERMISSION_MARKERS)


def quota_project_service_usage_message(project: Optional[str] = None) -> str:
    """Return actionable, non-secret remediation for the observed 403 shape."""
    project_label = f"quota project {project!r}" if project else "the quota project"
    return (
        "The OAuth token is valid, but Cloud Shell provisioning is blocked: "
        f"{project_label} does not grant `serviceusage.services.use` to this "
        "Google identity. Grant Service Usage Consumer "
        "(`roles/serviceusage.serviceUsageConsumer`) on that project, or use a "
        "quota project where this identity already has the permission. This is "
        "project authorization, not an invalid or expired refresh token."
    )


def addressed_user(path: str) -> Optional[str]:
    """Return the `users/<segment>` of a resource path, or None if absent."""
    m = _USERS_SEGMENT.search(path)
    return m.group(1) if m else None


def is_cross_user(path: str) -> bool:
    """True when the path names somebody other than the self-alias."""
    who = addressed_user(path)
    return who is not None and who != "me"


def looks_like_login_page(body: Any) -> bool:
    """True when a JSON endpoint served HTML instead."""
    if not isinstance(body, str):
        return False
    head = body[:2048].lstrip().lower()


    if not head.startswith("<"):
        return False
    return any(marker in head for marker in _HTML_MARKERS)


def _tail(body: Any, limit: int = 300) -> str:
    text = body if isinstance(body, str) else repr(body)
    text = " ".join(text.split())
    return text[:limit]


def diagnose(method: str, path: str, status: int, body: Any) -> str:
    """Build the operator-facing message for a failed public-API call."""
    where = f"{method} {path}"

    if looks_like_login_page(body):
        return (
            f"{where} returned HTTP 200 with a sign-in page instead of JSON. The "
            "credential was not accepted — Google silently redirects an "
            "unauthenticated caller here rather than answering 401 or 403, so a "
            "200 is not success on this API. Re-authenticate and retry; if the "
            "token was just minted, check it carries the cloud-platform scope, "
            "which is the only scope any CloudShell method accepts."
        )

    if status == 401:
        return (
            f"{where} returned 401. The access token is expired or invalid, and a "
            "refresh was either not configured or did not help. Re-authenticate."
        )

    if status == 403:
        if is_quota_project_service_usage_denial(body):
            return (
                f"{where} returned 403: "
                f"{quota_project_service_usage_message()}"
            )
        if is_cloudshell_api_disabled(body):
            return (
                f"{where} returned 403: the Cloud Shell API "
                "(`cloudshell.googleapis.com`) is disabled for the effective "
                "consumer project (SERVICE_DISABLED). Enable the API on that "
                "project with an authorized project administrator, wait for "
                "the change to propagate, then retry. This is not an invalid "
                "OAuth token or a Cloud Shell IAM-role denial; CloudBasher did "
                "not enable or modify any API."
            )
        return (
            f"{where} returned 403 PERMISSION_DENIED. The response did not match "
            "the known quota-project Service Usage denial or Cloud Shell API "
            "SERVICE_DISABLED response. Inspect Google's returned reason and "
            f"project/service metadata before changing IAM. Body: {_tail(body)}"
        )

    if status == 404:
        who = addressed_user(path)
        whose = "your own" if who in (None, "me") else f"{who}'s"
        return (
            f"{where} returned 404: no CloudShell environment exists at that address. "
            f"The path names {whose} environment; an environment is addressed by the "
            "owner's own email address, or by the alias 'me' for the caller."
        )

    if status == 500:
        if is_cross_user(path):
            return (
                f"{where} returned 500. The path addresses {addressed_user(path)}, who is "
                "not the caller. Every observed cross-user call has come back 500 "
                "INTERNAL rather than a refusal, so this reads as 'that is not your "
                f"environment' and not as a backend fault. {_NO_PERMISSION_STORY} "
                "Address your own environment with users/me."
            )
        if ":start" in path:
            return (
                f"{where} returned 500. A service-account identity cannot start a "
                "CloudShell environment — it can read the record (SUSPENDED) and gets "
                "500 on the start, because the environment belongs to a human Google "
                "Account with billing and quota context behind it. Use a personal "
                f"Gmail or Workspace account. {_NO_PERMISSION_STORY} No role grant "
                "changes this outcome."
            )
        return (
            f"{where} returned 500. This surface answers 500 for at least three "
            "distinct causes and does not distinguish them in the status: a "
            "service-account identity attempting a write, an environment addressed "
            "to somebody other than the caller, and genuine backend faults. "
            f"{_NO_PERMISSION_STORY} Body: {_tail(body)}"
        )

    return f"{where} returned {status}: {_tail(body)}"


def private_capture_dir() -> Path:
    """Create an owner-only diagnostics directory outside the current repo."""
    path = Path(tempfile.mkdtemp(prefix="cloudbasher-gcp-private-"))
    os.chmod(path, 0o700)
    repo_root = Path(__file__).resolve().parents[4]
    if path.resolve().is_relative_to(repo_root):
        raise RuntimeError("private GCP diagnostics unexpectedly landed in the repository")
    return path


def write_private(path: Path, name: str, data: bytes) -> Path:
    """Write one private artifact with mode 0600, replacing only this run's file."""
    target = path / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(target, 0o600)
    return target


def append_private_jsonl(path: Path, name: str, record: dict[str, Any]) -> None:
    """Append a complete protocol exchange; contents are intentionally sensitive."""
    target = path / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "ab") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, default=str).encode() + b"\n")
        stream.flush()
    os.chmod(target, 0o600)
