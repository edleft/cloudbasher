"""GCP-specific dot commands registered via GCPProvider.register_dot_commands()."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cloudbasher.core.utils.output import detail, eprint, log, out

if TYPE_CHECKING:
    from cloudbasher.core.types import InteractiveState


def cmd_token(args: list[str], state: "InteractiveState") -> bool:
    """.token — generate/refresh access JWT for GCP file service."""
    api = getattr(state, "api_client", None)
    if api is None:
        eprint("token: no API client available")
        return True

    gen = getattr(api, "generate_access_token", None)
    if gen is None:
        eprint("token: generate_access_token not available on public API (use --api-path private)")
        return True

    try:
        jwt = gen()
        out(f"Access JWT obtained (len={len(jwt)})")
        log(f"[token] generate_access_token ok jwt_len={len(jwt)}")
    except Exception as e:
        eprint(f"token: {e}")
    return True


def cmd_quota(args: list[str], state: "InteractiveState") -> bool:
    """.quota — show CloudShell weekly usage quota."""
    api = getattr(state, "api_client", None)
    if api is None:
        eprint("quota: no API client available")
        return True

    quota_fn = getattr(api, "quota", None)
    if quota_fn is None:
        eprint("quota: not available on public API (use --api-path private)")
        return True

    try:
        resp = quota_fn()
        if isinstance(resp, list) and resp and isinstance(resp[0], list):
            used, total, reset = resp[0][0], resp[0][1], resp[0][2]
            used_h = used // 3600
            total_h = total // 3600
            import datetime

            reset_dt = datetime.datetime.fromtimestamp(reset / 1000, tz=datetime.timezone.utc)
            out(f"Used : {used_h}h / {total_h}h")
            out(f"Reset: {reset_dt.strftime('%Y-%m-%d %H:%M UTC')}")
        else:
            out(f"Quota: {resp}")
        log(f"[quota] csp=gcp")
    except Exception as e:
        eprint(f"quota: {e}")
    return True


def cmd_fsls(args: list[str], state: "InteractiveState") -> bool:
    """.fsls [path] — list remote directory via HTTP file service."""
    fs = getattr(state, "_gcs_file_service", None)
    if fs is None:
        eprint("fsls: GCS file service not wired (use --api-path private and --gcp)")
        return True

    path = args[0] if args else "/"
    try:
        entries = fs.ls(path)
        if not entries:
            out(f"(empty directory: {path})")
        else:
            for entry in entries:
                name = entry.get("name", "?")
                is_dir = entry.get("is_dir", False)
                suffix = "/" if is_dir else ""
                out(f"  {name}{suffix}")
        log(f"[fsls] path={path} entries={len(entries)}")
    except Exception as e:
        eprint(f"fsls: {e}")
    return True


def cmd_fsupload(args: list[str], state: "InteractiveState") -> bool:
    """.fsupload <local_path> <remote_dir> — upload via HTTP file service."""
    if len(args) < 2:
        eprint("Usage: .fsupload <local_path> <remote_dir>")
        return True
    local_path, remote_dir = args[0], args[1]

    fs = getattr(state, "_gcs_file_service", None)
    if fs is None:
        eprint("fsupload: GCS file service not wired (use --api-path private and --gcp)")
        return True

    try:
        fs.upload_file(local_path, remote_dir)
        out(f"Uploaded {local_path} → {remote_dir}")
    except Exception as e:
        eprint(f"fsupload: {e}")
    return True


def cmd_fsdownload(args: list[str], state: "InteractiveState") -> bool:
    """.fsdownload <remote_path> <local_path> — download via HTTP file service."""
    if len(args) < 2:
        eprint("Usage: .fsdownload <remote_path> <local_path>")
        return True
    remote_path, local_path = args[0], args[1]

    fs = getattr(state, "_gcs_file_service", None)
    if fs is None:
        eprint("fsdownload: GCS file service not wired (use --api-path private and --gcp)")
        return True

    try:
        fs.download_file(remote_path, local_path)
        out(f"Downloaded {remote_path} → {local_path}")
    except Exception as e:
        eprint(f"fsdownload: {e}")
    return True


def register_gcp_commands(dispatcher: Any) -> None:
    """Register all GCP-specific dot commands with the dispatcher."""
    dispatcher.register(".token", cmd_token)
    dispatcher.register(".quota", cmd_quota)
    dispatcher.register(".fsls", cmd_fsls)
    dispatcher.register(".fsupload", cmd_fsupload)
    dispatcher.register(".fsdownload", cmd_fsdownload)
