#!/usr/bin/env python3
"""Force one gcloud OAuth refresh using the existing local token databases."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


def _config_dir() -> Path:
    configured = os.environ.get("CLOUDSDK_CONFIG")
    return Path(configured).expanduser() if configured else Path.home() / ".config" / "gcloud"


def _db(path: Path, *, readonly: bool = False) -> sqlite3.Connection:
    if not path.is_file():
        raise ValueError(f"missing gcloud cache database: {path.name}")
    if readonly:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
    else:
        connection = sqlite3.connect(path, timeout=5)
    connection.execute("PRAGMA busy_timeout=5000")
    return connection


def _columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in connection.execute(f'PRAGMA table_info("{table}")'))


def _has_refresh_credential(config_dir: Path, account: str) -> bool:
    connection = _db(config_dir / "credentials.db", readonly=True)
    try:
        columns = _columns(connection, "credentials")
        if not {"account_id", "value"}.issubset(columns):
            raise ValueError("unrecognized gcloud credentials.db schema")
        row = connection.execute(
            "SELECT value FROM credentials WHERE account_id = ?", (account,)
        ).fetchone()
        if row is None:
            return False
        value = row[0]
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")
        return "refresh_token" in str(value)
    finally:
        connection.close()


def _snapshot_access_row(
    config_dir: Path, account: str
) -> tuple[tuple[str, ...], tuple[object, ...]]:
    connection = _db(config_dir / "access_tokens.db")
    try:
        columns = _columns(connection, "access_tokens")
        if not {"account_id", "access_token", "token_expiry", "rapt_token"}.issubset(
            columns
        ):
            raise ValueError("unrecognized gcloud access_tokens.db schema")
        cursor = connection.execute(
            "SELECT * FROM access_tokens WHERE account_id = ?", (account,)
        )
        row = cursor.fetchone()
        if row is None:
            raise ValueError("no cached access-token row for this account")
        record = dict(zip(columns, row, strict=True))
        if not record.get("access_token"):
            raise ValueError("cached access-token row has no token to expire")
        return columns, tuple(row)
    finally:
        connection.close()


def _replace_access_row(
    config_dir: Path,
    account: str,
    columns: Sequence[str],
    row: Sequence[object],
) -> None:
    quoted = ", ".join('"' + column.replace('"', '""') + '"' for column in columns)
    placeholders = ", ".join("?" for _ in columns)
    connection = _db(config_dir / "access_tokens.db")
    try:
        with connection:
            connection.execute(
                f'REPLACE INTO access_tokens ({quoted}) VALUES ({placeholders})',
                tuple(row),
            )
    finally:
        connection.close()


def _expire_access_row(config_dir: Path, account: str) -> None:
    connection = _db(config_dir / "access_tokens.db")
    try:
        with connection:
            cursor = connection.execute(
                "UPDATE access_tokens SET token_expiry = ? WHERE account_id = ?",
                ("1970-01-01 00:00:00", account),
            )
            if cursor.rowcount != 1:
                raise ValueError("expected exactly one cached access-token row")
    finally:
        connection.close()


def _cache_has_fresh_access_token(config_dir: Path, account: str) -> bool:
    connection = _db(config_dir / "access_tokens.db", readonly=True)
    try:
        row = connection.execute(
            "SELECT access_token, token_expiry FROM access_tokens WHERE account_id = ?",
            (account,),
        ).fetchone()
        if row is None or not row[0] or not row[1]:
            return False
        expiry = row[1]
        if isinstance(expiry, datetime):
            parsed = expiry
        else:
            parsed = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc) > datetime.now(timezone.utc)
    except (sqlite3.Error, ValueError):
        return False
    finally:
        connection.close()


def _configured_impersonation(gcloud: str) -> bool | None:
    try:
        result = subprocess.run(
            [gcloud, "config", "get-value", "auth/impersonate_service_account", "--quiet"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = result.stdout.strip().casefold()
    return result.returncode == 0 and value not in {"", "(unset)", "none", "null"}


def _failure_reason(stderr: str) -> str:
    lower = stderr.casefold()
    if "invalid_rapt" in lower or "rapt_required" in lower:
        return "invalid_rapt"
    if "invalid_grant" in lower:
        return "invalid_grant"
    if "invalid_client" in lower:
        return "invalid_client"
    if "reauth" in lower or "reauthentication" in lower:
        return "reauth_required"
    status = re.search(r"\bHTTP(?: error)?\s+(\d{3})\b", stderr, re.IGNORECASE)
    if status:
        return f"http_{status.group(1)}"
    return "gcloud_error"


def run(
    account: str, *, confirm: bool, show_token: bool = False, timeout: int = 180
) -> int:
    if not confirm:
        print("Refusing cache mutation without --confirm-cache-write.", file=sys.stderr)
        return 2

    config_dir = _config_dir()
    gcloud = shutil.which("gcloud")
    if not gcloud:
        print("gcloud executable not found on PATH.", file=sys.stderr)
        return 2

    try:
        if not _has_refresh_credential(config_dir, account):
            raise ValueError("no refresh credential found for the selected account")
        columns, original_row = _snapshot_access_row(config_dir, account)
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(f"gcloud_refresh=not_attempted reason={exc}")
        return 2

    impersonation = _configured_impersonation(gcloud)
    if impersonation is None:
        print("gcloud_refresh=not_attempted reason=cannot_check_impersonation")
        return 2
    if impersonation:
        print("gcloud_refresh=not_attempted reason=service_account_impersonation_configured")
        return 2

    print(
        "Forcing one gcloud refresh; do not run another gcloud command concurrently.",
        file=sys.stderr,
    )
    try:
        _expire_access_row(config_dir, account)
        result = subprocess.run(
            [gcloud, "auth", "print-access-token", account, "--verbosity=error"],
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        access_token = result.stdout.strip()
        if (
            result.returncode == 0
            and access_token
            and _cache_has_fresh_access_token(config_dir, account)
        ):
            if show_token:
                print(access_token)
            print(
                "gcloud_refresh=success cache_updated=yes "
                f"token_printed={'yes' if show_token else 'no'}"
            )
            return 0

        reason = (
            _failure_reason(result.stderr)
            if result.returncode != 0
            else "token_output_or_cache_missing"
        )
        _replace_access_row(config_dir, account, columns, original_row)
        print(f"gcloud_refresh=failed reason={reason} original_cache_restored=yes")
        return 1
    except subprocess.TimeoutExpired:
        _replace_access_row(config_dir, account, columns, original_row)
        print("gcloud_refresh=failed reason=timeout original_cache_restored=yes")
        return 1
    except KeyboardInterrupt:
        _replace_access_row(config_dir, account, columns, original_row)
        print("\ngcloud_refresh=interrupted original_cache_restored=yes")
        return 130
    except (OSError, sqlite3.Error, ValueError) as exc:
        _replace_access_row(config_dir, account, columns, original_row)

        print(f"gcloud_refresh=failed reason=local_error detail={type(exc).__name__}")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--account", required=True, help="gcloud account email to refresh")
    parser.add_argument(
        "--confirm-cache-write",
        action="store_true",
        help="allow temporary expiry change in the existing access_tokens.db",
    )
    parser.add_argument(
        "--show-token",
        action="store_true",
        help="print the refreshed access token to stdout (sensitive; default: hidden)",
    )
    parser.add_argument(
        "--timeout", type=int, default=180, help="gcloud refresh timeout in seconds (default: 180)"
    )
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 600:
        parser.error("--timeout must be between 1 and 600 seconds")
    return run(
        args.account,
        confirm=args.confirm_cache_write,
        show_token=args.show_token,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    raise SystemExit(main())
