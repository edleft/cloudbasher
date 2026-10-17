#!/usr/bin/env python3
"""Read gcloud's local SQLite token caches and format cached GCP credentials."""

from __future__ import annotations

import argparse
import base64
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONFIG_DIR = Path.home() / ".config" / "gcloud"
ACCESS_DB = CONFIG_DIR / "access_tokens.db"
CREDENTIALS_DB = CONFIG_DIR / "credentials.db"
def _connect(path: Path) -> sqlite3.Connection:
    if not path.is_file():
        raise ValueError(f"required gcloud cache database is missing: {path}")
    try:
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection
    except sqlite3.Error as exc:
        raise ValueError(f"cannot open gcloud cache database {path.name}: {exc}") from None


def _decode_value(value: Any) -> Any:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _columns(cursor: sqlite3.Cursor) -> tuple[str, ...]:
    return tuple(column[0] for column in cursor.description or ())


def _records(db_path: Path, table: str, token_type: str) -> list[dict[str, Any]]:
    connection = _connect(db_path)
    try:
        cursor = connection.execute(f"SELECT * FROM {table}")
        columns = _columns(cursor)
        records: list[dict[str, Any]] = []
        for values in cursor.fetchall():
            row = dict(zip(columns, values, strict=True))
            if token_type == "refresh":
                if "value" in row:
                    row["value"] = _decode_value(row["value"])
                    credential = row["value"]
                    if not isinstance(credential, dict) or not credential.get("refresh_token"):
                        continue
            records.append({"token_type": token_type, **row})
        return records
    except sqlite3.Error as exc:
        raise ValueError(f"cannot read {db_path.name}:{table}: {exc}") from None
    finally:
        connection.close()


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(
            "time must be ISO-8601, e.g. 2026-10-08T18:30:00Z"
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _expiry(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return (
        lowered.endswith(("_token", "_secret"))
        or lowered in {"token", "secret", "value", "credential"}
    )


def _mask(value: Any) -> str:
    text = str(value or "")
    if not text:
        return ""
    if len(text) <= 16:
        return "*" * len(text)
    return f"{text[:8]}…{text[-6:]} (len={len(text)})"


def _redact(value: Any, key: str = "") -> Any:
    if _is_secret_key(key):
        if isinstance(value, dict):
            return {name: _redact(item, name) for name, item in value.items()}
        if isinstance(value, list):
            return [_redact(item, key) for item in value]
        return _mask(value)
    if isinstance(value, dict):
        return {name: _redact(item, name) for name, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, key) for item in value]
    return value


def _record_expiry(record: dict[str, Any]) -> datetime | None:
    return _expiry(record.get("token_expiry"))


def _local_expiry(value: Any) -> str:
    """Format a cache expiry in local time with offset and zone abbreviation."""
    parsed = _expiry(value)
    if parsed is None:
        return _field_value(value)
    local = parsed.astimezone()
    return f"{local.isoformat(timespec='seconds')} [{local.tzname() or 'local time'}]"


def load_records(
    token_type: str,
    account: str | None = None,
    expires_before: datetime | None = None,
    expires_after: datetime | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if token_type in ("refresh", "both"):
        records.extend(_records(CREDENTIALS_DB, "credentials", "refresh"))
    if token_type in ("access", "both"):
        records.extend(_records(ACCESS_DB, "access_tokens", "access"))

    selected: list[dict[str, Any]] = []
    for record in records:
        if account and str(record.get("account_id", "")).casefold() != account.casefold():
            continue
        if expires_before or expires_after:


            expiry = _record_expiry(record)
            if expiry is None:
                continue
            if expires_before and expiry > expires_before:
                continue
            if expires_after and expiry < expires_after:
                continue
        selected.append(record)


    def sort_key(record: dict[str, Any]) -> tuple[int, str | float]:
        if record["token_type"] == "refresh":
            return 0, str(record.get("account_id", "")).casefold()
        expiry = _record_expiry(record)
        return 1, -expiry.timestamp() if expiry else float("inf")

    selected.sort(key=sort_key)
    return selected


def _latest_rapt_by_account() -> dict[str, str]:
    """Return each cached account's RAPT from its latest-expiring AT row."""
    by_account: dict[str, list[dict[str, Any]]] = {}
    for record in _records(ACCESS_DB, "access_tokens", "access"):
        rapt = str(record.get("rapt_token") or "").strip()
        if rapt:
            account = str(record.get("account_id", "")).casefold()
            by_account.setdefault(account, []).append(record)
    result: dict[str, str] = {}
    for account, records in by_account.items():
        records.sort(
            key=lambda row: _record_expiry(row).timestamp()
            if _record_expiry(row)
            else float("-inf"),
            reverse=True,
        )
        result[account] = str(records[0]["rapt_token"])
    return result


def _field_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return str(value)


def render_table(records: list[dict[str, Any]]) -> None:
    for index, record in enumerate(records):
        if index:
            print()
        print(f"[{record['token_type'].upper()} TOKEN]")
        for key, value in record.items():
            shown = _redact(value, key)
            if key == "token_expiry":
                shown = _local_expiry(value)
            print(f"{key:<34} | {_field_value(shown)}")


def render_json(records: list[dict[str, Any]]) -> None:
    output = []
    for record in records:
        shown = _redact(record)
        if "token_expiry" in record:
            shown["token_expiry"] = _local_expiry(record["token_expiry"])
        output.append(shown)
    print(json.dumps(output, indent=2, ensure_ascii=False))


def _rc_values(
    record: dict[str, Any], rapt_by_account: dict[str, str] | None = None
) -> dict[str, Any]:
    kind = record["token_type"]
    if kind == "refresh":
        credential = _decode_value(record.get("value", {}))
        if not isinstance(credential, dict):
            credential = {}


        values = {
            key: credential[key]
            for key in (
                "type",
                "client_id",
                "client_secret",
                "refresh_token",
                "quota_project_id",
                "project_id",
            )
            if credential.get(key) not in (None, "")
        }
        values.setdefault("type", "authorized_user")
        values["email"] = record.get("account_id", "")
        rapt = (rapt_by_account or {}).get(
            str(record.get("account_id", "")).casefold()
        )
        if rapt:
            values["rapt_token"] = rapt
        return values


    return {
        "access_token": record.get("access_token", ""),
        "email": record.get("account_id", ""),
    }


def render_rc(records: list[dict[str, Any]]) -> None:
    rapt_by_account = _latest_rapt_by_account() if any(
        row["token_type"] == "refresh" for row in records
    ) else {}
    for index, record in enumerate(records):
        if index:
            print()
        values = _rc_values(record, rapt_by_account)
        print(f"# DESCRIPTION: GCP cached OAuth {record['token_type']} token")
        print("csp=gcp")
        for key, value in values.items():
            if key == "token_type":
                continue
            print(f"{key}={_field_value(value)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--account", help="exact cached account_id to select")
    parser.add_argument(
        "--token-type",
        choices=("refresh", "access", "both"),
        default="both",
        help="token database(s) to inspect (default: both)",
    )
    parser.add_argument(
        "--expires-before",
        type=_parse_time,
        help="include access tokens expiring at or before this ISO-8601 time (UTC if no zone)",
    )
    parser.add_argument(
        "--expires-after",
        type=_parse_time,
        help="include access tokens expiring at or after this ISO-8601 time (UTC if no zone)",
    )
    parser.add_argument(
        "--format", choices=("json", "table", "rc"), default="table", help="output format"
    )
    args = parser.parse_args(argv)

    try:
        records = load_records(
            args.token_type,
            account=args.account,
            expires_before=args.expires_before,
            expires_after=args.expires_after,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not records:
        print("No cached tokens matched the requested filters.")
        return 0
    if args.format == "json":
        render_json(records)
    elif args.format == "rc":
        print(
            "WARNING: rc output contains live OAuth credentials; protect it and "
            "keep it out of Git.",
            file=sys.stderr,
        )
        render_rc(records)
    else:
        render_table(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
