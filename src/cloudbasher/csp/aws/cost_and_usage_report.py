#!/usr/bin/env python3
"""AWS Cost & Usage Report (CUR) S3 reader."""

from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

from cloudbasher.core.utils.output import detail
from cloudbasher.csp.aws.credentials import AwsSessionCreds
from cloudbasher.csp.aws.signing import _build_url_opener, api_detail, sigv4_sign


def _current_month_manifest_key(
    report_name: str, prefix: str, *, today: Optional[dt.date] = None
) -> str:
    """Compute this month's CUR manifest S3 key from today's date."""
    if today is None:
        today = dt.date.today()

    period_start = today.replace(day=1)
    if period_start.month == 12:
        period_end = period_start.replace(year=period_start.year + 1, month=1)
    else:
        period_end = period_start.replace(month=period_start.month + 1)

    period = f"{period_start.strftime('%Y%m%d')}-{period_end.strftime('%Y%m%d')}"
    manifest_name = f"{report_name}-Manifest.json"

    segments = []
    if prefix:
        segments.append(prefix)
    segments.extend([report_name, report_name, period, manifest_name])
    return "/".join(segments)


def _s3_get_object(
    creds: AwsSessionCreds,
    *,
    bucket: str,
    key: str,
    region: str,
    timeout: int,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> bytes:
    """Fetch a single S3 object via a SigV4-signed GetObject GET request."""
    host = f"{bucket}.s3.{region}.amazonaws.com"


    encoded_key = urllib.parse.quote(key, safe="/")
    canonical_uri = f"/{encoded_key}"
    url = f"https://{host}{canonical_uri}"

    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    headers = sigv4_sign(
        method="GET",
        service="s3",
        region=region,
        host=host,
        canonical_uri=canonical_uri,
        canonical_query="",
        body=b"",
        creds=creds,
        amz_date=amz_date,
        date_stamp=date_stamp,
    )

    req = urllib.request.Request(url, headers=headers, method="GET")
    opener = _build_url_opener(proxy_url, proxy_insecure=proxy_insecure)

    api_detail(creds, f"S3 request: GET {url}")

    with opener.open(req, timeout=timeout) as resp:
        return resp.read()


def fetch_month_to_date_summary(
    creds: AwsSessionCreds,
    *,
    bucket: str,
    report_name: str,
    prefix: str = "",
    region: str,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    today: Optional[dt.date] = None,
) -> dict[str, Any]:
    """Fetch this month's CUR manifest + CSV part(s) from S3, aggregate lineItem/UnblendedCost by product/ProductName."""
    manifest_key = _current_month_manifest_key(report_name, prefix, today=today)

    try:
        manifest_bytes = _s3_get_object(
            creds,
            bucket=bucket,
            key=manifest_key,
            region=region,
            timeout=timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            api_detail(creds, f"CUR manifest not found: s3://{bucket}/{manifest_key}")
            return {
                "ok": False,
                "total_usd": 0.0,
                "by_service": [],
                "error": (
                    "CUR report not yet delivered for this billing period, or the "
                    "bucket/report_name/prefix configuration doesn't match a real "
                    "report -- first delivery after enabling CUR can take up to 24 "
                    "hours."
                ),
            }
        api_detail(creds, f"CUR manifest fetch failed: HTTP {exc.code}")
        return {
            "ok": False,
            "total_usd": 0.0,
            "by_service": [],
            "error": f"Failed to fetch CUR manifest: HTTP {exc.code}",
        }
    except urllib.error.URLError as exc:
        api_detail(creds, f"CUR manifest fetch failed: {exc.reason}")
        return {
            "ok": False,
            "total_usd": 0.0,
            "by_service": [],
            "error": f"Failed to fetch CUR manifest: {exc.reason}",
        }
    except Exception as exc:  # pragma: no cover - defensive, never raise
        api_detail(creds, f"CUR manifest fetch failed: {exc}")
        return {
            "ok": False,
            "total_usd": 0.0,
            "by_service": [],
            "error": f"Failed to fetch CUR manifest: {exc}",
        }

    try:
        manifest = json.loads(manifest_bytes.decode("utf-8", "replace"))
        report_keys = manifest.get("reportKeys", [])
    except Exception as exc:
        detail(f"CUR manifest parse failed: {exc}")
        return {
            "ok": False,
            "total_usd": 0.0,
            "by_service": [],
            "error": f"Failed to parse CUR manifest: {exc}",
        }

    if not report_keys:
        return {
            "ok": False,
            "total_usd": 0.0,
            "by_service": [],
            "error": "CUR manifest has no report data files (reportKeys is empty).",
        }

    totals_by_service: dict[str, float] = {}

    try:
        for report_key in report_keys:
            raw_bytes = _s3_get_object(
                creds,
                bucket=bucket,
                key=report_key,
                region=region,
                timeout=timeout,
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
            )
            csv_text = gzip.decompress(raw_bytes).decode("utf-8", "replace")
            reader = csv.DictReader(io.StringIO(csv_text))
            for row in reader:
                service = row.get("product/ProductName")
                cost_raw = row.get("lineItem/UnblendedCost")
                if not service or cost_raw is None:
                    continue
                try:
                    cost = float(cost_raw)
                except (TypeError, ValueError):
                    continue
                totals_by_service[service] = totals_by_service.get(service, 0.0) + cost
    except Exception as exc:
        api_detail(creds, f"CUR report data fetch/parse failed: {exc}")
        return {
            "ok": False,
            "total_usd": 0.0,
            "by_service": [],
            "error": f"Failed to fetch/parse CUR report data: {exc}",
        }

    by_service = sorted(totals_by_service.items(), key=lambda kv: kv[1], reverse=True)
    total_usd = sum(totals_by_service.values())

    return {
        "ok": True,
        "total_usd": total_usd,
        "by_service": by_service,
        "error": "",
    }


def format_billing_summary(summary: dict[str, Any], *, top_n: int = 10) -> str:
    """Render a fetch_month_to_date_summary() result as a display string: a month-to-date total line, then up to top_n services sorted descending by cost. If summary["ok"] is False, render the error message instead (never crash on a failed fetch)."""
    try:
        if not summary.get("ok"):
            error = summary.get("error") or "Unknown error fetching billing data."
            return f"Billing data unavailable: {error}"

        total_usd = summary.get("total_usd", 0.0)
        by_service = summary.get("by_service", [])

        lines = [f"Month-to-date: ${total_usd:,.2f}"]
        for service, cost in by_service[:top_n]:
            lines.append(f"  {service:<28} ${cost:,.2f}")
        return "\n".join(lines)
    except Exception as exc:  # pragma: no cover - defensive, never raise
        return f"Billing data unavailable: {exc}"
