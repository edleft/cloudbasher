#!/usr/bin/env python3
"""Summarise an MSAL token cache (``~/.azure/msal_token_cache.json``)."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_PATH = Path.home() / ".azure" / "msal_token_cache.json"


PROFILE_NAME = "azureProfile.json"

GUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


TYPE_NAMES = {"AccessToken": "access", "RefreshToken": "refresh", "IdToken": "id"}


KNOWN_CLIENTS = {
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Azure CLI",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Azure PowerShell",
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": "Azure Portal",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "Azure Active Directory PowerShell",
    "00000002-0000-0000-c000-000000000000": "Azure AD Graph",
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1": "Visual Studio",
    "aebc6443-996d-45c2-90f0-388ff96faa56": "Visual Studio Code",
    "18fbca16-2224-45f6-85b0-f7bf2b39b3f3": "Microsoft Docs",
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064": "Graph Explorer",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph CLI",
}


SECRET_FIELDS = ("secret", "id_token", "access_token", "refresh_token")


CLAIM_ORDER = (
    "aud",
    "iss",
    "appid",
    "app_displayname",
    "appidacr",
    "idtyp",
    "upn",
    "unique_name",
    "preferred_username",
    "email",
    "name",
    "oid",
    "tid",
    "sub",
    "ver",
    "iat",
    "nbf",
    "exp",
    "scp",
    "roles",
    "wids",
    "groups",
    "amr",
    "acr",
    "auth_time",
    "ipaddr",
    "ctry",
    "puid",
    "rh",
    "xms_cc",
)


def obfuscate(value: str, keep: int = 6) -> str:
    """first6 + ****** + last6. Short values are fully hidden."""
    if not value:
        return ""
    if len(value) <= keep * 2 + 4:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * keep}{value[-keep:]}"


def local_time(epoch) -> str:
    """Epoch seconds -> 'YYYY-MM-DD HH:MM:SS TZ' in local time."""
    if epoch in (None, ""):
        return ""
    try:
        secs = float(epoch)
    except (TypeError, ValueError):
        return str(epoch)
    if secs > 1e11:
        secs /= 1000.0
    dt = datetime.fromtimestamp(secs, tz=timezone.utc).astimezone()
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def relative(epoch, now: float | None = None) -> str:
    """'in 42m' / '3h12m ago' / '' when unparseable."""
    if epoch in (None, ""):
        return ""
    try:
        secs = float(epoch)
    except (TypeError, ValueError):
        return ""
    if secs > 1e11:
        secs /= 1000.0
    delta = secs - (now if now is not None else time.time())
    future = delta >= 0
    delta = abs(delta)
    d, rem = divmod(int(delta), 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        span = f"{d}d{h}h"
    elif h:
        span = f"{h}h{m}m"
    elif m:
        span = f"{m}m{s}s"
    else:
        span = f"{s}s"
    return f"in {span}" if future else f"{span} ago"


def when(epoch) -> str:
    """Local time with the relative offset appended."""
    if epoch in (None, ""):
        return "-"
    rel = relative(epoch)
    return f"{local_time(epoch)} ({rel})" if rel else local_time(epoch)


def client_label(client_id: str) -> str:
    name = KNOWN_CLIENTS.get(client_id)
    return f"{name} [{client_id}]" if name else (client_id or "-")


def short_client(client_id: str) -> str:
    """Table-sized client label: name if known, else the full uuid."""
    return KNOWN_CLIENTS.get(client_id) or client_id or "-"


def summarise_scopes(target: str) -> str:
    """'https://x/.default https://x/user_impersonation' -> 'x/ [.default, user_impersonation]'."""
    if not target:
        return "-"
    by_resource: dict[str, list[str]] = {}
    for scope in target.split():
        if "://" in scope:
            rest = scope.split("://", 1)[1]
            resource, _, leaf = rest.rpartition("/")
            resource = resource or rest
        else:
            resource, leaf = "", scope
        by_resource.setdefault(resource, []).append(leaf or "/")
    return "; ".join(
        f"{res}/ [{', '.join(scopes)}]" if res else ", ".join(scopes)
        for res, scopes in by_resource.items()
    )


def decode_jwt_claims(token: str) -> dict | None:
    """Payload of a JWS, unverified. None when the value isn't a JWT."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def short_account(home_account_id: str) -> str:
    """'<oid>.<tid>' -> '<oid[:8]>…' -- enough to correlate rows."""
    if not home_account_id:
        return "-"
    return home_account_id.split(".", 1)[0][:8] + "…"


def render_table(headers, rows, out=sys.stdout) -> None:
    """Left-aligned table, greedily shrunk to the terminal width."""
    if not rows:
        out.write("  (none)\n")
        return
    widths = [max(len(headers[i]), *(len(r[i]) for r in rows)) for i in range(len(headers))]
    limit = shutil.get_terminal_size((120, 24)).columns - 2
    while sum(widths) + 2 * (len(widths) - 1) > limit:
        widest = max(range(len(widths)), key=lambda i: widths[i])
        if widths[widest] <= 10:
            break
        widths[widest] -= 1

    def fmt(cells):
        parts = []
        for cell, width in zip(cells, widths):
            cell = cell if len(cell) <= width else cell[: width - 1] + "…"
            parts.append(cell.ljust(width))
        return "  ".join(parts).rstrip()

    out.write("  " + fmt(headers) + "\n")
    out.write("  " + fmt(["-" * w for w in widths]) + "\n")
    for row in rows:
        out.write("  " + fmt(row) + "\n")


def section(title: str, out=sys.stdout) -> None:
    out.write(f"\n{title}\n{'=' * len(title)}\n")


def build(cache: dict) -> dict:
    """Cache dict -> per-section lists of display-ready records."""
    accounts = []
    by_home_id: dict[str, dict] = {}
    for key, entry in sorted(cache.get("Account", {}).items()):
        record = {
            "key": key,
            "home_account_id": entry.get("home_account_id", ""),
            "username": entry.get("username", ""),
            "local_account_id": entry.get("local_account_id", ""),
            "realm": entry.get("realm", ""),
            "environment": entry.get("environment", ""),
            "authority_type": entry.get("authority_type", ""),
            "account_source": entry.get("account_source", ""),
        }
        accounts.append(record)
        by_home_id[record["home_account_id"]] = record

    def identity(entry: dict) -> str:
        home = entry.get("home_account_id", "")
        account = by_home_id.get(home)
        return account["username"] if account and account["username"] else short_account(home)

    def credential(key: str, entry: dict) -> dict:
        secret = entry.get("secret", "")
        claims = decode_jwt_claims(secret)
        return {
            "key": key,
            "identity": identity(entry),
            "home_account_id": entry.get("home_account_id", ""),
            "client_id": entry.get("client_id", ""),
            "client": client_label(entry.get("client_id", "")),
            "realm": entry.get("realm", ""),
            "environment": entry.get("environment", ""),
            "credential_type": entry.get("credential_type", ""),
            "token_type": entry.get("token_type", ""),
            "target": entry.get("target", ""),
            "scopes": summarise_scopes(entry.get("target", "")),
            "cached_at": entry.get("cached_at", ""),
            "expires_on": entry.get("expires_on", ""),
            "extended_expires_on": entry.get("extended_expires_on", ""),
            "last_modification_time": entry.get("last_modification_time", ""),
            "family_id": entry.get("family_id", ""),
            "secret": secret,
            "secret_len": len(secret),
            "secret_masked": obfuscate(secret),
            "is_jwt": claims is not None,
            "claims": claims,
        }

    return {
        "accounts": accounts,
        "access_tokens": [
            credential(k, v) for k, v in sorted(cache.get("AccessToken", {}).items())
        ],
        "refresh_tokens": [
            credential(k, v) for k, v in sorted(cache.get("RefreshToken", {}).items())
        ],
        "id_tokens": [credential(k, v) for k, v in sorted(cache.get("IdToken", {}).items())],
        "app_metadata": [
            {
                "key": k,
                "client_id": v.get("client_id", ""),
                "client": client_label(v.get("client_id", "")),
                "environment": v.get("environment", ""),
                "family_id": v.get("family_id", ""),
            }
            for k, v in sorted(cache.get("AppMetadata", {}).items())
        ],
    }


FILTER_ALIASES = {
    "type": "type",
    "kind": "type",
    "identity": "identity",
    "upn": "identity",
    "user": "identity",
    "username": "identity",
    "tenant": "tenant",
    "tenant_id": "tenant",
    "tenantid": "tenant",
    "tid": "tenant",
    "realm": "tenant",
    "subscription": "subscription",
    "subscription_id": "subscription",
    "subscriptionid": "subscription",
    "sub": "subscription",
    "client": "client",
    "client_id": "client",
    "clientid": "client",
    "app": "client",
    "resource": "resource",
    "scope": "resource",
    "audience": "resource",
    "aud": "resource",
}

FILTER_FIELDS = sorted(set(FILTER_ALIASES.values()))


def load_subscriptions(cache_path: Path) -> list[dict]:
    """az CLI subscription list, read beside the cache. [] when absent."""
    for candidate in (cache_path.parent / PROFILE_NAME, DEFAULT_PATH.parent / PROFILE_NAME):
        try:

            data = json.loads(candidate.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        subs = data.get("subscriptions")
        if isinstance(subs, list):
            return [s for s in subs if isinstance(s, dict)]
    return []


def _dedupe(values) -> list[str]:
    seen, out = set(), []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def record_tenants(rec: dict) -> list[str]:
    """Every tenant id this record could be matched by."""
    claims = rec.get("claims") or {}
    realm = rec.get("realm") or ""
    issued = _dedupe(
        [
            claims.get("tid") or "",
            realm if GUID_RE.fullmatch(realm) else "",
        ]
    )
    if issued:
        return issued
    home = rec.get("home_account_id") or ""
    return _dedupe([home.split(".", 1)[1]] if "." in home else [])


def match_values(rec: dict, field: str, subs: list[dict]) -> list[str]:
    """The strings a filter on `field` is tested against. Any hit is a match."""
    claims = rec.get("claims") or {}
    if field == "type":
        credential_type = rec.get("credential_type", "")
        return _dedupe([TYPE_NAMES.get(credential_type, ""), credential_type])
    if field == "identity":
        return _dedupe(
            [
                rec.get("identity", ""),
                rec.get("home_account_id", ""),
                claims.get("upn") or "",
                claims.get("preferred_username") or "",
                claims.get("unique_name") or "",
                claims.get("email") or "",
                claims.get("name") or "",
            ]
        )
    if field == "tenant":
        return record_tenants(rec)
    if field == "client":
        client_id = rec.get("client_id", "")
        return _dedupe(
            [
                client_id,
                KNOWN_CLIENTS.get(client_id, ""),
                claims.get("appid") or "",
                claims.get("app_displayname") or "",
            ]
        )
    if field == "resource":
        aud = claims.get("aud")
        aud_values = aud if isinstance(aud, list) else [aud or ""]
        return _dedupe([rec.get("target", ""), *aud_values, claims.get("scp") or ""])
    if field == "subscription":
        tenants = set(record_tenants(rec))
        return _dedupe(
            [
                value
                for s in subs
                if {s.get("tenantId", ""), s.get("homeTenantId", "")} & tenants
                for value in (s.get("id", ""), s.get("name", ""))
            ]
        )
    raise KeyError(field)


def parse_filters(specs: list[str]) -> list[tuple[str, "re.Pattern[str]"]]:
    """['upn=merlin', 'type=access'] -> [(field, compiled regex), ...]."""
    parsed = []
    for spec in specs:
        key, sep, pattern = spec.partition("=")
        if not sep:
            raise ValueError(f"--filter needs KEY=REGEX, got {spec!r}")
        field = FILTER_ALIASES.get(key.strip().lower())
        if field is None:
            raise ValueError(
                f"unknown filter key {key.strip()!r}; known keys: "
                + ", ".join(sorted(FILTER_ALIASES))
            )
        try:
            parsed.append((field, re.compile(pattern, re.I)))
        except re.error as exc:
            raise ValueError(f"bad regex for {field}: {pattern!r} ({exc})") from exc
    return parsed


def select(data: dict, filters, subs: list[dict]) -> list[dict]:
    """Every token record matching ALL filters, freshest first."""
    records = data["access_tokens"] + data["refresh_tokens"] + data["id_tokens"]
    matched = [
        rec
        for rec in records
        if all(
            any(rx.search(value) for value in match_values(rec, field, subs))
            for field, rx in filters
        )
    ]


    def freshness(rec):
        for key in ("expires_on", "last_modification_time", "cached_at"):
            value = rec.get(key)
            if value in (None, ""):
                continue
            try:
                return float(value)
            except (TypeError, ValueError):
                continue
        return 0.0

    return sorted(matched, key=freshness, reverse=True)


RC_TOKEN_KEY = {
    "AccessToken": "AZURE_ACCESS_TOKEN",
    "RefreshToken": "AZURE_REFRESH_TOKEN",
    "IdToken": "AZURE_ID_TOKEN",
}


def emit(records: list[dict], fmt: str, nomask: bool, out=sys.stdout) -> None:
    """Print matched records in the requested format."""

    def token(rec):
        return rec["secret"] if nomask else rec["secret_masked"]

    if fmt == "value":
        for rec in records:
            out.write(token(rec) + "\n")
        return

    if fmt in ("rc", "env"):
        prefix = "export " if fmt == "env" else ""
        for i, rec in enumerate(records):
            if i:
                out.write("\n")
            tenants = record_tenants(rec)
            pairs = [
                (RC_TOKEN_KEY.get(rec["credential_type"], "AZURE_TOKEN"), token(rec)),
                ("AZURE_CLIENT_ID", rec["client_id"]),
                ("AZURE_TENANT_ID", tenants[0] if tenants else ""),
            ]
            for key, value in pairs:
                if value:
                    out.write(f"{prefix}{key}={value}\n")
        return

    if fmt == "json":
        out.write(
            json.dumps([scrub_record(rec, nomask) for rec in records], indent=2, sort_keys=False)
            + "\n"
        )
        return

    render_table(
        ["#", "TYPE", "IDENTITY", "CLIENT", "TENANT", "RESOURCE / SCOPES", "EXPIRES", "TOKEN"],
        [
            [
                str(i),
                TYPE_NAMES.get(rec["credential_type"], rec["credential_type"]),
                rec["identity"] or "-",
                short_client(rec["client_id"]),
                (record_tenants(rec) or ["-"])[0],
                rec["scopes"],
                when(rec["expires_on"] or rec["last_modification_time"]),
                token(rec),
            ]
            for i, rec in enumerate(records, 1)
        ],
        out,
    )


def print_claims(records: list[dict], out=sys.stdout) -> None:
    for i, rec in enumerate(records, 1):
        claims = rec.get("claims")
        if not claims:
            continue
        out.write(
            f"\n  [{i}] {rec['credential_type']} - {rec['identity']}"
            f" / {short_client(rec['client_id'])}\n"
        )
        ordered = [c for c in CLAIM_ORDER if c in claims]
        ordered += sorted(c for c in claims if c not in CLAIM_ORDER)
        for name in ordered:
            value = claims[name]
            if name in ("iat", "nbf", "exp", "auth_time"):
                value = when(value)
            elif isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            elif name in SECRET_FIELDS:
                value = obfuscate(str(value))
            out.write(f"      {name:<16} {value}\n")


def report(data: dict, path: Path, show_claims: bool, nomask: bool = False, out=sys.stdout) -> None:
    counts = (
        f"{len(data['accounts'])} accounts, "
        f"{len(data['access_tokens'])} access, "
        f"{len(data['refresh_tokens'])} refresh, "
        f"{len(data['id_tokens'])} id, "
        f"{len(data['app_metadata'])} app-metadata"
    )
    out.write(f"MSAL token cache: {path}\n")
    out.write(f"Now: {local_time(time.time())}   Entries: {counts}\n")

    section("ACCOUNTS", out)
    render_table(
        ["ACCT", "USERNAME", "TENANT (realm)", "ENVIRONMENT", "AUTHORITY", "SOURCE"],
        [
            [
                short_account(a["home_account_id"]),
                a["username"] or "-",
                a["realm"] or "-",
                a["environment"] or "-",
                a["authority_type"] or "-",
                a["account_source"] or "-",
            ]
            for a in data["accounts"]
        ],
        out,
    )

    section("ACCESS TOKENS", out)
    render_table(
        ["#", "IDENTITY", "CLIENT", "TENANT", "TYPE", "RESOURCE / SCOPES", "EXPIRES", "TOKEN"],
        [
            [
                str(i),
                t["identity"] or "-",
                short_client(t["client_id"]),
                (record_tenants(t) or [t["realm"]] or ["-"])[0] or "-",
                t["token_type"] or "-",
                t["scopes"],
                when(t["expires_on"]),
                t["secret"] if nomask else t["secret_masked"],
            ]
            for i, t in enumerate(data["access_tokens"], 1)
        ],
        out,
    )

    section("REFRESH TOKENS", out)
    render_table(
        ["#", "IDENTITY", "CLIENT", "FAMILY", "RESOURCE / SCOPES", "LAST MODIFIED", "TOKEN"],
        [
            [
                str(i),
                t["identity"] or "-",
                short_client(t["client_id"]),
                t["family_id"] or "-",
                t["scopes"],
                when(t["last_modification_time"]),
                t["secret"] if nomask else t["secret_masked"],
            ]
            for i, t in enumerate(data["refresh_tokens"], 1)
        ],
        out,
    )

    section("ID TOKENS", out)
    render_table(
        ["#", "IDENTITY", "CLIENT", "TENANT", "ISSUED", "EXPIRES", "TOKEN"],
        [
            [
                str(i),
                t["identity"] or "-",
                short_client(t["client_id"]),
                (record_tenants(t) or [t["realm"]] or ["-"])[0] or "-",
                when((t["claims"] or {}).get("iat")),
                when((t["claims"] or {}).get("exp")),
                t["secret"] if nomask else t["secret_masked"],
            ]
            for i, t in enumerate(data["id_tokens"], 1)
        ],
        out,
    )

    section("APP METADATA", out)
    render_table(
        ["CLIENT", "ENVIRONMENT", "FAMILY"],
        [
            [m["client"], m["environment"] or "-", m["family_id"] or "-"]
            for m in data["app_metadata"]
        ],
        out,
    )

    if show_claims:
        section("ACCESS TOKEN CLAIMS", out)
        print_claims(data["access_tokens"], out)
        section("ID TOKEN CLAIMS", out)
        print_claims(data["id_tokens"], out)


def scrub_record(rec: dict, nomask: bool = False) -> dict:
    """One credential record, timestamps expanded and secrets handled."""
    scrubbed = json.loads(json.dumps(rec))
    if nomask:
        scrubbed["secret"] = rec.get("secret", "")
    else:
        scrubbed.pop("secret", None)
    for field in ("cached_at", "expires_on", "extended_expires_on", "last_modification_time"):
        if scrubbed.get(field):
            scrubbed[f"{field}_local"] = local_time(scrubbed[field])
            scrubbed[f"{field}_relative"] = relative(scrubbed[field])
    claims = scrubbed.get("claims")
    if claims:
        for name in ("iat", "nbf", "exp", "auth_time"):
            if name in claims:
                claims[f"{name}_local"] = local_time(claims[name])
        if not nomask:
            for name in SECRET_FIELDS:
                if name in claims:
                    claims[name] = obfuscate(str(claims[name]))
    return scrubbed


def scrub_for_json(data: dict, nomask: bool = False) -> dict:
    """Whole-cache JSON: raw secrets dropped, timestamps in both forms."""
    groups = ("access_tokens", "refresh_tokens", "id_tokens")
    return {
        key: (
            [scrub_record(rec, nomask) for rec in value]
            if key in groups
            else json.loads(json.dumps(value))
        )
        for key, value in data.items()
    }


FILTER_EPILOG = """\
filter keys (all aliases fold onto six fields):
  type          access | refresh | id
  identity      UPN / username / oid          (aliases: upn, user, username)
  tenant        tenant id                     (aliases: tenant_id, tid, realm)
  subscription  subscription id or name       (aliases: subscription_id, sub)
  client        client id or app name         (aliases: client_id, app)
  resource      target scopes / audience      (aliases: scope, audience, aud)

Each value is an unanchored case-insensitive regex, so one syntax covers exact,
partial and pattern matching -- 8ddb, 8ddb.*, or the full client id all match.
Anchor with ^...$ for a strict exact match. Repeat --filter to AND conditions;
use regex alternation (access|refresh) to OR within one field.

Subscription ids are not in the MSAL cache: they are resolved through
azureProfile.json beside it, subscription -> tenant, then matched on tenant.
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=FILTER_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-f",
        "--file",
        type=Path,
        default=DEFAULT_PATH,
        help=f"cache path (default: {DEFAULT_PATH})",
    )
    parser.add_argument(
        "-c",
        "--claims",
        action="store_true",
        help="also decode and print JWT claims for access/id tokens",
    )
    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="emit JSON instead of tables (same as --format json)",
    )
    parser.add_argument(
        "--filter",
        metavar="KEY=REGEX",
        action="append",
        default=[],
        help="keep only matching tokens and print them; repeatable "
        "(ANDed). Keys: " + ", ".join(FILTER_FIELDS),
    )
    parser.add_argument(
        "--format",
        choices=("value", "rc", "env", "json", "table"),
        help="output for filtered tokens (default: value -- the bare "
        "token, one per line, no quotes or field names)",
    )
    parser.add_argument(
        "--nomask",
        action="store_true",
        help="print token values in full instead of first6****last6",
    )
    args = parser.parse_args(argv)

    try:
        raw = args.file.read_text()
    except OSError as exc:
        print(f"error: cannot read {args.file}: {exc}", file=sys.stderr)
        return 1
    try:
        cache = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: {args.file} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    data = build(cache)

    if args.filter or args.format:
        try:
            filters = parse_filters(args.filter)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        subs = load_subscriptions(args.file) if any(f == "subscription" for f, _ in filters) else []
        if not subs and any(f == "subscription" for f, _ in filters):
            print(
                f"error: no {PROFILE_NAME} beside {args.file} or in "
                f"{DEFAULT_PATH.parent} -- cannot resolve a subscription to a tenant",
                file=sys.stderr,
            )
            return 1
        matched = select(data, filters, subs)
        if not matched:
            print("error: no token matched the filters", file=sys.stderr)
            return 1
        fmt = args.format or ("json" if args.json else "value")
        if fmt in ("value", "rc", "env") and not args.nomask:
            print(
                "note: token values are masked; pass --nomask to print them in full",
                file=sys.stderr,
            )
        if fmt == "table" and args.nomask:
            print(
                "note: the table truncates to terminal width -- use --format "
                "value/rc/env/json to copy a token",
                file=sys.stderr,
            )
        if fmt == "value" and len(matched) > 1:
            print(
                f"note: {len(matched)} tokens matched (freshest first); "
                "add filters to narrow to one",
                file=sys.stderr,
            )
        emit(matched, fmt, args.nomask)
        return 0

    if args.json:
        print(json.dumps(scrub_for_json(data, args.nomask), indent=2, sort_keys=False))
    else:
        report(data, args.file, args.claims, args.nomask)
    return 0


if __name__ == "__main__":
    sys.exit(main())
