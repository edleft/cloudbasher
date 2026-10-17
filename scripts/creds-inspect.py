#!/usr/bin/env python3
"""Structure-only inspector for a CloudBasher ``-F`` credential file."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


_NEVER_MASK = re.compile(r"(?i)(secret|password|private_key|token|passphrase|client_secret)")

_KV_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*(.*)$")


def _describe(key: str, value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    n = len(value)


    if value.startswith("op://") or ("{{" in value and "op://" in value):
        return value
    if _NEVER_MASK.search(key):
        return f"<{n} chars, withheld>"
    if n <= 8:
        return f"<{n} chars>"
    return f"{value[:4]}...{value[-4:]} <{n} chars>"


_TYPE_LABELS: dict[tuple[str, str], str] = {
    ("aws", "AwsConsoleCreds"): "AWS  console username/password",
    ("aws", "AwsSSOCreds:browser"): "AWS  SSO via browser (type 4)",
    ("aws", "AwsSSOCreds:device"): "AWS  SSO via device code (type 5)",
    ("aws", "AwsSessionCreds:federated"): "AWS  AKIA key -> ACT_AS=federated",
    ("aws", "AwsSessionCreds:role"): "AWS  key -> ACT_AS=role:<arn>",
    ("aws", "AwsSessionCreds:direct-unbound"): "AWS  AKIA key -> ACT_AS=direct-unbound",
    ("aws", "AwsSessionCreds:direct"): "AWS  ASIA key -> ACT_AS=direct",
    ("gcp", "GCPServiceAccountFile"): "GCP  service account key",
    ("gcp", "GCPAuthorizedUserFile"): "GCP  OAuth refresh token (authorized_user)",
    ("gcp", "GCPAccessTokenFile"): "GCP  OAuth access token (bare)",
    ("gcp", "GCPCookiesFile"): "GCP  console session cookies",
    ("gcp", "GCPConsoleCredsFile"): "GCP  console username/password",
    ("azure", "AzureServicePrincipalCreds:secret"): "AZ   service principal (secret)",
    ("azure", "AzureServicePrincipalCreds:certificate"): "AZ   service principal (certificate)",
    ("azure", "AzureRefreshTokenCreds"): "AZ   OAuth refresh token",
    ("azure", "AzureAccessTokenCreds"): "AZ   OAuth access token",
    ("azure", "AzureConsoleCreds"): "AZ   console username/password",
}


def _type_keys(provider: str, parsed: object) -> list[str]:
    """The coverage keys for one parsed block -- a LIST, because one block can be several credential types."""
    name = type(parsed).__name__
    if name == "AwsSSOCreds":
        return [f"{name}:{getattr(parsed, 'sso_flow', 'browser')}"]
    if name == "AzureServicePrincipalCreds":
        uses_cert = getattr(parsed, "uses_certificate", None)
        return [f"{name}:{'certificate' if uses_cert and uses_cert() else 'secret'}"]
    if name == "AwsSessionCreds":
        act_as = getattr(parsed, "act_as", None)
        return [f"{name}:{act_as.mode}"] if act_as is not None else [f"{name}:<no ACT_AS>"]
    return [name]


def _diagnose_block(block: str) -> list[str]:
    """Say WHERE a failing block went wrong, without printing one byte of it."""
    import json  # noqa: PLC0415

    from cloudbasher.core.credential_file import (  # noqa: PLC0415
        _ANNOTATION_RE,
        _OVERRIDE_RE,
    )


    body: list[tuple[int, str]] = []
    for n, line in enumerate(block.splitlines(), 1):
        if _OVERRIDE_RE.match(line) or _ANNOTATION_RE.match(line):
            continue
        body.append((n, line))

    meaningful = [(n, ln) for n, ln in body if ln.strip() and not ln.strip().startswith("#")]
    if not meaningful:
        return ["      the block has no credential lines at all once `csp=`/comments are removed"]

    hints: list[str] = []
    first_char = meaningful[0][1].strip()[0]


    if first_char in "{[":
        text = "\n".join(ln for _, ln in body)
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            body_lines = [n for n, _ in body]
            where = (
                f"file line {body_lines[exc.lineno - 1]}"
                if 0 < exc.lineno <= len(body_lines)
                else f"body line {exc.lineno}"
            )
            hints.append(f"      looks like JSON and is NOT valid JSON: {exc.msg}")
            hints.append(f"      at {where}, column {exc.colno}")
            hints.append("      (a trailing comma and a single-quoted string are the usual two)")
            return hints
        hints.append("      valid JSON, so the shape is what was not recognised")


    else:
        for n, line in meaningful:
            if "=" not in line and ":" not in line:
                hints.append(
                    f"      file line {n} has no `=` ({len(line.strip())} chars), and ONE such "
                    f"line makes the parser reject the WHOLE block"
                )
                hints.append("      (a value pasted on a line of its own is the usual cause)")
                return hints


    names: list[str] = []
    exported: list[int] = []
    for n, line in meaningful:
        m = _KV_RE.match(line)
        if not m:
            continue
        names.append(m.group(1).lower())
        if line.strip().lower().startswith("export "):
            exported.append(n)
    if names:
        hints.append(f"      keys present: {', '.join(sorted(set(names))) or '(none)'}")
    if exported:
        hints.append(
            f"      `export ` prefix on file line(s) {', '.join(map(str, exported))} -- the GCP "
            f"and Azure parsers do NOT strip it, so the key name becomes `export <name>` "
            f"and matches no alias"
        )
    hints.append("      compare against the shapes listed in the error above")
    return hints


def _per_block_report(blocks: list[str]) -> list[str]:
    """Parse each block on its own, so one bad block does not hide the rest."""
    from cloudbasher.core.credential_file import parse_multi_creds_text  # noqa: PLC0415
    from cloudbasher.core.exceptions import CredentialError  # noqa: PLC0415

    found: list[str] = []
    for i, block in enumerate(blocks, 1):
        if not block.strip():
            continue
        try:
            results = parse_multi_creds_text(block)
        except CredentialError as exc:
            first = str(exc).splitlines()[0]
            print(f"  block {i}: FAILED -- {first}")
            for hint in _diagnose_block(block):
                print(hint)
            continue
        if not results:
            print(f"  block {i}: skipped (no CSP recognised it)")
            print("      no `csp=aws|gcp|azure` line -- every block needs one")
            continue
        for pb in results:
            keys = _type_keys(pb.provider, pb.parsed)
            found.extend(keys)
            print(f"  block {i}: ok -- {pb.provider} {' + '.join(keys)}")
    return found


def _declared_providers(blocks: list[str]) -> set[str]:
    """The CSPs the FILE declares, from its own `csp=` lines."""
    from cloudbasher.core.credential_file import _OVERRIDE_RE  # noqa: PLC0415

    declared = set()
    for block in blocks:
        for line in block.splitlines():
            m = _OVERRIDE_RE.match(line)
            if m:
                declared.add(m.group(1).lower())
    return declared


def _coverage_report(found: list[str], providers: Optional[set[str]] = None) -> None:
    """Which of the end-to-end credential types this file does and does not carry."""
    present = set(found)
    rows = [
        ((prov, key), label)
        for (prov, key), label in _TYPE_LABELS.items()
        if not providers or prov.lower() in providers
    ]
    print()
    scope = "/".join(sorted(p.upper() for p in providers)) if providers else "all CSPs"
    print(f"--- credential-type coverage ({scope}) ---")
    for (_provider, key), label in rows:
        mark = "x" if key in present else " "
        print(f"  [{mark}] {label}")
    missing = sum(1 for (_p, k), _l in rows if k not in present)
    if missing:
        print(
            f"  ({len(rows) - missing}/{len(rows)} present; "
            "blanks are types this file cannot test)"
        )
    else:
        print("  all types present")


def _shape_of(stripped: str) -> str:
    """Name a non-`key=value` line by what it IS, never by what it contains."""
    if stripped in ("{", "}", "[", "]"):
        return f"{stripped}   (JSON punctuation)"
    if stripped.startswith('"') and ":" in stripped:
        name = stripped.split('"')[1] if stripped.count('"') >= 2 else "?"
        return f'  "{name}": <{len(stripped)} chars>   (JSON field)'
    if stripped.startswith(("ssh-", "ecdsa-")):
        return f"an SSH PUBLIC key line, {len(stripped)} chars"
    if stripped.startswith("-----BEGIN"):
        return "the start of a PEM block"
    return (
        f"{len(stripped)} chars, no `=` and not JSON — if the block is not JSON, "
        f"this line makes the whole block unparseable"
    )


def _result_line(parsed_types: list[str], *, ok: bool) -> None:
    """The verdict, LAST, on one line."""
    print()
    if ok and parsed_types:
        print(f"RESULT: OK -- {', '.join(sorted(set(parsed_types)))}")
    elif ok:
        print("RESULT: no credentials parsed (every block was skipped)")
    else:
        got = f"; parsed anyway: {', '.join(sorted(set(parsed_types)))}" if parsed_types else ""
        print(f"RESULT: FAILED -- see the per-block lines above{got}")


def _describe_value(key: str, value: object) -> str:
    """`_describe`, but for a field of any type."""
    if isinstance(value, str):
        return _describe(key, value)
    if isinstance(value, dict):
        inner = ", ".join(f"{k}: {_describe_value(str(k), v)}" for k, v in value.items())
        return "{" + inner + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_describe_value(key, v) for v in value) + "]"
    return repr(value)


def main(argv: list[str]) -> int:
    target = Path(argv[1]) if len(argv) > 1 else Path("creds.rc")
    if not target.is_file():
        print(f"no such file: {target}", file=sys.stderr)
        return 1

    text = target.read_text(encoding="utf-8")
    lines = text.splitlines()
    print(f"file: {target}  ({len(lines)} lines, {len(text)} bytes)")

    from cloudbasher.core.credential_file import (
        _split_blocks,  # noqa: PLC0415
        merged_blocks_error,
        parse_multi_creds_text,
    )
    from cloudbasher.core.exceptions import CredentialError


    blocks = _split_blocks(text, strict=False)
    n = len(blocks)
    print(f"{n} credential block{'' if n == 1 else 's'} (blocks are separated by a blank line)")
    if len(blocks) == 1 and len(lines) > 12:
        print(
            "  NOTE: the whole file came back as ONE block. Blocks are "
            "separated by a BLANK line -- a '#' comment line does not "
            "separate them."
        )


    from cloudbasher.core.secret_refs import describe_refs  # noqa: PLC0415

    summary = describe_refs(text)
    print(f"{summary}\n" if summary else "")

    for i, block in enumerate(blocks, 1):
        block_lines = block.splitlines()
        merged = merged_blocks_error(block)
        flag = "  *** MERGED BLOCKS ***" if merged else ""
        print(f"--- block {i}: what is in it ---{flag}")
        if merged:
            print(f"  !! {merged}")
        for line in block_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                print(f"  # <comment, {len(stripped)} chars>")
                continue
            m = _KV_RE.match(line)
            if m:
                key, value = m.group(1), m.group(2)
                print(f"  {key} = {_describe(key, value)}")
            else:


                print(f"  {_shape_of(stripped)}")
        print()

    print("--- what it parsed as ---")
    parsed_types: list[str] = []
    try:
        results = parse_multi_creds_text(text)
    except CredentialError as exc:


        print(f"whole-file parse failed: {exc}")
        print()
        print("  falling back to per-block parsing, so the blocks that ARE")
        print("  fine can still be confirmed:")
        parsed_types = _per_block_report(blocks)
        _coverage_report(parsed_types, _declared_providers(blocks))
        _result_line(parsed_types, ok=False)
        return 2
    if not results:
        print("no credentials parsed (every block was skipped)")
        return 0
    for i, pb in enumerate(results, 1):
        print(
            f"  credential {i}: block {pb.block} provider={pb.provider} "
            f"type={type(pb.parsed).__name__}"
        )
        parsed_types.extend(_type_keys(pb.provider, pb.parsed))
        for field, value in vars(pb.parsed).items():
            if value in (None, "", [], {}):
                continue
            print(f"      {field} = {_describe_value(field, value)}")
    _coverage_report(parsed_types, _declared_providers(blocks))
    _result_line(parsed_types, ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
