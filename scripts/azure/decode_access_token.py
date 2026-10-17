#!/usr/bin/env python3
"""Decode and display the claims from an Azure OAuth access-token JWT."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "src"))

from cloudbasher.csp.azure.credentials import _decode_jwt_payload  # noqa: E402


def decode_access_token(token: str) -> dict[str, Any]:
    """Return unverified JWT payload claims or raise for a non-JWT/empty token."""
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
        raise ValueError("expected a three-part signed JWT access token")

    claims = _decode_jwt_payload(token)
    if not isinstance(claims, dict) or not claims:
        raise ValueError("JWT payload is malformed or contains no claims")
    return claims


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decode and display an Azure OAuth access token's JWT claims.",
        epilog=(
            "A decoded JWT is not verified: do not trust these claims for auth decisions. "
            "Claims may contain personal or tenant identifiers. Prefer TOKEN in the "
            "environment; a command-line token may be visible in shell history or process listings."
        ),
    )
    parser.add_argument(
        "token",
        nargs="?",
        help="access-token JWT (if omitted, read TOKEN from the environment)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    token = args.token if args.token is not None else os.environ.get("TOKEN")
    if not token:
        parser.error(
            "provide TOKEN as the positional argument or set the TOKEN environment variable"
        )

    try:
        claims = decode_access_token(token)
    except ValueError as exc:
        parser.error(str(exc))

    print(json.dumps(claims, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
