"""Shared guards for credentials whose invalidity is already known locally."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cloudbasher.core.identity_listing import credential_is_invalid

if TYPE_CHECKING:
    from cloudbasher.core.types import CredentialRecord


def known_invalid_credential_error(
    record: "CredentialRecord | None", action: str, *, label: str = "credential"
) -> str | None:
    """Return a safe refusal message when an action would reuse known-invalid auth."""
    if record is None or not credential_is_invalid(record):
        return None
    return (
        f"{action}: {label} is known invalid; no action was taken. "
        "Replace or re-authenticate it first."
    )
