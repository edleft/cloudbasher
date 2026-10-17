"""TOTP resolution for credential files -- the ONE place a 2FA code is produced."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import struct
import time
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

from cloudbasher.core import mfa_keys
from cloudbasher.core.exceptions import CredentialError
from cloudbasher.core.mfa_keys import MfaKeyFamily


_CODE_RE = re.compile(r"^\d{6,8}$")

_DEFAULT_PERIOD = 30
_DEFAULT_DIGITS = 6


_DYNAMIC_TRUNCATION_MASK = 0x7FFFFFFF


def _b32_key(seed: str) -> bytes:
    """Decode a base32 TOTP seed, tolerating how issuers actually print them."""


    compact = re.sub(r"[\s\-=]", "", seed).upper()
    if not compact:
        raise CredentialError("MFA seed is empty.")
    padded = compact + "=" * (-len(compact) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise CredentialError(
            "MFA seed is not valid base32. Expected the shared secret from the "
            "authenticator setup screen (letters A-Z and digits 2-7), or an "
            "otpauth:// URI. Nothing about the seed itself is echoed here."
        ) from exc


def totp(
    seed: str,
    *,
    at: Optional[float] = None,
    digits: int = _DEFAULT_DIGITS,
    period: int = _DEFAULT_PERIOD,
) -> str:
    """RFC 6238 TOTP. ``at`` is a Unix timestamp; default now."""
    counter = int((time.time() if at is None else at) // period)
    digest = hmac.new(_b32_key(seed), struct.pack(">Q", counter), hashlib.sha1).digest()


    offset = digest[-1] & 0x0F
    (truncated,) = struct.unpack(">I", digest[offset : offset + 4])
    return str((truncated & _DYNAMIC_TRUNCATION_MASK) % (10**digits)).zfill(digits)


def seed_from_otpauth(value: str) -> Optional[str]:
    """The ``secret=`` of an ``otpauth://`` URI, or None if this is not one."""
    if not value.strip().lower().startswith("otpauth://"):
        return None
    secret = parse_qs(urlparse(value.strip()).query).get("secret", [""])[0]
    if not secret:
        raise CredentialError(
            "MFA reference resolved to an otpauth:// URI with no secret= parameter."
        )
    return secret


def code_from_resolved(value: str, *, at: Optional[float] = None) -> str:
    """Turn whatever a reference resolved to into a code."""


    seed = _looks_like_seed(value)
    return value.strip() if seed is None else totp(seed, at=at)


def _is_op_ref(value: str) -> bool:
    """Whether ``value`` is a 1Password reference rather than a literal."""
    v = value.strip()
    return v.startswith("op://") or (v.startswith("{{") and "op://" in v)


def _looks_like_seed(value: str) -> Optional[str]:
    """The base32 seed behind ``value``, or None if it is a finished code."""
    value = value.strip()
    if _CODE_RE.match(value):
        return None
    return seed_from_otpauth(value) or value


class MfaSource:
    """A code generator for one credential, resolved lazily and reused safely."""

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        seed: Optional[str] = None,
        runner=None,
        where: str = "credential file",
        sleep=time.sleep,
    ) -> None:
        self._declared_code = (code or "").strip() or None
        self._seed = (seed or "").strip() or None
        self._runner = runner
        self._where = where
        self._sleep = sleep

        self._last: Optional[tuple[str, int]] = None

    @property
    def declared(self) -> bool:
        """Whether this credential declares any MFA material at all."""
        return bool(self._declared_code or self._seed)

    @property
    def caches_seed(self) -> bool:
        """True once a seed is held, meaning no further `op` call will happen."""
        return self._seed is not None

    def _fetch(self) -> str:
        """One `op` invocation, bypassing `read_credential_file`'s cache."""
        from cloudbasher.core import secret_refs

        assert self._declared_code is not None


        return (
            secret_refs.resolve_refs(
                f"{secret_refs.DEFERRED_RESOLVE_KEY}={self._declared_code}",
                where=self._where,
                validate_deferred=False,
                runner=self._runner,
            )
            .partition("=")[2]
            .strip()
        )

    def seconds_until_fresh(self, *, at: Optional[float] = None) -> float:
        """How long until `code()` can hand out DIFFERENT digits"""
        if self._last is None:
            return 0.0
        now = time.time() if at is None else at
        if int(now // _DEFAULT_PERIOD) != self._last[1]:
            return 0.0
        return max(0.0, (self._last[1] + 1) * _DEFAULT_PERIOD - now)

    def code(self, *, at: Optional[float] = None) -> Optional[str]:
        """A code valid now, never a repeat of the previous one."""
        if not self.declared:
            return None

        now = time.time() if at is None else at
        value = self._produce(now)
        window = int(now // _DEFAULT_PERIOD)

        if self._last is not None and self._last == (value, window):


            now = (window + 1) * _DEFAULT_PERIOD
            self._sleep(max(0.0, now - (time.time() if at is None else at)))
            value = self._produce(now)
            window = int(now // _DEFAULT_PERIOD)

        self._last = (value, window)
        return value

    def _produce(self, now: float) -> str:
        if self._seed is not None:


            seed = _looks_like_seed(self._seed)
            if seed is not None:


                self._seed = seed
            if seed is None:


                code_keys = " / ".join(f"`{k}=`" for k in mfa_keys.CONSOLE.code_keys)
                seed_keys = " / ".join(f"`{k}=`" for k in mfa_keys.CONSOLE.seed_keys)
                raise CredentialError(
                    f"{self._where}: a finished six-digit code was declared as an MFA SEED, "
                    "and a code cannot be used to compute later codes.\n"
                    "  Declare a code -- or an `op://` reference that returns one, which is "
                    f"what `?attribute=otp` does -- in the CODE key ({code_keys}, or their "
                    f"`SSO_` forms). The SEED key ({seed_keys}) takes a base32 seed or "
                    "an `otpauth://` URI.\n"
                    "  The distinction is not cosmetic: a seed key is resolved when the file is "
                    "read, so a code placed there is already stale when a login form asks for it."
                )
            return totp(seed, at=now)
        assert self._declared_code is not None
        if not _is_op_ref(self._declared_code):


            return code_from_resolved(self._declared_code, at=now)
        raw = self._fetch()
        seed = _looks_like_seed(raw)
        if seed is not None:

            self._seed = seed
            return totp(seed, at=now)
        return raw


MAX_FACTOR_ATTEMPTS = 3


FACTOR_SETTLE_MS = 3000
FACTOR_SETTLE_TICK_MS = 150


class FactorPrompt:
    """One login's factor-prompt state: the cap, the no-replay, the settle and the wording"""

    def __init__(
        self,
        mfa: "MfaSource",
        family: "MfaKeyFamily",
        *,
        where: str,
        max_attempts: int = MAX_FACTOR_ATTEMPTS,
    ) -> None:
        self._mfa = mfa
        self._family = family
        self._where = where
        self._max_attempts = max_attempts


        self.attempts = 0

    @property
    def cap_spent(self) -> bool:
        return self.attempts >= self._max_attempts

    def next_code(self) -> "Optional[str]":
        """One fresh code, COUNTED against the cap, or None."""
        if self.cap_spent or not self._mfa.declared:
            return None
        code = self._mfa.code()
        if code is None:
            return None
        self.attempts += 1
        return code

    def answer(
        self,
        *,
        fill: "Any",
        submit: "Any",
        still_prompting: "Any",
        sleep_ms: "Any",
        settle_ms: int = FACTOR_SETTLE_MS,
        tick_ms: int = FACTOR_SETTLE_TICK_MS,
    ) -> bool:
        """Answer the prompt ONCE, and return whether a code was submitted."""


        wait_s = self._mfa.seconds_until_fresh()
        if wait_s > 0:
            waited_ms = 0
            target_ms = int(wait_s * 1000) + tick_ms
            while waited_ms < target_ms:
                sleep_ms(tick_ms)
                waited_ms += tick_ms
                try:
                    if not still_prompting():


                        return False
                except Exception:
                    return False
        code = self.next_code()
        if code is None:
            return False


        fill(code)
        submit()
        waited = 0
        while waited < settle_ms:
            sleep_ms(tick_ms)
            waited += tick_ms
            try:
                if not still_prompting():
                    return True
            except Exception:
                return True
        return True


    def _note(self, *, ref: str = "", seed: str = "") -> str:
        """What the credential ARRIVED carrying, in the file's own key names."""
        return declared_note(self._family, ref=ref, seed=seed)

    def _advice(self) -> str:
        """The "declare one of these" advice for this family."""
        return declare_advice(self._family)

    def nothing_declared(self, *, observed: str = "") -> str:
        """The refusal for a prompt nothing here can answer."""
        lines = [f"{self._where}: a second factor was demanded and nothing here can answer it."]
        if observed:
            lines.append(f"  observed: {observed}")
        lines.append(f"  The credential that reached this login {self._note()}.")
        advice = self._advice()
        if advice:
            lines.append(advice)
        return "\n".join(lines)

    def refused(self, *, observed: str = "") -> str:
        """The refusal for a prompt that was answered and came back anyway."""
        lines = [
            f"{self._where}: the declared second factor was refused "
            f"{self.attempts} time(s) and the prompt is still there."
        ]
        if observed:
            lines.append(f"  observed: {observed}")
        lines.append(
            "  The codes were typed in, and the prompt survived the post-submit "
            "settle, so they are being REFUSED rather than missed -- check that "
            "the seed belongs to this user and that this machine's clock is "
            "right. A TOTP code is valid for 30 seconds."
        )
        return "\n".join(lines)

    def attended_notice(self, *, budget_s: float) -> str:
        """What to print when a human can finish it in a visible browser."""
        return (
            f"{self._where}: a second factor is required -- complete it in the "
            f"browser window. Waiting up to {budget_s:.0f}s.\n"
            "  To answer it unattended instead, declare one of these in the "
            f"credential block.\n{self._advice()}"
        )


def mfa_source(
    *,
    ref: str = "",
    seed: str = "",
    where: str = "credential file",
    runner=None,
) -> MfaSource:
    """Build the `MfaSource` for one credential. **THE ONE CONSTRUCTION SITE.**"""
    return MfaSource(code=ref, seed=seed, where=where, runner=runner)


def declared_note(family: "MfaKeyFamily", *, ref: str = "", seed: str = "") -> str:
    """What this credential ARRIVED carrying, in the file's own key names"""
    held = []
    if seed.strip():
        held.append(f"{'/'.join(family.seed_keys)} (a TOTP seed)")
    if ref.strip():


        shape = "a 1Password reference" if _is_op_ref(ref) else "a literal code"
        held.append(f"{'/'.join(family.code_keys)} ({shape})")
    if held:
        return "carries " + " and ".join(held)
    return "carries none of " + ", ".join(family.keys)


def declare_advice(family: "MfaKeyFamily") -> str:
    """The "you need a second factor" advice for one credential family."""
    if not family.keys:
        return ""
    advice = "  Declare one: " + " / ".join(f"{k}=" for k in family.keys)
    if family.code_keys:
        advice += (
            f"\n  A 1Password reference keeps the seed in the vault: "
            f"{family.code_keys[0]}=op://Vault/Item/one-time password?attribute=otp"
        )
    return advice
