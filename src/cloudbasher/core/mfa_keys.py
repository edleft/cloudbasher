"""The MFA key vocabulary, declared ONCE"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MfaKeyFamily:
    """One login's MFA key vocabulary: the SEED slot and the CODE slot."""


    name: str

    seed_keys: tuple[str, ...]

    code_keys: tuple[str, ...]


    prefixes: tuple[str, ...] = ()

    @property
    def seed_spellings(self) -> "frozenset[str]":
        """Every upper-cased spelling of this family's SEED keys that a parser accepts. The parsers used to branch on the literal declarations, so a key added to ``seed_keys`` was deferred and advertised but never parsed."""
        return frozenset(
            sp for key in self.seed_keys for sp in spellings(key, prefixes=self.prefixes)
        )

    @property
    def code_spellings(self) -> "frozenset[str]":
        """Every upper-cased spelling of this family's CODE keys a parser accepts."""
        return frozenset(
            sp for key in self.code_keys for sp in spellings(key, prefixes=self.prefixes)
        )

    @property
    def normalised_seed_keys(self) -> tuple[str, ...]:
        """The seed keys as a lowercased, underscore-free JSON view sees them."""
        return tuple(key.lower().replace("_", "") for key in self.seed_keys)

    @property
    def normalised_code_keys(self) -> tuple[str, ...]:
        """The code keys as a lowercased, underscore-free JSON view sees them."""
        return tuple(key.lower().replace("_", "") for key in self.code_keys)

    @property
    def keys(self) -> tuple[str, ...]:
        """Every key in the family, seed slot first."""
        return self.seed_keys + self.code_keys


CONSOLE = MfaKeyFamily(
    name="console",
    seed_keys=("MFA_SECRET",),
    code_keys=("MFA_CODE", "TOTP"),


    prefixes=("AZURE_",),
)


SSO = MfaKeyFamily(
    name="sso",
    seed_keys=("SSO_MFA_SECRET",),
    code_keys=("SSO_MFA_CODE", "SSO_TOTP"),


)


FAMILIES: tuple[MfaKeyFamily, ...] = (CONSOLE, SSO)


def spellings(key: str, *, prefixes: "tuple[str, ...]" = ()) -> "frozenset[str]":
    """Every spelling of ``key`` a credential-file parser accepts, upper-cased."""
    bare = key.upper()
    forms = {bare, bare.replace("_", "")}
    return frozenset(forms | {f"{prefix}{form}" for prefix in prefixes for form in forms})


def deferred_value_keys() -> frozenset[str]:
    """Every key whose value must survive a credential-file read UNRESOLVED."""


    return frozenset(spelling for family in FAMILIES for spelling in family.code_spellings)


def family_for_key(key: str) -> "MfaKeyFamily | None":
    """The family a file key belongs to, or None."""
    upper = key.upper()
    for family in FAMILIES:
        if upper in family.seed_spellings or upper in family.code_spellings:
            return family
    return None
