"""The ACT_AS declaration: what identity an AWS credential acts as."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from cloudbasher.core.exceptions import CredentialError
from cloudbasher.core.provision_grammar import ProvisionGrammar

_USAGE = (
    "ACT_AS must be one of:\n"
    "  ACT_AS=role:<arn>        assume that role  -> assumed-role/<role>/<name>\n"
    "  ACT_AS=federated         federate          -> federated-user/<name>\n"
    "  ACT_AS=direct            use as-is (session tokens only)\n"
    "  ACT_AS=direct-unbound    use a PERMANENT key as-is; the container gets\n"
    "                           no credentials, so in-shell `aws` will not work"
)


DIRECT_MODES = ("direct", "direct-unbound")


DERIVING_MODES = ("role", "federated")


UNBOUND_MODES = ("direct-unbound",)


def skips_projection(act_as: Optional["ActAs"]) -> bool:
    """Whether this declaration means "do not project into the container"."""
    return act_as is not None and act_as.mode in UNBOUND_MODES


def can_derive(extra: Optional[dict]) -> bool:
    """Whether this credential can DERIVE a new principal -- the ONE predicate. `#562`."""
    return act_as_mode_of(extra) in DERIVING_MODES and not (extra or {}).get("session_token")


def derives_nothing_because(extra: Optional[dict], *, kind: str = "") -> str:
    """The CLAUSE that says why `can_derive` said no. One home, four readers."""
    mode = act_as_mode_of(extra)
    if kind == "console":
        return "signs in through the browser"
    if not mode:
        return "declares no ACT_AS, so there is no principal to derive"
    if (extra or {}).get("session_token") and mode in DERIVING_MODES:
        return (
            f"declares ACT_AS={mode} but holds a temporary token -- chaining "
            "from a session token is not implemented here"
        )
    return f"declares ACT_AS={mode}, so it IS the identity"


class DerivationState(Enum):
    """What a credential must do about a derived principal. THREE-VALUED, `#838`."""

    OWES_A_NAME = "owes-a-name"
    DECLARED_DIRECT = "declared-direct"
    NOT_A_PERMANENT_KEY = "not-a-permanent-key"


def derivation_state(extra: Optional[dict], *, kind: str) -> DerivationState:
    """Classify `extra`+`kind` into the three arms above. `#838`."""
    if kind != "permanent":
        return DerivationState.NOT_A_PERMANENT_KEY
    if act_as_mode_of(extra) in DIRECT_MODES:
        return DerivationState.DECLARED_DIRECT
    return DerivationState.OWES_A_NAME


PROVISION_KEYWORDS = ("region", "as", "duration", "index")

_REGION = "region <selector>"


def provision_grammar(mode: str, *, kind: str = "") -> ProvisionGrammar:
    """The `.provision` grammar for a credential declaring ``mode``."""
    if mode == "role":


        return ProvisionGrammar(
            keywords=("region", "as", "index"),
            grammar=(
                f"Provision armed — [<ID>|selected] {_REGION} "
                "[as <name>] [index <index|start-end>]"
            ),
            note="This credential assumes a ROLE, so no `role` keyword is needed.",
            prefill_suffix="region ",
        )
    if mode == "federated":
        return ProvisionGrammar(
            keywords=("region", "as", "duration", "index"),
            grammar=(
                f"Provision armed — [<ID>|selected] {_REGION} "
                "[as <name>] [index <index|start-end>] [duration <seconds>]"
            ),
            note="This credential FEDERATES, so no `federation` keyword is needed.",
            prefill_suffix="region ",
        )
    if mode in DIRECT_MODES:
        return ProvisionGrammar(
            keywords=("region",),
            grammar=f"Provision armed — [<ID>|selected] {_REGION}",
            note=(
                f"This credential IS the identity (ACT_AS={mode}), so there is "
                "nothing to derive: no `role`, `federation`, `as` or `duration`."
            ),
            prefill_suffix="region ",
        )
    if kind == "console":


        return ProvisionGrammar(
            keywords=("region",),
            grammar=f"Provision armed — [<ID>|selected] {_REGION}",
            note="Name the region; there is nothing else to supply.",
            prefill_suffix="region ",
        )


    return ProvisionGrammar(
        keywords=PROVISION_KEYWORDS,
        grammar=(
            f"Provision armed — [<ID>|selected] {_REGION} "
            "[as <name>] [index <index|start-end>] [duration <seconds>]"
        ),
        note="Combine the keywords in any order.",
    )


@dataclass(frozen=True)
class ActAs:
    """The declared base identity. ``role_arn`` is set only for mode "role"."""

    mode: str
    role_arn: Optional[str] = None


def parse_act_as(raw: str) -> ActAs:
    """Parse an ACT_AS value. Raises CredentialError with usage on anything unrecognised -- there is no fallback mode, by design."""
    text = (raw or "").strip()
    head, sep, rest = text.partition(":")
    mode = head.strip().lower()
    value = rest.strip()

    if mode == "role":
        if not value:
            raise CredentialError(f"ACT_AS=role needs a role ARN: ACT_AS=role:<role-arn>\n{_USAGE}")
        if not value.startswith("arn:"):
            raise CredentialError(
                f"ACT_AS=role:{value!r} does not look like a role ARN.\n"
                "Expected ACT_AS=role:arn:aws:iam::<account>:role/<name>.\n"
                "If you meant to federate under that name, the name is not part "
                "of ACT_AS: use ACT_AS=federated, then name the identity per "
                "action (e.g. `.provision <ID> as <name>`) or declare "
                "FEDERATION_NAME=<name> in this block."
            )
        return ActAs(mode="role", role_arn=value)

    if mode in ("federated",) + DIRECT_MODES:
        if sep or value:
            raise CredentialError(
                f"ACT_AS={mode} takes no value (got {value!r}).\n"
                "ACT_AS declares the base identity only. To name the derived "
                "principal, either name it per action (`as <name>` on the "
                "provisioning command, e.g. `.provision <ID> as <name>`) or "
                "declare a default in this same block: "
                "FEDERATION_NAME=<name> for an action that federates, "
                "ROLE_SESSION_NAME=<name> for one that assumes a role -- "
                "whichever the action derives, not this ACT_AS. Both routes "
                "are honoured; suffixing ACT_AS is not."
            )
        return ActAs(mode=mode)

    raise CredentialError(f"unknown ACT_AS mode {head.strip()!r}.\n{_USAGE}")


def parse_act_as_declaration(values: Any) -> ActAs:
    """Parse the ONE ``ACT_AS`` a credential block is allowed to declare. `#477`."""
    raw_items: list[str] = []
    for value in values if isinstance(values, (list, tuple)) else [values]:
        for part in str(value or "").split(","):
            if part.strip():
                raw_items.append(part.strip())

    if not raw_items:
        raise CredentialError(f"ACT_AS is empty.\n{_USAGE}")

    if len(raw_items) > 1:
        raise CredentialError(
            f"a credential block declares exactly ONE ACT_AS, and this one "
            f"declares {len(raw_items)}: {', '.join(raw_items)}.\n"
            "Split it into one block per derivation, repeating the key material "
            "in each. Each block is then one credential with one number, and "
            "the number the listing shows is the number the file shows.\n"
            f"{_USAGE}"
        )

    return parse_act_as(raw_items[0])


def role_name_from_arn(role_arn: Optional[str], *, missing: str = "") -> str:
    """The short role name in ``arn:aws:iam::<acct>:role/<path>/<Name>``."""
    return (role_arn or "").rsplit("/", 1)[-1].strip() or missing


def act_as_permits(act_as: Optional[ActAs], derives: str, role_arn: Optional[str]) -> bool:
    """Does this ONE declaration cover the derivation an action is about to do?"""
    if act_as is None or act_as.mode != derives:
        return False
    return derives != "role" or role_arn is None or act_as.role_arn == role_arn


def require_act_as_permits(
    act_as: Optional[ActAs],
    *,
    derives: str,
    role_arn: Optional[str],
    where: str,
) -> None:
    """Raise unless ``act_as`` IS the derivation ``derives`` describes."""
    if act_as is None:


        raise CredentialError(
            f"{where}: this credential carries no ACT_AS declaration to check "
            "against.\n(internal: an AwsSessionCreds was built without "
            "act_as -- use act_as_from_extra(), the one reconstruction "
            "point, rather than setting the mode alone.)"
        )
    if act_as_permits(act_as, derives, role_arn):
        return

    wanted = "assume roles" if derives == "role" else "federate"
    derived = "assumed-role/<role>/<name>" if derives == "role" else "federated-user/<name>"

    if derives == "role" and role_arn and act_as.mode == "role":


        lines = [
            f"{where}: this credential does not declare that it can assume that role.",
            f"  requested: {role_arn}",
            f"  declared:  {act_as.role_arn}",
            "Which roles a key can assume is validated knowledge, not something to "
            "discover per action -- so each one has to be recorded in a credential "
            "block of its own.",
            f"  find out:  `.creds <ID> perms role {role_arn}`",
            f"  then add:  a block with this key material and ACT_AS=role:{role_arn}",
        ]
    else:
        lines = [
            f"{where}: this credential does not declare that it can {wanted}.",
            f"  declared:  {describe_act_as(act_as)}",
            f"Deriving {derived} is validated knowledge about the key, not something "
            "to discover per action -- so it has to be recorded in the credential "
            "block.",
            "  find out:  `.creds <ID> perms"
            + (f" role {role_arn}" if derives == "role" and role_arn else "")
            + "`",
            "  then add:  a block with this key material and "
            + (
                f"ACT_AS=role:{role_arn}"
                if derives == "role" and role_arn
                else "ACT_AS=role:<arn>" if derives == "role" else "ACT_AS=federated"
            ),
        ]
    raise CredentialError("\n".join(lines))


def describe_act_as(act_as: ActAs) -> str:
    """One-line rendering for error text."""
    if act_as.mode == "role" and act_as.role_arn:
        return f"ACT_AS=role:{act_as.role_arn}"
    return f"ACT_AS={act_as.mode}"


def act_as_mode_of(extra: Optional[dict]) -> str:
    """The declared `ACT_AS` mode from an ``extra`` dict, normalised. "" if absent."""
    return str((extra or {}).get("act_as_mode") or "").strip().lower()


def act_as_from_extra(extra: dict) -> Optional[ActAs]:
    """Rebuild the declared ActAs from a Credentials.extra dict."""
    mode = extra.get("act_as_mode")
    if not mode:
        return None
    raw = f"role:{extra.get('role_arn', '')}" if mode == "role" else str(mode)
    return parse_act_as(raw)


def validate_act_as(act_as: ActAs, *, is_akia: bool, where: str) -> None:
    """Reject the two combinations AWS makes impossible, before any cloud call."""
    if act_as.mode == "federated" and not is_akia:
        raise CredentialError(
            f"{where}: ACT_AS=federated needs a long-term (AKIA) key, but this "
            "credential has a session token. sts:GetFederationToken cannot be "
            "called with temporary credentials.\n"
            "Use ACT_AS=role:<role-arn> to chain into a role, or ACT_AS=direct "
            "to use this session token as-is."
        )
    if act_as.mode == "direct" and is_akia:
        raise CredentialError(
            f"{where}: ACT_AS=direct needs a session token, but this credential "
            "is a long-term (AKIA) key. `putCredentials` rejects a raw permanent "
            "key, so the container would get no working credentials.\n"
            "Use ACT_AS=federated or ACT_AS=role:<role-arn> to upgrade it -- or "
            "ACT_AS=direct-unbound if you want to drive CloudShell with this key "
            "and accept that in-shell `aws` will not work.\n"
            "The refusal stands rather than being relaxed: someone who typed "
            '`direct` meaning "use my key" would otherwise get a shell whose '
            "AWS CLI silently fails, which is the confusion this gate exists to "
            "prevent."
        )
