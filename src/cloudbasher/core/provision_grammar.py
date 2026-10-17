"""What `.provision` accepts for one credential -- dispatched per CSP."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProvisionGrammar:
    """What `.provision` will actually accept for ONE credential."""


    keywords: tuple[str, ...]

    grammar: str


    note: str = ""

    prefill_suffix: str = ""

    @property
    def hint(self) -> str:
        """Grammar and note as one string -- what the whole line says."""
        if not self.note:
            return self.grammar
        sep = "" if self.grammar.rstrip().endswith((".", "!", "?")) else "."
        return f"{self.grammar}{sep} {self.note}"


def grammar_for(provider: str, mode: str = "", kind: str = "") -> ProvisionGrammar:
    """The `.provision` grammar for a credential of `provider`."""
    name = (provider or "").strip().lower()
    if name == "aws":
        from cloudbasher.csp.aws.act_as import provision_grammar

        return provision_grammar(mode, kind=kind)
    if name in ("gcp", "azure"):
        return _selector_only_grammar(name)
    return _no_credential()


def bulk_grammar(count: int) -> ProvisionGrammar:
    """The grammar when the command will act on a SELECTION, not one row."""


    from cloudbasher.csp.aws.commands import _PER_CREDENTIAL_TERMS

    rows = "credential" if count == 1 else f"{count} credentials"
    refused = ", ".join(f"`{t}`" for t in _PER_CREDENTIAL_TERMS)


    return ProvisionGrammar(
        keywords=("region",),
        grammar="Provision armed — selected region <selector> [index <index|start-end>]",
        note=(
            f"acts on the {rows} ticked in the pane; an index applies to every "
            f"row and overrides a declared INDEX=. {refused} are refused -- "
            "they would give every row one shared name"
        ),
        prefill_suffix="region ",
    )


def _selector_only_grammar(name: str) -> ProvisionGrammar:
    label = "GCP" if name == "gcp" else "Azure"
    note = (


        "GCP Cloud Shell has no selectable region -- Google assigns the zone."
        if name == "gcp"
        else ""
    )
    return ProvisionGrammar(
        keywords=(),
        grammar=f"Provision — {label} accepts no additional modifiers.",
        note=note,
        prefill_suffix="",
    )


def _no_credential() -> ProvisionGrammar:
    """The cursor is on no credential, or on a provider nothing knows about."""
    return ProvisionGrammar(
        keywords=(),
        grammar="Provision — move to a credential row, or type `.provision <ID> ...`.",
        prefill_suffix="",
    )
