"""The FOCI candidate list, with a citation on every entry -- `51.16` /"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

SECUREWORKS = "secureworks"
OWNER = "owner-2026-09-01"
OBSERVED = "observed"


VENDOR_SOURCE = "vendor-source"
UNVERIFIED = "unverified"


SECUREWORKS_FOCI: dict[str, str] = {
    "00b41c95-dab0-4487-9791-b9d2c32c80f2": "Office 365 Management",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
    "0ec893e0-5785-4de6-99da-4ed124e5296c": "Office UWP PWA",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264": "Microsoft Teams",
    "22098786-6e16-43cc-a27d-191a01a1e3b5": "Microsoft To-Do client",
    "26a7ee05-5602-4d76-a7ba-eae8b7b67941": "Windows Search",
    "27922004-5251-4030-b22d-91ecd9a37ea4": "Outlook Mobile",
    "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8": "Microsoft Bing Search for Microsoft Edge",
    "4813382a-8fa7-425e-ab75-3b753aab3abb": "Microsoft Authenticator App",
    "4e291c71-d680-4d0e-9640-0a3358e31177": "PowerApps",
    "57336123-6e14-4acc-8dcf-287b6088aa28": "Microsoft Whiteboard Client",
    "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0": "Microsoft Flow",
    "66375f6b-983f-4c2c-9701-d680650f588f": "Microsoft Planner",
    "844cca35-0656-46ce-b636-13f48b0eecbd": "Microsoft Stream Mobile Native",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1": "Visual Studio",
    "87749df4-7ccf-48f8-aa87-704bad0e0e16": "Microsoft Teams - Device Admin Agent",
    "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223": "Microsoft Intune Company Portal",
    "a40d7d7d-59aa-447e-a655-679a4107e548": "Accounts Control UI",
    "a569458c-7f2b-45cb-bab9-b7dee514d112": "Yammer iPhone",
    "ab9b8c07-8f02-4f72-87fa-80105867a763": "OneDrive SyncEngine",
    "af124e86-4e96-495a-b70a-90f90ab96707": "OneDrive iOS App",
    "b26aadf8-566f-4478-926f-589f601d9c74": "OneDrive",
    "be1918be-3fe3-4be9-b32b-b542fc27f02e": "M365 Compliance Drive Client",
    "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12": "Microsoft Power BI",
    "cab96880-db5b-4e15-90a7-f3f1d62ffe39": "Microsoft Defender Platform",
    "cf36b471-5b44-428c-9ce7-313bf84528de": "Microsoft Bing Search",
    "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0": "SharePoint",
    "d3590ed6-52b3-4102-aeff-aad2292ab01c": "Microsoft Office",
    "d7b530a4-7680-4c23-a8bf-c52c121d2e87": "Microsoft Edge Enterprise New Tab Page",
    "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3": "Microsoft Defender for Mobile",
    "e9b154d0-7658-433b-bb25-6b8e0a8a7c59": "Outlook Lite",
    "e9c51622-460d-4d3d-952d-966a5b1da34c": "Microsoft Edge",
    "eb539595-3fe1-474e-9c1d-feb3625d1be5": "Microsoft Tunnel",
    "ecd6b820-32c2-49b6-98a6-444530e5a77a": "Microsoft Edge",
    "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d": "SharePoint Android",
    "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34": "Microsoft Edge",
}


OWNER_CONFIRMED: dict[str, str] = {
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": "Azure Portal",
    "872cd9fa-d31f-45e0-9eab-6e460a02d1f1": "Visual Studio",
}


@dataclass(frozen=True)
class Candidate:
    """One app id the harness will drive a device-code flow for."""

    client_id: str
    name: str
    sources: tuple[str, ...]
    note: str = ""


    expected_refusal_at_token: Optional[str] = None

    @property
    def informative(self) -> bool:
        """Whether a refusal from this id says anything about FOCI."""
        return UNVERIFIED not in self.sources


_OWNER_2026_09_02: tuple[Candidate, ...] = (
    Candidate(
        client_id="00000006-0000-0ff1-ce00-000000000000",
        name="Microsoft Office 365 Portal",
        sources=(OWNER,),
        note=(
            "Owner: 'doesn't work -- needs client_secret in step #2'. It DOES issue a "
            "device code, which is consistent rather than contradictory: /devicecode "
            "does not authenticate the client at all, so a confidential app gets a "
            "user_code and is refused later at the token exchange. Same shape as "
            "b677c290, and the prediction is recorded at the rung it belongs to."
        ),
        expected_refusal_at_token="AADSTS7000218",
    ),
    Candidate(
        client_id="756bccdc-1c1e-4556-b7a4-fe6eafe61d35",
        name="Customer Log (owner's name)",
        sources=(OWNER,),
        note="Owner-supplied, name theirs. Issues a device code for the ARM scope.",
    ),
    Candidate(
        client_id="ce6ff14a-7fdc-4685-bbe0-f6afdfcfa8e0",
        name="App List (owner's name)",
        sources=(OWNER,),
        note="Owner-supplied, name theirs. Issues a device code for the ARM scope.",
    ),
    Candidate(
        client_id="74658136-14ec-4630-ad9b-26e160ff0fc6",
        name="ADIbiza",
        sources=(OWNER,),
        note=(
            "Owner-supplied. The Entra admin-portal blade client -- an ARM-management "
            "surface, so an interesting counterpart to the Azure Portal id we know is "
            "allowlisted."
        ),
    ),
    Candidate(
        client_id="29d9ed98-a469-4536-ade2-f981bc1d605e",
        name="Microsoft Authentication Broker",
        sources=(OWNER,),
        note=(
            "Owner-supplied. The WAM broker -- and NOT the id this catalog previously "
            "guessed for it: `AzureClientIds.WAM_BROKER` holds c44b4083-cba6-..., "
            "which is UNOBSERVED and shares only its first UUID segment with the real "
            "Azure Portal. A fourth mislabel in that class, and the first with a "
            "sourced replacement."
        ),
    ),
)


_EXTRA: tuple[Candidate, ...] = (
    Candidate(
        client_id="245e1dee-74ef-4257-a8c8-8208296e1dfd",
        name="Windows Terminal (Azure Cloud Shell profile)",


        sources=(VENDOR_SOURCE, OBSERVED),
        note=(
            "AZ-OBS-222. A literal in microsoft/terminal's "
            "src/cascadia/TerminalConnection/AzureClientID.h, not a build-time "
            "substitution; AzureConnection.cpp drives it through the v1 device-code "
            "endpoints asking for management.core.windows.net/. Corroborated by "
            "microsoft/terminal issue #6257, Elastic's device-code detection rule and "
            "the public well-known-id lists. "
            "BOTH OPEN QUESTIONS ARE NOW MEASURED, 2026-09-22, and this note keeps "
            "the prediction because it was wrong in an instructive way. "
            "(1) ALLOWLISTED: YES -- AZ-OBS-223, rung 1 PASS beside an Azure CLI "
            "control in the same tenant seconds apart, no ClientNotAllowed. Claim F "
            "measured the allowlist at 2 of 23 with Azure PowerShell REFUSED and "
            "therefore predicted a refusal here. The MECHANISM survived; the census "
            "did not -- 2 of 23 was taken over a candidate set that never contained "
            "this id, so it could not have found it. At least 3 of 24. "
            "(2) FOCI: NO -- AZ-OBS-224, the foci key was ABSENT from the token "
            "response, which is the negative answer rather than a gap. This row "
            "previously reasoned from the SecureWorks list's SILENCE, which is not a "
            "measurement; the direct signal was one key in a response we already had. "
            "It does get a refresh token, but a non-family RT redeems only for its "
            "own client id, so the reach does not compound into cross-client "
            "redemption."
        ),
    ),
    Candidate(
        client_id="c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
        name="Azure Portal",
        sources=(OWNER, OBSERVED),
        note=(
            "The id the portal actually authorised as, first native capture 2026-08-28. "
            "NOT in the SecureWorks list -- identity confirmed, family membership unknown, "
            "and that gap is exactly what a device-code run measures."
        ),
    ),
    Candidate(
        client_id="b677c290-cf4b-4a8e-a60e-91ba650a4abe",
        name="CloudShell portal app (confidential)",
        sources=(UNVERIFIED,),
        note=(
            "NEVER OBSERVED on any capture, despite the docs building a narrative on it. "
            "Kept as a control: a confidential app must refuse a public flow, so a SUCCESS "
            "would overturn more than it confirmed. Stage 0 (2026-09-01) shows it DOES issue "
            "a device code -- initiation is unauthenticated -- so the control lives at the "
            "token poll, which also means an attacker can raise a user_code under this id."
        ),
        expected_refusal_at_token="AADSTS7000218",
    ),
    Candidate(
        client_id="14d82eec-204b-4c2f-b7e8-296a70dab67e",
        name="Microsoft Graph PowerShell",
        sources=(UNVERIFIED,),
        note="Catalogued; not in the SecureWorks list. Public client, ARM scope not Graph-only.",
    ),
    Candidate(
        client_id="aebc6443-996d-45c2-90f0-388ff96faa56",
        name="Visual Studio Code",
        sources=(UNVERIFIED,),
        note="Catalogued; not in the SecureWorks list.",
    ),
    Candidate(
        client_id="c7f5b65f-f7e6-485a-b1cf-c5e22f4dd8b0",
        name="Azure Storage Explorer",
        sources=(UNVERIFIED,),
        note=(
            "Catalogued; not in the SecureWorks list. Interesting anyway -- the storage key "
            "is the control-plane/data-plane bridge, so a storage client reaching CloudShell "
            "would be worth knowing."
        ),
    ),
)


EXCLUDED: dict[str, str] = {
    "04b07795-8542-4c4c-9cb8-f0f09d69f25f": (
        "AzureClientIds.AZURE_CLI -- an UNVERIFIED id whose NAME is also wrong (the Azure CLI "
        "is 04b07795-8ddb-...). Not in the SecureWorks list, no positive evidence anywhere, "
        "and its only live datum is an HTTP 400. Nothing to learn from a sign-in."
    ),
    "c44b4083-cba6-42be-8e29-b9702cdde539": (
        "AzureClientIds.WAM_BROKER -- UNOBSERVED, and shares only its first UUID segment with "
        "the real portal id. Same shape of error as the two 04b07795- mislabels."
    ),
    "04f0c124-f2bc-4f59-8241-bf6df9866bbd": (
        "The value AzureClientIds.VISUAL_STUDIO held until 2026-09-01. NOT Visual Studio -- "
        "both SecureWorks and the owner give 872cd9fa-d31f-45e0-9eab-6e460a02d1f1. A third "
        "mislabel in that catalog after the two corrected on 2026-08-28."
    ),
    "windows-terminal": (
        "SUPERSEDED 2026-09-22 -- the id EXISTS and is now a candidate, "
        "245e1dee-74ef-4257-a8c8-8208296e1dfd (AZ-OBS-222). "
        "This entry is kept, not deleted, because the reading it records is the "
        "instructive part. It said: 'No client id exists. Owner 2026-09-01: N/A -- "
        "host terminal, not an Azure OAuth client', correcting the 2026-08-30 "
        "direction to include it. That was right about the HOST -- a terminal "
        "emulator has no OAuth client id -- and wrong about the unit of analysis: "
        "the Azure Cloud Shell CONNECTION PROFILE has one, and it is a literal in "
        "AzureClientID.h. That distinction is the one missed in "
        "51.16, and it was missed a second time here, in the exclusion written to "
        "record the first miss."
    ),
}


def candidates() -> list[Candidate]:
    """Every app id the harness should attempt, SecureWorks first."""
    out = [
        Candidate(
            client_id=cid,
            name=name,
            sources=(SECUREWORKS,) + ((OWNER,) if cid in OWNER_CONFIRMED else ()),
        )
        for cid, name in sorted(SECUREWORKS_FOCI.items())
    ]
    return out + list(_EXTRA) + list(_OWNER_2026_09_02)
