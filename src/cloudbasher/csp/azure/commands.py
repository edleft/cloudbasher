"""Azure-specific dot commands registered via AzureProvider.register_dot_commands()."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from cloudbasher.core.credential_validation import known_invalid_credential_error
from cloudbasher.core.exceptions import CredentialError
from cloudbasher.core.utils.output import eprint, log, out
from cloudbasher.csp.azure.types import from_unified

if TYPE_CHECKING:
    from cloudbasher.core.cli.command_spec import ParseResult
    from cloudbasher.core.types import CredentialRecord, InteractiveState


def _numbered_records_for_provision(
    r: "ParseResult", state: "InteractiveState"
) -> list[tuple[int, "CredentialRecord"]] | None:
    """Resolve one Azure-only `.provision` request before any cloud action."""
    if r.segments:
        bad = ", ".join(sorted(r.segments))
        eprint(
            "provision: Azure accepts no modifiers; use `.provision <ID>` "
            f"to create or reuse its one CloudShell node (unexpected: {bad})."
        )
        return None

    from cloudbasher.core.selection import (
        implicit_credential_records,
        nothing_selected_message,
        resolve_numbered_selector,
        selected_credential_records,
    )
    from cloudbasher.core.types import numbered_originating_records

    numbered = numbered_originating_records(state.credentials_by_id)
    selector = r.selector
    if selector is None:
        picked_records = implicit_credential_records(state)
        if not picked_records:
            cursor_id = getattr(state, "cursor_credential_id", None)
            picked_records = [rec for _number, rec in numbered if rec.id == cursor_id]
        if not picked_records:
            eprint("provision: name an Azure credential ID, or select one first.")
            return None
        picked = [
            (number, rec)
            for number, rec in numbered
            if any(rec.id == chosen.id for chosen in picked_records)
        ]
    elif selector.strip().lower() == "selected":
        selected = selected_credential_records(state)
        if not selected:
            eprint(f"provision: {nothing_selected_message()}")
            return None
        picked = [
            (number, rec)
            for number, rec in numbered
            if any(rec.id == chosen.id for chosen in selected)
        ]
    else:
        picked, unknown, malformed = resolve_numbered_selector(numbered, selector)
        if malformed:
            eprint(f"provision: credential selector {malformed[0]!r} is not a number")
            return None
        if unknown:
            eprint(f"provision: no credential [{unknown[0]}]")
            return None

    providers = {rec.provider for _number, rec in picked}
    if len(providers) != 1 or not providers <= {"azure", "gcp"}:
        names = ", ".join(f"[{number}] {rec.provider}" for number, rec in picked)
        eprint(
            "provision: non-AWS provisioning accepts one provider at a time "
            f"({names}). Select only Azure or only GCP credentials."
        )
        return None
    return picked


def _notify_node_change(state: "InteractiveState", node: Any) -> None:
    """Request the TUI repaint after an Azure node state transition."""
    from cloudbasher.core.cli.dispatcher import notify_node_change

    notify_node_change(state, node)


def cmd_provision(r: "ParseResult", state: "InteractiveState") -> bool:
    """`.provision <ID>|selected [--yes]` — explicitly create/reuse one non-AWS shell."""
    picked = _numbered_records_for_provision(r, state)
    if picked is None:
        return True

    rejected = [
        known_invalid_credential_error(
            rec, "provision", label=f"{rec.provider.upper()} credential [{number}]"
        )
        for number, rec in picked
    ]
    rejected = [message for message in rejected if message]
    if rejected:
        for message in rejected:
            eprint(message)
        return True

    show_browser = bool(
        getattr(getattr(state, "args", None), "show_browser", False)
    )
    gcp_console_records = [
        (number, rec)
        for number, rec in picked
        if rec.provider == "gcp"
        and (
            rec.kind == "console"
            or bool(getattr(rec.raw, "extra", {}).get("_needs_playwright"))
            or bool(
                getattr(rec.raw, "extra", {}).get("username")
                and getattr(rec.raw, "extra", {}).get("password")
            )
        )
    ]


    if gcp_console_records and "gcp-console-confirmed" not in r.flags:
        typed = r.raw.strip()
        rerun = f"{typed} --gcp-console-confirmed"
        if "yes" not in r.flags:
            rerun += " --yes"
        state.pending_confirm = (
            "GCP sign-in may need verification; browser opens if needed. Continue [Y/n]?",
            rerun,
        )
        return True

    if "yes" not in r.flags:
        rerun = " ".join(token for token in r.raw.split() if token != "--yes") + " --yes"
        noun = "node" if len(picked) == 1 else "nodes"
        state.pending_confirm = (
            f"provision {len(picked)} Cloud Shell {noun} [Y/n]",
            rerun,
        )
        return True


    from cloudbasher.cli.main import _bootstrap_primary_node_for_credential, _primary_node_id
    from cloudbasher.core.types import NodeRecord

    args = getattr(state, "args", None)
    if args is None:
        eprint("provision: internal state has no invocation arguments")
        return True

    for number, rec in picked:
        node = state.nodes_by_id.get(_primary_node_id(rec.id))
        if node is not None and getattr(node, "_runtime_session", None) is not None:
            out(
                f"provision: {rec.provider.upper()} credential [{number}] "
                f"already has node {node.id}"
            )
            continue
        node = node or NodeRecord(
            id=_primary_node_id(rec.id),
            credential_id=rec.id,
            region=None,
            environment_id=None,
            session=None,
            container_status="Pending",
        )


        node.mark_working()
        state.register_node(node)
        _notify_node_change(state, node)
        try:
            import copy

            credential_args = copy.copy(args)
            if rec.provider == "gcp":
                credential_args.show_browser = show_browser and rec.kind == "console"


            ready = _bootstrap_primary_node_for_credential(
                args=credential_args,
                rec=rec,
                emit=out,
                gcp_wait_mode="auto",
                node=node,
                on_node_change=lambda changed: _notify_node_change(state, changed),
                credential_registry=state.credentials_by_id,
            )
        except Exception as exc:
            node.container_status = "Failed"
            node.end_connect()
            node.clear_working()
            _notify_node_change(state, node)
            eprint(f"provision: {rec.provider.upper()} credential [{number}] failed: {exc}")
            continue
        node.clear_working()
        state.register_node(ready)
        state.active_node_id = ready.id
        _notify_node_change(state, ready)
        out(f"provision: {rec.provider.upper()} credential [{number}] ready as node {ready.id}")
    return True


def cmd_delete(
    r: "ParseResult",
    state: "InteractiveState",
    *,
    node_ids: set[str] | None = None,
    emit_summary: bool = True,
    confirmed: bool = False,
) -> bool:
    """Confirmation-gated Azure Cloud Shell reset for selected Azure nodes."""
    from cloudbasher.core.cli.dispatcher import _resolve_nodes_or_report

    selector = r.selector or ""
    if "force" in r.flags:
        eprint("delete: --force has no Azure reset meaning; no action was taken.")
        return True
    if node_ids is None:
        node_ids = _resolve_nodes_or_report("delete", selector, state)
        if node_ids is None:
            return True
    records = [
        (node_id, state.nodes_by_id[node_id])
        for node_id in node_ids
        if node_id in state.nodes_by_id
    ]
    if not records:
        return True
    if any(
        (state.credentials_by_id.get(node.credential_id) is None)
        or state.credentials_by_id[node.credential_id].provider != "azure"
        for _node_id, node in records
    ):
        eprint("delete: Azure reset accepts Azure nodes only; no action was taken.")
        return True
    for _node_id, node in records:
        credential = state.credentials_by_id.get(node.credential_id)
        invalid = known_invalid_credential_error(
            credential, "delete", label=f"credential for node {node.id}"
        )
        if invalid:
            eprint(invalid)
            return True

    if "yes" not in r.flags and not confirmed:
        state.pending_confirm = (
            "Reset Azure Cloud Shell: console/container and userSettings may be deleted; "
            "backing storage account/file share remain [Y/n]",
            f".delete {selector} --yes",
        )
        return True

    deleted: list[str] = []
    failed: list[str] = []
    from cloudbasher.core.cli.dispatcher import (
        begin_node_activity,
        close_parked_browser,
        disconnect_node,
        end_node_activity,
    )

    for node_id, node in records:
        api = getattr(node, "_runtime_api_client", None) or _get_api(state)
        if api is None:
            failed.append(node_id)
            eprint(f"delete: Azure reset for node {node_id} has no API client.")
            continue
        begin_node_activity(state, node)
        console_removed = False
        try:


            api.delete_console()
            console_removed = True
            api.delete_user_settings()
        except Exception as exc:
            if console_removed:


                disconnect_node(node)
                close_parked_browser(node)
                node.environment_id = None
                node.session = None
                node.container_status = "Unknown"
            failed.append(node_id)
            eprint(f"delete: Azure reset for node {node_id} failed ({type(exc).__name__}).")
            continue
        finally:
            end_node_activity(state, node)
        disconnect_node(node)
        close_parked_browser(node)
        state.nodes_by_id.pop(node_id, None)
        deleted.append(node_id)


        _notify_node_change(state, node)

    if getattr(state, "active_node_id", None) in deleted:
        state.active_node_id = next(iter(state.nodes_by_id), None)

    if emit_summary:
        out(
            f"Azure Cloud Shell reset: {len(deleted)}/{len(records)} node(s) "
            "(backing storage retained)."
        )
    if failed:
        eprint(f"Azure reset incomplete for node(s): {', '.join(failed)}")
    if emit_summary:
        state.last_node_action_message = (
            "Azure reset complete" if not failed else f"Azure reset · {len(failed)} failed"
        )
    if records:


        _notify_node_change(state, records[-1][1])
    return True


def _get_api(state: "InteractiveState") -> Any:
    """Return the live AzureCloudShellAPI from state.api_client or None."""
    return getattr(state, "api_client", None)


def _get_console(state: "InteractiveState") -> Any:
    """Return cached ConsoleInfo from state.extra or None."""
    extra = getattr(state, "extra", None) or {}
    return extra.get("azure_console")


def _put_console_note(api: Any) -> str:
    """One-line `.perms` note for a console PUT, led by what its status means."""
    written = api.provision_console(os_type="Linux")
    verb = "created it" if written.created else "one already existed"
    return f"HTTP {written.status} — {verb}: {written.console.console_id}"


def _get_terminal(state: "InteractiveState") -> Any:
    """Return cached TerminalInfo from state.extra or None."""
    extra = getattr(state, "extra", None) or {}
    return extra.get("azure_terminal")


def cmd_creds(args: list[str], state: "InteractiveState") -> bool:
    """.creds [show|configure] — show current credentials or re-authenticate."""
    if args and args[0] == "configure":
        _cmd_creds_configure(state)
        return True

    creds = state.credentials
    if creds is None:
        out("No credentials loaded. Use .creds configure or re-run with -F FILE.")
        return True

    fields = from_unified(creds)
    display = {
        "email": fields.get("email") or "(unknown)",
        "tenant_id": fields.get("tenant_id", ""),
        "subscription_id": fields.get("subscription_id", ""),
        "client_id": fields.get("client_id") or "(interactive)",
        "token_expiry": (
            fields.get("token_expiry").isoformat() if fields.get("token_expiry") else "(no expiry)"
        ),
    }
    out(json.dumps(display, indent=2))
    return True


def _cmd_creds_configure(state: "InteractiveState") -> None:
    """Interactive credential re-configuration."""
    out("Configure Azure credentials:")
    out("  1. JSON credential file path")
    out("  2. Device code flow (interactive)")
    out("  Enter '.' to cancel")
    try:
        choice = input("Choice [2]: ").strip() or "2"
    except (EOFError, KeyboardInterrupt):
        return
    if choice == ".":
        return

    if choice == "1":
        try:
            path = input("Credential file path: ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if not path or path == ".":
            return
        try:
            from cloudbasher.csp.azure.credentials import load_credentials_from_file

            new_creds = load_credentials_from_file(path)
            state.credentials = new_creds
            fields = from_unified(new_creds)
            out(f"Loaded credentials (email={fields.get('email') or '?'})")
        except CredentialError as exc:
            eprint(f"Error: {exc}")
    else:

        fields = from_unified(state.credentials) if state.credentials else {}
        tenant = fields.get("tenant_id", "")
        if not tenant:
            try:
                tenant = input("Tenant ID: ").strip()
            except (EOFError, KeyboardInterrupt):
                return
        sub = fields.get("subscription_id", "")
        if not sub:
            try:
                sub = input("Subscription ID: ").strip()
            except (EOFError, KeyboardInterrupt):
                return
        if not tenant or not sub:
            eprint("Tenant ID and Subscription ID are required.")
            return
        try:
            from cloudbasher.csp.azure.credentials import load_credentials_from_device_code

            new_creds = load_credentials_from_device_code(tenant, sub)
            state.credentials = new_creds
            new_fields = from_unified(new_creds)
            out(f"Authenticated (email={new_fields.get('email') or '?'})")
        except CredentialError as exc:
            eprint(f"Error: {exc}")


def cmd_region(args: list[str], state: "InteractiveState") -> bool:
    """.region [REGION] — show or set the current Azure region."""
    extra = getattr(state, "extra", None) or {}
    if not args:
        console = extra.get("azure_console")
        region = console.region if console else extra.get("azure_region", "unknown")
        out(f"Region: {region}")
        return True

    new_region = args[0]
    if not hasattr(state, "extra") or state.extra is None:
        state.extra = {}  # type: ignore[assignment]
    state.extra["azure_region"] = new_region  # type: ignore[index]


    if state.session and hasattr(state.session, "region"):
        state.session.region = new_region  # type: ignore[assignment]
    out(f"Azure region set to: {new_region}")
    log(f"[azure] region set to {new_region}")
    return True


def cmd_enum(args: list[str], state: "InteractiveState") -> bool:
    """.enum — list Azure CloudShell console/terminal status and public IP."""

    extra = getattr(state, "extra", None) or {}
    console = extra.get("azure_console")
    terminal = extra.get("azure_terminal")

    if console is None:


        out("  (no console in this session — Azure exposes no read path to find one;")
        out("   run a command to provision, or .perms for the write-verb probe)")
        return True


    pub_ip = ""
    session_obj = getattr(state, "_session_obj", None) or getattr(state, "session", None)
    if session_obj is not None and hasattr(session_obj, "exec_in_shell"):
        try:
            pub_ip = session_obj.exec_in_shell(
                "curl -s --max-time 5 ip.me 2>/dev/null", timeout=10.0
            ).strip()
        except Exception:
            pass

    idle = f"{terminal.idle_timeout}min" if terminal else ""
    headers = ["console_id", "idle_timeout", "region", "state", "public_ip"]
    row = [
        console.console_id,
        idle,
        console.region,
        console.provisioning_state,
        pub_ip or "(unknown)",
    ]
    widths = [max(len(h), len(v)) for h, v in zip(headers, row)]
    try:
        _tw = os.get_terminal_size().columns
    except OSError:
        _tw = 9999
    _total = 1 + sum(w + 3 for w in widths)
    if _total > _tw:
        _n = len(widths)
        _avail = _tw - 1 - 3 * _n
        if _avail > _n:
            _s = sum(widths)
            widths = [max(4, int(w * _avail / _s)) for w in widths]

    def _trunc(s: str, w: int) -> str:
        return s if len(s) <= w else s[: w - 1] + "…"

    def _div() -> str:
        return "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def _row(cells: list) -> str:
        return (
            "|"
            + "|".join(
                f" {_trunc(str(cells[i]), widths[i]):<{widths[i]}} " for i in range(len(widths))
            )
            + "|"
        )

    out(_div())
    out(_row(headers))
    out(_div())
    out(_row(row))
    out(_div())
    log(f"enum: console_id={console.console_id} state={console.provisioning_state} ip={pub_ip}")
    return True


def cmd_perms(args: list[str], state: "InteractiveState") -> bool:
    """Azure RBAC permission discovery via live API probes."""
    from cloudbasher.core.exceptions import CloudShellAutomationError as _CSAError

    if state.credentials is None:
        eprint("No credentials loaded. Use .creds configure or -F <file>.")
        return True

    api = _get_api(state)
    if api is None:
        eprint(".perms requires an active API client (run a command first to bootstrap session).")
        return True

    creds_fields = from_unified(state.credentials)
    out("== Azure CloudShell Permission Discovery ==")
    out(
        f"subscription={creds_fields.get('subscription_id', '?')}  "
        f"email={creds_fields.get('email') or '?'}"
    )
    out("")

    probes = [
        ("GET userSettings", lambda: json.dumps(api.get_user_settings(), indent=2)[:80]),


        ("GET console", lambda: f"HTTP {api.read_console_probe()} (404 expected — no read verb)"),
        ("PUT console", lambda: _put_console_note(api)),
    ]
    out(f"{'probe':<30}  {'status':<15}  notes")
    out("─" * 70)
    for probe_name, probe_fn in probes:
        try:
            note = probe_fn()


            out(f"  {probe_name:<28}  {'✓ allowed':<15}  {note}")
        except _CSAError as exc:
            short = str(exc)[:50]
            out(f"  {probe_name:<28}  {'✗ denied':<15}  {short}")

    out("")
    out("Note: PUT console creates a real console if not present — 201 says it did,")
    out("      200 says one was already there. That status code is the only console")
    out("      state Azure will report; GET answers 404 either way (AZ-OBS-201).")
    return True


def register_azure_commands(dispatcher: Any) -> None:
    """Register all Azure-specific dot commands with the dispatcher."""
    dispatcher.register(".creds", cmd_creds, help="Show or configure Azure credentials")
    dispatcher.register(".region", cmd_region, help="Show or set Azure region")
    dispatcher.register(".enum", cmd_enum, help="List Azure CloudShell console status + public IP")
