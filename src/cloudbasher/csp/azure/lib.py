"""Azure CloudShell orchestration facade — bootstrap, run_command, file ops."""

from __future__ import annotations

import re
import time
from typing import Any, Optional

from cloudbasher.core.exceptions import CloudShellAutomationError, SessionError
from cloudbasher.core.types import Credentials
from cloudbasher.core.utils.output import detail, log, out_ts
from cloudbasher.csp.azure.api import AzureCloudShellAPI
from cloudbasher.csp.azure.session import AzureSession
from cloudbasher.csp.azure.storage_names import derive_storage_names
from cloudbasher.csp.azure.types import (
    CommandRunOptions,
    ConsoleInfo,
    TerminalInfo,
    is_isolated_console,
    resolve_storage_profile,
)


def _ephemeral_user_settings_body(creds: Credentials) -> dict[str, Any]:
    """The observed clean-account `userSettings` body for an ephemeral shell."""
    fields = creds.extra or {}
    subscription_id = str(fields.get("subscription_id") or "")
    region = str(fields.get("cloudshell_region") or "")
    session_type = str(fields.get("cloudshell_session_type") or "").lower()
    if not subscription_id or not region:
        raise CloudShellAutomationError(
            "Azure clean-account setup requires subscription_id and region in the console "
            "credential block before it can create userSettings."
        )
    if session_type != "ephemeral":
        requested = session_type or "(unset)"
        raise CloudShellAutomationError(
            f"Azure clean-account setup requested session_type={requested!r}; "
            "the Ephemeral settings builder only accepts session_type=ephemeral."
        )


    return {
        "properties": {


            "networkType": "Default",
            "preferredLocation": region,
            "preferredOsType": "linux",
            "preferredShellType": "bash",
            "sessionType": "Ephemeral",
            "userSubscription": subscription_id,
            "terminalSettings": {"fontSize": "Medium", "fontStyle": "Monospace"},
            "vnetSettings": None,
        }
    }


def _mounted_user_settings_body(
    creds: Credentials, storage_profile: dict[str, Any]
) -> dict[str, Any]:
    fields = creds.extra or {}
    subscription_id = str(fields.get("subscription_id") or "")
    region = str(fields.get("cloudshell_region") or "")
    if not subscription_id or not region:
        raise CloudShellAutomationError(
            "Azure mounted_auto setup requires subscription_id and region in the "
            "credential block before it can create userSettings."
        )
    return {
        "properties": {
            "networkType": "Default",
            "preferredLocation": region,
            "preferredOsType": "linux",
            "preferredShellType": "bash",
            "sessionType": "Mounted",
            "storageProfile": storage_profile,
            "terminalSettings": {"fontSize": "medium", "fontStyle": "monospace"},
            "userSubscription": subscription_id,
            "vnetSettings": None,
        }
    }


def _arm_token_claims(creds: Credentials) -> dict[str, Any]:


    from cloudbasher.csp.azure.credentials import _decode_jwt_payload

    token = creds.access_token
    if not isinstance(token, str) or not token:
        raise CloudShellAutomationError(
            "Azure mounted_auto needs an ARM access token to derive Portal storage names."
        )
    claims = _decode_jwt_payload(token)
    if not claims:
        raise CloudShellAutomationError(
            "Azure mounted_auto needs a decodable ARM token with the Portal's "
            "storage-name claims (puid or altsecid, and upn or unique_name)."
        )
    declared_tenant = str((creds.extra or {}).get("tenant_id") or "").lower()
    token_tenant = str(claims.get("tid") or "").lower()
    if declared_tenant and token_tenant and declared_tenant != token_tenant:
        raise CloudShellAutomationError(
            "Azure mounted_auto token tenant does not match tenant_id in the credential block."
        )
    return claims


def _storage_account_body(region: str) -> dict[str, Any]:
    """The account PUT body observed in the native Portal first-run flow."""
    return {
        "kind": "StorageV2",
        "location": region,
        "sku": {"name": "Standard_LRS"},
        "tags": {"ms-resource-usage": "azure-cloud-shell"},
        "properties": {
            "allowBlobPublicAccess": False,
            "minimumTlsVersion": "TLS1_2",
            "supportsHttpsTrafficOnly": True,
            "encryption": {
                "keySource": "Microsoft.Storage",
                "services": {"blob": {"enabled": True}, "file": {"enabled": True}},
            },
        },
    }


def _resource_properties(data: dict[str, Any]) -> dict[str, Any]:
    properties = data.get("properties", {})
    return properties if isinstance(properties, dict) else {}


def _ensure_storage_provider_registered(api: AzureCloudShellAPI, subscription_id: str) -> None:
    """Follow the captured Storage RP registration/poll path with a hard limit."""
    state = api.get_storage_provider_state(subscription_id).get("registrationState", "")
    if state == "Registered":
        return
    api.register_storage_provider(subscription_id)
    deadline = time.monotonic() + 150
    while True:
        state = api.get_storage_provider_state(subscription_id).get("registrationState", "")
        if state == "Registered":
            return
        if time.monotonic() >= deadline:
            raise CloudShellAutomationError(
                "Azure Microsoft.Storage provider did not reach Registered within 150s "
                f"(last state={state or 'unknown'})."
            )
        time.sleep(5)


def _ensure_mounted_auto_storage(api: AzureCloudShellAPI, creds: Credentials) -> dict[str, Any]:
    """Adopt/create the Portal-convention storage account before writing settings."""
    fields = creds.extra or {}
    subscription_id = str(fields.get("subscription_id") or "")
    region = str(fields.get("cloudshell_region") or "")
    if not subscription_id or not region:
        raise CloudShellAutomationError(
            "Azure mounted_auto setup requires subscription_id and region in the "
            "credential block before it can create userSettings."
        )
    if not re.fullmatch(r"[a-z0-9-]+", region.lower()):
        raise CloudShellAutomationError(
            "Azure mounted_auto region must use the standard Azure location name."
        )
    region = region.lower()
    claims = _arm_token_claims(creds)
    resource_group, account_name, share_name = derive_storage_names(claims, region)
    account_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Storage/storageAccounts/{account_name}"
    )

    try:
        account = api.get_storage_account(subscription_id, resource_group, account_name)
    except CloudShellAutomationError as exc:


        if exc.status_code != 404:
            raise
        log("Azure mounted_auto: account absent; creating Cloud Shell storage resources...")
        _ensure_storage_provider_registered(api, subscription_id)
        api.put_resource_group(subscription_id, resource_group, location=region)
        api.put_storage_account(
            subscription_id,
            resource_group,
            account_name,
            _storage_account_body(region),
        )
        deadline = time.monotonic() + 120
        account = {}
        while True:
            try:
                account = api.get_storage_account(subscription_id, resource_group, account_name)
            except CloudShellAutomationError as poll_exc:
                if poll_exc.status_code != 404:
                    raise
            state = _resource_properties(account).get("provisioningState", "")
            if account and state == "Succeeded":
                break
            if account and state in {"Failed", "Canceled"}:
                raise CloudShellAutomationError(
                    f"Azure mounted_auto storage account provisioning reached {state}."
                )
            if time.monotonic() >= deadline:
                raise CloudShellAutomationError(
                    "Azure mounted_auto storage account did not reach Succeeded within 120s "
                    f"(last state={state or 'not visible'})."
                )
            time.sleep(3.5)
    else:
        state = _resource_properties(account).get("provisioningState", "")
        deadline = time.monotonic() + 120
        while state not in {"Succeeded", "Failed", "Canceled"}:
            if time.monotonic() >= deadline:
                raise CloudShellAutomationError(
                    "Azure mounted_auto adopted storage account did not reach "
                    f"Succeeded within 120s (last state={state or 'unknown'})."
                )
            time.sleep(3.5)
            account = api.get_storage_account(subscription_id, resource_group, account_name)
            state = _resource_properties(account).get("provisioningState", "")
        if state and state != "Succeeded":
            raise CloudShellAutomationError(
                f"Azure mounted_auto adopted storage account reached {state}."
            )

    log(f"Azure mounted_auto selected Azure's conventional storage profile in {region}.")
    return {
        "diskSizeInGB": 5,
        "fileShareName": share_name,
        "storageAccountResourceId": account_id,
    }


def ensure_user_settings(api: AzureCloudShellAPI) -> dict[str, Any]:
    """Read settings, or create the explicitly selected clean-state form."""
    try:
        return api.get_user_settings()
    except CloudShellAutomationError as exc:
        if exc.status_code != 404 or exc.error_code != "UserSettingsNotFound":
            raise
    session_type = str((api.credentials.extra or {}).get("cloudshell_session_type") or "").lower()
    if session_type == "ephemeral":
        body = _ephemeral_user_settings_body(api.credentials)
        log("CloudShell user settings absent — creating declared Ephemeral settings...")
    elif session_type == "mounted_auto":
        storage_profile = _ensure_mounted_auto_storage(api, api.credentials)
        body = _mounted_user_settings_body(api.credentials, storage_profile)
        log("CloudShell user settings absent — creating declared Mounted settings.")
    else:
        requested = session_type or "(unset)"
        raise CloudShellAutomationError(
            f"Azure clean-account setup requires session_type=ephemeral or "
            f"session_type=mounted_auto; got {requested!r}."
        )
    return api.put_user_settings(body)


def provision_or_reuse_console(
    api: AzureCloudShellAPI,
    *,
    timeout: int = 120,
) -> ConsoleInfo:
    """PUT the console; the status code says whether it already existed."""
    fields = api.credentials.extra or {}
    sub_id = fields.get("subscription_id", "")
    tenant_id = fields.get("tenant_id", "")
    log(f"GET userSettings: sub={sub_id}  tenant={tenant_id}")
    settings = ensure_user_settings(api)
    props = settings.get("properties", settings)
    region = props.get("preferredLocation", "")
    shell_type = props.get("preferredShellType", "")
    os_type = props.get("preferredOsType", "")
    storage = resolve_storage_profile(props)
    net = "  network=Isolated" if is_isolated_console(props) else ""
    log(f"CloudShell user settings: region={region}  shell={shell_type}  os={os_type}{net}")
    if storage:
        log(f"  storageAccount={storage.get('storageAccountResourceId','')}")
        log(
            f"  fileShare={storage.get('fileShareName','')}  "
            f"diskSizeGB={storage.get('diskSizeInGB','')}"
        )
    else:
        log("  (no storage profile in user settings)")

    log("PUT Azure CloudShell console (201 = created, 200 = reusing an existing one)...")
    written = api.provision_console(os_type="Linux")

    console = written.console
    verb = "Created" if written.created else "Reused existing"
    log(f"{verb} console: {console.console_id} region={console.region} (PUT {written.status})")
    detail(f"Provision initiated: state={console.provisioning_state}")

    if not console.is_ready:
        log("Waiting for console to become ready...")
        console = api.wait_console_ready(timeout=timeout)

    out_ts(f"Console ready: {console.console_id} region={console.region}")
    return console


def bootstrap_session(
    creds: Credentials,
    options: CommandRunOptions,
    *,
    reuse: bool = True,
    saved_console: Optional[ConsoleInfo] = None,
    saved_terminal: Optional[TerminalInfo] = None,
    api_client: Optional[AzureCloudShellAPI] = None,
) -> tuple[ConsoleInfo, TerminalInfo, AzureSession]:
    """Full session bootstrap: find/create console → create terminal → WS connect → warmup."""


    if api_client is None:
        from cloudbasher.csp.azure.provider import AzureProvider

        api_client = AzureProvider().create_api_client(
            creds,
            timeout=options.http_timeout,
            proxy_url=options.proxy_url,
            proxy_insecure=options.proxy_insecure,
        )
    api = api_client

    extra = creds.extra or {}
    if (
        creds.access_token
        and not extra.get("refresh_token")
        and not extra.get("client_secret")
        and not extra.get("certificate_path")
        and not extra.get("certificate_pem")
        and extra.get("auth_flow") != "portal"
        and not getattr(creds, "_runtime_audience_token_provider", None)
    ):
        log(
            "Azure static access token: CloudBasher can reuse it only for its exact "
            "audience after Azure validates it. It cannot acquire Graph or Key Vault "
            "tokens; use an OAuth refresh-token or Azure Console credential for those `az` commands."
        )

    console = provision_or_reuse_console(api, timeout=options.env_wait_timeout)

    if reuse and saved_terminal and saved_console:
        try:
            log(f"Attempting to reconnect saved terminal {saved_terminal.terminal_id}...")
            session = AzureSession(
                console,
                saved_terminal,
                creds,
                timeout=options.ws_timeout,
                proxy_url=options.proxy_url,
                proxy_insecure=options.proxy_insecure,
                api_client=api,
            )
            session.connect()
            session.ensure_persistent_shell()
            out_ts(
                f"Reconnected terminal={saved_terminal.terminal_id} "
                f"console={console.console_id}"
            )
            return console, saved_terminal, session
        except (SessionError, CloudShellAutomationError) as exc:
            log(f"Saved terminal reconnect failed ({exc}); creating new terminal")

    log(f"Creating terminal (shell={options.shell}, cols=220, rows=50)...")
    terminal = api.create_terminal(
        console,
        cols=220,
        rows=50,
        shell=options.shell,
    )
    log(f"Terminal created: {terminal.terminal_id} socket={terminal.socket_uri}")

    session = AzureSession(
        console,
        terminal,
        creds,
        timeout=options.ws_timeout,
        proxy_url=options.proxy_url,
        proxy_insecure=options.proxy_insecure,
        api_client=api,
    )
    session.connect()
    session.ensure_persistent_shell()

    out_ts(
        f"Session ready: console={console.console_id} "
        f"terminal={terminal.terminal_id} region={console.region}"
    )
    return console, terminal, session


def run_command(
    *,
    creds: Credentials,
    options: CommandRunOptions,
) -> dict[str, Any]:
    """Bootstrap a session, execute one command, return output dict."""
    console, terminal, session = bootstrap_session(creds, options)
    try:
        output = session.exec_in_shell(
            options.command or "",
            timeout=float(options.ws_timeout),
            raw=False,
        )
    finally:
        session.close()

    return {
        "output": output,
        "exit_code": 0,
        "console": console.summary_dict(),
        "terminal": terminal.summary_dict(),
    }


def upload_file(
    api: AzureCloudShellAPI,
    console: ConsoleInfo,
    terminal: TerminalInfo,
    local_path: str,
    remote_path: str,
) -> None:
    log(f"Uploading {local_path} → {remote_path}")
    resp = api.upload_file(console, terminal, local_path, remote_path)
    detail(f"Upload response: {resp}")
    out_ts(f"Upload complete: {local_path} → {remote_path}")


def download_file(
    api: AzureCloudShellAPI,
    console: ConsoleInfo,
    terminal: TerminalInfo,
    remote_path: str,
    local_path: str,
) -> None:
    log(f"Downloading {remote_path} → {local_path}")
    api.download_file(console, terminal, remote_path, local_path)
    out_ts(f"Download complete: {remote_path} → {local_path}")


def list_directory(
    api: AzureCloudShellAPI,
    console: ConsoleInfo,
    terminal: TerminalInfo,
    path: str,
) -> list[dict[str, Any]]:
    return api.list_directory(console, terminal, path)
