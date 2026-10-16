"""TUI-based interactive mode."""

from __future__ import annotations

import threading
import time
from typing import Callable, Optional

from ..exceptions import CloudShellAutomationError
from ..tui.application import ShellContextInfo, TUIApplication
from ..types import InteractiveState
from ..utils.output import detail, eprint, log
from .base import InteractiveMode


def _verify_gcp_oauth_credential(record, state: InteractiveState) -> bool:
    """Verify a GCP OAuth credential and resolve its user/org labels read-only."""
    from cloudbasher.core.identity_listing import (
        mark_credential_invalid,
        mark_credential_verified,
    )
    from cloudbasher.csp.gcp.credentials import (
        _GCLOUD_CLIENT_ID,
        _GCLOUD_CLIENT_SECRET,
        GCPInvalidAccessToken,
        exchange_oauth_refresh_token,
        inspect_oauth_access_token,
        resolve_quota_project,
    )

    extra = record.raw.extra or {}
    data = extra.get("data") if isinstance(extra.get("data"), dict) else {}
    refresh_token = str(extra.get("refresh_token") or data.get("refresh_token") or "")
    access_token = str(
        extra.get("access_token")
        or data.get("access_token")
        or record.raw.access_token
        or ""
    )
    try:
        if refresh_token:
            client_id = str(
                extra.get("client_id") or data.get("client_id") or _GCLOUD_CLIENT_ID
            )
            client_secret = str(
                extra.get("client_secret")
                or data.get("client_secret")
                or _GCLOUD_CLIENT_SECRET
            )
            rapt_token = str(extra.get("rapt_token") or data.get("rapt_token") or "")
            if rapt_token:
                access_token = exchange_oauth_refresh_token(
                    refresh_token, client_id, client_secret, rapt_token
                )
            else:
                access_token = exchange_oauth_refresh_token(
                    refresh_token, client_id, client_secret
                )
        details = inspect_oauth_access_token(
            access_token,
            project_id=(
                str(extra.get("project_id") or data.get("project_id") or "") or None
            ),
            quota_project=resolve_quota_project(
                getattr(state, "args", None), record.raw
            ),
            **_proxy_kwargs(state),
        )
    except Exception as exc:
        invalid_grant = refresh_token and "invalid_grant" in str(exc).lower()
        if isinstance(exc, GCPInvalidAccessToken) or invalid_grant:
            mark_credential_invalid(record, state.credentials_by_id)
        raise

    email = str(details.get("email") or "").strip()
    if email:


        extra["username"] = email
    organization_id = str(details.get("organization_id") or "").strip()
    organization_name = str(details.get("organization_name") or "").strip()
    subject = str(details.get("subject") or "").strip()
    if organization_id:
        record._resolved_account = organization_id
        record._resolved_organization_name = organization_name
    elif subject:


        record._resolved_subject = subject
    if details.get("cloudshell_denial") == "quota_project_serviceusage":


        log(
            "[gcp.identity] OAuth token is valid, but Cloud Shell API access is "
            "denied by the quota project's Service Usage permission; grant "
            "serviceusage.services.use (for example via "
            "roles/serviceusage.serviceUsageConsumer) or choose an authorized quota project."
        )
    elif details.get("cloudshell_denial") == "cloudshell_api_disabled":
        log(
            "[gcp.identity] OAuth token is valid, but cloudshell.googleapis.com "
            "is disabled for the effective consumer project. Enable the Cloud "
            "Shell API with an authorized project administrator, wait for "
            "propagation, then retry."
        )
    mark_credential_verified(record, state.credentials_by_id)
    return True


def _verify_azure_oauth_credential(record, state: InteractiveState) -> bool:
    """Verify a file-backed Azure OAuth credential without creating resources."""
    from cloudbasher.csp.azure.credentials import (
        bind_refresh_token_rotation,
        load_credentials_from_record_extra,
    )
    from cloudbasher.csp.azure.provider import AzureProvider

    extra = record.raw.extra or {}
    try:
        credentials = load_credentials_from_record_extra(extra, headless=True)
        bind_refresh_token_rotation(credentials, extra)
        if credentials.email and not extra.get("username"):
            extra["username"] = credentials.email

        if extra.get("access_token") and not extra.get("refresh_token"):
            args = getattr(state, "args", None)
            api = AzureProvider().create_api_client(
                credentials,
                timeout=getattr(args, "http_timeout", 30),
                proxy_url=getattr(args, "proxy", None),
                proxy_insecure=getattr(args, "proxy_insecure", False),
            )
            api.list_subscriptions()
    except Exception as exc:
        from cloudbasher.csp.azure.credentials import mark_credential_rejected

        mark_credential_rejected(record, state.credentials_by_id, exc)
        raise


    from cloudbasher.core.identity_listing import mark_credential_verified

    mark_credential_verified(record, state.credentials_by_id)
    return True


class BootstrapError(Exception):
    """CSP bootstrap failed; propagates to main() as a fatal error."""


class TUIMode(InteractiveMode):
    """TUI-based interactive mode with split-pane layout."""

    def run(
        self,
        state: InteractiveState,
        bootstrap_callback: Optional[Callable[[], None]] = None,
        multi_node: bool = False,
    ) -> Optional[str]:
        try:


            try:
                import textual  # noqa: F401
            except ImportError:


                eprint(
                    "Error: textual is not installed, and it is required -- "
                    "this release has no readline fallback (`#407`). "
                    "Install it with: pip install cloudbasher[all]"
                )
                return "readline"

            tui_app = TUIApplication(state)

            def _resolve_and_push_identity() -> None:
                """Push the initial status-bar context. Makes NO cloud call."""
                try:
                    csp = state.csp_provider
                    creds = getattr(state, "credentials", None)
                    identity = ""
                    scope = ""
                    region = ""

                    if csp.name == "aws":


                        region = str((getattr(creds, "extra", None) or {}).get("region") or "")
                    elif csp.name == "gcp":
                        identity, scope = _resolve_gcp_identity(creds)

                    ctx = ShellContextInfo(identity=identity, scope=scope, region=region)


                    textual_app = getattr(tui_app, "_textual_app", None)
                    if textual_app is not None:
                        textual_app.call_from_thread(setattr, textual_app, "context_info", ctx)
                except Exception:
                    pass

            def _resolve_identity_for_credential(credential_id: str) -> None:
                """Resolve ONE credential's real IAM identity, on demand."""
                try:
                    from cloudbasher.core.node_ids import originating_root_record

                    records = getattr(state, "credentials_by_id", None) or {}


                    rec = originating_root_record(credential_id, records)
                    if rec is None:
                        return
                    extra = rec.raw.extra or {}
                    if rec.provider == "aws":
                        if getattr(rec, "_resolved_identity_arn", None):
                            return
                        if not extra.get("access_key"):
                            return
                    elif rec.provider == "azure":


                        if getattr(rec, "_credential_verified", False):
                            return
                        if not (extra.get("refresh_token") or extra.get("access_token")):
                            return
                    elif rec.provider == "gcp":
                        data = extra.get("data") if isinstance(extra.get("data"), dict) else {}
                        if getattr(rec, "_credential_verified", False) or rec.status == "invalid":
                            return
                        if not (
                            extra.get("access_token")
                            or extra.get("refresh_token")
                            or data.get("refresh_token")
                        ):
                            return
                    else:
                        return
                except Exception:
                    return

                def _work(rec=rec) -> None:
                    try:

                        if rec.provider == "azure":
                            if _verify_azure_oauth_credential(rec, state):
                                textual_app = getattr(tui_app, "_textual_app", None)
                                if textual_app is not None:
                                    textual_app.call_from_thread(
                                        textual_app.refresh_node_table
                                    )
                            return

                        if rec.provider == "gcp":
                            if _verify_gcp_oauth_credential(rec, state):
                                textual_app = getattr(tui_app, "_textual_app", None)
                                if textual_app is not None:
                                    textual_app.call_from_thread(
                                        textual_app.refresh_node_table
                                    )
                            return

                        def _rejected(error: str, rec=rec) -> None:
                            rec._identity_rejected = error

                        arn, account, _region = _resolve_aws_identity(
                            rec.raw,
                            **_proxy_kwargs(state),
                            label=rec.id,
                            on_rejected=_rejected,
                        )
                        if arn or account:


                            rec._identity_rejected = None
                        elif rec._identity_rejected is None:
                            return
                        if arn:
                            rec._resolved_identity_arn = arn
                        if account:
                            rec._resolved_account = account
                        textual_app = getattr(tui_app, "_textual_app", None)
                        if textual_app is not None:
                            textual_app.call_from_thread(textual_app.refresh_node_table)
                    except Exception:


                        if rec.provider in {"azure", "gcp"} and rec.status == "invalid":
                            textual_app = getattr(tui_app, "_textual_app", None)
                            if textual_app is not None:
                                textual_app.call_from_thread(
                                    textual_app.refresh_node_table
                                )

                threading.Thread(target=_work, daemon=True).start()

            state.resolve_credential_identity = _resolve_identity_for_credential

            def _resolve_every_loaded_identity() -> None:
                """Resolve AWS identity labels and verify Azure/GCP OAuth credentials."""
                for rec in list((getattr(state, "credentials_by_id", None) or {}).values()):
                    if rec.role == "originating":
                        _resolve_identity_for_credential(rec.id)

            state.resolve_all_credential_identities = _resolve_every_loaded_identity

            def _request_table_refresh() -> None:
                """Ask the Nodes pane to repaint. NO ARGUMENT, and that is the point -- `#504`."""
                try:
                    textual_app = getattr(tui_app, "_textual_app", None)
                    if textual_app is not None:
                        textual_app.schedule_node_table_refresh()
                except Exception:
                    pass

            def _on_node_change(node) -> None:
                """Re-render the Nodes table as a secondary/fanout node's status transitions (Pending -> Connecting -> Running/ Failed) mid-bootstrap, not just once the whole thing is done. Called synchronously from within bootstrap_callback() (still on the pre-"ready" background thread), potentially by many concurrent worker threads at once during a large fan-out -- schedule_node_table_refresh() coalesces bursts into a single App-thread round trip instead of every caller blocking on its own call_from_thread(refresh_node_table)."""
                _request_table_refresh()

            def _startup_callback() -> None:
                """Run optional bootstrap; identity resolution happens off-thread."""
                if multi_node:
                    state.on_node_change = _on_node_change


                    state.request_table_refresh = _request_table_refresh
                if bootstrap_callback is not None:
                    bootstrap_callback()
                threading.Thread(target=_resolve_and_push_identity, daemon=True).start()


                if multi_node:
                    _resolve_every_loaded_identity()

            return tui_app.run(startup_callback=_startup_callback, multi_node=multi_node)

        except BootstrapError:
            raise
        except CloudShellAutomationError as exc:
            eprint(f"error: {exc}")
            return "readline"
        except Exception as exc:
            eprint(f"TUI mode error: {exc}")
            return "readline"


def _proxy_kwargs(state: InteractiveState) -> dict:
    """``--proxy``/``--proxy-insecure`` as kwargs for the STS identity call."""
    args = getattr(state, "args", None)
    return {
        "proxy_url": getattr(args, "proxy", None),
        "proxy_insecure": bool(getattr(args, "proxy_insecure", False)),
    }


def _resolve_aws_identity(
    creds,
    *,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    label: str = "",
    on_rejected: Optional[Callable[[str], None]] = None,
) -> tuple[str, str, str]:
    """Return (identity_arn, account_id, region) from AWS credentials."""
    if creds is None:
        return "", "", ""
    try:
        extra = creds.extra if hasattr(creds, "extra") else {}
        access_key = extra.get("access_key", "")
        secret_key = extra.get("secret_key", "")
        if not (access_key and secret_key):
            return "", "", ""
        from cloudbasher.csp.aws.credentials import signing_creds_from_extra
        from cloudbasher.csp.aws.signing import get_caller_identity


        aws_creds = signing_creds_from_extra(extra)


        result: dict = {}
        for attempt in range(3):
            result = get_caller_identity(
                aws_creds, timeout=10, proxy_url=proxy_url, proxy_insecure=proxy_insecure
            )
            if result["ok"] or not result.get("transient"):
                break
            if attempt < 2:
                detail(
                    f"identity label: STS unreachable ({result.get('error')})"
                    f"{f' for {label}' if label else ''}, "
                    f"retrying ({attempt + 2}/3)"
                )
                time.sleep(1.0 + attempt)
        if result["ok"]:
            region = extra.get("region", "")
            return result["arn"], result["account"], region
        error = result.get("error") or "unknown error"
        who = f" for {label}" if label else ""


        if result.get("transient") is not False:


            detail(
                f"identity label unresolved{who} (STS GetCallerIdentity: "
                f"{error}). This only populates the Identity column; the "
                "session and its credentials are unaffected. GetCallerIdentity "
                "uses the GLOBAL endpoint sts.amazonaws.com, unlike the "
                "regional CloudShell calls and unlike the AWS CLI v2 default, "
                "so it can fail alone where they succeed. Behind a proxy, pass "
                "--proxy."
            )
        else:


            if on_rejected is not None:
                try:
                    on_rejected(error)
                except Exception:
                    pass
            log(
                f"credential REJECTED by STS GetCallerIdentity{who}: {error}. "
                "That call needs no IAM permission, so this is the credential "
                "being refused rather than a missing grant -- expect the same "
                "refusal from anything else using it. Nothing was disconnected "
                "on the strength of one global-endpoint call; the Identity "
                "column stays blank."
            )
    except Exception:
        pass
    return "", "", ""


def _resolve_gcp_identity(creds) -> tuple[str, str]:
    """Return (identity_email, org) from GCP credentials."""
    if creds is None:
        return "", ""
    try:
        email = ""
        if hasattr(creds, "extra"):
            email = creds.extra.get("service_account_email", "")
        if not email:

            import os

            email = os.environ.get("CLOUDSDK_CORE_ACCOUNT", "")
        return email, ""
    except Exception:
        return "", ""
