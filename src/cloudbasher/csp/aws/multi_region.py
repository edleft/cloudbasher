"""AWS multi-region execution support."""

from __future__ import annotations

import concurrent.futures
import difflib
import fnmatch
import time
from typing import TYPE_CHECKING, Any, Callable, Optional

from cloudbasher.core.cancel import in_flight, report_cancellation, skip_if_cancelled
from cloudbasher.core.node_ids import originating_root_record
from cloudbasher.core.types import CONTROL_PLANE_UNASKED
from cloudbasher.core.utils.output import detail, eprint, log, log_scope, out
from cloudbasher.core.utils.perf_config import (
    get_env_start_expected_seconds,
    pool_width,
    status_poll_wait,
)
from cloudbasher.core.utils.timeline import mark as timeline_mark
from cloudbasher.core.utils.timeline import record_span
from cloudbasher.csp.aws.keepalive import attach_to_node, start_all_keepalives

if TYPE_CHECKING:
    from cloudbasher.core.types import Credentials, NodeRecord


    from cloudbasher.csp.aws.control_plane import ConsoleSourcePool
    from cloudbasher.csp.base import CSPProvider


class _EnvironmentStateError(RuntimeError):
    """Environment reached ERROR/DELETED while bootstrap_node_for_region() was waiting for RUNNING."""

    def __init__(self, status: str) -> None:
        super().__init__(f"environment in state {status}")


        self.status = status


class _EnvironmentWaitTimeout(TimeoutError):
    """Environment never reached RUNNING within env_wait_timeout."""


class _BrowserOnlyCredentialError(RuntimeError):
    """A console/SSO credential reached the REST path, which cannot sign for it."""

    def __init__(self, shape: str, region: str) -> None:
        super().__init__(
            f"{shape} credentials cannot use the REST path (region {region}): "
            "describeEnvironments/getEnvironmentStatus/start_environment all "
            "return 403 for a credential whose only proof of identity is a "
            "browser session. Path B drives the lifecycle through the browser "
            "instead -- use the TUI (.provision/.connect), not the -c fan-out."
        )


        self.shape = shape


_ALL_REGIONS = [
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ca-central-1",
    "eu-central-1",
    "eu-north-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
]


def resolve_regions(selector: str, api_client: Optional[Any] = None) -> list[str]:
    """Resolve a region selector to a list of concrete region strings."""
    selector = selector.strip()

    if selector.upper() == "ALL":
        return list(_ALL_REGIONS)

    if "," in selector:


        seen: dict[str, bool] = {}
        resolved: list[str] = []
        for part in (p.strip() for p in selector.split(",")):
            if not part:
                continue
            for region in resolve_regions(part, api_client):
                if region not in seen:
                    seen[region] = True
                    resolved.append(region)
        return resolved

    if "*" in selector or "?" in selector or "[" in selector:
        return [r for r in _ALL_REGIONS if fnmatch.fnmatch(r, selector)]


    if selector not in _ALL_REGIONS:
        near = difflib.get_close_matches(selector, _ALL_REGIONS, n=3, cutoff=0.6)
        suggestion = f" Did you mean {' or '.join(near)}?" if near else ""
        raise ValueError(
            f"{selector!r} is not a known AWS region.{suggestion} "
            f"Use a literal region, a glob (`ap-*`), a comma-list, or ALL."
        )
    return [selector]


def _wait_for_running(
    api: Any,
    env_id: str,
    env_wait_timeout: int,
    emit: Optional[Callable[[str], None]] = None,
) -> None:
    """Poll an environment's status until RUNNING, starting it if it's SUSPENDED/STOPPED. Shared by bootstrap_node_for_region() (a just-created/just-found environment), reconnect_node_session() (a previously-provisioned environment that's since auto-suspended from CloudShell's own idle timeout -- confirmed via manual verification: a region-fanned node had already gone SUSPENDED by the time a later .bulk reconnect was attempted, well within the same session), and cli/main.py's single-node bootstrap."""
    wait_start = time.time()
    start_attempted = False


    with status_poll_wait() as schedule_for:
        expected = 0.0
        schedule = schedule_for(expected)


        polls = 0
        started_at: Optional[float] = None
        prev_poll: Optional[float] = None
        while True:


            now = time.time()
            if now - wait_start >= env_wait_timeout:
                break
            status_resp = api.get_environment_status(env_id)
            status = status_resp.get("status", "")
            polls += 1
            elapsed = (now - started_at) if started_at else 0.0
            timeline_mark(
                "env.status",
                loop="wait_for_running",
                status=status,
                polls=polls,
                since_anchor_s=round(elapsed, 3) if started_at else None,
                phase=schedule.phase_at(elapsed) if started_at else "unanchored",
                region=getattr(api, "region", ""),
            )
            if status == "RUNNING":


                if started_at is not None:
                    record_span(
                        "env.start_to_running",
                        (now - started_at) * 1000,
                        polls=polls,


                        lower_bound_s=(
                            round(max(0.0, prev_poll - started_at), 3) if prev_poll else 0.0
                        ),
                        region=getattr(api, "region", ""),
                    )
                if emit:
                    emit("Environment is RUNNING")
                return
            if status in ("SUSPENDED", "STOPPED") and not start_attempted:
                if emit:
                    emit(f"Environment is {status}, starting...")
                api.start_environment(env_id)
                start_attempted = True
                started_at = time.time()


                expected = get_env_start_expected_seconds()
                schedule = schedule_for(expected)
            elif status in ("ERROR", "DELETED"):
                raise _EnvironmentStateError(status)
            elif emit:
                emit(f"Environment status: {status} (waiting...)")
            prev_poll = now


            schedule = schedule_for(expected)
            time.sleep(schedule.delay_after((time.time() - started_at) if started_at else 0.0))
    raise _EnvironmentWaitTimeout(f"environment not RUNNING after {env_wait_timeout}s")


def _try_wait_for_running(api: Any, env_id: str, env_wait_timeout: int = 60) -> Optional[bool]:
    """_wait_for_running(), but a failure degrades the node instead of denying it."""
    if api is None:
        detail(f"[reconnect] no control-plane client; cannot restore {env_id} to RUNNING")
        return None
    try:
        _wait_for_running(api, env_id, env_wait_timeout)
        return True
    except Exception as exc:
        log(f"[reconnect] could not restore {env_id} to RUNNING: {exc}")
        eprint(
            f"WARNING: environment {env_id} is not RUNNING ({exc}).\n"
            "  The shell may open over the browser DOM, but a real WebSocket "
            "session cannot be created until it is."
        )
        return False


def bootstrap_node_for_region(
    provider: "CSPProvider",
    credentials: "Credentials",
    region: str,
    env_wait_timeout: int = 60,
    http_timeout: int = 30,
    ws_timeout: int = 60,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> tuple[Any, Any, str]:
    """Bootstrap one region's CloudShell environment + session (no command run)."""
    from cloudbasher.csp.aws.api import session_kwargs_from_stream_info


    from cloudbasher.csp.aws.commands import browser_credential_shape

    _browser = browser_credential_shape(getattr(credentials, "extra", None) or {})
    if _browser is not None:
        raise _BrowserOnlyCredentialError(type(_browser).__name__, region)

    api = provider.create_api_client(
        credentials,
        region=region,
        timeout=http_timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )

    env_list = api.describe_environments()
    envs = env_list.get("environments", [])
    if envs:
        from cloudbasher.csp.aws.api import select_environment


        env_id = (select_environment(envs) or {}).get("EnvironmentId")
    else:
        resp = api.create_environment()
        env_id = resp.get("environment_id")

    _wait_for_running(api, env_id, env_wait_timeout)

    session_resp = api.open_stream(env_id)

    session = provider.create_session(
        credentials,
        env_id,


        **session_kwargs_from_stream_info(session_resp),
        timeout=ws_timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    return api, session, env_id


def run_command_for_region(
    provider: "CSPProvider",
    credentials: "Credentials",
    region: str,
    command: str,
    env_wait_timeout: int = 60,
    http_timeout: int = 30,
    ws_timeout: int = 60,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> tuple[str, str, int]:
    """Bootstrap a session in one region, run one command, return results."""
    try:
        _, session, _ = bootstrap_node_for_region(
            provider,
            credentials,
            region,
            env_wait_timeout=env_wait_timeout,
            http_timeout=http_timeout,
            ws_timeout=ws_timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        )
    except _EnvironmentStateError as e:
        return (region, f"[ERROR] {e}", 1)
    except _EnvironmentWaitTimeout as e:
        return (region, f"[TIMEOUT] {e}", 1)
    except Exception as e:
        return (region, f"[ERROR] {e}", 1)

    try:
        output = session.exec_command(command, timeout=ws_timeout)
        return (region, output or "", 0)
    finally:
        try:
            session.close()
        except Exception:
            pass


def provision_nodes_for_regions(
    state: Any,
    credential_id: str,
    credentials: "Credentials",
    provider: "CSPProvider",
    regions: list[str],
    on_node_change: Any = None,
) -> "list[NodeRecord]":
    """Promote AWS's 1:N region fan-out into persisted, CONNECTED NodeRecords."""
    from cloudbasher.cli.main import (
        _apply_bootstrap_result,
        _bootstrap_aws_session,
        _publish_bootstrapped_node,
    )
    from cloudbasher.core.types import NodeRecord, record_env_id_for

    emit_change = on_node_change or (lambda _n: None)
    args_ns = getattr(state, "args", None)


    pending_by_id: dict[str, NodeRecord] = {}
    fan_labels: dict[str, str] = {}
    for region in regions:
        node_id = f"{credential_id}:{region}"
        node = NodeRecord(
            id=node_id,
            credential_id=credential_id,
            region=region,
            environment_id=None,
            session=None,
            container_status="Pending",
        )
        state.register_node(node)
        emit_change(node)
        node.begin_connect("provision region ALL")
        emit_change(node)
        pending_by_id[node_id] = node
        fan_labels[node_id] = region

    def _connect_one(node_id: str, _ctx: Any) -> tuple[bool, list[str]]:
        """ON the shared primitive, which now owns everything this used to hand-roll: the pool and its bound, ``skip_if_cancelled()`` INSIDE the task, ``in_flight()``, exception isolation, ``was_cancelled``, the per-node repaint -- and the admission gate, which is the reason this migration stopped being cosmetic. Without it, ``.provision`` was the one command a dead resolver could still drain at failure speed."""
        node = pending_by_id[node_id]
        region = node.region or ""


        def _emit(msg: str) -> None:
            log(f"[multi_region] {msg}")

        with log_scope(region):
            result = _bootstrap_aws_session(
                args=args_ns,
                provider=provider,
                credentials=credentials,
                env_id=None,
                region=region,
                emit=_emit,


                credential_record=state.credentials_by_id.get(credential_id),
                credential_registry=state.credentials_by_id,


                on_environment_known=record_env_id_for(node),
            )
            if result.session_obj is not None:


                from cloudbasher.core.identity_listing import mark_credential_verified

                credential_record = state.credentials_by_id.get(credential_id)
                if credential_record is not None:
                    mark_credential_verified(credential_record, state.credentials_by_id)


            _apply_bootstrap_result(node, result, region=region, emit=_emit)


        bootstrapped[node.id] = result
        return True, []

    nodes: list[NodeRecord] = []


    from cloudbasher.core.cli.dispatcher import fan_out_over_nodes as _fan_out

    bootstrapped: dict[str, Any] = {}

    def _note_failure(node: NodeRecord, exc: BaseException) -> None:
        """The THIRD of five sites. The raw exception keeps its own line so the classifier LEADS the evidence rather than replacing it -- the log is an audit trail, and a classifier can be wrong."""
        from cloudbasher.csp.aws.failure import note_node_failure

        _label, _why = note_node_failure(node, exc, emit_change)
        log(f"[multi_region] provision failed region={node.region}: {_why}")
        log(f"[multi_region]   raw: {exc}")

    def _finish_one(node_id: str) -> None:
        """Everything a provisioned node still needs, on the COLLECTING thread."""
        node = pending_by_id[node_id]
        region = node.region or ""
        result = bootstrapped[node_id]


        try:
            _swapped = _console_control_plane_client(state, node, http_timeout=30)
            node._runtime_api_client = (
                tag_client_kind(_swapped, "console") if _swapped is not None else result.api_client
            )
        except Exception as exc:
            log(f"[multi_region] console control-plane client unavailable: {exc}")
            node._runtime_api_client = result.api_client


        _publish_bootstrapped_node(node, result)


        emit_change(node)
        nodes.append(node)
        log(f"[multi_region] provisioned region={region} node_id={node.id}")


    try:


        outcome = _fan_out(
            "provision",
            pending_by_id,
            fan_labels,
            _connect_one,
            state,
            refresh=False,
            on_failure=_note_failure,
            on_success=_finish_one,
        )


        for node_id in outcome.cancelled:
            eprint(f"provision: {fan_labels[node_id]}: skipped -- cancelled")
            log(f"[multi_region] skipped -- cancelled: region={fan_labels[node_id]}")
    finally:


        for _claimed in pending_by_id.values():
            if _claimed.end_connect():
                emit_change(_claimed)


    report_cancellation(out)
    return nodes


def run_command_all_regions(
    provider: "CSPProvider",
    credentials: "Credentials",
    regions: list[str],
    command: str,
    max_workers: Optional[int] = None,
    **kwargs: Any,
) -> list[tuple[str, str, int]]:
    """Fan out command execution across multiple regions in parallel."""


    workers = pool_width(len(regions), max_workers)
    log(f"[multi_region] command={command!r} regions={regions} workers={workers}")
    results: list[tuple[str, str, int]] = []

    def _run_one(region: str) -> tuple[str, str, int]:


        if skip_if_cancelled():
            return region, "skipped -- cancelled", 130
        with in_flight():
            return run_command_for_region(provider, credentials, region, command, **kwargs)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_region = {executor.submit(_run_one, region): region for region in regions}
        for future in concurrent.futures.as_completed(future_to_region):
            result = future.result()
            results.append(result)
            region, output, rc = result
            status = "OK" if rc == 0 else "ERR"
            log(f"[multi_region] region={region} status={status}")

    results.sort(key=lambda x: x[0])
    return results


def _derive_node_credentials_and_api_client(
    state: Any,
    node: "NodeRecord",
    *,
    http_timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> tuple[Any, Any]:
    """Shared prefix of reconnect_node_api_client()/reconnect_node_session(): resolve the node's identity via resolve_credential_chain() (re-derives via STS if the cached target-identity creds have expired) and build a fresh API client for it. Returns (credentials, api_client) -- the full session path needs `credentials` again for create_session(); the control-plane-only path only needs the api client."""


    def _permanent(message: str) -> RuntimeError:
        exc = RuntimeError(message)


        exc.cb_failure_class = "not_provisioned"  # type: ignore[attr-defined]
        return exc

    credential_record = state.credentials_by_id.get(node.credential_id)
    if credential_record is None:
        raise _permanent(f"no credential record for {node.credential_id!r}")
    if not node.environment_id:
        raise _permanent(
            f"node {node.id!r} has no recorded environment_id -- it was never "
            "provisioned. Provision it, or delete the row."
        )
    if not node.region:
        raise _permanent(f"node {node.id!r} has no recorded region")

    return signing_client_for_record(
        state,
        credential_record,
        node.region,
        http_timeout=http_timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )


def signing_client_for_record(
    state: Any,
    credential_record: Any,
    region: str,
    *,
    http_timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    artifact_capture: Any = None,
) -> tuple[Any, Any]:
    """Track A: build a SigV4-signing API client from a key-bearing record."""
    from cloudbasher.core.types import Credentials, carry_aws_identity_keys
    from cloudbasher.csp.aws.credentials import resolve_credential_chain
    from cloudbasher.csp.aws.provider import AWSProvider

    live_creds = resolve_credential_chain(
        credential_record,
        state.credentials_by_id,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )


    extra = live_creds.to_cache_dict()
    carry_aws_identity_keys(credential_record.raw.extra, extra)
    credentials = Credentials(provider="aws", extra=extra)
    provider = AWSProvider()
    api = provider.create_api_client(
        credentials,
        region=region,
        timeout=http_timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,


        credential_record=credential_record,
        credential_registry=state.credentials_by_id,


        artifact_capture=artifact_capture,
    )
    return credentials, api


def resolve_sso_if_needed(state: Any, rec: Any, *, verb: str) -> Optional[str]:
    """Turn an unresolved SSO record into an ASIA triple, once. Error or None."""
    from cloudbasher.csp.aws.commands import _browser_creds_for, _resolve_sso_record
    from cloudbasher.csp.aws.credentials import AwsSSOCreds

    extra = getattr(getattr(rec, "raw", None), "extra", None) or {}
    if extra.get("access_key"):
        return None
    browser_creds = _browser_creds_for(extra)
    if not isinstance(browser_creds, AwsSSOCreds):
        return None
    return _resolve_sso_record(state, rec, browser_creds, verb=verb)


def _live_node_client_for(state: Any, rec: Any, region: str) -> Optional[Any]:
    """A live API client already held by a node of `rec` in `region`."""
    from cloudbasher.csp.aws.provision_request import node_is_live

    nodes = getattr(state, "nodes_by_id", None)
    if not nodes:
        return None
    for node in nodes.values():
        if node.credential_id != rec.id or node.region != region:
            continue


        client = getattr(node, "_runtime_api_client", None)
        if client is None or not node_is_live(node):
            continue
        try:
            setattr(client, BORROWED_CLIENT_ATTR, True)
        except (AttributeError, TypeError):


            continue
        return client
    return None


def resolve_credential_client(
    state: Any,
    rec: Any,
    region: str,
    *,
    verb: str = "command",
    http_timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
    headless: bool = True,
    ui_wait_timeout: int = 60,
    artifact_capture: Any = None,
    console_sources: "Optional[ConsoleSourcePool]" = None,
) -> tuple[Optional[Any], Optional[str]]:
    """A CloudShell API client for a CREDENTIAL, before any node exists."""
    from cloudbasher.csp.aws.commands import _browser_creds_for
    from cloudbasher.csp.aws.credentials import AwsConsoleCreds, AwsSSOCreds

    extra = rec.raw.extra


    borrowed = _live_node_client_for(state, rec, region)
    if borrowed is not None:
        return borrowed, None


    if not extra.get("access_key"):
        browser_creds = _browser_creds_for(extra)


        if isinstance(browser_creds, AwsSSOCreds):
            sso_error = resolve_sso_if_needed(state, rec, verb=verb)
            if sso_error is not None:
                return None, sso_error

        elif isinstance(browser_creds, AwsConsoleCreds):
            return _console_credential_client(
                rec,
                browser_creds,
                region,
                verb=verb,
                http_timeout=http_timeout,
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
                headless=headless,
                ui_wait_timeout=ui_wait_timeout,
                sources=console_sources,
            )

        else:


            return None, (
                f"{verb}: credential [{rec.label}] has no access key and no "
                "console/SSO login to obtain one with -- nothing can be signed "
                "with it."
            )

    try:
        _creds, api = signing_client_for_record(
            state,
            rec,
            region,
            http_timeout=http_timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
            artifact_capture=artifact_capture,
        )
    except Exception as exc:


        return None, f"{verb}: {rec.label}: {exc}"
    return api, None


BROWSER_HANDLES_ATTR = "_cb_browser_handles"


BORROWED_CLIENT_ATTR = "_cb_borrowed"


CONTROL_PLANE_SOURCE_ATTR = "_cb_control_plane_source"


CLIENT_KIND_ATTR = "_cb_client_kind"


def tag_client_kind(client: Any, kind: str) -> Any:
    """Record what `client` was built to sign for, and return it."""
    try:
        setattr(client, CLIENT_KIND_ATTR, kind)
    except (AttributeError, TypeError):
        pass
    return client


def node_client_is_usable(state: Any, node: Any, client: Any) -> bool:
    """Can this CACHED client actually sign for this node?"""
    if client is None:
        return False
    from cloudbasher.csp.aws.commands import _browser_creds_for
    from cloudbasher.csp.aws.credentials import AwsConsoleCreds


    root = originating_root_record(node.credential_id, getattr(state, "credentials_by_id", {}))
    if root is None:
        return True
    if not isinstance(_browser_creds_for(root.raw.extra), AwsConsoleCreds):
        return True

    return getattr(client, CLIENT_KIND_ATTR, "") == "console"


def _console_credential_client(
    rec: Any,
    console_creds: Any,
    region: str,
    *,
    verb: str,
    http_timeout: int,
    proxy_url: Optional[str],
    proxy_insecure: bool,
    headless: bool,
    ui_wait_timeout: int,
    sources: Optional[dict] = None,
) -> tuple[Optional[Any], Optional[str]]:
    """Track B: perform the console login and return its presign-backed client."""
    from cloudbasher.core.browser_options import BrowserOptions
    from cloudbasher.csp.aws.control_plane import ControlPlaneUnavailable, _ConsoleSource

    key = str(getattr(rec, "id", "") or id(rec))
    shared = sources is not None

    def _build() -> Any:


        out(f"[{verb}] {rec.label}: signing in through the browser ({region})...")


        return _ConsoleSource(
            console_creds,
            timeout=http_timeout,
            browser=BrowserOptions(
                headless=headless,
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
                ui_wait_timeout=ui_wait_timeout,
            ),
        )

    source = None
    try:
        if shared:
            client = sources.client_for(key, region, _build)
        else:
            source = _build()
            client = source.client_for(region)
    except ControlPlaneUnavailable as exc:
        if source is not None:
            source.close()
        return None, f"{verb}: console login failed for {rec.label} in {region}: {exc}"
    except Exception as exc:  # noqa: BLE001 - reported against the credential
        if source is not None:
            source.close()
        return None, f"{verb}: console client failed for {rec.label} in {region}: {exc}"


    attr, value = (BORROWED_CLIENT_ATTR, True) if shared else (CONTROL_PLANE_SOURCE_ATTR, source)
    try:
        setattr(client, attr, value)
    except (AttributeError, TypeError) as exc:
        if not shared:
            source.close()
        return None, (
            f"{verb}: cannot track the login browser for {rec.label} in {region} "
            f"({exc}) -- refusing rather than leaking it"
        )
    return client, None


def _close_browser_handles(handles: Any) -> None:
    """Close a parked browser. NEVER raises."""


    if not isinstance(handles, tuple) or len(handles) != 2:
        return
    browser, context = handles
    if browser is None and context is None:
        return
    try:
        from cloudbasher.csp.aws.browser import close_playwright_browser

        close_playwright_browser(browser=browser, context=context)
    except Exception as exc:
        detail(f"[console] could not close the login browser: {exc}")


def close_credential_client(client: Any) -> None:
    """Close whatever `resolve_credential_client` opened for this client."""
    if getattr(client, BORROWED_CLIENT_ATTR, False):

        return


    source = getattr(client, CONTROL_PLANE_SOURCE_ATTR, None)
    if source is not None:
        try:
            setattr(client, CONTROL_PLANE_SOURCE_ATTR, None)
        except (AttributeError, TypeError):
            pass
        try:
            source.close()
        except Exception as exc:  # noqa: BLE001 - a lost result is worse than a leak
            detail(f"[console] could not close the control-plane source: {exc}")
        return


def reconnect_node_api_client(
    state: Any,
    node: "NodeRecord",
    *,
    http_timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> Any:
    """Re-derive credentials and return a fresh API client for `node`, without opening a live shell session or starting a heartbeat."""


    console_api = _console_control_plane_client(state, node, http_timeout=http_timeout)
    if console_api is not None:
        node._runtime_api_client = tag_client_kind(console_api, "console")
        return console_api

    _, api = _derive_node_credentials_and_api_client(
        state,
        node,
        http_timeout=http_timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    return api


class ConsoleControlPlaneNotYetWired(RuntimeError):
    """A control-plane call was asked of a console node before the presign-backed signer exists."""


def _console_control_plane_client(state: Any, node: "NodeRecord", *, http_timeout: int) -> Any:
    """A console-signed control-plane client for this node, or None if it is not a console node."""
    from cloudbasher.csp.aws.console_api import ConsoleCloudShellAPI

    if _console_creds_for_node(state, node) is None:
        return None

    session = getattr(node, "_runtime_session", None)


    page = getattr(session, "_page", None) if session is not None else None
    if page is None:
        raise ConsoleControlPlaneNotYetWired(
            f"#{getattr(node, 'seq', '?')} {node.region}: this AWS Console node has no "
            "live Portal browser for its AWS CloudShell control-plane request.\n"
            "  Reconnect this AWS node with `.connect <node-selector>`, then "
            "retry the AWS lifecycle command.\n"
            "  `.unregister` only removes local tracking; it does not delete the "
            "AWS environment."
        )
    detail(
        f"[console-api] signing control-plane calls through the console session "
        f"region={node.region}"
    )
    return ConsoleCloudShellAPI(page, region=node.region, timeout=http_timeout)


def _console_creds_for_node(state: Any, node: "NodeRecord") -> Optional[Any]:
    """The console/SSO login for this node, or None if it has a signing key."""
    from cloudbasher.csp.aws.commands import _browser_creds_for

    record = state.credentials_by_id.get(node.credential_id)
    if record is None:
        return None
    extra = getattr(record.raw, "extra", None) or {}
    if extra.get("access_key"):


        return None
    return _browser_creds_for(extra)


_PARKED_SHELL_PROBE_SECONDS = 8


_PARKED_SHELL_RECOVER_SECONDS = 60


def _presign_projection_enabled() -> bool:
    """Is the fast console projection switched on? Default YES, since 2026-08-16."""
    from cloudbasher.csp.aws.console_bootstrap import presign_projection_enabled

    return presign_projection_enabled()


def _revive_parked_shell_on_owner_thread(
    page: Any,
    region: str,
    env_id: str = "",
    *,
    shell_is_dead: bool = False,
    have_session: bool = False,
) -> str:
    """Is there a live shell on this page -- and if not, can we get one back?"""
    from cloudbasher.csp.aws.cloudshell_terminal import (
        describe_terminal_state,
        wait_for_terminal_ready,
    )
    from cloudbasher.csp.aws.console_bootstrap import project_credentials_via_presign
    from cloudbasher.csp.aws.playwright_login import navigate_to_cloudshell


    page.title()


    if shell_is_dead:


        if not _presign_projection_enabled():
            detail(
                "[reconnect] presign projection is off "
                "(CLOUDBASHER_PRESIGN_PROJECTION=0); rebuilding the widget"
            )
        elif not have_session:


            detail(
                "[reconnect] no session to project into; rebuilding the widget, "
                "which creates one and projects in native's order"
            )
        elif env_id:
            try:
                project_credentials_via_presign(page, region=region, env_id=env_id)
                return "projected"
            except Exception as exc:
                log(
                    f"[reconnect] presign projection failed ({exc}); falling back "
                    f"to the widget rebuild"
                )
        else:
            detail("[reconnect] no environment id; cannot project via presign")
        detail(
            "[reconnect] the parked page's shell died when its environment was "
            "suspended; reopening CloudShell in it without probing"
        )
    elif wait_for_terminal_ready(page, timeout=_PARKED_SHELL_PROBE_SECONDS, region=region):
        return "rebuilt"
    else:
        detail(
            f"[reconnect] the parked page has no shell — "
            f"{describe_terminal_state(page)}; reopening CloudShell in it"
        )
    return (
        "rebuilt"
        if navigate_to_cloudshell(
            page, region=region, ui_wait_timeout=_PARKED_SHELL_RECOVER_SECONDS
        )
        else ""
    )


def _credential_invalidator(state: Any) -> Optional[Callable[[Any], None]]:
    """The hook a heartbeat calls when it proves its credential dead. Bound to `InteractiveState.invalidate_credential`, which owns both registries and is therefore the only thing able to reach the failed credential's nodes."""
    invalidate = getattr(state, "invalidate_credential", None)
    if invalidate is None:
        return None

    def _hook(failed_node: Any) -> None:
        invalidate(
            failed_node.credential_id,
            detected_on=failed_node,
            reason="heartbeat could not authenticate this credential",
        )

    return _hook


def _reuse_parked_browser(state: Any, node: "NodeRecord") -> Any:
    """A session rebuilt on a browser `.stop`/`.disconnect` parked, or None."""
    from cloudbasher.csp.aws.browser import await_presign_for_region
    from cloudbasher.csp.aws.playwright_owner import run_owned

    handles = getattr(node, "_runtime_parked_browser", None)
    if not handles:
        return None
    page = handles.get("page")
    owned = (page, handles.get("browser"), handles.get("context"))

    def _give_up(why: str) -> None:
        """Drop the handles AND close what they point at, then let the caller sign in again."""
        node._runtime_parked_browser = None
        detail(f"[reconnect] parked browser for {node.region} {why}")
        try:
            from cloudbasher.csp.aws.browser import close_playwright_browser

            close_playwright_browser(handles.get("browser"), handles.get("context"), page)
        except Exception as exc:
            detail(f"[reconnect] could not close the unusable parked browser: {exc}")

    from cloudbasher.core.types import Credentials
    from cloudbasher.csp.aws.console_api import ConsoleCloudShellAPI
    from cloudbasher.csp.aws.console_bootstrap import console_reprojector_for
    from cloudbasher.csp.aws.provider import AWSProvider


    out(f"[reconnect] #{getattr(node, 'seq', '?')} {node.region} reuses the parked browser")
    session = AWSProvider().create_session(
        Credentials(provider="aws", extra={}),
        node.environment_id or "",
        stream_url="",
        token_value="",
    )
    session.set_playwright_page(page)
    session.set_playwright_handles(browser=handles.get("browser"), context=handles.get("context"))
    node._runtime_api_client = tag_client_kind(
        ConsoleCloudShellAPI(page, region=node.region), "console"
    )


    env_running = _try_wait_for_running(node._runtime_api_client, node.environment_id or "")


    got_socket = _try_console_websocket(
        session, node._runtime_api_client, node.environment_id or "", env_running
    )


    revived = ""
    if getattr(node, "_runtime_parked_shell_is_dead", False):
        if env_running is False:
            _give_up("environment is not RUNNING; credentials cannot be projected")
            return None
        try:
            revived = run_owned(
                owned,
                _revive_parked_shell_on_owner_thread,
                page,
                node.region or "",
                node.environment_id or "",
                shell_is_dead=True,
                have_session=got_socket,
            )
        except Exception as exc:
            _give_up(f"is not usable: {exc}")
            return None
        if not revived:
            _give_up("could not restore credentials after its environment stopped")
            return None


    if not got_socket and revived != "rebuilt":
        try:
            shell_is_live = run_owned(
                owned,
                _revive_parked_shell_on_owner_thread,
                page,
                node.region or "",
                node.environment_id or "",
                shell_is_dead=False,
            )
        except Exception as exc:
            _give_up(f"is not usable: {exc}")
            return None
        if not shell_is_live:


            _give_up("has no socket and no usable shell; signing in again")
            return None

    node._runtime_parked_browser = None
    node._runtime_parked_shell_is_dead = False


    try:
        _cp_identity = await_presign_for_region(page, node.region, wait_seconds=0)
    except Exception:  # noqa: BLE001
        _cp_identity = CONTROL_PLANE_UNASKED
    session.set_control_plane_identity(_cp_identity)


    node._runtime_session = session
    attach_to_node(
        node,
        start_all_keepalives(
            node._runtime_api_client,
            node.environment_id or "",
            session=session,
            node=node,
            on_node_change=getattr(state, "on_node_change", None),


            on_credential_invalid=_credential_invalidator(state),


            on_reproject=console_reprojector_for(
                lambda: getattr(node, "_runtime_api_client", None),
                region=node.region or "",
                env_id=node.environment_id or "",
            ),
        ),
    )
    return session


_CONSOLE_ERROR_PREFIXES = (
    "Unable to create the environment",
    "Unable to start the environment",
    "Failed to create the environment",
)


def _console_error_text(session: Any) -> str:
    """The console's own visible error, or "" if there is none to read."""
    page = getattr(session, "_page", None)
    if page is None:
        return ""
    try:
        from cloudbasher.csp.aws.cloudshell_terminal import terminal_contexts

        for ctx in terminal_contexts(page):
            for prefix in _CONSOLE_ERROR_PREFIXES:
                try:
                    node = ctx.get_by_text(prefix, exact=False).first
                    if node.is_visible(timeout=250):
                        return " ".join(str(node.inner_text()).split())[:400]
                except Exception:
                    continue
    except Exception:
        pass
    return ""


def _try_console_websocket(
    session: Any, api: Any, env_id: str, env_running: Optional[bool] = None
) -> bool:
    """Give a console session a REAL WebSocket if `/createSession` will yield one."""
    if api is None:
        return False
    if env_running is False:


        reason = _console_error_text(session)
        log(
            f"[console] skipping createSession for {env_id}: the environment is "
            f"not RUNNING, so a session cannot be created."
            + (f" The console reports: {reason}" if reason else "")
        )
        eprint(
            f"Environment {env_id} is not RUNNING, so no WebSocket session was "
            f"attempted.\n"
            + (
                f"  The AWS console reports: {reason}\n"
                if reason
                else "  The console gave no visible reason.\n"
            )
            + "  Commands will use the browser DOM path if the page has a shell."
        )
        session._websocket_dead = True
        return False
    opener = getattr(api, "open_stream", None)
    if not callable(opener):
        return False
    try:
        info = opener(env_id)
    except Exception as exc:
        log(f"[console] createSession refused ({exc}); commands will use the DOM path")
        session._websocket_dead = True
        return False


    session.adopt_stream_info(info)
    session.api_client = api
    session._websocket_dead = False
    out(f"[console] real WebSocket session obtained for {env_id}")
    return True


def _reconnect_console_node_via_browser(
    state: Any,
    node: "NodeRecord",
    console_creds: Any,
    *,
    ws_timeout: int = 60,
    http_timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> Any:
    """Re-open a console/SSO node's session by signing in again."""
    from cloudbasher.core.types import Credentials
    from cloudbasher.csp.aws.browser import bootstrap_via_console_login
    from cloudbasher.csp.aws.console_bootstrap import console_reprojector_for
    from cloudbasher.csp.aws.provider import AWSProvider

    if not node.region:
        raise RuntimeError(f"node {node.id!r} has no recorded region")


    parked = _reuse_parked_browser(state, node)
    if parked is not None:
        return parked

    out(f"[reconnect] #{getattr(node, 'seq', '?')} {node.region} signs in via the browser...")
    result = bootstrap_via_console_login(
        pw_creds=console_creds,
        region=node.region,
        env_id=node.environment_id or "",
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )

    env_id = result.get("environment_id") or node.environment_id
    if not env_id:
        raise RuntimeError(
            f"browser login for #{getattr(node, 'seq', '?')} {node.region} completed but no "
            "CloudShell environment id was captured"
        )
    node.environment_id = env_id

    record = state.credentials_by_id.get(node.credential_id)
    credentials = record.raw if record is not None else Credentials(provider="aws", extra={})

    provider = AWSProvider()
    session = provider.create_session(
        credentials,
        env_id,
        stream_url="",
        token_value="",
        timeout=ws_timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    session.set_playwright_page(result["page"])


    session.set_control_plane_identity(result.get("presign", CONTROL_PLANE_UNASKED))
    session.set_playwright_handles(browser=result["browser"], context=result["context"])


    try:
        from cloudbasher.csp.aws.console_api import ConsoleCloudShellAPI

        node._runtime_api_client = tag_client_kind(
            ConsoleCloudShellAPI(result["page"], region=node.region, timeout=http_timeout),
            "console",
        )
        detail(f"[reconnect] control-plane client rebound to the new page {node.region}")
    except Exception as exc:
        node._runtime_api_client = None
        detail(f"[reconnect] no console control-plane client for {node.region}: {exc}")


    env_running = _try_wait_for_running(node._runtime_api_client, env_id)


    _try_console_websocket(session, node._runtime_api_client, env_id, env_running)


    node._runtime_session = session
    attach_to_node(
        node,
        start_all_keepalives(
            node._runtime_api_client,
            env_id,
            session=session,
            node=node,
            on_node_change=getattr(state, "on_node_change", None),


            on_credential_invalid=_credential_invalidator(state),


            on_reproject=console_reprojector_for(
                lambda: getattr(node, "_runtime_api_client", None),
                region=node.region or "",
                env_id=env_id,
                timeout=http_timeout,
            ),
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        ),
    )


    presign = result.get("presign") or "?"
    detail(
        f"[reconnect] console node live in browser region={node.region} "
        f"env_id={env_id} presign={presign}"
    )
    return session


def _mark_credentials_not_projected(node: Any, state: Any) -> None:
    """Record that this node's container has no credentials. Never raises."""
    try:
        node._last_failure_class = "credentials_not_projected"
        on_change = getattr(state, "on_node_change", None)
        if callable(on_change):
            on_change(node)
    except Exception:  # noqa: BLE001 -- a label must not fail a bootstrap
        pass


def _retry_credential_projection(
    node: Any,
    api: Any,
    *,
    http_timeout: int,
    proxy_url: Optional[str],
    proxy_insecure: bool,
) -> bool:
    """One fresh projection attempt. True if it worked. Never raises."""
    from cloudbasher.csp.aws.console_bootstrap import begin_credential_projection

    try:
        begin_credential_projection(
            getattr(node, "_runtime_api_client", None) or api,
            region=node.region,
            env_id=node.environment_id,
            timeout=http_timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        ).finish()
        return True
    except Exception:  # noqa: BLE001 -- the caller reports; this only answers
        return False


def reconnect_node_session(
    state: Any,
    node: "NodeRecord",
    *,
    env_wait_timeout: int = 60,
    http_timeout: int = 30,
    ws_timeout: int = 60,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> Any:
    """Re-open a live session for a node whose session isn't currently held."""
    from cloudbasher.csp.aws.api import session_kwargs_from_stream_info

    console_creds = _console_creds_for_node(state, node)
    if console_creds is not None:
        return _reconnect_console_node_via_browser(
            state,
            node,
            console_creds,
            ws_timeout=ws_timeout,
            http_timeout=http_timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        )

    credentials, api = _derive_node_credentials_and_api_client(
        state,
        node,
        http_timeout=http_timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
    )
    node._runtime_api_client = api


    from cloudbasher.csp.aws.act_as import act_as_from_extra, skips_projection
    from cloudbasher.csp.aws.console_bootstrap import (
        begin_credential_projection,
        make_reprojector,
    )

    if skips_projection(act_as_from_extra(getattr(credentials, "extra", None) or {})):
        detail(
            f"[reconnect] ACT_AS=direct-unbound; no credential projection for "
            f"{node.region} -- in-shell `aws` will not work, by declaration"
        )
        pending = None
    else:
        pending = begin_credential_projection(
            api,
            region=node.region,
            env_id=node.environment_id,
            timeout=http_timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        )

    _wait_for_running(api, node.environment_id, env_wait_timeout)


    stream_info = api.open_stream(node.environment_id)

    try:
        if pending is not None:
            pending.finish()
            detail(f"[reconnect] credential projection complete region={node.region}")
    except Exception as proj_exc:


        retried = _retry_credential_projection(
            node,
            api,
            http_timeout=http_timeout,
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        )
        if retried:
            log(
                f"[reconnect] credential projection RECOVERED on retry "
                f"region={node.region} env_id={node.environment_id} "
                f"(first attempt: {proj_exc})"
            )
        else:
            eprint(
                f"WARNING: credential projection FAILED for #{getattr(node, 'seq', '?')} "
                f"{node.region}: {proj_exc}\n"
                "  Retried once and it failed again. The shell will open, but AWS CLI "
                "calls inside it will fail with a container-role 500 until the "
                "keepalive re-projects (up to 20 min), or you reconnect the node."
            )
            log(
                f"[reconnect] credential projection FAILED region={node.region} "
                f"env_id={node.environment_id}: {proj_exc} (retry also failed)"
            )


            _mark_credentials_not_projected(node, state)

    from cloudbasher.csp.aws.provider import AWSProvider

    provider = AWSProvider()
    session = provider.create_session(
        credentials,
        node.environment_id,

        **session_kwargs_from_stream_info(stream_info),
        timeout=ws_timeout,
        proxy_url=proxy_url,
        proxy_insecure=proxy_insecure,
        api_client=api,
    )


    node._runtime_session = session
    attach_to_node(
        node,
        start_all_keepalives(
            api,
            node.environment_id,
            session=session,
            node=node,
            on_node_change=getattr(state, "on_node_change", None),


            on_credential_invalid=_credential_invalidator(state),


            on_reproject=make_reprojector(
                pending,
                lambda: getattr(node, "_runtime_api_client", None) or api,
                region=node.region,
                env_id=node.environment_id,
                timeout=http_timeout,
                proxy_url=proxy_url,
                proxy_insecure=proxy_insecure,
            ),
            proxy_url=proxy_url,
            proxy_insecure=proxy_insecure,
        ),
    )
    return session
