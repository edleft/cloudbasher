#!/usr/bin/env python3
"""CloudBasher command-line interface."""

from __future__ import annotations

import argparse
import atexit
import os
import shlex
import sys
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

from cloudbasher import __version__
from cloudbasher.core.browser_options import browser_options
from cloudbasher.core.exceptions import (
    CloudBasherError,
    CloudShellAutomationError,
    CredentialError,
)

if TYPE_CHECKING:
    from cloudbasher.csp.aws.act_as import ActAs
    from cloudbasher.csp.aws.credentials import TargetIdentity
from cloudbasher.core.interactive.readline_mode import ReadlineMode
from cloudbasher.core.interactive.repl_shared import AVAILABLE_UI_MODES
from cloudbasher.core.interactive.tui_mode import BootstrapError, TUIMode
from cloudbasher.core.session import keepalive_policy
from cloudbasher.core.types import (
    CONTROL_PLANE_UNASKED,
    CredentialRecord,
    Credentials,
    InteractiveState,
    NodeRecord,
    SessionInfo,
    record_env_id_for,
)
from cloudbasher.core.utils.output import (
    begin_shutdown,
    close_output_logging,
    configure_output_logging,
    detail,
    eprint,
    log,
    out,
    out_ts,
    set_log_console_echo,
)
from cloudbasher.csp import AWSProvider, AzureProvider, GCPProvider

_STATE_BIN_AWS = "state_aws.bin"
_STATE_BIN_AZURE = "state_azure.bin"
_STATE_BIN_GCP = "state_gcp.bin"


class _ResumeAction(argparse.Action):
    """`-m [STATE_FILE]` — sets BOTH the optional filename and the boolean."""

    def __call__(self, parser, namespace, values, option_string=None) -> None:  # type: ignore[override]
        setattr(namespace, "resume", True)


        setattr(namespace, self.dest, values or None)


def _resolve_state_multi_bin(state_bin: str, multi_node: bool) -> str:
    """Return the node-registry state filename for this run."""
    if multi_node:
        return "state.bin"
    return state_bin.replace(".bin", "_multi.bin")


def _fmt_cred_summary(credentials) -> str:
    """One-line credential summary for --notui startup output."""
    extra = credentials.extra or {}
    if credentials.provider == "aws":
        access_key = extra.get("access_key", "")
        session_token = extra.get("session_token") or ""
        key_str = f"{access_key[:4]}..." if access_key else "unset"
        token_str = "set" if session_token else "unset"
        return f"access_key_id={key_str} session_token={token_str}"
    return f"access_token={'set' if credentials.access_token else 'unset'}"


_RELEASE = ".".join(__version__.split(".")[:2])

_EPILOG = """\
--------------------------------------------------------------------------
Exactly one credential source per run: -F, --creds-env, or -m. Nothing is
discovered ambiently -- not ~/.aws/credentials, not an instance role.

AWS, Azure, and GCP credential sources are detected from their contents and
can be used to start a session. GCP release acceptance remains in progress.

Interactive only. Start a session, then drive it with dot-commands: .provision,
.connect, .enum, .upload, .download, .bulk. `.help` lists them, `?` shows the same.

Examples:
  cloudbasher -F creds.rc                    # start the TUI
  cloudbasher --creds-env                    # one supported provider environment
  cloudbasher -m                             # resume a saved session
"""


def _parse_float_list(raw: str) -> list[float]:
    """Comma-separated floats, e.g. rc's ``"15,45"`` -> ``[15.0, 45.0]``. Malformed entries are dropped rather than raising -- rc-typo tolerance, same rationale as every setter in perf_config.py/redact.py."""
    values: list[float] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            values.append(float(part))
        except ValueError:
            continue
    return values


def _apply_performance_tuning_from_rc(rc: Any) -> None:
    """``[performance]`` section: thread-pool size and WebSocket connect retry/timeout knobs, all rc-configurable so multi-node fan-out speed can be tuned/A-B-tested without a code change (user-reported: 160-node --resume felt slow; see perf_config.py's module docstring for the full list of consumers and cloudbasher.rc.example for the documented keys). Every value defaults to this project's original hardcoded constant, so an unconfigured rc file changes nothing."""
    from ..core.utils import perf_config
    from ..csp.aws.session import AWSSession


    _knobs: tuple[tuple[str, Callable[[Any], None], Callable[[str], Any]], ...] = (
        ("ui.log_buffer_lines", perf_config.set_log_buffer_lines, int),
        ("performance.max_workers", perf_config.set_max_workers, int),
        (
            "performance.node_refresh_min_interval_seconds",
            perf_config.set_node_refresh_min_interval_seconds,
            float,
        ),
        (
            "performance.log_follow_repin_seconds",
            perf_config.set_log_follow_repin_seconds,
            float,
        ),
        (
            "performance.log_repeat_window_seconds",
            perf_config.set_log_repeat_window_seconds,
            float,
        ),
        (
            "performance.node_follow_frontier_rows",
            perf_config.set_node_follow_frontier_rows,
            int,
        ),
        (
            "performance.node_follow_repin_seconds",
            perf_config.set_node_follow_repin_seconds,
            float,
        ),
        (
            "performance.ws_handshake_timeout_seconds",
            perf_config.set_ws_handshake_timeout_seconds,
            float,
        ),
        ("performance.throttle_max_retries", perf_config.set_throttle_max_retries, int),
        (
            "performance.heartbeat_interval_seconds",
            perf_config.set_heartbeat_interval_seconds,
            int,
        ),
        (
            "performance.heartbeat_ws_ping_interval_seconds",
            perf_config.set_heartbeat_ws_ping_interval_seconds,
            int,
        ),
        (
            "performance.heartbeat_retry_interval_seconds",
            perf_config.set_heartbeat_retry_interval_seconds,
            int,
        ),
        (
            "performance.credential_reproject_interval_seconds",
            perf_config.set_credential_reproject_interval_seconds,
            int,
        ),
        ("performance.heartbeat_max_retries", perf_config.set_heartbeat_max_retries, int),


        (
            "performance.env_status_poll_interval_seconds",
            perf_config.set_env_status_poll_interval_seconds,
            float,
        ),
        (
            "performance.env_start_expected_seconds",
            perf_config.set_env_start_expected_seconds,
            float,
        ),
        (
            "performance.env_stop_expected_seconds",
            perf_config.set_env_stop_expected_seconds,
            float,
        ),
        (
            "performance.env_status_poll_dense_seconds",
            perf_config.set_env_status_poll_dense_seconds,
            float,
        ),
        (
            "performance.env_status_poll_quiet_fraction",
            perf_config.set_env_status_poll_quiet_fraction,
            float,
        ),
        (
            "performance.reset_retry_delay_seconds",
            perf_config.set_reset_retry_delay_seconds,
            float,
        ),
        (
            "performance.throttle_backoff_base_seconds",
            perf_config.set_throttle_backoff_base_seconds,
            float,
        ),
        (
            "performance.credential_refresh_fraction",
            perf_config.set_credential_refresh_fraction,
            float,
        ),


        (
            "performance.supervisor_poll_seconds",
            perf_config.set_supervisor_poll_seconds,
            float,
        ),
        (
            "performance.supervisor_max_recoveries",
            perf_config.set_supervisor_max_recoveries,
            int,
        ),
    )
    for _key, _setter, _coerce in _knobs:
        if _key in rc:
            try:
                _setter(_coerce(rc.get_string(_key)))
            except ValueError:
                pass


    perf_config.set_frame_trace(rc.get_bool("net.frame_trace", False))

    _probe_mode = (rc.get_string("performance.prompt_probe_mode") or "").strip().lower()
    if _probe_mode:
        if _probe_mode in perf_config.PROMPT_PROBE_MODES:
            perf_config.set_prompt_probe_mode(_probe_mode)
        else:
            eprint(
                f"cloudbasher: ignoring performance.prompt_probe_mode={_probe_mode!r} -- "
                f"expected one of {', '.join(perf_config.PROMPT_PROBE_MODES)}"
            )


    if "performance.warmup_retry_delays_seconds" in rc:
        delays = _parse_float_list(rc.get_string("performance.warmup_retry_delays_seconds"))
        if delays:
            perf_config.set_warmup_retry_delays_seconds(tuple(delays))


    AWSSession.WARMUP_RETRY_DELAYS_SECONDS = perf_config.get_warmup_retry_delays_seconds()
    AWSSession.RESET_RETRY_DELAY_SECONDS = perf_config.get_reset_retry_delay_seconds()


def _build_base_parser() -> argparse.ArgumentParser:
    """Build the shared argument parser (CSP-agnostic flags only)."""
    parser = argparse.ArgumentParser(
        prog="cloudbasher",
        description=f"CloudShell Container Management POC -- AWS + Azure + GCP (v{_RELEASE})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )


    action_group = parser.add_argument_group("actions (mutually exclusive)")
    action_mex = action_group.add_mutually_exclusive_group()


    action_mex.add_argument(
        "-c",
        "--command",
        metavar="CMD",
        help=argparse.SUPPRESS,
    )
    action_mex.add_argument(
        "-f",
        "--run",
        dest="run_file",
        metavar="FILE",
        help=argparse.SUPPRESS,
    )
    action_mex.add_argument(
        "-u",
        "--upload",
        nargs=2,
        metavar=("LOCAL", "REMOTE"),
        help=argparse.SUPPRESS,
    )
    action_mex.add_argument(
        "-d",
        "--download",
        nargs=2,
        metavar=("REMOTE", "LOCAL"),
        help=argparse.SUPPRESS,
    )
    action_mex.add_argument(
        "-e",
        "--enum",
        action="store_true",
        help=argparse.SUPPRESS,
    )


    conn_group = parser.add_argument_group("connection")


    parser.set_defaults(resume=False)
    creds_group = conn_group.add_mutually_exclusive_group()
    creds_group.add_argument(
        "-F",
        "--creds-file",
        dest="creds_file",
        metavar="PATH",
        default=None,
        help=(
            "Read declared identities from a credentials file; provider is "
            "detected from its contents. See creds.rc.example"
        ),
    )
    creds_group.add_argument(
        "--creds-env",
        dest="creds_env",
        action="store_true",


        help="Read one supported identity from environment variables",
    )
    conn_group.add_argument(
        "--device-code",
        action="store_true",


        help="Authenticate AWS SSO by device code -- for a host with no browser",
    )
    conn_group.add_argument(
        "-r",
        "--region",
        metavar="REGION",


        help=argparse.SUPPRESS,
    )


    conn_group.add_argument(
        "--env",
        "--environment",
        dest="environment_id",
        metavar="ENV_ID",


        help=argparse.SUPPRESS,
    )


    creds_group.add_argument(
        "-m",
        "--resume",
        dest="resume_file",
        action=_ResumeAction,
        nargs="?",
        const="",
        default=None,
        metavar="STATE_FILE",


        help=(
            "Restore saved credentials and node state. Bare -m uses "
            "state.bin; pass a filename for a different one. Nodes come back "
            "disconnected"
        ),
    )


    ui_group = parser.add_argument_group("UI")
    ui_group.add_argument(
        "--show-browser",
        dest="show_browser",
        action="store_true",
        help=(
            "Show Console login browsers from the start (default: headless); "
            "automated login remains enabled"
        ),
    )
    ui_mex = ui_group.add_mutually_exclusive_group()
    ui_mex.add_argument(
        "--tui",
        dest="tui",
        action="store_true",


        default=None,
        help="Split-pane TUI. The default, and the only interface this release ships",
    )
    ui_mex.add_argument(
        "--notui",
        dest="tui",
        action="store_false",
        default=None,


        help="NOT SUPPORTED in this release -- refused at startup; returns in a future release",
    )


    ui_group.add_argument(
        "--redact",
        dest="redact_mode",
        nargs="?",
        const="partial",
        default=None,
        choices=["partial", "pseudonym"],
        help=(
            "Mask accounts, IPs, hostnames and usernames for a demo (bare "
            "--redact means partial). Toggle live with 'm'; never affects the "
            "log file"
        ),
    )


    settings_group = parser.add_argument_group("settings")
    settings_group.add_argument(
        "-o",
        "--set",
        dest="overrides",
        action="append",
        metavar="KEY=VALUE",
        default=None,
        help=(
            "Override one cloudbasher.rc setting for this run, e.g. "
            "-o net.http_timeout=90. Repeatable; beats every rc file"
        ),
    )

    output_group = parser.add_argument_group("output")
    output_group.add_argument(
        "-l",
        "--log",
        default=None,
        metavar="FILE",
        help=("Log file (default: cloudbasher.log); " "use stdout or stderr for console"),
    )
    output_group.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="-v: log to console; -vv: enable debug detail",
    )
    output_group.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    output_group.add_argument(
        "--timeline",
        default=None,
        metavar="FILE",


        help=argparse.SUPPRESS,
    )

    parser.add_argument(
        "--version",
        action="version",


        version=f"%(prog)s {__version__}",
    )


    return parser


def _parse_setting_overrides(raw: list[str]) -> dict[str, str]:
    """`["a.b=c", "d.e=f"]` -> `{"a.b": "c", "d.e": "f"}` (`#360`)."""
    out: dict[str, str] = {}
    for item in raw:
        key, sep, value = item.partition("=")
        if not sep or not key.strip():
            raise SystemExit(
                f"-o/--set expects KEY=VALUE, got {item!r}.\n"
                f"  e.g. -o aws.artifact_dir=/tmp/art"
            )
        out[key.strip().lower()] = value
    return out


def _warn_unconsumed_overrides_at_exit(rc: Any, overrides: dict[str, str]) -> None:
    """Report `-o` keys nothing ever read, once, as the process exits."""
    import atexit

    def _report() -> None:
        unread = sorted(set(overrides) - rc.keys_read())
        if not unread:
            return
        eprint(f"warning: {len(unread)} -o setting(s) were never read: " + ", ".join(unread))
        eprint(
            "  a key nothing consumes is usually a typo -- "
            "check the name against cloudbasher.rc.example"
        )

    atexit.register(_report)


def _raise_fd_limit(rc: Any) -> None:
    """Raise the open-file limit and REPORT it. `#467`, steps 1 and 2."""
    from cloudbasher.core.utils.fd_limit import DEFAULT_TARGET, FLEET_FLOOR, raise_soft_limit

    target = rc.get_int("performance.max_open_files", DEFAULT_TARGET)
    if target <= 0:
        log("[fd] descriptor-limit raise DISABLED by performance.max_open_files=0")
        return

    result = raise_soft_limit(target)
    log(f"[fd] {result.summary()} ({result.note})")
    if not result.supported:
        return
    if result.raised:
        eprint(f"[fd] {result.summary()}")
    if not result.adequate:


        eprint(
            f"WARNING: only {result.after} open files available (need "
            f">= {FLEET_FLOOR} for a large fan-out). {result.advice()}"
        )


def parse_arguments(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Two-phase parse: detect CSP first, inject CSP-specific flags, then full parse."""


    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("-F", "--creds-file", dest="creds_file", default=None)
    known, _ = pre.parse_known_args(argv)

    csp_name = detect_csp(known.creds_file)
    if csp_name == "aws":
        provider = AWSProvider()
    elif csp_name == "azure":
        provider = AzureProvider()
    else:
        provider = GCPProvider()


    parser = _build_base_parser()
    provider.register_cli_args(parser)
    args = parser.parse_args(argv)

    args._provider = provider


    if args.log is None:
        args.log = "cloudbasher.log"


    from ..core import branding as _branding
    from ..core.config import load_user_config, set_active_config

    rc = load_user_config(warn=eprint)


    _overrides = _parse_setting_overrides(getattr(args, "overrides", None) or [])
    if _overrides:
        rc = rc.with_overrides(_overrides)
        _warn_unconsumed_overrides_at_exit(rc, _overrides)


    set_active_config(rc)


    args.proxy = rc.get_string("net.proxy") or None
    args.proxy_insecure = rc.get_bool("net.proxy_insecure", False)
    args.env_wait_timeout = rc.get_int("net.env_wait_timeout", 60)
    args.http_timeout = rc.get_int("net.http_timeout", 30)
    args.ws_timeout = rc.get_int("net.ws_timeout", 60)
    args.auto_connect = rc.get_bool("session.auto_connect", False)
    args.mouse = rc.get_bool("ui.mouse", False)


    _policy = (rc.get_string("keepalive.policy") or "").strip().lower()
    if _policy:
        if _policy in keepalive_policy.KEEPALIVE_POLICIES:
            keepalive_policy.set_default_policy(_policy)
        else:
            eprint(
                f"cloudbasher: ignoring keepalive.policy={_policy!r} -- "
                f"expected one of {', '.join(keepalive_policy.KEEPALIVE_POLICIES)}"
            )


    _raise_fd_limit(rc)


    _net_trace_on = rc.get_bool("diag.net_trace")
    if _net_trace_on:
        from cloudbasher.core.utils import dns_trace as _dns_trace

        _dns_report_path = rc.get_string("diag.net_trace_path") or "net_trace_report.txt"
        if _dns_trace.install_with_exit_report(_dns_report_path):


            eprint(
                f"[diag] network tracing ON (getaddrinfo + descriptor "
                f"pressure) -- report at exit to {_dns_report_path}. "
                f"Quit with .quit; a hard kill loses it."
            )


            _dns_bisect = rc.get_int("diag.net_bisect", 3)
            _dns_trace.set_bisect_budget(_dns_bisect)
            if _dns_bisect:
                eprint(
                    f"[diag] the first {_dns_bisect} failing lookup(s) will be "
                    f"BISECTED against the primary nameserver -- grep "
                    f"[dns-bisect] in the log for the verdict."
                )


    args.reuse_page = rc.get_bool("aws.reuse_page", False)
    args.ui_wait_timeout = rc.get_int("aws.ui_wait_timeout", 60)
    args.keep_stderr_progress = rc.get_bool("aws.keep_stderr_progress", False)
    args.artifact_dir = rc.get_string("aws.artifact_dir") or None


    args.console_login_ttl = rc.get_int("aws.console_login_ttl_seconds", 0)

    _branding.set_title(rc.get_string("ui.title"))
    _branding.set_prompt_text(rc.get_string("ui.prompt"))
    _branding.set_mouse_capture(args.mouse)


    if args.tui is None:
        args.tui = rc.get_string("ui.mode", "tui").strip().lower() != "notui"


    from ..core.utils.redact import (
        add_redact_rule,
        clear_redact_rules,
        set_field_mode_override,
        set_redaction_enabled,
        set_redaction_mode,
    )

    if args.redact_mode is not None:
        set_redaction_enabled(True)
        set_redaction_mode(args.redact_mode)
    else:
        set_redaction_enabled(rc.get_bool("redact.enabled", False))
        set_redaction_mode(rc.get_string("redact.mode", "partial") or "partial")


    for field_name, field_mode in rc.items_with_prefix("redact.field").items():
        set_field_mode_override(field_name, field_mode)


    clear_redact_rules()
    _rule_parts: dict[str, dict[str, str]] = {}
    for key, value in rc.items_with_prefix("redact.rule").items():
        for suffix in ("pattern", "mode", "scope"):
            if key.endswith(f".{suffix}"):
                _rule_parts.setdefault(key[: -(len(suffix) + 1)], {})[suffix] = value
                break
    for rule_name, parts in _rule_parts.items():
        if "pattern" in parts and "mode" in parts:
            add_redact_rule(rule_name, parts["pattern"], parts["mode"], parts.get("scope"))


    _apply_performance_tuning_from_rc(rc)


    args.multi_node = True
    return args


def detect_csp(creds_file: Optional[str] = None) -> str:
    """Auto-detect cloud service provider."""
    if creds_file:
        from cloudbasher.core.credential_file import parse_multi_creds_file

        try:
            parsed = parse_multi_creds_file(creds_file)
        except (OSError, CloudBasherError):


            parsed = []
        if parsed:
            return parsed[0].provider

    import os


    if os.getenv("AWS_REGION") or os.getenv("AWS_ACCESS_KEY_ID"):
        return "aws"


    if os.getenv("GOOGLE_APPLICATION_CREDENTIALS") or os.getenv("GCP_PROJECT"):
        return "gcp"


    if os.getenv("AZURE_CLIENT_ID") or os.getenv("AZURE_TENANT_ID"):
        return "azure"


    return "aws"


def resolve_creds_source(args: Any) -> str:
    """Which named source identities come from: "file", "env" or "resume"."""
    if getattr(args, "creds_file", None):
        return "file"
    if getattr(args, "creds_env", False):
        return "env"
    if getattr(args, "resume", False):
        return "resume"
    raise CredentialError(
        "no identity source. CloudBasher does not search the environment for "
        "credentials -- name one explicitly:\n"
        "  -F/--creds-file PATH   declared identities from a file\n"
        "  --creds-env            one identity from this CSP's env vars\n"
        "  --resume               restore a prior session's identities"
    )


def _creds_source_where(args: Any, source: str) -> str:
    """How to name the credential's origin in an error the user has to act on."""
    return {
        "file": f"{getattr(args, 'creds_file', None) or '<file>'} block 1",
        "env": "--creds-env",
        "resume": "resumed state",
    }[source]


def _preflight_identity_name_for_command_mode(credentials: Credentials, args: Any) -> None:
    """Raise if `-c <command>` cannot possibly resolve an identity name (M7)."""
    if not getattr(args, "command", None):
        return
    from cloudbasher.core.credential_file import _kind_for
    from cloudbasher.csp.aws.act_as import DerivationState, derivation_state
    from cloudbasher.csp.aws.credentials import (
        resolve_identity_name,
        session_creds_from_extra,
    )

    extra = credentials.extra
    if derivation_state(extra, kind=_kind_for(extra)) is not DerivationState.OWES_A_NAME:
        return


    resolve_identity_name(
        session_creds_from_extra(extra),
        None,
        where="-c: the command this run will execute",
    )


def _notui_unsupported_error(args: Any) -> Optional[str]:
    """v0.9 IS TUI-ONLY: refuse a resolved `--notui`, or None (`#407`)."""
    if getattr(args, "tui", True):
        return None
    return (
        f"Error: --notui is not supported in v{_RELEASE}.\n"
        "\n"
        "The readline interface cannot start in this release: it needs a single\n"
        "session that nothing creates any more, since multi-node became the only\n"
        "mode. Making it equivalent to the TUI is planned for a future release.\n"
        "\n"
        "Run without --notui for the split-pane TUI. If cloudbasher.rc carries\n"
        "`ui.mode = notui`, remove it or override with `-o ui.mode=tui`."
    )


def _unsupported_csp_error(csp_name: str) -> Optional[str]:
    """Refuse an unknown detected CSP, or return None for supported providers."""
    if csp_name in {"aws", "azure", "gcp"}:
        return None
    other = csp_name.upper()
    return (
        f"Unsupported cloud provider '{other}' was detected.\n"
        "  Use a credential source for AWS, Azure, or GCP."
    )


def _preflight_credential_source(args: Any, csp_name: str) -> Optional[str]:
    """Reject a broken credential source before anything starts, or None."""
    try:
        source = resolve_creds_source(args)
    except CredentialError as exc:
        return str(exc)

    if source == "file":
        from pathlib import Path

        path = getattr(args, "creds_file", None) or ""
        if not Path(path).expanduser().exists():
            return f"Credentials file not found: {path}"


        from cloudbasher.core.credential_file import merged_blocks_error_in_text

        try:
            _raw = Path(path).expanduser().read_text(encoding="utf-8")
        except OSError:
            _raw = ""
        if _raw:
            _merged = merged_blocks_error_in_text(_raw)
            if _merged:
                return f"{path}: {_merged}"


        if csp_name == "aws":
            from cloudbasher.csp.aws.credentials import sso_preflight_error

            _sso_err = sso_preflight_error(path)
            if _sso_err:
                return f"{path}: {_sso_err}"

    if source == "env":
        if csp_name == "gcp":
            from cloudbasher.csp.gcp.credentials import preflight_env_error as _gcp_pre

            return _gcp_pre()
        if csp_name == "azure":
            from cloudbasher.csp.azure.credentials import preflight_env_error as _az_pre

            return _az_pre(
                tenant_id=getattr(args, "tenant", None) or "",
                subscription_id=getattr(args, "subscription", None) or "",
            )

    if csp_name == "aws" and source in ("file", "env"):


        from cloudbasher.csp.aws.credentials import AWSCredentialProvider

        try:
            _creds = AWSCredentialProvider(
                credential_file=getattr(args, "creds_file", None),
                device_code=getattr(args, "device_code", False),
                region=getattr(args, "region", None),
                source=source,
            ).load()
            _require_act_as(_creds, where=_creds_source_where(args, source))
            _preflight_identity_name_for_command_mode(_creds, args)
        except CredentialError as exc:
            return str(exc)
        return None


    return None


def _prompt_passphrase(resuming: bool, state_file: str = "state.bin") -> Optional[str]:
    """Prompt for the state file passphrase.  Returns None if the user skips."""
    import os

    env_pp = os.environ.get("CB_PASSPHRASE")
    if env_pp:
        return env_pp

    import getpass
    import sys


    _fd: Optional[int] = None
    _old_tty: object = None
    try:
        import termios

        _fd = sys.stdin.fileno()
        _old_tty = termios.tcgetattr(_fd)
    except Exception:
        pass
    try:
        if resuming:
            return getpass.getpass(f"  Passphrase for {state_file}: ") or None
        else:
            pp = getpass.getpass("  Passphrase to encrypt saved state (Enter to skip): ")
            if not pp:
                return None
            pp2 = getpass.getpass("  Confirm passphrase: ")
            if pp != pp2:
                eprint("  Passphrases do not match — state will not be saved.")
                return None
            return pp
    except (EOFError, KeyboardInterrupt, OSError):


        print()
        return None
    finally:
        if _fd is not None and _old_tty is not None:
            try:
                import termios

                termios.tcsetattr(_fd, termios.TCSADRAIN, _old_tty)
            except Exception:
                pass


def _parse_private_env(raw: Any) -> dict:
    """Extract key fields from a GCP private API environment array (positional)."""
    if not raw or not isinstance(raw, list):
        return {}
    if raw and isinstance(raw[0], list):
        raw = raw[0][0] if (raw[0] and isinstance(raw[0][0], list)) else raw[0]

    def _g(idx: int, default: Any = None) -> Any:
        return raw[idx] if idx < len(raw) and raw[idx] is not None else default

    return {
        "state": _g(3, 0),
        "ssh_username": _g(4, ""),
        "ssh_host": _g(5, ""),
        "ssh_port": int(_g(6, 6000) or 6000),
        "web_host": _g(11, ""),
    }


def _resolve_gcp_quota_project(args: Any, credentials: Any) -> Optional[str]:
    """Compatibility wrapper for the shared GCP quota-project resolver."""
    from cloudbasher.csp.gcp.credentials import resolve_quota_project

    return resolve_quota_project(args, credentials)


def _run_batch_file(run_file: str, state: InteractiveState, dispatcher) -> int:
    """Execute a dot-command batch file line by line."""
    from cloudbasher.core.cli.batch_runner import run_batch_file

    return run_batch_file(run_file, state, dispatcher).exit_code


def _check_dependencies(csp_name: str) -> None:
    """Check required and optional packages; exit with install hint on failure."""
    base_required: dict[str, str] = {
        "textual": "textual  # TUI split-pane mode (default backend)",
    }


    base_optional: dict[str, str] = {}
    csp_required: dict[str, str] = {}
    if csp_name == "aws":
        csp_required = {"websocket": "websocket-client"}
    elif csp_name == "gcp":
        csp_required = {
            "paramiko": "paramiko",
            "google.auth": "google-auth",
        }
    elif csp_name == "azure":
        csp_required = {
            "websocket": "websocket-client",
            "msal": "msal",
        }

    all_required = {**base_required, **csp_required}
    missing_required: list[tuple[str, str]] = []
    missing_optional: list[tuple[str, str]] = []

    for module, package in all_required.items():
        try:
            __import__(module)
        except ImportError:
            missing_required.append((module, package))

    for module, package in base_optional.items():
        try:
            __import__(module)
        except ImportError:
            missing_optional.append((module, package))

    if missing_optional:
        pkgs = "  ".join(pkg.split("#")[0].strip() for _, pkg in missing_optional)
        print(
            f"[{csp_name}] Optional packages missing (TUI disabled): pip install {pkgs}",
            file=sys.stderr,
        )

    if missing_required:
        lines = [f"Missing required Python packages for {csp_name}:\n"]
        for module, pkg in missing_required:
            lines.append(f"  {pkg}  (import name: {module})")
        lines.append(
            "\nInstall with:\n  pip install "
            + " ".join(pkg.split("#")[0].strip() for _, pkg in missing_required)
        )
        print("\n".join(lines), file=sys.stderr)
        sys.exit(1)


@dataclass
class _BootstrapResult:
    """What a per-CSP bootstrap helper hands back to _bootstrap_session so it can populate state.api_client/session/keepalive/_session_obj the same way for all three CSPs."""

    api_client: Any
    session_obj: Any
    env_id: str
    region: str


    keepalive: Optional[Any] = None
    web_host: str = ""


    container_status: Optional[str] = None


    control_plane_evidence: str = ""


def _attach_keepalives(node: Any, handles: Optional[Any]) -> None:
    """Hand every keepalive layer a bootstrap started to the node that owns its teardown. A no-op for a bootstrap that started none."""
    if handles is None:
        return
    attach = getattr(handles, "attach_to_node", None)
    if callable(attach):
        attach(node)
        return
    from cloudbasher.csp.aws.keepalive import attach_to_node

    attach_to_node(node, handles)


def _apply_bootstrap_result(
    node: Any,
    result: "_BootstrapResult",
    *,
    region: str,
    emit: Callable[[str], None],
) -> None:
    """Populate a just-bootstrapped node from its `_BootstrapResult`. WORKER-SIDE."""
    node.environment_id = result.env_id
    node.session = SessionInfo(
        environment_id=result.env_id or "",
        region=region,
        user="",
        hostname="",
        ip_address="",
        web_host=result.web_host or "",
    )


    node._runtime_session = result.session_obj
    _record_bootstrap_control_plane_evidence(node, result)
    _probe_after_bootstrap(node, emit)


def _publish_bootstrapped_node(node: Any, result: "_BootstrapResult") -> None:
    """The half of a bootstrap whose order against other nodes is observable."""


    _attach_keepalives(node, result.keepalive)
    _record_bootstrap_control_plane_evidence(node, result)
    node.container_status = "Running"
    node.end_connect()


def _record_session_control_plane_evidence(
    node: Any, session: Any, observation: str = ""
) -> None:
    """Normalize and publish one provider observation at the shared boundary."""
    from cloudbasher.core.control_plane_status import (
        normalize_control_plane_evidence,
        record_control_plane_evidence,
    )
    from cloudbasher.core.types import CONTROL_PLANE_ACCEPTED

    if observation:
        record_control_plane_evidence(node, normalize_control_plane_evidence(observation))
    elif session is not None:
        legacy = getattr(session, "cb_control_plane_identity", "")
        record_control_plane_evidence(
            node,
            normalize_control_plane_evidence(legacy) if legacy else CONTROL_PLANE_ACCEPTED,
        )


def _record_bootstrap_control_plane_evidence(node: Any, result: "_BootstrapResult") -> None:
    """One publication point for provider bootstrap evidence and AWS legacy presign."""
    _record_session_control_plane_evidence(
        node, result.session_obj, result.control_plane_evidence
    )


def _run_node_bootstrap(
    node: Any, operation: Callable[..., "_BootstrapResult"], **kwargs: Any
) -> "_BootstrapResult":
    """Record the latest bootstrap auth outcome at the shared node boundary."""
    from cloudbasher.core.control_plane_status import (
        classify_control_plane_exception,
        record_control_plane_evidence,
    )
    from cloudbasher.core.types import CONTROL_PLANE_UNASKED

    record_control_plane_evidence(node, CONTROL_PLANE_UNASKED)
    try:
        result = operation(**kwargs)
    except Exception as exc:
        record_control_plane_evidence(node, classify_control_plane_exception(exc))
        raise
    _record_bootstrap_control_plane_evidence(node, result)
    return result


def _load_saved_state_or_none(state_bin: str, passphrase: Optional[str], resume: bool) -> dict:
    """Wraps InteractiveState.load_saved_state with the --resume-gated empty- dict default shared by both bootstrap paths. Raises ValueError on a corrupt/wrong-passphrase state file -- callers decide how to report that."""
    return InteractiveState.load_saved_state(state_bin, passphrase=passphrase) if resume else {}


def _restore_multi_node_registry(
    state: InteractiveState,
    state_multi_bin: str,
    passphrase: Optional[str],
    resume: bool,
    emit: Callable[[str], None],
    will_reprobe: bool = False,
) -> None:
    """On --resume, repopulate state.credentials_by_id/nodes_by_id/ active_node_id from the persisted multi-node registry (InteractiveState. save_registry()/load_registry() already existed but were never called -- this is the wiring). Must run BEFORE _bootstrap_session() so its own multi-CSP synthesis (_synthesize_primary_credential_record, _bootstrap_multi_csp_nodes) sees the restored registry rather than starting from empty dicts; the actual live-status re-check happens separately in _reprobe_restored_node_statuses(), after bootstrap completes, so it can skip nodes that were freshly (re)connected this run."""
    if not resume:
        return
    try:
        credentials_by_id, nodes_by_id, active_node_id, unmanaged = InteractiveState.load_registry(
            state_multi_bin, passphrase=passphrase
        )
    except ValueError as exc:
        emit(f"Could not load multi-node registry {state_multi_bin}: {exc}")
        return


    if unmanaged:
        try:


            restore = getattr(state.csp_provider, "unmanaged_from_dict", None)
            if restore is not None:
                restore(state, unmanaged)
        except Exception as exc:  # noqa: BLE001
            emit(f"Could not restore the unmanaged set: {exc}")
    if not credentials_by_id and not nodes_by_id:
        return


    if will_reprobe:
        for node in nodes_by_id.values():
            if not node.environment_id or not node.region:
                continue
            rec = credentials_by_id.get(node.credential_id)
            if rec is None or rec.provider not in {"aws", "azure"}:
                continue
            node.begin_connect()


    unseeded = sorted((n for n in nodes_by_id.values() if n.seq == 0), key=lambda n: n.id)
    if unseeded:
        next_seq = max((n.seq for n in nodes_by_id.values()), default=0) + 1
        for node in unseeded:
            node.seq = next_seq
            next_seq += 1
    state.credentials_by_id.update(credentials_by_id)
    state.nodes_by_id.update(nodes_by_id)


    if nodes_by_id:
        state._next_node_seq = max(
            state._next_node_seq, max(n.seq for n in nodes_by_id.values()) + 1
        )
    if state.active_node_id is None:
        state.active_node_id = active_node_id


    emit(
        f"Restored {len(credentials_by_id)} credential(s) and "
        f"{len(nodes_by_id)} node(s) from {state_multi_bin}"
    )


def _resolve_sso_credential_in_place(credentials: Any, args: Any, emit: Any) -> None:
    """Turn a loaded Identity Center credential into key material, in place."""


    _browser = browser_options(args)
    from cloudbasher.csp.aws.commands import _browser_creds_for
    from cloudbasher.csp.aws.credentials import (
        AwsSSOCreds,
        merge_sso_keys,
        resolve_sso_to_keys,
    )

    extra = getattr(credentials, "extra", None) or {}
    sso = _browser_creds_for(extra)
    if not isinstance(sso, AwsSSOCreds):
        return
    if extra.get("access_key"):


        return
    emit("Signing in to Identity Center " f"({sso.sso_region or 'no SSO_REGION declared'})...")
    credentials.extra = merge_sso_keys(
        credentials.extra or {},
        resolve_sso_to_keys(
            sso,

            headless=_browser.headless,
            proxy_url=_browser.proxy_url,
            proxy_insecure=_browser.proxy_insecure,
        ),
    )
    emit("✓ Identity Center credentials resolved")


def _console_creds_from_credentials(credentials: Any) -> Optional[Any]:
    """The parsed console/SSO dataclass rebuilt from a restored credential, or None."""
    from cloudbasher.csp.aws.commands import console_login_for

    return console_login_for(getattr(credentials, "extra", None) or {})


def _backfill_saved_credentials_from_registry(
    saved: dict, state: InteractiveState, csp_name: str
) -> dict:
    """Structural fix: state_<csp>.bin's single-slot 'credentials' save and state_<csp>_multi.bin's registry save are two independent persistence paths for what should be the same identity. The single-slot save can go missing/stale (e.g. state.credentials gets temporarily repointed by _node_dispatch_context() for per-node dot-command dispatch -- a real incident traced back to this) without the registry's own save being affected at all, since save_registry() persists state.credentials_by_id, a completely separate attribute."""
    if csp_name != "aws":
        return saved


    originating = next(
        (
            rec
            for rec in state.credentials_by_id.values()
            if rec.role == "originating"
            and rec.provider == "aws"
            and rec.kind in ("permanent", "console")
        ),
        None,
    )
    if originating is None:
        return saved
    extra = originating.raw.extra or {}
    access_key = extra.get("access_key", "")
    secret_key = extra.get("secret_key", "")
    if not (access_key and secret_key):
        if not (extra.get("username") and extra.get("password")):
            return saved


        from cloudbasher.csp.aws.credentials import browser_extra_to_persist

        browser_entry = browser_extra_to_persist(extra)
        if browser_entry:
            saved = dict(saved)
            saved["credentials"] = browser_entry
        return saved

    saved = dict(saved)


    from cloudbasher.csp.aws.credentials import key_extra_to_persist

    saved["credentials"] = key_extra_to_persist(extra)
    return saved


def _backfill_saved_session_from_registry(
    saved: dict, state: InteractiveState, csp_name: str
) -> dict:
    """Under --multi-node, state_<csp>.bin is no longer written at all (see main()'s finally: block) -- its region/environment_id/user/ hostname/ip_address/web_host fields would otherwise be permanently "unknown" on --resume, since the primary bootstrap reads them from ``saved`` before _restore_multi_node_registry's own nodes are consulted."""
    originating = next(
        (
            rec
            for rec in state.credentials_by_id.values()
            if rec.role == "originating" and rec.provider == csp_name
        ),
        None,
    )
    if originating is None:
        return saved
    node = next(
        (
            n
            for n in state.nodes_by_id.values()
            if n.credential_id == originating.id and n.session is not None
        ),
        None,
    )
    if node is None or node.session is None:
        return saved

    saved = dict(saved)
    saved.update(
        {
            "environment_id": node.session.environment_id,
            "region": node.session.region,
            "user": node.session.user,
            "hostname": node.session.hostname,
            "ip_address": node.session.ip_address,
            "web_host": node.session.web_host,
        }
    )
    return saved


def _is_interactive_run(args: Any) -> bool:
    """A run with no scripted action -- i.e. a TUI or readline session."""
    return not (
        getattr(args, "command", None)
        or getattr(args, "run_file", None)
        or getattr(args, "upload", None)
        or getattr(args, "download", None)
        or getattr(args, "enum", None)
    )


def _preflight_region_error(args: Any, csp_name: str) -> Optional[str]:
    """Refuse a run that will CREATE a CloudShell environment with no region."""
    if csp_name != "aws" or getattr(args, "region", None):
        return None
    if not _should_connect_on_bootstrap(args, _is_interactive_run(args)):
        return None
    return (
        "No region. This invocation opens a CloudShell session immediately, "
        "so the region cannot be deferred to `.provision` and is not "
        "defaulted -- pass `--region <region>`."
    )


def _should_connect_on_bootstrap(args: Any, is_interactive: bool) -> bool:
    """Whether _bootstrap_session()'s primary AWS identity should connect eagerly (create/start/open a session) vs. register-only. Scripted one-shot invocations (-c/--run/.upload/.download/.enum, i.e. ``is_interactive=False``) need a live session immediately, regardless of `session.auto_connect`, so they always connect -- "no impact on scripted usage" per the 3-axis model. Genuinely interactive startup (TUI or readline) only connects the primary node when `session.auto_connect` is on; this is a separate, simpler check than _should_auto_connect_on_resume() below (which still only governs reprobing every OTHER restored node, and still requires --multi-node -- unchanged)."""


    if _should_skip_primary_bootstrap_on_resume(args, is_interactive):
        return False
    if getattr(args, "enum", False):
        return False
    return (not is_interactive) or bool(getattr(args, "auto_connect", False))


def _should_skip_primary_bootstrap_on_resume(args: Any, is_interactive: bool) -> bool:
    """Whether TUI resume should reconnect only the restored node registry."""
    return bool(
        is_interactive
        and getattr(args, "resume", False)
        and getattr(args, "multi_node", False)
        and getattr(args, "auto_connect", False)
    )


def _bootstrap_tui_startup(
    *,
    state: InteractiveState,
    args: Any,
    provider: Any,
    csp_name: str,
    saved: dict,
    emit: Callable[[str], None],
    gcp_wait_mode: str,
    connect: bool,
    is_interactive: bool,
) -> None:
    """Bootstrap a TUI invocation, or leave an opted-in resume to its registry."""
    if _should_skip_primary_bootstrap_on_resume(args, is_interactive):
        state.args = args
        emit(
            "Resuming saved nodes; auto-connect uses each node's "
            "saved provider and region."
        )
        return

    _bootstrap_session(
        state=state,
        args=args,
        provider=provider,
        csp_name=csp_name,
        saved=saved,
        emit=emit,
        gcp_wait_mode=gcp_wait_mode,
        connect=connect,
    )


def _should_auto_connect_on_resume(args: Any) -> bool:
    """Whether to eagerly reprobe/reconnect every OTHER restored node (not the primary identity -- see `_connect_on_bootstrap` in main(), a separate check that governs the primary node for both single- and multi-node mode) during bootstrap -- both of main()'s _reprobe_restored_node_statuses() call sites (TUI background-thread path and the readline/-c synchronous path) gate on this, rather than duplicating the condition inline. Default off (per the `session.auto_connect` entry in cloudbasher.rc.example): a plain --resume just restores registration + last-known container_status, leaving reconnecting to an explicit .connect. Scoped to --multi-node only -- single-node mode never has "other restored nodes" to reprobe in the first place."""
    return bool(getattr(args, "multi_node", False) and getattr(args, "auto_connect", False))


def _reprobe_restored_node_statuses(state: InteractiveState, emit: Callable[[str], None]) -> None:
    """Unify-connect-flow change: ACTIVELY RECONNECT every restored node instead of just polling its status. Previously this only called get_environment_status() and trusted the result -- restored nodes stayed disconnected (no live session, no heartbeat) until a user manually triggered 's'/'c' Connect or .bulk. Now a --resume brings every restored AWS node back to the exact same connected state as one that was never disconnected: reconnect_node_session() wakes a SUSPENDED/ STOPPED environment, resolves (re-deriving via STS if expired) the node's live credentials, opens a WebSocket, and starts its heartbeat -- the node's status becomes "Running" as a side effect of successfully reconnecting, not a separately-trusted label."""
    from cloudbasher.csp.aws.multi_region import reconnect_node_session

    to_reconnect = []
    for node in state.nodes_by_id.values():
        if node._runtime_session is not None:
            continue
        if not node.environment_id:
            continue
        rec = state.credentials_by_id.get(node.credential_id)
        if rec is None or rec.provider not in {"aws", "azure", "gcp"}:
            continue
        if rec.provider == "aws" and not node.region:
            continue
        to_reconnect.append(node)
    if not to_reconnect:
        return

    nodes_by_id = {node.id: node for node in to_reconnect}


    handed_off: set[str] = set()

    def _reconnect_one(node_id: str, _ctx: Any) -> tuple[bool, list[str]]:
        """Build and INSTALL this node's session. `#443`, ON the primitive."""
        node = nodes_by_id[node_id]
        with node._recovery_lock:
            if node._runtime_session is not None:
                handed_off.add(node_id)
                return True, []
            rec = state.credentials_by_id[node.credential_id]
            if rec.provider == "azure":
                from cloudbasher.csp.azure.provider import AzureProvider

                AzureProvider().reconnect_node(state, node)
            elif rec.provider == "gcp":
                from cloudbasher.csp.gcp.provider import GCPProvider

                GCPProvider().reconnect_node(state, node)
            else:
                node._runtime_session = reconnect_node_session(state, node)


        try:
            node._runtime_session.ensure_connected()
        except Exception as exc:


            emit(f"could not pre-open the session for {node.id}: {exc}")
        _probe_after_bootstrap(node, emit)
        return True, []

    def _note_failure(node: NodeRecord, exc: BaseException) -> None:
        """The FOURTH of five failure sites, and the one `#111` would have shipped past: a `--resume` whose restored nodes cannot reconnect is exactly when a user is staring at red rows wondering why, and this recorded no class at all."""
        why = str(exc)
        try:
            from cloudbasher.csp.aws.failure import note_node_failure

            _label, why = note_node_failure(node, exc)
        except Exception:
            node.container_status = "Failed"
            node.end_connect()
        emit(f"could not reconnect restored node {node.id}: {why}")
        emit(f"  raw: {exc}")

    def _publish_one(node_id: str) -> None:
        """The status flip, on the COLLECTING thread."""
        node = nodes_by_id[node_id]
        if node_id in handed_off or (
            node._runtime_session is not None and node.container_status == "Running"
        ):
            return
        node.container_status = "Running"
        node.end_connect()


    from cloudbasher.core.cli.dispatcher import fan_out_over_nodes

    outcome = fan_out_over_nodes(
        "reconnect",
        nodes_by_id,
        {},
        _reconnect_one,
        state,
        on_failure=_note_failure,
        on_success=_publish_one,
    )
    for node_id in outcome.cancelled:


        emit(f"skipped reconnect -- cancelled: {node_id}")


def _enter_shell_mode_if_ready(state: InteractiveState, emit: Callable[[str], None]) -> None:
    """Single-node sessions should display as "connected" immediately once bootstrap completes, not only after the user types the bare `.command` to enter shell mode explicitly (`_cmd_command()` in core/cli/dispatcher.py). The session is already command-ready by the time _bootstrap_session() returns (every per-CSP bootstrap function ends with an eager handshake/probe) -- readline already executes non-dot-command input as a raw shell command either way (see ReadlineMode.run()'s "else" branch), so setting in_shell_mode/ shell_prompt_info early only changes what the prompt/status row *shows*, not what commands do."""
    session = getattr(state, "_session_obj", None)
    if session is None:
        return
    from cloudbasher.core.session.shell import ShellModeHandler

    state.in_shell_mode = True
    try:
        state.shell_prompt_info = ShellModeHandler(session).setup_prompt_info()
    except Exception as exc:
        emit(f"shell-mode context gather failed (best-effort): {exc}")


def _register_aws_node(
    *,
    args: Any,
    provider: Any,
    credentials: Any,
    env_id: Optional[str],
    region: Optional[str],
    emit: Callable[[str], None],
    credential_record: Any = None,
    credential_registry: Any = None,
    on_environment_known: Optional[Callable[[str], None]] = None,
) -> _BootstrapResult:
    """Register-only counterpart to _bootstrap_aws_session: constructs the api_client but never calls create_environment()/start_environment()/ open_stream(), never opens a WebSocket, and -- Task 11 -- never calls describeEnvironments/getEnvironmentStatus either."""


    if not region:
        emit(
            "Credentials loaded; no region named, so nothing is registered. "
            "Run `.provision <ID> region <selector>` to create a node."
        )
        return _BootstrapResult(
            api_client=None,
            session_obj=None,
            env_id=env_id or "",
            region="",
            container_status="Unknown",
        )
    emit(
        f"Registering AWS CloudShell node (region: {region}) -- nothing "
        "connected or discovered; name an identity (.provision/.register) "
        "to discover its environments."
    )
    api_client = provider.create_api_client(
        credentials,
        region=region,
        timeout=args.http_timeout,
        proxy_url=args.proxy,
        proxy_insecure=args.proxy_insecure,
        artifact_dir=getattr(args, "artifact_dir", None),


        credential_record=credential_record,
        credential_registry=credential_registry,
    )

    return _BootstrapResult(
        api_client=api_client,
        session_obj=None,
        env_id=env_id or "",
        region=region,
        container_status="Unknown",
    )


def _startup_console_creds(blocks: list, console_blocks: list) -> Any:
    """Decide whether a process-wide console/SSO browser-login signal may be armed from this credential file -- permitted only when the file declares exactly one credential, the single case where "the file's shape" and "this credential's shape" are the same statement."""
    from cloudbasher.csp.aws.credentials import AwsConsoleCreds

    if len(blocks) == 1 and console_blocks:
        parsed = console_blocks[0].parsed
        return parsed if isinstance(parsed, AwsConsoleCreds) else None
    return None


def _bootstrap_aws_session_via_browser(
    *,
    args: Any,
    provider: Any,
    credentials: Any,
    api_client: Any,
    env_id: Optional[str],
    region: str,
    emit: Callable[[str], None],
    pw_creds: Any = None,
) -> tuple:
    """Bootstrap one CloudShell session entirely through the browser."""


    _browser = browser_options(args)
    from cloudbasher.csp.aws.browser import bootstrap_via_console_login

    emit("Running Playwright console/SSO login...")


    console_result = bootstrap_via_console_login(
        pw_creds=pw_creds if pw_creds is not None else args.pw_creds,
        region=region,
        env_id=env_id or "",
        headless=_browser.headless,
        proxy_url=_browser.proxy_url,
        proxy_insecure=_browser.proxy_insecure,
        ui_wait_timeout=_browser.ui_wait_timeout,
    )
    env_id = console_result.get("environment_id") or env_id


    try:
        from cloudbasher.csp.aws.console_api import ConsoleCloudShellAPI

        console_client = ConsoleCloudShellAPI(
            console_result["page"],
            region=region or "",
            timeout=args.http_timeout,
        )
    except Exception as exc:
        detail(f"[console] no presign control-plane client: {exc}")
        console_client = None

    if not env_id and console_client is not None:


        try:
            from cloudbasher.csp.aws.api import select_environment

            envs = console_client.describe_environments().get("environments", [])
            env_id = (select_environment(envs) or {}).get("EnvironmentId") or ""
            if env_id:
                log(
                    f"[console] environment id not intercepted; recovered "
                    f"{env_id} from describeEnvironments ({len(envs)} in region)"
                )
        except Exception as exc:
            detail(f"[console] describeEnvironments could not recover an env id: {exc}")

    if not env_id:
        raise BootstrapError(
            "browser login completed but no CloudShell environment id was captured "
            f"for region {region}, and describeEnvironments reported none.\n"
            "The console page never reached the point of creating one -- retry, "
            "or raise --ui-wait-timeout."
        )

    emit("✓ Playwright login complete — commands will run through the browser terminal")
    session = provider.create_session(
        credentials,
        env_id,
        stream_url="",
        token_value="",
        api_client=api_client,
        timeout=args.ws_timeout,
    )
    session.set_playwright_page(console_result["page"])


    session.set_control_plane_identity(console_result.get("presign", CONTROL_PLANE_UNASKED))
    session.set_playwright_handles(
        browser=console_result["browser"],
        context=console_result["context"],
    )


    from cloudbasher.csp.aws.multi_region import _try_console_websocket

    _try_console_websocket(session, console_client, env_id)


    return session, env_id, console_client


def _finish_aws_bootstrap(
    *,
    args: Any,
    session: Any,
    api_client: Any,
    env_id: Optional[str],
    region: str,
    emit: Callable[[str], None],


    on_reproject: Optional[Callable[[], None]] = None,
) -> "_BootstrapResult":
    """The tail both AWS bootstrap paths share: warm the socket, start every keepalive layer, build the result."""
    from cloudbasher.core.session.quiet import exec_quiet
    from cloudbasher.core.utils.perf_config import get_heartbeat_interval_seconds
    from cloudbasher.csp.aws.keepalive import start_all_keepalives

    hb_interval = get_heartbeat_interval_seconds()


    handles = start_all_keepalives(api_client, env_id or "", on_reproject=on_reproject)
    emit(f"Heartbeat loop started interval={hb_interval}s environment_id={env_id}")
    if handles.bridge_thread is not None:
        emit(f"Extensions bridge started environment_id={env_id}")


    emit("Connecting to shell...")
    exec_quiet(session, ":", raw=False)
    emit("✓ Shell connection ready")


    if handles.attach_session is not None:
        handles.attach_session(session)

    emit(f"region={region} startup_session_bootstrapped=true environment_id={env_id}")
    emit(f"region_selector={region}")

    return _BootstrapResult(
        api_client=api_client,
        session_obj=session,
        env_id=env_id or "",
        region=region,
        keepalive=handles,
    )


def _bootstrap_aws_session(
    *,
    args: Any,
    provider: Any,
    credentials: Any,
    env_id: Optional[str],
    region: Optional[str],
    emit: Callable[[str], None],
    credential_record: Any = None,
    credential_registry: Any = None,
    on_environment_known: Optional[Callable[[str], None]] = None,
) -> _BootstrapResult:
    """AWS branch of _bootstrap_session: environment lifecycle, credential projection, WebSocket session creation, heartbeat."""


    if not region:
        raise BootstrapError(
            "no region named. This action creates a CloudShell environment, "
            "so the region cannot be guessed -- pass `--region <region>`."
        )
    emit("Bootstrapping AWS CloudShell environment...")
    api_client = provider.create_api_client(
        credentials,
        region=region,
        timeout=args.http_timeout,
        proxy_url=args.proxy,
        proxy_insecure=args.proxy_insecure,
        artifact_dir=getattr(args, "artifact_dir", None),


        credential_record=credential_record,
        credential_registry=credential_registry,
    )


    _resolved_pw_creds = getattr(args, "pw_creds", None)
    if _resolved_pw_creds is None:
        _console = _console_creds_from_credentials(credentials)
        if _console is not None:
            log("saved console credentials — re-running the browser login")
            _resolved_pw_creds = _console


    _own_key = bool((getattr(credentials, "extra", None) or {}).get("access_key"))
    if _own_key and _resolved_pw_creds is not None:
        log(
            "browser path declined: this credential has its own access key, so "
            "it signs for itself -- a console login belonging to another "
            "credential block will not be used for it"
        )

    if _resolved_pw_creds is not None and not _own_key:


        from cloudbasher.csp.aws.console_bootstrap import console_reprojector_for

        session, env_id, console_client = _bootstrap_aws_session_via_browser(
            args=args,
            pw_creds=_resolved_pw_creds,
            provider=provider,
            credentials=credentials,
            api_client=api_client,
            env_id=env_id,
            region=region,
            emit=emit,
        )
        return _finish_aws_bootstrap(
            args=args,
            session=session,


            api_client=console_client or api_client,
            env_id=env_id,
            region=region,
            emit=emit,


            on_reproject=console_reprojector_for(
                lambda: console_client or api_client,
                region=region,
                env_id=env_id or "",
                timeout=args.http_timeout,
            ),
        )

    env_list = api_client.describe_environments()
    envs = env_list.get("environments", [])
    if envs:
        from cloudbasher.csp.aws.api import is_vpc_environment, select_environment

        chosen = select_environment(envs) or {}
        env_id = env_id or chosen.get("EnvironmentId")
        if is_vpc_environment(chosen):


            emit(
                f"Using VPC environment: {env_id} "
                f"({chosen.get('EnvironmentName') or 'unnamed'}) -- no default "
                f"environment exists in this region"
            )
        else:
            emit(f"Using existing environment: {env_id}")
    else:
        emit("No existing environment found, creating new one...")
        cr = api_client.create_environment()
        env_id = cr.get("environment_id")
        emit(f"Created environment: {env_id}")


    from ..csp.aws.multi_region import (
        _EnvironmentStateError,
        _EnvironmentWaitTimeout,
        _wait_for_running,
    )

    if on_environment_known is not None and env_id:
        try:
            on_environment_known(env_id)
        except Exception:
            log(f"[bootstrap] on_environment_known failed for {env_id}")


    from cloudbasher.csp.aws.act_as import act_as_from_extra, skips_projection
    from cloudbasher.csp.aws.console_bootstrap import (
        begin_credential_projection,
        make_reprojector,
    )


    if skips_projection(act_as_from_extra(credentials.extra or {})):
        emit(
            "ACT_AS=direct-unbound: skipping credential projection -- the "
            "container will have no AWS credentials, so in-shell `aws` will "
            "not work. CloudShell itself is fully usable."
        )
        pending_projection = None
    else:
        emit("Running browser-free OAuth PKCE credential projection...")
        pending_projection = begin_credential_projection(
            api_client,
            region=region,
            env_id=env_id,
            timeout=args.http_timeout,
            proxy_url=getattr(args, "proxy", None),
            proxy_insecure=getattr(args, "proxy_insecure", False),
        )

    try:
        _wait_for_running(api_client, env_id, args.env_wait_timeout, emit=emit)
    except _EnvironmentStateError as exc:
        raise BootstrapError(f"Environment entered terminal state: {exc.status}") from exc
    except _EnvironmentWaitTimeout as exc:
        raise BootstrapError(
            f"Environment did not reach RUNNING within {args.env_wait_timeout}s"
        ) from exc


    emit("Creating CloudShell session...")
    sess_resp = api_client.open_stream(env_id)
    stream_url = sess_resp.get("stream_url")
    token_value = sess_resp.get("token_value")
    if not stream_url or not token_value:
        raise BootstrapError("open_stream did not return stream_url or token_value")


    try:
        api_session_creds = api_client.get_session_creds()


        upgraded_from_akia = not credentials.extra.get("session_token")
        if upgraded_from_akia and api_session_creds.expiration:
            credentials.extra["cached_upgrade"] = api_session_creds.to_cache_dict()


        if pending_projection is not None:
            pending_projection.finish()
            emit("✓ OAuth credential projection complete")
    except Exception as oauth_exc:


        emit(
            f"WARNING: credential projection FAILED: {oauth_exc}\n"
            "  The shell will open, but AWS CLI calls inside it will fail with a "
            "container-role 500 -- no credentials were projected.\n"
            "  Reconnect to retry; if it persists, run with -v to see the "
            "redeemCode/putCredentials exchange."
        )
        log(
            f"[bootstrap] credential projection FAILED region={region} "
            f"env_id={env_id}: {oauth_exc}"
        )

    emit("✓ Session created")
    from cloudbasher.csp.aws.api import session_kwargs_from_stream_info

    session = provider.create_session(
        credentials,
        env_id,


        **session_kwargs_from_stream_info(sess_resp),
        api_client=api_client,
        timeout=args.ws_timeout,
    )

    return _finish_aws_bootstrap(
        args=args,
        session=session,
        api_client=api_client,
        env_id=env_id,
        region=region,
        emit=emit,


        on_reproject=make_reprojector(
            pending_projection,
            lambda: api_client,
            region=region,
            env_id=env_id or "",
            timeout=args.http_timeout,
            proxy_url=getattr(args, "proxy", None),
            proxy_insecure=getattr(args, "proxy_insecure", False),
        ),
    )


def _bootstrap_azure_session(
    *,
    state: InteractiveState,
    args: Any,
    provider: Any,
    credentials: Any,
    saved: dict,
    emit: Callable[[str], None],
) -> _BootstrapResult:
    """Azure branch of _bootstrap_session: session bootstrap via csp.azure.lib, plus the azure-only state.extra["azure_console"/"azure_terminal"] mutation."""
    emit("Bootstrapping Azure CloudShell session...")
    from cloudbasher.csp.azure import lib as az_lib
    from cloudbasher.csp.azure.types import CommandRunOptions as AzOpts

    az_opts = AzOpts(
        shell=getattr(args, "shell", "bash") or "bash",
        env_wait_timeout=args.env_wait_timeout,
        http_timeout=args.http_timeout,
        ws_timeout=args.ws_timeout,
        proxy_url=args.proxy,
        proxy_insecure=args.proxy_insecure,
    )
    saved_console = None
    saved_terminal = None
    if args.resume and saved:
        from cloudbasher.csp.azure.types import ConsoleInfo as CI
        from cloudbasher.csp.azure.types import TerminalInfo as TI

        sc = saved.get("azure_console")
        st = saved.get("azure_terminal")
        if sc:
            try:
                saved_console = CI.from_dict(sc)
            except Exception:
                pass
        if st:
            try:
                saved_terminal = TI.from_dict(st)
            except Exception:
                pass


    api_client = provider.create_api_client(
        credentials,
        timeout=args.http_timeout,
        proxy_url=args.proxy,
        proxy_insecure=args.proxy_insecure,
    )
    az_console, az_terminal, session = az_lib.bootstrap_session(
        credentials,
        az_opts,
        reuse=args.resume,
        saved_console=saved_console,
        saved_terminal=saved_terminal,
        api_client=api_client,
    )
    if not hasattr(state, "extra") or state.extra is None:
        state.extra = {}
    state.extra["azure_console"] = az_console
    state.extra["azure_terminal"] = az_terminal
    region = az_console.region
    env_id = az_console.console_id
    emit(f"Azure CloudShell ready: console={env_id} region={region}")
    from cloudbasher.csp.azure.relay_keepalive import start_session_relay_keepalive

    keepalive = start_session_relay_keepalive(session)

    return _BootstrapResult(
        api_client=api_client,
        session_obj=session,
        env_id=env_id,
        region=region,
        keepalive=keepalive,
    )


def _bootstrap_gcp_session(
    *,
    state: InteractiveState,
    args: Any,
    provider: Any,
    credentials: Any,
    env_id: Optional[str],
    emit: Callable[[str], None],
    wait_mode: str,
    credential_record: Optional[CredentialRecord] = None,
) -> _BootstrapResult:
    browser_sessions: list[Any] = []
    return _bootstrap_gcp_session_impl(
        state=state, args=args, provider=provider, credentials=credentials,
        env_id=env_id, emit=emit, wait_mode=wait_mode,
        browser_sessions=browser_sessions,
        credential_record=credential_record,
    )


def _bootstrap_gcp_session_impl(
    *,
    state: InteractiveState,
    args: Any,
    provider: Any,
    credentials: Any,
    env_id: Optional[str],
    emit: Callable[[str], None],
    wait_mode: str,
    browser_sessions: list[Any],
    credential_record: Optional[CredentialRecord] = None,
) -> _BootstrapResult:
    """GCP branch of _bootstrap_session: private-API (cookie-auth + WebSocket SSH) or public-API (OAuth2 + direct TCP SSH) session bootstrap."""


    _browser = browser_options(args)
    emit("Bootstrapping GCP CloudShell environment...")
    quota_project = _resolve_gcp_quota_project(args, credentials)
    configured_api_path = getattr(args, "api_path", "public") or "public"
    _gcp_needs_browser = bool(credentials.extra.get("_needs_playwright"))
    _gcp_has_cookies = bool(credentials.extra.get("cookies"))


    api_path = (
        "private"
        if _gcp_needs_browser or _gcp_has_cookies
        else configured_api_path
    )
    if api_path != configured_api_path:
        log("GCP private API path selected from this credential's Console/cookie shape")


    console_oauth: dict[str, Any] = {}
    console_oauth_ready = threading.Event()
    console_oauth_request_seen = threading.Event()
    console_oauth_activity = threading.Event()
    pkey = None
    pub_key_str = None
    if api_path == "private" and getattr(args, "gcp_pw_email", None) and not _gcp_needs_browser:
        log(
            "GCP browser login declined: this credential is not console-shaped, "
            "so a sign-in belonging to another credential block will not be run "
            "for it (its cookies would be written onto this credential)"
        )
    if api_path == "private" and _gcp_needs_browser and not credentials.extra.get("cookies"):
        emit("Capturing browser cookies via Playwright (private API path)...")
        from cloudbasher.csp.gcp.playwright_login import (
            GCPBrowserSession,
        )
        from cloudbasher.csp.gcp.playwright_login import (
            playwright_login_for_cookies as gcp_pw_login,
        )

        if credentials.extra.get("project_id"):
            from cloudbasher.csp.gcp.session import generate_ssh_keypair


            pkey, pub_key_str = generate_ssh_keypair()

        def _remember_console_oauth(payload: dict[str, Any]) -> None:


            console_oauth.clear()
            console_oauth.update(payload)
            console_oauth_ready.set()
            console_oauth_activity.set()

        def _remember_console_oauth_request() -> None:
            console_oauth_request_seen.set()
            console_oauth_activity.set()

        def _remember_console_xsrf(token: str) -> None:


            credentials.extra["xsrf_token"] = token

        login_kwargs: dict[str, Any] = {
            "headless": _browser.headless,
            "project_id": credentials.extra.get("project_id"),
            "setupsession_public_key": pub_key_str,
            "proxy_url": _browser.proxy_url,
            "proxy_insecure": _browser.proxy_insecure,
            "wait_mode": wait_mode,


            "prefill_email": (
                credentials.extra.get("pw_username") or getattr(args, "gcp_pw_email", None)
            ),
            "password": credentials.extra.get("pw_password"),
            "oauth_token_callback": _remember_console_oauth,
            "oauth_request_callback": _remember_console_oauth_request,
            "xsrf_token_callback": _remember_console_xsrf,
            "keep_browser_open": True,
            "capture_login_screenshots": bool(getattr(args, "show_browser", False)),
        }
        captured = gcp_pw_login(
            **login_kwargs,
        )
        if isinstance(captured, GCPBrowserSession):
            browser_sessions.append(captured)


            from cloudbasher.csp.gcp.provider import retain_browser_session

            retain_browser_session(state, captured)
            credentials.extra["cookies"] = captured.cookies
            credentials.extra["_diagnostics_dir"] = str(captured.diagnostics_dir)
            import json

            from cloudbasher.csp.gcp.diagnostics import write_private

            write_private(
                captured.diagnostics_dir,
                "session-material.json",
                json.dumps(
                    {
                        "google_cookies": captured.cookies,
                        "browser_oauth_response": console_oauth,
                        "browser_xsrf_token": credentials.extra.get("xsrf_token"),
                    },
                    ensure_ascii=False,
                    indent=2,
                ).encode("utf-8"),
            )
        else:
            credentials.extra["cookies"] = captured


        credentials.extra.pop("pw_password", None)
        cookie_count = (
            len(captured.cookies)
            if isinstance(captured, GCPBrowserSession)
            else len(captured)
        )
        emit(f"✓ Captured {cookie_count} Google session cookies")

    api_client = provider.create_api_client(
        credentials,
        api_path=api_path,
        timeout=args.http_timeout,
        proxy_url=args.proxy,
        proxy_insecure=args.proxy_insecure,
        quota_project=quota_project,
        request_executor=(browser_sessions[-1].request if browser_sessions else None),
    )
    diagnostics_dir = credentials.extra.pop("_diagnostics_dir", None)
    env_id = env_id or "default"

    from cloudbasher.csp.gcp.private_api import (
        GCSPrivateAPI,
        extract_tab_id,
    )

    if isinstance(api_client, GCSPrivateAPI):

        if credentials.extra.get("xsrf_token"):
            emit("GCP private API: using browser-context XSRF token")
        else:
            emit("GCP private API: obtaining XSRF token...")
            api_client.new_token()


        emit("Reading Cloud Shell user and terminal state...")
        api_client.user_state()
        api_client.quota()
        tabs_raw = api_client.list_tabs()
        api_client.terminal_theme()

        from cloudbasher.csp.gcp.session import generate_ssh_keypair, private_key_to_pem

        if pkey is None or pub_key_str is None:
            pkey, pub_key_str = generate_ssh_keypair()


        emit("Starting environment and setting up session (setupsession)...")
        native_setupsession = (
            browser_sessions[-1].native_setupsession_response
            if credentials.extra.get("project_id") and browser_sessions
            else None
        )
        if native_setupsession is not None:
            sess_result = api_client.parse_setup_session_response(native_setupsession)
            log("[gcp.bootstrap] reusing native Console setupsession response")
        else:
            sess_result = api_client.setup_session(pub_key_str)
        session_token = sess_result.get("session_token")
        if not session_token:
            raise BootstrapError("setupsession did not return a session token")


        env_arr = sess_result.get("environment")
        env_p = _parse_private_env(env_arr) if env_arr else {}
        emit("Checking environment state...")
        env_raw = api_client.environments_list()
        env_p = _parse_private_env(env_raw) or env_p
        wait_start = time.time()
        while env_p.get("state", 0) != 3:
            if time.time() - wait_start > args.env_wait_timeout:
                raise BootstrapError(
                    f"Environment did not reach RUNNING within {args.env_wait_timeout}s"
                )
            emit(f"Environment state: {env_p.get('state', 0)} (waiting...)")
            time.sleep(3)
            env_raw = api_client.environments_list()
            env_p = _parse_private_env(env_raw) or env_p
        emit("Environment is RUNNING")

        web_host = env_p.get("web_host", "")
        ssh_username = env_p.get("ssh_username", "")
        ssh_port = int(env_p.get("ssh_port", 6000) or 6000)

        if not web_host:
            raise BootstrapError(
                "setup_session did not return a cloudshell.dev hostname"
                " — verify cookies are valid"
            )

        api_client.save_tab(ssh_port, extract_tab_id(tabs_raw))


        emit("Preparing Cloud Shell WebSocket access token...")
        cloudshell_access_token = api_client.generate_access_token(
            f"users/me/environments/{env_id}"
        )

        ssh_key_pem = private_key_to_pem(pkey)
        emit(f"✓ Session ready web_host={web_host} user={ssh_username}")

        session = provider.create_session(
            credentials,
            env_id,
            web_host=web_host,
            session_token=session_token,
            cloudshell_access_token=cloudshell_access_token,
            cookies=credentials.extra.get("cookies"),
            ssh_username=ssh_username,
            ssh_key=ssh_key_pem,
            timeout=args.ws_timeout,
            proxy_url=args.proxy,
            proxy_insecure=args.proxy_insecure,
            diagnostics_dir=diagnostics_dir,
        )


        session.ensure_persistent_shell()


        if _gcp_needs_browser and browser_sessions and not console_oauth_ready.is_set():
            console_oauth_activity.wait(35.0)
            if not console_oauth_ready.is_set() and not console_oauth_request_seen.is_set():
                if browser_sessions:
                    emit("Requesting the native Cloud Shell OAuth token...")
                    try:
                        token_payload = browser_sessions[-1].issue_cloudshell_oauth_token()
                        if token_payload.get("access_token"):
                            _remember_console_oauth(token_payload)
                    except Exception as exc:
                        log(
                            "[gcp.bootstrap] native issueToken request failed "
                            f"({type(exc).__name__}); details omitted"
                        )
            if not console_oauth_ready.is_set():
                token_wait = 35.0 if console_oauth_request_seen.is_set() else 15.0
                if console_oauth_ready.wait(token_wait):
                    log(
                        "[gcp.bootstrap] native OAuth token response received "
                        "after terminal readiness"
                    )
                elif console_oauth_request_seen.is_set():
                    log(
                        "[gcp.bootstrap] native issueToken request was observed, "
                        f"but no usable OAuth response arrived within {token_wait:g}s"
                    )
                else:
                    log(
                        "[gcp.bootstrap] no native issueToken request or OAuth "
                        "response was observed"
                    )

        if isinstance(console_oauth, dict) and console_oauth.get("access_token"):
            scopes = set(str(console_oauth.get("scope") or "").split())
            if "https://www.googleapis.com/auth/cloud-platform" in scopes:
                emit("Projecting the observed Google user OAuth token into Cloud Shell...")
                try:
                    api_client.environments_authorize(
                        f"users/me/environments/{env_id}",
                        access_token=str(console_oauth["access_token"]),
                        id_token=(
                            str(console_oauth["id_token"])
                            if console_oauth.get("id_token")
                            else None
                        ),
                        expires_in=(
                            int(console_oauth.get("expires_in"))
                            if str(console_oauth.get("expires_in", "")).isdigit()
                            else 3600
                        ),
                    )
                    emit("✓ Cloud Shell user credentials authorized")
                except Exception as exc:


                    emit(
                        "Warning: terminal is ready, but Google user credentials "
                        f"could not be authorized ({type(exc).__name__}); "
                        "in-container gcloud authentication may be unavailable."
                    )
            else:
                emit(
                    "Warning: browser token did not include the Cloud Shell "
                    "`cloud-platform` scope; "
                    "the terminal may open without authenticated `gcloud` access."
                )
            project_id = str(credentials.extra.get("project_id") or "").strip()
            if (
                project_id
                and credential_record is not None
                and "https://www.googleapis.com/auth/cloud-platform" in scopes
            ):
                try:
                    from cloudbasher.csp.gcp.credentials import resolve_project_organization

                    org_id, org_name = resolve_project_organization(
                        str(console_oauth["access_token"]),
                        project_id,
                        quota_project=quota_project,
                        proxy_url=args.proxy,
                        proxy_insecure=args.proxy_insecure,
                    )
                    if org_id:
                        credential_record._resolved_account = org_id
                        credential_record._resolved_organization_name = org_name
                except Exception as exc:


                    log(
                        "[gcp.identity] configured project organization lookup "
                        f"unavailable ({type(exc).__name__})"
                    )
            console_oauth.clear()
        elif _gcp_needs_browser:
            emit(
                "Warning: no Cloud Shell OAuth token response was captured; "
                "the terminal can still open, but in-container Google CLI "
                "authentication is not confirmed."
            )
            if str(credentials.extra.get("project_id") or "").strip():
                emit(
                    "Warning: organization discovery for the configured project was skipped "
                    "because Console did not return a Google OAuth token."
                )

        emit(f"✓ SSH-over-WebSocket session ready ({ssh_username}@{web_host})")
        emit(f"environment_id={env_id} startup_session_bootstrapped=true api_path=private")
        from cloudbasher.csp.gcp.heartbeat import start_session_pty_keepalive

        keepalive = start_session_pty_keepalive(session)

        return _BootstrapResult(
            api_client=api_client,
            session_obj=session,
            env_id=env_id,
            region="",
            keepalive=keepalive,
            web_host=web_host,
            control_plane_evidence="accepted",
        )

    else:

        env_name = (
            f"users/me/environments/{env_id}"
            if env_id and env_id != "default"
            else "users/me/environments/default"
        )

        try:
            env = api_client.get_environment(env_name)
        except CloudShellAutomationError as quota_err:
            from cloudbasher.csp.gcp.diagnostics import (
                is_quota_project_service_usage_denial,
                quota_project_service_usage_message,
            )

            if quota_err.status_code == 403 and is_quota_project_service_usage_denial(
                quota_err.response_body or str(quota_err)
            ):
                message = quota_project_service_usage_message(quota_project)
                log(f"[gcp.provision] {message}")
                raise BootstrapError(message) from quota_err
            if "quota project" in str(quota_err).lower() and not quota_project:
                if args.resume:
                    emit("Stored credentials need quota project — re-authenticating via OAuth...")
                    from cloudbasher.csp.gcp.credentials import GCPCredentialProvider as GCPcp

                    fresh = GCPcp(device_code=args.device_code)
                    new_creds = fresh.reauth_via_browser_or_device_code(
                        skip_browser=args.device_code,
                    )
                    if new_creds:
                        credentials = new_creds
                        state.credentials = credentials
                        quota_project = _resolve_gcp_quota_project(args, credentials)
                        api_client = provider.create_api_client(
                            credentials,
                            api_path=api_path,
                            timeout=args.http_timeout,
                            proxy_url=args.proxy,
                            proxy_insecure=args.proxy_insecure,
                            quota_project=quota_project,
                        )
                        env = api_client.get_environment(env_name)
                    else:
                        raise BootstrapError(
                            "GCP API requires a quota project and OAuth re-auth failed.\n"
                            "  Fix: set quota_project_id=<project-id> in this GCP credential block."
                        ) from quota_err
                else:
                    raise BootstrapError(
                        "GCP API requires a quota project.\n"
                        "  Fix: set quota_project_id=<project-id> in this GCP credential block."
                    ) from quota_err
            else:
                raise
        state_val = env.get("state", "")

        from cloudbasher.csp.gcp.session import generate_ssh_keypair, private_key_to_pem

        pkey, pub_key_str = generate_ssh_keypair()
        ssh_key_pem = private_key_to_pem(pkey)
        initial_access_token = getattr(api_client, "access_token", None)
        if not isinstance(initial_access_token, str) or not initial_access_token:
            initial_access_token = credentials.access_token
        use_start_credentials = bool(
            state_val != "RUNNING"
            and isinstance(initial_access_token, str)
            and initial_access_token
            and not credentials.extra.get("service_account_email")
        )

        if state_val != "RUNNING":
            if use_start_credentials:
                emit("Starting environment with SSH key and OAuth credentials...")
                op = api_client.start_environment(
                    env_id or "default",
                    access_token=initial_access_token,
                    public_keys=[pub_key_str],
                )
            else:
                emit(f"Environment is {state_val or 'SUSPENDED'}, starting...")
                op = api_client.start_environment(env_id or "default")
            op_name = op.get("operation_name", "")
            if op_name:
                emit("Waiting for start operation...")
                api_client.wait_operation(op_name, timeout=args.env_wait_timeout)

            wait_start = time.time()
            while time.time() - wait_start < args.env_wait_timeout:
                env = api_client.get_environment(env_name)
                state_val = env.get("state", "")
                if state_val == "RUNNING":
                    break
                emit(f"Environment state: {state_val} (waiting...)")
                time.sleep(3)
            else:
                raise BootstrapError(
                    f"Environment did not reach RUNNING within {args.env_wait_timeout}s"
                )

        emit("Environment is RUNNING")
        ssh_host = env.get("ssh_host", "")
        ssh_port = int(env.get("ssh_port", 22))
        ssh_username = env.get("ssh_username", "root")

        if not ssh_host:
            raise BootstrapError("Environment has no SSH host (may still be provisioning)")

        if use_start_credentials:
            emit("✓ SSH key and OAuth credentials submitted with environment start")
        else:
            emit("Setting up SSH key...")
            op = api_client.add_public_key(env_name, key=pub_key_str)
            op_name = op.get("operation_name", "")
            if op_name:
                api_client.wait_operation(op_name, timeout=60)
            time.sleep(1)
            emit("✓ SSH key added")

        session = provider.create_session(
            credentials,
            env_id,
            ssh_host=ssh_host,
            ssh_port=ssh_port,
            ssh_username=ssh_username,
            ssh_key=ssh_key_pem,
            timeout=args.ws_timeout,
        )


        session.ensure_persistent_shell()


        api_access_token = getattr(api_client, "access_token", None)
        shell_access_token = (
            api_access_token
            if isinstance(api_access_token, str) and api_access_token
            else credentials.access_token
        )
        if isinstance(shell_access_token, str) and shell_access_token and not credentials.extra.get(
            "service_account_email"
        ):
            if not use_start_credentials:
                emit("Projecting OAuth credentials into Cloud Shell...")
                auth_result = api_client.authorize_environment(
                    env_name,
                    access_token=shell_access_token,
                )
                auth_op = (
                    auth_result.get("operation_name", "")
                    if isinstance(auth_result, dict)
                    else ""
                )
                if auth_op:
                    api_client.wait_operation(auth_op, timeout=60)
                emit("✓ Cloud Shell OAuth credentials authorized")

        emit(f"✓ SSH session ready ({ssh_username}@{ssh_host}:{ssh_port})")
        emit(f"project={quota_project or env_id} startup_session_bootstrapped=true")
        from cloudbasher.csp.gcp.heartbeat import start_session_pty_keepalive

        keepalive = start_session_pty_keepalive(session)

        return _BootstrapResult(
            api_client=api_client,
            session_obj=session,
            env_id=env_id or "",
            region="",
            keepalive=keepalive,
            control_plane_evidence="accepted",
        )


def _activate_target_identity(
    rec: CredentialRecord,
    credentials_by_id: dict[str, CredentialRecord],
    emit: Callable[[str], None],
    requested_name: Optional[str] = None,
) -> str:
    """Derive-and-record the ONE target identity `rec` gets upgraded to, and return that target CredentialRecord's id (or `rec.id` unchanged if no upgrade applies or the derivation failed)."""
    from cloudbasher.csp.aws.credentials import (
        derive_target_credentials,
        resolve_identity_name,
        resolve_target_identity,
        session_creds_from_extra,
    )

    if rec.provider != "aws":
        return rec.id
    if rec.kind != "permanent":
        return rec.id


    raw = session_creds_from_extra(rec.raw.extra)
    try:


        name, name_source = resolve_identity_name(raw, requested_name, where=f"activating {rec.id}")
        identity = resolve_target_identity(raw, name=name, name_source=name_source)
        derived = derive_target_credentials(raw, identity)
    except Exception as exc:
        emit(f"target-identity activation failed for {rec.id}: {exc}")
        return rec.id


    from cloudbasher.csp.aws.commands import derived_target_id, derived_target_record

    target_id = derived_target_id(rec.id, identity.kind, identity.ref, name)


    credentials_by_id[target_id] = derived_target_record(
        parent_rec=rec,
        target_id=target_id,
        label=identity.ref,
        upgraded=derived,
        target_kind=identity.kind,
        target_ref=identity.ref,
        target_session_name=identity.session_name,
        target_duration_seconds=identity.duration_seconds,
    )
    _emit_target_identity(identity, emit)
    return target_id


def _require_act_as(credentials: Credentials, *, where: str) -> Optional["ActAs"]:
    """Every AWS key-based credential must declare what identity it acts as."""
    from cloudbasher.csp.aws.act_as import act_as_from_extra, validate_act_as

    extra = credentials.extra or {}
    access_key = extra.get("access_key", "")
    if not access_key:
        return None
    from cloudbasher.csp.aws.act_as import act_as_mode_of

    if not act_as_mode_of(extra):
        raise CredentialError(
            f"{where}: this AWS credential must declare ACT_AS.\n"
            "\n"
            "  ACT_AS=role:<role-arn>   assume that role\n"
            "  ACT_AS=federated         federate\n"
            "  ACT_AS=direct            use this session token as-is\n"
            "\n"
            "Whichever mode you pick, the derived principal's NAME is named per "
            "action or declared in this same block (FEDERATION_NAME for a "
            "federating action, ROLE_SESSION_NAME for one that assumes a role -- "
            "whichever the action derives, not this ACT_AS).\n"
            "\n"
            "Required rather than defaulted because the resulting identity is a "
            "namespace: CloudShell only shows you environments created by the "
            "same principal, so guessing it would silently decide which "
            "environments .enum/.register/.delete can even see."
        )


    act_as = act_as_from_extra(extra)
    assert act_as is not None
    validate_act_as(act_as, is_akia=not extra.get("session_token"), where=where)
    return act_as


def _target_identity_label(identity: "TargetIdentity") -> str:
    """The same short "<kind>/<name>" form the Nodes table's Target Identity column shows, so the startup line and the table cannot describe the node differently."""
    if identity.kind == "assume_role":
        return f"role/{identity.session_name}"
    return f"federated/{identity.ref}"


def _emit_target_identity(identity: "TargetIdentity", emit: Callable[[str], None]) -> None:
    """Announce the identity a credential was upgraded to, its NAME, and where that name came from."""
    from cloudbasher.csp.aws.credentials import describe_name_source

    label = _target_identity_label(identity)
    if identity.kind == "assume_role":
        emit(f"target identity: {label}  (role {identity.ref})")
    else:
        emit(f"target identity: {label}")
    key = "ROLE_SESSION_NAME" if identity.kind == "assume_role" else "FEDERATION_NAME"
    emit(f"  {describe_name_source(identity.name_source, key=key)}")


_CREDS_SOURCE_FLAG = {"file": "--creds-file", "env": "--creds-env", "resume": "--resume"}


def _emit_identity_listing(
    credentials_by_id: dict[str, CredentialRecord],
    *,
    source: str,
    path: Optional[str],
    emit: Callable[[str], None],
) -> None:
    """List every loaded identity with where it came from and what it acts as."""
    from cloudbasher.core.identity_listing import build_identity_rows, emit_identity_rows

    flag = _CREDS_SOURCE_FLAG[source]
    where = f"{path} ({flag})" if path else flag


    from cloudbasher.core.utils.redact import register_identity_names_from

    register_identity_names_from(credentials_by_id)

    rows = build_identity_rows(credentials_by_id)


    if not rows:
        emit(f"No identities registered from {where} (see the credentials= line below).")
        return
    emit(f"Identities loaded from {where}:")
    emit_identity_rows(rows, emit=emit, detail=detail)


_PRIMARY_NODE_SUFFIX = "primary"
_LEGACY_PRIMARY_NODE_SUFFIX = "default"


def _primary_node_id(credential_id: str) -> str:
    """The node id for a credential's own bootstrapped session."""
    return f"{credential_id}:{_PRIMARY_NODE_SUFFIX}"


def _find_primary_node(
    nodes_by_id: dict[str, NodeRecord], credential_id: str
) -> Optional[NodeRecord]:
    """A credential's already-registered primary node, if any -- accepting the pre-Phase-28 ":primary" id so a --resume from an older state file finds its restored node instead of registering a second one beside it."""
    node = nodes_by_id.get(_primary_node_id(credential_id))
    if node is not None:
        return node
    return nodes_by_id.get(f"{credential_id}:{_LEGACY_PRIMARY_NODE_SUFFIX}")


def _gcp_console_record_for_credentials(
    credentials_by_id: dict[str, CredentialRecord], credentials: Any
) -> Optional[CredentialRecord]:
    """Find the GCP Console row corresponding to the loaded runtime credential."""
    runtime_extra = credentials.extra or {}
    username = runtime_extra.get("pw_username") or runtime_extra.get("username")
    project_id = runtime_extra.get("project_id")
    quota_project_id = runtime_extra.get("quota_project_id")
    return next(
        (
            record
            for record in credentials_by_id.values()
            if record.provider == "gcp"
            and record.kind == "console"
            and (
                (record.raw.extra or {}).get("pw_username")
                or (record.raw.extra or {}).get("username")
            )
            == username
            and (record.raw.extra or {}).get("project_id") == project_id
            and (record.raw.extra or {}).get("quota_project_id") == quota_project_id
        ),
        None,
    )


def _bootstrap_session(
    *,
    state: InteractiveState,
    args: Any,
    provider: Any,
    csp_name: str,
    saved: dict,
    emit: Callable[[str], None],
    gcp_wait_mode: str,
    region_override: Optional[str] = None,
    connect: bool = True,
) -> Any:
    """Load credentials, bring up the CSP environment/session, and mutate `state` in place (credentials, api_client, session, heartbeat_stop, _session_obj, and -- for Azure -- extra["azure_console"/"azure_terminal"]). Returns a CommandDispatcher constructed for provider.on_session_ready()."""
    if csp_name == "aws":


        _region = args.region
        emit(
            f"Using AWS CloudShell (region: {_region})"
            if _region
            else "Using AWS CloudShell (region: not set -- name one with "
            "`--region` or `.provision <ID> region <selector>`)"
        )
    elif csp_name == "azure":
        _tenant = getattr(args, "tenant", None) or ""
        emit(f"Using Azure CloudShell (tenant: {_tenant or 'auto-detect'})")
    else:
        emit("Using GCP Cloud Shell")

    state.args = args


    _creds_source = resolve_creds_source(args)


    _declared_records = getattr(args, "_multi_credential_records", [])
    if csp_name in {"azure", "gcp"} and _creds_source == "file" and _declared_records:
        state.credentials_by_id.update({rec.id: rec for rec in _declared_records})
        _emit_identity_listing(
            state.credentials_by_id,
            source=_creds_source,
            path=getattr(args, "creds_file", None),
            emit=emit,
        )
        emit(
            f"{csp_name.upper()} credentials registered; run `.provision <ID>` "
            "to explicitly create/reuse and open Cloud Shell."
        )
        from cloudbasher.core.cli.dispatcher import CommandDispatcher

        dispatcher = CommandDispatcher(provider)
        provider.register_dot_commands(dispatcher)
        return dispatcher

    cred_provider = provider.create_credential_provider(
        credential_file=args.creds_file,
        device_code=args.device_code,
        region=args.region,
        project_id=getattr(args, "project", None),
        tenant_id=getattr(args, "tenant", None),
        subscription_id=getattr(args, "subscription", None),
        no_browser=getattr(args, "no_browser", False),
        login_hint=getattr(args, "login_hint", None),
        show_browser=bool(getattr(args, "show_browser", False)),


        proxy_url=getattr(args, "proxy", None),
        proxy_insecure=bool(getattr(args, "proxy_insecure", False)),
        saved_state=saved,
        source=_creds_source,
    )
    emit("Loading credentials...")
    credentials = cred_provider.load()
    emit("✓ Credentials loaded")
    if csp_name == "aws":


        _resolve_sso_credential_in_place(credentials, args, emit)


        _require_act_as(credentials, where=_creds_source_where(args, _creds_source))
    state.credentials = credentials


    _fresh_records = getattr(args, "_multi_credential_records", [])
    _fresh_by_id = {rec.id: rec for rec in _fresh_records}
    state.credentials_by_id.update(_fresh_by_id)


    if csp_name == "aws":
        _ensure_originating_records(state, "aws", credentials)
    _emit_identity_listing(
        state.credentials_by_id,
        source=_creds_source,
        path=getattr(args, "creds_file", None),
        emit=emit,
    )
    if saved:
        emit(f"Resuming from saved state (saved_at={saved.get('saved_at', '?')})")
    emit(f"credentials={_fmt_cred_summary(credentials)}")

    env_id = args.environment_id or saved.get("environment_id") or None
    region = region_override or args.region or saved.get("region") or None

    if csp_name == "azure":
        if args.resume and not connect:


            emit(
                "Azure CloudShell restored without connecting; no console request was made. "
                "Use `.connect <selector>` to reconnect."
            )
            result = _BootstrapResult(
                api_client=None,
                session_obj=None,
                env_id=env_id or "",
                region=region or "",
                container_status="Unknown",
                web_host=saved.get("web_host", ""),
            )
        else:
            result = _bootstrap_azure_session(
                state=state,
                args=args,
                provider=provider,
                credentials=credentials,
                saved=saved,
                emit=emit,
            )
    elif csp_name == "aws":


        primary_rec = _ensure_originating_records(state, "aws", credentials)
        _orig_emit = emit
        _primary_rec_id = primary_rec.id

        def emit(text: str) -> None:
            _orig_emit(f"[{_primary_rec_id}] {text}")

        aws_bootstrap_fn = _bootstrap_aws_session if connect else _register_aws_node
        result = aws_bootstrap_fn(
            args=args,
            provider=provider,
            credentials=credentials,
            env_id=env_id,
            region=region,
            emit=emit,


            credential_record=primary_rec,
            credential_registry=state.credentials_by_id,
        )
        if connect and result.session_obj is not None:


            from cloudbasher.core.identity_listing import mark_credential_verified

            mark_credential_verified(primary_rec, state.credentials_by_id)
    else:
        gcp_record = _gcp_console_record_for_credentials(
            state.credentials_by_id, credentials
        )
        result = _bootstrap_gcp_session(
            state=state,
            args=args,
            provider=provider,
            credentials=credentials,
            env_id=env_id,
            emit=emit,
            wait_mode=gcp_wait_mode,
            credential_record=gcp_record,
        )

    state.api_client = result.api_client
    state.session = SessionInfo(
        environment_id=result.env_id or "",


        region=result.region or "",
        user=saved.get("user", "unknown"),
        hostname=saved.get("hostname", "unknown"),
        ip_address=saved.get("ip_address", "unknown"),
        web_host=result.web_host or saved.get("web_host", "unknown"),
    )


    if result.keepalive is not None:


        heartbeat_stop = getattr(result.keepalive, "heartbeat_stop", None)
        heartbeat_thread = getattr(result.keepalive, "heartbeat_thread", None)
        if heartbeat_stop is not None:
            state.heartbeat_stop = heartbeat_stop
        if heartbeat_thread is not None:
            state.heartbeat_thread = heartbeat_thread


    state._keepalive_handles = result.keepalive
    if result.session_obj is not None:
        state._session_obj = result.session_obj

    from cloudbasher.core.cli.dispatcher import CommandDispatcher

    dispatcher = CommandDispatcher(provider)
    provider.register_dot_commands(dispatcher)
    provider.on_session_ready(state, args)

    if csp_name == "aws":


        primary_rec = _ensure_originating_records(state, "aws", credentials)


        node_credential_id = primary_rec.id
        existing_node = _find_primary_node(state.nodes_by_id, primary_rec.id)
        if existing_node is not None or connect:
            node = existing_node or NodeRecord(
                id=_primary_node_id(primary_rec.id),
                credential_id=node_credential_id,
                region=None,
                environment_id=None,
                session=None,
                container_status="Pending",
            )
            node.credential_id = node_credential_id
            node.region = state.session.region if state.session else None
            node.environment_id = state.session.environment_id if state.session else None
            node.session = state.session


            if result.container_status is None:
                node.container_status = "Running"
            elif result.container_status != "Unknown":
                node.container_status = result.container_status
            node.end_connect()
            node._runtime_session = getattr(state, "_session_obj", None)
            node._runtime_api_client = state.api_client
            _record_session_control_plane_evidence(node, node._runtime_session)
            _attach_keepalives(node, result.keepalive)
            _probe_after_bootstrap(node, emit)
            state.register_node(node)
            state.active_node_id = node.id

    if args.multi_node:


        _ensure_originating_records(state, csp_name, credentials)
        _bootstrap_multi_csp_nodes(
            state=state,
            args=args,
            csp_name=csp_name,
            emit=emit,
            gcp_wait_mode=gcp_wait_mode,
            connect=connect,
            on_node_change=getattr(state, "on_node_change", None) or (lambda _n: None),
        )

    return dispatcher


def records_from_creds_file(args: Any) -> list[CredentialRecord]:
    """Every CredentialRecord an ``-F`` file declares, or [] when no file is named."""
    if not getattr(args, "creds_file", None):
        return []
    from cloudbasher.core.credential_file import (
        build_credential_records,
        parse_multi_creds_file,
    )

    try:
        parsed = parse_multi_creds_file(args.creds_file)
    except OSError:
        return []


    records = [
        build_credential_records(
            pb.provider,
            pb.parsed,
            source_block=pb.block,
            description=pb.description,
        )
        for pb in parsed
    ]


    _disambiguate_colliding_ids(records)
    if records:
        log(
            f"credential file parsed: {len(records)} identities across "
            f"{len({r.provider for r in records})} CSP(s)"
        )
    return records


def _disambiguate_colliding_ids(records: list[CredentialRecord]) -> None:
    """Keep two different blocks from collapsing into one registry entry."""
    seen: set[str] = set()
    renamed: list[tuple[str, str]] = []
    for rec in records:
        block = rec.source_block
        if rec.id not in seen:
            seen.add(rec.id)
            continue
        if block is None:


            continue
        original = rec.id
        rec.id = f"{rec.id}#b{block}"
        seen.add(rec.id)
        renamed.append((original, rec.id))

    for original, new_id in renamed:
        out(
            f"credential id collision: two blocks produced the id {original!r}; "
            f"the later one is now {new_id!r} so both stay addressable"
        )


def _ensure_originating_records(
    state: InteractiveState, csp_name: str, credentials: Credentials
) -> CredentialRecord:
    """Register this credential's originating record for ``csp_name`` if none exists yet, and return it."""
    from cloudbasher.core.credential_file import build_credential_records_for_credentials

    existing = [
        rec
        for rec in state.credentials_by_id.values()
        if rec.role == "originating" and rec.provider == csp_name
    ]
    if existing:
        return existing[0]
    rec = build_credential_records_for_credentials(csp_name, credentials)
    state.credentials_by_id[rec.id] = rec
    return rec


def _bootstrap_primary_node_for_credential(
    *,
    args: Any,
    rec: CredentialRecord,
    emit: Callable[[str], None],
    gcp_wait_mode: str,
    node: Optional[NodeRecord] = None,
    on_node_change: Callable[[NodeRecord], None] = lambda _n: None,
    connect: bool = True,
    credential_registry: Any = None,
) -> NodeRecord:
    """Bootstrap one primary node for a single loaded credential."""
    node = node or NodeRecord(
        id=f"{rec.id}:primary",
        credential_id=rec.id,
        region=None,
        environment_id=None,
        session=None,
        container_status="Pending",
    )


    if node.begin_connect("provision (primary node bootstrap)"):
        on_node_change(node)
    from cloudbasher.core.control_plane_status import record_control_plane_evidence
    from cloudbasher.core.types import CONTROL_PLANE_UNASKED

    record_control_plane_evidence(node, CONTROL_PLANE_UNASKED)

    _orig_emit = emit

    def _phase_emit(text: str) -> None:


        _orig_emit(f"[{rec.id}] {text}")

    emit = _phase_emit


    bootstrap_credentials = rec.raw
    azure_extra = rec.raw.extra or {}
    if rec.provider == "azure" and (
        rec.kind == "console"
        or azure_extra.get("access_token")
        or azure_extra.get("refresh_token")
    ):
        from cloudbasher.csp.azure.credentials import (
            bind_refresh_token_rotation,
            load_credentials_from_record_extra,
        )

        try:
            bootstrap_credentials = load_credentials_from_record_extra(
                azure_extra,
                headless=not bool(getattr(args, "show_browser", False)),
            )
        except Exception as exc:
            from cloudbasher.csp.azure.credentials import mark_credential_rejected

            mark_credential_rejected(rec, credential_registry, exc)
            raise
        if bootstrap_credentials.email and not azure_extra.get("username"):


            azure_extra["username"] = bootstrap_credentials.email
        bind_refresh_token_rotation(bootstrap_credentials, azure_extra)


    gcp_extra = rec.raw.extra or {}
    gcp_data = gcp_extra.get("data") if isinstance(gcp_extra.get("data"), dict) else {}
    if rec.provider == "gcp" and (
        (gcp_extra.get("username") and gcp_extra.get("password"))
        or gcp_extra.get("access_token")
        or gcp_extra.get("refresh_token")
        or gcp_data.get("refresh_token")
    ):
        from cloudbasher.csp.gcp.credentials import load_credentials_from_record_extra

        bootstrap_credentials = load_credentials_from_record_extra(gcp_extra)

    if rec.provider == "aws":
        node_provider = AWSProvider()
        aws_bootstrap_fn = _bootstrap_aws_session if connect else _register_aws_node
        result = _run_node_bootstrap(node, aws_bootstrap_fn,
            args=args,
            provider=node_provider,
            credentials=bootstrap_credentials,
            env_id=None,
            region=None,
            emit=emit,


            credential_record=rec,
            credential_registry=credential_registry,


            on_environment_known=record_env_id_for(node),
        )
    elif rec.provider == "gcp":
        node_provider = GCPProvider()
        scratch_state = InteractiveState(csp_provider=node_provider)
        result = _run_node_bootstrap(node, _bootstrap_gcp_session,
            state=scratch_state,
            args=args,
            provider=node_provider,
            credentials=bootstrap_credentials,
            env_id=None,
            emit=emit,
            wait_mode=gcp_wait_mode,
            credential_record=rec,
        )
    elif rec.provider == "azure":
        node_provider = AzureProvider()
        scratch_state = InteractiveState(csp_provider=node_provider)
        try:
            result = _run_node_bootstrap(node, _bootstrap_azure_session,
                state=scratch_state,
                args=args,
                provider=node_provider,
                credentials=bootstrap_credentials,
                saved={},
                emit=emit,
            )
        except Exception as exc:
            from cloudbasher.csp.azure.credentials import mark_credential_rejected

            mark_credential_rejected(rec, credential_registry, exc)
            raise
    else:
        raise ValueError(f"unknown credential provider: {rec.provider!r}")

    node.region = result.region or None
    node.environment_id = result.env_id or None
    node.session = SessionInfo(
        environment_id=result.env_id or "",
        region=result.region or "",
        user="",
        hostname="",
        ip_address="",
        web_host=result.web_host or "",
    )


    if result.container_status is None:
        node.container_status = "Running"
    elif result.container_status != "Unknown":
        node.container_status = result.container_status


    from cloudbasher.core.identity_listing import mark_credential_verified

    mark_credential_verified(rec, credential_registry)
    node.end_connect()
    node._runtime_session = result.session_obj
    _record_bootstrap_control_plane_evidence(node, result)
    node._runtime_api_client = result.api_client


    _attach_keepalives(node, result.keepalive)
    on_node_change(node)
    return node


def _bootstrap_multi_csp_nodes(
    *,
    state: InteractiveState,
    args: Any,
    csp_name: str,
    emit: Callable[[str], None],
    gcp_wait_mode: str,
    on_node_change: Callable[[NodeRecord], None] = lambda _n: None,
    connect: bool = True,
) -> None:
    """Populate state.nodes_by_id with one primary node per SECONDARY loaded credential -- the primary credential (the one matching csp_name) is registered by _bootstrap_session() itself now, so this function only still owns primary registration for GCP/Azure (unchanged, still multi_node-gated -- their register-only treatment is deferred to a later phase) plus every secondary originating credential from a multi-CSP -F file."""
    primary_rec = next(
        (
            rec
            for rec in state.credentials_by_id.values()
            if rec.role == "originating" and rec.provider == csp_name
        ),
        None,
    )
    if (
        primary_rec is not None
        and csp_name != "aws"
        and not (csp_name == "azure" and args.resume and not connect)
    ):


        node_credential_id = primary_rec.id
        node = NodeRecord(
            id=f"{primary_rec.id}:primary",
            credential_id=node_credential_id,
            region=state.session.region if state.session else None,
            environment_id=state.session.environment_id if state.session else None,
            session=state.session,
            container_status="Running",
        )


        node._runtime_session = getattr(state, "_session_obj", None)
        node._runtime_api_client = state.api_client
        _record_session_control_plane_evidence(node, node._runtime_session)


        _attach_keepalives(node, getattr(state, "_keepalive_handles", None))
        _probe_after_bootstrap(node, emit)
        state.register_node(node)
        state.active_node_id = node.id

    for rec in state.credentials_by_id.values():
        if rec.role != "originating" or rec is primary_rec:
            continue
        if rec.provider in {"azure", "gcp"}:


            continue
        existing = _find_primary_node(state.nodes_by_id, rec.id)
        if rec.provider == "aws" and existing is None and not connect:


            continue
        stub = existing or NodeRecord(
            id=_primary_node_id(rec.id),
            credential_id=rec.id,
            region=None,
            environment_id=None,
            session=None,
            container_status="Pending",
        )
        state.register_node(stub)


        if stub.begin_connect("provision (primary node bootstrap)"):
            on_node_change(stub)
        try:
            node = _bootstrap_primary_node_for_credential(
                args=args,
                rec=rec,
                emit=emit,
                gcp_wait_mode=gcp_wait_mode,
                node=stub,
                on_node_change=on_node_change,
                connect=connect,
                credential_registry=state.credentials_by_id,
            )
        except Exception as exc:
            from cloudbasher.core.control_plane_status import (
                classify_control_plane_exception,
                record_control_plane_evidence,
            )

            record_control_plane_evidence(
                stub, classify_control_plane_exception(exc)
            )

            _why = str(exc)
            try:
                from cloudbasher.csp.aws.failure import note_node_failure

                _label, _why = note_node_failure(stub, exc)
            except Exception:

                stub.container_status = "Failed"
                stub.end_connect()
            emit(f"failed to bootstrap primary node for {rec.id}: {_why}")
            emit(f"  raw: {exc}")
            on_node_change(stub)
            continue
        finally:


            if stub.end_connect():
                on_node_change(stub)
        _probe_after_bootstrap(node, emit)
        state.register_node(node)
        if state.active_node_id is None:
            state.active_node_id = node.id


def _probe_node_prompt_info(node: NodeRecord, emit: Callable[[str], None]) -> None:
    """Best-effort IP/hostname derivation for a just-bootstrapped node."""
    if node._runtime_session is None or node.session is None:
        return


    node._runtime_prompt_probed_session = node._runtime_session
    try:
        from cloudbasher.core.session.shell import ShellModeHandler

        info = ShellModeHandler(node._runtime_session).setup_prompt_info()
        if info.ip:
            node.session.ip_address = info.ip
        if info.host:
            node.session.hostname = info.host
        if info.user:
            node.session.user = info.user
    except Exception as exc:
        emit(f"prompt-info probe failed for {node.id}: {exc}")
    finally:


        from cloudbasher.core.session.quiet import clear_terminal

        clear_terminal(node._runtime_session)


def _probe_after_bootstrap(node: "NodeRecord", emit: Callable[[str], None]) -> None:
    """`_probe_node_prompt_info`, unless `performance.prompt_probe_mode` defers it."""
    from cloudbasher.core.utils.perf_config import get_prompt_probe_mode

    if get_prompt_probe_mode() == "eager":
        _probe_node_prompt_info(node, emit)


def _persist_on_exit(
    state: Any,
    *,
    bootstrap_succeeded: bool,
    multi_node: bool,
    state_path: str,
    registry_path: str,
) -> None:
    """Decide what survives the process, including after a failed bootstrap."""
    have_nodes = bool(getattr(state, "nodes_by_id", None))
    if bootstrap_succeeded:
        out("Saving state...")


        if not multi_node:
            state.save_state(state_path)
        state.save_registry(registry_path)
        if getattr(state, "_passphrase", None):
            log("State saved (encrypted) to " f"{registry_path if multi_node else state_path}")
    elif have_nodes:


        out("Saving recovered nodes...")
        state.save_registry(registry_path)
        log(
            "Bootstrap failed, but nodes were registered afterwards -- saving "
            f"{registry_path}. Not writing {state_path}: a partial identity "
            "must not overwrite a known-good one."
        )
    else:
        log(
            f"Bootstrap failed and nothing was registered -- not overwriting "
            f"{state_path}/{registry_path} with an unvalidated identity."
        )


class _TerminalStateGuard:
    """Save the terminal's line discipline on entry and put it back on exit."""

    def __init__(self) -> None:
        self._saved_by_fd: dict[int, Any] = {}
        self._restore_results: dict[int, str] = {}
        self._previous_signal_handlers: dict[int, Any] = {}

    def __enter__(self) -> "_TerminalStateGuard":
        try:
            import termios


            for stream in (sys.stdin, sys.stdout, sys.stderr):
                try:
                    fd = stream.fileno()
                    if fd not in self._saved_by_fd and os.isatty(fd):
                        self._saved_by_fd[fd] = termios.tcgetattr(fd)
                except Exception:
                    continue
        except Exception:


            self._saved_by_fd = {}
        return self

    def restore(self) -> None:
        self._restore_results = {}
        if not self._saved_by_fd:
            return
        import termios

        for fd, saved in self._saved_by_fd.items():
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, saved)
                self._restore_results[fd] = (
                    "verified" if termios.tcgetattr(fd) == saved else "mismatch"
                )
            except Exception as exc:
                self._restore_results[fd] = f"error:{type(exc).__name__}"

    def install_signal_handlers(self) -> None:
        """Restore tty state before default termination on catchable signals."""
        import signal
        import threading

        if threading.current_thread() is not threading.main_thread():
            return
        for name in ("SIGTERM", "SIGHUP"):
            signum = getattr(signal, name, None)
            if signum is None:
                continue
            try:
                previous = signal.getsignal(signum)
                self._previous_signal_handlers[signum] = previous

                def _restore_then_dispatch(received: int, frame: Any) -> None:
                    self.restore()
                    original = self._previous_signal_handlers.get(received)
                    if callable(original):
                        original(received, frame)
                    elif original == signal.SIG_IGN:
                        return
                    else:
                        signal.signal(received, signal.SIG_DFL)
                        os.kill(os.getpid(), received)

                signal.signal(signum, _restore_then_dispatch)
            except (OSError, RuntimeError, ValueError):


                self._previous_signal_handlers.pop(signum, None)

    def restore_signal_handlers(self) -> None:
        """Put the process's original handlers back after ``main()`` returns."""
        import signal
        import threading

        if threading.current_thread() is not threading.main_thread():
            return
        for signum, handler in self._previous_signal_handlers.items():
            try:
                signal.signal(signum, handler)
            except (OSError, RuntimeError, ValueError):
                pass
        self._previous_signal_handlers.clear()

    def diagnostic(self) -> str:
        if not self._saved_by_fd:
            return "captured_fds=none (stdin/stdout/stderr were not ttys)"
        results = ",".join(
            f"{fd}:{self._restore_results.get(fd, 'not-restored')}"
            for fd in self._saved_by_fd
        )
        return f"restore_fds={results}"

    def __exit__(self, *_exc: Any) -> bool:
        self.restore()
        return False


def _close_output_and_restore_terminal(guard: _TerminalStateGuard) -> None:
    """Synchronously restore the tty, record verification, then close logging."""
    try:
        _restore_terminal_and_report(guard)
    finally:
        close_output_logging()


def _restore_terminal_and_report(guard: _TerminalStateGuard) -> None:
    guard.restore()
    log(f"[terminal] {guard.diagnostic()}")


def main() -> int:
    """Main CLI entry point."""
    import os
    import sys
    import warnings

    _invoked_as = os.path.basename(sys.argv[0]) if sys.argv else ""
    if _invoked_as in ("cloudshell-runner", "csr"):
        warnings.warn(
            f"'{_invoked_as}' is a deprecated alias; use 'cloudbasher' or 'cb' instead. "
            "This alias will be removed in v0.3.0.",
            DeprecationWarning,
            stacklevel=2,
        )


    _tty_guard = _TerminalStateGuard().__enter__()
    _tty_guard.install_signal_handlers()
    atexit.register(_tty_guard.restore)


    try:
        from cloudbasher.csp.aws.browser import _stop_leaked_playwright_contexts

        atexit.register(_stop_leaked_playwright_contexts)
    except Exception:
        pass

    args = parse_arguments()


    configure_output_logging(args.log)
    if args.verbose >= 1:
        set_log_console_echo(True)
    if getattr(args, "timeline", None):
        from cloudbasher.core.utils.timeline import configure_timeline


        eprint(f"timeline: recording to {configure_timeline(args.timeline)}")

    try:

        provider = args._provider
        csp_name = provider.name


        _notui_err = _notui_unsupported_error(args)
        if _notui_err:
            eprint(_notui_err)
            return 1

        if getattr(args, "creds_file", None):
            from cloudbasher.core.secret_refs import warm_credential_file

            warm_credential_file(args.creds_file)

        _unsupported_csp = _unsupported_csp_error(csp_name)
        if _unsupported_csp:
            eprint(_unsupported_csp)
            return 1

        _check_dependencies(csp_name)

        _preflight_err = _preflight_credential_source(args, csp_name)
        if _preflight_err:
            eprint(_preflight_err)
            return 1

        _preflight_err = _preflight_region_error(args, csp_name)
        if _preflight_err:
            eprint(_preflight_err)
            return 1


        if csp_name == "aws" and getattr(args, "creds_file", None):


            from cloudbasher.core.credential_file import parse_multi_creds_file
            from cloudbasher.csp.aws.credentials import (
                AwsConsoleCreds as _ACC,
            )
            from cloudbasher.csp.aws.credentials import (
                AwsSSOCreds as _ASC,
            )

            try:
                _blocks = parse_multi_creds_file(args.creds_file)
            except Exception:


                _blocks = []
            _console_blocks = [b for b in _blocks if isinstance(b.parsed, (_ACC, _ASC))]
            _armed = _startup_console_creds(_blocks, _console_blocks)
            if _armed is not None:
                log("console credentials detected — using browser console login")
                args.pw_creds = _armed
            elif _console_blocks:
                log(
                    f"{len(_console_blocks)} console/SSO block(s) in a "
                    f"{len(_blocks)}-block file — each credential decides its own "
                    "login path; not arming a process-wide one"
                )


        if csp_name == "gcp" and getattr(args, "creds_file", None):


            from cloudbasher.core.credential_file import (
                parse_multi_creds_file as _gcp_multi,
            )
            from cloudbasher.csp.gcp.credentials import (
                GCPConsoleCredsFile as _GCC,
            )
            from cloudbasher.csp.gcp.credentials import (
                GCPCookiesFile as _GCK,
            )

            try:
                _gcp_blocks = _gcp_multi(args.creds_file)
            except Exception:
                _gcp_blocks = []
            if any(isinstance(b.parsed, (_GCC, _GCK)) for b in _gcp_blocks):
                if not getattr(args, "api_path", None) or args.api_path == "public":
                    args.api_path = "private"
                    log("GCP cookies/console credentials detected — setting --api-path private")


            _console = next((b for b in _gcp_blocks if isinstance(b.parsed, _GCC)), None)
            if _console is not None:
                args.gcp_pw_email = _console.parsed.username
                log("GCP console credentials detected — using browser sign-in for cookies")


        args._multi_credential_records = records_from_creds_file(args)

        if csp_name == "gcp":
            _STATE_BIN = _STATE_BIN_GCP
        elif csp_name == "azure":
            _STATE_BIN = _STATE_BIN_AZURE
        else:
            _STATE_BIN = _STATE_BIN_AWS
        _STATE_MULTI_BIN = _resolve_state_multi_bin(_STATE_BIN, args.multi_node)


        if args.resume_file:
            if args.multi_node:
                _STATE_MULTI_BIN = args.resume_file
            else:


                if not args.resume_file.endswith(".bin"):


                    from pathlib import Path as _Path

                    eprint(
                        f"Warning: -m {args.resume_file!r} will be used as "
                        f"{_Path(args.resume_file).with_suffix('.bin')} "
                        "(single-node state files are always .bin)"
                    )
                _STATE_BIN = args.resume_file
            log(f"state file override: {args.resume_file}")


        _is_tui_interactive = (
            args.tui
            and not args.command
            and not args.run_file
            and not args.upload
            and not args.download
            and not args.enum
        )


        from cloudbasher.core import env_journal as _env_journal

        _env_journal.configure(_env_journal.path_beside_registry(_STATE_MULTI_BIN))


        _is_interactive = _is_interactive_run(args)
        _connect_on_bootstrap = _should_connect_on_bootstrap(args, _is_interactive)


        _passphrase: Optional[str] = None
        if args.resume or _is_interactive:
            _passphrase = _prompt_passphrase(resuming=args.resume, state_file=_STATE_BIN)
            if args.resume and _passphrase is None:
                from pathlib import Path as _Path

                if _Path(_STATE_BIN).exists():
                    eprint(f"Error: passphrase required to decrypt {_STATE_BIN}")
                    return 1

        if csp_name == "aws" and _passphrase:
            from cloudbasher.csp.aws.console_bootstrap import set_browser_auth_passphrase as _sbap

            _sbap(_passphrase)

        if _is_tui_interactive:
            state = InteractiveState(csp_provider=provider, ui_mode="tui")
            state._passphrase = _passphrase
            try:
                saved = _load_saved_state_or_none(_STATE_BIN, _passphrase, args.resume)
            except ValueError as _e:
                eprint(f"Error loading state: {_e}")
                return 1
            _restore_multi_node_registry(
                state,
                _STATE_MULTI_BIN,
                _passphrase,
                args.resume,
                log,
                will_reprobe=_should_auto_connect_on_resume(args),
            )
            saved = _backfill_saved_credentials_from_registry(saved, state, csp_name)
            saved = _backfill_saved_session_from_registry(saved, state, csp_name)


            bootstrap_succeeded = False

            def _bootstrap() -> None:
                """Run inside TUI worker thread; output goes to log pane."""
                nonlocal bootstrap_succeeded
                try:
                    _bootstrap_tui_startup(
                        state=state,
                        args=args,
                        provider=provider,
                        csp_name=csp_name,
                        saved=saved,
                        emit=log,
                        gcp_wait_mode="auto",
                        connect=_connect_on_bootstrap,
                        is_interactive=_is_tui_interactive,
                    )
                    bootstrap_succeeded = True
                    if _should_auto_connect_on_resume(args):


                        import threading as _threading

                        _threading.Thread(
                            target=_reprobe_restored_node_statuses,
                            args=(state, log),
                            daemon=True,
                        ).start()
                    else:
                        _enter_shell_mode_if_ready(state, log)
                except BootstrapError:
                    raise
                except Exception as e:
                    if args.verbose >= 2:


                        import traceback

                        for ln in traceback.format_exc().splitlines():
                            log(ln)


                    raise BootstrapError(str(e)) from e

            had_error = False


            _readline_bounced_to_tui = False
            try:
                _first_tui_run = True
                current_mode: Optional[str] = "tui"
                while current_mode in AVAILABLE_UI_MODES:
                    if current_mode == "tui":
                        try:
                            cb = _bootstrap if _first_tui_run else None
                            _first_tui_run = False
                            next_mode = TUIMode().run(
                                state,
                                bootstrap_callback=cb,
                                multi_node=args.multi_node,
                            )
                            current_mode = next_mode if next_mode else None
                        except BootstrapError as e:
                            eprint(f"Bootstrap failed: {e}")
                            return 1
                        except Exception as e:
                            eprint(f"TUI error: {e}")
                            if args.verbose >= 2:
                                import traceback

                                for ln in traceback.format_exc().splitlines():
                                    log(ln)
                            had_error = True


                            current_mode = None
                    elif current_mode == "readline":
                        try:
                            next_mode = ReadlineMode().run(state)
                            current_mode = next_mode if next_mode else None
                        except Exception as e:
                            eprint(f"Readline error: {e}")
                            if args.verbose >= 2:
                                import traceback

                                for ln in traceback.format_exc().splitlines():
                                    log(ln)
                            had_error = True
                            if _readline_bounced_to_tui:
                                break
                            _readline_bounced_to_tui = True
                            current_mode = "tui"
            except KeyboardInterrupt:
                eprint("\nInterrupted")
                return 130
            finally:


                state.close()
                _persist_on_exit(
                    state,
                    bootstrap_succeeded=bootstrap_succeeded,
                    multi_node=args.multi_node,
                    state_path=_STATE_BIN,
                    registry_path=_STATE_MULTI_BIN,
                )
                _sess_obj = getattr(state, "_session_obj", None)
                if _sess_obj is not None:
                    try:
                        _sess_obj.close()
                    except Exception:
                        pass
                _restore_terminal_and_report(_tty_guard)
                begin_shutdown()
            return 1 if had_error else 0


        try:
            saved = _load_saved_state_or_none(_STATE_BIN, _passphrase, args.resume)
        except ValueError as _e:
            eprint(f"Error loading state: {_e}")
            return 1
        if saved:
            out_ts(f"state_imported={_STATE_BIN}")

        region = args.region or saved.get("region") or None


        _enum_region_selector: str | None = None
        if csp_name == "aws" and args.enum and region:
            raw = region.strip().upper()
            if raw == "ALL" or "," in region or any(c in region for c in ("*", "?", "[")):
                _enum_region_selector = region
                region = "us-west-1"


        state = InteractiveState(csp_provider=provider, ui_mode="tui")
        state._passphrase = _passphrase
        _restore_multi_node_registry(
            state,
            _STATE_MULTI_BIN,
            _passphrase,
            args.resume,
            out_ts,
            will_reprobe=_should_auto_connect_on_resume(args),
        )
        saved = _backfill_saved_credentials_from_registry(saved, state, csp_name)
        saved = _backfill_saved_session_from_registry(saved, state, csp_name)
        try:
            dispatcher = _bootstrap_session(
                state=state,
                args=args,
                provider=provider,
                csp_name=csp_name,
                saved=saved,
                emit=out_ts,
                gcp_wait_mode="input",
                region_override=region,
                connect=_connect_on_bootstrap,
            )
            if args.multi_node:
                if _should_auto_connect_on_resume(args):
                    _reprobe_restored_node_statuses(state, out_ts)
            else:
                _enter_shell_mode_if_ready(state, out_ts)
        except CloudBasherError as e:
            eprint(f"Bootstrap error: {e}")
            return 1
        except Exception as e:
            eprint(f"Bootstrap error: {e}")
            if args.verbose >= 2:
                import traceback

                traceback.print_exc()
            return 1

        credentials = state.credentials
        assert credentials is not None
        api_client = state.api_client
        session = getattr(state, "_session_obj", None)


        if args.command:

            if csp_name == "aws" and args.region and args.region not in ("", "us-west-1"):
                from cloudbasher.csp.aws.multi_region import (
                    resolve_regions,
                    run_command_all_regions,
                )

                regions = resolve_regions(args.region, api_client)
                if len(regions) > 1:
                    out(f"Multi-region execution: {len(regions)} regions")
                    results = run_command_all_regions(
                        provider,
                        credentials,
                        regions,
                        args.command,
                        env_wait_timeout=args.env_wait_timeout,
                        http_timeout=args.http_timeout,
                        ws_timeout=args.ws_timeout,
                        proxy_url=args.proxy,
                        proxy_insecure=args.proxy_insecure,
                    )
                    any_err = False
                    for reg, output, rc in results:
                        status = "OK" if rc == 0 else "ERR"
                        out(f"\n=== {reg} [{status}] ===")
                        if output:
                            out(output)
                        if rc != 0:
                            any_err = True
                    return 1 if any_err else 0

            if session is None:
                eprint("Error: No session available for command execution")
                return 1
            try:
                log(f"Executing: {args.command}")
                output = session.exec_command(args.command)
                if output:
                    out(output)
                return 0
            except Exception as e:
                eprint(f"Error executing command: {e}")
                if args.verbose >= 2:
                    import traceback

                    traceback.print_exc()
                return 1

        elif args.run_file:
            return _run_batch_file(args.run_file, state, dispatcher)

        elif args.upload:
            local_path, remote_path = args.upload
            dispatcher.dispatch(
                f".upload {shlex.quote(local_path)} {shlex.quote(remote_path)}", state
            )
            return 0

        elif args.download:
            remote_path, local_path = args.download
            dispatcher.dispatch(
                f".download {shlex.quote(remote_path)} {shlex.quote(local_path)}", state
            )
            return 0

        elif args.enum:
            enum_cmd = f".enum {_enum_region_selector}" if _enum_region_selector else ".enum"
            cont = dispatcher.dispatch(enum_cmd, state)
            return 0 if cont else 1

        else:

            if session is None:
                eprint("Error: No session available for interactive mode")
                return 1

            had_error = False


            _readline_bounced_to_tui = False
            try:
                current_mode = state.ui_mode
                while current_mode in AVAILABLE_UI_MODES:
                    if current_mode == "tui":
                        try:
                            next_mode = TUIMode().run(
                                state,
                                multi_node=args.multi_node,
                            )
                            current_mode = next_mode if next_mode else None
                        except Exception as e:
                            eprint(f"TUI error: {e}")
                            if args.verbose >= 2:
                                import traceback

                                traceback.print_exc()
                            had_error = True


                            current_mode = None
                    elif current_mode == "readline":
                        try:
                            next_mode = ReadlineMode().run(state)
                            current_mode = next_mode if next_mode else None
                        except Exception as e:
                            eprint(f"Readline error: {e}")
                            if args.verbose >= 2:
                                import traceback

                                traceback.print_exc()
                            had_error = True
                            if _readline_bounced_to_tui:
                                break
                            _readline_bounced_to_tui = True
                            current_mode = "tui"

            except KeyboardInterrupt:
                eprint("\nInterrupted")
                return 130
            except Exception as e:
                eprint(f"Error: {e}")
                if args.verbose >= 2:
                    import traceback

                    traceback.print_exc()
                return 1
            finally:


                state.close()


                _persist_on_exit(
                    state,
                    bootstrap_succeeded=True,
                    multi_node=args.multi_node,
                    state_path=_STATE_BIN,
                    registry_path=_STATE_MULTI_BIN,
                )
                if session:
                    try:
                        session.close()
                    except Exception:
                        pass
                _restore_terminal_and_report(_tty_guard)
                begin_shutdown()

            return 1 if had_error else 0

        return 0

    except CloudBasherError as e:
        eprint(f"Error: {e}")
        return 1
    except KeyboardInterrupt:
        eprint("\nInterrupted")
        return 130
    except Exception as e:
        eprint(f"Unexpected error: {e}")
        if "--verbose" in sys.argv or "-v" in sys.argv or "-vv" in sys.argv:
            import traceback

            traceback.print_exc()
        return 1
    finally:
        try:
            _close_output_and_restore_terminal(_tty_guard)
        finally:
            _tty_guard.restore_signal_handlers()


if __name__ == "__main__":
    sys.exit(main())
