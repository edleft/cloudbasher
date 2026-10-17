"""THE grammar table: one declarative spec per dot-command."""

from __future__ import annotations

import re

from ..session.keepalive_policy import KEEPALIVE_POLICIES
from .command_spec import (
    CommandSpec,
    Effects,
    Flag,
    Positional,
    Rest,
    Slot,
    SlotKind,
    Verb,
)

__all__ = ["CORE_SPECS"]


_FILE_NODE_SELECTOR = re.compile(r"^\d+(?:\.\d+)?(?:,\d+(?:\.\d+)?)*$")


def _is_file_node_selector(token: str) -> bool:
    """Whether a first token is the reserved file-command target selector."""
    return token.lower() in {"all", "selected"} or bool(_FILE_NODE_SELECTOR.fullmatch(token))


BULK = CommandSpec(
    name="bulk",
    summary="Run a command on the nodes a selector matches",
    effects=Effects.READ_ONLY,
    terminals=(
        Slot(SlotKind.NODE, name="selector", required=True),
        Rest("command", required=True),
    ),
    notes=(
        "selector: selected | ALL | <region-glob> | <comma-list>\n"
        "The command is taken from the raw line, so quoting survives: "
        '`.bulk ALL echo "x y"` runs `echo "x y"` on each node.'
    ),
)


COMMAND = CommandSpec(
    name="command",
    summary="Run one shell command on the active node, or enter shell mode",
    effects=Effects.READ_ONLY,
    terminals=(Rest("command"),),
)

ECHO = CommandSpec(
    name="echo",
    summary="Print a message",
    effects=Effects.READ_ONLY,
    terminals=(Rest("message"),),
)

LS = CommandSpec(
    name="ls",
    summary="List remote paths on a selected node or nodes",
    effects=Effects.READ_ONLY,
    terminals=(
        Slot(
            SlotKind.NODE,
            name="selector",
            accepts=_is_file_node_selector,
            usage_label="<node#>|selected|ALL",
        ),
        Rest("path"),
    ),
    notes=(
        "Defaults to `.` when no path is given. `selected` and `ALL` are reserved "
        "first tokens; escape a literal path as `./selected` or `./all`."
    ),
)

RUN = CommandSpec(
    name="run",
    summary="Execute a selected-node shell file line by line",
    effects=Effects.READ_ONLY,
    terminals=(Rest("file", required=True),),
    notes=(
        "Shell lines execute on the selected node and dot commands use the normal "
        "dispatcher. This is distinct from CLI `-f`, which accepts only strict "
        "batch-approved dot commands. READ_ONLY describes `.run` reading the file; "
        "the file's commands declare their own effects (directive 8)."
    ),
)

LOOP = CommandSpec(
    name="loop",
    summary="Run a shell command in a background loop",
    effects=Effects.READ_ONLY,
    terminals=(
        Positional("interval_seconds", required=True, kind="int"),
        Rest("command", required=True),
    ),
)


def _node_command(
    name: str,
    summary: str,
    effects: Effects,
    *,
    confirmable: bool = False,
    forcible: bool = False,
    extra_note: str = "",
) -> CommandSpec:
    """The eight commands whose whole grammar is "a node selector"."""
    terminals: tuple = (Slot(SlotKind.NODE, name="selector", required=True, greedy=True),)
    if confirmable:
        terminals += (Flag("yes", help="skip the confirmation prompt"),)
    if forcible:


        terminals += (
            Flag("force", help="override a build's claim on the node (see .delete's help)"),
        )


    _notes = "selector: selected | ALL | <region-glob> | <comma-list> | <node#>"
    if extra_note:
        _notes += "\n" + extra_note
    return CommandSpec(
        name=name,
        summary=summary,
        effects=effects,
        terminals=terminals,
        notes=_notes,
    )


OUTPUT = _node_command(
    "output", "Show the full last bulk output for those nodes", Effects.READ_ONLY
)
DEREGISTER = _node_command(
    "unregister",
    "Remove the nodes from view/the registry, but leaving CloudShell environment alone",
    Effects.MUTATES_REGISTRY,
    extra_note="aliases: .deregister, .forget -- no cloud call, environment untouched",
)
DELETE = _node_command(
    "delete",
    "Apply the selected provider's destructive Cloud Shell delete/reset behavior",
    Effects.DESTROYS_CLOUD | Effects.MUTATES_REGISTRY,
    confirmable=True,
    forcible=True,
    extra_note=(
        "AWS: permanently deletes the environment; --force can release a build claim\n"
        "Azure: confirms a reset of the console and userSettings; backing storage remains\n"
        "Azure does not support --force. GCP Console `.delete` abandons the active "
        "Cloud Shell session and removes the local node record; it does not promise "
        "permanent environment or user-data deletion. GCP `.delete` applies only to "
        "Console credential nodes; the public OAuth API has no environment-delete method.\n"
        "Mixed-provider selections are confirmed once, then each provider "
        "applies its own behavior.\n"
        "--yes skips the applicable confirmation. A node without an environment is left alone."
    ),
)
DISCONNECT = _node_command(
    "disconnect",
    "Close the WebSocket session for selected node(s), leaving the environment(s) running",
    Effects.READ_ONLY,
)
CONNECT = _node_command(
    "connect",
    "Create a WebSocket session to selected node(s)",
    Effects.READ_ONLY,
    extra_note="`.connect ALL` really opens sockets for a restored fleet, not just rows",
)
START = _node_command(
    "start", "Start or resume the selected node(s) environment(s)", Effects.CREATES_CLOUD
)
STOP = _node_command(
    "stop",
    "Suspend selected node environments when supported; unsupported providers report no action",
    Effects.DESTROYS_CLOUD,
    extra_note=(
        "alias: .suspend; Azure and GCP have no stop/suspend operation, "
        "so no action is taken"
    ),
)


CREDS = CommandSpec(
    name="creds",
    summary="Show loaded identities, probe what they may do, or re-derive one",
    effects=Effects.READ_ONLY,
    terminals=(


        Slot(SlotKind.CRED, name="selector", usage_label="<ID>|selected|ALL"),
        Verb("show"),
        Verb("perms"),
        Verb("refresh"),
    ),
    subcommands={
        "show": CommandSpec(
            name="creds show",
            summary="List loaded identities",
            terminals=(Rest("unexpected"),),
        ),
        "perms": CommandSpec(
            name="creds perms",
            summary="Ask AWS what those credentials may actually derive",


            terminals=(Rest("roles"),),
            notes="After `perms` the only extra is a role to probe: `role <arn>`, "
            "or a bare `arn:...`. Repeatable.",
        ),
        "refresh": CommandSpec(
            name="creds refresh",
            summary="Re-derive an ACT_AS=role/federated credential, then re-project it",
            effects=Effects.MUTATES_REGISTRY,
        ),
    },
    notes=(
        "An omitted selector means the ticked rows, then the cursor.\n"
        "`configure` is Azure-only -- AWS and GCP credentials come from "
        "-F/--creds-env, and there is no interactive editor for them."
    ),
)


UPLOAD = CommandSpec(
    name="upload",
    summary="Copy a local file into selected node(s)",
    effects=Effects.MUTATES_REGISTRY,
    terminals=(
        Slot(
            SlotKind.NODE,
            name="selector",
            accepts=_is_file_node_selector,
            usage_label="<node#>|selected|ALL",
        ),
        Positional("local_path", required=True, kind="path"),
        Positional("remote_path", required=True, kind="path"),
    ),
    notes=(
        "`selected` and `ALL` are reserved first tokens; escape a literal local path "
        "as `./selected` or `./all`."
    ),
)

DOWNLOAD = CommandSpec(
    name="download",
    summary="Copy a file out of one selected node",
    effects=Effects.READ_ONLY,
    terminals=(
        Slot(
            SlotKind.NODE,
            name="selector",
            accepts=_is_file_node_selector,
            usage_label="<node#>|selected|ALL",
        ),
        Positional("remote_path", required=True, kind="path"),
        Positional("local_path", required=True, kind="path"),
    ),
    notes=(
        "A selector matching more than one node is refused to prevent local-file "
        "overwrite. `selected` and `ALL` are reserved first tokens; escape a literal "
        "remote path as `./selected` or `./all`."
    ),
)

FG = CommandSpec(
    name="fg",
    summary="Bring a background job to the foreground",
    effects=Effects.READ_ONLY,
    terminals=(Positional("job_id", required=True, kind="int"),),
)

KILL = CommandSpec(
    name="kill",
    summary="Stop a background job",
    effects=Effects.READ_ONLY,
    terminals=(Positional("job_id", required=True, kind="int"),),
)


ENUM_CORE = CommandSpec(
    name="enum",
    summary="List CloudShell environments",


    effects=Effects.READ_ONLY,
    terminals=(),
)


REGION = CommandSpec(
    name="region",
    summary="Show or set the region (ALL, glob, comma-list, literal)",
    effects=Effects.MUTATES_REGISTRY,
    terminals=(Positional("selector", required=False),),
)


HELP = CommandSpec(
    name="help",
    summary="Show this help; `.help <cmd>` for one command in full",
    effects=Effects.READ_ONLY,
    terminals=(Positional("cmd", required=False),),
)
STATE = CommandSpec(
    name="state",
    summary="Show session state",
    effects=Effects.READ_ONLY,
    terminals=(),
)
HISTORY = CommandSpec(
    name="history",
    summary="Show command history",
    effects=Effects.READ_ONLY,
    terminals=(),
)
CLEAR = CommandSpec(
    name="clear",


    summary="Clear the output pane",
    effects=Effects.READ_ONLY,
    hidden=True,
    terminals=(),
)
VERBOSE = CommandSpec(
    name="verbose",
    summary="Echo the log to the console: on, off, or show",
    effects=Effects.READ_ONLY,


    terminals=(
        Positional(
            "mode",
            required=False,
            usage_label="on|off",
            accepts=lambda t: t.lower() in ("on", "off"),
            reject_hint=lambda t: f"verbose takes `on` or `off`, not {t!r}",
        ),
    ),
)
JOBS = CommandSpec(
    name="jobs",
    summary="List background jobs",
    effects=Effects.READ_ONLY,
    terminals=(),
)
QUIT = CommandSpec(
    name="quit",
    summary="Exit CloudBasher",
    effects=Effects.READ_ONLY,
    terminals=(),
)


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


SLEEP = CommandSpec(
    name="sleep",
    summary="Pause for N seconds",
    effects=Effects.READ_ONLY,


    terminals=(
        Positional(
            "seconds",
            required=False,
            usage_label="seconds",
            accepts=_is_number,
            reject_hint=lambda t: f"sleep takes a number of seconds, not {t!r}",
        ),
    ),
)
UI = CommandSpec(
    name="ui",
    summary="Show the current UI mode (`tui` is the only one in this release)",
    effects=Effects.READ_ONLY,
    terminals=(


        Positional(
            "mode",
            required=False,
            usage_label="tui",


            accepts=lambda t: t.lower() == "tui",
            reject_hint=lambda t: (


                "`--notui` / readline mode is not supported in this release "
                "-- it returns in a future release. `tui` is the only mode."
                if t.lower() == "notui"
                else f"unknown UI mode {t!r} -- use `tui`"
            ),
        ),
    ),
)
BG = CommandSpec(
    name="bg",
    summary="Resume a suspended job in the background",
    effects=Effects.READ_ONLY,
    terminals=(Positional("job_id", required=False, kind="int"),),
)


HEARTBEAT = CommandSpec(
    name="heartbeat",
    summary="Show or set a node's keepalive policy, or beat every armed layer now",


    effects=Effects.READ_ONLY,
    terminals=(


        Slot(SlotKind.NODE, name="selector", usage_label="<node#>|selected|ALL"),


        *(Verb(_p) for _p in KEEPALIVE_POLICIES),
        Verb("now"),
    ),
    notes=(
        "Bare `.heartbeat` shows every node's policy and live layer state.\n"
        "session: all four layers, and a dead session is rebuilt unattended.\n"
        "container: layers 1+3 -- hold the environment, let the session go.\n"
        "native: no interaction ping, so a parked node suspends like a "
        "console tab, and is not repaired for you.\n"
        "off: nothing, for demonstrating the timers.\n"
        "now: beat every layer this node's policy arms, and say what was sent.\n"
        "A policy is saved with the node, so it survives --resume. Cadences "
        "are tuning and live in `[performance]`; set the default policy with "
        "`[keepalive] policy` or `-o keepalive.policy=<v>`."
    ),
)


CORE_SPECS: dict[str, CommandSpec] = {
    ".bulk": BULK,
    ".output": OUTPUT,
    ".unregister": DEREGISTER,
    ".deregister": DEREGISTER,
    ".forget": DEREGISTER,
    ".delete": DELETE,
    ".disconnect": DISCONNECT,
    ".connect": CONNECT,
    ".start": START,
    ".stop": STOP,
    ".suspend": STOP,
    ".command": COMMAND,
    ".echo": ECHO,
    ".ls": LS,
    ".run": RUN,
    ".loop": LOOP,
    ".creds": CREDS,
    ".upload": UPLOAD,
    ".download": DOWNLOAD,
    ".fg": FG,
    ".kill": KILL,


    ".enum": ENUM_CORE,
    ".region": REGION,
    ".help": HELP,
    ".state": STATE,
    ".history": HISTORY,
    ".clear": CLEAR,
    ".verbose": VERBOSE,
    ".jobs": JOBS,
    ".quit": QUIT,
    ".exit": QUIT,
    ".": QUIT,
    ".sleep": SLEEP,
    ".ui": UI,
    ".bg": BG,
    ".heartbeat": HEARTBEAT,
    ".ping": HEARTBEAT,
}
