#!/bin/bash
# CloudBasher — Easy wrapper script
# Usage: ./run.sh -F <creds-file> [-o KEY=VALUE] [--show-browser] [-v]
#
# `--interactive` and `--aws|--gcp|--azure` were REMOVED: the TUI is
# the only interface, and no switch is CSP-specific -- the CSP comes from the
# credential file.
#
# Every run needs exactly one credential source: -F/--creds-file, --creds-env,
# or --resume/-m. Pass --help for the full flag list.
#
# Resolves the venv in this order: venv (project convention) → .venv (uv legacy default).
# If neither exists, prints install hints and exits.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -x "$SCRIPT_DIR/.venv/bin/cloudbasher" ]]; then
    BIN="$SCRIPT_DIR/.venv/bin/cloudbasher"
elif [[ -x "$SCRIPT_DIR/venv/bin/cloudbasher" ]]; then
    BIN="$SCRIPT_DIR/venv/bin/cloudbasher"
else
    echo "ERROR: cloudbasher not found in .venv/ or venv/" >&2
    echo "       Install with one of:" >&2
    echo "         UV_PROJECT_ENVIRONMENT=venv uv sync --extra aws --extra gcp --extra azure" >&2
    echo "         python3 -m venv venv && venv/bin/pip install -r requirements.txt && venv/bin/pip install --no-deps ." >&2
    exit 1
fi

echo "$BIN" "$@"

# Keep an outer TTY snapshot as a last-resort cleanup boundary. The Python
# guard handles CloudBasher's own exits, but this shell survives a killed or
# otherwise abnormal Python process and can restore the terminal on its exit.
TTY_STATE=""
if [[ -r /dev/tty ]]; then
    TTY_STATE="$(stty -g </dev/tty 2>/dev/null || true)"
fi
# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2329
_restore_tty_on_exit() {
    local exit_status=$?
    trap - EXIT
    if [[ -n "$TTY_STATE" ]]; then
        stty "$TTY_STATE" </dev/tty 2>/dev/null || true
    fi
    exit "$exit_status"
}

# Invoked indirectly by the signal traps.
# shellcheck disable=SC2329
trap _restore_tty_on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Keep the CLI in the foreground process group so it retains normal TTY and
# Ctrl-C behavior. Its exit (including signal termination) returns here and
# the EXIT trap restores the pre-run terminal snapshot.
"$BIN" "$@"
