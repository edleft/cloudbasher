"""Readline-based interactive mode (fallback)."""

from __future__ import annotations

import time
from typing import Optional

from ..cli.dispatcher import CommandDispatcher
from ..session.activity import activity_from
from ..session.prompt import display_prompt
from ..types import InteractiveState
from ..utils.output import (
    _is_color_tty,
    eprint,
    log,
    out,
    render_pty_output,
)
from .base import InteractiveMode
from .repl_shared import (
    APP_QUIT_COMMANDS,
    SURFACE_EXIT_COMMANDS,
    expand_history_bang,
    is_quit_confirmed,
    pending_question,
)


def _confirm_quit_readline() -> bool:
    """Show 'quit [Y/n]' at the confirmation prompt. Returns True to quit."""
    try:
        answer = input("quit [Y/n] ")
        return is_quit_confirmed(answer)
    except KeyboardInterrupt:
        out("")
        return is_quit_confirmed("")
    except EOFError:
        out("")
        return is_quit_confirmed("")


_pending_question = pending_question


class ReadlineMode(InteractiveMode):
    """Readline-based interactive REPL (fallback when TUI unavailable)."""

    def __init__(self):
        """Initialize readline mode."""
        self.dispatcher: Optional[CommandDispatcher] = None


        self._announced_recovery_at: Optional[float] = None

    def run(self, state: InteractiveState) -> Optional[str]:
        """Run readline interactive mode."""
        self.dispatcher = CommandDispatcher(state.csp_provider)
        state.csp_provider.register_dot_commands(self.dispatcher)

        out("\nEntering interactive readline mode")
        out("Type '.help' for commands, 'exit' or 'quit' to exit")


        if not getattr(state, "nodes_by_id", None):
            out(
                "No nodes registered yet -- run .provision (create + connect) "
                "or .register (attach to something that already exists)."
            )
        out("-" * 60)

        try:
            while True:
                try:

                    prompt = self._build_prompt(state)
                    line = input(prompt).strip()

                    if not line:
                        continue

                    try:
                        expanded = expand_history_bang(line, state)
                    except IndexError as e:
                        eprint(str(e))
                        continue
                    if expanded != line:
                        out(expanded)
                        line = expanded


                    if state.in_shell_mode:


                        if line in SURFACE_EXIT_COMMANDS | APP_QUIT_COMMANDS | {"."}:
                            state.in_shell_mode = False
                            out("Exited shell mode")
                            continue

                        if not hasattr(state, "_session_obj"):
                            eprint("Error: No session object")
                            continue
                        session = state._session_obj
                        try:
                            raw_out = session.exec_command(line, raw=True)
                            if raw_out:
                                rendered = render_pty_output(
                                    raw_out,
                                    line,
                                    color=_is_color_tty(),
                                    command_echo_present=getattr(
                                        session, "raw_exec_output_has_command_echo", True
                                    ),
                                    framed_output=(
                                        getattr(session, "raw_exec_output_is_framed", False) is True
                                    ),
                                )
                                if rendered:
                                    out(rendered)
                            state.add_history(line)
                        except Exception as e:
                            eprint(f"Error: {e}")
                        continue


                    if line.startswith("."):
                        continue_loop = self.dispatcher.dispatch(line, state)
                        if not continue_loop:
                            if _confirm_quit_readline():
                                break
                            continue

                        if state.ui_mode != "readline":
                            return state.ui_mode
                    elif line in ("exit", "quit"):

                        if _confirm_quit_readline():
                            break
                    else:

                        if not hasattr(state, "_session_obj"):
                            eprint("Error: No session object")
                            continue
                        session = state._session_obj
                        try:
                            output = session.exec_command(line, raw=_is_color_tty())
                            if output:
                                out(output)
                            state.add_history(line)
                        except Exception as e:
                            eprint(f"Error: {e}")

                except KeyboardInterrupt:


                    log("Ctrl-C at prompt — returning to prompt")
                except EOFError:
                    if state.in_shell_mode:
                        state.in_shell_mode = False
                        out("")
                        out("Exited shell mode")
                        continue
                    out("")
                    if _confirm_quit_readline():
                        break

        except Exception as e:
            eprint(f"Error in readline mode: {e}")
            return None

        return None

    def _build_prompt(self, state: InteractiveState) -> str:
        """Build the interactive prompt."""


        question = _pending_question(state)
        if question is not None:
            return f"{question} "


        aftermath = self._recovery_aftermath(state)
        if state.in_shell_mode:
            session = getattr(state, "_session_obj", None)
            native_prompt = display_prompt(session) if session is not None else None
            if native_prompt:
                return aftermath + native_prompt + " "
            if state.shell_prompt_info:
                return aftermath + state.shell_prompt_info.format_prompt()
            return aftermath + "$ "
        from ..branding import get_prompt_text

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        n = len(state.get_history()) + 1
        return f"{aftermath}[{ts}][{n}]:{get_prompt_text()} "

    def _recovery_aftermath(self, state: InteractiveState) -> str:
        """A one-line notice about a cold-shell recovery, or "" -- once only."""
        activity = activity_from(getattr(state, "_session_obj", None))
        if activity is None or activity.recovered_at is None:
            return ""
        if activity.recovered_at == self._announced_recovery_at:
            return ""
        self._announced_recovery_at = activity.recovered_at
        return f"[shell rebuilt after {activity.recovery_seconds:.0f}s]\n"
