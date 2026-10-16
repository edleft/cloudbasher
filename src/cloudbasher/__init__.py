"""CloudBasher - Multi-cloud interactive shell automation."""


__version__ = "0.9.0"
__author__ = "CloudBasher Contributors"

from .core.exceptions import (
    CloudShellAutomationError,
    CloudBasherError,
    CommandError,
    CredentialError,
    SessionError,
    UIError,
)
from .core.types import Credentials, InteractiveState, SessionInfo, ShellPromptInfo

__all__ = [
    "CloudBasherError",
    "CloudShellAutomationError",
    "CredentialError",
    "SessionError",
    "CommandError",
    "UIError",
    "Credentials",
    "SessionInfo",
    "ShellPromptInfo",
    "InteractiveState",
]
