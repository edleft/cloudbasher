"""Custom exceptions."""

import warnings as _warnings
from typing import Optional


class CloudBasherError(Exception):
    """Base exception."""

    pass


class CloudShellAutomationError(CloudBasherError):
    """CloudShell automation failed."""

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        error_code: Optional[str] = None,
        response_body: Optional[str] = None,
        response_message: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.response_body = response_body
        self.response_message = response_message
        self.request_id = request_id
        self.correlation_id = correlation_id


class CredentialError(CloudBasherError):
    """Credential loading/refresh failed."""

    pass


class SessionError(CloudBasherError):
    """Session management failed."""

    pass


class CommandOutcomeUnknown(SessionError):
    """A shell command was sent, but CloudBasher did not observe completion."""

    pass


class CommandError(CloudBasherError):
    """Command execution failed."""

    pass


class UIError(CloudBasherError):
    """UI/TUI error."""

    pass


def __getattr__(name: str):
    if name == "CloudShellRunnerError":
        _warnings.warn(
            "CloudShellRunnerError is deprecated; use CloudBasherError. "
            "This alias will be removed in v0.3.0.",
            DeprecationWarning,
            stacklevel=2,
        )
        return CloudBasherError
    raise AttributeError(f"module 'cloudbasher.core.exceptions' has no attribute {name!r}")


class LoginGateExceeded(CloudBasherError):
    """A console sign-in gave up on `_LOGIN_GATE` -- the queue or the hold."""

    pass
