"""In-memory capture of the Azure Portal's delegated ARM token response."""

from __future__ import annotations

import datetime as dt
import json
import queue
import re
import threading
import urllib.parse
from dataclasses import dataclass
from typing import Any, Optional

from cloudbasher.core.exceptions import CredentialError
from cloudbasher.core.utils.page_poll import poll_page_until
from cloudbasher.csp.azure.app_ids import AzureClientIds
from cloudbasher.csp.azure.audiences import (
    normalized_jwt_audiences,
    resolve_azure_audience,
)
from cloudbasher.csp.azure.credentials import _decode_jwt_payload

_TOKEN_ENDPOINT = re.compile(
    r"^https://login\.microsoftonline\.com/[^/]+/oauth2/v2\.0/token(?:[?#]|$)",
    re.IGNORECASE,
)
_LEGACY_ARM_AUDIENCE = "https://management.core.windows.net/"


@dataclass(frozen=True)
class PortalArmToken:
    """A Portal bearer retained only for the running credential/session path."""

    access_token: str
    refresh_token: Optional[str]
    expires_at: Optional[dt.datetime]
    client_id: str
    tenant_id: str


class PortalTokenCapture:
    """Filter Portal token responses without retaining cookies or raw bodies."""

    def __init__(self, *, expected_tenant: str = "") -> None:
        self._expected_tenant = expected_tenant
        self._token: Optional[PortalArmToken] = None
        self.rejected_responses = 0

    @property
    def token(self) -> Optional[PortalArmToken]:
        return self._token

    def observe_response(self, response: Any) -> None:
        """Consider one Playwright response; ignore every non-Portal-token call."""
        url = str(getattr(response, "url", ""))
        if not _TOKEN_ENDPOINT.match(url) or self._token is not None:
            return
        try:
            payload = json.loads(response.text())
        except Exception:  # noqa: BLE001 -- network/login variants are non-fatal here
            self.rejected_responses += 1
            return
        if not isinstance(payload, dict):
            self.rejected_responses += 1
            return
        access_token = payload.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            self.rejected_responses += 1
            return
        claims = _decode_jwt_payload(access_token)
        if not self._is_observed_portal_arm_claim_set(claims):
            self.rejected_responses += 1
            return
        expires_at = _expiry_from_payload(payload)
        self._token = PortalArmToken(
            access_token=access_token,
            refresh_token=_optional_string(payload.get("refresh_token")),
            expires_at=expires_at,
            client_id=str(claims["appid"]),
            tenant_id=str(claims["tid"]),
        )

    def require_token(self) -> PortalArmToken:
        if self._token is None:
            raise CredentialError(
                "Azure Portal did not yield an observed delegated ARM token. "
                "No token response was persisted; inspect the redacted browser trace."
            )
        return self._token

    def _is_observed_portal_arm_claim_set(self, claims: dict[str, Any]) -> bool:
        """The acceptance predicate; keep its evidence-bearing fields explicit."""
        if claims.get("aud") != _LEGACY_ARM_AUDIENCE:
            return False
        if claims.get("appid") != AzureClientIds.AZURE_PORTAL_OBSERVED:
            return False
        tenant_id = claims.get("tid")
        if not isinstance(tenant_id, str) or not tenant_id:
            return False
        return not self._expected_tenant or tenant_id == self._expected_tenant


class PortalAudienceTokenProvider:
    """Mint a narrowly allowlisted audience token in the Portal browser origin."""

    def __init__(
        self,
        creds: Any,
        *,
        mfa: Any,
        expected_tenant: str,
        headless: bool,
    ) -> None:
        self._creds = creds
        self._mfa = mfa
        self._expected_tenant = expected_tenant
        self._headless = headless
        self._requests: queue.Queue[Any] = queue.Queue()
        self._ready = threading.Event()
        self._initial_token: Optional[PortalArmToken] = None
        self._tenant_id = ""
        self._client_id = ""
        self._refresh_token = ""
        self._startup_diagnostic = ""
        self._closed = False
        self._thread = threading.Thread(
            target=self._browser_owner,
            name="azure-portal-token-provider",
            daemon=True,
        )
        self._thread.start()
        if not self._ready.wait(timeout=120):
            self.close()
            raise CredentialError("Azure Portal browser token provider startup timed out.")
        if self._initial_token is None:
            self.close()
            error = CredentialError("Azure Portal browser token provider could not authenticate.")
            error.safe_diagnostic = self._startup_diagnostic or "portal_startup_failed"
            raise error

    def take_initial_token(self) -> PortalArmToken:
        token = self._initial_token
        if token is None:
            raise CredentialError("Azure Portal browser token provider is not ready.")
        self._initial_token = None
        return token

    def _browser_owner(self) -> None:
        from cloudbasher.csp.azure.playwright_login import BrowserSession

        browser = BrowserSession(headless=self._headless, handle_sigint=False)
        try:
            browser.__enter__()
            page = browser.new_page()
            self._initial_token = capture_portal_arm_token(
                page,
                self._creds,
                mfa=self._mfa,
                expected_tenant=self._expected_tenant,
            )
            page_url = urllib.parse.urlsplit(str(getattr(page, "url", "")))
            if (
                page_url.scheme.lower() != "https"
                or (page_url.hostname or "").lower() != "portal.azure.com"
            ):
                raise CredentialError("Azure Portal login did not remain on the Portal origin.")
            self._tenant_id = self._initial_token.tenant_id
            self._client_id = self._initial_token.client_id
            self._refresh_token = self._initial_token.refresh_token or ""
            self._creds = None
            self._mfa = None
            self._ready.set()
            while True:
                request = self._requests.get()
                if request is None:
                    break
                profile, reply = request
                try:
                    reply.put((self._redeem_in_browser(page, profile), ""))
                except Exception as exc:  # noqa: BLE001 -- expose safe class/category only
                    reply.put(
                        (None, getattr(exc, "safe_diagnostic", "portal_browser_request_failed"))
                    )
        except BaseException as exc:
            if not self._ready.is_set():
                self._startup_diagnostic = f"portal_startup_failed:{type(exc).__name__.lower()}"
                self._ready.set()
        finally:
            browser.__exit__(None, None, None)
            self._refresh_token = ""
            self._initial_token = None
            self._creds = None
            self._mfa = None

    def _redeem_in_browser(self, page: Any, profile: Any) -> str:
        from cloudbasher.csp.azure.credentials import _decode_jwt_payload

        if not self._refresh_token:
            error = CredentialError("Azure Portal token provider has no in-memory renewal token.")
            error.safe_diagnostic = "portal_refresh_unavailable"
            raise error
        try:
            result = page.evaluate(
                """async ({url, refreshToken, clientId, scope}) => {
                  const body = new URLSearchParams({client_id: clientId,
                    grant_type: 'refresh_token', refresh_token: refreshToken, scope});
                  const response = await fetch(url, {method: 'POST',
                    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                    body: body.toString(), credentials: 'omit'});
                  let payload = {};
                  try { payload = await response.json(); } catch (_) {}
                  return {status: response.status, body: payload};
                }""",
                {
                    "url": f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token",
                    "refreshToken": self._refresh_token,
                    "clientId": self._client_id,
                    "scope": profile.scope,
                },
            )
        except Exception as exc:  # noqa: BLE001 -- never surface browser exception text
            error = CredentialError("Azure Portal browser token request failed.")
            error.safe_diagnostic = "portal_browser_request_failed"
            raise error from exc

        body = result.get("body") if isinstance(result, dict) else None
        status = result.get("status") if isinstance(result, dict) else None
        if not isinstance(status, int) or status < 100 or status > 599:
            error = CredentialError("Azure Portal token endpoint returned an invalid response.")
            error.safe_diagnostic = "portal_token_response_invalid"
            raise error
        if status != 200:
            error_code = body.get("error") if isinstance(body, dict) else None
            if not isinstance(error_code, str) or not re.fullmatch(
                r"[A-Za-z0-9_]{1,40}", error_code
            ):
                error_code = "unknown"
            error = CredentialError("Azure Portal token endpoint rejected the request.")
            error.safe_diagnostic = f"portal_token_http_{status}_{error_code}"
            raise error
        token = body.get("access_token") if isinstance(body, dict) else None
        if not isinstance(token, str) or not token:
            error = CredentialError("Azure Portal token response omitted an access token.")
            error.safe_diagnostic = "portal_token_missing_access_token"
            raise error
        claims = _decode_jwt_payload(token)
        try:
            expires_at = int(claims.get("exp") or 0)
        except (TypeError, ValueError, OverflowError) as exc:
            error = CredentialError("Azure Portal token response had invalid expiry.")
            error.safe_diagnostic = "portal_invalid_expiry"
            raise error from exc
        checks = (
            (
                str(claims.get("tid") or "").lower() == self._tenant_id.lower(),
                "tenant",
            ),
            (
                str(claims.get("appid") or claims.get("azp") or "").lower()
                == self._client_id.lower(),
                "client",
            ),
            (
                bool(
                    normalized_jwt_audiences(claims).intersection(
                        value.lower() for value in profile.jwt_audiences
                    )
                ),
                "audience",
            ),
            (isinstance(claims.get("scp"), str) and bool(claims["scp"]), "scope"),
            (
                expires_at > int(dt.datetime.now(dt.timezone.utc).timestamp()),
                "expiry",
            ),
        )
        failed = ",".join(name for passed, name in checks if not passed)
        if failed:
            error = CredentialError(
                "Azure Portal token response failed delegated-token validation."
            )
            error.safe_diagnostic = f"portal_token_claims_rejected:{failed}"
            raise error
        rotated = body.get("refresh_token")
        if isinstance(rotated, str) and rotated:
            self._refresh_token = rotated
        return token

    def __call__(self, _credentials: Any, audience: str) -> str:
        profile = resolve_azure_audience(audience)
        if self._closed or profile is None:
            error = CredentialError("Azure Portal token provider rejected the requested audience.")
            error.safe_diagnostic = "portal_audience_rejected"
            raise error
        reply: queue.Queue[Any] = queue.Queue(maxsize=1)
        self._requests.put((profile, reply))
        try:
            token, diagnostic = reply.get(timeout=45)
        except queue.Empty as exc:
            error = CredentialError("Azure Portal browser token request timed out.")
            error.safe_diagnostic = "portal_browser_request_timeout"
            raise error from exc
        if not token:
            error = CredentialError("Azure Portal browser token request failed.")
            error.safe_diagnostic = diagnostic or "portal_browser_request_failed"
            raise error
        return token

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._requests.put(None)
        if self._thread is not threading.current_thread():
            self._thread.join(timeout=5)


def capture_portal_arm_token(
    page: Any,
    creds: Any,
    *,
    mfa: Any,
    expected_tenant: str,
    timeout_ms: int = 30_000,
) -> PortalArmToken:
    """Sign in to Portal and return its observed ARM bearer in memory."""
    from cloudbasher.csp.azure.playwright_login import console_login

    capture = PortalTokenCapture(expected_tenant=expected_tenant)
    page.on("response", capture.observe_response)
    sign_in = console_login(page, creds, mfa=mfa, timeout_ms=timeout_ms)
    if not sign_in.ok:
        raise CredentialError(f"Azure Portal sign-in failed: {sign_in.error}")

    outcome = poll_page_until(
        page,
        until=lambda: capture.token,
        budget_ms=timeout_ms,
        tick_ms=250,
    )
    if outcome.timed_out:
        return capture.require_token()
    return outcome.verdict


def _optional_string(value: object) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _expiry_from_payload(payload: dict[str, Any]) -> Optional[dt.datetime]:
    """Convert a token response expiry without parsing or exposing its token."""
    seconds = payload.get("expires_in")
    try:
        seconds_int = int(seconds)
    except (TypeError, ValueError):
        return None
    if seconds_int <= 0:
        return None
    return dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds_int)
