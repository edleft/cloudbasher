"""AWS STS helpers for credential upgrade."""

from __future__ import annotations

import datetime as dt
import json
import time
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Optional

from cloudbasher.core.exceptions import CloudShellAutomationError
from cloudbasher.core.utils.output import detail
from cloudbasher.csp.aws.credentials import AwsSessionCreds
from cloudbasher.csp.aws.signing import sigv4_sign, _build_url_opener, api_detail, api_log

_STS_HOST = "sts.amazonaws.com"
_STS_REGION = "us-east-1"
_STS_VERSION = "2011-06-15"
_STS_NS = f"https://{_STS_HOST}/doc/{_STS_VERSION}/"


def _sts_post(
    action: str,
    params: dict[str, str],
    creds: AwsSessionCreds,
    timeout: int,
    proxy_url: Optional[str],
    proxy_insecure: bool,
    *,
    host: str = _STS_HOST,
    service: str = "sts",
    version: str = _STS_VERSION,
) -> str:
    """Sign and POST a form-encoded STS request. Returns the raw response body."""
    all_params = {"Action": action, "Version": version, **params}
    body = urllib.parse.urlencode(sorted(all_params.items())).encode("ascii")

    now = dt.datetime.now(dt.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    headers = sigv4_sign(
        method="POST",
        service=service,
        region=_STS_REGION,
        host=host,
        canonical_uri="/",
        canonical_query="",
        body=body,
        creds=creds,
        amz_date=amz_date,
        date_stamp=date_stamp,
    )


    headers["Content-Type"] = "application/x-www-form-urlencoded"

    req = urllib.request.Request(
        url=f"https://{host}/",
        data=body,
        headers=headers,
        method="POST",
    )
    opener = _build_url_opener(proxy_url, proxy_insecure=proxy_insecure)


    api_log(creds, f"API request: POST {host} Action={action}")

    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            api_log(creds, f"API response: POST {host} Action={action} status={resp.status}")
            return raw
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        raise CloudShellAutomationError(
            f"{service.upper()} {action} failed: HTTP {exc.code}; body={raw}"
        ) from exc
    except urllib.error.URLError as exc:
        raise CloudShellAutomationError(
            f"{service.upper()} {action} request failed: {exc.reason}"
        ) from exc


def _parse_creds_from_sts(
    raw: str, action: str, parent: Optional[AwsSessionCreds] = None
) -> AwsSessionCreds:
    """Parse Credentials element from an STS response (JSON or XML)."""
    if raw.lstrip().startswith("{"):
        j = json.loads(raw)

        result_key = f"{action}Result"
        response_key = f"{action}Response"
        result_obj = j.get(response_key, j).get(result_key, {})
        creds_obj = result_obj.get("Credentials", {})


        principal = result_obj.get("AssumedRoleUser") or result_obj.get("FederatedUser") or {}
        return AwsSessionCreds(
            principal_arn=principal.get("Arn") or None,
            cred_ref=parent.cred_ref if parent else "",
            access_key=creds_obj["AccessKeyId"],
            secret_key=creds_obj["SecretAccessKey"],
            session_token=creds_obj["SessionToken"],
            expiration=creds_obj.get("Expiration") or None,


            issued_at=time.time(),
        )
    else:
        root = ET.fromstring(raw)

        def _text(tag: str) -> str:
            el = root.find(f".//{{{_STS_NS}}}{tag}")
            return (el.text or "") if el is not None else ""

        return AwsSessionCreds(
            access_key=_text("AccessKeyId"),
            secret_key=_text("SecretAccessKey"),
            session_token=_text("SessionToken"),
            expiration=_text("Expiration") or None,


            principal_arn=_text("Arn") or None,
            cred_ref=parent.cred_ref if parent else "",
            issued_at=time.time(),
        )


FEDERATION_TOKEN_MAX_SECONDS = 129600


ASSUME_ROLE_DEFAULT_SECONDS = 3600
ASSUME_ROLE_CEILING_SECONDS = 43200


ROLE_CHAINING_MAX_SECONDS = 3600


def role_max_session_duration(
    *,
    creds: AwsSessionCreds,
    role_arn: str,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> Optional[int]:
    """The role's own `MaxSessionDuration`, or None if we cannot find out."""
    name = role_arn.rsplit("/", 1)[-1].strip()
    if not name:
        return None
    try:
        raw = _sts_post(
            "GetRole",
            {"RoleName": name},
            creds,
            timeout,
            proxy_url,
            proxy_insecure,
            host="iam.amazonaws.com",
            service="iam",
            version="2010-05-08",
        )
    except Exception as exc:  # noqa: BLE001 -- refusal is an answer, see above
        detail(
            f"iam:GetRole unavailable for {name} ({type(exc).__name__}); "
            "using AssumeRole's default duration",
            axis=creds.identity_axis,
        )
        return None
    m = re.search(r"<MaxSessionDuration>(\d+)</MaxSessionDuration>", raw)
    if not m:
        return None
    value = int(m.group(1))
    detail(f"iam:GetRole {name} MaxSessionDuration={value}s", axis=creds.identity_axis)
    return min(value, ASSUME_ROLE_CEILING_SECONDS)


def sts_assume_role(
    *,
    creds: AwsSessionCreds,
    role_arn: str,
    role_session_name: str,
    duration_seconds: int = 3600,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> AwsSessionCreds:
    """Assume an IAM role and return the resulting ASIA credentials."""
    detail(
        f"sts_assume_role role_arn={role_arn} session_name={role_session_name}",
        axis=creds.identity_axis,
    )
    raw = _sts_post(
        "AssumeRole",
        {
            "RoleArn": role_arn,
            "RoleSessionName": role_session_name,
            "DurationSeconds": str(duration_seconds),
        },
        creds,
        timeout,
        proxy_url,
        proxy_insecure,
    )
    result = _parse_creds_from_sts(raw, "AssumeRole", creds)


    api_detail(result, "sts_assume_role ok")
    return result


def sts_get_federation_token(
    *,
    creds: AwsSessionCreds,
    name: str,
    duration_seconds: int = FEDERATION_TOKEN_MAX_SECONDS,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> AwsSessionCreds:
    """Get a federated-user ASIA credential from permanent IAM key credentials."""
    import json as _json

    policy = _json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        },
        separators=(",", ":"),
    )
    detail(f"sts_get_federation_token name={name}", axis=creds.identity_axis)
    raw = _sts_post(
        "GetFederationToken",
        {
            "Name": name,
            "DurationSeconds": str(duration_seconds),
            "Policy": policy,
        },
        creds,
        timeout,
        proxy_url,
        proxy_insecure,
    )
    result = _parse_creds_from_sts(raw, "GetFederationToken", creds)
    api_detail(result, "sts_get_federation_token ok")
    return result


def sts_get_caller_identity(
    *,
    creds: AwsSessionCreds,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> tuple[str, str, str]:
    """Resolve which principal a set of credentials actually is."""
    detail("sts_get_caller_identity", axis=creds.identity_axis)
    raw = _sts_post("GetCallerIdentity", {}, creds, timeout, proxy_url, proxy_insecure)


    if raw.lstrip().startswith("{"):
        payload = json.loads(raw)
        result = payload.get("GetCallerIdentityResponse", payload).get(
            "GetCallerIdentityResult", {}
        )
        arn = str(result.get("Arn", ""))
        account = str(result.get("Account", ""))
        user_id = str(result.get("UserId", ""))
    else:


        def _tag(name: str) -> str:
            match = re.search(rf"<(?:\w+:)?{name}>([^<]*)</(?:\w+:)?{name}>", raw)
            return match.group(1) if match else ""

        arn, account, user_id = _tag("Arn"), _tag("Account"), _tag("UserId")
    if not arn:


        raise CloudShellAutomationError(
            "STS GetCallerIdentity returned no <Arn> "
            f"(HTTP 200, {len(raw)} bytes -- unrecognised response shape)"
        )
    detail(f"sts_get_caller_identity ok arn={arn}", axis=creds.identity_axis)
    return arn, account, user_id


def sts_get_session_token(
    *,
    creds: AwsSessionCreds,
    duration_seconds: int = 43200,
    timeout: int = 30,
    proxy_url: Optional[str] = None,
    proxy_insecure: bool = False,
) -> AwsSessionCreds:
    """Upgrade permanent IAM key credentials to a temporary session token."""
    detail("sts_get_session_token", axis=creds.identity_axis)
    raw = _sts_post(
        "GetSessionToken",
        {"DurationSeconds": str(duration_seconds)},
        creds,
        timeout,
        proxy_url,
        proxy_insecure,
    )
    result = _parse_creds_from_sts(raw, "GetSessionToken", creds)


    api_detail(result, "sts_get_session_token ok")
    return result
