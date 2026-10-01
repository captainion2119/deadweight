"""AWS session plumbing: client pool, retries, error classification, read-only role assumption."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

import boto3
import botocore.session
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.exceptions import (BotoCoreError, ClientError, ConnectTimeoutError, EndpointConnectionError,
                                 ReadTimeoutError)

RETRY_CONFIG = Config(
    retries={"mode": "adaptive", "max_attempts": 8},
    max_pool_connections=64,
    connect_timeout=10,
    read_timeout=60,
    user_agent_extra="deadweight",
)

# Session policies attached when assuming a role: the effective permissions become the
# intersection of the role's policies and these, so the scan is read-only even if the role
# itself could write.
READONLY_SESSION_POLICIES = ("policy/ReadOnlyAccess", "policy/AWSBillingReadOnlyAccess")


class ScanCancelled(Exception):
    """Raised inside collectors when the user cancels the scan."""


class TaskTimeout(Exception):
    """Raised inside collectors when a single collector exceeds its time budget."""


class ClientPool:
    """One botocore client per (service, region), shared by all worker threads.
    botocore clients are thread-safe; creating them is not, hence the lock."""

    def __init__(self, session: boto3.Session):
        self.session = session
        self._clients: dict[tuple[str, str], object] = {}
        self._lock = threading.Lock()

    def get(self, service: str, region: str | None = None):
        key = (service, region or "")
        client = self._clients.get(key)
        if client is None:
            with self._lock:
                client = self._clients.get(key)
                if client is None:
                    client = self.session.client(service, region_name=region or None, config=RETRY_CONFIG)
                    self._clients[key] = client
        return client


# ── error classification ──────────────────────────────────────────────────────

THROTTLE_CODES = {"Throttling", "ThrottlingException", "ThrottledException", "TooManyRequestsException",
                  "RequestLimitExceeded", "SlowDown", "RequestThrottled", "RequestThrottledException",
                  "PriorRequestNotComplete", "LimitExceededException"}
DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedException",
                "AuthorizationError", "Forbidden", "ForbiddenException", "AuthorizationErrorException",
                "InvalidAccessException", "ExpiredToken", "ExpiredTokenException"}
UNAVAILABLE_CODES = {"OptInRequired", "SubscriptionRequiredException", "UnknownOperationException",
                     "UnsupportedOperation", "UnsupportedOperationException", "InvalidAction",
                     "UnrecognizedClientException", "InvalidClientTokenId", "NotSubscribedException",
                     "UnsupportedActionException", "ServiceNotEnabledException"}
NOT_ENABLED_HINTS = ("is not enabled", "not been enabled", "not enrolled", "isn't enrolled", "not opted in",
                     "is not subscribed", "no default view", "does not have an index", "not configured")
UNAVAILABLE_HINTS = ("not authorized to invoke this api", "not available in", "not supported in",
                     "is not supported", "region is disabled", "not currently supported",
                     "your account is not authorized to", "unsupported region", "unknown operation")

# IAM action prefixes that differ from botocore's signing name.
IAM_PREFIX = {"monitoring": "cloudwatch", "email": "ses", "tagging": "tag", "cloudcontrolapi": "cloudformation",
              "elasticmapreduce": "elasticmapreduce", "es": "es", "aoss": "aoss",
              "bedrock-agent": "bedrock", "acm-pca": "acm-pca", "billing": "billing"}


def iam_action(client, operation: str) -> str:
    meta = getattr(client, "meta", None)
    model = getattr(meta, "service_model", None)
    prefix = (getattr(model, "signing_name", None) or getattr(model, "endpoint_prefix", None) or "").lower()
    return f"{IAM_PREFIX.get(prefix, prefix)}:{operation}" if prefix else operation


def classify(exc: BaseException) -> tuple[str, str]:
    """Map an exception to a coverage status and a short detail.

    Statuses: denied (missing IAM permission) · not-available (service/feature not offered in
    this region or account) · not-enabled (feature exists but is switched off) · throttled ·
    timeout · skipped (cancelled) · error (everything else)."""
    if isinstance(exc, ScanCancelled):
        return "skipped", "scan cancelled"
    if isinstance(exc, TaskTimeout):
        return "timeout", str(exc)
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        code, msg = str(err.get("Code", "")), str(err.get("Message", ""))
        low = msg.lower()
        detail = f"{code}: {msg}" if msg else code
        if code in THROTTLE_CODES or "rate exceeded" in low:
            return "throttled", detail
        if any(h in low for h in NOT_ENABLED_HINTS):
            return "not-enabled", detail
        if any(h in low for h in UNAVAILABLE_HINTS) or code in UNAVAILABLE_CODES:
            return "not-available", detail
        if code in DENIED_CODES or "not authorized to perform" in low or "is not authorized" in low:
            return "denied", detail
        return "error", detail
    if isinstance(exc, EndpointConnectionError):
        return "not-available", "no endpoint for this service in this region"
    if isinstance(exc, (ConnectTimeoutError, ReadTimeoutError)):
        return "timeout", str(exc)
    if isinstance(exc, BotoCoreError):
        return "error", str(exc)
    return "error", f"{type(exc).__name__}: {exc}"


def failed_action(exc: BaseException, client=None) -> str:
    if isinstance(exc, ClientError) and getattr(exc, "operation_name", None):
        return iam_action(client, exc.operation_name) if client is not None else exc.operation_name
    return ""


# ── identity & read-only role ─────────────────────────────────────────────────

def partition_of(arn: str) -> str:
    parts = (arn or "").split(":")
    return parts[1] if len(parts) > 1 and parts[1] else "aws"


def is_root(identity: dict) -> bool:
    return str(identity.get("Arn", "")).endswith(":root")


def assume_readonly_session(base: boto3.Session, role_arn: str, *, external_id: str | None = None,
                            session_name: str = "deadweight", region: str | None = None) -> boto3.Session:
    """A boto3 session for `role_arn` whose credentials refresh automatically and are
    limited to read-only actions by AWS-managed session policies."""
    sts = base.client("sts", config=RETRY_CONFIG)
    partition = partition_of(role_arn)
    policies = [{"arn": f"arn:{partition}:iam::aws:{p}"} for p in READONLY_SESSION_POLICIES]

    def refresh() -> dict:
        kw = {"RoleArn": role_arn, "RoleSessionName": session_name, "PolicyArns": policies, "DurationSeconds": 3600}
        if external_id:
            kw["ExternalId"] = external_id
        creds = sts.assume_role(**kw)["Credentials"]
        expiry = creds["Expiration"]
        if isinstance(expiry, datetime):
            expiry = expiry.astimezone(timezone.utc).isoformat()
        return {"access_key": creds["AccessKeyId"], "secret_key": creds["SecretAccessKey"],
                "token": creds["SessionToken"], "expiry_time": expiry}

    bc = botocore.session.get_session()
    bc._credentials = RefreshableCredentials.create_from_metadata(
        metadata=refresh(), refresh_using=refresh, method="sts-assume-role")
    return boto3.Session(botocore_session=bc, region_name=region or base.region_name)


def enabled_regions(pool: ClientPool, home: str) -> list[str]:
    try:
        ec2 = pool.get("ec2", home)
        return sorted(r["RegionName"] for r in ec2.describe_regions(AllRegions=False)["Regions"])
    except Exception:
        return sorted(pool.session.get_available_regions("ec2"))
