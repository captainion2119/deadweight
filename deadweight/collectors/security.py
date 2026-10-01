"""Security & identity: KMS, Secrets Manager, WAF, Private CA, IAM, GuardDuty, Security Hub, CloudTrail, Config."""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Resource
from ..pricing import RATES
from .base import Ctx, collector


@collector("KMS", "security", bill="AWS Key Management Service", client="kms",
           actions=("kms:ListKeys", "kms:DescribeKey", "kms:GetKeyLastUsage"),
           desc="Customer-managed keys with last use (disabled keys are still billed)")
def kms(ctx: Ctx) -> None:
    c = ctx.client("kms")
    keys = list(ctx.pages(c, "list_keys", "Keys"))

    def describe(k: dict):
        return ctx.step("KMS DescribeKey", lambda: ctx.call(c, "describe_key", KeyId=k["KeyId"])["KeyMetadata"])
    for m in ctx.map(describe, keys):
        if not m or m.get("KeyManager") != "CUSTOMER":
            continue
        state = m.get("KeyState", "")
        billed = state not in ("PendingDeletion", "PendingReplicaDeletion")
        r = Resource("KMS", ctx.region, "key", m["KeyId"], m.get("Description") or m["KeyId"], state, m["Arn"],
                     f"{m.get('KeySpec', '')} · {m.get('KeyUsage', '')}" + (" · multi-region" if m.get("MultiRegion") else ""),
                     monthly_estimate=RATES["kms_key_month"] if billed else 0.0, created=str(m.get("CreationDate", "")),
                     estimate_note="Approx customer-managed key monthly charge; requests excluded" if billed
                                   else "Pending deletion: no longer billed")
        r.details.update(key_state=state, deletion_date=str(m.get("DeletionDate", "")))
        if billed and hasattr(c, "get_key_last_usage"):        # API added April 2026
            lu = ctx.step("KMS GetKeyLastUsage", lambda: ctx.call(c, "get_key_last_usage", KeyId=m["KeyId"])) or {}
            last = (lu.get("KeyLastUsage") or {})
            r.details.update(last_used=str(last.get("Timestamp", "") or ""), last_operation=last.get("Operation", ""),
                             tracking_start=str(lu.get("TrackingStartDate", "") or last.get("TrackingStartDate", "") or ""))
        ctx.add(r)


@collector("Secrets Manager", "security", bill="AWS Secrets Manager", client="secretsmanager",
           actions=("secretsmanager:ListSecrets",), desc="Secrets with last-accessed date and rotation")
def secrets(ctx: Ctx) -> None:
    c = ctx.client("secretsmanager")
    for x in ctx.pages(c, "list_secrets", "SecretList"):
        r = Resource("Secrets Manager", ctx.region, "secret", x["ARN"], x["Name"], "active", x["ARN"],
                     f"rotation {'on' if x.get('RotationEnabled') else 'off'} · last accessed {str(x.get('LastAccessedDate', 'never'))[:10]}",
                     {t.get("Key", ""): t.get("Value", "") for t in x.get("Tags", [])},
                     monthly_estimate=RATES["secret_month"], created=str(x.get("CreatedDate", "")),
                     estimate_note="Approx per-secret monthly charge; API calls excluded")
        r.details.update(last_accessed=str(x.get("LastAccessedDate", "")), rotation=bool(x.get("RotationEnabled")),
                         primary_region=x.get("PrimaryRegion"))
        ctx.add(r)


@collector("WAF", "security", bill="AWS WAF", client="wafv2",
           actions=("wafv2:ListWebACLs", "wafv2:GetWebACL", "wafv2:ListResourcesForWebACL", "cloudwatch:GetMetricData"),
           desc="Web ACLs (regional + CloudFront) priced per ACL and rule; associations and request counts")
def waf(ctx: Ctx) -> None:
    c = ctx.client("wafv2")
    scopes = ["REGIONAL"] + (["CLOUDFRONT"] if ctx.region == "us-east-1" else [])
    for scope in scopes:
        for acl in ctx.pages(c, "list_web_acls", "WebACLs", Scope=scope):
            d = ctx.step("WAF GetWebACL", lambda: ctx.call(c, "get_web_acl", Name=acl["Name"], Id=acl["Id"], Scope=scope)) or {}
            rules = len((d.get("WebACL") or {}).get("Rules", []))
            est = RATES["waf_acl_month"] + rules * RATES["waf_rule_month"]
            r = Resource("WAF", "global" if scope == "CLOUDFRONT" else ctx.region, "web-acl", acl["ARN"], acl["Name"], "active",
                         acl["ARN"], f"{scope.lower()} · {rules} rules", monthly_estimate=est,
                         estimate_note=f"$5/web ACL + {rules} rule(s) × $1; $0.60 per million requests and paid managed rule groups excluded")
            r.details["rules"] = rules
            if scope == "REGIONAL":
                assoc = 0
                for rtype in ("APPLICATION_LOAD_BALANCER", "API_GATEWAY", "APPSYNC", "COGNITO_USER_POOL", "APP_RUNNER_SERVICE"):
                    out = ctx.step("WAF ListResourcesForWebACL",
                                   lambda rtype=rtype: ctx.call(c, "list_resources_for_web_acl", WebACLArn=acl["ARN"], ResourceType=rtype))
                    if out is None:
                        assoc = None
                        break
                    assoc += len(out.get("ResourceArns", []))
                r.details["associated"] = assoc
            # WAF emits request metrics only when non-zero.
            dims = {"WebACL": acl["Name"], "Rule": "ALL", **({"Region": ctx.region} if scope == "REGIONAL" else {})}
            for metric in ("AllowedRequests", "BlockedRequests", "CountedRequests"):
                ctx.metric(r, f"waf_{metric}_30d", "AWS/WAFV2", metric, dims, days=30, missing="zero",
                           region=ctx.region if scope == "REGIONAL" else "us-east-1")
            ctx.add(r)


@collector("Private CA", "security", bill="AWS Certificate Manager", client="acm-pca",
           actions=("acm-pca:ListCertificateAuthorities",), desc="Private certificate authorities ($400/month each)")
def private_ca(ctx: Ctx) -> None:
    c = ctx.client("acm-pca")
    for x in ctx.pages(c, "list_certificate_authorities", "CertificateAuthorities"):
        status = x.get("Status", "")
        if status == "DELETED":
            continue
        short = x.get("UsageMode") == "SHORT_LIVED_CERTIFICATE"
        est = RATES["pca_short_lived_month"] if short else RATES["pca_month"]
        ctx.add(Resource("Private CA", ctx.region, "certificate-authority", x["Arn"],
                         (x.get("CertificateAuthorityConfiguration") or {}).get("Subject", {}).get("CommonName", "") or x["Arn"].rsplit("/", 1)[-1],
                         status.lower(), x["Arn"], f"{x.get('Type', '')} · {x.get('UsageMode', 'GENERAL_PURPOSE')}",
                         monthly_estimate=est, created=str(x.get("CreatedAt", "")),
                         estimate_note=f"${est:g}/month per CA (charged until deleted, including while disabled); certificates excluded"))


@collector("IAM", "security", scope="global", client="iam",
           actions=("iam:GetAccountSummary", "iam:ListUsers", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"),
           desc="Root credentials/MFA summary, users and access-key age (hygiene, no cost)")
def iam(ctx: Ctx) -> None:
    c = ctx.client("iam", "us-east-1")
    summary = ctx.call(c, "get_account_summary").get("SummaryMap", {})
    acct = Resource("IAM", "global", "account-summary", f"account/{ctx.account}", "Account root", "active",
                    f"arn:{ctx.partition}:iam::{ctx.account}:root",
                    f"root MFA {'on' if summary.get('AccountMFAEnabled') else 'OFF'} · root access keys {summary.get('AccountAccessKeysPresent', 0)}",
                    monthly_estimate=0.0, estimate_note="IAM is free")
    acct.details.update(root_mfa=bool(summary.get("AccountMFAEnabled")), root_keys=int(summary.get("AccountAccessKeysPresent", 0)),
                        users=summary.get("Users"), roles=summary.get("Roles"))
    ctx.add(acct)
    now = datetime.now(timezone.utc)
    users = list(ctx.pages(c, "list_users", "Users"))

    def keys(u: dict):
        out = []
        for k in ctx.pages(c, "list_access_keys", "AccessKeyMetadata", UserName=u["UserName"]):
            last = ctx.step("IAM GetAccessKeyLastUsed", lambda: ctx.call(c, "get_access_key_last_used", AccessKeyId=k["AccessKeyId"])) or {}
            out.append((k, (last.get("AccessKeyLastUsed") or {}).get("LastUsedDate")))
        return u, out
    for u, ks in ctx.map(keys, users):
        ctx.add(Resource("IAM", "global", "user", u["Arn"], u["UserName"], "active", u["Arn"], f"{len(ks)} access key(s)",
                         monthly_estimate=0.0, estimate_note="IAM is free", created=str(u.get("CreateDate", ""))))
        for k, last in ks:
            created = k.get("CreateDate")
            age = (now - created).days if isinstance(created, datetime) else None
            r = Resource("IAM", "global", "access-key", k["AccessKeyId"], f"{u['UserName']} · {k['AccessKeyId'][-4:]}",
                         str(k.get("Status", "")).lower(), "", f"age {age if age is not None else '?'} d · last used {str(last or 'never')[:10]}",
                         monthly_estimate=0.0, estimate_note="IAM is free", created=str(created or ""))
            r.details.update(age_days=age, last_used=str(last or ""), user=u["UserName"])
            r.relate("user", u["Arn"])
            ctx.add(r)


@collector("GuardDuty", "security", bill="Amazon GuardDuty", client="guardduty",
           actions=("guardduty:ListDetectors", "guardduty:GetDetector"), desc="Detectors (usage-based)")
def guardduty(ctx: Ctx) -> None:
    c = ctx.client("guardduty")
    for d in ctx.pages(c, "list_detectors", "DetectorIds"):
        x = ctx.call(c, "get_detector", DetectorId=d)
        ctx.add(Resource("GuardDuty", ctx.region, "detector", d, d, str(x.get("Status", "")).lower(),
                         ctx.arn("guardduty", f"detector/{d}"), f"finding frequency {x.get('FindingPublishingFrequency', '')}",
                         estimate_note="Billed per event/GB analysed; use actual cost"))


@collector("Security Hub", "security", bill="AWS Security Hub", client="securityhub",
           actions=("securityhub:DescribeHub",), desc="Hub subscription (billed per check/finding)")
def securityhub(ctx: Ctx) -> None:
    c = ctx.client("securityhub")
    x = ctx.call(c, "describe_hub")
    ctx.add(Resource("Security Hub", ctx.region, "hub", x.get("HubArn", "hub"), "Security Hub", "enabled", x.get("HubArn", ""),
                     estimate_note="Billed per security check and finding ingested; use actual cost",
                     created=str(x.get("SubscribedAt", ""))))


@collector("CloudTrail", "security", bill="AWS CloudTrail", client="cloudtrail",
           actions=("cloudtrail:DescribeTrails", "cloudtrail:GetEventSelectors", "cloudtrail:ListEventDataStores"),
           desc="Trails (paid copies / data events) and CloudTrail Lake event data stores")
def cloudtrail(ctx: Ctx) -> None:
    c = ctx.client("cloudtrail")
    for t in ctx.call(c, "describe_trails", includeShadowTrails=False).get("trailList", []):
        sel = ctx.step("CloudTrail event selectors", lambda: ctx.call(c, "get_event_selectors", TrailName=t["TrailARN"])) or {}
        data_events = bool(sel.get("AdvancedEventSelectors")) and any(
            any(f.get("Field") == "eventCategory" and "Data" in f.get("Equals", []) for f in s.get("FieldSelectors", []))
            for s in sel.get("AdvancedEventSelectors", [])) or any(s.get("DataResources") for s in sel.get("EventSelectors", []))
        r = Resource("CloudTrail", ctx.region, "trail", t["TrailARN"], t["Name"], "active", t["TrailARN"],
                     ("multi-region" if t.get("IsMultiRegionTrail") else "single-region")
                     + (" · organization" if t.get("IsOrganizationTrail") else "") + (" · data events" if data_events else ""),
                     estimate_note="First copy of management events is free; extra copies $2/100k events, data events $0.10/100k")
        r.details.update(data_events=data_events, multi_region=t.get("IsMultiRegionTrail"), s3_bucket=t.get("S3BucketName"))
        ctx.add(r)

    def lake():
        for s in ctx.pages(c, "list_event_data_stores", "EventDataStores"):
            ctx.add(Resource("CloudTrail", ctx.region, "event-data-store", s["EventDataStoreArn"], s.get("Name", ""),
                             str(s.get("Status", "")).lower(), s["EventDataStoreArn"],
                             estimate_note="CloudTrail Lake: billed per GB ingested and stored; use actual cost"))
    ctx.step("CloudTrail Lake", lake)


@collector("Config", "security", bill="AWS Config", client="config",
           actions=("config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus"),
           desc="Configuration recorders (billed per configuration item)")
def config(ctx: Ctx) -> None:
    c = ctx.client("config")
    status = {s["name"]: s for s in ctx.call(c, "describe_configuration_recorder_status").get("ConfigurationRecordersStatus", [])}
    for rec in ctx.call(c, "describe_configuration_recorders").get("ConfigurationRecorders", []):
        st = status.get(rec["name"], {})
        group = rec.get("recordingGroup") or {}
        mode = (rec.get("recordingMode") or {}).get("recordingFrequency", "CONTINUOUS")
        ctx.add(Resource("Config", ctx.region, "recorder", f"{ctx.region}/{rec['name']}", rec["name"],
                         "recording" if st.get("recording") else "stopped", rec.get("arn", ""),
                         f"{'all resources' if group.get('allSupported') else 'selected resources'} · {mode.lower()}",
                         estimate_note="$0.003 per configuration item recorded (continuous); use actual cost"))
