"""Findings: rule-based waste/hygiene/security checks with $ impact, plus AWS's own recommendations
(Cost Optimization Hub, falling back to Compute Optimizer) and Cost Anomaly Detection results."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable, Iterable

from .aws import classify, failed_action, is_root
from .models import Finding, Resource, ScanResult
from .pricing import RATES

GIB = 1024 ** 3
NONPROD = re.compile(r"(^|[-_.:/\s])(dev|develop|staging|stage|stg|test|qa|uat|sandbox|demo|preview)([-_.:/\s]|$)", re.I)
OLD_FAMILIES = {"t1", "t2", "m1", "m2", "m3", "m4", "c1", "c3", "c4", "r3", "r4", "i2", "d2", "g2", "g3", "p2", "x1", "cc2", "hs1"}
RULES: list[Callable[[ScanResult, dict], Iterable[Finding]]] = []


def rule(fn):
    RULES.append(fn)
    return fn


def _age_days(value) -> int | None:
    if not value:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        s = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            m = re.search(r"(\d{4}-\d{2}-\d{2})", s)
            if not m:
                return None
            dt = datetime.fromisoformat(m.group(1))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - dt).days)


def F(rule_id: str, title: str, severity: str, category: str, r: Resource | None = None, savings: float | None = None,
      detail: str = "") -> Finding:
    return Finding(rule_id, title, severity, category, resource_key=(r.arn or r.resource_id) if r else "",
                   resource_name=(r.name or r.resource_id) if r else "", service=r.service if r else "",
                   region=r.region if r else "", monthly_savings=round(savings, 2) if savings else savings, detail=detail)


def _by(res: ScanResult) -> dict:
    idx: dict = {"service": defaultdict(list), "id": {}}
    for r in res.resources:
        idx["service"][r.service].append(r)
        idx["id"][r.resource_id] = r
        if r.arn:
            idx["id"][r.arn] = r
    return idx


def _metric(r: Resource, key: str):
    return (r.details.get("metrics") or {}).get(key)


def _sev(amount: float | None, high: float = 20, medium: float = 5) -> str:
    if amount is None:
        return "low"
    return "high" if amount >= high else "medium" if amount >= medium else "low"


# ── waste ────────────────────────────────────────────────────────────────────

@rule
def ebs_unattached(res, idx):
    for r in idx["service"]["EBS"]:
        if r.state == "available":
            yield F("ebs-unattached", "Unattached EBS volume", _sev(r.monthly_estimate), "waste", r, r.monthly_estimate,
                    f"{r.config}; not attached to any instance. Snapshot it if needed, then delete.")


@rule
def eip_idle(res, idx):
    for r in idx["service"]["Elastic IP"]:
        if r.state == "idle":
            yield F("eip-idle", "Elastic IP not associated", "medium", "waste", r, r.monthly_estimate,
                    f"{r.config} is billed $0.005/h while unused. Release it if it is not reserved for a reason.")
        elif r.usage_state == "stopped-billed":
            yield F("eip-stopped-instance", "Elastic IP on a stopped instance", "low", "waste", r, r.monthly_estimate,
                    "; ".join(r.usage_evidence) + ". The address is billed while the instance is stopped.")


@rule
def stopped_instances(res, idx):
    for r in idx["service"]["EC2"]:
        if r.state != "stopped":
            continue
        vols = [idx["id"].get(v) for v in r.relations.get("volume", [])]
        cost = sum((v.monthly_estimate or 0) for v in vols if v)
        m = re.search(r"\((\d{4}-\d{2}-\d{2})", r.details.get("state_reason", ""))
        age = _age_days(m.group(1)) if m else None
        if age is None or age >= 7:
            yield F("ec2-stopped", "Stopped instance still paying for storage", _sev(cost, 10, 2), "waste", r, cost or None,
                    f"Stopped{f' for {age} days' if age is not None else ''}; {len(vols)} attached volume(s) still billed. "
                    "Create an AMI and terminate if it is no longer needed.")


@rule
def ec2_idle(res, idx):
    # Compute Optimizer's all-of test: peak CPU < 5% AND < 5 MB network per day over 14 days (see deadweight.usage).
    for r in idx["service"]["EC2"]:
        if r.state == "running" and r.usage_state == "idle":
            yield F("ec2-idle", "Idle EC2 instance", _sev(r.monthly_estimate), "waste", r, r.monthly_estimate,
                    "; ".join(r.usage_evidence) + ". Stop, downsize or schedule it.")


@rule
def ecs_idle(res, idx):
    for r in idx["service"]["ECS"]:
        if r.resource_type == "service" and r.usage_state == "idle":
            yield F("ecs-idle", "ECS service doing no work", _sev(r.monthly_estimate), "waste", r, r.monthly_estimate,
                    "; ".join(r.usage_evidence) + ". Scale it to zero or delete it if nothing depends on it.")


@rule
def rds_idle(res, idx):
    for svc in ("RDS", "DocumentDB", "Neptune"):
        for r in idx["service"][svc]:
            conns = _metric(r, "connections_max_14d")
            if r.resource_type == "db-instance" and r.state == "available" and conns is not None and conns == 0:
                yield F("rds-idle", "Database with no connections in 14 days", _sev(r.monthly_estimate), "waste", r,
                        r.monthly_estimate, "Zero connections for 14 days. Snapshot and delete, or stop it while unused.")


@rule
def rds_multiaz_nonprod(res, idx):
    for r in idx["service"]["RDS"]:
        if r.resource_type == "db-instance" and r.details.get("multi_az") and r.monthly_estimate:
            label = " ".join([r.name, r.resource_id, *r.tags.values()])
            if NONPROD.search(label):
                yield F("rds-multiaz-nonprod", "Multi-AZ on a non-production database", "medium", "rightsizing", r,
                        r.monthly_estimate / 2, "Name/tags look non-production; Single-AZ halves instance and storage cost.")


NAT_TITLES = {"orphaned": ("nat-orphaned", "NAT gateway that nothing routes to"),
              "idle": ("nat-idle", "NAT gateway with no traffic in 30 days"),
              "low-use": ("nat-low-use", "NAT gateway paid to exist, moving almost no data")}


@rule
def nat_idle(res, idx):
    """Routing, workloads behind it and 30 days of traffic (see deadweight.usage). Savings include the gateway's
    Elastic IPs, which are released with it."""
    for r in idx["service"]["NAT Gateway"]:
        if r.state != "available" or r.usage_state not in NAT_TITLES:
            continue
        rule_id, title = NAT_TITLES[r.usage_state]
        eips = [idx["id"].get(a) for a in r.relations.get("elastic-ip", [])]
        eip_cost = sum((e.monthly_estimate or 0) for e in eips if e)
        savings = (r.monthly_estimate or 0) + eip_cost
        detail = "; ".join(r.usage_evidence)
        if eip_cost:
            detail += f"; its {len([e for e in eips if e])} Elastic IP(s) add ${eip_cost:,.2f}/mo"
        detail += (". Check it is not a DR standby; remove it, or share one NAT per VPC and use VPC endpoints for AWS services."
                   if r.usage_state != "orphaned" else ". Delete it after confirming no route will be added.")
        yield F(rule_id, title, _sev(savings), "waste", r, savings, detail)


@rule
def nat_per_vpc(res, idx):
    by_vpc = defaultdict(list)
    for r in idx["service"]["NAT Gateway"]:
        if r.state == "available":
            vpc = (r.relations.get("vpc") or [None])[0]
            if vpc:                      # older reports do not record the VPC; don't guess
                by_vpc[(r.region, vpc)].append(r)
    for (region, vpc), nats in by_vpc.items():
        if len(nats) > 1:
            hourly = min((n.monthly_estimate or 0) for n in nats)
            yield Finding("nat-consolidate", f"{len(nats)} NAT gateways in one VPC", "low", "rightsizing", resource_key=vpc,
                          resource_name=vpc, service="NAT Gateway", region=region, monthly_savings=round(hourly * (len(nats) - 1), 2),
                          detail="One NAT per AZ buys resilience; non-production VPCs can usually share one (saves the others' hourly charge).")


@rule
def lb_no_targets(res, idx):
    for r in idx["service"]["ELB"]:
        t, h = r.details.get("targets"), r.details.get("healthy_targets")
        if t == 0:
            yield F("lb-no-targets", "Load balancer with no targets", _sev(r.monthly_estimate), "waste", r, r.monthly_estimate,
                    "No registered targets. Delete it if it is not about to be used.")
        elif t and h == 0:
            yield F("lb-unhealthy", "Load balancer with no healthy targets", "medium", "hygiene", r, None,
                    f"{t} target(s), none healthy.")


@rule
def gp2_to_gp3(res, idx):
    for r in idx["service"]["EBS"]:
        if r.details.get("volume_type") == "gp2":
            size = r.details.get("size_gb") or 0
            save = size * (RATES["ebs_gb"]["gp2"] - RATES["ebs_gb"]["gp3"])
            if save > 0:
                yield F("ebs-gp2", "gp2 volume can move to gp3", "low", "rightsizing", r, save,
                        "gp3 is 20% cheaper per GB with a 3,000 IOPS baseline; migrate in place with ModifyVolume.")


@rule
def previous_generation(res, idx):
    for r in idx["service"]["EC2"]:
        itype = r.details.get("instance_type", "")
        if r.state == "running" and itype.split(".")[0] in OLD_FAMILIES:
            yield F("ec2-previous-gen", "Previous-generation instance type", "low", "rightsizing", r,
                    (r.monthly_estimate or 0) * 0.1 or None, f"{itype}: current generations (or Graviton) are typically 10–40% cheaper per unit of performance.")


@rule
def fargate_x86(res, idx):
    for r in idx["service"]["ECS"]:
        if r.details.get("launch_type") == "FARGATE" and r.details.get("arch") == "X86_64" and r.monthly_estimate:
            yield F("fargate-graviton", "Fargate service on x86", "low", "rightsizing", r, r.monthly_estimate * 0.2,
                    "Fargate on ARM64 (Graviton) is 20% cheaper if the images are multi-arch.")


@rule
def eks_extended(res, idx):
    for r in idx["service"]["EKS"]:
        if r.details.get("version_status") == "EXTENDED_SUPPORT":
            yield F("eks-extended-support", "EKS cluster on extended support", "high", "waste", r,
                    (RATES["eks_extended_h"] - RATES["eks_h"]) * 730,
                    f"Kubernetes {r.details.get('version')} is past standard support; upgrading removes the $0.50/h surcharge.")


@rule
def log_retention(res, idx):
    for r in idx["service"]["CloudWatch Logs"]:
        gb = (r.details.get("stored_bytes") or 0) / GIB
        if not r.details.get("retention_days") and gb >= 1:
            yield F("logs-no-retention", "Log group never expires", _sev(r.monthly_estimate, 10, 2), "hygiene", r,
                    r.monthly_estimate, f"{gb:,.1f} GB kept forever. Set a retention period (savings up to the full storage cost).")


@rule
def secrets_unused(res, idx):
    for r in idx["service"]["Secrets Manager"]:
        last, created = _age_days(r.details.get("last_accessed")), _age_days(r.created)
        if (last is not None and last > 90) or (last is None and (created or 0) > 90):
            yield F("secret-unused", "Secret not accessed in 90+ days", "low", "waste", r, r.monthly_estimate,
                    f"Last accessed {f'{last} days ago' if last is not None else 'never'}.")


@rule
def kms_disabled(res, idx):
    for r in idx["service"]["KMS"]:
        if r.state == "Disabled":
            yield F("kms-disabled", "Disabled KMS key still billed", "low", "waste", r, r.monthly_estimate,
                    "Disabled customer-managed keys cost $1/month; schedule deletion if nothing needs to decrypt with it.")


@rule
def old_snapshots(res, idx):
    used_by_ami = {s for a in idx["service"]["AMIs"] for s in a.relations.get("snapshot", [])}
    for r in idx["service"]["EBS Snapshots"]:
        age = _age_days(r.created)
        if age and age > 180 and r.resource_id not in used_by_ami:
            yield F("snapshot-old", "EBS snapshot older than 180 days", "low", "hygiene", r, r.details.get("upper_bound"),
                    f"{age} days old, not used by any AMI. Savings shown are an upper bound (snapshots are incremental).")
    for r in idx["service"]["RDS"]:
        if r.resource_type in ("db-snapshot", "db-cluster-snapshot"):
            age = _age_days(r.created)
            if age and age > 180:
                yield F("rds-snapshot-old", "Manual database snapshot older than 180 days", "low", "hygiene", r,
                        r.details.get("upper_bound"), f"{age} days old; billed if backup storage exceeds the free allowance.")


@rule
def ecr_hygiene(res, idx):
    for r in idx["service"]["ECR"]:
        if r.details.get("lifecycle") is False and (r.details.get("images") or 0) > 20:
            yield F("ecr-no-lifecycle", "ECR repository without a lifecycle policy", "low", "hygiene", r,
                    (r.monthly_estimate or 0) * 0.5 or None,
                    f"{r.details.get('images')} images ({r.details.get('untagged')} untagged). Expire old/untagged images.")


@rule
def s3_hygiene(res, idx):
    for r in idx["service"]["S3"]:
        size = (r.details.get("size_bytes") or 0) / GIB
        if r.details.get("lifecycle") is False and size >= 50:
            yield F("s3-no-lifecycle", "Large bucket without lifecycle rules", "low", "hygiene", r, None,
                    f"{size:,.0f} GB. Consider Intelligent-Tiering or transitions; with versioning "
                    f"{r.details.get('versioning')}, noncurrent versions also accumulate.")


@rule
def route53_empty(res, idx):
    for r in idx["service"]["Route53"]:
        count = r.details.get("record_count")
        if count is None:      # older reports only carry "N records" in the config text
            m = re.match(r"(\d+) records", r.config or "")
            count = int(m.group(1)) if m else None
        if r.resource_type == "hosted-zone" and count is not None and count <= 2:
            yield F("route53-empty-zone", "Hosted zone with only NS/SOA records", "low", "waste", r, r.monthly_estimate,
                    "No records beyond the defaults; delete it if the domain is not in use.")


@rule
def stale_alarms(res, idx):
    for r in idx["service"]["CloudWatch Alarms"]:
        if r.details.get("state") == "INSUFFICIENT_DATA" and (_age_days(r.details.get("state_updated")) or 0) > 30:
            yield F("alarm-stale", "Alarm with insufficient data for 30+ days", "low", "hygiene", r, r.monthly_estimate,
                    "Its metric probably no longer exists (deleted resource).")


@rule
def always_on_fees(res, idx):
    for r in idx["service"]["Transfer Family"]:
        if r.state in ("offline", "stopped"):
            yield F("transfer-stopped", "Stopped Transfer Family server is still billed", "high", "waste", r, r.monthly_estimate,
                    "Endpoints are billed per protocol-hour until the server is deleted.")
    for r in idx["service"]["Private CA"]:
        if r.state == "disabled":
            yield F("pca-disabled", "Disabled private CA is still billed", "high", "waste", r, r.monthly_estimate,
                    "Private CAs cost $400/month until deleted.")
    for r in idx["service"]["SageMaker"]:
        if r.resource_type == "notebook-instance" and r.state == "inservice":
            yield F("sagemaker-notebook", "SageMaker notebook instance running", "medium", "waste", r, r.monthly_estimate,
                    "Billed every hour it runs; stop it or add an auto-stop lifecycle configuration.")


@rule
def public_ipv4(res, idx):
    ips = [r for r in idx["service"]["Public IPv4"] if r.details.get("interface_type") in ("interface", None) and r.relations.get("instance")]
    if ips:
        yield Finding("public-ipv4", f"{len(ips)} instance(s) with an auto-assigned public IPv4", "low", "rightsizing",
                      service="Public IPv4", monthly_savings=round(len(ips) * RATES["public_ipv4_h"] * 730, 2),
                      detail="Each costs $3.65/month. Instances behind a load balancer or reached via SSM/EC2 Instance Connect rarely need one.")


# ── security ─────────────────────────────────────────────────────────────────

@rule
def iam_hygiene(res, idx):
    for r in idx["service"]["IAM"]:
        if r.resource_type == "account-summary":
            if r.details.get("root_keys"):
                yield F("root-access-keys", "Root user has access keys", "high", "security", r, None,
                        "Delete root access keys; use IAM roles / Identity Center instead.")
            if not r.details.get("root_mfa"):
                yield F("root-no-mfa", "Root user has no MFA", "high", "security", r, None, "Enable MFA on the root user.")
        elif r.resource_type == "access-key" and r.state == "active":
            age, last = r.details.get("age_days"), _age_days(r.details.get("last_used"))
            if (last is None and (age or 0) > 30) or (last is not None and last > 90):
                yield F("iam-key-unused", "Active access key unused for 90+ days", "medium", "security", r, None,
                        f"Last used {f'{last} days ago' if last is not None else 'never'}; deactivate it.")
            elif age and age > 90:
                yield F("iam-key-old", "Access key older than 90 days", "low", "security", r, None, f"{age} days old; rotate it.")
    if is_root(res.identity) and not res.meta.get("role_arn"):
        yield Finding("scan-as-root", "This scan used root credentials", "medium", "security", service="IAM",
                      detail="Run the tool with a read-only role (--role-arn) or an SSO read-only profile.")


# ── coverage & anomalies ─────────────────────────────────────────────────────

@rule
def coverage_gaps(res, idx):
    for row in res.reconciliation:
        if row["run_rate"] < 1:
            continue
        if row["status"] in ("no collector", "nothing found", "discovered only"):
            yield Finding("coverage-gap", f"{row['label']}: billed but not inventoried", "info", "coverage", service=row["label"],
                          detail=f"${row['run_rate']:,.2f}/mo run-rate with status '{row['status']}'. "
                                 + ("No collector covers this service yet." if row["status"] == "no collector"
                                    else "Resources were not found or only found generically."))
        elif row["status"] == "partly explained" and row["estimate"] is not None and row["run_rate"] - row["estimate"] > 10:
            yield Finding("coverage-unexplained", f"{row['label']}: ${row['run_rate'] - row['estimate']:,.0f}/mo not explained by resources",
                          "info", "coverage", service=row["label"],
                          detail=f"Estimated ${row['estimate']:,.2f} vs run-rate ${row['run_rate']:,.2f}; usage-based charges or unpriced resources.")


@rule
def anomalies(res, idx):
    for a in res.anomalies:
        impact = a.get("impact") or 0
        yield Finding("cost-anomaly", f"Cost anomaly: {a.get('service') or 'unknown service'}",
                      "high" if impact >= 100 else "medium" if impact >= 10 else "low", "anomaly", service=a.get("service", ""),
                      region=a.get("region", ""),
                      detail=f"${impact:,.2f} impact {a.get('start', '')[:10]} → {(a.get('end') or 'ongoing')[:10]}"
                             + (f" · {a.get('usage_type')}" if a.get("usage_type") else ""))


# ── AWS recommendations ──────────────────────────────────────────────────────

COH_CATEGORY = {"Stop": "waste", "Delete": "waste", "ScaleIn": "waste",
                "Rightsize": "rightsizing", "Upgrade": "rightsizing", "MigrateToGraviton": "rightsizing"}


def coh_category(action: str) -> str:
    """Stop/Delete/ScaleIn are idle verdicts; Purchase* are commitment buys, never waste."""
    if str(action).startswith("Purchase"):
        return "commitment"
    return COH_CATEGORY.get(action, "rightsizing")


def cost_optimization_hub(scanner) -> list[Finding]:
    c = scanner.pool.get("cost-optimization-hub", "us-east-1")
    out = []
    for rec in (x for page in c.get_paginator("list_recommendations").paginate() for x in page.get("items", [])):
        savings = float(rec.get("estimatedMonthlySavings") or 0)
        action = str(rec.get("actionType", ""))
        out.append(Finding(f"coh-{action.lower()}", f"{action}: {rec.get('currentResourceType', '')}",
                           _sev(savings), coh_category(action),
                           resource_key=rec.get("resourceArn") or rec.get("resourceId", ""), resource_name=rec.get("resourceId", ""),
                           service=rec.get("currentResourceType", ""), region=rec.get("region", ""), monthly_savings=round(savings, 2),
                           detail=f"{rec.get('currentResourceSummary', '')} → {rec.get('recommendedResourceSummary', '')} · effort "
                                  f"{rec.get('implementationEffort', '?')}", source="cost-optimization-hub"))
    return out


def _code(e: Exception) -> str:
    return str(getattr(e, "response", {}).get("Error", {}).get("Code", "")) if hasattr(e, "response") else ""


def compute_optimizer_idle(scanner, regions: list[str]) -> tuple[list[Finding], str]:
    """Compute Optimizer's own idle verdicts (EC2, EBS, ECS on Fargate, RDS, NAT, ASG, DynamoDB, ElastiCache…).
    Returns (findings, status) where status is ok | not-enabled | sdk-unsupported | <classify status>."""
    out, seen = [], set()
    for region in regions:
        c = scanner.pool.get("compute-optimizer", region)
        if not hasattr(c, "get_idle_recommendations"):
            return out, "sdk-unsupported"
        token = None
        while True:
            try:
                resp = c.get_idle_recommendations(maxResults=100, **({"nextToken": token} if token else {}))
            except Exception as e:
                if _code(e).startswith("OptInRequired"):
                    return out, "not-enabled"
                raise
            for rec in resp.get("idleRecommendations", []):
                arn = rec.get("resourceArn") or rec.get("resourceId", "")
                if arn in seen:
                    continue
                seen.add(arn)
                rtype = str(rec.get("resourceType", "resource"))
                so = ((rec.get("savingsOpportunityAfterDiscounts") or rec.get("savingsOpportunity") or {})
                      .get("estimatedMonthlySavings") or {})
                savings = float(so.get("value") or 0) or None
                finding = str(rec.get("finding", "Idle"))
                metrics = ", ".join(f"{m.get('name')} {m.get('statistic', '')} {m.get('value')}"
                                    for m in (rec.get("utilizationMetrics") or [])[:3])
                out.append(Finding(f"co-idle-{rtype.lower()}", f"Compute Optimizer: {finding.lower()} {rtype}", _sev(savings), "waste",
                                   resource_key=arn, resource_name=str(rec.get("resourceId") or arn.rsplit("/", 1)[-1]),
                                   service=rtype, region=arn.split(":")[3] if arn.count(":") >= 3 else region,
                                   monthly_savings=round(savings, 2) if savings else None,
                                   detail="; ".join(x for x in (rec.get("findingDescription", ""),
                                                                f"{rec.get('lookBackPeriodInDays', '?')}-day lookback", metrics) if x),
                                   source="compute-optimizer"))
            token = resp.get("nextToken")
            if not token:
                break
    return out, "ok"


def trusted_advisor(scanner) -> tuple[list[Finding], set[str]]:
    """Read-only probe: works only on Business Support+ (or higher) accounts. Returns findings and flagged resource IDs."""
    c = scanner.pool.get("trustedadvisor", "us-east-1")
    out, flagged_ids = [], set()
    recs = [x for page in c.get_paginator("list_recommendations").paginate(pillar="cost_optimizing")
            for x in page.get("recommendationSummaries", [])]
    for rec in recs:
        if rec.get("status") not in ("warning", "error"):
            continue
        agg = ((rec.get("pillarSpecificAggregates") or {}).get("costOptimizing") or {})
        savings = float(agg.get("estimatedMonthlySavings") or 0) or None
        flagged = (rec.get("resourcesAggregates") or {}).get("warningCount", 0) + (rec.get("resourcesAggregates") or {}).get("errorCount", 0)
        f = Finding("ta-" + re.sub(r"[^a-z0-9]+", "-", str(rec.get("name", "")).lower()).strip("-"),
                    f"Trusted Advisor: {rec.get('name', '')}", _sev(savings), "waste", monthly_savings=savings,
                    detail=f"{flagged} resource(s) flagged", source="trusted-advisor")
        keys = []
        if len(out) < 20:
            try:
                for page in c.get_paginator("list_recommendation_resources").paginate(recommendationIdentifier=rec["arn"]):
                    keys += [x["awsResourceId"] for x in page.get("recommendationResourceSummaries", [])
                             if x.get("awsResourceId") and x.get("status") in ("warning", "error")]
            except Exception:
                pass
        f.resource_key = keys[0] if len(keys) == 1 else ""
        flagged_ids.update(keys)
        out.append(f)
    return out, flagged_ids


CONFIG_UNUSED_RULES = {"EIP_ATTACHED", "EC2_VOLUME_INUSE_CHECK", "SECRETSMANAGER_SECRET_UNUSED", "EC2_STOPPED_INSTANCE",
                       "VPC_NETWORK_ACL_UNUSED_CHECK", "EC2_SECURITY_GROUP_ATTACHED_TO_ENI"}


def config_unused(scanner, regions: list[str]) -> tuple[list[Finding], set[str]]:
    """Read existing AWS Config compliance for 'unused resource' managed rules (no rules are created)."""
    out, keys = [], set()
    for region in regions:
        c = scanner.pool.get("config", region)
        rules = [x for page in c.get_paginator("describe_config_rules").paginate() for x in page.get("ConfigRules", [])]
        for rule_ in rules:
            src = rule_.get("Source") or {}
            if src.get("Owner") != "AWS" or src.get("SourceIdentifier") not in CONFIG_UNUSED_RULES:
                continue
            ids = []
            for page in c.get_paginator("get_compliance_details_by_config_rule").paginate(
                    ConfigRuleName=rule_["ConfigRuleName"], ComplianceTypes=["NON_COMPLIANT"]):
                for ev in page.get("EvaluationResults", []):
                    q = (ev.get("EvaluationResultIdentifier") or {}).get("EvaluationResultQualifier") or {}
                    if q.get("ResourceId"):
                        ids.append(q["ResourceId"])
            keys.update(ids)
            if ids:
                out.append(Finding(f"config-{src['SourceIdentifier'].lower().replace('_', '-')}",
                                   f"AWS Config: {rule_['ConfigRuleName']} non-compliant", "info", "hygiene", region=region,
                                   detail=f"{len(ids)} resource(s): " + ", ".join(ids[:5]) + (" …" if len(ids) > 5 else ""),
                                   source="aws-config"))
    return out, keys


USAGE_TITLES = {"idle": "{svc} {typ} doing no work", "orphaned": "{svc} {typ} that nothing uses",
                "low-use": "{svc} {typ} barely used", "stale": "{svc} {typ} not used in a long time",
                "stopped-billed": "{svc} {typ} stopped but still billed"}


def usage_findings(res: ScanResult, existing: list[Finding]) -> list[Finding]:
    """One finding per billed resource whose usage state is waste and that no specific rule already reported."""
    flagged = {f.resource_key for f in existing if f.resource_key}
    out = []
    for r in res.resources:
        key = r.arn or r.resource_id
        if r.usage_state not in USAGE_TITLES or key in flagged or r.resource_id in flagged:
            continue
        if r.details.get("usage_owner") in flagged:      # an IP held by a flagged resource goes away with it
            continue
        cost = r.monthly_estimate or 0
        if cost <= 0 or "excluded" in r.usage_overlays:
            continue
        typ = r.resource_type.replace("-", " ")
        # "Elastic IP" + "elastic ip" → just "Elastic IP"; "Lambda" + "function" stays "Lambda function"
        what = r.service if typ.lower() in r.service.lower() else f"{r.service} {typ}"
        title = USAGE_TITLES[r.usage_state].replace("{svc} {typ}", "{what}").format(what=what)
        sev = "low" if r.usage_state == "stale" or "too-new" in r.usage_overlays else _sev(cost)
        out.append(F(f"usage-{r.usage_state}", title, sev, "waste" if r.usage_state != "stale" else "hygiene", r, cost,
                     "; ".join(r.usage_evidence)))
    return out


def compute_optimizer(scanner, regions: list[str]) -> list[Finding]:
    out = []
    calls = [("get_ec2_instance_recommendations", "instanceRecommendations", "instanceArn", "EC2"),
             ("get_ebs_volume_recommendations", "volumeRecommendations", "volumeArn", "EBS"),
             ("get_lambda_function_recommendations", "lambdaFunctionRecommendations", "functionArn", "Lambda"),
             ("get_ecs_service_recommendations", "ecsServiceRecommendations", "serviceArn", "ECS")]
    for region in regions:
        c = scanner.pool.get("compute-optimizer", region)
        for op, key, arn_key, svc in calls:
            if not hasattr(c, op):
                continue
            token = None
            while True:
                resp = getattr(c, op)(**({"nextToken": token} if token else {}))
                for rec in resp.get(key, []):
                    finding = str(rec.get("finding", "")).upper()
                    if finding in ("OPTIMIZED", "NOTOPTIMIZED", "") and svc != "Lambda":
                        continue
                    opts = rec.get("recommendationOptions") or rec.get("volumeRecommendationOptions") or rec.get(
                        "memorySizeRecommendationOptions") or rec.get("serviceRecommendationOptions") or [{}]
                    so = (opts[0].get("savingsOpportunity") or {}).get("estimatedMonthlySavings") or {}
                    savings = float(so.get("value") or 0) or None
                    if not savings and finding in ("OPTIMIZED", ""):
                        continue
                    out.append(Finding(f"co-{svc.lower()}-{finding.lower()}", f"Compute Optimizer: {svc} {finding.replace('_', ' ').lower()}",
                                       _sev(savings), "rightsizing", resource_key=rec.get(arn_key, ""),
                                       resource_name=str(rec.get(arn_key, "")).rsplit("/", 1)[-1].rsplit(":", 1)[-1], service=svc,
                                       region=region, monthly_savings=round(savings, 2) if savings else None,
                                       detail=", ".join(str(x) for x in (rec.get("findingReasonCodes") or [])), source="compute-optimizer"))
                token = resp.get("nextToken")
                if not token:
                    break
    return out


def _probe(scanner, label: str, fn):
    """Run an optional AWS source; denied / not subscribed / not enrolled become coverage states, not errors."""
    try:
        return fn()
    except Exception as e:
        status, detail = classify(e)
        code = _code(e)
        if label == "Trusted Advisor" and (code == "SubscriptionRequiredException"
                                           or (code.startswith("AccessDenied") and status != "denied")):
            status, detail = "not-available", "needs Business Support+ (or higher): " + detail
        if code.startswith("OptInRequired") or code == "NoSuchConfigurationRecorderException":
            status = "not-enabled"
        scanner.coverage_event(label, "global", status, detail, failed_action(e))
        return None


def _rules(res: ScanResult, on_error=None) -> list[Finding]:
    idx = _by(res)
    found: list[Finding] = []
    for fn in RULES:
        try:
            found.extend(fn(res, idx))
        except Exception as e:
            if on_error:
                on_error(fn, e)
    return found + usage_findings(res, found)


def _finish(res: ScanResult, found: list[Finding]) -> None:
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    found.sort(key=lambda f: (order.get(f.severity, 9), -(f.monthly_savings or 0)))
    res.findings = found
    by_key = defaultdict(list)
    for f in found:
        if f.resource_key:
            by_key[f.resource_key].append(f.rule)
    for r in res.resources:
        rules = by_key.get(r.arn or r.resource_id) or by_key.get(r.resource_id)
        if rules:
            r.details["findings"] = rules


def run(scanner, res: ScanResult) -> None:
    from . import usage
    found = _rules(res, lambda fn, e: scanner.coverage_event(f"Finding rule {fn.__name__}", "global", "error",
                                                             f"{type(e).__name__}: {e}"))
    if scanner.opts.recommendations:
        agrees: set[str] = set()
        co = _probe(scanner, "Compute Optimizer idle", lambda: compute_optimizer_idle(scanner, scanner.regions))
        if co is not None:
            recs, status = co
            found.extend(recs)
            agrees |= {f.resource_key for f in recs}
            scanner.coverage_event("Compute Optimizer idle", "global", status,
                                   {"ok": f"{len(recs)} idle recommendations",
                                    "not-enabled": "Compute Optimizer is not enabled for this account (free opt-in)",
                                    "sdk-unsupported": "upgrade boto3 for GetIdleRecommendations"}.get(status, ""))
        recs = _probe(scanner, "Cost Optimization Hub", lambda: cost_optimization_hub(scanner))
        if recs is not None:
            # COH repackages Compute Optimizer idle verdicts as Stop/Delete: keep the CO one (it carries the metrics).
            recs = [f for f in recs if not (f.category == "waste" and f.resource_key in agrees)]
            found.extend(recs)
            agrees |= {f.resource_key for f in recs if f.category == "waste"}
            scanner.coverage_event("Cost Optimization Hub", "global", "ok", f"{len(recs)} recommendations")
        else:
            recs = _probe(scanner, "Compute Optimizer", lambda: compute_optimizer(scanner, scanner.regions))
            if recs is not None:
                found.extend(recs)
                scanner.coverage_event("Compute Optimizer", "global", "ok", f"{len(recs)} recommendations")
        ta = _probe(scanner, "Trusted Advisor", lambda: trusted_advisor(scanner))
        if ta is not None:
            found.extend(ta[0])
            agrees |= ta[1]
            scanner.coverage_event("Trusted Advisor", "global", "ok", f"{len(ta[0])} cost checks flagged")
        cfg = _probe(scanner, "AWS Config rules", lambda: config_unused(scanner, scanner.regions))
        if cfg is not None:
            found.extend(cfg[0])
            agrees |= cfg[1]
            scanner.coverage_event("AWS Config rules", "global", "ok" if cfg[0] or cfg[1] else "not-enabled",
                                   f"{len(cfg[1])} non-compliant resources" if cfg[1] else "no 'unused resource' managed rules found")
        usage.mark_aws_agrees(res, {k for k in agrees if k})
    _finish(res, found)


def rerun_rules(res: ScanResult) -> None:
    """Recompute rule-based findings for a loaded report (AWS recommendations are kept as saved). Reports written
    before usage classification existed are classified from whatever they contain (no first-seen store)."""
    from . import usage
    if not any(r.usage_state for r in res.resources):
        usage.classify(res, store=None)
    kept = [f for f in res.findings if f.source != "rule"]
    _finish(res, _rules(res) + kept)
