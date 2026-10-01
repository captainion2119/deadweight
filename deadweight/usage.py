"""Usage classification: is a resource billed, is it doing work, and so what is it?

Every resource gets one state:
    active · low-use (paid to exist, does a trickle) · idle (paid to exist, does nothing) · orphaned (nothing references it)
    stopped-billed (parent stopped, storage/IP still billed) · stale (last used long ago) · clutter (pay-per-use, unused,
    costs ~$0) · unknown (no usable signal) · unattributed (billed, not inventoried; summary only)
plus overlays: shared · excluded · too-new · unhealthy · aws-agrees · confirmed.

Thresholds follow AWS's own detectors where they exist (Compute Optimizer idle rules, Trusted Advisor checks, the
AWS Config secretsmanager-secret-unused default); see reports/AWS usage billing and idle detection.md."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .models import Resource, ScanResult

STATES = ("active", "low-use", "idle", "orphaned", "stopped-billed", "stale", "clutter", "unknown", "unattributed")
WASTE_STATES = {"low-use", "idle", "orphaned", "stopped-billed", "stale"}
STORE_PATH = Path.home() / ".cache" / "deadweight" / "usage-state.json"
CONFIRM_DAYS = 7
GIB, MB = 1024 ** 3, 1024 ** 2
EXCLUDE = re.compile(r"(do[-_ ]?not[-_ ]?delete|donotdelete|^keep$|retain|protect|^backup$|disaster[-_ ]?recovery|^dr$)", re.I)
SHARED = {("NAT Gateway", "nat-gateway"), ("VPC", "vpc-endpoint"), ("Transit Gateway", "tgw-attachment")}


@dataclass
class Verdict:
    state: str
    evidence: list[str] = field(default_factory=list)
    confidence: str = "medium"
    window: int = 14


def _metric(r: Resource, key: str):
    return (r.details.get("metrics") or {}).get(key)


def _total(r: Resource, *keys: str) -> float | None:
    vals = [_metric(r, k) for k in keys]
    vals = [v for v in vals if v is not None]
    return sum(vals) if vals else None


def _prefixed_total(r: Resource, prefix: str) -> tuple[float | None, int]:
    vals = [v for k, v in (r.details.get("metrics") or {}).items() if k.startswith(prefix)]
    present = [v for v in vals if v is not None]
    return (sum(present) if present else None), len(vals)


def _daily_max(r: Resource, *keys: str) -> float | None:
    """Largest per-day total across several daily series (e.g. NetworkIn + NetworkOut)."""
    series = [(r.details.get("series") or {}).get(k) or [] for k in keys]
    days: dict[str, float] = {}
    seen = False
    for s in series:
        for day, v in s:
            if v is not None:
                days[day] = days.get(day, 0.0) + v
                seen = True
    return max(days.values()) if seen else None


def _complete(r: Resource, key: str) -> bool:
    pts, win = (r.details.get("metric_points") or {}).get(key), (r.details.get("metric_window") or {}).get(key)
    return bool(win) and pts is not None and pts >= 0.8 * win


def age_days(value, now: datetime | None = None) -> int | None:
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
    return max(0, ((now or datetime.now(timezone.utc)) - dt).days)


# ── per-service rules ─────────────────────────────────────────────────────────

def _nat(r: Resource, idx) -> Verdict | None:
    if r.state not in ("available", "pending"):
        return None
    d = r.details
    if d.get("routed") is False:
        return Verdict("orphaned", ["no route table sends traffic to this NAT gateway"], "high", 30)
    ev = []
    if d.get("enis_behind") == 0:
        ev.append("routed, but no workload network interfaces in the subnets it serves")
    src, dst = _metric(r, "nat_BytesInFromSource_30d"), _metric(r, "nat_BytesInFromDestination_30d")
    out, conns = _metric(r, "nat_BytesOutToDestination_30d"), _metric(r, "nat_ActiveConnectionCount_30d")
    if all(v is None for v in (src, dst, out)):
        if ev:
            return Verdict("idle", ev, "medium", 30)
        return Verdict("unknown", ["no NAT traffic metrics returned for the last 30 days"], "low", 30)
    processed = (src or 0) + (dst or 0)
    existence = float(d.get("hourly") or 0.045) * 730
    if processed == 0 and not (out or 0) and not (conns or 0):
        return Verdict("idle", ev + ["0 bytes and 0 connections in 30 d"], "high", 30)
    gb = processed / GIB
    per_gb = existence / gb if gb > 0 else float("inf")
    d["effective_per_gb"] = None if per_gb == float("inf") else round(per_gb, 2)
    if gb < 1 or per_gb > 5:
        return Verdict("low-use", ev + [f"{gb:,.2f} GB processed in 30 d",
                                        f"≈ ${per_gb:,.2f}/GB effective vs $0.045/GB list" if gb > 0 else "no measurable data processed"],
                       "medium", 30)
    return Verdict("active", [f"{gb:,.1f} GB processed in 30 d (≈ ${per_gb:,.2f}/GB effective)"], "high", 30)


def _ec2(r: Resource, idx) -> Verdict | None:
    if r.state == "running":
        cpu = _metric(r, "cpu_max_14d")
        if cpu is None:
            return Verdict("unknown", ["no CPU metrics for the last 14 days"], "low")
        net = _daily_max(r, "net_in_14d", "net_out_14d")
        conf = "high" if _complete(r, "cpu_max_14d") else "medium"
        if cpu < 5 and net is not None and net < 5 * MB:
            return Verdict("idle", [f"peak CPU {cpu:.1f}% in 14 d", f"at most {net / MB:.1f} MB network per day"], conf)
        if cpu < 5:
            return Verdict("low-use", [f"peak CPU {cpu:.1f}% in 14 d", "network traffic unknown" if net is None
                                       else f"up to {net / MB:,.0f} MB network per day"], "low")
        return Verdict("active", [f"peak CPU {cpu:.1f}% in 14 d"], conf)
    if r.state in ("stopped", "stopping"):
        m = re.search(r"\((\d{4}-\d{2}-\d{2})", r.details.get("state_reason", ""))
        days = age_days(m.group(1)) if m else None
        vols = [idx["id"].get(v) for v in r.relations.get("volume", [])]
        ev = [f"stopped {days} days ago" if days is not None else "stopped",
              f"{len([v for v in vols if v])} attached EBS volume(s) still billed"]
        return Verdict("stopped-billed", ev, "high" if (days or 0) >= 30 else "medium", 30)
    return None


def _ebs(r: Resource, idx) -> Verdict | None:
    if r.state == "available":
        return Verdict("orphaned", ["not attached to any instance"], "high", 32)
    inst = [idx["id"].get(i) for i in r.relations.get("instance", [])]
    if any(i is not None and i.state in ("stopped", "stopping") for i in inst):
        return Verdict("stopped-billed", ["attached to a stopped instance"], "high", 30)
    if r.details.get("root"):
        return None          # root volumes follow their instance (Compute Optimizer excludes them too)
    ops = _daily_max(r, "ebs_VolumeReadOps_14d", "ebs_VolumeWriteOps_14d")
    if ops is None:
        return None
    if ops < 1:
        return Verdict("idle", ["fewer than 1 read/write per day for 14 d (non-root volume)"], "high")
    return Verdict("active", [f"up to {ops:,.0f} I/O operations per day"], "high")


def _elb(r: Resource, idx) -> Verdict | None:
    d = r.details
    if d.get("targets") == 0:
        return Verdict("orphaned", ["no registered targets"], "high")
    req = _metric(r, "lb_requests_14d")
    if req is not None:
        if req == 0:
            return Verdict("idle", ["0 requests in 14 d"], "high")
        per_day = req / 14
        if per_day < 100:
            return Verdict("low-use", [f"about {per_day:,.0f} requests/day over 14 d"], "medium")
        return Verdict("active", [f"about {per_day:,.0f} requests/day over 14 d"], "high")
    flows, data = _metric(r, "lb_new_flows_14d"), _metric(r, "lb_bytes_14d")
    if flows is not None or data is not None:
        if not flows and not data:
            return Verdict("idle", ["0 new flows and 0 bytes processed in 14 d"], "high")
        return Verdict("active", [f"{(data or 0) / GIB:,.2f} GB processed in 14 d"], "high")
    return Verdict("unknown", ["no load balancer traffic metrics"], "low")


def _ecs(r: Resource, idx) -> Verdict | None:
    d = r.details
    if r.resource_type != "service":
        return None
    if not d.get("running") and not d.get("desired"):
        return Verdict("clutter", ["no tasks desired or running"], "high")
    cpu, mem = _metric(r, "ecs_cpu_max_14d"), _metric(r, "ecs_mem_max_14d")
    req, n_tg = _prefixed_total(r, "tg_requests_14d:")
    if cpu is not None and mem is not None and cpu < 1 and mem < 1:
        return Verdict("idle", [f"peak CPU {cpu:.2f}% and memory {mem:.2f}% in 14 d"], "high")
    if n_tg and req == 0:
        return Verdict("idle", ["0 requests through its load balancer in 14 d"], "medium")
    if cpu is None and not n_tg:
        return Verdict("unknown", ["no ECS service metrics"], "low")
    ev = []
    if cpu is not None:
        ev.append(f"peak CPU {cpu:.1f}%" + (f", memory {mem:.1f}%" if mem is not None else "") + " in 14 d")
    if n_tg and req:
        ev.append(f"{req:,.0f} requests in 14 d")
    return Verdict("active", ev, "high")


def _rds(r: Resource, idx) -> Verdict | None:
    if r.resource_type != "db-instance":
        return None
    if r.state == "stopped":
        return Verdict("stopped-billed", ["stopped: storage still billed; RDS restarts it after 7 days"], "high")
    conns = _metric(r, "connections_max_14d")
    if conns is None:
        return Verdict("unknown", ["no DatabaseConnections metric"], "low") if r.state == "available" else None
    if conns == 0:
        return Verdict("idle", ["0 client connections in 14 d"], "high" if _complete(r, "connections_max_14d") else "medium")
    return Verdict("active", [f"up to {conns:,.0f} connections in 14 d"], "high")


def _ddb(r: Resource, idx) -> Verdict | None:
    used = _total(r, "ddb_ConsumedReadCapacityUnits_14d", "ddb_ConsumedWriteCapacityUnits_14d")
    if used is None:
        return Verdict("unknown", ["no consumed-capacity metrics"], "low")
    if used == 0:
        if r.details.get("billing_mode") == "PROVISIONED":
            return Verdict("idle", ["0 reads/writes in 14 d; provisioned capacity still billed"], "high")
        return Verdict("clutter", ["no reads or writes in 14 d (on-demand: only storage billed)"], "high")
    return Verdict("active", [f"{used:,.0f} capacity units consumed in 14 d"], "high")


def _zero_is_clutter(key: str, days: int, what: str) -> Callable[[Resource, dict], Verdict | None]:
    def rule(r: Resource, idx) -> Verdict | None:
        v = _metric(r, key)
        if v is None:
            return None
        return Verdict("clutter", [f"0 {what} in {days} d"], "high", days) if v == 0 else \
            Verdict("active", [f"{v:,.0f} {what} in {days} d"], "high", days)
    return rule


def _lambda(r: Resource, idx) -> Verdict | None:
    v = _metric(r, "invocations_90d")
    if v is None:
        return None
    if v == 0:
        if r.details.get("provisioned_concurrency"):
            return Verdict("idle", ["0 invocations in 90 d while provisioned concurrency is billed"], "high", 90)
        return Verdict("clutter", ["0 invocations in 90 d"], "high", 90)
    return Verdict("active", [f"{v:,.0f} invocations in 90 d"], "high", 90)


def _sqs(r: Resource, idx) -> Verdict | None:
    v = _total(r, "sqs_NumberOfMessagesSent_30d", "sqs_NumberOfMessagesReceived_30d")
    if v is None:
        return None
    return Verdict("clutter", ["no messages sent or received in 30 d"], "high", 30) if v == 0 else \
        Verdict("active", [f"{v:,.0f} messages sent/received in 30 d"], "high", 30)


def _waf(r: Resource, idx) -> Verdict | None:
    if r.details.get("associated") == 0:
        return Verdict("orphaned", ["not associated with any load balancer, API or other resource"], "high", 30)
    v = _total(r, "waf_AllowedRequests_30d", "waf_BlockedRequests_30d", "waf_CountedRequests_30d")
    if v is None:
        return None
    return Verdict("idle", ["0 requests inspected in 30 d"], "high", 30) if v == 0 else \
        Verdict("active", [f"{v:,.0f} requests inspected in 30 d"], "high", 30)


def _route53(r: Resource, idx) -> Verdict | None:
    if r.resource_type != "hosted-zone" or r.details.get("private"):
        return None
    v = _metric(r, "dns_queries_30d")
    if v is None:
        return Verdict("unknown", ["no DNSQueries datapoints (queried in us-east-1)"], "low", 30)
    return Verdict("idle", ["0 DNS queries in 30 d"], "medium", 30) if v == 0 else \
        Verdict("active", [f"{v:,.0f} DNS queries in 30 d"], "high", 30)


def _last_used(r: Resource, days: int = 90, *, created_key: str = "", what: str = "used") -> Verdict | None:
    last = r.details.get("last_used") or r.details.get("last_accessed")
    if last:
        age = age_days(last)
        if age is None:
            return None
        return Verdict("stale", [f"last {what} {age} days ago"], "high", days) if age > days else \
            Verdict("active", [f"last {what} {age} days ago"], "high", days)
    created = age_days(r.details.get(created_key) if created_key else r.created)
    if created is not None and created > days:
        return Verdict("stale", [f"never {what} (created {created} days ago)"], "medium", days)
    return None


def _kms(r: Resource, idx) -> Verdict | None:
    if r.state == "Disabled":
        return Verdict("idle", ["disabled, yet still billed $1/month"], "high", 90)
    if r.details.get("last_used"):
        return _last_used(r, 90)
    start = age_days(r.details.get("tracking_start"))
    if start is not None:
        if start > 90:
            return Verdict("stale", [f"no recorded use since tracking began {start} days ago"], "medium", 90)
        return Verdict("unknown", ["key predates usage tracking; no use recorded yet"], "low", 90)
    return None


def _secret(r: Resource, idx) -> Verdict | None:
    return _last_used(r, 90, what="accessed")


def _ecr(r: Resource, idx) -> Verdict | None:
    if not r.details.get("images"):
        return Verdict("clutter", ["no images"], "high", 90)
    if r.details.get("last_used"):
        return _last_used(r, 90, what="pulled")
    push = age_days(r.details.get("last_push"))
    if push is not None and push > 90:
        return Verdict("stale", [f"no pulls recorded; last push {push} days ago"], "medium", 90)
    return None


def _logs(r: Resource, idx) -> Verdict | None:
    v = _metric(r, "logs_incoming_90d")
    if v is None:
        return None
    if v == 0:
        gb = (r.details.get("stored_bytes") or 0) / GIB
        if gb > 0.01:
            return Verdict("stale", [f"nothing ingested in 90 d; {gb:,.2f} GB still stored"], "high", 90)
        return Verdict("clutter", ["nothing ingested in 90 d and nothing stored"], "high", 90)
    return Verdict("active", [f"{v / MB:,.1f} MB ingested in 90 d"], "high", 90)


def _glue(r: Resource, idx) -> Verdict | None:
    if r.resource_type not in ("job", "crawler"):
        return None
    last = r.details.get("last_used")
    if last:
        age = age_days(last)
        return Verdict("clutter", [f"last run {age} days ago"], "high", 90) if (age or 0) > 90 else \
            Verdict("active", [f"last run {age} days ago"], "high", 90)
    created = age_days(r.created)
    if created is not None and created > 90:
        return Verdict("clutter", ["no runs in the 90 days of retained history"], "medium", 90)
    return None


def _efs(r: Resource, idx) -> Verdict | None:
    conns, io = _metric(r, "efs_connections_30d"), _metric(r, "efs_io_bytes_30d")
    if conns is None and io is None:
        return None
    if not conns and not io:
        return Verdict("idle", ["0 client connections and no I/O in 30 d; storage still billed"], "medium", 30)
    return Verdict("active", [f"{(io or 0) / GIB:,.2f} GB of I/O in 30 d"], "high", 30)


def _agentcore(r: Resource, idx) -> Verdict | None:
    if r.resource_type != "agent-runtime":
        return None
    v = _metric(r, "agentcore_invocations_30d")
    if v is None:
        return None
    return Verdict("clutter", ["0 invocations in 30 d"], "medium", 30) if v == 0 else \
        Verdict("active", [f"{v:,.0f} invocations in 30 d"], "high", 30)


def _snapshot(r: Resource, idx) -> Verdict | None:
    age = age_days(r.created)
    if age is not None and age > 180 and r.resource_id not in idx["ami_snapshots"]:
        return Verdict("stale", [f"{age} days old and not used by any AMI"], "medium", 180)
    return None


def _ami(r: Resource, idx) -> Verdict | None:
    last = r.details.get("last_used")
    age = age_days(last) if last else age_days(r.created)
    if age is not None and age > 180:
        return Verdict("stale", [f"last launched {age} days ago" if last else f"never launched (created {age} days ago)"],
                       "medium", 180)
    return None


RULES: dict[str, Callable[[Resource, dict], Verdict | None]] = {
    "NAT Gateway": _nat, "EC2": _ec2, "EBS": _ebs, "ELB": _elb, "ECS": _ecs, "RDS": _rds, "DocumentDB": _rds, "Neptune": _rds,
    "DynamoDB": _ddb, "Lambda": _lambda, "SQS": _sqs, "SNS": _zero_is_clutter("sns_published_30d", 30, "messages published"),
    "Step Functions": _zero_is_clutter("sfn_executions_90d", 90, "executions"),
    "API Gateway": _zero_is_clutter("api_requests_30d", 30, "requests"), "WAF": _waf, "Route53": _route53, "KMS": _kms,
    "Secrets Manager": _secret, "ECR": _ecr, "CloudWatch Logs": _logs, "Glue": _glue, "EFS": _efs,
    "Bedrock AgentCore": _agentcore, "EBS Snapshots": _snapshot, "AMIs": _ami,
}


# ── public IPs inherit their owner's verdict ────────────────────────────────

def _inherit(r: Resource, owner: Resource | None, what: str) -> Verdict | None:
    if owner is None or not owner.usage_state:
        return None
    r.details["usage_owner"] = owner.arn or owner.resource_id
    return Verdict(owner.usage_state, [f"held by {what} {owner.name or owner.resource_id}, which is {owner.usage_state}"],
                   owner.usage_confidence or "medium", 30)


def _eip(r: Resource, idx) -> Verdict | None:
    nat = idx["nat_by_eip"].get(r.resource_id)
    if nat is not None:
        return _inherit(r, nat, "NAT gateway") or Verdict("active", [f"held by NAT gateway {nat.resource_id}"], "low", 30)
    if not r.details.get("associated"):
        return Verdict("orphaned", ["Elastic IP not associated with anything"], "high", 7)
    inst = next((idx["id"].get(i) for i in r.relations.get("instance", []) if idx["id"].get(i)), None)
    if inst is not None and inst.state in ("stopped", "stopping"):
        return Verdict("stopped-billed", [f"attached to stopped instance {inst.resource_id}"], "high", 7)
    return _inherit(r, inst, "instance") or Verdict("active", ["associated with a running network interface"], "low", 7)


def _public_ip(r: Resource, idx) -> Verdict | None:
    owner = r.details.get("owner") or {}
    kind, oid = owner.get("kind"), owner.get("id", "")
    if kind == "nat":
        return _inherit(r, idx["id"].get(oid), "NAT gateway")
    if kind == "elb":
        return _inherit(r, idx["elb_by_name"].get(oid), "load balancer")
    if kind == "instance":
        return _inherit(r, idx["id"].get(oid), "instance")
    label = {"ecs-task": "an ECS task", "lambda": "a Lambda function"}.get(kind, f"a {kind or 'network'} interface")
    return Verdict("active", [f"attached to {label}"], "low", 7)


# ── engine ────────────────────────────────────────────────────────────────────

class UsageStore:
    """Remembers when a resource was first seen in a waste state, so a verdict seen on two scans at least
    CONFIRM_DAYS apart is promoted to 'confirmed' (Cloud Custodian's mark-then-act grace period, without tagging)."""

    def __init__(self, path: Path | None | str = "default"):
        path = STORE_PATH if path == "default" else path      # resolved at call time so tests can redirect it
        self.path = path
        self.data: dict = {}
        if path and path.exists():
            try:
                self.data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                self.data = {}

    def observe(self, account: str, key: str, state: str, now: datetime) -> int:
        if state not in WASTE_STATES:
            self.data.get(account or "-", {}).pop(key, None)
            return 0
        acct = self.data.setdefault(account or "-", {})
        entry = acct.get(key)
        if not entry or entry.get("state") != state:
            acct[key] = {"state": state, "first_seen": now.isoformat()}
            return 0
        return age_days(entry["first_seen"], now) or 0

    def save(self) -> None:
        if not self.path:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data), encoding="utf-8")
        except Exception:
            pass


def _index(res: ScanResult) -> dict:
    idx: dict = {"id": {}, "nat_by_eip": {}, "elb_by_name": {}, "ami_snapshots": set()}
    for r in res.resources:
        idx["id"][r.resource_id] = r
        if r.arn:
            idx["id"][r.arn] = r
        if r.service == "NAT Gateway":
            for a in r.relations.get("elastic-ip", []):
                idx["nat_by_eip"][a] = r
        elif r.service == "ELB":
            idx["elb_by_name"][r.resource_id] = r
        elif r.service == "AMIs":
            idx["ami_snapshots"].update(r.relations.get("snapshot", []))
    return idx


def _overlays(r: Resource, window: int, now: datetime) -> list[str]:
    out = []
    if (r.service, r.resource_type) in SHARED:
        out.append("shared")
    if any(EXCLUDE.search(k) or EXCLUDE.search(str(v)) for k, v in r.tags.items()):
        out.append("excluded")
    created = age_days(r.created, now)
    if created is not None and created < window:
        out.append("too-new")
    if r.service == "ELB" and r.details.get("targets") and r.details.get("healthy_targets") == 0:
        out.append("unhealthy")
    return out


def classify(res: ScanResult, store: UsageStore | None = None, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    idx = _index(res)
    owners = [r for r in res.resources if r.service not in ("Elastic IP", "Public IPv4")]
    ips = [r for r in res.resources if r.service in ("Elastic IP", "Public IPv4")]
    for r in owners + ips:          # IPs last: they inherit their owner's verdict
        if r.category != "resource":
            continue
        r.details.pop("usage_owner", None)
        rule = _eip if r.service == "Elastic IP" else _public_ip if r.service == "Public IPv4" else RULES.get(r.service)
        v = rule(r, idx) if rule else None
        r.usage_overlays = [o for o in r.usage_overlays if o == "aws-agrees"]
        account, key = r.account_id or (res.identity or {}).get("Account", ""), r.arn or r.resource_id
        if v is None:
            r.usage_state, r.usage_evidence, r.usage_confidence = "", [], ""
            if store is not None:
                store.observe(account, key, "", now)
            continue
        r.usage_state, r.usage_evidence, r.usage_confidence = v.state, list(v.evidence), v.confidence
        overlays = _overlays(r, v.window, now)
        if "too-new" in overlays:
            r.usage_confidence = "low"
        if store is not None:
            days = store.observe(account, key, v.state, now)
            if days >= CONFIRM_DAYS:
                overlays.append("confirmed")
                r.usage_evidence.append(f"same verdict for {days} days")
        r.usage_overlays = sorted(set(r.usage_overlays) | set(overlays))
    if store is not None:
        store.save()
    summarise(res)


def monthly_cost(r: Resource, res: ScanResult) -> float:
    if r.actual_mtd is not None and res.period is not None:
        return r.actual_mtd * (res.period.days_in_month / max(1, res.period.elapsed_days))
    return r.monthly_estimate or 0.0


def summarise(res: ScanResult) -> None:
    summary: dict[str, dict] = {}
    for r in res.resources:
        if r.usage_state:
            s = summary.setdefault(r.usage_state, {"count": 0, "monthly_cost": 0.0})
            s["count"] += 1
            s["monthly_cost"] = round(s["monthly_cost"] + monthly_cost(r, res), 2)
    cur = res.meta.get("cur") or {}
    if cur.get("unattributed_cost"):
        summary["unattributed"] = {"count": int(cur.get("unmatched_resource_ids", 0)), "monthly_cost": round(float(cur["unattributed_cost"]), 2)}
    res.meta["usage_summary"] = summary


def mark_aws_agrees(res: ScanResult, keys: set[str]) -> int:
    n = 0
    for r in res.resources:
        if (r.arn and r.arn in keys) or r.resource_id in keys:
            if "aws-agrees" not in r.usage_overlays:
                r.usage_overlays = sorted(set(r.usage_overlays) | {"aws-agrees"})
                n += 1
    return n
