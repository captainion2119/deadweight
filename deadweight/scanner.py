"""Scan orchestration: identity → regions → inventory (parallel) → metrics → costs → CUR → findings."""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable

import boto3

from . import collectors  # noqa: F401  (registers every collector)
from .aws import (ClientPool, ScanCancelled, TaskTimeout, assume_readonly_session, classify, enabled_regions,
                  failed_action, is_root, partition_of)
from .billing import ARN_BILL, reconcile
from .collectors.base import REGISTRY, Ctx, MetricRequest, Spec
from .costs import CE_REQUEST_COST, CostExplorer
from .models import Resource, ScanResult, month_window
from .pricing import DEFAULT_CACHE, PriceResolver

EC2_PREFIXES = {"i-": "instance", "vol-": "volume", "eipalloc-": "elastic-ip", "nat-": "natgateway", "vpc-": "vpc",
                "subnet-": "subnet", "sg-": "security-group", "snap-": "snapshot", "ami-": "image",
                "eni-": "network-interface", "vpce-": "vpc-endpoint", "tgw-attach-": "transit-gateway-attachment",
                "tgw-": "transit-gateway", "vpn-": "vpn-connection"}
SERVICES = [k for k, s in REGISTRY.items()]
DEFAULT_SERVICES = {k for k, s in REGISTRY.items() if s.default}


@dataclass
class ScanOptions:
    profile: str | None = None
    role_arn: str | None = None
    external_id: str | None = None
    services: set[str] = field(default_factory=lambda: set(DEFAULT_SERVICES))
    regions: list[str] | None = None          # explicit list; None = every enabled region
    region_mode: str = "all"                  # all | active (regions with spend or discovered resources)
    workers: int = 16
    task_timeout: float = 300.0
    metrics: bool = True
    costs: bool = True
    cost_tags: bool = True
    forecast: bool = True
    anomalies: bool = True
    recommendations: bool = True
    cur: str = "auto"                         # auto | off
    cur_path: str | None = None
    price_cache: bool = True
    usage_store: bool = True                  # remember first-seen-idle dates in ~/.cache/deadweight/usage-state.json
    org: bool = False
    org_role: str = "OrganizationAccountAccessRole"
    accounts: list[str] | None = None


@dataclass
class AccountScope:
    account: str
    name: str
    session: Any
    pool: ClientPool

    @property
    def label(self) -> str:
        return self.account


class Scanner:
    def __init__(self, options: ScanOptions, log: Callable[[str], None] | None = None,
                 on_resource: Callable[[Resource], None] | None = None,
                 on_progress: Callable[[str, int, int], None] | None = None):
        self.opts = options
        self.log = log or (lambda _: None)
        self.on_resource = on_resource or (lambda _: None)
        self.on_progress = on_progress or (lambda _l, _d, _t: None)
        base = boto3.Session(profile_name=options.profile or None)
        self.base_identity = base.client("sts").get_caller_identity()
        self.session = assume_readonly_session(base, options.role_arn, external_id=options.external_id) if options.role_arn else base
        self.pool = ClientPool(self.session)
        self.identity = self.pool.get("sts", self.session.region_name or "us-east-1").get_caller_identity() if options.role_arn else self.base_identity
        self.account = str(self.identity.get("Account", ""))
        self.partition = partition_of(str(self.identity.get("Arn", "")))
        self.home_region = self.session.region_name or "us-east-1"
        self.prices = PriceResolver(self.pool, DEFAULT_CACHE if options.price_cache else None)
        self.cancel_event = threading.Event()
        self.regions = list(options.regions or [])
        self.resources: list[Resource] = []
        self.catalog: list[Resource] = []
        self.coverage: list[dict[str, Any]] = []
        self.errors: list[str] = []
        self._seen: dict[tuple, Resource] = {}
        self._catalog_seen: set[tuple] = set()
        self._lock = threading.RLock()
        self._metric_reqs: list[MetricRequest] = []
        self._done = 0
        self._total = 1
        self.result = ScanResult(identity=self.identity)
        self.scopes: list[AccountScope] = [AccountScope(self.account, "", self.session, self.pool)]

    # ── public ──────────────────────────────────────────────────────────────────
    def cancel(self) -> None:
        self.cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def run(self) -> ScanResult:
        t0 = time.monotonic()
        res = self.result
        res.period = month_window(date.today())
        if is_root(self.base_identity) and not self.opts.role_arn:
            self.log("[warn] Scanning with root credentials. Prefer a read-only role (--role-arn) or an SSO read-only profile.")
        self.ce = CostExplorer(self.pool, res.period, self.coverage_event)
        res.meta.update(role_arn=self.opts.role_arn or "", base_identity=self.base_identity.get("Arn", ""))
        if self.opts.org:
            self._phase("Organization accounts", self._discover_accounts)
        self._resolve_regions()
        specs = [REGISTRY[k] for k in REGISTRY if k in self.opts.services]
        self._inventory(specs)
        if not self.cancelled and self.opts.metrics and self._metric_reqs:
            self._phase("CloudWatch metrics", self._metrics)
        if not self.cancelled and self.opts.costs:
            self._costs(res)
        if not self.cancelled and self.opts.cur != "off":
            from . import cur
            self._phase("Cost & Usage Report", lambda: cur.attach(self, res))
        res.resources, res.catalog, res.coverage, res.errors = self.resources, self.catalog, self.coverage, self.errors
        known = {s.bill for s in REGISTRY.values() if s.bill} | {f"{s.bill}/{s.usage}" for s in REGISTRY.values() if s.usage}
        known |= set(ARN_BILL.values())
        res.reconciliation = reconcile(res.costs, res.billing_breakdown, self.resources, known)
        if not self.cancelled:
            from . import findings, usage
            store = usage.UsageStore() if self.opts.usage_store else None
            self._phase("Usage classification", lambda: usage.classify(res, store))
            self._phase("Findings", lambda: findings.run(self, res))
        self.prices.flush()
        res.meta.update(duration_s=round(time.monotonic() - t0, 1), regions=self.regions, workers=self.opts.workers,
                        services=sorted(self.opts.services), ce_requests=self.ce.requests,
                        ce_cost=round(self.ce.requests * CE_REQUEST_COST, 2), pricing_requests=self.prices.requests,
                        metric_queries=len(self._metric_reqs), cancelled=self.cancelled, region_mode=self.opts.region_mode,
                        accounts=[{"id": sc.account, "name": sc.name} for sc in self.scopes])
        res.generated_at = datetime.now(timezone.utc)
        self.on_progress("done", self._total, self._total)
        return res

    # Convenience entry point -------------------------------------------------------
    def scan(self) -> list[Resource]:
        self.run()
        return self.resources

    # ── resources ───────────────────────────────────────────────────────────────
    @staticmethod
    def canonical_key(r: Resource) -> tuple:
        arn = r.arn or (r.resource_id if str(r.resource_id).startswith("arn:") else "")
        if arn.startswith("arn:"):
            parts = arn.split(":", 5)
            if len(parts) == 6:
                svc, region, tail = parts[2].lower(), parts[3], parts[5]
                if svc == "elasticloadbalancing" or ("/" not in tail and ":" not in tail):
                    norm = tail
                else:
                    sep = "/" if "/" in tail and (":" not in tail or tail.index("/") < tail.index(":")) else ":"
                    typ, rid = tail.split(sep, 1)
                    norm = f"{typ.lower()}/{rid}"
                return (svc, region, norm)
        rid = str(r.resource_id)
        for pre, typ in EC2_PREFIXES.items():
            if rid.startswith(pre):
                return ("ec2", r.region, f"{typ}/{rid}")
        return (r.service.lower(), r.region, f"{r.resource_type.lower()}/{rid}")

    def add(self, r: Resource, source: str | None = None) -> Resource:
        source = source or "Direct API"
        if source not in r.discovery_sources:
            r.discovery_sources.append(source)
        with self._lock:
            if r.category == "catalog":
                key = (r.service, r.region, r.resource_type, r.resource_id)
                if key not in self._catalog_seen:
                    self._catalog_seen.add(key)
                    self.catalog.append(r)
                return r
            key = self.canonical_key(r)
            old = self._seen.get(key)
            if old is None:
                self._seen[key] = r
                self.resources.append(r)
                new = True
            else:
                new = False
                if merge_into(old, r):
                    self._rebind(r, old)     # later metric callbacks must update the surviving object
                r = old
        if new:
            self.on_resource(r)
        return r

    def _rebind(self, direct: Resource, merged: Resource) -> None:
        for m in self._metric_reqs:
            if m.resource is direct:
                m.resource = merged

    def coverage_event(self, source: str, region: str, status: str, detail: str = "", action: str = "",
                       account: str = "") -> None:
        ev = {"source": source, "region": region, "status": status, "detail": detail}
        if action:
            ev["action"] = action
        if account and len(self.scopes) > 1:
            ev["account"] = account
        with self._lock:
            self.coverage.append(ev)
            if status in ("error", "denied", "timeout", "throttled"):
                self.errors.append(f"{source}/{region}: {detail}")
        if status in ("error", "denied", "timeout"):
            self.log(f"[error] {source}/{region}: {detail}")

    def request_metric(self, req: MetricRequest) -> None:
        with self._lock:
            self._metric_reqs.append(req)

    # ── phases ──────────────────────────────────────────────────────────────────
    def _tick(self, label: str) -> None:
        with self._lock:
            self._done += 1
            done, total = self._done, self._total
        self.on_progress(label, done, total)

    def _phase(self, label: str, fn: Callable[[], Any]) -> Any:
        self.on_progress(label, self._done, self._total)
        try:
            return fn()
        except ScanCancelled:
            return None
        except Exception as e:
            status, detail = classify(e)
            self.coverage_event(label, "global", status, detail)
            return None
        finally:
            self._tick(label)

    def _discover_accounts(self) -> None:
        org = self.pool.get("organizations", "us-east-1")
        accounts = [a for page in org.get_paginator("list_accounts").paginate() for a in page.get("Accounts", [])
                    if a.get("Status", "ACTIVE") == "ACTIVE"]
        wanted = set(self.opts.accounts or [])
        for a in accounts:
            aid = a["Id"]
            if aid == self.account:
                self.scopes[0].name = a.get("Name", "")
                continue
            if wanted and aid not in wanted:
                continue
            role = f"arn:{self.partition}:iam::{aid}:role/{self.opts.org_role}"
            try:
                sess = assume_readonly_session(self.session, role, session_name="deadweight-org")
                sess.client("sts").get_caller_identity()
                self.scopes.append(AccountScope(aid, a.get("Name", ""), sess, ClientPool(sess)))
                self.coverage_event("Organization account", "global", "ok", f"{aid} {a.get('Name', '')} via {self.opts.org_role}")
            except Exception as e:
                status, detail = classify(e)
                self.coverage_event("Organization account", "global", status, f"{aid} {a.get('Name', '')}: {detail}", "sts:AssumeRole")
        self.log(f"Organization mode: scanning {len(self.scopes)} account(s)")

    def _resolve_regions(self) -> None:
        if self.regions:
            return
        all_regions = enabled_regions(self.pool, self.home_region)
        if self.opts.region_mode != "active":
            self.regions = all_regions
            return
        active = set()
        try:
            active |= set(self.ce.active_regions())
        except Exception as e:
            self.log(f"Active-region lookup via Cost Explorer failed ({e}); scanning all regions")
            self.regions = all_regions
            return
        active.add(self.home_region)
        self.regions = [r for r in all_regions if r in active]
        for r in all_regions:
            if r not in active:
                self.coverage_event("Region targeting", r, "skipped", "No spend this month (active-region mode)")
        self.log(f"Active-region mode: {len(self.regions)} of {len(all_regions)} regions have spend")

    def _inventory(self, specs: list[Spec]) -> None:
        base: list[tuple[Spec, str]] = []
        for s in specs:
            if s.scope == "global":
                base.append((s, "global"))
                continue
            try:
                avail = set(self.session.get_available_regions(s.client, partition_name=self.partition)) if s.client else set()
            except Exception:
                avail = set()
            missing = [r for r in self.regions if avail and r not in avail]
            if missing:
                self.coverage_event(s.key, f"{len(missing)} regions", "not-available", "No endpoint in: " + ", ".join(missing))
            base += [(s, r) for r in self.regions if r not in missing]
        # Built spec-major, so consecutive tasks hit different regions and throttling spreads out.
        base.sort(key=lambda t: t[0].scope != "global")
        tasks = [(s, r, sc) for sc in self.scopes for s, r in base]
        o = self.opts
        cost_steps = (5 + o.cost_tags + o.forecast + o.anomalies) if o.costs else 0
        self._total = max(1, len(tasks) + o.metrics + (o.cur != "off") + 2 + cost_steps)
        self.log(f"Inventory: {len(tasks)} collector tasks across {len(self.regions)} regions and {len(self.scopes)} account(s) "
                 f"on {self.opts.workers} workers")

        def run(spec: Spec, region: str, scope: AccountScope) -> None:
            label = f"{spec.key}/{region}"
            if self.cancelled:
                self.coverage_event(spec.key, region, "skipped", "scan cancelled", account=scope.label)
                return
            ctx = Ctx(self, spec, region, time.monotonic() + self.opts.task_timeout if self.opts.task_timeout else None, scope)
            self.on_progress(label, self._done, self._total)
            try:
                spec.fn(ctx)
                self.coverage_event(spec.key, region, "ok", f"{ctx.count} item(s)", account=scope.label)
            except Exception as e:
                status, detail = classify(e)
                self.coverage_event(spec.key, region, status, detail,
                                    failed_action(e, _client_for(scope, spec, region, self.home_region)), account=scope.label)

        with ThreadPoolExecutor(max_workers=max(1, self.opts.workers)) as ex:
            futures = {ex.submit(run, s, r, sc): (s, r) for s, r, sc in tasks}
            for f in as_completed(futures):
                s, r = futures[f]
                self._tick(f"{s.key}/{r}")
                if self.cancelled:
                    for other in futures:
                        other.cancel()

    def _metrics(self) -> None:
        groups: dict[tuple, list[MetricRequest]] = defaultdict(list)
        for m in self._metric_reqs:
            groups[(m.region, m.days, m.scope.account if m.scope else self.account)].append(m)
        pools = {sc.account: sc.pool for sc in self.scopes}

        def fetch(key: tuple) -> None:
            region, days, account = key
            reqs = groups[key]
            cw = pools.get(account, self.pool).get("cloudwatch", region)
            start, end, dates = daily_window(days)
            for i in range(0, len(reqs), 500):
                if self.cancelled:
                    return
                chunk = reqs[i:i + 500]
                # One datapoint per UTC day: billing is per metric, so a daily series costs the same as one
                # aggregate and allows "k of N days" rules and sparklines.
                queries = [{"Id": f"m{j}", "ReturnData": True, "MetricStat": {
                    "Metric": {"Namespace": m.namespace, "MetricName": m.metric,
                               "Dimensions": [{"Name": k, "Value": v} for k, v in m.dims.items()]},
                    "Period": 86400, "Stat": m.stat}} for j, m in enumerate(chunk)]
                points: dict[str, list[tuple]] = defaultdict(list)
                token = None
                while True:
                    kw = {"MetricDataQueries": queries, "StartTime": start, "EndTime": end, "ScanBy": "TimestampAscending"}
                    if token:
                        kw["NextToken"] = token
                    resp = cw.get_metric_data(**kw)
                    for r in resp.get("MetricDataResults", []):
                        points[r["Id"]].extend(zip(r.get("Timestamps", []), r.get("Values", [])))
                    token = resp.get("NextToken")
                    if not token:
                        break
                for j, m in enumerate(chunk):
                    apply_metric(m, points.get(f"m{j}") or [], dates)

        def safe(key):
            try:
                fetch(key)
                self.coverage_event("CloudWatch metrics", key[0], "ok", f"{len(groups[key])} metric queries ({key[1]} d)")
            except Exception as e:
                status, detail = classify(e)
                self.coverage_event("CloudWatch metrics", key[0], status, detail, "cloudwatch:GetMetricData")
        with ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(safe, list(groups)))

    def _costs(self, res: ScanResult) -> None:
        ce = self.ce

        def step(label: str, fn: Callable[[], Any]) -> Any:
            def wrapped():
                out = fn()
                self.coverage_event(label, "global", "ok", "")
                return out
            return self._phase(label, wrapped)

        rc = step("EC2 resource-level actual costs", ce.ec2_resource_costs) or {}
        for r in self.resources:
            if r.service == "EC2" and r.resource_id in rc:
                r.actual_recent, r.actual_recent_period = rc[r.resource_id], "(last 14 days)"
        res.costs = step("Cost Explorer services", ce.services) or []
        extra: list[tuple[str, str]] = []
        if self.opts.cost_tags:
            keys = step("Cost allocation tags", ce.active_tag_keys) or []
            extra += [("TAG", k) for k in keys]
            res.meta["cost_tags"] = keys
        if self.opts.org:
            extra.append(("DIMENSION", "LINKED_ACCOUNT"))
        res.billing_breakdown = self._phase("Cost Explorer breakdown", lambda: ce.dimensions(extra=extra)) or []
        res.daily = step("Cost Explorer daily trend", ce.daily) or []
        if self.opts.forecast:
            res.forecast = step("Cost Explorer forecast", ce.forecast)
        if self.opts.anomalies:
            res.anomalies = step("Cost anomalies", ce.anomalies) or []


def daily_window(days: int, now: datetime | None = None) -> tuple[datetime, datetime, list[str]]:
    """[start, end) aligned to UTC midnight so every datapoint is one whole day; today is excluded."""
    end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    start = end - timedelta(days=days)
    return start, end, [(start + timedelta(days=i)).date().isoformat() for i in range(days)]


def aggregate(values: list[float], stat: str) -> float | None:
    if not values:
        return None
    if stat == "Sum":
        return float(sum(values))
    if stat == "Maximum":
        return float(max(values))
    if stat == "Minimum":
        return float(min(values))
    return float(sum(values) / len(values))


def apply_metric(m: MetricRequest, points: list[tuple], dates: list[str]) -> None:
    """Store the daily series, its aggregate and datapoint count, then run the collector's callback.

    Days without a datapoint become 0 when the metric is only emitted on activity (`missing == "zero"`),
    otherwise None: "no data" must never be read as "idle" for metrics that emit zeros."""
    by_day: dict[str, list[float]] = defaultdict(list)
    for ts, v in points:
        day = ts.astimezone(timezone.utc).date().isoformat() if isinstance(ts, datetime) else str(ts)[:10]
        by_day[day].append(float(v))
    fill = 0.0 if m.missing == "zero" else None
    series = [[d, aggregate(by_day[d], m.stat) if d in by_day else fill] for d in dates]
    present = [v for _, v in series if v is not None]
    agg = aggregate(present, m.stat)
    if agg is None and m.missing == "zero":
        agg = 0.0
    d = m.resource.details
    d.setdefault("series", {})[m.key] = series
    d.setdefault("metrics", {})[m.key] = agg
    d.setdefault("metric_points", {})[m.key] = sum(1 for day in dates if day in by_day)
    d.setdefault("metric_window", {})[m.key] = len(dates)
    if m.on_value:
        try:
            m.on_value(m.resource, agg)
        except Exception:
            pass


def merge_into(old: Resource, r: Resource) -> bool:
    """Fold a duplicate sighting `r` into `old`. Returns True when `r` came from a direct collector and
    replaced the generic fields of `old`."""
    for src in r.discovery_sources:
        if src not in old.discovery_sources:
            old.discovery_sources.append(src)
    took = False
    if old.service.startswith("AWS/") and not r.service.startswith("AWS/"):
        # A direct collector is richer than a generic discovery hit: take its fields.
        for f in ("service", "resource_type", "resource_id", "state", "config", "monthly_estimate", "estimate_note",
                  "bill_service", "usage_family", "created", "actual_recent", "actual_recent_period"):
            setattr(old, f, getattr(r, f))
        old.name = r.name or old.name
        old.region = r.region or old.region
        old.details.update(r.details)
        for k, ids in r.relations.items():
            old.relate(k, *ids)
        took = True
    old.tags = {**old.tags, **r.tags}
    for f in ("name", "arn", "account_id"):
        if not getattr(old, f) and getattr(r, f):
            setattr(old, f, getattr(r, f))
    return took


def dedupe(resources: list[Resource]) -> list[Resource]:
    """De-duplicate an already collected list (used for schema-5 reports)."""
    seen: dict[tuple, Resource] = {}
    out: list[Resource] = []
    for r in resources:
        key = Scanner.canonical_key(r)
        if key in seen:
            merge_into(seen[key], r)
        else:
            seen[key] = r
            out.append(r)
    return out


def _client_for(scope: AccountScope, spec: Spec, region: str, home: str):
    if not spec.client:
        return None
    try:
        return scope.pool.get(spec.client, home if region == "global" else region)
    except Exception:
        return None
