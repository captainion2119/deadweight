"""Collector registry and the context object every collector receives."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator

from ..aws import ScanCancelled, TaskTimeout, classify, failed_action
from ..models import HOURS_MONTH, Resource

if TYPE_CHECKING:
    from ..scanner import Scanner

FAMILIES = {
    "compute": "Compute", "storage": "Storage", "database": "Database", "network": "Networking",
    "security": "Security & identity", "integration": "Integration & analytics",
    "observability": "Observability", "ai": "AI / ML", "discovery": "Deep discovery",
}


@dataclass
class Spec:
    key: str                       # name shown in the UI and used for selection, e.g. "EC2"
    family: str
    fn: Callable[["Ctx"], None]
    scope: str = "regional"        # regional | global
    bill: str = ""                 # Cost Explorer SERVICE this collector's resources are billed under
    usage: str = ""                # usage family inside that bill line (only for shared lines)
    actions: tuple[str, ...] = ()  # IAM actions the collector needs
    default: bool = True           # selected by default
    desc: str = ""
    client: str = ""               # boto3 service name, used to skip regions without an endpoint


REGISTRY: dict[str, Spec] = {}


def collector(key: str, family: str, *, scope: str = "regional", bill: str = "", usage: str = "",
              actions: Iterable[str] = (), default: bool = True, desc: str = "", client: str = ""):
    def deco(fn):
        REGISTRY[key] = Spec(key, family, fn, scope, bill, usage, tuple(actions), default, desc, client)
        return fn
    return deco


@dataclass
class MetricRequest:
    region: str
    resource: Resource
    key: str
    namespace: str
    metric: str
    dims: dict[str, str]
    stat: str = "Sum"
    days: int = 14
    on_value: Callable[[Resource, float | None], None] | None = None
    scope: Any = None
    missing: str = "unknown"   # what an empty series means: "zero" (metric only emitted when non-zero) or "unknown"


def dig(obj: Any, path: str) -> list:
    for part in path.split("."):
        if not isinstance(obj, dict):
            return []
        obj = obj.get(part)
    return obj if isinstance(obj, list) else []


class Ctx:
    """What a collector sees: clients for its region, pagination, resource registration,
    coverage events, pricing and deferred CloudWatch metric requests."""

    def __init__(self, scanner: "Scanner", spec: Spec, region: str, deadline: float | None = None, scope=None):
        self.scanner = scanner
        self.spec = spec
        self.region = region                     # "global" for global collectors
        self.scope = scope or scanner.scopes[0]  # which account (pool + id) this task runs in
        self.account = self.scope.account
        self.partition = scanner.partition
        self.prices = scanner.prices
        self.deadline = deadline
        self.count = 0

    # AWS access --------------------------------------------------------------------
    @property
    def api_region(self) -> str:
        return self.scanner.home_region if self.region == "global" else self.region

    def client(self, service: str, region: str | None = None):
        return self.scope.pool.get(service, region or self.api_region)

    def check(self) -> None:
        if self.scanner.cancel_event.is_set():
            raise ScanCancelled()
        if self.deadline is not None and time.monotonic() > self.deadline:
            raise TaskTimeout(f"{self.spec.key} exceeded {self.scanner.opts.task_timeout:.0f}s")

    def call(self, client, op: str, **kw) -> dict:
        self.check()
        return getattr(client, op)(**kw)

    def pages(self, client, op: str, key: str, **kw) -> Iterator[Any]:
        """Every item under `key` (dotted path) across all pages. There is no silent fallback
        to a single un-paginated call: errors propagate and are reported."""
        if client.can_paginate(op):
            for page in client.get_paginator(op).paginate(**kw):
                self.check()
                yield from dig(page, key)
        else:
            yield from dig(self.call(client, op, **kw), key)

    def map(self, fn: Callable[[Any], Any], items: list, workers: int = 8) -> list:
        """Run per-item API calls in parallel inside one collector (bucket details, etc.)."""
        if len(items) <= 1:
            return [fn(i) for i in items]
        with ThreadPoolExecutor(max_workers=min(workers, len(items))) as ex:
            return list(ex.map(fn, items))

    def step(self, label: str, fn: Callable[[], Any], region: str | None = None) -> Any:
        """Run an optional sub-step; on failure record coverage and carry on."""
        try:
            return fn()
        except (ScanCancelled, TaskTimeout):
            raise
        except Exception as e:
            status, detail = classify(e)
            self.coverage(label, status, detail, region=region, action=failed_action(e))
            return None

    # results -----------------------------------------------------------------------
    def arn(self, service: str, resource: str, region: str | None = None, account: str | None = None) -> str:
        reg = self.api_region if region is None else region
        acct = self.account if account is None else account
        return f"arn:{self.partition}:{service}:{reg}:{acct}:{resource}"

    def add(self, r: Resource, source: str = "Direct API") -> Resource:
        if not r.bill_service:
            r.bill_service = self.spec.bill
        if not r.usage_family:
            r.usage_family = self.spec.usage
        if not r.account_id:
            r.account_id = self.account
        self.count += 1
        return self.scanner.add(r, source)

    def coverage(self, source: str, status: str, detail: str = "", region: str | None = None, action: str = "") -> None:
        self.scanner.coverage_event(source, region or self.region, status, detail, action, account=self.scope.label)

    def metric(self, r: Resource, key: str, namespace: str, metric: str, dims: dict[str, str], *, stat: str = "Sum",
               days: int = 14, region: str | None = None, missing: str = "unknown",
               on_value: Callable[[Resource, float | None], None] | None = None) -> None:
        """Request a daily series. `missing="zero"` for metrics AWS only emits when non-zero (ALB, WAF, Lambda,
        SQS/SNS after 6 idle hours…), so an empty series counts as no activity rather than no data."""
        if self.scanner.opts.metrics:
            self.scanner.request_metric(MetricRequest(region or self.api_region, r, key, namespace, metric, dims,
                                                      stat, days, on_value, self.scope, missing))


def monthly(hourly: float | None) -> float | None:
    return None if hourly is None else hourly * HOURS_MONTH


def add_estimate(r: Resource, amount: float | None, note: str) -> None:
    """Add a cost component to a resource's estimate and append its explanation."""
    if amount is None:
        return
    first = r.monthly_estimate is None      # the default "use actual cost" note is replaced, not extended
    r.monthly_estimate = (r.monthly_estimate or 0.0) + amount
    r.estimate_note = note if first or not r.estimate_note else f"{r.estimate_note}; {note}"
