"""Data model shared by the scanner, the cost engine, the findings engine, reports and the UI."""
from __future__ import annotations

import calendar
import json
from dataclasses import asdict, dataclass, field, fields
from datetime import date, datetime, timedelta
from typing import Any

HOURS_MONTH = 730.0


@dataclass
class Resource:
    service: str
    region: str
    resource_type: str
    resource_id: str
    name: str = ""
    state: str = ""
    arn: str = ""
    config: str = ""
    tags: dict[str, str] = field(default_factory=dict)
    monthly_estimate: float | None = None
    estimate_note: str = "Not estimated (usage/configuration dependent)"
    actual_recent: float | None = None
    actual_recent_period: str = ""
    category: str = "resource"  # resource | catalog
    discovery_sources: list[str] = field(default_factory=list)
    # Added in report schema 6 ------------------------------------------------------------
    bill_service: str = ""      # Cost Explorer SERVICE this resource is billed under
    usage_family: str = ""      # usage-type family inside that bill line (e.g. NatGateway)
    account_id: str = ""
    created: str = ""           # ISO timestamp when the API exposes it
    relations: dict[str, list[str]] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    actual_mtd: float | None = None   # per-resource actual cost from CUR / Data Exports
    # Usage classification (deadweight.usage) ------------------------------------------------
    usage_state: str = ""             # active | low-use | idle | orphaned | stopped-billed | stale | clutter | unknown | unattributed
    usage_evidence: list[str] = field(default_factory=list)
    usage_overlays: list[str] = field(default_factory=list)   # shared | excluded | too-new | unhealthy | aws-agrees | confirmed
    usage_confidence: str = ""        # high | medium | low

    def relate(self, kind: str, *ids: str | None) -> None:
        bucket = self.relations.setdefault(kind, [])
        for i in ids:
            if i and i not in bucket:
                bucket.append(i)


@dataclass
class CostRow:
    service: str
    actual_mtd: float = 0.0
    projected_month: float = 0.0
    currency: str = "USD"
    # Added in report schema 6
    bill_service: str = ""               # raw Cost Explorer SERVICE name
    amortized_mtd: float | None = None   # AmortizedCost (RI / Savings Plan fees spread over usage)
    net_amortized_mtd: float | None = None


@dataclass
class Finding:
    rule: str                      # stable id, e.g. "ebs-unattached"
    title: str
    severity: str                  # high | medium | low | info
    category: str                  # waste | rightsizing | hygiene | security | coverage
    resource_key: str = ""         # ARN or ID of the resource it is about
    resource_name: str = ""
    service: str = ""
    region: str = ""
    monthly_savings: float | None = None
    detail: str = ""
    source: str = "rule"           # rule | cost-optimization-hub | compute-optimizer


@dataclass
class Period:
    """The Cost Explorer window being reported on."""
    start: date
    end: date                      # exclusive, as Cost Explorer expects
    complete: bool                 # True when the whole month is in the past
    as_of: date

    @property
    def days_in_month(self) -> int:
        return calendar.monthrange(self.start.year, self.start.month)[1]

    @property
    def elapsed_days(self) -> int:
        return self.days_in_month if self.complete else max(1, (self.end - self.start).days)

    @property
    def label(self) -> str:
        return f"{self.start:%b %Y}" + (" (complete)" if self.complete else " to date")

    def to_dict(self) -> dict:
        return {"start": self.start.isoformat(), "end": self.end.isoformat(), "complete": self.complete,
                "as_of": self.as_of.isoformat()}

    @classmethod
    def from_dict(cls, d: dict) -> "Period":
        return cls(date.fromisoformat(d["start"]), date.fromisoformat(d["end"]), bool(d.get("complete")),
                   date.fromisoformat(d.get("as_of") or d["end"]))


def month_window(today: date) -> Period:
    """Month-to-date window. On the 1st there is no completed day yet (start would equal end,
    which Cost Explorer rejects), so report on the previous, complete month instead."""
    if today.day == 1:
        prev_end = today - timedelta(days=1)
        return Period(prev_end.replace(day=1), today, True, today)
    return Period(today.replace(day=1), today, False, today)


@dataclass
class ScanResult:
    """Everything one scan (or one saved report) contains."""
    identity: dict[str, Any] = field(default_factory=dict)
    resources: list[Resource] = field(default_factory=list)
    catalog: list[Resource] = field(default_factory=list)
    costs: list[CostRow] = field(default_factory=list)
    billing_breakdown: list[dict[str, Any]] = field(default_factory=list)
    coverage: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    period: Period | None = None
    daily: list[tuple[str, float]] = field(default_factory=list)
    forecast: float | None = None
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    reconciliation: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    generated_at: datetime | None = None


# ── helpers ───────────────────────────────────────────────────────────────────

def money(v: float | None, currency: str = "USD") -> str:
    if v is None:
        return "N/A"
    sym = "$" if currency == "USD" else f"{currency} "
    return f"{sym}{v:,.2f}"


def tags_to_dict(tags: list[dict] | None) -> dict[str, str]:
    return {str(x.get("Key", "")): str(x.get("Value", "")) for x in (tags or [])}


def name_from_tags(tags: dict[str, str], fallback: str = "") -> str:
    return tags.get("Name") or fallback


def resource_from_dict(d: dict) -> Resource:
    names = {f.name for f in fields(Resource)}
    return Resource(**{k: v for k, v in d.items() if k in names})


def costrow_from_dict(d: dict) -> CostRow:
    names = {f.name for f in fields(CostRow)}
    return CostRow(**{k: v for k, v in d.items() if k in names})


def finding_from_dict(d: dict) -> Finding:
    names = {f.name for f in fields(Finding)}
    return Finding(**{k: v for k, v in d.items() if k in names})


def csv_row(obj) -> dict[str, Any]:
    """asdict() with nested dict/list fields JSON-encoded so they survive CSV."""
    d = asdict(obj)
    for k, v in d.items():
        if isinstance(v, (dict, list)):
            d[k] = json.dumps(v, ensure_ascii=False, default=str)
    return d
