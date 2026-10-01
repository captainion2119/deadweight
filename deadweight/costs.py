"""Cost Explorer queries. Every request is counted: Cost Explorer charges $0.01 per API request."""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from .billing import LABEL
from .models import CostRow, Period

DIMENSIONS = ["USAGE_TYPE", "OPERATION", "REGION", "RECORD_TYPE", "PURCHASE_TYPE", "INSTANCE_TYPE"]
CE_REQUEST_COST = 0.01


class CostExplorer:
    def __init__(self, pool, period: Period, coverage=None):
        self.ce = pool.get("ce", "us-east-1")
        self.period = period
        self.requests = 0
        self._coverage = coverage or (lambda *a, **k: None)

    def _call(self, op: str, **kw) -> dict:
        self.requests += 1
        return getattr(self.ce, op)(**kw)

    @property
    def window(self) -> dict[str, str]:
        return {"Start": self.period.start.isoformat(), "End": self.period.end.isoformat()}

    def services(self) -> list[CostRow]:
        """Per-service cost for the period: unblended (the source of truth) plus amortized and net-amortized
        in the same request at no extra cost."""
        metrics = ["UnblendedCost", "AmortizedCost", "NetAmortizedCost"]
        raw: dict[str, dict[str, Any]] = {}
        token = None
        while True:
            kw = {"TimePeriod": self.window, "Granularity": "MONTHLY", "Metrics": metrics,
                  "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}]}
            if token:
                kw["NextPageToken"] = token
            resp = self._call("get_cost_and_usage", **kw)
            for period in resp.get("ResultsByTime", []):
                for g in period.get("Groups", []):
                    m = g.get("Metrics", {})
                    d = raw.setdefault(g["Keys"][0], {"u": 0.0, "a": 0.0, "n": 0.0, "unit": "USD"})
                    d["u"] += float((m.get("UnblendedCost") or {}).get("Amount", 0) or 0)
                    d["a"] += float((m.get("AmortizedCost") or {}).get("Amount", 0) or 0)
                    d["n"] += float((m.get("NetAmortizedCost") or {}).get("Amount", 0) or 0)
                    d["unit"] = (m.get("UnblendedCost") or {}).get("Unit", "USD")
            token = resp.get("NextPageToken")
            if not token:
                break
        p = self.period
        scale = 1.0 if p.complete else p.days_in_month / p.elapsed_days
        rows = [CostRow(LABEL.get(name, name), d["u"], d["u"] * scale, d["unit"], bill_service=name,
                        amortized_mtd=d["a"], net_amortized_mtd=d["n"]) for name, d in raw.items()]
        return sorted(rows, key=lambda x: x.actual_mtd, reverse=True)

    def dimensions(self, dims: list[str] | None = None, extra: list[tuple[str, str]] | None = None) -> list[dict[str, Any]]:
        """SERVICE × dimension breakdown. `extra` adds (GroupBy type, key) pairs such as ("TAG", "app")."""
        rows: list[dict[str, Any]] = []
        groups = [("DIMENSION", d) for d in (dims or DIMENSIONS)] + list(extra or [])
        for gtype, key in groups:
            label = key if gtype == "DIMENSION" else f"TAG:{key}" if gtype == "TAG" else f"{gtype}:{key}"
            token = None
            try:
                while True:
                    kw = {"TimePeriod": self.window, "Granularity": "MONTHLY", "Metrics": ["UnblendedCost"],
                          "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}, {"Type": gtype, "Key": key}]}
                    if token:
                        kw["NextPageToken"] = token
                    resp = self._call("get_cost_and_usage", **kw)
                    for period in resp.get("ResultsByTime", []):
                        for g in period.get("Groups", []):
                            keys = g.get("Keys", [])
                            m = (g.get("Metrics") or {}).get("UnblendedCost") or {}
                            amount = float(m.get("Amount", 0) or 0)
                            if abs(amount) > 1e-10:
                                value = keys[1] if len(keys) > 1 else ""
                                if gtype == "TAG":
                                    value = value.split("$", 1)[-1] or "(untagged)"
                                rows.append({"service": keys[0] if keys else "", "dimension": label, "value": value,
                                             "actual_mtd": amount, "currency": m.get("Unit", "USD")})
                    token = resp.get("NextPageToken")
                    if not token:
                        break
                self._coverage(f"Cost Explorer dimension {label}", "global", "ok", f"queried {label}")
            except Exception as e:
                self._coverage(f"Cost Explorer dimension {label}", "global", "error", str(e))
        return rows

    def daily(self, days: int = 30) -> list[tuple[str, float]]:
        end = self.period.end if not self.period.complete else self.period.as_of
        start = end - timedelta(days=days)
        out: dict[str, float] = {}
        token = None
        while True:
            kw = {"TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()}, "Granularity": "DAILY",
                  "Metrics": ["UnblendedCost"]}
            if token:
                kw["NextPageToken"] = token
            resp = self._call("get_cost_and_usage", **kw)
            for r in resp.get("ResultsByTime", []):
                out[r["TimePeriod"]["Start"]] = float((r.get("Total", {}).get("UnblendedCost") or {}).get("Amount", 0) or 0)
            token = resp.get("NextPageToken")
            if not token:
                break
        return sorted(out.items())

    def forecast(self) -> float | None:
        """AWS's own month-end forecast (actual so far + forecast for the remaining days)."""
        p = self.period
        if p.complete:
            return None
        month_end = (p.start.replace(day=28) + timedelta(days=4)).replace(day=1)
        start = max(p.as_of, p.end)
        if start >= month_end:
            return None
        resp = self._call("get_cost_forecast", TimePeriod={"Start": start.isoformat(), "End": month_end.isoformat()},
                          Metric="UNBLENDED_COST", Granularity="MONTHLY")
        return float((resp.get("Total") or {}).get("Amount", 0) or 0)

    def anomalies(self, days: int = 30) -> list[dict[str, Any]]:
        end = self.period.as_of
        resp = self._call("get_anomalies", DateInterval={"StartDate": (end - timedelta(days=days)).isoformat(),
                                                         "EndDate": end.isoformat()}, MaxResults=50)
        out = []
        for a in resp.get("Anomalies", []):
            causes = a.get("RootCauses") or [{}]
            c0 = causes[0]
            out.append({"id": a.get("AnomalyId"), "start": a.get("AnomalyStartDate"), "end": a.get("AnomalyEndDate"),
                        "impact": float((a.get("Impact") or {}).get("TotalImpact", 0) or 0),
                        "service": c0.get("Service", ""), "region": c0.get("Region", ""), "usage_type": c0.get("UsageType", ""),
                        "account": c0.get("LinkedAccount", ""), "score": (a.get("AnomalyScore") or {}).get("CurrentScore")})
        return out

    def active_tag_keys(self, limit: int = 3) -> list[str]:
        keys: list[str] = []
        token = None
        while True:
            kw = {"Status": "Active", "Type": "UserDefined", "MaxResults": 100, **({"NextToken": token} if token else {})}
            resp = self._call("list_cost_allocation_tags", **kw)
            keys += [t["TagKey"] for t in resp.get("CostAllocationTags", [])]
            token = resp.get("NextToken")
            if not token:
                break
        return keys[:limit]

    def ec2_resource_costs(self) -> dict[str, float]:
        """Best-effort actual EC2 resource cost for the last 14 days (needs resource-level data enabled)."""
        today = self.period.as_of
        start = max(today.replace(day=1), today - timedelta(days=13)) if today.day > 1 else today - timedelta(days=13)
        out: dict[str, float] = {}
        token = None
        while True:
            kw = {"TimePeriod": {"Start": start.isoformat(), "End": today.isoformat()}, "Granularity": "DAILY",
                  "Filter": {"Dimensions": {"Key": "SERVICE", "Values": ["Amazon Elastic Compute Cloud - Compute"]}},
                  "Metrics": ["UnblendedCost"], "GroupBy": [{"Type": "DIMENSION", "Key": "RESOURCE_ID"}]}
            if token:
                kw["NextPageToken"] = token
            resp = self._call("get_cost_and_usage_with_resources", **kw)
            for period in resp.get("ResultsByTime", []):
                for g in period.get("Groups", []):
                    rid = g["Keys"][0]
                    out[rid] = out.get(rid, 0.0) + float(g["Metrics"]["UnblendedCost"]["Amount"])
            token = resp.get("NextPageToken")
            if not token:
                break
        return out

    def active_regions(self) -> list[str]:
        resp = self._call("get_cost_and_usage", TimePeriod=self.window, Granularity="MONTHLY", Metrics=["UnblendedCost"],
                          GroupBy=[{"Type": "DIMENSION", "Key": "REGION"}])
        out = set()
        for period in resp.get("ResultsByTime", []):
            for g in period.get("Groups", []):
                if float((g.get("Metrics", {}).get("UnblendedCost") or {}).get("Amount", 0) or 0) > 0.001:
                    out.add(g["Keys"][0])
        return sorted(out)
