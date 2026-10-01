"""Saving, loading, comparing and rendering scan results (JSON + CSV + self-contained HTML)."""
from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from .aws import classify
from .billing import bill_of, explained_totals, reconcile, upgrade_resource, ARN_BILL
from .models import (Period, Resource, ScanResult, costrow_from_dict, csv_row, finding_from_dict, money, month_window,
                     resource_from_dict)

COST_SEMANTICS = {
    "actual_mtd": "AWS Cost Explorer UnblendedCost; financial source of truth for scanned account",
    "projected_month": "simple current-month run-rate projection, not AWS forecast",
    "monthly_estimate": "configuration/list-price estimate; null means not calculated, never means free",
    "actual_recent": "best-effort EC2 resource-level Cost Explorer cost for last 14 days when granular data is enabled",
    "actual_mtd_resource": "per-resource actual cost from the CUR / Data Exports when available",
    "forecast": "AWS Cost Explorer GetCostForecast for the rest of the month (null when unavailable)",
    "amortized_mtd": "AmortizedCost: upfront RI / Savings Plan fees spread over the period",
}
BASE_ACTIONS = [
    "sts:GetCallerIdentity", "ec2:DescribeRegions", "pricing:GetProducts", "cloudwatch:GetMetricData",
    "ce:GetCostAndUsage", "ce:GetCostAndUsageWithResources", "ce:GetCostForecast", "ce:GetAnomalies",
    "ce:ListCostAllocationTags", "cost-optimization-hub:ListRecommendations", "compute-optimizer:GetEnrollmentStatus",
    "compute-optimizer:GetEC2InstanceRecommendations", "compute-optimizer:GetEBSVolumeRecommendations",
    "compute-optimizer:GetLambdaFunctionRecommendations", "compute-optimizer:GetECSServiceRecommendations",
    "bcm-data-exports:ListExports", "bcm-data-exports:GetExport", "cur:DescribeReportDefinitions",
    "s3:ListBucket", "s3:GetObject", "compute-optimizer:GetIdleRecommendations",
    "trustedadvisor:ListRecommendations", "trustedadvisor:ListRecommendationResources",
    "config:DescribeConfigRules", "config:GetComplianceDetailsByConfigRule",
]


# ── serialisation ─────────────────────────────────────────────────────────────

def to_dict(res: ScanResult) -> dict[str, Any]:
    return {
        "version": 6,
        "generated_at": (res.generated_at or datetime.now(timezone.utc)).isoformat(),
        "identity": res.identity,
        "period": res.period.to_dict() if res.period else None,
        "resources": [asdict(x) for x in res.resources],
        "catalog": [asdict(x) for x in res.catalog],
        "costs": [asdict(x) for x in res.costs],
        "billing_breakdown": res.billing_breakdown,
        "reconciliation": res.reconciliation,
        "daily": res.daily,
        "forecast": res.forecast,
        "anomalies": res.anomalies,
        "findings": [asdict(f) for f in res.findings],
        "cost_semantics": COST_SEMANTICS,
        "coverage": res.coverage,
        "errors": res.errors,
        "meta": res.meta,
    }


def _write_csv(path: Path, rows: list[dict], fields: list[str] | None = None) -> None:
    fields = fields or (list(rows[0].keys()) if rows else ["empty"])
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)


def export(res: ScanResult, out_dir: Path, formats: tuple[str, ...] = ("json", "csv", "html"),
           html_style: str = "report") -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    written: list[Path] = []
    if "json" in formats:
        p = out_dir / f"aws-report-{stamp}.json"
        p.write_text(json.dumps(to_dict(res), indent=2, default=str), encoding="utf-8")
        written.append(p)
    if "csv" in formats:
        tables = {
            "resources": [csv_row(r) for r in res.resources],
            "costs": [csv_row(c) for c in res.costs],
            "billing-breakdown": [{k: x.get(k, "") for k in ("service", "dimension", "value", "actual_mtd", "currency")}
                                  for x in res.billing_breakdown],
            "catalog": [csv_row(r) for r in res.catalog],
            "findings": [csv_row(f) for f in res.findings],
            "reconciliation": [{k: v for k, v in {**row, "parent": parent}.items() if k != "children"}
                               for top in res.reconciliation for row, parent in [(top, "")] + [(c, top["label"]) for c in top["children"]]],
        }
        empty = {"resources": csv_row(Resource("", "", "", "")), "costs": None, "catalog": csv_row(Resource("", "", "", ""))}
        for name, rows in tables.items():
            p = out_dir / f"aws-{name}-{stamp}.csv"
            fields = list(rows[0].keys()) if rows else (list(empty[name].keys()) if empty.get(name) else None)
            _write_csv(p, rows, fields)
            written.append(p)
    if "html" in formats:
        p = out_dir / f"aws-report-{stamp}.html"
        p.write_text(html(res, html_style), encoding="utf-8")
        written.append(p)
    perms = missing_permissions(res)
    if perms:
        p = out_dir / f"aws-missing-permissions-{stamp}.json"
        p.write_text(json.dumps(perms, indent=2), encoding="utf-8")
        written.append(p)
    return written


_LEGACY_ERR = re.compile(r"An error occurred \(([^)]+)\) when calling the (\w+) operation(?:\s*\([^)]*\))?:\s*(.*)", re.S)


def _reclassify(ev: dict) -> dict:
    """Schema-5 reports used a single 'unavailable' status; split it the way current scans do."""
    if ev.get("status") == "not-configured":
        return {**ev, "status": "not-enabled"}
    if ev.get("status") != "unavailable":
        return ev
    m = _LEGACY_ERR.search(str(ev.get("detail", "")))
    if not m:
        return {**ev, "status": "error"}
    code, op, msg = m.groups()
    status, _ = classify(ClientError({"Error": {"Code": code, "Message": msg}}, op))
    return {**ev, "status": status}


def load(path: Path | str) -> ScanResult:
    from . import findings
    from .collectors.base import REGISTRY
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        gen = datetime.fromisoformat(d["generated_at"])
    except Exception:
        gen = datetime.fromtimestamp(Path(path).stat().st_mtime, timezone.utc)
    res = ScanResult(
        identity=d.get("identity", {}),
        resources=[resource_from_dict(x) for x in d.get("resources", [])],
        catalog=[resource_from_dict(x) for x in d.get("catalog", [])],
        costs=[costrow_from_dict(x) for x in d.get("costs", [])],
        billing_breakdown=d.get("billing_breakdown", []),
        coverage=[_reclassify(x) for x in d.get("coverage", [])],
        errors=d.get("errors", []),
        daily=[tuple(x) for x in d.get("daily", [])],
        forecast=d.get("forecast"),
        anomalies=d.get("anomalies", []),
        findings=[finding_from_dict(x) for x in d.get("findings", [])],
        reconciliation=d.get("reconciliation") or [],
        meta=d.get("meta", {}),
        generated_at=gen,
    )
    res.period = Period.from_dict(d["period"]) if d.get("period") else month_window(gen.astimezone().date())
    for r in res.resources + res.catalog:
        upgrade_resource(r, REGISTRY)
    if d.get("version", 5) < 6:
        from .scanner import dedupe
        res.resources = dedupe(res.resources)     # schema-5 reports could list one resource twice
    if not res.reconciliation:
        known = {s.bill for s in REGISTRY.values() if s.bill} | {f"{s.bill}/{s.usage}" for s in REGISTRY.values() if s.usage}
        res.reconciliation = reconcile(res.costs, res.billing_breakdown, res.resources, known | set(ARN_BILL.values()))
    if "findings" not in d:
        findings.rerun_rules(res)            # also classifies usage
    elif "usage_summary" not in res.meta:
        from . import usage
        usage.classify(res, store=None)      # reports saved before usage states existed
    res.meta.setdefault("version", d.get("version", 5))
    return res


# ── comparison ────────────────────────────────────────────────────────────────

def diff(a: ScanResult, b: ScanResult) -> dict[str, Any]:
    from .scanner import Scanner
    ka = {Scanner.canonical_key(r): r for r in a.resources}
    kb = {Scanner.canonical_key(r): r for r in b.resources}
    added = sorted((kb[k] for k in kb.keys() - ka.keys()), key=lambda r: (r.service, r.region, r.name or r.resource_id))
    removed = sorted((ka[k] for k in ka.keys() - kb.keys()), key=lambda r: (r.service, r.region, r.name or r.resource_id))
    changed = []
    for k in ka.keys() & kb.keys():
        x, y = ka[k], kb[k]
        deltas = []
        if (x.state or "") != (y.state or ""):
            deltas.append(("state", x.state, y.state))
        if abs((x.monthly_estimate or 0) - (y.monthly_estimate or 0)) >= 0.5:
            deltas.append(("estimate", x.monthly_estimate, y.monthly_estimate))
        if (x.config or "") != (y.config or "") and not y.service.startswith("AWS/"):
            deltas.append(("config", x.config, y.config))
        if deltas:
            changed.append({"resource": y, "deltas": deltas})
    bills: dict[str, dict] = {}
    for side, res in (("a", a), ("b", b)):
        for c in res.costs:
            row = bills.setdefault(bill_of(c), {"bill": bill_of(c), "label": c.service, "a": 0.0, "b": 0.0})
            row[side] += c.projected_month
    cost_rows = sorted(({**r, "delta": r["b"] - r["a"]} for r in bills.values()), key=lambda r: abs(r["delta"]), reverse=True)

    def totals(res: ScanResult) -> dict:
        est, run = explained_totals(res.reconciliation)
        return {"resources": len(res.resources), "run_rate": sum(c.projected_month for c in res.costs),
                "actual": sum(c.actual_mtd for c in res.costs),
                "estimate": sum((r.monthly_estimate or 0) for r in res.resources),
                "explained": est / run if run else None,
                "savings": sum((f.monthly_savings or 0) for f in res.findings),
                "generated_at": res.generated_at.isoformat() if res.generated_at else "",
                "period": res.period.label if res.period else ""}
    return {"added": added, "removed": removed, "changed": sorted(changed, key=lambda c: c["resource"].service),
            "costs": cost_rows, "a": totals(a), "b": totals(b), "unique_a": len(ka), "unique_b": len(kb),
            "same_account": str(a.identity.get("Account", "")) == str(b.identity.get("Account", ""))}


# ── IAM policies ──────────────────────────────────────────────────────────────

def policy(services: set[str] | None = None) -> dict:
    from .collectors.base import REGISTRY
    actions = set(BASE_ACTIONS)
    for k, s in REGISTRY.items():
        if services is None or k in services:
            actions.update(s.actions)
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "AwsCostTuiReadOnly", "Effect": "Allow", "Action": sorted(actions), "Resource": "*"}]}


def missing_permissions(res: ScanResult) -> dict | None:
    actions = sorted({c["action"] for c in res.coverage if c.get("status") == "denied" and c.get("action")})
    if not actions:
        return None
    return {"Version": "2012-10-17", "Statement": [{"Sid": "AwsCostTuiMissing", "Effect": "Allow", "Action": actions, "Resource": "*"}]}


# ── HTML ──────────────────────────────────────────────────────────────────────

def html(res: ScanResult, style: str = "report") -> str:
    from .html_report import render
    return render(res, style)
