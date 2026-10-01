"""Actual cost per resource from AWS Data Exports (CUR 2.0) or a legacy Parquet CUR — read-only.

The export's S3 location is discovered with bcm-data-exports / cur read APIs, the current billing
period's Parquet files are downloaded with s3:GetObject into a local cache, and aggregated locally by
line_item_resource_id with DuckDB (or pyarrow). Nothing is created or changed in AWS."""
from __future__ import annotations

import glob
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .aws import classify

CACHE = Path.home() / ".cache" / "deadweight" / "cur"
MAX_DOWNLOAD = 2 * 1024 ** 3
AWS_ID = re.compile(r"^(i|vol|nat|eipalloc|snap|ami|eni|vpce|tgw-attach|vpn|igw|fs|fsap)-[0-9a-f]+$")


@dataclass
class ExportLocation:
    name: str
    bucket: str
    prefix: str
    region: str
    kind: str          # cur2 | legacy


def discover(pool) -> list[ExportLocation]:
    out: list[ExportLocation] = []
    try:
        dx = pool.get("bcm-data-exports", "us-east-1")
        for e in _all(dx, "list_exports", "Exports"):
            d = dx.get_export(ExportArn=e["ExportArn"]).get("Export", {})
            s3 = (d.get("DestinationConfigurations") or {}).get("S3Destination") or {}
            fmt = (s3.get("S3OutputConfigurations") or {}).get("Format", "")
            query = str((d.get("DataQuery") or {}).get("QueryStatement", ""))
            if fmt == "PARQUET" and "COST_AND_USAGE_REPORT" in query.upper():
                out.append(ExportLocation(d.get("Name", ""), s3["S3Bucket"], s3.get("S3Prefix", ""), s3.get("S3Region", "us-east-1"), "cur2"))
    except Exception:
        pass
    try:
        cur = pool.get("cur", "us-east-1")
        for d in _all(cur, "describe_report_definitions", "ReportDefinitions"):
            if str(d.get("Format", "")).lower() == "parquet":
                out.append(ExportLocation(d["ReportName"], d["S3Bucket"], d.get("S3Prefix", ""), d.get("S3Region", "us-east-1"), "legacy"))
    except Exception:
        pass
    return out


def _all(client, op: str, key: str, **kw) -> list:
    if client.can_paginate(op):
        return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]
    return list(getattr(client, op)(**kw).get(key, []))


def period_objects(pool, loc: ExportLocation, start) -> list[dict]:
    s3 = pool.get("s3", loc.region)
    base = loc.prefix.strip("/")
    if loc.kind == "cur2":
        exact = "/".join(p for p in (base, loc.name, "data", f"BILLING_PERIOD={start:%Y-%m}") if p) + "/"
        marker = f"BILLING_PERIOD={start:%Y-%m}/"
    else:
        exact = "/".join(p for p in (base, loc.name, loc.name, f"year={start.year}", f"month={start.month}") if p) + "/"
        marker = f"year={start.year}/month={start.month}/"
    objs = [o for o in _all(s3, "list_objects_v2", "Contents", Bucket=loc.bucket, Prefix=exact) if o["Key"].endswith(".parquet")]
    if not objs:     # tolerate other prefix layouts: search the export's prefix for the period marker
        objs = [o for o in _all(s3, "list_objects_v2", "Contents", Bucket=loc.bucket, Prefix=(base + "/") if base else "")
                if marker in o["Key"] and o["Key"].endswith(".parquet")]
    return objs


def download(pool, loc: ExportLocation, objs: list[dict]) -> list[Path]:
    s3 = pool.get("s3", loc.region)
    paths = []
    total = 0
    for o in objs:
        total += int(o.get("Size") or 0)
        if total > MAX_DOWNLOAD:
            raise RuntimeError(f"CUR files for this period exceed {MAX_DOWNLOAD / 1024 ** 3:.0f} GB; use --cur-path with a pre-filtered copy")
        dest = CACHE / loc.bucket / o["Key"]
        if not (dest.exists() and dest.stat().st_size == int(o.get("Size") or -1)):
            dest.parent.mkdir(parents=True, exist_ok=True)
            s3.download_file(loc.bucket, o["Key"], str(dest))
        paths.append(dest)
    return paths


def aggregate(paths: list[Path | str]) -> dict[str, float]:
    files = [str(p) for p in paths]
    if not files:
        return {}
    try:
        import duckdb
        con = duckdb.connect()
        rows = con.execute(
            "SELECT line_item_resource_id, SUM(line_item_unblended_cost) FROM read_parquet(?, union_by_name=true) "
            "WHERE line_item_resource_id IS NOT NULL AND line_item_resource_id <> '' GROUP BY 1", [files]).fetchall()
        return {str(rid): float(cost or 0) for rid, cost in rows}
    except ImportError:
        pass
    try:
        import pyarrow.parquet as pq
    except ImportError as e:
        raise RuntimeError("Reading CUR Parquet files needs `pip install duckdb` (or pyarrow)") from e
    out: dict[str, float] = {}
    for f in files:
        t = pq.read_table(f, columns=["line_item_resource_id", "line_item_unblended_cost"]).to_pydict()
        for rid, cost in zip(t["line_item_resource_id"], t["line_item_unblended_cost"]):
            if rid:
                out[rid] = out.get(rid, 0.0) + float(cost or 0)
    return out


USAGE_ITEM_TYPES = ("Usage", "DiscountedUsage", "SavingsPlanCoveredUsage")
REGION_PREFIX = re.compile(r"^[A-Z]{2,4}\d?-(?=[A-Za-z])")
# Charges that accrue because a resource exists (hours, IP-hours, GB-months, reserved task capacity)…
EXISTENCE = re.compile(r"Hours|Hrs|BoxUsage|InstanceUsage|Multi-AZUsage|LoadBalancerUsage|PublicIPv4|TimedStorage|ByteHrs|"
                       r"VolumeUsage|SnapshotUsage|StorageUsage|Storage$|KMS-Keys|Secret|HostedZone|WebACL|Rule$|"
                       r"Fargate-vCPU|Fargate-GB|Fargate-ARM|NatGateway-Hours|Endpoint-Hour|VpcEndpoint-Hours|ProvisionedConcurrency",
                       re.I)
# …versus charges that accrue because it does work (bytes, requests, LCUs, invocations).
ACTIVITY = re.compile(r"Bytes|Requests?|LCU|DataTransfer|DataProcessing|Invocation|Lambda-GB-Second|Queries|IOUsage|"
                      r"API|Messages|Transitions|Events", re.I)


def strip_region(usage_type: str) -> str:
    """'USE1-NatGateway-Hours' → 'NatGateway-Hours' (only the first location prefix is removed)."""
    return REGION_PREFIX.sub("", usage_type or "", count=1)


def charge_kind(usage_type: str) -> str:
    ut = strip_region(usage_type)
    if ACTIVITY.search(ut) and not re.search(r"Hours|Hrs|ByteHrs", ut):
        return "activity"
    if EXISTENCE.search(ut):
        return "existence"
    return "activity"


def pivot(paths: list[Path | str]) -> tuple[dict[str, dict], float]:
    """Per resource ID: total, existence vs activity cost and cost by usage type (region prefix stripped);
    plus the usage cost that carries no resource ID ("unattributed": data transfer, requests…)."""
    files = [str(p) for p in paths]
    if not files:
        return {}, 0.0
    rows: list[tuple] = []
    try:
        import duckdb
        con = duckdb.connect()
        cols = {d[0] for d in con.execute("SELECT * FROM read_parquet(?, union_by_name=true) LIMIT 0", [files]).description}
        ut = "line_item_usage_type" if "line_item_usage_type" in cols else "''"
        where = (f"line_item_line_item_type IN ({', '.join(repr(t) for t in USAGE_ITEM_TYPES)})"
                 if "line_item_line_item_type" in cols else "TRUE")
        rows = con.execute(
            f"SELECT COALESCE(line_item_resource_id, ''), {ut}, SUM(line_item_unblended_cost) "
            f"FROM read_parquet(?, union_by_name=true) WHERE {where} GROUP BY 1, 2", [files]).fetchall()
    except ImportError:
        import pyarrow.parquet as pq
        acc: dict[tuple, float] = {}
        for f in files:
            names = set(pq.read_schema(f).names)
            want = [c for c in ("line_item_resource_id", "line_item_unblended_cost", "line_item_usage_type",
                                "line_item_line_item_type") if c in names]
            t = pq.read_table(f, columns=want).to_pydict()
            n = len(t["line_item_unblended_cost"])
            for i in range(n):
                if "line_item_line_item_type" in t and t["line_item_line_item_type"][i] not in USAGE_ITEM_TYPES:
                    continue
                key = (t["line_item_resource_id"][i] or "", (t.get("line_item_usage_type") or [""] * n)[i] or "")
                acc[key] = acc.get(key, 0.0) + float(t["line_item_unblended_cost"][i] or 0)
        rows = [(k[0], k[1], v) for k, v in acc.items()]
    out: dict[str, dict] = {}
    unattributed = 0.0
    for rid, usage_type, cost in rows:
        cost = float(cost or 0)
        if not rid:
            unattributed += cost
            continue
        d = out.setdefault(str(rid), {"total": 0.0, "existence": 0.0, "activity": 0.0, "by_usage_type": {}})
        d["total"] += cost
        d[charge_kind(usage_type)] += cost
        key = strip_region(usage_type) or "(unknown)"
        d["by_usage_type"][key] = d["by_usage_type"].get(key, 0.0) + cost
    return out, unattributed


def _tail(s: str) -> str:
    return re.split(r"[/:]", s)[-1] if s else s


def match(resources, costs: dict[str, float] | dict[str, dict]) -> tuple[int, float, float]:
    """Attach CUR cost to inventoried resources. `costs` is {resource_id: amount} or the pivot from pivot()."""
    index: dict[str, Any] = {}
    for r in resources:
        for k in (r.resource_id, r.arn):
            if k:
                index.setdefault(str(k), r)
        t = _tail(r.arn or "")
        if AWS_ID.match(t or ""):
            index.setdefault(t, r)
    for r in resources:
        r.actual_mtd = None
        r.details.pop("cur", None)
    n, matched, total = 0, 0.0, 0.0
    for rid, value in costs.items():
        amount = value["total"] if isinstance(value, dict) else value
        total += amount
        r = index.get(rid) or (index.get(_tail(rid)) if AWS_ID.match(_tail(rid) or "") else None)
        if r is not None:
            r.actual_mtd = (r.actual_mtd or 0.0) + amount
            if isinstance(value, dict):
                cur = r.details.setdefault("cur", {"existence": 0.0, "activity": 0.0, "by_usage_type": {}})
                cur["existence"] = round(cur["existence"] + value["existence"], 6)
                cur["activity"] = round(cur["activity"] + value["activity"], 6)
                for ut, c in value["by_usage_type"].items():
                    cur["by_usage_type"][ut] = round(cur["by_usage_type"].get(ut, 0.0) + c, 6)
            matched += amount
            n += 1
    return n, matched, total


def attach(scanner, res) -> None:
    opts = scanner.opts
    if opts.cur_path:
        p = Path(opts.cur_path)
        files = sorted(glob.glob(str(p / "**" / "*.parquet"), recursive=True)) if p.is_dir() else sorted(glob.glob(opts.cur_path))
        source = f"local files ({opts.cur_path})"
    else:
        locs = sorted(discover(scanner.pool), key=lambda l: l.kind != "cur2")
        if not locs:
            scanner.coverage_event("Cost & Usage Report", "global", "not-enabled",
                                   "No Parquet Data Export (CUR 2.0) or legacy CUR found; per-resource actuals unavailable")
            return
        loc = locs[0]
        try:
            objs = period_objects(scanner.pool, loc, res.period.start)
        except Exception as e:
            status, detail = classify(e)
            scanner.coverage_event("Cost & Usage Report", "global", status, f"s3://{loc.bucket}/{loc.prefix}: {detail}", "s3:ListBucket")
            return
        if not objs:
            scanner.coverage_event("Cost & Usage Report", "global", "not-enabled",
                                   f"Export '{loc.name}' has no files for {res.period.start:%Y-%m} yet")
            return
        files = download(scanner.pool, loc, objs)
        source = f"s3://{loc.bucket}/{loc.prefix} ({loc.kind})"
    costs, no_id = pivot(files)
    n, matched, total = match(scanner.resources, costs)
    # Unattributed = usage with no resource ID (transfer, requests) + resource IDs we could not match to inventory.
    res.meta["cur"] = {"source": source, "files": len(files), "resource_ids": len(costs), "matched_resources": n,
                       "matched_cost": round(matched, 2), "total_resource_cost": round(total, 2),
                       "no_resource_id_cost": round(no_id, 2), "unmatched_resource_ids": len(costs) - n,
                       "unattributed_cost": round(no_id + (total - matched), 2)}
    scanner.coverage_event("Cost & Usage Report", "global", "ok",
                           f"{len(costs)} resource IDs, ${total:,.2f} with resource IDs; ${matched:,.2f} matched to {n} inventoried resources;"
                           f" ${no_id:,.2f} usage without a resource ID")
