"""Observability: CloudWatch Logs, alarms, dashboards."""
from __future__ import annotations

from datetime import datetime, timezone

from ..models import Resource
from ..pricing import RATES, region_note
from .base import Ctx, collector

GIB = 1024 ** 3
CW_BILL = "AmazonCloudWatch"


@collector("CloudWatch Logs", "observability", bill=CW_BILL, usage="Logs", client="logs",
           actions=("logs:DescribeLogGroups",), desc="Log groups: stored bytes, retention, class")
def log_groups(ctx: Ctx) -> None:
    c = ctx.client("logs")
    for g in ctx.pages(c, "describe_log_groups", "logGroups"):
        stored = float(g.get("storedBytes") or 0)
        gb = stored / GIB
        retention = g.get("retentionInDays")
        created = datetime.fromtimestamp(g["creationTime"] / 1000, timezone.utc).isoformat() if g.get("creationTime") else ""
        r = Resource("CloudWatch Logs", ctx.region, "log-group", g["logGroupName"], g["logGroupName"], "active",
                     str(g.get("arn", "")).removesuffix(":*"),
                     f"{gb:,.2f} GB stored · retention {f'{retention} d' if retention else 'never expires'} · {str(g.get('logGroupClass', 'STANDARD')).lower()}",
                     created=created, monthly_estimate=gb * RATES["logs_gb"],
                     estimate_note=f"{gb:,.2f} GB × ${RATES['logs_gb']}/GB-mo storage{region_note(ctx.region)}; ingestion ($0.50/GB) excluded")
        r.details.update(stored_bytes=stored, retention_days=retention, log_class=g.get("logGroupClass", "STANDARD"))
        # Only emitted while events arrive, so an empty 90-day series means nothing was ingested.
        ctx.metric(r, "logs_incoming_90d", "AWS/Logs", "IncomingBytes", {"LogGroupName": g["logGroupName"]}, days=90, missing="zero")
        ctx.add(r)


@collector("CloudWatch Alarms", "observability", bill=CW_BILL, usage="Alarms", client="cloudwatch",
           actions=("cloudwatch:DescribeAlarms",), desc="Metric and composite alarms")
def alarms(ctx: Ctx) -> None:
    c = ctx.client("cloudwatch")
    for page in c.get_paginator("describe_alarms").paginate(AlarmTypes=["MetricAlarm", "CompositeAlarm"]):
        ctx.check()
        for a in page.get("MetricAlarms", []):
            metrics = [m for m in a.get("Metrics", []) if m.get("MetricStat")] or [None]
            high_res = int(a.get("Period") or 60) < 60
            anomaly = bool(a.get("ThresholdMetricId"))
            unit = RATES["cw_alarm_hr"] if high_res else RATES["cw_alarm_std"]
            n = 3 if anomaly else len(metrics)
            r = Resource("CloudWatch Alarms", ctx.region, "alarm", a["AlarmArn"], a["AlarmName"], str(a.get("StateValue", "")).lower(),
                         a["AlarmArn"], f"{a.get('Namespace', 'metric math')} · {a.get('MetricName', '')}" + (" · high-res" if high_res else ""),
                         monthly_estimate=unit * n,
                         estimate_note=f"{n} metric(s) × ${unit}/alarm-month{' (anomaly detection bills 3)' if anomaly else ''}; first 10 standard alarms free")
            r.details.update(state=a.get("StateValue"), state_updated=str(a.get("StateUpdatedTimestamp", "")),
                             actions_enabled=a.get("ActionsEnabled"))
            ctx.add(r)
        for a in page.get("CompositeAlarms", []):
            ctx.add(Resource("CloudWatch Alarms", ctx.region, "composite-alarm", a["AlarmArn"], a["AlarmName"],
                             str(a.get("StateValue", "")).lower(), a["AlarmArn"], "composite",
                             monthly_estimate=RATES["cw_alarm_composite"], estimate_note="$0.50 per composite alarm-month"))


@collector("CloudWatch Dashboards", "observability", scope="global", bill=CW_BILL, usage="Dashboards", client="cloudwatch",
           actions=("cloudwatch:ListDashboards",), desc="Dashboards ($3/month after the first 3)")
def dashboards(ctx: Ctx) -> None:
    c = ctx.client("cloudwatch", "us-east-1")
    boards = sorted(ctx.pages(c, "list_dashboards", "DashboardEntries"), key=lambda d: d.get("DashboardName", ""))
    for i, d in enumerate(boards):
        free = i < 3
        ctx.add(Resource("CloudWatch Dashboards", "global", "dashboard", d["DashboardArn"], d["DashboardName"], "active",
                         d["DashboardArn"], f"{int(d.get('Size') or 0) / 1024:,.1f} KB",
                         monthly_estimate=0.0 if free else RATES["cw_dashboard"],
                         estimate_note="Within the 3 free dashboards" if free else "$3 per dashboard-month"))
