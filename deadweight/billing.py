"""Bill ↔ inventory reconciliation.

Every collector declares the exact Cost Explorer SERVICE name its resources are billed under (and, for
shared lines such as "EC2 - Other", a usage-type family). Reconciliation joins on those names, so a
bill line is matched to the resources that produce it instead of to a look-alike display label."""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any, Iterable

from .models import CostRow, Resource

# ARN service prefix → Cost Explorer SERVICE, for resources found only by generic discovery.
ARN_BILL = {
    "ec2": "Amazon Elastic Compute Cloud - Compute", "rds": "Amazon Relational Database Service",
    "s3": "Amazon Simple Storage Service", "lambda": "AWS Lambda", "logs": "AmazonCloudWatch", "cloudwatch": "AmazonCloudWatch",
    "memorydb": "Amazon MemoryDB", "bedrock-agentcore": "Amazon Bedrock AgentCore", "bedrock": "Amazon Bedrock",
    "elasticloadbalancing": "Amazon Elastic Load Balancing", "ecs": "Amazon Elastic Container Service",
    "eks": "Amazon Elastic Container Service for Kubernetes", "apigateway": "Amazon API Gateway",
    "kms": "AWS Key Management Service", "secretsmanager": "AWS Secrets Manager", "servicediscovery": "AWS Cloud Map",
    "ses": "Amazon Simple Email Service", "athena": "Amazon Athena", "states": "AWS Step Functions", "glue": "AWS Glue",
    "wafv2": "AWS WAF", "elasticfilesystem": "Amazon Elastic File System", "ecr": "Amazon EC2 Container Registry (ECR)",
    "cloudfront": "Amazon CloudFront", "route53": "Amazon Route 53", "dynamodb": "Amazon DynamoDB",
    "sqs": "Amazon Simple Queue Service", "sns": "Amazon Simple Notification Service", "elasticache": "Amazon ElastiCache",
    "es": "Amazon OpenSearch Service", "aoss": "Amazon OpenSearch Service", "kinesis": "Amazon Kinesis",
    "firehose": "Amazon Kinesis Firehose", "kafka": "Amazon Managed Streaming for Apache Kafka", "mq": "Amazon MQ",
    "redshift": "Amazon Redshift", "sagemaker": "Amazon SageMaker", "backup": "AWS Backup", "fsx": "Amazon FSx",
    "transfer": "AWS Transfer Family", "acm-pca": "AWS Certificate Manager", "cloudtrail": "AWS CloudTrail",
    "config": "AWS Config", "guardduty": "Amazon GuardDuty", "securityhub": "AWS Security Hub",
    "events": "Amazon EventBridge", "scheduler": "Amazon EventBridge", "pipes": "Amazon EventBridge",
    "cognito-idp": "Amazon Cognito", "cognito-identity": "Amazon Cognito", "appsync": "AWS AppSync",
    "amplify": "AWS Amplify", "codebuild": "AWS CodeBuild", "codepipeline": "AWS CodePipeline",
    "timestream": "Amazon Timestream", "cassandra": "Amazon Keyspaces", "aps": "Amazon Managed Service for Prometheus",
    "grafana": "Amazon Managed Grafana", "datasync": "AWS DataSync", "lex": "Amazon Lex", "connect": "Amazon Connect",
    "iot": "AWS IoT", "geo": "Amazon Location Service", "emr-serverless": "Amazon EMR", "elasticmapreduce": "Amazon Elastic MapReduce",
    "dms": "AWS Database Migration Service", "network-firewall": "AWS Network Firewall", "globalaccelerator": "AWS Global Accelerator",
    "apprunner": "AWS App Runner", "lightsail": "Amazon Lightsail", "kendra": "Amazon Kendra", "ssm": "AWS Systems Manager",
}

# Display labels for bill lines.
LABEL = {
    "Amazon Elastic Compute Cloud - Compute": "EC2 Compute", "Amazon Simple Storage Service": "S3",
    "Amazon Relational Database Service": "RDS", "Amazon Elastic Container Service": "ECS",
    "Amazon Elastic Container Service for Kubernetes": "EKS", "AWS Lambda": "Lambda", "Amazon DynamoDB": "DynamoDB",
    "Amazon API Gateway": "API Gateway", "Amazon CloudFront": "CloudFront", "Amazon Route 53": "Route53",
    "Amazon ElastiCache": "ElastiCache", "Amazon OpenSearch Service": "OpenSearch",
    "Amazon Elastic Container Registry (ECR)": "ECR", "Amazon EC2 Container Registry (ECR)": "ECR",
    "AWS Secrets Manager": "Secrets Manager", "Amazon Simple Queue Service": "SQS",
    "Amazon Simple Notification Service": "SNS", "AWS Key Management Service": "KMS", "Amazon Bedrock": "Bedrock",
    "Amazon Virtual Private Cloud": "VPC", "Amazon Elastic Load Balancing": "ELB", "AmazonCloudWatch": "CloudWatch",
    "Amazon Elastic File System": "EFS",
}
LABEL_TO_BILL = {v: k for k, v in LABEL.items() if k != "Amazon Elastic Container Registry (ECR)"}

SPECIAL = {"Tax": "tax", "AWS Cost Explorer": "billing API", "AWS Marketplace": "marketplace",
           "Savings Plans for AWS Compute usage": "commitment", "Savings Plans for  Compute usage": "commitment",
           "AWS Support (Business)": "support", "AWS Support (Developer)": "support",
           "AWS Support (Enterprise)": "support", "AWS Support (Enterprise On-Ramp)": "support",
           "Refund": "credit", "Credit": "credit"}

# Usage-type families inside shared bill lines (first matching pattern wins).
USAGE_FAMILIES = {
    "EC2 - Other": [("NAT Gateway", r"NatGateway"), ("EBS snapshots", r"EBS:Snapshot"), ("EBS volumes", r"EBS:"),
                    ("Elastic IP (legacy)", r"ElasticIP"), ("Data transfer", r"DataTransfer|-Bytes$|AWS-(In|Out)")],
    "Amazon Virtual Private Cloud": [("Public IPv4", r"PublicIPv4"), ("VPC endpoints", r"VpcEndpoint"),
                                     ("Transit Gateway", r"TransitGateway"), ("VPN", r"VPN|ClientVPN"),
                                     ("Data transfer", r"DataTransfer|-Bytes$")],
    "AmazonCloudWatch": [("Logs", r"TimedStorage-ByteHrs|DataProcessing-Bytes|VendedLog|Logs"),
                         ("Alarms", r"AlarmMonitorUsage|HighResAlarm|CompositeAlarm"), ("Dashboards", r"DashboardsUsage"),
                         ("Metrics & API", r"MetricMonitorUsage|Requests|GMD|API|Metric")],
}


EC2_TYPE_BILL = {
    "volume": ("EC2 - Other", "EBS volumes"), "snapshot": ("EC2 - Other", "EBS snapshots"),
    "natgateway": ("EC2 - Other", "NAT Gateway"), "elastic-ip": ("Amazon Virtual Private Cloud", "Public IPv4"),
    "vpc-endpoint": ("Amazon Virtual Private Cloud", "VPC endpoints"),
    "transit-gateway-attachment": ("Amazon Virtual Private Cloud", "Transit Gateway"),
    "transit-gateway": ("Amazon Virtual Private Cloud", "Transit Gateway"), "vpn-connection": ("Amazon Virtual Private Cloud", "VPN"),
    "instance": ("Amazon Elastic Compute Cloud - Compute", ""), "image": ("EC2 - Other", "EBS snapshots"),
}
CW_TYPE_FAMILY = {"alarm": "Alarms", "dashboard": "Dashboards", "log-group": "Logs"}


def generic_bill(arn: str, rtype: str = "") -> tuple[str, str]:
    """(bill line, usage family) for a resource only known by ARN / generic type."""
    parts = arn.split(":", 5) if arn.startswith("arn:") else []
    svc = parts[2] if len(parts) > 2 else ""
    tail = parts[5] if len(parts) > 5 else ""
    kind = re.split(r"[/:]", tail)[0] if tail else (rtype.split(":", 1)[-1] if ":" in rtype else rtype)
    if svc == "ec2":
        return EC2_TYPE_BILL.get(kind, ("Amazon Virtual Private Cloud", ""))
    if svc in ("logs", "cloudwatch"):
        return "AmazonCloudWatch", CW_TYPE_FAMILY.get(kind, "Logs" if svc == "logs" else "")
    return ARN_BILL.get(svc, ""), ""


def bill_of(c: CostRow) -> str:
    return c.bill_service or LABEL_TO_BILL.get(c.service, c.service)


def usage_family(bill: str, usage_type: str) -> str:
    for label, pattern in USAGE_FAMILIES.get(bill, []):
        if re.search(pattern, usage_type or ""):
            return label
    return "Other"


def upgrade_resource(r: Resource, specs: dict) -> None:
    """Fill billing fields on resources from older reports."""
    if r.bill_service:
        return
    spec = specs.get(r.service)
    if spec is not None:
        r.bill_service, r.usage_family = spec.bill, r.usage_family or spec.usage
    elif r.service.startswith("AWS/"):
        r.bill_service, fam = generic_bill(r.arn or str(r.resource_id), r.resource_type)
        r.usage_family = r.usage_family or fam
        if not r.bill_service:
            r.bill_service = ARN_BILL.get(r.service[4:], "")
    if r.service == "VPC" and r.resource_type == "vpc-endpoint":
        r.usage_family = "VPC endpoints"


def reconcile(costs: list[CostRow], breakdown: list[dict], resources: Iterable[Resource], known_bills: set[str]) -> list[dict[str, Any]]:
    by_bill: dict[str, list[Resource]] = defaultdict(list)
    for r in resources:
        if r.category == "resource" and r.bill_service:
            by_bill[r.bill_service].append(r)
    usage: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for row in breakdown:
        bill = row.get("service", "")
        if bill in USAGE_FAMILIES and row.get("dimension") == "USAGE_TYPE":
            usage[bill][usage_family(bill, row.get("value", ""))] += float(row.get("actual_mtd") or 0)

    def summarise(rs: list[Resource]) -> tuple[float | None, int, int]:
        priced = [r.monthly_estimate for r in rs if r.monthly_estimate is not None]
        direct = sum(1 for r in rs if not r.service.startswith("AWS/"))
        return (sum(priced) if priced else None), len(priced), direct

    def status(bill: str, rs: list[Resource], est: float | None, run_rate: float, direct: int) -> str:
        if bill in SPECIAL:
            return SPECIAL[bill]
        if run_rate < 0.005 and not est:
            return "negligible"
        if not rs:
            return "nothing found" if bill in known_bills else "no collector"
        if direct == 0:
            return "discovered only"
        if est is None:
            return "usage-based"
        ratio = est / run_rate if run_rate > 0 else float("inf")
        return "reconciled" if 0.8 <= ratio <= 1.25 else "partly explained" if ratio < 0.8 else "over-estimated"

    rows, billed = [], set()
    for c in sorted(costs, key=lambda c: c.actual_mtd, reverse=True):
        bill = bill_of(c)
        billed.add(bill)
        rs = by_bill.get(bill, [])
        est, priced, direct = summarise(rs)
        factor = c.projected_month / c.actual_mtd if c.actual_mtd else 1.0
        row = {"bill": bill, "label": c.service, "actual": c.actual_mtd, "run_rate": c.projected_month, "currency": c.currency,
               "estimate": est, "resources": len(rs), "priced": priced,
               "explained": (est / c.projected_month) if (est is not None and c.projected_month > 0) else None,
               "status": status(bill, rs, est, c.projected_month, direct), "children": []}
        if bill in USAGE_FAMILIES:
            fams = dict(usage.get(bill, {}))
            for r in rs:
                fams.setdefault(r.usage_family or "Other", 0.0)
            for fam, actual in sorted(fams.items(), key=lambda kv: kv[1], reverse=True):
                frs = [r for r in rs if (r.usage_family or "Other") == fam]
                fest, fpriced, fdirect = summarise(frs)
                run = actual * factor
                row["children"].append({"bill": bill, "label": fam, "actual": actual, "run_rate": run, "currency": c.currency,
                                        "estimate": fest, "resources": len(frs), "priced": fpriced,
                                        "explained": (fest / run) if (fest is not None and run > 0) else None,
                                        "status": status(f"{bill}/{fam}", frs, fest, run, fdirect) if fam not in ("Data transfer", "Other")
                                        else "usage-based" if actual else "negligible"})
        rows.append(row)
    for bill, rs in by_bill.items():
        if bill in billed:
            continue
        est, priced, _ = summarise(rs)
        if est:
            rows.append({"bill": bill, "label": LABEL.get(bill, bill), "actual": 0.0, "run_rate": 0.0, "currency": "USD",
                         "estimate": est, "resources": len(rs), "priced": priced, "explained": None,
                         "status": "not billed yet", "children": []})
    return rows


def explained_totals(rows: list[dict]) -> tuple[float, float]:
    """(estimated, run-rate) over bill lines that resources can explain (excludes tax, support, credits…)."""
    est = run = 0.0
    for r in rows:
        if r["status"] in set(SPECIAL.values()) or r["status"] == "not billed yet":
            continue
        run += r["run_rate"]
        est += min(r["estimate"] or 0.0, r["run_rate"] * 1.25) if r["run_rate"] else 0.0
    return est, run
