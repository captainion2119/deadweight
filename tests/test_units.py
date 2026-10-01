import json
import os
import sys
import threading
import time
import warnings
from datetime import date
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).parent))
import fixture  # noqa: E402,F401  (fake credentials)
import boto3  # noqa: E402
from botocore.exceptions import ClientError, EndpointConnectionError  # noqa: E402
from moto import mock_aws  # noqa: E402

from deadweight import billing, cur, findings, report, usage  # noqa: E402
from deadweight.aws import classify  # noqa: E402
from deadweight.models import CostRow, Finding, Resource, ScanResult, month_window  # noqa: E402
from deadweight.pricing import PriceResolver, RATES  # noqa: E402
from deadweight.scanner import Scanner, ScanOptions  # noqa: E402


@pytest.fixture(autouse=True)
def _private_usage_store(tmp_path, monkeypatch):
    """Scans in these tests must never write the user's real ~/.cache/deadweight/usage-state.json."""
    monkeypatch.setattr(usage, "STORE_PATH", tmp_path / "usage-state.json")


def ce(code, msg="", op="ListX"):
    return ClientError({"Error": {"Code": code, "Message": msg}}, op)


# ── classification ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("exc,status", [
    (ce("AccessDeniedException", "User: arn:aws:iam::1:user/x is not authorized to perform: bedrock:ListX"), "denied"),
    (ce("AccessDeniedException", "Your account is not authorized to invoke this API operation."), "not-available"),
    (ce("UnknownOperationException", ""), "not-available"),
    (ce("ThrottlingException", "Rate exceeded"), "throttled"),
    (ce("InvalidAccessException", "Account 1 is not subscribed to AWS Security Hub"), "not-enabled"),
    (ce("UnauthorizedOperation", "You are not authorized to perform this operation."), "denied"),
    (ce("InternalServerErrorException", "boom"), "error"),
    (EndpointConnectionError(endpoint_url="https://x"), "not-available"),
])
def test_classify(exc, status):
    assert classify(exc)[0] == status


def test_month_window():
    p = month_window(date(2026, 10, 1))
    assert (p.start, p.end, p.complete, p.elapsed_days) == (date(2026, 9, 1), date(2026, 10, 1), True, 30)
    p = month_window(date(2026, 9, 30))
    assert (p.start, p.end, p.complete, p.elapsed_days, p.days_in_month) == (date(2026, 9, 1), date(2026, 9, 30), False, 29, 30)


# ── de-duplication keys ──────────────────────────────────────────────────────

@pytest.mark.parametrize("direct,generic", [
    (Resource("EC2", "us-east-1", "instance", "i-0abc"), Resource("AWS/ec2", "us-east-1", "ec2:instance", "x", arn="arn:aws:ec2:us-east-1:1:instance/i-0abc")),
    (Resource("NAT Gateway", "us-east-1", "nat-gateway", "nat-0abc"), Resource("AWS/ec2", "us-east-1", "t", "x", arn="arn:aws:ec2:us-east-1:1:natgateway/nat-0abc")),
    (Resource("Elastic IP", "us-east-1", "elastic-ip", "eipalloc-1"), Resource("AWS/ec2", "us-east-1", "t", "x", arn="arn:aws:ec2:us-east-1:1:elastic-ip/eipalloc-1")),
    (Resource("S3", "eu-west-1", "bucket", "b", arn="arn:aws:s3:::b"), Resource("AWS/s3", "global", "s3:bucket", "x", arn="arn:aws:s3:::b")),
    (Resource("SQS", "us-east-1", "queue", "https://q/1/jobs", arn="arn:aws:sqs:us-east-1:1:jobs"), Resource("AWS/sqs", "us-east-1", "sqs:queue", "x", arn="arn:aws:sqs:us-east-1:1:jobs")),
    (Resource("RDS", "us-east-1", "db-instance", "db1", arn="arn:aws:rds:us-east-1:1:db:db1"), Resource("AWS/rds", "us-east-1", "rds:db", "x", arn="arn:aws:rds:us-east-1:1:db:db1")),
])
def test_canonical_key(direct, generic):
    assert Scanner.canonical_key(direct) == Scanner.canonical_key(generic)


# ── pricing ──────────────────────────────────────────────────────────────────

def product(price, **attrs):
    return {"a": attrs, "d": [(price, "Hrs")]}


class FakePrices(PriceResolver):
    def __init__(self, catalog):
        super().__init__(pool=None, cache_path=None)
        self.catalog = catalog

    def products(self, service_code, filters, max_pages=10):
        return [p for p in self.catalog.get(service_code, []) if all(p["a"].get(k, v) == v for k, v in filters.items())]


def test_pricing_selection():
    pr = FakePrices({
        "AmazonEC2": [product(0.0, regionCode="us-east-1", instanceType="t3.micro", operatingSystem="Linux"),
                      product(0.0104, regionCode="us-east-1", instanceType="t3.micro", operatingSystem="Linux"),
                      product(0.0196, regionCode="us-east-1", instanceType="t3.micro", operatingSystem="Windows"),
                      product(0.0116, location="EU (Ireland)", instanceType="t3.micro", operatingSystem="Linux")],
        "AmazonRDS": [product(0.032, regionCode="us-east-1", instanceType="db.t4g.small", databaseEngine="PostgreSQL", deploymentOption="Single-AZ"),
                      product(0.064, regionCode="us-east-1", instanceType="db.t4g.small", databaseEngine="PostgreSQL", deploymentOption="Multi-AZ")],
        "AmazonECS": [product(0.03238, regionCode="us-east-1", usagetype="USE1-Fargate-ARM-vCPU-Hours:perCPU"),
                      product(0.04048, regionCode="us-east-1", usagetype="USE1-Fargate-vCPU-Hours:perCPU"),
                      product(0.00356, regionCode="us-east-1", usagetype="USE1-Fargate-ARM-GB-Hours"),
                      product(0.004445, regionCode="us-east-1", usagetype="USE1-Fargate-GB-Hours"),
                      product(0.0127, regionCode="us-east-1", usagetype="USE1-SpotUsage:Fargate-vCPU-Hours:perCPU")],
    })
    assert pr.ec2_hourly("us-east-1", "t3.micro") == 0.0104             # $0 dimension ignored
    assert pr.ec2_hourly("us-east-1", "t3.micro", "Windows") == 0.0196  # real OS, not always Linux
    assert pr.ec2_hourly("eu-west-1", "t3.micro") == 0.0116             # falls back to location name
    assert pr.rds_hourly("us-east-1", "postgres", "db.t4g.small", multi_az=True) == 0.064
    assert pr.rds_hourly("us-east-1", "postgres", "db.t4g.small", multi_az=False) == 0.032
    assert pr.fargate_rates("us-east-1", "ARM64")[:2] == (0.03238, 0.00356)
    assert pr.fargate_rates("us-east-1", "X86_64")[:2] == (0.04048, 0.004445)
    v, g, note = pr.fargate_rates("eu-west-1", "ARM64")
    assert (v, g) == (RATES["fargate_vcpu_h"]["ARM64"], RATES["fargate_gb_h"]["ARM64"]) and "us-east-1" in note


def test_fargate_estimate_matches_hand_calc():
    from deadweight.collectors.compute import _fargate_estimate

    class C:
        region = "us-east-1"
        prices = FakePrices({})
    r = Resource("ECS", "us-east-1", "service", "s", "s")
    _fargate_estimate(C(), r, "1024", "2048", "ARM64", "LINUX", 2, 0.0)
    expected = 2 * (1 * RATES["fargate_vcpu_h"]["ARM64"] + 2 * RATES["fargate_gb_h"]["ARM64"]) * 730
    assert abs(r.monthly_estimate - expected) < 1e-6
    _fargate_estimate(C(), r, "1024", "2048", "ARM64", "LINUX", 2, 1.0)
    assert abs(r.monthly_estimate - expected * 0.3) < 1e-6


# ── reconciliation ───────────────────────────────────────────────────────────

def test_reconcile_statuses():
    costs = [CostRow("EC2 - Other", 100, 103.4, bill_service="EC2 - Other"), CostRow("Tax", 10, 10.3, bill_service="Tax"),
             CostRow("AWS WAF", 5, 5.2, bill_service="AWS WAF"), CostRow("Amazon Kendra", 40, 41, bill_service="Amazon Kendra")]
    breakdown = [{"service": "EC2 - Other", "dimension": "USAGE_TYPE", "value": "NatGateway-Hours", "actual_mtd": 95},
                 {"service": "EC2 - Other", "dimension": "USAGE_TYPE", "value": "EBS:VolumeUsage.gp3", "actual_mtd": 5}]
    res = [Resource("NAT Gateway", "us-east-1", "nat-gateway", "n1", monthly_estimate=98.0, bill_service="EC2 - Other", usage_family="NAT Gateway"),
           Resource("EBS", "us-east-1", "volume", "v1", monthly_estimate=5.0, bill_service="EC2 - Other", usage_family="EBS volumes")]
    rows = {r["bill"]: r for r in billing.reconcile(costs, breakdown, res, {"EC2 - Other", "AWS WAF"})}
    assert rows["EC2 - Other"]["status"] == "reconciled"
    assert {c["label"]: c["status"] for c in rows["EC2 - Other"]["children"]} == {"NAT Gateway": "reconciled", "EBS volumes": "reconciled"}
    assert rows["Tax"]["status"] == "tax"
    assert rows["AWS WAF"]["status"] == "nothing found"
    assert rows["Amazon Kendra"]["status"] == "no collector"


# ── CUR ──────────────────────────────────────────────────────────────────────

def _parquet(path: Path, rows):
    import duckdb
    con = duckdb.connect()
    con.execute("CREATE TABLE t (line_item_resource_id VARCHAR, line_item_unblended_cost DOUBLE)")
    con.executemany("INSERT INTO t VALUES (?, ?)", rows)
    con.execute(f"COPY t TO '{path.as_posix()}' (FORMAT PARQUET)")


def test_cur_aggregate_and_match(tmp_path):
    f = tmp_path / "part-0.parquet"
    _parquet(f, [("i-0abc", 5.0), ("i-0abc", 1.5), ("arn:aws:ec2:us-east-1:1:natgateway/nat-9", 31.0), ("my-bucket", 0.4),
                 ("arn:aws:lambda:us-east-1:1:function:unknown", 0.1), ("", 3.0)])
    costs = cur.aggregate([f])
    assert costs["i-0abc"] == 6.5 and "" not in costs
    rs = [Resource("EC2", "us-east-1", "instance", "i-0abc", arn="arn:aws:ec2:us-east-1:1:instance/i-0abc"),
          Resource("NAT Gateway", "us-east-1", "nat-gateway", "nat-9", arn="arn:aws:ec2:us-east-1:1:natgateway/nat-9"),
          Resource("S3", "us-east-1", "bucket", "my-bucket", arn="arn:aws:s3:::my-bucket")]
    n, matched, total = cur.match(rs, costs)
    assert n == 3 and abs(matched - 37.9) < 1e-9 and abs(total - 38.0) < 1e-9
    assert rs[0].actual_mtd == 6.5 and rs[1].actual_mtd == 31.0


def test_cur_attach_from_s3(tmp_path, monkeypatch):
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="billing-exports")
        f = tmp_path / "x.parquet"
        _parquet(f, [("i-1", 2.0)])
        start = date.today().replace(day=1) if date.today().day > 1 else month_window(date.today()).start
        key = f"cur/my-export/data/BILLING_PERIOD={start:%Y-%m}/my-export-00001.snappy.parquet"
        s3.put_object(Bucket="billing-exports", Key=key, Body=f.read_bytes())
        monkeypatch.setattr(cur, "CACHE", tmp_path / "cache")
        monkeypatch.setattr(cur, "discover", lambda pool: [cur.ExportLocation("my-export", "billing-exports", "cur", "us-east-1", "cur2")])
        sc = Scanner(ScanOptions(regions=["us-east-1"], services=set(), price_cache=False, costs=False, recommendations=False))
        sc.resources.append(Resource("EC2", "us-east-1", "instance", "i-1"))
        res = ScanResult(period=month_window(date.today()))
        cur.attach(sc, res)
        assert sc.resources[0].actual_mtd == 2.0
        assert res.meta["cur"]["matched_resources"] == 1


# ── engine behaviour ─────────────────────────────────────────────────────────

def test_cancel_and_timeout():
    with mock_aws():
        fixture.populate()
        sc = Scanner(ScanOptions(regions=fixture.REGIONS, price_cache=False, workers=2, costs=False, recommendations=False, cur="off"))
        t = threading.Thread(target=sc.run)
        t.start()
        time.sleep(0.3)
        sc.cancel()
        t.join(60)
        assert not t.is_alive()
        assert sc.result.meta["cancelled"] is True
        assert any(c["status"] == "skipped" for c in sc.coverage)

        sc = Scanner(ScanOptions(regions=["us-east-1"], services={"EC2", "EBS"}, price_cache=False, task_timeout=1e-9,
                                 costs=False, recommendations=False, cur="off"))
        res = sc.run()
        assert {c["status"] for c in res.coverage if c["source"] in ("EC2", "EBS")} == {"timeout"}


def test_active_region_mode(monkeypatch):
    with mock_aws():
        from deadweight.costs import CostExplorer
        monkeypatch.setattr(CostExplorer, "active_regions", lambda self: ["eu-west-1"])
        sc = Scanner(ScanOptions(region_mode="active", services={"VPC"}, price_cache=False, costs=False, recommendations=False, cur="off"))
        res = sc.run()
        assert sc.regions == ["eu-west-1", "us-east-1"]
        assert any(c["status"] == "skipped" and c["source"] == "Region targeting" for c in res.coverage)


def test_org_mode_scans_member_accounts():
    with mock_aws():
        org = boto3.client("organizations", region_name="us-east-1")
        org.create_organization(FeatureSet="ALL")
        member = org.create_account(AccountName="dev", Email="dev@example.com")["CreateAccountStatus"]["AccountId"]
        creds = boto3.client("sts").assume_role(RoleArn=f"arn:aws:iam::{member}:role/OrganizationAccountAccessRole",
                                                 RoleSessionName="setup")["Credentials"]
        msess = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                              aws_session_token=creds["SessionToken"], region_name="us-east-1")
        msess.client("sqs").create_queue(QueueName="member-queue")
        boto3.client("sqs", region_name="us-east-1").create_queue(QueueName="payer-queue")
        res = Scanner(ScanOptions(org=True, regions=["us-east-1"], services={"SQS"}, price_cache=False, costs=False,
                                  recommendations=False, cur="off")).run()
        accts = {r.name: r.account_id for r in res.resources}
        assert accts["member-queue"] == member and accts["payer-queue"] != member
        assert len(res.meta["accounts"]) == 2


# ── findings & reports ───────────────────────────────────────────────────────

def _nat(nid, src, dst, routed=True, enis=3, conns=1.0):
    return Resource("NAT Gateway", "us-east-1", "nat-gateway", nid, state="available", monthly_estimate=32.85,
                    details={"routed": routed, "enis_behind": enis, "hourly": 0.045,
                             "metrics": {"nat_BytesInFromSource_30d": src, "nat_BytesInFromDestination_30d": dst,
                                         "nat_BytesOutToDestination_30d": src, "nat_ActiveConnectionCount_30d": conns}},
                    relations={"vpc": ["vpc-1"]})


class _S:
    opts = ScanOptions(recommendations=False)
    regions: list = []

    def coverage_event(self, *a, **k):
        pass


def test_rules_on_synthetic_resources():
    nat = _nat("nat-1", 1e6, 2e6)
    nat2 = _nat("nat-2", 5e10, 5e10)
    rds = Resource("RDS", "us-east-1", "db-instance", "orders-staging", "orders-staging", "available", monthly_estimate=50,
                   details={"multi_az": True, "metrics": {"connections_max_14d": 0}})
    eks = Resource("EKS", "us-east-1", "cluster", "k", details={"version_status": "EXTENDED_SUPPORT", "version": "1.27"})
    res = ScanResult(identity={"Arn": "arn:aws:iam::1:root"}, resources=[nat, nat2, rds, eks])
    usage.classify(res)
    findings.run(_S(), res)
    rules = {f.rule for f in res.findings}
    assert {"nat-low-use", "nat-consolidate", "rds-idle", "rds-multiaz-nonprod", "eks-extended-support", "scan-as-root"} <= rules
    assert "nat-low-use" in nat.details["findings"] and not any(r.startswith("nat-") and r != "nat-consolidate"
                                                                 for r in nat2.details.get("findings", []))


# ── usage classification (missing data, NAT, ECS, IPs, state store) ─────────────

def test_missing_means_zero_vs_unknown():
    from datetime import datetime, timedelta, timezone
    from deadweight.collectors.base import MetricRequest
    from deadweight.scanner import apply_metric, daily_window
    start, end, dates = daily_window(5, now=datetime(2026, 9, 30, 15, tzinfo=timezone.utc))
    assert dates[0] == "2026-09-25" and dates[-1] == "2026-09-29" and end.hour == 0
    alb = Resource("ELB", "us-east-1", "application-load-balancer", "lb")
    rds = Resource("RDS", "us-east-1", "db-instance", "db")
    apply_metric(MetricRequest("us-east-1", alb, "lb_requests_14d", "AWS/ApplicationELB", "RequestCount", {}, missing="zero"), [], dates)
    apply_metric(MetricRequest("us-east-1", rds, "connections_max_14d", "AWS/RDS", "DatabaseConnections", {}, stat="Maximum"), [], dates)
    assert alb.details["metrics"]["lb_requests_14d"] == 0.0 and alb.details["series"]["lb_requests_14d"][0] == ["2026-09-25", 0.0]
    assert rds.details["metrics"]["connections_max_14d"] is None and rds.details["series"]["connections_max_14d"][0][1] is None
    pts = [(start + timedelta(days=1), 3.0), (start + timedelta(days=3), 7.0)]
    apply_metric(MetricRequest("us-east-1", rds, "cpu", "AWS/RDS", "CPUUtilization", {}, stat="Maximum"), pts, dates)
    assert rds.details["metrics"]["cpu"] == 7.0 and rds.details["metric_points"]["cpu"] == 2


def test_nat_classification_states():
    orphan = _nat("nat-o", None, None, routed=False)
    idle = _nat("nat-i", 0.0, 0.0, conns=0.0)
    low = _nat("nat-l", 0.2 * 1024 ** 3, 0.1 * 1024 ** 3)
    busy = _nat("nat-b", 600 * 1024 ** 3, 500 * 1024 ** 3)
    nobody = _nat("nat-n", None, None, enis=0)
    eip = Resource("Elastic IP", "us-east-1", "elastic-ip", "eipalloc-1", state="associated", monthly_estimate=3.65,
                   details={"associated": True})
    low.relations["elastic-ip"] = ["eipalloc-1"]
    res = ScanResult(resources=[orphan, idle, low, busy, nobody, eip])
    usage.classify(res)
    assert [orphan.usage_state, idle.usage_state, low.usage_state, busy.usage_state, nobody.usage_state] == \
        ["orphaned", "idle", "low-use", "active", "idle"]
    assert "shared" in low.usage_overlays and low.details["effective_per_gb"] > 5
    assert eip.usage_state == "low-use" and "NAT gateway" in eip.usage_evidence[0]
    findings.run(_S(), res)
    f = next(f for f in res.findings if f.rule == "nat-low-use")
    assert abs(f.monthly_savings - (32.85 + 3.65)) < 0.01


def test_nat_routing_from_route_tables():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.9.0.0/16")["Vpc"]["VpcId"]
        pub = ec2.create_subnet(VpcId=vpc, CidrBlock="10.9.0.0/24")["Subnet"]["SubnetId"]
        priv = ec2.create_subnet(VpcId=vpc, CidrBlock="10.9.1.0/24")["Subnet"]["SubnetId"]
        routed = ec2.create_nat_gateway(SubnetId=pub, AllocationId=ec2.allocate_address(Domain="vpc")["AllocationId"])["NatGateway"]
        spare = ec2.create_nat_gateway(SubnetId=pub, AllocationId=ec2.allocate_address(Domain="vpc")["AllocationId"])["NatGateway"]
        rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
        ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=routed["NatGatewayId"])
        ec2.associate_route_table(RouteTableId=rt, SubnetId=priv)
        ec2.create_network_interface(SubnetId=priv)
        sc = Scanner(ScanOptions(regions=["us-east-1"], services={"NAT Gateway"}, price_cache=False, usage_store=False,
                                 costs=False, recommendations=False, cur="off", metrics=False))
        res = sc.run()
    by = {r.resource_id: r for r in res.resources}
    assert by[routed["NatGatewayId"]].details["routed"] is True and by[routed["NatGatewayId"]].details["enis_behind"] >= 1
    assert by[spare["NatGatewayId"]].details["routed"] is False
    assert by[spare["NatGatewayId"]].usage_state == "orphaned"


def test_ecs_idle_and_active():
    def svc(name, metrics):
        return Resource("ECS", "us-east-1", "service", name, name, "active", monthly_estimate=40.0,
                        details={"launch_type": "FARGATE", "running": 1, "desired": 1, "metrics": metrics})
    quiet = svc("quiet", {"ecs_cpu_max_14d": 0.4, "ecs_mem_max_14d": 0.6})
    no_requests = svc("noreq", {"ecs_cpu_max_14d": 12.0, "ecs_mem_max_14d": 30.0, "tg_requests_14d:targetgroup/a/1": 0.0})
    busy = svc("busy", {"ecs_cpu_max_14d": 40.0, "ecs_mem_max_14d": 60.0, "tg_requests_14d:targetgroup/b/2": 5000.0})
    empty = Resource("ECS", "us-east-1", "service", "empty", details={"running": 0, "desired": 0})
    res = ScanResult(resources=[quiet, no_requests, busy, empty])
    usage.classify(res)
    assert [quiet.usage_state, no_requests.usage_state, busy.usage_state, empty.usage_state] == ["idle", "idle", "active", "clutter"]
    findings.run(_S(), res)
    assert {f.resource_name for f in res.findings if f.rule == "ecs-idle"} == {"quiet", "noreq"}


def test_public_ips_inherit_owner_and_eip_on_stopped_instance():
    lb = Resource("ELB", "us-east-1", "application-load-balancer", "web-alb", details={"targets": 0})
    inst = Resource("EC2", "us-east-1", "instance", "i-0aaa", state="stopped", details={"state_reason": "User initiated (2026-07-01 10:00:00 GMT)"})
    ip_lb = Resource("Public IPv4", "us-east-1", "public-ipv4", "3.3.3.3", details={"owner": {"kind": "elb", "id": "web-alb"}})
    ip_task = Resource("Public IPv4", "us-east-1", "public-ipv4", "4.4.4.4", details={"owner": {"kind": "ecs-task", "id": "x"}})
    eip = Resource("Elastic IP", "us-east-1", "elastic-ip", "eipalloc-9", state="associated", monthly_estimate=3.65,
                   details={"associated": True}, relations={"instance": ["i-0aaa"]})
    res = ScanResult(resources=[lb, inst, ip_lb, ip_task, eip])
    usage.classify(res)
    assert lb.usage_state == "orphaned" and ip_lb.usage_state == "orphaned" and "load balancer" in ip_lb.usage_evidence[0]
    assert ip_task.usage_state == "active" and ip_task.usage_confidence == "low"
    assert inst.usage_state == "stopped-billed" and eip.usage_state == "stopped-billed"
    findings.run(_S(), res)
    assert "eip-stopped-instance" in {f.rule for f in res.findings}


def test_usage_store_promotes_after_seven_days(tmp_path):
    from datetime import datetime, timedelta, timezone
    store_file = tmp_path / "state.json"
    t0 = datetime(2026, 9, 1, tzinfo=timezone.utc)

    def scan(now):
        r = Resource("EBS", "us-east-1", "volume", "vol-1", state="available", monthly_estimate=8.0, account_id="1")
        res = ScanResult(resources=[r])
        usage.classify(res, usage.UsageStore(store_file), now=now)
        return r
    assert "confirmed" not in scan(t0).usage_overlays
    assert "confirmed" not in scan(t0 + timedelta(days=3)).usage_overlays
    later = scan(t0 + timedelta(days=8))
    assert "confirmed" in later.usage_overlays and later.usage_state == "orphaned"
    # A resource that becomes active again starts over.
    r = Resource("EBS", "us-east-1", "volume", "vol-1", state="in-use", details={"root": True}, account_id="1")
    usage.classify(ScanResult(resources=[r]), usage.UsageStore(store_file), now=t0 + timedelta(days=9))
    assert "vol-1" not in json.loads(store_file.read_text())["1"]


def test_usage_summary_and_excluded_overlay():
    keep = Resource("EBS", "us-east-1", "volume", "vol-k", state="available", monthly_estimate=10.0, tags={"do-not-delete": "true"})
    gone = Resource("EBS", "us-east-1", "volume", "vol-g", state="available", monthly_estimate=5.0)
    res = ScanResult(resources=[keep, gone])
    usage.classify(res)
    assert "excluded" in keep.usage_overlays
    assert res.meta["usage_summary"]["orphaned"] == {"count": 2, "monthly_cost": 15.0}


# ── AWS idle verdicts ─────────────────────────────────────────────────────────

class _FakeCO:
    def __init__(self, error=None, items=None):
        self.error, self.items = error, items or []

    def get_idle_recommendations(self, **kw):
        if self.error:
            raise ClientError({"Error": {"Code": self.error, "Message": "not opted in"}}, "GetIdleRecommendations")
        return {"idleRecommendations": self.items}


class _Pool:
    def __init__(self, clients):
        self.clients = clients

    def get(self, service, region=None):
        return self.clients[service]


def test_compute_optimizer_idle_ingestion_and_opt_in():
    events = []

    class S(_S):
        opts = ScanOptions(recommendations=True)
        regions = ["us-east-1"]

        def coverage_event(self, source, region, status, detail="", action=""):
            events.append((source, status))
    arn = "arn:aws:ecs:us-east-1:1:service/c/web"
    svc = Resource("ECS", "us-east-1", "service", arn, "web", arn=arn, monthly_estimate=40.0,
                   details={"running": 1, "desired": 1, "metrics": {"ecs_cpu_max_14d": 30.0, "ecs_mem_max_14d": 20.0}})
    res = ScanResult(resources=[svc])
    usage.classify(res)
    s = S()
    s.pool = _Pool({"compute-optimizer": _FakeCO(items=[{
        "resourceArn": arn, "resourceId": "web", "resourceType": "ECSService", "finding": "Idle", "lookBackPeriodInDays": 14,
        "savingsOpportunity": {"estimatedMonthlySavings": {"currency": "USD", "value": 39.5}}}])})
    recs, status = findings.compute_optimizer_idle(s, s.regions)
    assert status == "ok" and recs[0].rule == "co-idle-ecsservice" and recs[0].source == "compute-optimizer" and recs[0].monthly_savings == 39.5
    assert usage.mark_aws_agrees(res, {recs[0].resource_key}) == 1 and "aws-agrees" in svc.usage_overlays
    s.pool = _Pool({"compute-optimizer": _FakeCO(error="OptInRequiredException")})
    assert findings.compute_optimizer_idle(s, s.regions) == ([], "not-enabled")


class _Fake:
    """A client whose operations return canned pages (or raise); paginators yield one page."""
    def __init__(self, **ops):
        self.ops = ops

    def can_paginate(self, op):
        return True

    def get_paginator(self, op):
        fn = self.__getattr__(op)
        return type("Pg", (), {"paginate": lambda _self, **kw: [fn(**kw)]})()

    def __getattr__(self, op):
        if op not in self.ops:
            raise AttributeError(op)
        val = self.ops[op]

        def call(**kw):
            if isinstance(val, Exception):
                raise val
            return val(**kw) if callable(val) else val
        return call


def test_aws_sources_probe_states_and_dedupe():
    events = {}

    class S(_S):
        opts = ScanOptions(recommendations=True)
        regions = ["us-east-1"]

        def coverage_event(self, source, region, status, detail="", action=""):
            events[source] = status
    eip = Resource("Elastic IP", "us-east-1", "elastic-ip", "eipalloc-1", state="associated", monthly_estimate=3.65,
                   details={"associated": True})
    vol = "arn:aws:ec2:us-east-1:1:volume/vol-9"
    s = S()
    s.pool = _Pool({
        "compute-optimizer": _FakeCO(items=[{"resourceArn": vol, "resourceId": "vol-9", "resourceType": "EBSVolume",
                                             "finding": "Unattached", "savingsOpportunity": {"estimatedMonthlySavings": {"value": 8}}}]),
        "cost-optimization-hub": _Fake(list_recommendations={"items": [
            {"actionType": "Delete", "resourceArn": vol, "resourceId": "vol-9", "estimatedMonthlySavings": 8},
            {"actionType": "PurchaseSavingsPlans", "resourceId": "sp", "estimatedMonthlySavings": 120}]}),
        "trustedadvisor": _Fake(list_recommendations=ClientError(
            {"Error": {"Code": "SubscriptionRequiredException", "Message": "Business support required"}}, "ListRecommendations")),
        "config": _Fake(describe_config_rules={"ConfigRules": [
            {"ConfigRuleName": "eip-attached", "Source": {"Owner": "AWS", "SourceIdentifier": "EIP_ATTACHED"}}]},
            get_compliance_details_by_config_rule={"EvaluationResults": [
                {"EvaluationResultIdentifier": {"EvaluationResultQualifier": {"ResourceId": "eipalloc-1"}}}]}),
    })
    res = ScanResult(resources=[eip])
    findings.run(s, res)
    rules = [f.rule for f in res.findings]
    assert rules.count("co-idle-ebsvolume") == 1 and "coh-delete" not in rules          # same verdict, kept once
    assert next(f for f in res.findings if f.rule == "coh-purchasesavingsplans").category == "commitment"
    assert events["Trusted Advisor"] == "not-available" and events["Compute Optimizer idle"] == "ok"
    assert "config-eip-attached" in rules and "aws-agrees" in eip.usage_overlays


def test_cost_optimization_hub_action_mapping():
    assert findings.coh_category("Delete") == "waste" and findings.coh_category("Stop") == "waste"
    assert findings.coh_category("ScaleIn") == "waste" and findings.coh_category("Rightsize") == "rightsizing"
    assert findings.coh_category("PurchaseSavingsPlans") == "commitment" and findings.coh_category("PurchaseReservedInstances") == "commitment"
    assert findings.coh_category("MigrateToGraviton") == "rightsizing"


# ── CUR existence/activity pivot ────────────────────────────────────────────────

def test_cur_existence_activity_pivot(tmp_path):
    import duckdb
    f = tmp_path / "cur.parquet"
    con = duckdb.connect()
    con.execute("CREATE TABLE t (line_item_resource_id VARCHAR, line_item_usage_type VARCHAR, line_item_line_item_type VARCHAR, "
                "line_item_unblended_cost DOUBLE)")
    nat = "arn:aws:ec2:us-east-1:1:natgateway/nat-9"
    con.executemany("INSERT INTO t VALUES (?, ?, ?, ?)", [
        (nat, "USE1-NatGateway-Hours", "Usage", 31.0), (nat, "USE1-NatGateway-Bytes", "Usage", 0.05),
        ("i-1", "USE1-BoxUsage:t3.micro", "Usage", 7.0), ("i-1", "USE1-DataTransfer-Out-Bytes", "Usage", 0.4),
        ("", "USE1-DataTransfer-Regional-Bytes", "Usage", 2.0), ("", "Tax", "Tax", 9.0), ("i-1", "USE1-BoxUsage:t3.micro", "Credit", -7.0)])
    con.execute(f"COPY t TO '{f.as_posix()}' (FORMAT PARQUET)")
    per, unattributed = cur.pivot([f])
    assert per[nat]["existence"] == 31.0 and per[nat]["activity"] == 0.05 and per[nat]["by_usage_type"]["NatGateway-Hours"] == 31.0
    assert per["i-1"]["total"] == 7.4 and unattributed == 2.0          # tax and credits are not usage
    r = Resource("NAT Gateway", "us-east-1", "nat-gateway", "nat-9", arn=nat)
    cur.match([r], per)
    assert r.actual_mtd == 31.05 and r.details["cur"]["existence"] == 31.0 and r.details["cur"]["activity"] == 0.05
    assert cur.charge_kind("USE1-TimedStorage-ByteHrs") == "existence" and cur.charge_kind("EU-Requests-Tier1") == "activity"


# ── Cloud Control: global types once, covered types skipped, ARNs, defaults ─────

class _FakeCC:
    def __init__(self, data):
        self.data, self.calls = data, []

    def can_paginate(self, op):
        return False

    def list_resources(self, TypeName):
        self.calls.append(TypeName)
        return {"ResourceDescriptions": [{"Identifier": i, "Properties": json.dumps(p)} for i, p in self.data.get(TypeName, [])]}


def test_cloud_control_global_dedupe_and_defaults():
    from deadweight.collectors import discovery
    from deadweight.collectors.base import Ctx, REGISTRY
    with mock_aws():
        sc = Scanner(ScanOptions(regions=["us-east-1", "eu-west-1"], services={"Cloud Control", "EC2", "Universal Discovery"},
                                 price_cache=False, usage_store=False, costs=False, recommendations=False, cur="off"))
    data = {
        "AWS::IAM::Role": [("app-role", {})],
        "AWS::EC2::Instance": [("i-0123456789abcdef0", {})],
        "AWS::EC2::SecurityGroup": [("sg-0123456789abcdef0", {"GroupName": "web"}), ("sg-0fedcba9876543210", {"GroupName": "default"})],
        "AWS::RDS::DBParameterGroup": [("default.postgres16", {}), ("custom-pg", {})],
        "AWS::KMS::Alias": [("alias/aws/ebs", {}), ("alias/app", {})],
    }
    fakes = {r: _FakeCC(data) for r in sc.regions}
    sc.pool = _Pool({})
    sc.scopes[0].pool = type("P", (), {"get": lambda self, s, region=None: fakes[region]})()
    # A Resource Explorer hit for the same security group must merge with the Cloud Control result.
    sc.add(Resource("AWS/ec2", "us-east-1", "ec2:security-group", "x", arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-0123456789abcdef0"),
           "Resource Explorer")
    types = list(data)
    for region in sc.regions:
        discovery._cloud_control(Ctx(sc, REGISTRY["Cloud Control"], region), types)
    assert "AWS::EC2::Instance" not in fakes["us-east-1"].calls                    # left to the EC2 collector
    assert "AWS::IAM::Role" in fakes["us-east-1"].calls and "AWS::IAM::Role" not in fakes["eu-west-1"].calls
    roles = [r for r in sc.resources if r.resource_type == "AWS::IAM::Role"]
    assert len(roles) == 1 and roles[0].region == "global" and roles[0].arn == "arn:aws:iam::123456789012:role/app-role"
    sgs = [r for r in sc.resources if "security-group" in (r.arn or "")]
    assert len([r for r in sgs if r.region == "us-east-1"]) == 1 and "Cloud Control" in sgs[0].discovery_sources
    names = {r.resource_id for r in sc.resources}
    assert not any("default.postgres16" in n or "alias/aws/" in n for n in names)
    assert any("custom-pg" in n for n in names) and any("alias/app" in n for n in names)
    assert not any(n.endswith("sg-0fedcba9876543210") for n in names)


# ── HTML report ──────────────────────────────────────────────────────────────

def test_html_report_layouts_escape_and_consistent_totals():
    from deadweight import html_report
    vpc = Resource("VPC", "us-east-1", "vpc", "vpc-1", name="main", config="10.0.0.0/16")
    nat = Resource("NAT Gateway", "us-east-1", "nat-gateway", "nat-1", name="<script>alert(1)</script>", state="available",
                   monthly_estimate=32.85, bill_service="EC2 - Other", usage_state="idle", usage_evidence=["0 bytes in 30 days"])
    nat.relate("vpc", "vpc-1")
    vol = Resource("EBS", "us-east-1", "volume", "vol-1", monthly_estimate=500.0, bill_service="EC2 - Other", usage_state="orphaned")
    busy = Resource("RDS", "us-east-1", "db-instance", "db-1", monthly_estimate=60.0,
                    bill_service="Amazon Relational Database Service", usage_state="active")
    ips = [Resource("Elastic IP", "us-east-1", "elastic-ip", f"eip-{i}", monthly_estimate=3.65, bill_service="Amazon Virtual Private Cloud",
                    usage_state="orphaned") for i in range(3)]
    costs = [CostRow("EC2 - Other", 90.0, 100.0, bill_service="EC2 - Other"),
             CostRow("RDS", 54.0, 60.0, bill_service="Amazon Relational Database Service"),
             CostRow("VPC", 9.0, 10.0, bill_service="Amazon Virtual Private Cloud"), CostRow("Tax", 4.5, 5.0, bill_service="Tax")]
    res = ScanResult(identity={"Account": "123456789012"}, period=month_window(date.today()), costs=costs,
                     resources=[vpc, nat, vol, busy, *ips],
                     findings=[Finding("eip-idle", "Elastic IP that nothing uses", "low", "waste", f"eip-{i}", f"eip-{i}", "Elastic IP",
                                       "us-east-1", 3.65) for i in range(3)])
    res.reconciliation = billing.reconcile(res.costs, [], res.resources, set())
    d = html_report.shape(res)
    # list-price estimates are capped at their bill line, so the grid, the flow and the KPI agree
    assert d["waste"] == pytest.approx(100.0 + 10.0, abs=0.01)
    assert d["quad"]["billed-idle"][1] == pytest.approx(d["waste"], abs=0.01)
    assert d["quad"]["billed-working"][0] == 1
    for style in html_report.STYLES:
        page = report.html(res, style)
        assert "<script>alert(1)</script>" not in page
        assert ("&lt;script&gt;" in page) == (style != "brief")      # the brief page has no network diagram
        assert 'class="sankey"' in page and "Billed versus working" in page
    full = report.html(res)
    # headline + one grouped row + one data-table row per finding
    assert "across 3 resources" in full and full.count("Elastic IP that nothing uses") == 1 + 1 + 3
    assert 'class="topo"' in full and "Network plumbing" in full
