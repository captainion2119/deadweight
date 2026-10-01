"""End-to-end scan of a mocked AWS account (moto): inventory, de-duplication, export round trip and diff."""
import sys
import warnings
from collections import Counter
from pathlib import Path

import pytest

warnings.filterwarnings("ignore")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).parent))
import fixture  # noqa: E402  (sets fake credentials before boto3 is used)
from moto import mock_aws  # noqa: E402

from deadweight import report  # noqa: E402
from deadweight.scanner import Scanner, ScanOptions  # noqa: E402

# Every service the fixture creates resources for; a collector that stops finding its resources fails here.
EXPECTED = {"EC2", "EBS", "Elastic IP", "NAT Gateway", "ELB", "RDS", "ECS", "Lambda", "S3", "DynamoDB", "Route53", "ECR",
            "Secrets Manager", "SQS", "SNS", "KMS", "VPC"}


@pytest.fixture(scope="module")
def scan():
    with mock_aws():
        fixture.populate()
        yield Scanner(ScanOptions(regions=fixture.REGIONS, price_cache=False, usage_store=False, workers=16)).run()


def test_scan_finds_every_fixture_service_once(scan):
    found = Counter(r.service for r in scan.resources)
    assert not EXPECTED - set(found), f"no resources found for {sorted(EXPECTED - set(found))}"
    dupes = [k for k, n in Counter(Scanner.canonical_key(r) for r in scan.resources).items() if n > 1]
    assert not dupes
    assert scan.findings and scan.meta.get("usage_summary")


def test_report_roundtrip_and_diff(scan, tmp_path):
    files = report.export(scan, tmp_path)
    names = {p.name.split("-2")[0] for p in files}
    assert {"aws-report", "aws-resources", "aws-costs", "aws-findings", "aws-reconciliation"} <= names
    saved = next(p for p in files if p.suffix == ".json")
    again = report.load(saved)
    assert len(again.resources) == len(scan.resources) and again.period.start == scan.period.start
    assert Counter(r.usage_state for r in again.resources) == Counter(r.usage_state for r in scan.resources)

    older = report.load(saved)
    dropped = [r for r in older.resources if r.service == "EBS"]
    older.resources = [r for r in older.resources if r.service != "EBS"]
    d = report.diff(older, again)
    assert d["a"]["resources"] == len(older.resources) and d["b"]["resources"] == len(again.resources)
    assert len(d["added"]) == len(dropped) and not d["removed"]

    assert "<html" in next(p for p in files if p.suffix == ".html").read_text(encoding="utf-8")
    assert "ec2:DescribeInstances" in report.policy()["Statement"][0]["Action"]
