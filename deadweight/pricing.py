"""List-price lookups: AWS Pricing API first, published us-east-1 rates as a fallback.

Every estimate produced from these numbers carries a note saying which rate was used, so a
fallback rate applied to another region is visible rather than silently wrong."""
from __future__ import annotations

import json
import math
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

REGION_LOCATION = {
    "us-east-1": "US East (N. Virginia)", "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)", "us-west-2": "US West (Oregon)",
    "ap-south-1": "Asia Pacific (Mumbai)", "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-southeast-1": "Asia Pacific (Singapore)", "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)", "ap-southeast-4": "Asia Pacific (Melbourne)",
    "ap-southeast-5": "Asia Pacific (Malaysia)", "ap-southeast-7": "Asia Pacific (Thailand)",
    "ap-northeast-1": "Asia Pacific (Tokyo)", "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)", "ap-east-1": "Asia Pacific (Hong Kong)",
    "ca-central-1": "Canada (Central)", "ca-west-1": "Canada West (Calgary)",
    "eu-central-1": "EU (Frankfurt)", "eu-central-2": "EU (Zurich)",
    "eu-west-1": "EU (Ireland)", "eu-west-2": "EU (London)", "eu-west-3": "EU (Paris)",
    "eu-north-1": "EU (Stockholm)", "eu-south-1": "EU (Milan)", "eu-south-2": "EU (Spain)",
    "me-south-1": "Middle East (Bahrain)", "me-central-1": "Middle East (UAE)", "il-central-1": "Israel (Tel Aviv)",
    "af-south-1": "Africa (Cape Town)", "sa-east-1": "South America (Sao Paulo)", "mx-central-1": "Mexico (Central)",
}

# Published us-east-1 on-demand list rates, used when the Pricing API has no answer.
RATES: dict[str, Any] = {
    "ebs_gb": {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015, "standard": 0.05},
    "ebs_gp3_iops": 0.005, "ebs_gp3_tput": 0.04, "ebs_io1_iops": 0.065,
    "ebs_io2_iops": [(32000, 0.065), (64000, 0.0455), (math.inf, 0.032)],
    "ebs_snapshot_gb": 0.05, "ebs_snapshot_archive_gb": 0.0125,
    "public_ipv4_h": 0.005, "nat_h": 0.045, "nat_gb": 0.045,
    "alb_h": 0.0225, "nlb_h": 0.0225, "gwlb_h": 0.0125, "clb_h": 0.025, "alb_lcu_h": 0.008, "nlb_lcu_h": 0.006,
    "eks_h": 0.10, "eks_extended_h": 0.60,
    "fargate_vcpu_h": {"X86_64": 0.04048, "ARM64": 0.03238}, "fargate_gb_h": {"X86_64": 0.004445, "ARM64": 0.00356},
    "rds_storage_gb": {"gp2": 0.115, "gp3": 0.115, "io1": 0.125, "io2": 0.125, "standard": 0.10}, "rds_piops": 0.10,
    "aurora_storage_gb": 0.10, "aurora_acu_h": 0.12,
    "s3_gb": {"StandardStorage": 0.023, "IntelligentTieringFAStorage": 0.023, "IntelligentTieringIAStorage": 0.0125,
              "IntelligentTieringAIAStorage": 0.004, "IntelligentTieringAAStorage": 0.0036,
              "IntelligentTieringDAAStorage": 0.00099, "StandardIAStorage": 0.0125, "OneZoneIAStorage": 0.01,
              "ReducedRedundancyStorage": 0.024, "GlacierInstantRetrievalStorage": 0.004, "GlacierStorage": 0.0036,
              "DeepArchiveStorage": 0.00099},
    "ecr_gb": 0.10, "logs_gb": 0.03,
    "dynamodb_rcu_h": 0.00013, "dynamodb_wcu_h": 0.00065, "dynamodb_gb": 0.25, "dynamodb_ia_gb": 0.10,
    "efs_gb": {"standard": 0.30, "ia": 0.016, "archive": 0.008}, "efs_onezone_gb": 0.16,
    "secret_month": 0.40, "kms_key_month": 1.0, "route53_zone_month": 0.50,
    "route53_hc_month": 0.50, "route53_hc_ext_month": 0.75,
    "vpce_interface_h": 0.01, "tgw_attach_h": 0.05, "vpn_h": 0.05, "clientvpn_assoc_h": 0.10, "ga_h": 0.025,
    "cw_alarm_std": 0.10, "cw_alarm_hr": 0.30, "cw_alarm_composite": 0.50, "cw_dashboard": 3.00,
    "waf_acl_month": 5.0, "waf_rule_month": 1.0, "pca_month": 400.0, "pca_short_lived_month": 50.0,
    "transfer_protocol_h": 0.30, "kinesis_shard_h": 0.015, "kinesis_ondemand_stream_h": 0.04,
    "lambda_pc_gb_s": 0.0000041667, "backup_warm_gb": 0.05, "kendra_dev_h": 1.125, "kendra_ent_h": 1.40,
    "aoss_ocu_h": 0.24, "msk_storage_gb": 0.10, "opensearch_gp3_gb": 0.122,
}

EC2_PLATFORM = {
    "Linux/UNIX": ("Linux", "NA"), "Windows": ("Windows", "NA"), "Red Hat Enterprise Linux": ("RHEL", "NA"),
    "Red Hat Enterprise Linux with HA": ("Red Hat Enterprise Linux with HA", "NA"), "SUSE Linux": ("SUSE", "NA"),
    "Ubuntu Pro": ("Ubuntu Pro", "NA"),
    "Windows with SQL Server Standard": ("Windows", "SQL Std"), "Windows with SQL Server Web": ("Windows", "SQL Web"),
    "Windows with SQL Server Enterprise": ("Windows", "SQL Ent"), "Linux with SQL Server Standard": ("Linux", "SQL Std"),
    "Linux with SQL Server Web": ("Linux", "SQL Web"), "Linux with SQL Server Enterprise": ("Linux", "SQL Ent"),
}
RDS_ENGINE = {
    "postgres": "PostgreSQL", "mysql": "MySQL", "mariadb": "MariaDB", "aurora-postgresql": "Aurora PostgreSQL",
    "aurora-mysql": "Aurora MySQL", "aurora": "Aurora MySQL", "oracle-ee": "Oracle", "oracle-se2": "Oracle",
    "oracle-ee-cdb": "Oracle", "oracle-se2-cdb": "Oracle", "sqlserver-ee": "SQL Server", "sqlserver-se": "SQL Server",
    "sqlserver-ex": "SQL Server", "sqlserver-web": "SQL Server", "db2-se": "Db2", "db2-ae": "Db2",
}
RDS_EDITION = {"oracle-ee": "Enterprise", "oracle-ee-cdb": "Enterprise", "oracle-se2": "Standard Two",
               "oracle-se2-cdb": "Standard Two", "sqlserver-ee": "Enterprise", "sqlserver-se": "Standard",
               "sqlserver-ex": "Express", "sqlserver-web": "Web"}
RDS_LICENSE = {"license-included": "License included", "bring-your-own-license": "Bring your own license"}
RDS_VOLUME = {"gp2": "General Purpose", "gp3": "General Purpose-GP3", "io1": "Provisioned IOPS",
              "io2": "Provisioned IOPS-IO2", "standard": "Magnetic"}

DEFAULT_CACHE = Path.home() / ".cache" / "deadweight" / "pricing.json"


def region_note(region: str) -> str:
    return "" if region in ("us-east-1", "global") else " (us-east-1 list rate)"


def io2_iops_month(iops: int) -> float:
    cost, prev = 0.0, 0
    for upto, rate in RATES["ebs_io2_iops"]:
        n = max(0, min(iops, upto) - prev)
        cost += n * rate
        prev = upto
        if iops <= upto:
            break
    return cost


class PriceResolver:
    """Thread-safe, cached Pricing API client. API calls are serialised (the Pricing API
    throttles hard); cache hits are lock-free."""

    def __init__(self, pool, cache_path: Path | None = DEFAULT_CACHE, ttl_days: float = 7.0):
        self.pool = pool
        self.cache_path = cache_path
        self.ttl = ttl_days * 86400
        self._mem: dict[str, list[dict]] = {}
        self._lock = threading.Lock()
        self.requests = 0
        self._dirty = False
        self._disk: dict[str, Any] = {}
        if cache_path and cache_path.exists():
            try:
                self._disk = json.loads(cache_path.read_text(encoding="utf-8"))
            except Exception:
                self._disk = {}

    # raw product access ----------------------------------------------------------
    def products(self, service_code: str, filters: dict[str, str], max_pages: int = 10) -> list[dict]:
        key = json.dumps([service_code, sorted(filters.items())])
        if key in self._mem:
            return self._mem[key]
        hit = self._disk.get(key)
        if hit and time.time() - hit.get("t", 0) < self.ttl:
            self._mem[key] = hit["p"]
            return hit["p"]
        with self._lock:
            if key in self._mem:
                return self._mem[key]
            out: list[dict] = []
            try:
                client = self.pool.get("pricing", "us-east-1")
                token = None
                for _ in range(max_pages):
                    kw = {"ServiceCode": service_code, "MaxResults": 100,
                          "Filters": [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in filters.items()]}
                    if token:
                        kw["NextToken"] = token
                    resp = client.get_products(**kw)
                    self.requests += 1
                    for raw in resp.get("PriceList", []):
                        out.append(_parse_product(raw))
                    token = resp.get("NextToken")
                    if not token:
                        break
            except Exception:
                out = []
            self._mem[key] = out
            self._disk[key] = {"t": time.time(), "p": out}
            self._dirty = True
            return out

    def ondemand(self, service_code: str, filters: dict[str, str], *, unit: str | None = None,
                 predicate: Callable[[dict], bool] | None = None) -> float | None:
        prices = [usd for p in self.products(service_code, filters) if predicate is None or predicate(p["a"])
                  for usd, u in p["d"] if usd > 0 and (unit is None or u == unit)]
        return min(prices) if prices else None

    def regional(self, service_code: str, region: str, filters: dict[str, str], **kw) -> float | None:
        value = self.ondemand(service_code, {"regionCode": region, **filters}, **kw)
        if value is None and region in REGION_LOCATION:
            value = self.ondemand(service_code, {"location": REGION_LOCATION[region], **filters}, **kw)
        return value

    def flush(self) -> None:
        if not (self._dirty and self.cache_path):
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._disk), encoding="utf-8")
            self._dirty = False
        except Exception:
            pass

    # service helpers ---------------------------------------------------------------
    def ec2_hourly(self, region: str, instance_type: str, platform: str = "Linux/UNIX", tenancy: str = "Shared") -> float | None:
        os_name, sw = EC2_PLATFORM.get(platform or "Linux/UNIX", ("Linux", "NA"))
        return self.regional("AmazonEC2", region, {
            "instanceType": instance_type, "operatingSystem": os_name, "tenancy": tenancy,
            "preInstalledSw": sw, "capacitystatus": "Used", "licenseModel": "No License required"})

    def rds_hourly(self, region: str, engine: str, instance_class: str, multi_az: bool = False,
                   license_model: str = "") -> float | None:
        if engine == "docdb":
            return self.regional("AmazonDocDB", region, {"instanceType": instance_class})
        if engine == "neptune":
            return self.regional("AmazonNeptune", region, {"instanceType": instance_class})
        db = RDS_ENGINE.get(engine)
        if not db:
            return None
        aurora = engine.startswith("aurora")
        f = {"instanceType": instance_class, "databaseEngine": db,
             "deploymentOption": "Single-AZ" if (aurora or not multi_az) else "Multi-AZ"}
        if engine in RDS_EDITION:
            f["databaseEdition"] = RDS_EDITION[engine]
        if license_model in RDS_LICENSE:
            f["licenseModel"] = RDS_LICENSE[license_model]
        return self.regional("AmazonRDS", region, f)

    def rds_storage_gb_month(self, region: str, storage_type: str, multi_az: bool) -> tuple[float, str]:
        vt = RDS_VOLUME.get(storage_type)
        v = self.regional("AmazonRDS", region, {"productFamily": "Database Storage", "volumeType": vt,
                                                 "deploymentOption": "Multi-AZ" if multi_az else "Single-AZ"}) if vt else None
        if v is not None:
            return v, ""
        return RATES["rds_storage_gb"].get(storage_type, 0.115) * (2 if multi_az else 1), region_note(region)

    def ebs_gb_month(self, region: str, volume_type: str) -> tuple[float | None, str]:
        v = self.regional("AmazonEC2", region, {"productFamily": "Storage", "volumeApiName": volume_type})
        if v is not None:
            return v, ""
        fb = RATES["ebs_gb"].get(volume_type)
        return fb, region_note(region) if fb is not None else ""

    def fargate_rates(self, region: str, arch: str = "X86_64") -> tuple[float, float, str]:
        arm = arch.upper() in ("ARM64", "ARM")
        tag = "ARM-" if arm else ""
        vcpu = gb = None
        for p in self.products("AmazonECS", {"regionCode": region}):
            ut = p["a"].get("usagetype", "")
            if "Windows" in ut or "Spot" in ut:
                continue
            for usd, _ in p["d"]:
                if usd <= 0:
                    continue
                if re.search(rf"Fargate-{tag}vCPU-Hours:perCPU$", ut) and (arm or "ARM" not in ut):
                    vcpu = usd if vcpu is None else min(vcpu, usd)
                elif re.search(rf"Fargate-{tag}GB-Hours$", ut) and (arm or "ARM" not in ut):
                    gb = usd if gb is None else min(gb, usd)
        key = "ARM64" if arm else "X86_64"
        if vcpu is not None and gb is not None:
            return vcpu, gb, ""
        return RATES["fargate_vcpu_h"][key], RATES["fargate_gb_h"][key], region_note(region)

    def instance_hourly(self, service_code: str, region: str, instance_type: str, **attrs: str) -> float | None:
        return self.regional(service_code, region, {"instanceType": instance_type, **attrs})


def _parse_product(raw: str | dict) -> dict:
    prod = json.loads(raw) if isinstance(raw, str) else raw
    dims = []
    for term in prod.get("terms", {}).get("OnDemand", {}).values():
        for dim in term.get("priceDimensions", {}).values():
            usd = dim.get("pricePerUnit", {}).get("USD")
            if usd is not None:
                try:
                    dims.append((float(usd), dim.get("unit", "")))
                except ValueError:
                    pass
    return {"a": prod.get("product", {}).get("attributes", {}), "d": dims}
