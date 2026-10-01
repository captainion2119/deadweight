"""Databases: RDS/Aurora/DocumentDB/Neptune, DynamoDB, ElastiCache, MemoryDB, OpenSearch, Redshift."""
from __future__ import annotations

from ..models import HOURS_MONTH, Resource, tags_to_dict
from ..pricing import RATES, region_note
from .base import Ctx, add_estimate, collector, monthly

GIB = 1024 ** 3
RDS_BILL = "Amazon Relational Database Service"
ENGINE_BILL = {"docdb": "Amazon DocumentDB (with MongoDB compatibility)", "neptune": "Amazon Neptune"}
ENGINE_LABEL = {"docdb": "DocumentDB", "neptune": "Neptune"}


def _gp3_baseline(gb: int) -> tuple[int, int]:
    # RDS gp3 includes 3,000 IOPS / 125 MB/s below 400 GiB and 12,000 / 500 at or above (most engines).
    return (12000, 500) if gb >= 400 else (3000, 125)


@collector("RDS", "database", bill=RDS_BILL, client="rds",
           actions=("rds:DescribeDBInstances", "rds:DescribeDBClusters", "rds:DescribeDBSnapshots",
                    "rds:DescribeDBClusterSnapshots", "pricing:GetProducts", "cloudwatch:GetMetricData"),
           desc="Instances (Multi-AZ, storage, IOPS priced), Aurora/DocumentDB/Neptune clusters incl. Serverless v2, manual snapshots")
def rds(ctx: Ctx) -> None:
    c = ctx.client("rds")
    rn = region_note(ctx.region)
    for x in ctx.pages(c, "describe_db_instances", "DBInstances"):
        engine, cls = x["Engine"], x["DBInstanceClass"]
        maz = bool(x.get("MultiAZ"))
        stype, gb, iops = x.get("StorageType", "gp2"), int(x.get("AllocatedStorage") or 0), x.get("Iops")
        aurora = engine.startswith("aurora") or engine in ENGINE_BILL
        status = x.get("DBInstanceStatus", "")
        r = Resource(ENGINE_LABEL.get(engine, "RDS"), ctx.region, "db-instance", x["DBInstanceIdentifier"], x["DBInstanceIdentifier"],
                     status, x.get("DBInstanceArn", ""),
                     f"{engine} | {cls}" + ("" if aurora else f" | {gb} GiB {stype}") + (" | Multi-AZ" if maz else ""),
                     tags_to_dict(x.get("TagList")), bill_service=ENGINE_BILL.get(engine, RDS_BILL),
                     created=str(x.get("InstanceCreateTime", "")))
        r.details.update(engine=engine, instance_class=cls, multi_az=maz, storage_type=stype, allocated_gb=gb, iops=iops,
                         storage_throughput=x.get("StorageThroughput"))
        r.relate("vpc", (x.get("DBSubnetGroup") or {}).get("VpcId"))
        r.relate("security-group", *[g.get("VpcSecurityGroupId") for g in x.get("VpcSecurityGroups", [])])
        r.relate("cluster", x.get("DBClusterIdentifier"))
        if cls == "db.serverless":
            r.estimate_note = "Aurora Serverless v2: capacity (ACUs) is priced on the cluster"
        elif status == "stopped":
            r.monthly_estimate, r.estimate_note = 0.0, "Stopped: instance hours $0 (storage still billed); auto-starts after 7 days"
        else:
            p = ctx.prices.rds_hourly(ctx.region, engine, cls, maz, x.get("LicenseModel", ""))
            if p is not None:
                add_estimate(r, monthly(p), f"on-demand {'Multi-AZ' if maz and not aurora else 'Single-AZ'} instance ${p:.4f}/h")
            else:
                r.estimate_note = "Pricing lookup unavailable"
            ctx.metric(r, "connections_max_14d", "AWS/RDS", "DatabaseConnections", {"DBInstanceIdentifier": x["DBInstanceIdentifier"]}, stat="Maximum")
            ctx.metric(r, "cpu_max_14d", "AWS/RDS", "CPUUtilization", {"DBInstanceIdentifier": x["DBInstanceIdentifier"]}, stat="Maximum")
        if not aurora and gb and r.estimate_note != "Pricing lookup unavailable":
            rate, note = ctx.prices.rds_storage_gb_month(ctx.region, stype, maz)
            add_estimate(r, gb * rate, f"{gb} GiB {stype} storage × ${rate:.3f}/GB-mo{note}")
            mult = 2 if maz else 1
            if stype in ("io1", "io2") and iops:
                add_estimate(r, iops * RATES["rds_piops"] * mult, f"{iops} provisioned IOPS × ${RATES['rds_piops']}{rn}")
            elif stype == "gp3":
                base_iops, base_tput = _gp3_baseline(gb)
                extra_iops = max(0, int(iops or base_iops) - base_iops)
                extra_tput = max(0, int(x.get("StorageThroughput") or base_tput) - base_tput)
                if extra_iops:
                    add_estimate(r, extra_iops * 0.02 * mult, f"+{extra_iops} gp3 IOPS × $0.02{rn}")
                if extra_tput:
                    add_estimate(r, extra_tput * 0.08 * mult, f"+{extra_tput} MB/s × $0.08{rn}")
        if r.monthly_estimate is not None:
            r.estimate_note += "; backups beyond free allowance, I/O and data transfer excluded"
        ctx.add(r)

    ctx.step("RDS clusters", lambda: _clusters(ctx, c))
    ctx.step("RDS manual snapshots", lambda: _snapshots(ctx, c))


def _clusters(ctx: Ctx, c) -> None:
    for x in ctx.pages(c, "describe_db_clusters", "DBClusters"):
        engine = x.get("Engine", "")
        if not (engine.startswith("aurora") or engine in ENGINE_BILL):
            continue   # Multi-AZ DB clusters of plain engines: their instances are priced above
        cid = x["DBClusterIdentifier"]
        sv2 = x.get("ServerlessV2ScalingConfiguration") or {}
        io_opt = x.get("StorageType") == "aurora-iopt1"
        r = Resource(ENGINE_LABEL.get(engine, "RDS"), ctx.region, "db-cluster", cid, cid, x.get("Status", ""), x.get("DBClusterArn", ""),
                     f"{engine} {x.get('EngineVersion', '')} · {len(x.get('DBClusterMembers', []))} instance(s)"
                     + (f" · Serverless v2 {sv2.get('MinCapacity')}-{sv2.get('MaxCapacity')} ACU" if sv2 else "")
                     + (" · I/O-Optimized" if io_opt else ""),
                     tags_to_dict(x.get("TagList")), bill_service=ENGINE_BILL.get(engine, RDS_BILL),
                     created=str(x.get("ClusterCreateTime", "")))
        r.relate("instance", *[m.get("DBInstanceIdentifier") for m in x.get("DBClusterMembers", [])])
        has_sv2_members = any(m for m in x.get("DBClusterMembers", []))
        if sv2 and has_sv2_members and x.get("Status") != "stopped":
            acu = float(sv2.get("MinCapacity") or 0)
            if acu:
                add_estimate(r, acu * RATES["aurora_acu_h"] * HOURS_MONTH,
                             f"Serverless v2 at minimum {acu:g} ACU × ${RATES['aurora_acu_h']}/h{region_note(ctx.region)} (scales up to {sv2.get('MaxCapacity')} ACU)")
        if x.get("EngineMode") == "serverless":
            r.estimate_note = f"Aurora Serverless v1 at {x.get('Capacity', '?')} ACU now; billed per ACU-second"
        rate = 0.225 if io_opt else RATES["aurora_storage_gb"]

        def on_volume(res: Resource, value: float | None, rate=rate) -> None:
            if value:
                gb = value / GIB
                res.details["storage_gb"] = gb
                add_estimate(res, gb * rate, f"cluster storage {gb:,.1f} GB × ${rate}/GB-mo{region_note(res.region)}")
        ctx.metric(r, "volume_bytes", "AWS/RDS", "VolumeBytesUsed", {"DBClusterIdentifier": cid}, stat="Maximum", days=2, on_value=on_volume)
        ctx.add(r)


def _snapshots(ctx: Ctx, c) -> None:
    for x in ctx.pages(c, "describe_db_snapshots", "DBSnapshots", SnapshotType="manual"):
        gb = int(x.get("AllocatedStorage") or 0)
        r = Resource("RDS", ctx.region, "db-snapshot", x["DBSnapshotIdentifier"], x["DBSnapshotIdentifier"], x.get("Status", ""),
                     x.get("DBSnapshotArn", ""), f"{x.get('Engine', '')} · {gb} GiB", created=str(x.get("SnapshotCreateTime", "")),
                     estimate_note="Billed as backup storage only beyond the free allowance (100% of provisioned storage per region); see RDS:ChargedBackupUsage")
        r.details.update(size_gb=gb, upper_bound=gb * 0.095)
        r.relate("instance", x.get("DBInstanceIdentifier"))
        ctx.add(r)
    for x in ctx.pages(c, "describe_db_cluster_snapshots", "DBClusterSnapshots", SnapshotType="manual"):
        gb = int(x.get("AllocatedStorage") or 0)
        r = Resource("RDS", ctx.region, "db-cluster-snapshot", x["DBClusterSnapshotIdentifier"], x["DBClusterSnapshotIdentifier"],
                     x.get("Status", ""), x.get("DBClusterSnapshotArn", ""), f"{x.get('Engine', '')} · {gb} GiB",
                     created=str(x.get("SnapshotCreateTime", "")),
                     estimate_note="Billed as backup storage beyond the free allowance; see Aurora:BackupUsage")
        r.details.update(size_gb=gb, upper_bound=gb * 0.021)
        r.relate("cluster", x.get("DBClusterIdentifier"))
        ctx.add(r)


@collector("DynamoDB", "database", bill="Amazon DynamoDB", client="dynamodb",
           actions=("dynamodb:ListTables", "dynamodb:DescribeTable"),
           desc="Tables with provisioned capacity (incl. GSIs) and storage priced")
def dynamodb(ctx: Ctx) -> None:
    c = ctx.client("dynamodb")
    names = list(ctx.pages(c, "list_tables", "TableNames"))
    rn = region_note(ctx.region)
    for x in ctx.map(lambda n: ctx.call(c, "describe_table", TableName=n)["Table"], names):
        mode = (x.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED")
        ia = (x.get("TableClassSummary") or {}).get("TableClass") == "STANDARD_INFREQUENT_ACCESS"
        size_gb = float(x.get("TableSizeBytes") or 0) / GIB
        r = Resource("DynamoDB", ctx.region, "table", x["TableName"], x["TableName"], x.get("TableStatus", ""), x.get("TableArn", ""),
                     f"{mode}{' · Standard-IA' if ia else ''} · {size_gb:,.2f} GB · {x.get('ItemCount', 0):,} items",
                     created=str(x.get("CreationDateTime", "")))
        if mode == "PROVISIONED":
            pt = x.get("ProvisionedThroughput") or {}
            rcu, wcu = int(pt.get("ReadCapacityUnits") or 0), int(pt.get("WriteCapacityUnits") or 0)
            for g in x.get("GlobalSecondaryIndexes", []):
                gp = g.get("ProvisionedThroughput") or {}
                rcu += int(gp.get("ReadCapacityUnits") or 0)
                wcu += int(gp.get("WriteCapacityUnits") or 0)
            mult = 1.25 if ia else 1.0
            add_estimate(r, (rcu * RATES["dynamodb_rcu_h"] + wcu * RATES["dynamodb_wcu_h"]) * HOURS_MONTH * mult,
                         f"{rcu} RCU + {wcu} WCU provisioned (incl. GSIs){rn}")
            r.details.update(rcu=rcu, wcu=wcu)
        storage_rate = RATES["dynamodb_ia_gb"] if ia else RATES["dynamodb_gb"]
        add_estimate(r, size_gb * storage_rate, f"{size_gb:,.2f} GB × ${storage_rate}/GB-mo (first 25 GB/region free)")
        if mode != "PROVISIONED":
            r.estimate_note += "; on-demand reads/writes billed per request"
        r.details["billing_mode"] = mode
        # DynamoDB emits zeros, so an empty series means a wrong dimension (unknown), not idle.
        for metric in ("ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits"):
            ctx.metric(r, f"ddb_{metric}_14d", "AWS/DynamoDB", metric, {"TableName": x["TableName"]})
        ctx.add(r)


@collector("ElastiCache", "database", bill="Amazon ElastiCache", client="elasticache",
           actions=("elasticache:DescribeCacheClusters", "elasticache:DescribeServerlessCaches", "pricing:GetProducts"),
           desc="Node-based clusters priced per node; serverless caches")
def elasticache(ctx: Ctx) -> None:
    c = ctx.client("elasticache")
    for x in ctx.pages(c, "describe_cache_clusters", "CacheClusters", ShowCacheNodeInfo=True):
        node, n, engine = x.get("CacheNodeType", ""), int(x.get("NumCacheNodes") or 1), x.get("Engine", "")
        r = Resource("ElastiCache", ctx.region, "cluster", x["CacheClusterId"], x["CacheClusterId"], x.get("CacheClusterStatus", ""),
                     x.get("ARN", ""), f"{engine} | {node} x{n}", created=str(x.get("CacheClusterCreateTime", "")))
        r.relate("replication-group", x.get("ReplicationGroupId"))
        p = ctx.prices.instance_hourly("AmazonElastiCache", ctx.region, node, cacheEngine=engine.capitalize())
        if p is not None:
            r.monthly_estimate, r.estimate_note = p * n * HOURS_MONTH, f"{n} × {node} on-demand ${p:.4f}/h; backups/data transfer excluded"
        else:
            r.estimate_note = "Node pricing lookup unavailable; inspect actual cost"
        ctx.add(r)
    if hasattr(c, "describe_serverless_caches"):
        def serverless():
            for x in ctx.pages(c, "describe_serverless_caches", "ServerlessCaches"):
                ctx.add(Resource("ElastiCache", ctx.region, "serverless-cache", x.get("ARN", x["ServerlessCacheName"]),
                                 x["ServerlessCacheName"], str(x.get("Status", "")).lower(), x.get("ARN", ""), x.get("Engine", ""),
                                 estimate_note="Serverless: billed per GB-hour stored (with a minimum) and per ECPU"))
        ctx.step("ElastiCache serverless", serverless)


@collector("MemoryDB", "database", bill="Amazon MemoryDB", client="memorydb",
           actions=("memorydb:DescribeClusters", "pricing:GetProducts"), desc="Clusters priced per node")
def memorydb(ctx: Ctx) -> None:
    c = ctx.client("memorydb")
    for x in ctx.pages(c, "describe_clusters", "Clusters", ShowShardDetails=True):
        nodes = sum(int(s.get("NumberOfNodes") or 0) for s in x.get("Shards", [])) or int(x.get("NumberOfShards") or 1)
        node = x.get("NodeType", "")
        r = Resource("MemoryDB", ctx.region, "cluster", x.get("ARN", x["Name"]), x["Name"], str(x.get("Status", "")).lower(),
                     x.get("ARN", ""), f"{x.get('Engine', 'redis')} · {node} × {nodes} nodes")
        p = ctx.prices.instance_hourly("AmazonMemoryDB", ctx.region, node)
        if p is not None:
            r.monthly_estimate, r.estimate_note = p * nodes * HOURS_MONTH, f"{nodes} × {node} ${p:.4f}/h; data written and snapshots excluded"
        else:
            r.estimate_note = "Node pricing lookup unavailable"
        ctx.add(r)


@collector("OpenSearch", "database", bill="Amazon OpenSearch Service", client="opensearch",
           actions=("es:ListDomainNames", "es:DescribeDomains", "pricing:GetProducts"),
           desc="Domains: data, master and warm nodes plus EBS storage priced")
def opensearch(ctx: Ctx) -> None:
    c = ctx.client("opensearch")
    names = [n["DomainName"] for n in ctx.call(c, "list_domain_names").get("DomainNames", [])]
    for i in range(0, len(names), 5):
        for x in ctx.call(c, "describe_domains", DomainNames=names[i:i + 5]).get("DomainStatusList", []):
            cfg = x.get("ClusterConfig") or {}
            r = Resource("OpenSearch", ctx.region, "domain", x["DomainName"], x["DomainName"],
                         "processing" if x.get("Processing") else "active", x.get("ARN", ""),
                         f"{cfg.get('InstanceType', '')} x{cfg.get('InstanceCount', 0)}"
                         + (f" + {cfg.get('DedicatedMasterCount')} masters" if cfg.get("DedicatedMasterEnabled") else ""))
            groups = [(cfg.get("InstanceType"), int(cfg.get("InstanceCount") or 0), "data")]
            if cfg.get("DedicatedMasterEnabled"):
                groups.append((cfg.get("DedicatedMasterType"), int(cfg.get("DedicatedMasterCount") or 0), "master"))
            if cfg.get("WarmEnabled"):
                groups.append((cfg.get("WarmType"), int(cfg.get("WarmCount") or 0), "warm"))
            unknown = False
            for itype, count, role in groups:
                if not itype or not count:
                    continue
                p = ctx.prices.instance_hourly("AmazonES", ctx.region, itype)
                if p is None:
                    unknown = True
                    continue
                add_estimate(r, p * count * HOURS_MONTH, f"{count} × {itype} {role} ${p:.4f}/h")
            ebs = x.get("EBSOptions") or {}
            if ebs.get("EBSEnabled") and ebs.get("VolumeSize"):
                total = int(ebs["VolumeSize"]) * int(cfg.get("InstanceCount") or 1)
                add_estimate(r, total * RATES["opensearch_gp3_gb"], f"{total} GB EBS × ${RATES['opensearch_gp3_gb']}{region_note(ctx.region)}")
            if unknown:   # a storage-only figure would understate the domain: show n/a, keep the partial in the note
                partial = r.monthly_estimate or 0.0
                r.details["partial_estimate"] = partial
                r.monthly_estimate = None
                r.estimate_note = f"Node pricing lookup unavailable (priced parts alone ≈ ${partial:,.2f}/mo)"
            ctx.add(r)


@collector("OpenSearch Serverless", "database", bill="Amazon OpenSearch Service", client="opensearchserverless",
           actions=("aoss:ListCollections",), desc="Collections (account-level OCU minimum)")
def opensearch_serverless(ctx: Ctx) -> None:
    c = ctx.client("opensearchserverless")
    for x in ctx.pages(c, "list_collections", "collectionSummaries"):
        ctx.add(Resource("OpenSearch Serverless", ctx.region, "collection", x.get("arn", x["id"]), x.get("name", ""),
                         str(x.get("status", "")).lower(), x.get("arn", ""),
                         estimate_note=f"Billed per OCU-hour (${RATES['aoss_ocu_h']}); an account keeps a minimum of ~1–2 OCUs "
                                       "(~$175–$350/mo) per KMS key while any collection exists"))


@collector("Redshift", "database", bill="Amazon Redshift", client="redshift",
           actions=("redshift:DescribeClusters", "redshift-serverless:ListWorkgroups", "pricing:GetProducts"),
           desc="Provisioned clusters priced per node; serverless workgroups")
def redshift(ctx: Ctx) -> None:
    c = ctx.client("redshift")
    for x in ctx.pages(c, "describe_clusters", "Clusters"):
        node, n = x.get("NodeType", ""), int(x.get("NumberOfNodes") or 1)
        status = x.get("ClusterStatus", "")
        r = Resource("Redshift", ctx.region, "cluster", x["ClusterIdentifier"], x["ClusterIdentifier"], status,
                     ctx.arn("redshift", f"cluster:{x['ClusterIdentifier']}"), f"{node} × {n}", tags_to_dict(x.get("Tags")),
                     created=str(x.get("ClusterCreateTime", "")))
        if status == "paused":
            r.monthly_estimate, r.estimate_note = 0.0, "Paused: compute $0; managed storage still billed"
        else:
            p = ctx.prices.instance_hourly("AmazonRedshift", ctx.region, node)
            if p is not None:
                r.monthly_estimate, r.estimate_note = p * n * HOURS_MONTH, f"{n} × {node} ${p:.4f}/h; RA3 managed storage and Spectrum excluded"
            else:
                r.estimate_note = "Node pricing lookup unavailable"
        ctx.add(r)

    def serverless():
        rs = ctx.client("redshift-serverless")
        for w in ctx.pages(rs, "list_workgroups", "workgroups"):
            ctx.add(Resource("Redshift", ctx.region, "serverless-workgroup", w.get("workgroupArn", w["workgroupName"]), w["workgroupName"],
                             str(w.get("status", "")).lower(), w.get("workgroupArn", ""), f"base {w.get('baseCapacity', '?')} RPU",
                             estimate_note="Serverless: billed per RPU-hour only while queries run"))
    ctx.step("Redshift Serverless", serverless)
