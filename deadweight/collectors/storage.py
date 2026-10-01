"""Storage: S3, EBS volumes, EBS snapshots, AMIs, EFS, FSx, ECR, AWS Backup."""
from __future__ import annotations

from botocore.exceptions import ClientError

from ..models import Resource, name_from_tags, tags_to_dict
from ..pricing import RATES, io2_iops_month, region_note
from .base import Ctx, add_estimate, collector

GIB = 1024 ** 3
EC2_OTHER = "EC2 - Other"
ROOT_DEVICES = {"/dev/xvda", "/dev/sda1", "/dev/sda", "/dev/nvme0n1"}


def _err_code(e: Exception) -> str:
    return e.response.get("Error", {}).get("Code", "") if isinstance(e, ClientError) else ""


@collector("S3", "storage", scope="global", bill="Amazon Simple Storage Service", client="s3",
           actions=("s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetLifecycleConfiguration",
                    "s3:GetBucketVersioning", "cloudwatch:GetMetricData"),
           desc="Buckets with size per storage class (CloudWatch), lifecycle and versioning")
def s3(ctx: Ctx) -> None:
    c = ctx.client("s3", "us-east-1")
    buckets = list(ctx.pages(c, "list_buckets", "Buckets"))

    def details(b: dict) -> tuple:
        name = b["Name"]
        try:
            loc = c.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            loc = "eu-west-1" if loc == "EU" else loc
        except Exception:
            loc = b.get("BucketRegion") or "unknown"
        cli = ctx.client("s3", loc if loc != "unknown" else "us-east-1")
        lifecycle = versioning = None
        try:
            lifecycle = bool(cli.get_bucket_lifecycle_configuration(Bucket=name).get("Rules"))
        except Exception as e:
            lifecycle = False if _err_code(e) == "NoSuchLifecycleConfiguration" else None
        try:
            versioning = cli.get_bucket_versioning(Bucket=name).get("Status") or "Off"
        except Exception:
            versioning = None
        return b, loc, lifecycle, versioning

    for b, loc, lifecycle, versioning in ctx.map(details, buckets, workers=16):
        name = b["Name"]
        r = Resource("S3", loc, "bucket", name, name, "active", f"arn:{ctx.partition}:s3:::{name}",
                     f"versioning {versioning or '?'} · lifecycle {'yes' if lifecycle else 'none' if lifecycle is False else '?'}",
                     estimate_note="Storage class, bytes, requests and transfer required; use actual cost",
                     created=str(b.get("CreationDate", "")))
        r.details.update(lifecycle=lifecycle, versioning=versioning, size_bytes=0.0)
        if loc != "unknown":
            for storage_type, rate in RATES["s3_gb"].items():
                def on_size(res: Resource, value: float | None, st=storage_type, rate=rate) -> None:
                    if not value:
                        return
                    res.details["size_bytes"] = res.details.get("size_bytes", 0.0) + value
                    res.details.setdefault("size_by_class", {})[st] = value
                    gb = value / GIB
                    add_estimate(res, gb * rate, f"{st.replace('Storage', '')} {gb:,.1f} GB × ${rate}/GB-mo")
                ctx.metric(r, f"bytes:{storage_type}", "AWS/S3", "BucketSizeBytes",
                           {"BucketName": name, "StorageType": storage_type}, stat="Average", days=3, region=loc,
                           on_value=on_size)
            ctx.metric(r, "objects", "AWS/S3", "NumberOfObjects", {"BucketName": name, "StorageType": "AllStorageTypes"},
                       stat="Average", days=3, region=loc)
        ctx.add(r)


def _ebs_estimate(ctx: Ctx, r: Resource, vtype: str, size: int, iops: int | None, tput: int | None) -> None:
    rate, note = ctx.prices.ebs_gb_month(ctx.region, vtype)
    if rate is None:
        r.estimate_note = "Storage price not mapped"
        return
    r.monthly_estimate = size * rate
    parts = [f"{size} GiB {vtype} × ${rate}/GB-mo{note}"]
    rn = region_note(ctx.region)
    if vtype == "gp3":
        extra_iops, extra_tput = max(0, (iops or 3000) - 3000), max(0, (tput or 125) - 125)
        if extra_iops:
            r.monthly_estimate += extra_iops * RATES["ebs_gp3_iops"]
            parts.append(f"+{extra_iops} IOPS × ${RATES['ebs_gp3_iops']}{rn}")
        if extra_tput:
            r.monthly_estimate += extra_tput * RATES["ebs_gp3_tput"]
            parts.append(f"+{extra_tput} MB/s × ${RATES['ebs_gp3_tput']}{rn}")
    elif vtype == "io1" and iops:
        r.monthly_estimate += iops * RATES["ebs_io1_iops"]
        parts.append(f"{iops} IOPS × ${RATES['ebs_io1_iops']}{rn}")
    elif vtype == "io2" and iops:
        r.monthly_estimate += io2_iops_month(iops)
        parts.append(f"{iops} IOPS (tiered){rn}")
    r.estimate_note = "; ".join(parts) + "; snapshots excluded"


@collector("EBS", "storage", bill=EC2_OTHER, usage="EBS volumes", client="ec2",
           actions=("ec2:DescribeVolumes", "pricing:GetProducts"),
           desc="Volumes incl. provisioned IOPS/throughput; attachment state")
def ebs(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    for x in ctx.pages(c, "describe_volumes", "Volumes"):
        tags = tags_to_dict(x.get("Tags"))
        vtype, size, vid = x["VolumeType"], int(x["Size"]), x["VolumeId"]
        attached = [a.get("InstanceId") for a in x.get("Attachments", []) if a.get("InstanceId")]
        r = Resource("EBS", ctx.region, "volume", vid, name_from_tags(tags), x["State"], ctx.arn("ec2", f"volume/{vid}"),
                     f"{size} GiB {vtype} | IOPS {x.get('Iops', '-')}" + (f" | {x.get('Throughput')} MB/s" if x.get("Throughput") else ""),
                     tags, created=str(x.get("CreateTime", "")))
        devices = [a.get("Device", "") for a in x.get("Attachments", [])]
        r.details.update(size_gb=size, volume_type=vtype, iops=x.get("Iops"), throughput=x.get("Throughput"),
                         encrypted=x.get("Encrypted"), attached=bool(attached), devices=devices,
                         root=any(d in ROOT_DEVICES for d in devices))
        r.relate("instance", *attached)
        _ebs_estimate(ctx, r, vtype, size, x.get("Iops"), x.get("Throughput"))
        if attached:    # EBS only reports while attached; an attached volume with no I/O may emit nothing
            for metric in ("VolumeReadOps", "VolumeWriteOps"):
                ctx.metric(r, f"ebs_{metric}_14d", "AWS/EBS", metric, {"VolumeId": vid}, missing="zero")
        ctx.add(r)


@collector("EBS Snapshots", "storage", bill=EC2_OTHER, usage="EBS snapshots", client="ec2",
           actions=("ec2:DescribeSnapshots",),
           desc="Snapshots you own (age, source volume, tier)")
def ebs_snapshots(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    for x in ctx.pages(c, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
        tags = tags_to_dict(x.get("Tags"))
        size = int(x.get("VolumeSize") or 0)
        tier = x.get("StorageTier", "standard")
        rate = RATES["ebs_snapshot_archive_gb"] if tier == "archive" else RATES["ebs_snapshot_gb"]
        sid = x["SnapshotId"]
        r = Resource("EBS Snapshots", ctx.region, "snapshot", sid, name_from_tags(tags, x.get("Description", "")[:60]),
                     str(x.get("State", "")), ctx.arn("ec2", f"snapshot/{sid}", account=""),
                     f"{size} GiB source volume · {tier}", tags, created=str(x.get("StartTime", "")),
                     estimate_note=f"Billed on changed blocks only (see EBS:SnapshotUsage); full-size upper bound ${size * rate:,.2f}/mo")
        r.details.update(size_gb=size, tier=tier, upper_bound=size * rate, description=x.get("Description", ""))
        r.relate("volume", x.get("VolumeId") if x.get("VolumeId") != "vol-ffffffff" else None)
        ctx.add(r)


@collector("AMIs", "storage", client="ec2", actions=("ec2:DescribeImages",),
           desc="Images you own (storage is billed through their snapshots)")
def amis(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    for x in ctx.pages(c, "describe_images", "Images", Owners=["self"]):
        tags = tags_to_dict(x.get("Tags"))
        snaps = [m.get("Ebs", {}).get("SnapshotId") for m in x.get("BlockDeviceMappings", [])]
        r = Resource("AMIs", ctx.region, "image", x["ImageId"], name_from_tags(tags, x.get("Name", "")), str(x.get("State", "")),
                     ctx.arn("ec2", f"image/{x['ImageId']}", account=""), f"{x.get('Architecture', '')} · {len([s for s in snaps if s])} snapshot(s)",
                     tags, created=str(x.get("CreationDate", "")), monthly_estimate=0.0, bill_service=EC2_OTHER,
                     usage_family="EBS snapshots", estimate_note="No AMI charge; its backing snapshots are billed (see EBS Snapshots)")
        r.relate("snapshot", *snaps)
        if x.get("LastLaunchedTime"):      # owner-only, up to 24 h delayed, tracked since 2017
            r.details["last_used"] = str(x["LastLaunchedTime"])
        ctx.add(r)


@collector("EFS", "storage", bill="Amazon Elastic File System", client="efs", actions=("elasticfilesystem:DescribeFileSystems",),
           desc="File systems by storage class; provisioned throughput")
def efs(ctx: Ctx) -> None:
    c = ctx.client("efs")
    for x in ctx.pages(c, "describe_file_systems", "FileSystems"):
        size = x.get("SizeInBytes") or {}
        std, ia, arch = (size.get("ValueInStandard") or size.get("Value") or 0), size.get("ValueInIA") or 0, size.get("ValueInArchive") or 0
        if size.get("ValueInStandard") is None:
            std = max(0, (size.get("Value") or 0) - ia - arch)
        one_zone = bool(x.get("AvailabilityZoneName"))
        tags = tags_to_dict(x.get("Tags"))
        r = Resource("EFS", ctx.region, "file-system", x["FileSystemId"], x.get("Name") or name_from_tags(tags),
                     str(x.get("LifeCycleState", "")), x.get("FileSystemArn", ""),
                     f"{(size.get('Value') or 0) / GIB:,.1f} GB · {x.get('ThroughputMode', '')}{' · One Zone' if one_zone else ''}",
                     tags, created=str(x.get("CreationTime", "")))
        rn = region_note(ctx.region)
        if one_zone:
            add_estimate(r, (std / GIB) * RATES["efs_onezone_gb"], f"One Zone {std / GIB:,.1f} GB × ${RATES['efs_onezone_gb']}{rn}")
        else:
            add_estimate(r, (std / GIB) * RATES["efs_gb"]["standard"], f"Standard {std / GIB:,.1f} GB × ${RATES['efs_gb']['standard']}{rn}")
        if ia:
            add_estimate(r, (ia / GIB) * RATES["efs_gb"]["ia"], f"IA {ia / GIB:,.1f} GB × ${RATES['efs_gb']['ia']}")
        if arch:
            add_estimate(r, (arch / GIB) * RATES["efs_gb"]["archive"], f"Archive {arch / GIB:,.1f} GB × ${RATES['efs_gb']['archive']}")
        if x.get("ThroughputMode") == "provisioned" and x.get("ProvisionedThroughputInMibps"):
            mibps = float(x["ProvisionedThroughputInMibps"])
            add_estimate(r, mibps * 6.0, f"provisioned throughput {mibps:g} MiB/s × $6{rn}")
        r.estimate_note += "; access charges excluded"
        r.details.update(size_bytes=float(size.get("Value") or 0))
        ctx.metric(r, "efs_connections_30d", "AWS/EFS", "ClientConnections", {"FileSystemId": x["FileSystemId"]}, days=30)
        ctx.metric(r, "efs_io_bytes_30d", "AWS/EFS", "TotalIOBytes", {"FileSystemId": x["FileSystemId"]}, days=30)
        ctx.add(r)


@collector("FSx", "storage", bill="Amazon FSx", client="fsx", actions=("fsx:DescribeFileSystems",),
           desc="File systems (Windows, Lustre, ONTAP, OpenZFS)")
def fsx(ctx: Ctx) -> None:
    c = ctx.client("fsx")
    for x in ctx.pages(c, "describe_file_systems", "FileSystems"):
        tags = tags_to_dict(x.get("Tags"))
        ctx.add(Resource("FSx", ctx.region, "file-system", x["FileSystemId"], name_from_tags(tags), str(x.get("Lifecycle", "")).lower(),
                         x.get("ResourceARN", ""), f"{x.get('FileSystemType', '')} · {x.get('StorageCapacity', 0)} GB {x.get('StorageType', '')}",
                         tags, created=str(x.get("CreationTime", "")),
                         estimate_note="Capacity, throughput and backup pricing varies by FSx type; use actual cost"))


@collector("ECR", "storage", bill="Amazon EC2 Container Registry (ECR)", client="ecr",
           actions=("ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:GetLifecyclePolicy"),
           desc="Repositories with image storage, untagged images and lifecycle policy")
def ecr(ctx: Ctx) -> None:
    c = ctx.client("ecr")
    repos = list(ctx.pages(c, "describe_repositories", "repositories"))

    def details(x: dict) -> tuple:
        name = x["repositoryName"]
        images = ctx.step(f"ECR images {name}", lambda: list(ctx.pages(c, "describe_images", "imageDetails", repositoryName=name))) or []
        try:
            c.get_lifecycle_policy(repositoryName=name)
            lifecycle = True
        except Exception as e:
            lifecycle = False if _err_code(e) == "LifecyclePolicyNotFoundException" else None
        return x, images, lifecycle

    for x, images, lifecycle in ctx.map(details, repos):
        size = sum(float(i.get("imageSizeInBytes") or 0) for i in images)
        untagged = sum(1 for i in images if not i.get("imageTags"))
        gb = size / GIB
        r = Resource("ECR", ctx.region, "repository", x["repositoryName"], x["repositoryName"], "active", x["repositoryArn"],
                     f"{len(images)} images · {gb:,.2f} GB · {untagged} untagged · lifecycle {'yes' if lifecycle else 'none'}",
                     created=str(x.get("createdAt", "")), monthly_estimate=gb * RATES["ecr_gb"],
                     estimate_note=f"{gb:,.2f} GB × ${RATES['ecr_gb']}/GB-mo upper bound (layers shared between images are counted per image); transfer excluded")
        r.details.update(images=len(images), untagged=untagged, size_bytes=size, lifecycle=lifecycle, uri=x.get("repositoryUri"))
        pulls = [i.get("lastRecordedPullTime") for i in images if i.get("lastRecordedPullTime")]
        pushes = [i.get("imagePushedAt") for i in images if i.get("imagePushedAt")]
        if pulls:
            r.details["last_used"] = str(max(pulls))      # refreshed by ECR roughly once a day
        if pushes:
            r.details["last_push"] = str(max(pushes))
        ctx.add(r)


@collector("Backup", "storage", bill="AWS Backup", client="backup",
           actions=("backup:ListBackupVaults", "backup:ListRecoveryPointsByBackupVault", "backup:ListBackupPlans"),
           desc="Vaults with recovery-point storage; backup plans")
def backup(ctx: Ctx) -> None:
    c = ctx.client("backup")
    for v in ctx.pages(c, "list_backup_vaults", "BackupVaultList"):
        points = ctx.step(f"Backup recovery points {v['BackupVaultName']}", lambda: list(
            ctx.pages(c, "list_recovery_points_by_backup_vault", "RecoveryPoints", BackupVaultName=v["BackupVaultName"]))) or []
        warm = sum(float(p.get("BackupSizeInBytes") or 0) for p in points if str(p.get("StorageClass", "WARM")) != "COLD")
        cold = sum(float(p.get("BackupSizeInBytes") or 0) for p in points if str(p.get("StorageClass")) == "COLD")
        r = Resource("Backup", ctx.region, "vault", v["BackupVaultArn"], v["BackupVaultName"], "active", v["BackupVaultArn"],
                     f"{len(points)} recovery points · {warm / GIB:,.1f} GB warm · {cold / GIB:,.1f} GB cold",
                     created=str(v.get("CreationDate", "")))
        add_estimate(r, warm / GIB * RATES["backup_warm_gb"], f"warm {warm / GIB:,.1f} GB × ~${RATES['backup_warm_gb']}/GB-mo (EBS/EFS rate; varies by resource type)")
        add_estimate(r, cold / GIB * 0.01, f"cold {cold / GIB:,.1f} GB × ~$0.01/GB-mo")
        r.details.update(recovery_points=len(points), warm_bytes=warm, cold_bytes=cold)
        ctx.add(r)
    for p in ctx.pages(c, "list_backup_plans", "BackupPlansList"):
        ctx.add(Resource("Backup", ctx.region, "plan", p["BackupPlanArn"], p.get("BackupPlanName", ""), "active", p["BackupPlanArn"],
                         monthly_estimate=0.0, estimate_note="Plans are free; the recovery points they create are billed"))
