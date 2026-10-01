"""Compute: EC2, Lambda, ECS/Fargate, EKS, App Runner, Lightsail, Batch, EMR, Elastic Beanstalk."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..models import HOURS_MONTH, Resource, name_from_tags, tags_to_dict
from ..pricing import RATES, region_note
from .base import Ctx, add_estimate, collector

EC2_BILL = "Amazon Elastic Compute Cloud - Compute"
SPOT_PRODUCT = {"Linux/UNIX": "Linux/UNIX", "Windows": "Windows", "Red Hat Enterprise Linux": "Red Hat Enterprise Linux",
                "SUSE Linux": "SUSE Linux"}


def _chunks(items: list, n: int):
    for i in range(0, len(items), n):
        yield items[i:i + n]


@collector("EC2", "compute", bill=EC2_BILL, client="ec2",
           actions=("ec2:DescribeInstances", "ec2:DescribeSpotPriceHistory", "pricing:GetProducts"),
           desc="Instances, priced by real OS/tenancy; Spot priced from spot history")
def ec2(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    spot_cache: dict[tuple, float | None] = {}

    def spot_price(itype: str, az: str, platform: str) -> float | None:
        key = (itype, az, platform)
        if key not in spot_cache:
            resp = ctx.call(c, "describe_spot_price_history", InstanceTypes=[itype], AvailabilityZone=az,
                            ProductDescriptions=[SPOT_PRODUCT.get(platform, "Linux/UNIX")],
                            StartTime=datetime.now(timezone.utc), MaxResults=1)
            hist = resp.get("SpotPriceHistory", [])
            spot_cache[key] = float(hist[0]["SpotPrice"]) if hist else None
        return spot_cache[key]

    for res in ctx.pages(c, "describe_instances", "Reservations"):
        for x in res.get("Instances", []):
            iid = x["InstanceId"]
            tags = tags_to_dict(x.get("Tags"))
            state = x.get("State", {}).get("Name", "")
            itype = x.get("InstanceType", "")
            platform = x.get("PlatformDetails", "Linux/UNIX")
            az = x.get("Placement", {}).get("AvailabilityZone", "")
            tenancy = "Dedicated" if x.get("Placement", {}).get("Tenancy") == "dedicated" else "Shared"
            spot = x.get("InstanceLifecycle") == "spot"
            r = Resource("EC2", ctx.region, "instance", iid, name_from_tags(tags), state,
                         ctx.arn("ec2", f"instance/{iid}"), f"{itype} | {platform}{' | spot' if spot else ''}", tags,
                         created=str(x.get("LaunchTime", "")))
            r.details.update(instance_type=itype, platform=platform, az=az, lifecycle="spot" if spot else "on-demand",
                             state_reason=x.get("StateTransitionReason", ""), public_ip=x.get("PublicIpAddress"))
            r.relate("vpc", x.get("VpcId"))
            r.relate("subnet", x.get("SubnetId"))
            r.relate("volume", *[m.get("Ebs", {}).get("VolumeId") for m in x.get("BlockDeviceMappings", [])])
            r.relate("eni", *[n.get("NetworkInterfaceId") for n in x.get("NetworkInterfaces", [])])
            r.relate("security-group", *[g.get("GroupId") for g in x.get("SecurityGroups", [])])
            if state == "running":
                if spot:
                    p = ctx.step(f"EC2 spot price {itype}", lambda: spot_price(itype, az, platform))
                    if p is not None:
                        r.monthly_estimate, r.estimate_note = p * HOURS_MONTH, f"Spot price ${p:.4f}/h ({az}); excludes EBS/data transfer"
                    else:
                        r.estimate_note = "Spot instance: on-demand list price does not apply; spot price unavailable"
                else:
                    p = ctx.prices.ec2_hourly(ctx.region, itype, platform, tenancy)
                    if p is not None:
                        r.monthly_estimate = p * HOURS_MONTH
                        r.estimate_note = f"On-demand {platform} {tenancy.lower()}-tenancy ${p:.4f}/h; excludes EBS, data transfer, RI/Savings Plan discounts"
                    else:
                        r.estimate_note = "Pricing lookup unavailable"
                ctx.metric(r, "cpu_max_14d", "AWS/EC2", "CPUUtilization", {"InstanceId": iid}, stat="Maximum")
                ctx.metric(r, "net_in_14d", "AWS/EC2", "NetworkIn", {"InstanceId": iid})
                ctx.metric(r, "net_out_14d", "AWS/EC2", "NetworkOut", {"InstanceId": iid})
            elif state in ("stopped", "stopping"):
                r.monthly_estimate, r.estimate_note = 0.0, "Stopped: compute $0; attached EBS volumes are billed separately"
            elif state in ("terminated", "shutting-down"):
                r.monthly_estimate, r.estimate_note = 0.0, "Terminated"
            ctx.add(r, "Direct EC2 API")


@collector("Lambda", "compute", bill="AWS Lambda", client="lambda",
           actions=("lambda:ListFunctions", "lambda:ListProvisionedConcurrencyConfigs"),
           desc="Functions incl. container-image functions; provisioned concurrency priced")
def lambda_(ctx: Ctx) -> None:
    c = ctx.client("lambda")
    fns = list(ctx.pages(c, "list_functions", "Functions"))
    resources = []
    for x in fns:
        runtime = x.get("Runtime") or ("container image" if x.get("PackageType") == "Image" else "unknown runtime")
        arch = (x.get("Architectures") or ["x86_64"])[0]
        r = Resource("Lambda", ctx.region, "function", x["FunctionName"], x["FunctionName"], "active", x["FunctionArn"],
                     f"{runtime} | {x.get('MemorySize', '?')} MB | {arch}",
                     estimate_note="Request/duration driven; use actual Cost Explorer cost", created=str(x.get("LastModified", "")))
        r.details.update(memory_mb=x.get("MemorySize"), arch=arch, package_type=x.get("PackageType", "Zip"), runtime=runtime)
        vpc = x.get("VpcConfig") or {}
        r.relate("vpc", vpc.get("VpcId"))
        r.relate("subnet", *vpc.get("SubnetIds", []))
        r.relate("role", x.get("Role"))
        resources.append(r)

    if len(resources) <= 500:   # one extra call per function; skip on very large accounts
        def pc(r: Resource):
            return ctx.step("Lambda provisioned concurrency", lambda: list(
                ctx.pages(c, "list_provisioned_concurrency_configs", "ProvisionedConcurrencyConfigs", FunctionName=r.resource_id)))
        for r, configs in zip(resources, ctx.map(pc, resources)):
            allocated = sum(int(cfg.get("AllocatedProvisionedConcurrentExecutions") or 0) for cfg in (configs or []))
            if allocated:
                gb = (r.details.get("memory_mb") or 128) / 1024
                rate = RATES["lambda_pc_gb_s"] * (0.8 if r.details.get("arch") == "arm64" else 1.0)
                r.details["provisioned_concurrency"] = allocated
                add_estimate(r, allocated * gb * rate * HOURS_MONTH * 3600,
                             f"provisioned concurrency {allocated} × {gb:g} GB always-on{region_note(ctx.region)}")
    for r in resources:
        # Lambda only emits Invocations when the function runs, so no datapoints means no invocations.
        ctx.metric(r, "invocations_90d", "AWS/Lambda", "Invocations", {"FunctionName": r.resource_id}, days=90, missing="zero")
        ctx.add(r)


def _fargate_estimate(ctx: Ctx, r: Resource, cpu: str | int | None, mem: str | int | None, arch: str, os_family: str,
                      count: int, spot_share: float) -> None:
    try:
        vcpu, gb = int(cpu) / 1024, int(mem) / 1024
    except (TypeError, ValueError):
        r.estimate_note = "Fargate task size unknown"
        return
    vr, gr, note = ctx.prices.fargate_rates(ctx.region, arch)
    per_task = (vcpu * vr + gb * gr) * HOURS_MONTH
    amount = count * per_task * (1 - 0.7 * spot_share)
    r.details.update(vcpu=vcpu, memory_gb=gb, arch=arch, tasks=count)
    r.monthly_estimate = amount
    parts = [f"Fargate {count} task(s) × ({vcpu:g} vCPU × ${vr}/h + {gb:g} GB × ${gr}/h){note}"]
    if spot_share:
        parts.append(f"{spot_share:.0%} on FARGATE_SPOT at ~70% off")
    if os_family and not os_family.startswith("LINUX"):
        parts.append("Windows OS licence fee excluded")
    parts.append("ephemeral storage >20 GB and data transfer excluded")
    r.estimate_note = "; ".join(parts)


def _tg_requests(ctx: Ctx, r: Resource, tg_arns: list[str]) -> None:
    """Request the ALB RequestCount of every target group a service sits behind (per load balancer)."""
    elbv2 = ctx.client("elbv2")
    for chunk in _chunks(tg_arns, 20):
        for tg in ctx.call(elbv2, "describe_target_groups", TargetGroupArns=chunk).get("TargetGroups", []):
            tg_dim = tg["TargetGroupArn"].split(":")[-1]
            for lb_arn in tg.get("LoadBalancerArns", []):
                lb_dim = lb_arn.split(":loadbalancer/", 1)[-1]
                if lb_dim.startswith("app/"):
                    ctx.metric(r, f"tg_requests_14d:{tg_dim}", "AWS/ApplicationELB", "RequestCount",
                               {"TargetGroup": tg_dim, "LoadBalancer": lb_dim}, missing="zero")


@collector("ECS", "compute", bill="Amazon Elastic Container Service", client="ecs",
           actions=("ecs:ListClusters", "ecs:DescribeClusters", "ecs:ListServices", "ecs:DescribeServices",
                    "ecs:DescribeTaskDefinition", "ecs:ListTasks", "ecs:DescribeTasks",
                    "elasticloadbalancing:DescribeTargetGroups", "cloudwatch:GetMetricData"),
           desc="Clusters, services and standalone tasks; Fargate tasks priced by vCPU/GB and architecture")
def ecs(ctx: Ctx) -> None:
    c = ctx.client("ecs")
    taskdefs: dict[str, dict] = {}

    def taskdef(arn: str) -> dict:
        if arn not in taskdefs:
            taskdefs[arn] = ctx.call(c, "describe_task_definition", taskDefinition=arn).get("taskDefinition", {})
        return taskdefs[arn]

    arns = list(ctx.pages(c, "list_clusters", "clusterArns"))
    clusters = []
    for chunk in _chunks(arns, 100):
        clusters += ctx.call(c, "describe_clusters", clusters=chunk).get("clusters", [])
    for cl in clusters:
        carn, cname = cl["clusterArn"], cl.get("clusterName", cl["clusterArn"].rsplit("/", 1)[-1])
        rc = Resource("ECS", ctx.region, "cluster", carn, cname, str(cl.get("status", "active")).lower(), carn,
                      f"{cl.get('activeServicesCount', 0)} services · {cl.get('runningTasksCount', 0)} running tasks",
                      monthly_estimate=0.0, estimate_note="Cluster object has no standalone charge; tasks/capacity determine cost")
        ctx.add(rc)
        svc_arns = list(ctx.pages(c, "list_services", "serviceArns", cluster=carn))
        for chunk in _chunks(svc_arns, 10):
            for s in ctx.call(c, "describe_services", cluster=carn, services=chunk).get("services", []):
                strategy = s.get("capacityProviderStrategy") or []
                total_w = sum(int(p.get("weight", 0)) for p in strategy) or 0
                spot_w = sum(int(p.get("weight", 0)) for p in strategy if p.get("capacityProvider") == "FARGATE_SPOT")
                launch = s.get("launchType") or ("FARGATE" if any(str(p.get("capacityProvider", "")).startswith("FARGATE")
                                                                  for p in strategy) else "EC2")
                td = ctx.step("ECS task definition", lambda: taskdef(s["taskDefinition"])) or {}
                plat = td.get("runtimePlatform") or {}
                arch = plat.get("cpuArchitecture") or "X86_64"
                running, desired = int(s.get("runningCount", 0)), int(s.get("desiredCount", 0))
                r = Resource("ECS", ctx.region, "service", s["serviceArn"], s["serviceName"], str(s.get("status", "")).lower(),
                             s["serviceArn"], f"{launch} · {running}/{desired} tasks · {arch}",
                             created=str(s.get("createdAt", "")))
                r.details.update(launch_type=launch, running=running, desired=desired)
                r.relate("cluster", carn)
                r.relate("task-definition", s.get("taskDefinition"))
                r.relate("target-group", *[lb.get("targetGroupArn") for lb in s.get("loadBalancers", [])])
                net = (s.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
                r.relate("subnet", *net.get("subnets", []))
                r.relate("security-group", *net.get("securityGroups", []))
                if launch == "FARGATE":
                    if running == 0:
                        r.monthly_estimate, r.estimate_note = 0.0, "No running tasks"
                    else:
                        _fargate_estimate(ctx, r, td.get("cpu"), td.get("memory"), arch, plat.get("operatingSystemFamily", "LINUX"),
                                          running, spot_w / total_w if total_w else 0.0)
                elif launch == "EXTERNAL":
                    r.estimate_note = "ECS Anywhere: billed per registered external instance-hour"
                else:
                    r.estimate_note = "EC2 launch type: cost sits on the container instances (listed under EC2)"
                if running:
                    dims = {"ClusterName": cname, "ServiceName": s["serviceName"]}
                    # No running tasks → no ECS metrics, so missing stays "unknown" here.
                    ctx.metric(r, "ecs_cpu_max_14d", "AWS/ECS", "CPUUtilization", dims, stat="Maximum")
                    ctx.metric(r, "ecs_mem_max_14d", "AWS/ECS", "MemoryUtilization", dims, stat="Maximum")
                    tg_arns = [lb.get("targetGroupArn") for lb in s.get("loadBalancers", []) if lb.get("targetGroupArn")]
                    if tg_arns:
                        ctx.step("ECS target-group traffic", lambda r=r, tg_arns=tg_arns: _tg_requests(ctx, r, tg_arns))
                ctx.add(r)

        # Standalone tasks (RunTask / scheduled tasks) that are not part of a service.
        task_arns = list(ctx.pages(c, "list_tasks", "taskArns", cluster=carn, desiredStatus="RUNNING"))
        for chunk in _chunks(task_arns, 100):
            for t in ctx.call(c, "describe_tasks", cluster=carn, tasks=chunk).get("tasks", []):
                if str(t.get("group", "")).startswith("service:"):
                    continue
                td = ctx.step("ECS task definition", lambda: taskdef(t["taskDefinitionArn"])) or {}
                arch = (td.get("runtimePlatform") or {}).get("cpuArchitecture") or "X86_64"
                name = str(t.get("group", "")).removeprefix("family:") or t["taskArn"].rsplit("/", 1)[-1]
                r = Resource("ECS", ctx.region, "task", t["taskArn"], name, str(t.get("lastStatus", "")).lower(), t["taskArn"],
                             f"{t.get('launchType', '?')} · standalone · {arch}", created=str(t.get("startedAt", "")))
                r.relate("cluster", carn)
                if t.get("launchType") == "FARGATE":
                    _fargate_estimate(ctx, r, t.get("cpu"), t.get("memory"), arch, "LINUX", 1,
                                      1.0 if t.get("capacityProviderName") == "FARGATE_SPOT" else 0.0)
                    r.estimate_note += "; assumes the task runs all month"
                ctx.add(r)


@collector("EKS", "compute", bill="Amazon Elastic Container Service for Kubernetes", client="eks",
           actions=("eks:ListClusters", "eks:DescribeCluster", "eks:DescribeClusterVersions", "eks:ListNodegroups",
                    "eks:DescribeNodegroup", "eks:ListFargateProfiles"),
           desc="Clusters (extended-support surcharge detected), node groups, Fargate profiles")
def eks(ctx: Ctx) -> None:
    c = ctx.client("eks")
    version_status: dict[str, str] = {}
    for n in ctx.pages(c, "list_clusters", "clusters"):
        x = ctx.call(c, "describe_cluster", name=n)["cluster"]
        version = x.get("version", "")
        if version and version not in version_status and hasattr(c, "describe_cluster_versions"):
            vs = ctx.step("EKS version support", lambda: ctx.call(c, "describe_cluster_versions", clusterVersions=[version]))
            for v in (vs or {}).get("clusterVersions", []):
                version_status[version] = str(v.get("versionStatus", ""))
        status = version_status.get(version, "")
        extended = status == "EXTENDED_SUPPORT"
        rate = RATES["eks_extended_h"] if extended else RATES["eks_h"]
        r = Resource("EKS", ctx.region, "cluster", n, n, x.get("status", ""), x.get("arn", ""),
                     f"Kubernetes {version}" + (" · extended support" if extended else ""),
                     monthly_estimate=rate * HOURS_MONTH,
                     estimate_note=f"{'Extended' if extended else 'Standard'}-support control plane ${rate}/h; worker nodes excluded"
                                   + ("" if status else " (support status unknown; standard rate assumed)"),
                     created=str(x.get("createdAt", "")))
        r.details.update(version=version, version_status=status or "unknown")
        r.relate("vpc", (x.get("resourcesVpcConfig") or {}).get("vpcId"))
        ctx.add(r)
        for ng_name in ctx.pages(c, "list_nodegroups", "nodegroups", clusterName=n):
            ng = ctx.call(c, "describe_nodegroup", clusterName=n, nodegroupName=ng_name)["nodegroup"]
            sc = ng.get("scalingConfig") or {}
            rn = Resource("EKS", ctx.region, "nodegroup", ng.get("nodegroupArn", ng_name), ng_name, str(ng.get("status", "")).lower(),
                          ng.get("nodegroupArn", ""),
                          f"{ng.get('capacityType', 'ON_DEMAND')} · {', '.join(ng.get('instanceTypes') or [])} · desired {sc.get('desiredSize', '?')}",
                          estimate_note="Nodes are billed as EC2 instances (listed under EC2)")
            rn.relate("cluster", x.get("arn"))
            ctx.add(rn)
        for fp in ctx.pages(c, "list_fargate_profiles", "fargateProfileNames", clusterName=n):
            rf = Resource("EKS", ctx.region, "fargate-profile", f"{n}/{fp}", fp, "active",
                          estimate_note="Pods on this profile are billed as Fargate vCPU/GB-hours")
            rf.relate("cluster", x.get("arn"))
            ctx.add(rf)


@collector("App Runner", "compute", bill="AWS App Runner", client="apprunner",
           actions=("apprunner:ListServices", "apprunner:DescribeService"),
           desc="Services; idle provisioned-instance memory priced")
def apprunner(ctx: Ctx) -> None:
    c = ctx.client("apprunner")
    for s in ctx.pages(c, "list_services", "ServiceSummaryList"):
        d = ctx.call(c, "describe_service", ServiceArn=s["ServiceArn"]).get("Service", {})
        inst = d.get("InstanceConfiguration") or {}
        try:
            mem_gb = int(str(inst.get("Memory", "2048")).split()[0]) / (1 if "GB" in str(inst.get("Memory", "")) else 1024)
        except ValueError:
            mem_gb = 2.0
        r = Resource("App Runner", ctx.region, "service", s["ServiceArn"], s.get("ServiceName", ""), str(s.get("Status", "")).lower(),
                     s["ServiceArn"], f"{inst.get('Cpu', '?')} CPU · {inst.get('Memory', '?')}", created=str(s.get("CreatedAt", "")))
        if s.get("Status") == "RUNNING":
            r.monthly_estimate = mem_gb * 0.007 * HOURS_MONTH
            r.estimate_note = f"1 provisioned instance idle memory {mem_gb:g} GB × $0.007/GB-h{region_note(ctx.region)}; active vCPU/memory billed per use"
        else:
            r.monthly_estimate, r.estimate_note = 0.0, "Paused"
        ctx.add(r)


@collector("Lightsail", "compute", bill="Amazon Lightsail", client="lightsail",
           actions=("lightsail:GetInstances", "lightsail:GetBundles", "lightsail:GetRelationalDatabases",
                    "lightsail:GetRelationalDatabaseBundles", "lightsail:GetDisks"),
           desc="Instances and databases at their exact bundle price; block storage disks")
def lightsail(ctx: Ctx) -> None:
    c = ctx.client("lightsail")
    instances = list(ctx.pages(c, "get_instances", "instances"))
    dbs = list(ctx.pages(c, "get_relational_databases", "relationalDatabases"))
    if instances:
        bundles = {b["bundleId"]: b for b in ctx.pages(c, "get_bundles", "bundles")}
        for x in instances:
            b = bundles.get(x.get("bundleId"), {})
            ctx.add(Resource("Lightsail", ctx.region, "instance", x.get("arn", x["name"]), x["name"],
                             str((x.get("state") or {}).get("name", "")), x.get("arn", ""),
                             f"{x.get('bundleId')} · {x.get('blueprintId')}", monthly_estimate=b.get("price"),
                             estimate_note="Lightsail bundle price (fixed monthly)" if b else "Bundle price unavailable"))
    if dbs:
        dbb = {b["bundleId"]: b for b in ctx.pages(c, "get_relational_database_bundles", "bundles")}
        for x in dbs:
            b = dbb.get(x.get("relationalDatabaseBundleId"), {})
            ctx.add(Resource("Lightsail", ctx.region, "database", x.get("arn", x["name"]), x["name"], str(x.get("state", "")),
                             x.get("arn", ""), str(x.get("relationalDatabaseBundleId", "")), monthly_estimate=b.get("price"),
                             estimate_note="Lightsail database bundle price"))
    for d in ctx.pages(c, "get_disks", "disks"):
        gb = d.get("sizeInGb") or 0
        ctx.add(Resource("Lightsail", ctx.region, "disk", d.get("arn", d["name"]), d["name"], str(d.get("state", "")),
                         d.get("arn", ""), f"{gb} GB", monthly_estimate=gb * 0.10,
                         estimate_note="Block storage $0.10/GB-mo"))


@collector("Batch", "compute", client="batch", actions=("batch:DescribeComputeEnvironments",),
           desc="Compute environments (capacity billed as EC2/Fargate)")
def batch(ctx: Ctx) -> None:
    c = ctx.client("batch")
    for e in ctx.pages(c, "describe_compute_environments", "computeEnvironments"):
        cr = e.get("computeResources") or {}
        ctx.add(Resource("Batch", ctx.region, "compute-environment", e["computeEnvironmentArn"], e.get("computeEnvironmentName", ""),
                         str(e.get("state", "")).lower(), e["computeEnvironmentArn"],
                         f"{e.get('type', '')} · {cr.get('type', '')} · {cr.get('minvCpus', 0)}-{cr.get('maxvCpus', 0)} vCPU",
                         monthly_estimate=0.0, estimate_note="No Batch charge; instances/Fargate tasks it launches are billed separately"))


@collector("EMR", "compute", bill="Amazon Elastic MapReduce", client="emr", actions=("elasticmapreduce:ListClusters",),
           desc="Active clusters (EMR surcharge; EC2 nodes listed under EC2)")
def emr(ctx: Ctx) -> None:
    c = ctx.client("emr")
    for cl in ctx.pages(c, "list_clusters", "Clusters", ClusterStates=["STARTING", "BOOTSTRAPPING", "RUNNING", "WAITING"]):
        st = cl.get("Status") or {}
        ctx.add(Resource("EMR", ctx.region, "cluster", cl["Id"], cl.get("Name", ""), str(st.get("State", "")).lower(),
                         cl.get("ClusterArn", ""), f"{cl.get('NormalizedInstanceHours', 0)} normalized instance-hours so far",
                         created=str((st.get("Timeline") or {}).get("CreationDateTime", "")),
                         estimate_note="EMR per-instance surcharge billed under Amazon Elastic MapReduce; nodes listed under EC2"))


@collector("Elastic Beanstalk", "compute", client="elasticbeanstalk", actions=("elasticbeanstalk:DescribeEnvironments",),
           desc="Environments (underlying EC2/ELB listed separately)")
def beanstalk(ctx: Ctx) -> None:
    c = ctx.client("elasticbeanstalk")
    for e in ctx.pages(c, "describe_environments", "Environments", IncludeDeleted=False):
        ctx.add(Resource("Elastic Beanstalk", ctx.region, "environment", e.get("EnvironmentArn", e["EnvironmentId"]),
                         e.get("EnvironmentName", ""), str(e.get("Status", "")).lower(), e.get("EnvironmentArn", ""),
                         f"{e.get('SolutionStackName', '')} · health {e.get('Health', '')}", monthly_estimate=0.0,
                         estimate_note="No Beanstalk charge; its EC2 instances and load balancers are listed separately"))
