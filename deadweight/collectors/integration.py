"""Integration & analytics: SQS, SNS, Kinesis, Firehose, MSK, MQ, Step Functions, SES, Transfer Family, Glue, Athena."""
from __future__ import annotations

from ..models import HOURS_MONTH, Resource
from ..pricing import RATES, region_note
from .base import Ctx, add_estimate, collector

USAGE = "Request/usage driven; use actual cost"


@collector("SQS", "integration", bill="Amazon Simple Queue Service", client="sqs", actions=("sqs:ListQueues", "cloudwatch:GetMetricData"),
           desc="Queues (messages sent/received, 30 days)")
def sqs(ctx: Ctx) -> None:
    c = ctx.client("sqs")
    for u in ctx.pages(c, "list_queues", "QueueUrls"):
        n = u.rsplit("/", 1)[-1]
        r = Resource("SQS", ctx.region, "queue", u, n, "active", ctx.arn("sqs", n), u, estimate_note="Request driven; use actual cost")
        # SQS stops emitting after 6 idle hours, so gaps are zeros. Never call GetQueueAttributes: it wakes the metrics.
        for metric in ("NumberOfMessagesSent", "NumberOfMessagesReceived"):
            ctx.metric(r, f"sqs_{metric}_30d", "AWS/SQS", metric, {"QueueName": n}, days=30, missing="zero")
        ctx.add(r)


@collector("SNS", "integration", bill="Amazon Simple Notification Service", client="sns", actions=("sns:ListTopics",), desc="Topics")
def sns(ctx: Ctx) -> None:
    c = ctx.client("sns")
    for x in ctx.pages(c, "list_topics", "Topics"):
        a = x["TopicArn"]
        r = Resource("SNS", ctx.region, "topic", a, a.rsplit(":", 1)[-1], "active", a,
                     estimate_note="Publish/delivery driven; use actual cost")
        ctx.metric(r, "sns_published_30d", "AWS/SNS", "NumberOfMessagesPublished", {"TopicName": a.rsplit(":", 1)[-1]},
                   days=30, missing="zero")
        ctx.add(r)


@collector("Kinesis", "integration", bill="Amazon Kinesis", client="kinesis",
           actions=("kinesis:ListStreams", "kinesis:DescribeStreamSummary"), desc="Data streams (shard-hours / on-demand stream-hours)")
def kinesis(ctx: Ctx) -> None:
    c = ctx.client("kinesis")
    rn = region_note(ctx.region)
    for name in ctx.pages(c, "list_streams", "StreamNames"):
        s = ctx.call(c, "describe_stream_summary", StreamName=name).get("StreamDescriptionSummary", {})
        mode = (s.get("StreamModeDetails") or {}).get("StreamMode", "PROVISIONED")
        shards = int(s.get("OpenShardCount") or 0)
        r = Resource("Kinesis", ctx.region, "stream", s.get("StreamARN", name), name, str(s.get("StreamStatus", "")).lower(),
                     s.get("StreamARN", ""), f"{mode.lower()} · {shards} shards · {s.get('RetentionPeriodHours', 24)} h retention",
                     created=str(s.get("StreamCreationTimestamp", "")))
        if mode == "ON_DEMAND":
            add_estimate(r, RATES["kinesis_ondemand_stream_h"] * HOURS_MONTH, f"on-demand stream-hour ${RATES['kinesis_ondemand_stream_h']}{rn}; per-GB excluded")
        else:
            add_estimate(r, shards * RATES["kinesis_shard_h"] * HOURS_MONTH, f"{shards} shard(s) × ${RATES['kinesis_shard_h']}/h{rn}; PUT units excluded")
        if int(s.get("RetentionPeriodHours") or 24) > 24:
            r.estimate_note += "; extended retention excluded"
        ctx.add(r)


@collector("Firehose", "integration", bill="Amazon Kinesis Firehose", client="firehose",
           actions=("firehose:ListDeliveryStreams",), desc="Delivery streams (per GB ingested)")
def firehose(ctx: Ctx) -> None:
    c = ctx.client("firehose")
    token = None
    while True:
        kw = {"Limit": 100, **({"ExclusiveStartDeliveryStreamName": token} if token else {})}
        resp = ctx.call(c, "list_delivery_streams", **kw)
        names = resp.get("DeliveryStreamNames", [])
        for n in names:
            ctx.add(Resource("Firehose", ctx.region, "delivery-stream", ctx.arn("firehose", f"deliverystream/{n}"), n, "active",
                             ctx.arn("firehose", f"deliverystream/{n}"), estimate_note="Billed per GB ingested; use actual cost"))
        if not resp.get("HasMoreDeliveryStreams") or not names:
            break
        token = names[-1]


@collector("MSK", "integration", bill="Amazon Managed Streaming for Apache Kafka", client="kafka",
           actions=("kafka:ListClustersV2", "pricing:GetProducts"), desc="Provisioned clusters (brokers + storage); serverless")
def msk(ctx: Ctx) -> None:
    c = ctx.client("kafka")
    for x in ctx.pages(c, "list_clusters_v2", "ClusterInfoList"):
        prov = x.get("Provisioned") or {}
        r = Resource("MSK", ctx.region, "cluster", x["ClusterArn"], x.get("ClusterName", ""), str(x.get("State", "")).lower(),
                     x["ClusterArn"], str(x.get("ClusterType", "")), created=str(x.get("CreationTime", "")))
        if prov:
            bng = prov.get("BrokerNodeGroupInfo") or {}
            itype, n = bng.get("InstanceType", ""), int(prov.get("NumberOfBrokerNodes") or 0)
            vol = int(((bng.get("StorageInfo") or {}).get("EbsStorageInfo") or {}).get("VolumeSize") or 0)
            r.config = f"{itype} × {n} brokers · {vol} GB each"
            p = ctx.prices.instance_hourly("AmazonMSK", ctx.region, itype)
            storage = vol * n * RATES["msk_storage_gb"]
            if p is not None:
                add_estimate(r, p * n * HOURS_MONTH, f"{n} × {itype} ${p:.4f}/h")
                add_estimate(r, storage, f"{vol * n} GB storage × ${RATES['msk_storage_gb']}{region_note(ctx.region)}")
            else:
                r.estimate_note = f"Broker pricing lookup unavailable (storage alone ≈ ${storage:,.2f}/mo)"
        else:
            r.estimate_note = "MSK Serverless: billed per cluster-hour, partition-hour and GB"
        ctx.add(r)


@collector("MQ", "integration", bill="Amazon MQ", client="mq", actions=("mq:ListBrokers", "mq:DescribeBroker", "pricing:GetProducts"),
           desc="Brokers (instance-hours × deployment mode)")
def mq(ctx: Ctx) -> None:
    c = ctx.client("mq")
    for b in ctx.pages(c, "list_brokers", "BrokerSummaries"):
        mode = b.get("DeploymentMode", "SINGLE_INSTANCE")
        itype = b.get("HostInstanceType", "")
        n = {"SINGLE_INSTANCE": 1, "ACTIVE_STANDBY_MULTI_AZ": 2, "CLUSTER_MULTI_AZ": 3}.get(mode, 1)
        r = Resource("MQ", ctx.region, "broker", b["BrokerArn"], b.get("BrokerName", ""), str(b.get("BrokerState", "")).lower(),
                     b["BrokerArn"], f"{b.get('EngineType', '')} · {itype} · {mode.lower()}", created=str(b.get("Created", "")))
        p = ctx.prices.instance_hourly("AmazonMQ", ctx.region, itype)
        if p is not None:
            r.monthly_estimate, r.estimate_note = p * n * HOURS_MONTH, f"{n} × {itype} ${p:.4f}/h; storage excluded"
        else:
            r.estimate_note = "Broker pricing lookup unavailable"
        ctx.add(r)


@collector("Step Functions", "integration", bill="AWS Step Functions", client="stepfunctions",
           actions=("states:ListStateMachines",), desc="State machines (per transition / duration)")
def stepfunctions(ctx: Ctx) -> None:
    c = ctx.client("stepfunctions")
    for x in ctx.pages(c, "list_state_machines", "stateMachines"):
        r = Resource("Step Functions", ctx.region, "state-machine", x["stateMachineArn"], x["name"], "active", x["stateMachineArn"],
                     str(x.get("type", "")), created=str(x.get("creationDate", "")), estimate_note=USAGE)
        # Sum, never SampleCount: two datapoints are emitted per execution.
        ctx.metric(r, "sfn_executions_90d", "AWS/States", "ExecutionsStarted", {"StateMachineArn": x["stateMachineArn"]},
                   days=90, missing="zero")
        ctx.add(r)


@collector("SES", "integration", bill="Amazon Simple Email Service", client="sesv2",
           actions=("ses:ListEmailIdentities", "ses:GetDedicatedIps"), desc="Identities and dedicated IPs ($24.95/month each)")
def ses(ctx: Ctx) -> None:
    c = ctx.client("sesv2")
    for x in ctx.pages(c, "list_email_identities", "EmailIdentities"):
        ctx.add(Resource("SES", ctx.region, "identity", f"{ctx.region}/{x['IdentityName']}", x["IdentityName"],
                         "verified" if x.get("SendingEnabled") else "not sending", ctx.arn("ses", f"identity/{x['IdentityName']}"),
                         str(x.get("IdentityType", "")), estimate_note="Per message; use actual cost"))

    def dedicated():
        for ip in ctx.pages(c, "get_dedicated_ips", "DedicatedIps"):
            ctx.add(Resource("SES", ctx.region, "dedicated-ip", ip["Ip"], ip["Ip"], str(ip.get("WarmupStatus", "")).lower(), "",
                             f"pool {ip.get('PoolName', '')}", monthly_estimate=24.95, estimate_note="Dedicated IP $24.95/month"))
    ctx.step("SES dedicated IPs", dedicated)


@collector("Transfer Family", "integration", bill="AWS Transfer Family", client="transfer",
           actions=("transfer:ListServers", "transfer:DescribeServer"), desc="Servers ($0.30/h per enabled protocol)")
def transfer(ctx: Ctx) -> None:
    c = ctx.client("transfer")
    for s in ctx.pages(c, "list_servers", "Servers"):
        d = ctx.call(c, "describe_server", ServerId=s["ServerId"]).get("Server", {})
        protocols = d.get("Protocols") or ["SFTP"]
        n = len(protocols)
        ctx.add(Resource("Transfer Family", ctx.region, "server", s["Arn"], s["ServerId"], str(s.get("State", "")).lower(), s["Arn"],
                         f"{', '.join(protocols)} · {s.get('EndpointType', '')}", monthly_estimate=n * RATES["transfer_protocol_h"] * HOURS_MONTH,
                         estimate_note=f"{n} protocol(s) × ${RATES['transfer_protocol_h']}/h{region_note(ctx.region)} — billed while the server exists, even when stopped; data excluded"))


@collector("Glue", "integration", bill="AWS Glue", client="glue",
           actions=("glue:GetJobs", "glue:GetJobRuns", "glue:GetCrawlers", "glue:GetDevEndpoints"),
           desc="Jobs (last run), crawlers (last crawl) and dev endpoints")
def glue(ctx: Ctx) -> None:
    c = ctx.client("glue")
    jobs = list(ctx.pages(c, "get_jobs", "Jobs"))

    def last_run(j: dict):
        runs = ctx.step("Glue job runs", lambda: ctx.call(c, "get_job_runs", JobName=j["Name"], MaxResults=1)) or {}
        return (runs.get("JobRuns") or [{}])[0].get("StartedOn")
    for j, started in zip(jobs, ctx.map(last_run, jobs)):
        r = Resource("Glue", ctx.region, "job", ctx.arn("glue", f"job/{j['Name']}"), j["Name"], "active", ctx.arn("glue", f"job/{j['Name']}"),
                     f"{j.get('Command', {}).get('Name', '')} · {j.get('WorkerType', '')} × {j.get('NumberOfWorkers', '')}",
                     estimate_note="Billed per DPU-hour while running; use actual cost", created=str(j.get("CreatedOn", "")))
        r.details["last_used"] = str(started or "")      # run history only goes back 90 days
        r.details["history_days"] = 90
        ctx.add(r)
    for cr in ctx.pages(c, "get_crawlers", "Crawlers"):
        r = Resource("Glue", ctx.region, "crawler", ctx.arn("glue", f"crawler/{cr['Name']}"), cr["Name"], str(cr.get("State", "")).lower(),
                     ctx.arn("glue", f"crawler/{cr['Name']}"), str((cr.get("Schedule") or {}).get("ScheduleExpression", "on demand")),
                     estimate_note="Billed per DPU-hour while running; use actual cost", created=str(cr.get("CreationTime", "")))
        r.details["last_used"] = str((cr.get("LastCrawl") or {}).get("StartTime", "") or "")
        ctx.add(r)

    def dev():
        for d in ctx.pages(c, "get_dev_endpoints", "DevEndpoints"):
            n = int(d.get("NumberOfNodes") or d.get("NumberOfWorkers") or 0)
            ctx.add(Resource("Glue", ctx.region, "dev-endpoint", d["EndpointName"], d["EndpointName"], str(d.get("Status", "")).lower(), "",
                             f"{n} DPU", monthly_estimate=n * 0.44 * HOURS_MONTH if d.get("Status") == "READY" else 0.0,
                             estimate_note=f"{n} DPU × $0.44/h while provisioned"))
    ctx.step("Glue dev endpoints", dev)


@collector("Athena", "integration", bill="Amazon Athena", client="athena", actions=("athena:ListWorkGroups",),
           desc="Workgroups (per TB scanned)")
def athena(ctx: Ctx) -> None:
    c = ctx.client("athena")
    for w in ctx.pages(c, "list_work_groups", "WorkGroups"):
        ctx.add(Resource("Athena", ctx.region, "workgroup", ctx.arn("athena", f"workgroup/{w['Name']}"), w["Name"],
                         str(w.get("State", "")).lower(), ctx.arn("athena", f"workgroup/{w['Name']}"),
                         estimate_note="Billed per TB scanned; use actual cost"))
