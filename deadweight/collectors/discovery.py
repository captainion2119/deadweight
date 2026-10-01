"""Generic discovery planes: Resource Explorer, Resource Groups Tagging API, Cloud Control API, AWS Config.

They overlap with the direct collectors on purpose; the scanner de-duplicates by ARN, and anything only
found here shows up as AWS/<service> so coverage gaps are visible."""
from __future__ import annotations

import json
import re

from ..aws import classify, failed_action
from ..billing import ARN_BILL, generic_bill
from ..models import Resource, name_from_tags
from .base import Ctx, collector

CC_CURATED = [
    "AWS::Events::Rule", "AWS::Events::EventBus", "AWS::Scheduler::Schedule", "AWS::Pipes::Pipe",
    "AWS::AppSync::GraphQLApi", "AWS::Cognito::UserPool", "AWS::Cognito::IdentityPool", "AWS::Amplify::App",
    "AWS::CodeBuild::Project", "AWS::CodePipeline::Pipeline", "AWS::CodeArtifact::Repository",
    "AWS::Timestream::Database", "AWS::Cassandra::Keyspace", "AWS::APS::Workspace", "AWS::Grafana::Workspace",
    "AWS::DataSync::Task", "AWS::Lex::Bot", "AWS::Connect::Instance", "AWS::IoT::TopicRule", "AWS::Location::Map",
    "AWS::EMRServerless::Application", "AWS::EC2::IPAM", "AWS::VpcLattice::Service", "AWS::DMS::ReplicationConfig",
    "AWS::MediaConvert::Queue", "AWS::QuickSight::DataSource", "AWS::Batch::JobQueue", "AWS::ECR::PullThroughCacheRule",
]


def generic(ctx: Ctx, arn: str, region: str, rtype: str, source: str, *, tags: dict | None = None, name: str = "",
            account: str = "", rid: str = "") -> None:
    svc = arn.split(":")[2] if arn.startswith("arn:") else (rtype.split("::")[1].lower() if "::" in rtype else "aws")
    bill, family = generic_bill(arn, rtype)
    r = Resource(f"AWS/{svc}", region or "global", rtype or "resource", rid or arn, name or name_from_tags(tags or {}),
                 "discovered", arn if arn.startswith("arn:") else "", source, tags or {},
                 estimate_note="Discovered generically; billing reconciled at service level",
                 bill_service=bill or ARN_BILL.get(svc, ""), usage_family=family, account_id=account)
    ctx.add(r, source)


def _tags_from_properties(props: list) -> dict:
    for p in props or []:
        if p.get("Name") == "tags":
            return {str(t.get("Key", "")): str(t.get("Value", "")) for t in (p.get("Data") or [])}
    return {}


def _search(ctx: Ctx, c, view: str, query: str = "*") -> tuple[list, bool]:
    items, token, complete = [], None, True
    while True:
        resp = ctx.call(c, "search", QueryString=query, ViewArn=view, MaxResults=1000, **({"NextToken": token} if token else {}))
        items += resp.get("Resources", [])
        complete = (resp.get("Count") or {}).get("Complete", True)
        token = resp.get("NextToken")
        if not token:
            return items, complete


@collector("Universal Discovery", "discovery", scope="global", client="resource-explorer-2",
           actions=("resource-explorer-2:ListIndexes", "resource-explorer-2:GetDefaultView", "resource-explorer-2:ListViews",
                    "resource-explorer-2:Search", "resource-explorer-2:ListResources", "resource-explorer-2:ListSupportedResourceTypes"),
           desc="Resource Explorer: one cross-region search through an aggregator index, otherwise each local index")
def resource_explorer(ctx: Ctx) -> None:
    home = ctx.scanner.home_region
    rx = ctx.client("resource-explorer-2", home)

    def supported():
        types = list(ctx.pages(rx, "list_supported_resource_types", "ResourceTypes"))
        ctx.coverage("Resource Explorer supported types", "ok", f"{len(types)} resource types supported by API")
        return types
    types = ctx.step("Resource Explorer supported types", supported) or []
    scanned = set(ctx.scanner.regions)
    try:
        indexes = list(ctx.pages(rx, "list_indexes", "Indexes"))
    except Exception as e:
        status, detail = classify(e)
        ctx.coverage("Resource Explorer index lookup", status, detail, action=failed_action(e, rx))
        indexes = [{"Region": r, "Type": "LOCAL"} for r in scanned]      # fall back to trying every region
    aggregator = next((i for i in indexes if i.get("Type") == "AGGREGATOR"), None)
    indexed = {i.get("Region") for i in indexes}
    for reg in sorted(scanned - indexed):
        ctx.coverage("Resource Explorer", "not-enabled", "No Resource Explorer index in this region; no changes made", region=reg)
    targets = [aggregator["Region"]] if aggregator else sorted(indexed & scanned)

    def search_region(reg: str) -> None:
        c = ctx.client("resource-explorer-2", reg)
        view = None
        try:
            view = ctx.call(c, "get_default_view").get("ViewArn")
        except Exception:
            pass
        if not view:
            views = ctx.step("Resource Explorer view lookup", lambda: list(ctx.pages(c, "list_views", "Views")), region=reg) or []
            view = views[0] if views else None
            if isinstance(view, dict):
                view = view.get("ViewArn") or view.get("Arn")
        if not view:
            ctx.coverage("Resource Explorer", "not-enabled", "No default/listed view found; no changes made", region=reg)
            return
        items, complete = _search(ctx, c, view)
        how = "search"
        if not complete:
            # Search stops at 1,000 results; ListResources pages through everything, else partition by service.
            if hasattr(c, "list_resources"):
                items, how = list(ctx.pages(c, "list_resources", "Resources", ViewArn=view)), "list_resources"
            else:
                seen, how = {x.get("Arn") for x in items}, "per-service search"
                for svc in sorted({t.get("Service") for t in types if t.get("Service")}):
                    more, _ = _search(ctx, c, view, f"service:{svc}")
                    items += [x for x in more if x.get("Arn") not in seen]
        for x in items:
            arn = x.get("Arn", "")
            generic(ctx, arn, x.get("Region") or reg, x.get("ResourceType", "") or "resource", "Resource Explorer",
                    tags=_tags_from_properties(x.get("Properties")), account=str(x.get("OwningAccountId", "")))
        scope = "aggregator (all indexed regions)" if aggregator else "local index"
        ctx.coverage("Resource Explorer", "ok", f"{len(items)} resources via {scope} · {how}", region=reg)
    for reg in targets:
        ctx.step(f"Resource Explorer {reg}", lambda reg=reg: search_region(reg), region=reg)


@collector("Tagging API", "discovery", client="resourcegroupstaggingapi", actions=("tag:GetResources",),
           desc="Resource Groups Tagging API: every tagged (or once-tagged) resource")
def tagging(ctx: Ctx) -> None:
    c = ctx.client("resourcegroupstaggingapi")
    n = 0
    for x in ctx.pages(c, "get_resources", "ResourceTagMappingList", ResourcesPerPage=100):
        tags = {t.get("Key", ""): t.get("Value", "") for t in x.get("Tags", [])}
        arn = x.get("ResourceARN", "")
        generic(ctx, arn, ctx.region, "tagged-resource", "Tagging API", tags=tags)
        n += 1
    ctx.coverage("Resource Groups Tagging API", "ok", f"{n} tagged/taggable mappings")


# Types whose list is account-wide: listing them per region repeats every item once per region.
CC_GLOBAL_NAMESPACES = {"IAM", "CloudFront", "Route53", "Organizations", "GlobalAccelerator", "Shield", "WAF",
                        "NetworkManager", "Route53RecoveryControl", "Route53RecoveryReadiness", "CE", "Budgets"}
CC_GLOBAL_TYPES = {"AWS::S3::Bucket", "AWS::S3::MultiRegionAccessPoint", "AWS::S3::StorageLens"}

# Cloud Control types a direct collector already inventories (richer, priced) → skipped when that collector runs.
CC_COVERED = {
    "AWS::EC2::Instance": "EC2", "AWS::EC2::Volume": "EBS", "AWS::EC2::EIP": "Elastic IP", "AWS::EC2::NatGateway": "NAT Gateway",
    "AWS::EC2::VPC": "VPC", "AWS::EC2::VPCEndpoint": "VPC", "AWS::EC2::TransitGateway": "Transit Gateway",
    "AWS::EC2::TransitGatewayAttachment": "Transit Gateway", "AWS::EC2::TransitGatewayVpcAttachment": "Transit Gateway",
    "AWS::EC2::VPNConnection": "VPN", "AWS::EC2::ClientVpnEndpoint": "VPN",
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "ELB", "AWS::ElasticLoadBalancing::LoadBalancer": "ELB",
    "AWS::ApiGateway::RestApi": "API Gateway", "AWS::ApiGatewayV2::Api": "API Gateway",
    "AWS::CloudFront::Distribution": "CloudFront", "AWS::Route53::HostedZone": "Route53", "AWS::Route53::HealthCheck": "Route53",
    "AWS::Route53Resolver::ResolverEndpoint": "Route 53 Resolver", "AWS::GlobalAccelerator::Accelerator": "Global Accelerator",
    "AWS::ServiceDiscovery::PrivateDnsNamespace": "Cloud Map", "AWS::ServiceDiscovery::PublicDnsNamespace": "Cloud Map",
    "AWS::ServiceDiscovery::HttpNamespace": "Cloud Map", "AWS::ServiceDiscovery::Service": "Cloud Map",
    "AWS::NetworkFirewall::Firewall": "Network Firewall", "AWS::Lambda::Function": "Lambda",
    "AWS::ECS::Cluster": "ECS", "AWS::ECS::Service": "ECS", "AWS::EKS::Cluster": "EKS", "AWS::EKS::Nodegroup": "EKS",
    "AWS::EKS::FargateProfile": "EKS", "AWS::AppRunner::Service": "App Runner", "AWS::Lightsail::Instance": "Lightsail",
    "AWS::Lightsail::Database": "Lightsail", "AWS::Lightsail::Disk": "Lightsail", "AWS::Batch::ComputeEnvironment": "Batch",
    "AWS::EMR::Cluster": "EMR", "AWS::ElasticBeanstalk::Environment": "Elastic Beanstalk", "AWS::S3::Bucket": "S3",
    "AWS::EFS::FileSystem": "EFS", "AWS::FSx::FileSystem": "FSx", "AWS::ECR::Repository": "ECR",
    "AWS::Backup::BackupVault": "Backup", "AWS::Backup::BackupPlan": "Backup", "AWS::RDS::DBInstance": "RDS",
    "AWS::RDS::DBCluster": "RDS", "AWS::DocDB::DBCluster": "RDS", "AWS::DocDB::DBInstance": "RDS", "AWS::Neptune::DBCluster": "RDS",
    "AWS::Neptune::DBInstance": "RDS", "AWS::DynamoDB::Table": "DynamoDB", "AWS::DynamoDB::GlobalTable": "DynamoDB",
    "AWS::ElastiCache::CacheCluster": "ElastiCache", "AWS::ElastiCache::ServerlessCache": "ElastiCache",
    "AWS::MemoryDB::Cluster": "MemoryDB", "AWS::OpenSearchService::Domain": "OpenSearch", "AWS::Elasticsearch::Domain": "OpenSearch",
    "AWS::OpenSearchServerless::Collection": "OpenSearch Serverless", "AWS::Redshift::Cluster": "Redshift",
    "AWS::RedshiftServerless::Workgroup": "Redshift", "AWS::KMS::Key": "KMS", "AWS::SecretsManager::Secret": "Secrets Manager",
    "AWS::WAFv2::WebACL": "WAF", "AWS::ACMPCA::CertificateAuthority": "Private CA", "AWS::IAM::User": "IAM",
    "AWS::GuardDuty::Detector": "GuardDuty", "AWS::SecurityHub::Hub": "Security Hub", "AWS::CloudTrail::Trail": "CloudTrail",
    "AWS::CloudTrail::EventDataStore": "CloudTrail", "AWS::Config::ConfigurationRecorder": "Config", "AWS::SQS::Queue": "SQS",
    "AWS::SNS::Topic": "SNS", "AWS::Kinesis::Stream": "Kinesis", "AWS::KinesisFirehose::DeliveryStream": "Firehose",
    "AWS::MSK::Cluster": "MSK", "AWS::MSK::ServerlessCluster": "MSK", "AWS::AmazonMQ::Broker": "MQ",
    "AWS::StepFunctions::StateMachine": "Step Functions", "AWS::SES::EmailIdentity": "SES", "AWS::Transfer::Server": "Transfer Family",
    "AWS::Glue::Job": "Glue", "AWS::Glue::Crawler": "Glue", "AWS::Athena::WorkGroup": "Athena", "AWS::Logs::LogGroup": "CloudWatch Logs",
    "AWS::CloudWatch::Alarm": "CloudWatch Alarms", "AWS::CloudWatch::CompositeAlarm": "CloudWatch Alarms",
    "AWS::CloudWatch::Dashboard": "CloudWatch Dashboards", "AWS::SageMaker::Endpoint": "SageMaker",
    "AWS::SageMaker::NotebookInstance": "SageMaker", "AWS::Kendra::Index": "Kendra", "AWS::Bedrock::Guardrail": "Bedrock",
    "AWS::Bedrock::Agent": "Bedrock", "AWS::Bedrock::KnowledgeBase": "Bedrock", "AWS::Bedrock::Prompt": "Bedrock",
    "AWS::Bedrock::Flow": "Bedrock",
}

# ARNs for types whose list handler only returns a name or id, so they de-duplicate against other sources.
CC_ARN = {
    "AWS::IAM::Role": "arn:{p}:iam::{a}:role/{id}", "AWS::IAM::User": "arn:{p}:iam::{a}:user/{id}",
    "AWS::IAM::Group": "arn:{p}:iam::{a}:group/{id}", "AWS::IAM::InstanceProfile": "arn:{p}:iam::{a}:instance-profile/{id}",
    "AWS::S3::Bucket": "arn:{p}:s3:::{id}", "AWS::Lambda::Function": "arn:{p}:lambda:{r}:{a}:function:{id}",
    "AWS::Logs::LogGroup": "arn:{p}:logs:{r}:{a}:log-group:{id}", "AWS::DynamoDB::Table": "arn:{p}:dynamodb:{r}:{a}:table/{id}",
    "AWS::ECR::Repository": "arn:{p}:ecr:{r}:{a}:repository/{id}", "AWS::ECS::Cluster": "arn:{p}:ecs:{r}:{a}:cluster/{id}",
    "AWS::EKS::Cluster": "arn:{p}:eks:{r}:{a}:cluster/{id}", "AWS::RDS::DBInstance": "arn:{p}:rds:{r}:{a}:db:{id}",
    "AWS::RDS::DBCluster": "arn:{p}:rds:{r}:{a}:cluster:{id}", "AWS::RDS::DBSubnetGroup": "arn:{p}:rds:{r}:{a}:subgrp:{id}",
    "AWS::RDS::DBParameterGroup": "arn:{p}:rds:{r}:{a}:pg:{id}", "AWS::RDS::DBClusterParameterGroup": "arn:{p}:rds:{r}:{a}:cluster-pg:{id}",
    "AWS::RDS::OptionGroup": "arn:{p}:rds:{r}:{a}:og:{id}", "AWS::Kinesis::Stream": "arn:{p}:kinesis:{r}:{a}:stream/{id}",
    "AWS::KinesisFirehose::DeliveryStream": "arn:{p}:firehose:{r}:{a}:deliverystream/{id}",
    "AWS::Athena::WorkGroup": "arn:{p}:athena:{r}:{a}:workgroup/{id}", "AWS::Glue::Job": "arn:{p}:glue:{r}:{a}:job/{id}",
    "AWS::Glue::Crawler": "arn:{p}:glue:{r}:{a}:crawler/{id}", "AWS::KMS::Key": "arn:{p}:kms:{r}:{a}:key/{id}",
    "AWS::KMS::Alias": "arn:{p}:kms:{r}:{a}:{id}", "AWS::CloudWatch::Alarm": "arn:{p}:cloudwatch:{r}:{a}:alarm:{id}",
    "AWS::ApiGateway::RestApi": "arn:{p}:apigateway:{r}::/restapis/{id}", "AWS::ApiGatewayV2::Api": "arn:{p}:apigateway:{r}::/apis/{id}",
    "AWS::Events::EventBus": "arn:{p}:events:{r}:{a}:event-bus/{id}", "AWS::CloudFront::Distribution": "arn:{p}:cloudfront::{a}:distribution/{id}",
    "AWS::Route53::HostedZone": "arn:{p}:route53:::hostedzone/{id}", "AWS::EFS::FileSystem": "arn:{p}:elasticfilesystem:{r}:{a}:file-system/{id}",
    "AWS::SSM::Parameter": "arn:{p}:ssm:{r}:{a}:parameter/{id_noslash}",
}
EC2_ID_TYPES = {"sg": "security-group", "subnet": "subnet", "rtb": "route-table", "igw": "internet-gateway", "acl": "network-acl",
                "dopt": "dhcp-options", "vpc": "vpc", "lt": "launch-template", "pl": "prefix-list", "eigw": "egress-only-internet-gateway",
                "eni": "network-interface", "i": "instance", "vol": "volume", "nat": "natgateway", "eipalloc": "elastic-ip",
                "vpce": "vpc-endpoint", "tgw-attach": "transit-gateway-attachment", "tgw-rtb": "transit-gateway-route-table",
                "tgw": "transit-gateway", "vpn": "vpn-connection", "cgw": "customer-gateway", "vgw": "vpn-gateway",
                "fl": "vpc-flow-log", "key": "key-pair", "snap": "snapshot", "ami": "image", "pcx": "vpc-peering-connection"}
EC2_ID = re.compile(r"^([a-z]+(?:-[a-z]+)?)-[0-9a-f]{8,17}$")


def cc_is_global(t: str) -> bool:
    parts = t.split("::")
    return t in CC_GLOBAL_TYPES or (len(parts) > 1 and parts[1] in CC_GLOBAL_NAMESPACES)


def cc_arn(t: str, ident: str, props: dict, region: str, account: str, partition: str) -> str:
    """The ARN of a Cloud Control result, built from its identifier when the list handler omits it."""
    for k in ("Arn", "ARN"):
        if str(props.get(k, "")).startswith("arn:"):
            return str(props[k])
    if ident.startswith("arn:"):
        return ident
    if t == "AWS::SQS::Queue" and ident.startswith("https://"):
        m = re.match(r"https://sqs\.([a-z0-9-]+)\.[^/]+/(\d+)/(.+)$", ident)
        return f"arn:{partition}:sqs:{m.group(1)}:{m.group(2)}:{m.group(3)}" if m else ""
    if t.startswith("AWS::EC2::"):
        m = EC2_ID.match(ident)
        if m and m.group(1) in EC2_ID_TYPES:
            acct = "" if m.group(1) in ("snap", "ami") else account
            return f"arn:{partition}:ec2:{region}:{acct}:{EC2_ID_TYPES[m.group(1)]}/{ident}"
    tpl = CC_ARN.get(t)
    if tpl and ident:
        return tpl.format(p=partition, a=account, r=region, id=ident, id_noslash=ident.lstrip("/"))
    return ""


def cc_aws_default(t: str, ident: str, props: dict) -> bool:
    """Objects AWS creates on its own in every account/region (never billed, never yours)."""
    name = str(props.get("Name") or props.get("DBParameterGroupName") or props.get("OptionGroupName")
               or props.get("CacheParameterGroupName") or props.get("PrefixListName") or props.get("AliasName")
               or props.get("GroupName") or ident)
    if t.endswith(("ParameterGroup", "OptionGroup")) and (name.startswith("default.") or name.startswith("default:")
                                                           or ident.startswith("default.") or ident.startswith("default:")):
        return True
    if t == "AWS::KMS::Alias" and (name.startswith("alias/aws/") or ident.startswith("alias/aws/")):
        return True
    if t in ("AWS::EC2::PrefixList", "AWS::EC2::ManagedPrefixList") and name.startswith("com.amazonaws."):
        return True
    if t == "AWS::SSM::Document" and re.match(r"^(AWS|Amazon)", name):
        return True
    if t == "AWS::EC2::SecurityGroup" and props.get("GroupName") == "default":
        return True
    if (t, name) in {("AWS::Events::EventBus", "default"), ("AWS::Athena::WorkGroup", "primary"),
                     ("AWS::Athena::DataCatalog", "AwsDataCatalog")}:
        return True
    return False


def _cloud_control(ctx: Ctx, types: list[str]) -> None:
    sc = ctx.scanner
    c = ctx.client("cloudcontrol")
    global_region = sc.home_region if sc.home_region in sc.regions else (sc.regions[0] if sc.regions else sc.home_region)
    covered = sum(1 for t in types if CC_COVERED.get(t) in sc.opts.services)
    todo = [t for t in types if CC_COVERED.get(t) not in sc.opts.services
            and (not cc_is_global(t) or ctx.region == global_region)]
    counts = {"ok": 0, "resources": 0, "unsupported": 0, "denied": 0, "error": 0, "defaults": 0}
    per_type: dict[str, int] = {}

    def one(t: str) -> None:
        try:
            items = list(ctx.pages(c, "list_resources", "ResourceDescriptions", TypeName=t))
        except Exception as e:
            status, _ = classify(e)
            counts["denied" if status == "denied" else "error" if status in ("error", "throttled", "timeout") else "unsupported"] += 1
            if status in ("skipped",):
                raise
            return
        counts["ok"] += 1
        region = "global" if cc_is_global(t) else ctx.region
        arn_region = "" if cc_is_global(t) else ctx.region
        for d in items:
            try:
                props = json.loads(d.get("Properties") or "{}")
            except ValueError:
                props = {}
            ident = str(d.get("Identifier", ""))
            if cc_aws_default(t, ident, props):
                counts["defaults"] += 1
                continue
            arn = cc_arn(t, ident, props, arn_region, ctx.account, ctx.partition)
            name = str(props.get("Name") or props.get("name") or props.get("RuleName") or "")
            tags = props.get("Tags") if isinstance(props.get("Tags"), dict) else {
                str(x.get("Key", "")): str(x.get("Value", "")) for x in (props.get("Tags") or []) if isinstance(x, dict)}
            generic(ctx, arn, region, t, "Cloud Control", tags=tags, name=name,
                    rid=arn or (ident if EC2_ID.match(ident) else f"{t}/{ident}"))
            counts["resources"] += 1
            per_type[t] = per_type.get(t, 0) + 1
    ctx.map(one, todo, workers=6)
    status = "ok" if counts["ok"] or not counts["denied"] else "denied"
    top = ", ".join(f"{t.split('::', 1)[1]} {n}" for t, n in sorted(per_type.items(), key=lambda kv: -kv[1])[:5])
    ctx.coverage("Cloud Control API", status,
                 f"{counts['resources']} resources from {counts['ok']}/{len(todo)} types · {covered} types left to direct collectors"
                 f" · {counts['defaults']} AWS-managed defaults skipped · {counts['unsupported']} not available"
                 f" · {counts['denied']} denied · {counts['error']} errors" + (f" · top: {top}" if top else ""))


@collector("Cloud Control", "discovery", client="cloudcontrol", actions=("cloudformation:ListResources",),
           desc=f"Cloud Control API over {len(CC_CURATED)} resource types not covered by direct collectors")
def cloud_control(ctx: Ctx) -> None:
    _cloud_control(ctx, CC_CURATED)


@collector("Cloud Control (all types)", "discovery", client="cloudcontrol", default=False,
           actions=("cloudformation:ListResources", "cloudformation:ListTypes"),
           desc="Every public resource type the CloudFormation registry lists (slow: hundreds of calls per region)")
def cloud_control_all(ctx: Ctx) -> None:
    cf = ctx.client("cloudformation")
    types = sorted({t["TypeName"] for t in ctx.pages(cf, "list_types", "TypeSummaries", Visibility="PUBLIC", Type="RESOURCE",
                                                       DeprecatedStatus="LIVE")})
    _cloud_control(ctx, types)


@collector("AWS Config inventory", "discovery", scope="global", client="config",
           actions=("config:DescribeConfigurationAggregators", "config:SelectAggregateResourceConfig",
                    "config:SelectResourceConfig", "config:DescribeConfigurationRecorderStatus"),
           desc="AWS Config's recorded inventory (across accounts and regions through an aggregator)")
def config_inventory(ctx: Ctx) -> None:
    query = ("SELECT resourceId, resourceName, resourceType, awsRegion, accountId, arn "
             "WHERE configurationItemStatus IN ('OK', 'ResourceDiscovered')")
    home = ctx.client("config", ctx.scanner.home_region)
    aggs = ctx.step("Config aggregators", lambda: ctx.call(home, "describe_configuration_aggregators").get("ConfigurationAggregators", [])) or []

    def ingest(rows) -> int:
        n = 0
        for raw in rows:
            x = json.loads(raw) if isinstance(raw, str) else raw
            arn = str(x.get("arn") or "")
            generic(ctx, arn, str(x.get("awsRegion") or ""), str(x.get("resourceType") or ""), "AWS Config",
                    name=str(x.get("resourceName") or ""), account=str(x.get("accountId") or ""),
                    rid=arn or f"{x.get('resourceType')}/{x.get('resourceId')}")
            n += 1
        return n
    if aggs:
        name = aggs[0]["ConfigurationAggregatorName"]
        n = ingest(ctx.pages(home, "select_aggregate_resource_config", "Results", Expression=query, ConfigurationAggregatorName=name))
        ctx.coverage("AWS Config inventory", "ok", f"{n} items via aggregator {name}", region="global")
        return

    def region(reg: str) -> None:
        c = ctx.client("config", reg)
        st = ctx.call(c, "describe_configuration_recorder_status").get("ConfigurationRecordersStatus", [])
        if not any(s.get("recording") for s in st):
            ctx.coverage("AWS Config inventory", "not-enabled", "No recording configuration recorder; no changes made", region=reg)
            return
        n = ingest(ctx.pages(c, "select_resource_config", "Results", Expression=query))
        ctx.coverage("AWS Config inventory", "ok", f"{n} recorded items", region=reg)
    for reg in ctx.scanner.regions:
        ctx.step("AWS Config inventory", lambda reg=reg: region(reg), region=reg)
