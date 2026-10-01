"""Networking: VPC, public IPv4, NAT, load balancers, API Gateway, CloudFront, Route 53, TGW, VPN,
Client VPN, Global Accelerator, Cloud Map, Direct Connect, Network Firewall."""
from __future__ import annotations

from ..models import HOURS_MONTH, Resource, name_from_tags, tags_to_dict
from ..pricing import RATES, region_note
from .base import Ctx, add_estimate, collector, monthly

GIB = 1024 ** 3
VPC_BILL = "Amazon Virtual Private Cloud"
EC2_OTHER = "EC2 - Other"
PUBLIC_IP_NOTE = "Public IPv4 $0.005/h (charged whether in use or idle)"


@collector("VPC", "network", bill=VPC_BILL, client="ec2",
           actions=("ec2:DescribeVpcs", "ec2:DescribeVpcEndpoints"),
           desc="VPCs (free) and VPC endpoints (interface endpoints priced per AZ)")
def vpc(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    for x in ctx.pages(c, "describe_vpcs", "Vpcs"):
        tags = tags_to_dict(x.get("Tags"))
        ctx.add(Resource("VPC", ctx.region, "vpc", x["VpcId"], name_from_tags(tags), x.get("State", "available"),
                         ctx.arn("ec2", f"vpc/{x['VpcId']}"), x.get("CidrBlock", "") + (" · default" if x.get("IsDefault") else ""),
                         tags, monthly_estimate=0.0,
                         estimate_note="VPC itself has no hourly charge; endpoints/NAT/IPAM/traffic may cost"))
    for x in ctx.pages(c, "describe_vpc_endpoints", "VpcEndpoints"):
        etype = x.get("VpcEndpointType", "")
        azs = len(x.get("SubnetIds", [])) or len(x.get("NetworkInterfaceIds", []))
        r = Resource("VPC", ctx.region, "vpc-endpoint", x["VpcEndpointId"], x.get("ServiceName", ""), x.get("State", ""),
                     ctx.arn("ec2", f"vpc-endpoint/{x['VpcEndpointId']}"), f"{etype} · {azs} AZ(s)", tags_to_dict(x.get("Tags")),
                     usage_family="VPC endpoints", created=str(x.get("CreationTimestamp", "")))
        r.relate("vpc", x.get("VpcId"))
        if etype in ("Gateway",):
            r.monthly_estimate, r.estimate_note = 0.0, "Gateway endpoints (S3/DynamoDB) are free"
        elif etype in ("Interface", "GatewayLoadBalancer", "Resource", "ServiceNetwork"):
            r.monthly_estimate = azs * RATES["vpce_interface_h"] * HOURS_MONTH
            r.estimate_note = f"{azs} AZ × ${RATES['vpce_interface_h']}/h{region_note(ctx.region)}; data processed excluded"
        ctx.add(r)


@collector("Elastic IP", "network", bill=VPC_BILL, usage="Public IPv4", client="ec2", actions=("ec2:DescribeAddresses",),
           desc="Elastic IPs, associated or idle")
def eip(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    for x in ctx.call(c, "describe_addresses").get("Addresses", []):
        tags = tags_to_dict(x.get("Tags"))
        aid = x.get("AllocationId", x.get("PublicIp", ""))
        r = Resource("Elastic IP", ctx.region, "elastic-ip", aid, name_from_tags(tags, x.get("PublicIp", "")),
                     "associated" if x.get("AssociationId") else "idle",
                     ctx.arn("ec2", f"elastic-ip/{aid}") if aid.startswith("eipalloc-") else "", x.get("PublicIp", ""), tags,
                     monthly_estimate=RATES["public_ipv4_h"] * HOURS_MONTH, estimate_note=PUBLIC_IP_NOTE)
        r.relate("instance", x.get("InstanceId"))
        r.relate("eni", x.get("NetworkInterfaceId"))
        r.details.update(public_ip=x.get("PublicIp"), associated=bool(x.get("AssociationId")),
                         owner=({"kind": "instance", "id": x["InstanceId"]} if x.get("InstanceId")
                                else {"kind": "eni", "id": x["NetworkInterfaceId"]} if x.get("NetworkInterfaceId")
                                else {"kind": "none", "id": ""}))
        ctx.add(r)


def ip_owner(eni: dict) -> dict:
    """Who holds a public address: the verdict of an IP follows its owner (NAT, load balancer, instance, task)."""
    import re
    kind, desc = eni.get("InterfaceType") or "interface", eni.get("Description") or ""
    att = eni.get("Attachment") or {}
    m = re.search(r"nat-[0-9a-f]+", desc)
    if kind == "nat_gateway" or m:
        return {"kind": "nat", "id": m.group(0) if m else ""}
    if desc.startswith("ELB "):
        return {"kind": "elb", "id": desc[4:].split("/")[1] if desc.count("/") >= 2 else desc[4:]}
    if att.get("InstanceId"):
        return {"kind": "instance", "id": att["InstanceId"]}
    if "arn:aws:ecs" in desc or "ecs" in str(eni.get("RequesterId", "")).lower():
        return {"kind": "ecs-task", "id": desc}
    if kind == "lambda":
        return {"kind": "lambda", "id": desc}
    return {"kind": "managed" if eni.get("RequesterManaged") else "other", "id": eni["NetworkInterfaceId"]}


@collector("Public IPv4", "network", bill=VPC_BILL, usage="Public IPv4", client="ec2", actions=("ec2:DescribeNetworkInterfaces",),
           desc="Every non-Elastic public IPv4 address (instances, load balancers, other managed ENIs)")
def public_ipv4(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    for eni in ctx.pages(c, "describe_network_interfaces", "NetworkInterfaces"):
        att = eni.get("Attachment") or {}
        kind = eni.get("InterfaceType") or "interface"
        owner = eni.get("RequesterId") or ""
        label = att.get("InstanceId") or eni.get("Description") or eni["NetworkInterfaceId"]
        for pip in eni.get("PrivateIpAddresses", []):
            assoc = pip.get("Association") or {}
            ip = assoc.get("PublicIp")
            if not ip or assoc.get("AllocationId"):
                continue        # Elastic IPs are counted by the Elastic IP collector
            r = Resource("Public IPv4", ctx.region, "public-ipv4", ip, f"{kind} · {label}"[:80], "in-use", "",
                         f"{kind} · {eni['NetworkInterfaceId']}" + (f" · {owner}" if owner and not owner.isdigit() else ""),
                         monthly_estimate=RATES["public_ipv4_h"] * HOURS_MONTH, estimate_note=PUBLIC_IP_NOTE)
            r.relate("eni", eni["NetworkInterfaceId"])
            r.relate("instance", att.get("InstanceId"))
            r.relate("vpc", eni.get("VpcId"))
            r.details.update(interface_type=kind, ip_owner=assoc.get("IpOwnerId"), description=eni.get("Description", ""),
                             owner=ip_owner(eni))
            ctx.add(r)


NAT_WINDOW = 30
# ENIs that never send traffic out through a NAT gateway.
NON_WORKLOAD_ENI = {"nat_gateway", "vpc_endpoint", "gateway_load_balancer_endpoint", "network_load_balancer"}


def nat_routing(ctx: Ctx, c, nats: list[dict]) -> dict[str, dict]:
    """Which route tables send traffic to each NAT, which subnets those tables serve (including the main
    table's implicit subnets) and how many workload ENIs sit in them."""
    vpcs = sorted({x.get("VpcId") for x in nats if x.get("VpcId")})
    if not vpcs:
        return {}
    flt = [{"Name": "vpc-id", "Values": vpcs}]
    tables = list(ctx.pages(c, "describe_route_tables", "RouteTables", Filters=flt))
    subnets = list(ctx.pages(c, "describe_subnets", "Subnets", Filters=flt))
    enis = list(ctx.pages(c, "describe_network_interfaces", "NetworkInterfaces", Filters=flt))
    explicit: dict[str, str] = {}
    main: dict[str, str] = {}
    for t in tables:
        for a in t.get("Associations", []):
            if a.get("Main"):
                main[t.get("VpcId", "")] = t["RouteTableId"]
            elif a.get("SubnetId"):
                explicit[a["SubnetId"]] = t["RouteTableId"]
    served: dict[str, set] = {}
    for s in subnets:
        table = explicit.get(s["SubnetId"]) or main.get(s.get("VpcId", ""))
        if table:
            served.setdefault(table, set()).add(s["SubnetId"])
    workload: dict[str, int] = {}
    for e in enis:
        if (e.get("InterfaceType") or "interface") in NON_WORKLOAD_ENI or str(e.get("Description", "")).startswith("ELB "):
            continue
        workload[e.get("SubnetId", "")] = workload.get(e.get("SubnetId", ""), 0) + 1
    out = {}
    for x in nats:
        nid = x["NatGatewayId"]
        rts = [t["RouteTableId"] for t in tables
               if any(rt.get("NatGatewayId") == nid and rt.get("State", "active") != "blackhole" for rt in t.get("Routes", []))]
        subs = sorted(set().union(*(served.get(t, set()) for t in rts))) if rts else []
        out[nid] = {"routed": bool(rts), "route_tables": rts, "subnets_served": subs,
                    "enis_behind": sum(workload.get(s, 0) for s in subs)}
    return out


@collector("NAT Gateway", "network", bill=EC2_OTHER, usage="NAT Gateway", client="ec2",
           actions=("ec2:DescribeNatGateways", "ec2:DescribeRouteTables", "ec2:DescribeSubnets",
                    "ec2:DescribeNetworkInterfaces", "cloudwatch:GetMetricData"),
           desc="NAT gateways: routing, workloads behind them, hours and 30 days of traffic")
def nat(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    hourly = ctx.prices.regional("AmazonEC2", ctx.region, {"productFamily": "NAT Gateway"},
                                 predicate=lambda a: str(a.get("usagetype", "")).endswith("NatGateway-Hours"))
    note = "" if hourly is not None else region_note(ctx.region)
    hourly = hourly if hourly is not None else RATES["nat_h"]
    nats = list(ctx.pages(c, "describe_nat_gateways", "NatGateways"))
    live = [x for x in nats if x.get("State") not in ("deleted", "deleting", "failed")]
    routing = (ctx.step("NAT routing", lambda: nat_routing(ctx, c, live)) or {}) if live else {}
    for x in nats:
        tags = tags_to_dict(x.get("Tags"))
        nid, state = x["NatGatewayId"], x.get("State", "")
        r = Resource("NAT Gateway", ctx.region, "nat-gateway", nid, name_from_tags(tags), state, ctx.arn("ec2", f"natgateway/{nid}"),
                     f"{x.get('ConnectivityType', 'public')} · {x.get('SubnetId', '')}", tags, created=str(x.get("CreateTime", "")))
        r.relate("vpc", x.get("VpcId"))
        r.relate("subnet", x.get("SubnetId"))
        r.relate("elastic-ip", *[a.get("AllocationId") for a in x.get("NatGatewayAddresses", [])])
        if state in ("deleted", "deleting", "failed"):
            r.monthly_estimate, r.estimate_note = 0.0, state.capitalize()
        else:
            r.monthly_estimate = hourly * HOURS_MONTH
            r.estimate_note = f"NAT hours ${hourly}/h{note}"
            r.details.update(routing.get(nid, {}), hourly=hourly)
            r.relate("route-table", *routing.get(nid, {}).get("route_tables", []))
            dims = {"NatGatewayId": nid}
            for metric in ("BytesInFromSource", "BytesInFromDestination"):     # bytes processed = data-processing charge
                def on_bytes(res: Resource, value: float | None, metric=metric) -> None:
                    if value:
                        gb_month = value / GIB / NAT_WINDOW * 30.4
                        add_estimate(res, gb_month * RATES["nat_gb"], f"{metric} ≈{gb_month:,.1f} GB/mo × ${RATES['nat_gb']}/GB")
                ctx.metric(r, f"nat_{metric}_30d", "AWS/NATGateway", metric, dims, days=NAT_WINDOW, on_value=on_bytes)
            ctx.metric(r, "nat_BytesOutToDestination_30d", "AWS/NATGateway", "BytesOutToDestination", dims, days=NAT_WINDOW)
            ctx.metric(r, "nat_ActiveConnectionCount_30d", "AWS/NATGateway", "ActiveConnectionCount", dims, stat="Maximum",
                       days=NAT_WINDOW)
        ctx.add(r)


@collector("ELB", "network", bill="Amazon Elastic Load Balancing", client="elbv2",
           actions=("elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeTargetGroups",
                    "elasticloadbalancing:DescribeTargetHealth", "cloudwatch:GetMetricData"),
           desc="ALB/NLB/GWLB (hours + LCUs from CloudWatch, target health) and Classic Load Balancers")
def elb(ctx: Ctx) -> None:
    c = ctx.client("elbv2")
    rn = region_note(ctx.region)
    lbs = list(ctx.pages(c, "describe_load_balancers", "LoadBalancers"))
    tgs = list(ctx.pages(c, "describe_target_groups", "TargetGroups")) if lbs else []

    def health(tg: dict) -> tuple[str, int, int]:
        desc = ctx.step("ELB target health", lambda: ctx.call(c, "describe_target_health", TargetGroupArn=tg["TargetGroupArn"]))
        targets = (desc or {}).get("TargetHealthDescriptions", [])
        healthy = sum(1 for t in targets if (t.get("TargetHealth") or {}).get("State") == "healthy")
        return tg["TargetGroupArn"], len(targets), healthy
    tg_health = {arn: (n, h) for arn, n, h in ctx.map(health, tgs)}

    for x in lbs:
        typ, arn = x.get("Type", ""), x["LoadBalancerArn"]
        hourly = {"application": RATES["alb_h"], "network": RATES["nlb_h"], "gateway": RATES["gwlb_h"]}.get(typ)
        mine = [tg for tg in tgs if arn in tg.get("LoadBalancerArns", [])]
        total = sum(tg_health.get(tg["TargetGroupArn"], (0, 0))[0] for tg in mine)
        healthy = sum(tg_health.get(tg["TargetGroupArn"], (0, 0))[1] for tg in mine)
        r = Resource("ELB", ctx.region, f"{typ}-load-balancer", x["LoadBalancerName"], x["LoadBalancerName"],
                     x.get("State", {}).get("Code", ""), arn, f"{x.get('Scheme', '')} · {healthy}/{total} healthy targets · {x.get('DNSName', '')}",
                     monthly_estimate=monthly(hourly), created=str(x.get("CreatedTime", "")),
                     estimate_note=f"{typ} LB-hours ${hourly}/h{rn}" if hourly else "Load balancer type not priced")
        r.details.update(targets=total, healthy_targets=healthy, target_groups=len(mine), scheme=x.get("Scheme"))
        r.relate("vpc", x.get("VpcId"))
        r.relate("target-group", *[tg["TargetGroupArn"] for tg in mine])
        r.relate("security-group", *x.get("SecurityGroups", []))
        if typ in ("application", "network"):
            dim = arn.split(":loadbalancer/", 1)[-1]
            ns = "AWS/ApplicationELB" if typ == "application" else "AWS/NetworkELB"
            rate = RATES["alb_lcu_h"] if typ == "application" else RATES["nlb_lcu_h"]

            def on_lcu(res: Resource, value: float | None, rate=rate) -> None:
                res.details["avg_lcu_14d"] = value
                if value:
                    add_estimate(res, value * rate * HOURS_MONTH, f"avg {value:.3f} LCU × ${rate}/LCU-h (14-day CloudWatch average)")
            ctx.metric(r, "avg_lcu_14d", ns, "ConsumedLCUs", {"LoadBalancer": dim}, stat="Average", on_value=on_lcu)
            # Work counters that exclude health checks; ELB only emits them when there is traffic.
            if typ == "application":
                ctx.metric(r, "lb_requests_14d", ns, "RequestCount", {"LoadBalancer": dim}, missing="zero")
            else:
                ctx.metric(r, "lb_new_flows_14d", ns, "NewFlowCount", {"LoadBalancer": dim}, missing="zero")
            ctx.metric(r, "lb_bytes_14d", ns, "ProcessedBytes", {"LoadBalancer": dim}, missing="zero")
        ctx.add(r)

    def classic():
        cl = ctx.client("elb")
        for x in ctx.pages(cl, "describe_load_balancers", "LoadBalancerDescriptions"):
            r = Resource("ELB", ctx.region, "classic-load-balancer", x["LoadBalancerName"], x["LoadBalancerName"], "active",
                         ctx.arn("elasticloadbalancing", f"loadbalancer/{x['LoadBalancerName']}"),
                         f"classic · {x.get('Scheme', '')} · {len(x.get('Instances', []))} instances",
                         monthly_estimate=RATES["clb_h"] * HOURS_MONTH, created=str(x.get("CreatedTime", "")),
                         estimate_note=f"Classic LB-hours ${RATES['clb_h']}/h{rn}; $0.008/GB processed excluded")
            r.details.update(targets=len(x.get("Instances", [])), healthy_targets=None)
            r.relate("instance", *[i.get("InstanceId") for i in x.get("Instances", [])])
            r.relate("vpc", x.get("VPCId"))
            ctx.metric(r, "lb_requests_14d", "AWS/ELB", "RequestCount", {"LoadBalancerName": x["LoadBalancerName"]}, missing="zero")
            ctx.add(r)
    ctx.step("Classic Load Balancers", classic)


@collector("API Gateway", "network", bill="Amazon API Gateway", client="apigateway",
           actions=("apigateway:GET",), desc="REST, HTTP and WebSocket APIs")
def apigw(ctx: Ctx) -> None:
    c = ctx.client("apigateway")
    for x in ctx.pages(c, "get_rest_apis", "items", PaginationConfig={"PageSize": 500}):
        r = Resource("API Gateway", ctx.region, "rest-api", x["id"], x["name"], "active",
                     f"arn:{ctx.partition}:apigateway:{ctx.region}::/restapis/{x['id']}", "REST",
                     tags=x.get("tags") or {}, created=str(x.get("createdDate", "")),
                     estimate_note="Request/data driven; use actual cost")
        # REST metrics are keyed by API *name*; only emitted when there are requests.
        ctx.metric(r, "api_requests_30d", "AWS/ApiGateway", "Count", {"ApiName": x["name"]}, days=30, missing="zero")
        ctx.add(r)

    def v2():
        c2 = ctx.client("apigatewayv2")
        for x in ctx.pages(c2, "get_apis", "Items"):
            r = Resource("API Gateway", ctx.region, "v2-api", x["ApiId"], x.get("Name", x["ApiId"]), "active",
                         f"arn:{ctx.partition}:apigateway:{ctx.region}::/apis/{x['ApiId']}", x.get("ProtocolType", ""),
                         tags=x.get("Tags") or {}, created=str(x.get("CreatedDate", "")),
                         estimate_note="Request/data driven; use actual cost")
            metric = "Count" if x.get("ProtocolType") == "HTTP" else "MessageCount"
            ctx.metric(r, "api_requests_30d", "AWS/ApiGateway", metric, {"ApiId": x["ApiId"]}, days=30, missing="zero")
            ctx.add(r)
    ctx.step("API Gateway v2", v2)


@collector("CloudFront", "network", scope="global", bill="Amazon CloudFront", client="cloudfront",
           actions=("cloudfront:ListDistributions",), desc="Distributions (all pages)")
def cloudfront(ctx: Ctx) -> None:
    c = ctx.client("cloudfront", "us-east-1")
    for x in ctx.pages(c, "list_distributions", "DistributionList.Items"):
        ctx.add(Resource("CloudFront", "global", "distribution", x["Id"], x.get("Comment") or x["DomainName"],
                         "deployed" if x.get("Status") == "Deployed" else x.get("Status", ""), x["ARN"],
                         f"{x['DomainName']} · {x.get('PriceClass', '')}" + ("" if x.get("Enabled", True) else " · disabled"),
                         estimate_note="Request/transfer driven; use actual cost"))


@collector("Route53", "network", scope="global", bill="Amazon Route 53", client="route53",
           actions=("route53:ListHostedZones", "route53:ListHealthChecks"),
           desc="Hosted zones and health checks")
def route53(ctx: Ctx) -> None:
    c = ctx.client("route53", "us-east-1")
    for x in ctx.pages(c, "list_hosted_zones", "HostedZones"):
        zid = x["Id"].split("/")[-1]
        private = (x.get("Config") or {}).get("PrivateZone")
        r = Resource("Route53", "global", "hosted-zone", zid, x["Name"], "active", f"arn:{ctx.partition}:route53:::hostedzone/{zid}",
                     f"{x.get('ResourceRecordSetCount', 0)} records{' · private' if private else ''}",
                     monthly_estimate=RATES["route53_zone_month"],
                     estimate_note="$0.50/zone-month (first 25 zones; $0.10 after); queries excluded",
                     details={"record_count": x.get("ResourceRecordSetCount", 0), "private": private})
        if not private:     # DNSQueries exists for public zones only, and only in us-east-1
            ctx.metric(r, "dns_queries_30d", "AWS/Route53", "DNSQueries", {"HostedZoneId": zid}, days=30, region="us-east-1")
        ctx.add(r)
    for h in ctx.pages(c, "list_health_checks", "HealthChecks"):
        cfg = h.get("HealthCheckConfig") or {}
        typ = cfg.get("Type", "")
        extras = sum([typ.startswith("HTTPS"), "STR_MATCH" in typ, cfg.get("RequestInterval") == 10, bool(cfg.get("MeasureLatency"))])
        est = RATES["route53_hc_month"] + extras * 1.0
        ctx.add(Resource("Route53", "global", "health-check", h["Id"], cfg.get("FullyQualifiedDomainName") or cfg.get("IPAddress") or h["Id"],
                         "active", f"arn:{ctx.partition}:route53:::healthcheck/{h['Id']}", typ, monthly_estimate=est,
                         estimate_note=f"$0.50 base (AWS endpoint) + {extras} optional feature(s) × $1; non-AWS endpoints cost $0.75 base"))


@collector("Route 53 Resolver", "network", bill="Amazon Route 53", client="route53resolver",
           actions=("route53resolver:ListResolverEndpoints",), desc="Inbound/outbound resolver endpoints ($0.125 per IP-hour)")
def resolver(ctx: Ctx) -> None:
    c = ctx.client("route53resolver")
    for x in ctx.pages(c, "list_resolver_endpoints", "ResolverEndpoints"):
        n = int(x.get("IpAddressCount") or 0)
        ctx.add(Resource("Route 53 Resolver", ctx.region, "resolver-endpoint", x["Id"], x.get("Name") or x["Id"],
                         str(x.get("Status", "")).lower(), x.get("Arn", ""), f"{x.get('Direction', '')} · {n} IPs",
                         monthly_estimate=n * 0.125 * HOURS_MONTH,
                         estimate_note=f"{n} ENI × $0.125/h{region_note(ctx.region)}; queries excluded"))


@collector("Transit Gateway", "network", bill=VPC_BILL, usage="Transit Gateway", client="ec2",
           actions=("ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayAttachments"),
           desc="Transit gateways and attachments ($/attachment-hour)")
def tgw(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    for x in ctx.pages(c, "describe_transit_gateways", "TransitGateways"):
        if x.get("State") == "deleted":
            continue
        ctx.add(Resource("Transit Gateway", ctx.region, "transit-gateway", x["TransitGatewayId"],
                         name_from_tags(tags_to_dict(x.get("Tags"))), x.get("State", ""), x.get("TransitGatewayArn", ""),
                         monthly_estimate=0.0, estimate_note="No charge for the gateway itself; attachments and data processed are billed"))
    for a in ctx.pages(c, "describe_transit_gateway_attachments", "TransitGatewayAttachments"):
        if a.get("State") in ("deleted", "deleting", "rejected", "failed"):
            continue
        aid = a["TransitGatewayAttachmentId"]
        r = Resource("Transit Gateway", ctx.region, "tgw-attachment", aid, name_from_tags(tags_to_dict(a.get("Tags"))),
                     a.get("State", ""), ctx.arn("ec2", f"transit-gateway-attachment/{aid}"),
                     f"{a.get('ResourceType', '')} · {a.get('ResourceId', '')}",
                     monthly_estimate=RATES["tgw_attach_h"] * HOURS_MONTH,
                     estimate_note=f"${RATES['tgw_attach_h']}/attachment-hour{region_note(ctx.region)}; $0.02/GB processed excluded")
        r.relate("transit-gateway", a.get("TransitGatewayId"))
        ctx.add(r)


@collector("VPN", "network", bill=VPC_BILL, usage="VPN", client="ec2",
           actions=("ec2:DescribeVpnConnections", "ec2:DescribeClientVpnEndpoints", "ec2:DescribeClientVpnTargetNetworks"),
           desc="Site-to-Site VPN connections and Client VPN endpoints")
def vpn(ctx: Ctx) -> None:
    c = ctx.client("ec2")
    for x in ctx.call(c, "describe_vpn_connections").get("VpnConnections", []):
        if x.get("State") in ("deleted", "deleting"):
            continue
        ctx.add(Resource("VPN", ctx.region, "vpn-connection", x["VpnConnectionId"], name_from_tags(tags_to_dict(x.get("Tags"))),
                         x.get("State", ""), ctx.arn("ec2", f"vpn-connection/{x['VpnConnectionId']}"),
                         f"{x.get('Type', '')} · {x.get('TransitGatewayId') or x.get('VpnGatewayId', '')}",
                         monthly_estimate=RATES["vpn_h"] * HOURS_MONTH,
                         estimate_note=f"${RATES['vpn_h']}/connection-hour{region_note(ctx.region)}; data transfer excluded"))

    def client_vpn():
        for x in ctx.pages(c, "describe_client_vpn_endpoints", "ClientVpnEndpoints"):
            eid = x["ClientVpnEndpointId"]
            nets = list(ctx.pages(c, "describe_client_vpn_target_networks", "ClientVpnTargetNetworks", ClientVpnEndpointId=eid))
            n = sum(1 for t in nets if (t.get("Status") or {}).get("Code") == "associated")
            ctx.add(Resource("VPN", ctx.region, "client-vpn-endpoint", eid, x.get("Description") or eid,
                             str((x.get("Status") or {}).get("Code", "")), ctx.arn("ec2", f"client-vpn-endpoint/{eid}"),
                             f"{n} associated subnet(s)", monthly_estimate=n * RATES["clientvpn_assoc_h"] * HOURS_MONTH,
                             estimate_note=f"{n} association(s) × ${RATES['clientvpn_assoc_h']}/h{region_note(ctx.region)}; $0.05/connection-hour excluded"))
    ctx.step("Client VPN", client_vpn)


@collector("Global Accelerator", "network", scope="global", bill="AWS Global Accelerator", client="globalaccelerator",
           actions=("globalaccelerator:ListAccelerators",), desc="Accelerators ($0.025/h fixed fee)")
def global_accelerator(ctx: Ctx) -> None:
    c = ctx.client("globalaccelerator", "us-west-2")      # the API only lives in us-west-2
    for x in ctx.pages(c, "list_accelerators", "Accelerators"):
        ctx.add(Resource("Global Accelerator", "global", "accelerator", x["AcceleratorArn"], x.get("Name", ""),
                         str(x.get("Status", "")).lower(), x["AcceleratorArn"], "enabled" if x.get("Enabled") else "disabled",
                         monthly_estimate=RATES["ga_h"] * HOURS_MONTH,
                         estimate_note="$0.025/h fixed fee; DT-Premium per GB excluded"))


@collector("Cloud Map", "network", bill="AWS Cloud Map", client="servicediscovery",
           actions=("servicediscovery:ListNamespaces", "servicediscovery:ListServices"),
           desc="Namespaces and services (registered instances $0.10/month)")
def cloud_map(ctx: Ctx) -> None:
    c = ctx.client("servicediscovery")
    for ns in ctx.pages(c, "list_namespaces", "Namespaces"):
        ctx.add(Resource("Cloud Map", ctx.region, "namespace", ns["Arn"], ns.get("Name", ""), "active", ns["Arn"], ns.get("Type", ""),
                         monthly_estimate=0.0, estimate_note="Namespace free; hosted zones it creates are billed under Route 53"))
    for s in ctx.pages(c, "list_services", "Services"):
        n = int(s.get("InstanceCount") or 0)
        ctx.add(Resource("Cloud Map", ctx.region, "service", s["Arn"], s.get("Name", ""), "active", s["Arn"], f"{n} instances",
                         monthly_estimate=n * 0.10, estimate_note=f"{n} registered instance(s) × $0.10/month; API calls excluded"))


@collector("Direct Connect", "network", bill="AWS Direct Connect", client="directconnect",
           actions=("directconnect:DescribeConnections",), desc="Dedicated connections (port-hours)")
def direct_connect(ctx: Ctx) -> None:
    c = ctx.client("directconnect")
    port = {"1Gbps": 0.30, "10Gbps": 2.25, "100Gbps": 22.50}
    for x in ctx.call(c, "describe_connections").get("connections", []):
        if x.get("connectionState") in ("deleted", "rejected"):
            continue
        rate = port.get(str(x.get("bandwidth", "")))
        ctx.add(Resource("Direct Connect", ctx.region, "connection", x["connectionId"], x.get("connectionName", ""),
                         x.get("connectionState", ""), "", f"{x.get('bandwidth', '')} · {x.get('location', '')}",
                         monthly_estimate=monthly(rate),
                         estimate_note=f"dedicated port ${rate}/h (US rate); data transfer out excluded" if rate else
                                       "Hosted connection: price depends on the partner"))


@collector("Network Firewall", "network", bill="AWS Network Firewall", client="network-firewall",
           actions=("network-firewall:ListFirewalls", "network-firewall:DescribeFirewall"),
           desc="Firewalls priced per endpoint (AZ)-hour")
def network_firewall(ctx: Ctx) -> None:
    c = ctx.client("network-firewall")
    for f in ctx.pages(c, "list_firewalls", "Firewalls"):
        d = ctx.call(c, "describe_firewall", FirewallArn=f["FirewallArn"]).get("Firewall", {})
        n = len(d.get("SubnetMappings", [])) or 1
        r = Resource("Network Firewall", ctx.region, "firewall", f["FirewallArn"], f.get("FirewallName", ""), "active", f["FirewallArn"],
                     f"{n} endpoint(s)", monthly_estimate=n * 0.395 * HOURS_MONTH,
                     estimate_note=f"{n} endpoint × $0.395/h{region_note(ctx.region)}; $0.065/GB processed excluded")
        r.relate("vpc", d.get("VpcId"))
        ctx.add(r)
