"""AI / ML: Bedrock (catalog + account resources), Bedrock AgentCore, SageMaker, Kendra."""
from __future__ import annotations

import hashlib
import json

from ..aws import classify, failed_action
from ..models import HOURS_MONTH, Resource
from ..pricing import RATES
from .base import Ctx, collector

BEDROCK_CALLS = [
    ("list_foundation_models", "modelSummaries", "foundation-model-catalog", "modelId", "modelName"),
    ("list_custom_models", "modelSummaries", "custom-model", "modelArn", "modelName"),
    ("list_imported_models", "modelSummaries", "imported-model", "modelArn", "modelName"),
    ("list_provisioned_model_throughputs", "provisionedModelSummaries", "provisioned-throughput", "provisionedModelArn", "provisionedModelName"),
    ("list_inference_profiles", "inferenceProfileSummaries", "inference-profile", "inferenceProfileArn", "inferenceProfileName"),
    ("list_guardrails", "guardrails", "guardrail", "arn", "name"),
    ("list_marketplace_model_endpoints", "marketplaceModelEndpoints", "marketplace-model-endpoint", "endpointArn", "endpointName"),
]
AGENT_CALLS = [
    ("list_agents", "agentSummaries", "agent", "agentId", "agentName"),
    ("list_knowledge_bases", "knowledgeBaseSummaries", "knowledge-base", "knowledgeBaseId", "name"),
    ("list_prompts", "promptSummaries", "prompt", "id", "name"),
    ("list_flows", "flowSummaries", "flow", "id", "name"),
]
CATALOG_TYPES = {"foundation-model-catalog", "inference-profile"}


def list_all(ctx: Ctx, client, op: str, key: str, **kw) -> list:
    if client.can_paginate(op):
        return list(ctx.pages(client, op, key, **kw))
    out, token = [], None
    for _ in range(100):
        resp = ctx.call(client, op, **kw, **({"nextToken": token} if token else {}))
        out.extend(resp.get(key, []) or [])
        token = resp.get("nextToken") or resp.get("NextToken")
        if not token:
            break
    return out


def _rid(x: dict, *keys: str) -> str:
    for k in keys:
        if x.get(k):
            return str(x[k])
    return hashlib.sha1(json.dumps(x, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _surface(ctx: Ctx, client, calls, prefix: str, bill: str, label: str = "Bedrock") -> int:
    n = 0
    for op, key, typ, idkey, namekey in calls:
        source = f"{prefix}.{op}"
        if not hasattr(client, op):
            ctx.coverage(source, "sdk-unsupported", "Upgrade boto3/botocore for this API")
            continue
        try:
            items = list_all(ctx, client, op, key)
        except Exception as e:
            status, detail = classify(e)
            ctx.coverage(source, status, detail, action=failed_action(e, client))
            if status in ("skipped", "timeout"):
                raise
            continue
        for x in items:
            rid = _rid(x, idkey, "modelId", "arn")
            cat = "catalog" if typ in CATALOG_TYPES else "resource"
            state = str(x.get("status") or (x.get("modelLifecycle") or {}).get("status") or ("available" if cat == "catalog" else "active"))
            note = ("Available Bedrock API/catalog entry; not counted as a deployed account resource" if cat == "catalog"
                    else "Provisioned throughput: billed per model unit-hour; see actual cost" if typ == "provisioned-throughput"
                    else "Bedrock account resource; actual charges come from Cost Explorer/usage")
            r = Resource(label, ctx.region, typ, rid, str(x.get(namekey) or x.get("modelName") or rid), state,
                         str(x.get("modelArn") or x.get("arn") or (rid if rid.startswith("arn:") else "")),
                         json.dumps(x, default=str)[:500], estimate_note=note, category=cat, bill_service=bill,
                         created=str(x.get("createdAt") or x.get("creationTime") or ""))
            if typ == "agent-runtime" and r.arn:
                # Dimension names for AgentCore are not confirmed, so an empty series stays "unknown".
                ctx.metric(r, "agentcore_invocations_30d", "AWS/Bedrock-AgentCore", "Invocations", {"Resource": r.arn}, days=30)
            ctx.add(r, source)
            n += 1
        ctx.coverage(source, "ok", f"{len(items)} items")
    return n


@collector("Bedrock", "ai", bill="Amazon Bedrock", client="bedrock",
           actions=("bedrock:ListFoundationModels", "bedrock:ListCustomModels", "bedrock:ListImportedModels",
                    "bedrock:ListProvisionedModelThroughputs", "bedrock:ListInferenceProfiles", "bedrock:ListGuardrails",
                    "bedrock:ListMarketplaceModelEndpoints", "bedrock:ListAgents", "bedrock:ListKnowledgeBases",
                    "bedrock:ListPrompts", "bedrock:ListFlows"),
           desc="Model catalog (kept separate from inventory), custom/imported models, provisioned throughput, agents, knowledge bases")
def bedrock(ctx: Ctx) -> None:
    n = _surface(ctx, ctx.client("bedrock"), BEDROCK_CALLS, "Bedrock", "Amazon Bedrock")
    n += _surface(ctx, ctx.client("bedrock-agent"), AGENT_CALLS, "BedrockAgent", "Amazon Bedrock")
    ctx.coverage("Bedrock deep scan", "ok", f"{n} catalog/account items")


@collector("Bedrock AgentCore", "ai", bill="Amazon Bedrock AgentCore", client="bedrock-agentcore-control",
           actions=("bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore:ListMemories", "bedrock-agentcore:ListGateways"),
           desc="Agent runtimes, memories, gateways, browsers and code interpreters")
def agentcore(ctx: Ctx) -> None:
    c = ctx.client("bedrock-agentcore-control")
    calls = [("list_agent_runtimes", "agentRuntimes", "agent-runtime", "agentRuntimeArn", "agentRuntimeName"),
             ("list_memories", "memories", "memory", "arn", "id"),
             ("list_gateways", "items", "gateway", "gatewayId", "name"),
             ("list_browsers", "browserSummaries", "browser", "browserArn", "name"),
             ("list_code_interpreters", "codeInterpreterSummaries", "code-interpreter", "codeInterpreterArn", "name")]
    _surface(ctx, c, calls, "AgentCore", "Amazon Bedrock AgentCore", label="Bedrock AgentCore")


@collector("SageMaker", "ai", bill="Amazon SageMaker", client="sagemaker",
           actions=("sagemaker:ListEndpoints", "sagemaker:DescribeEndpoint", "sagemaker:DescribeEndpointConfig",
                    "sagemaker:ListNotebookInstances", "sagemaker:ListApps", "pricing:GetProducts"),
           desc="Real-time endpoints and notebook instances priced per instance-hour; running Studio apps")
def sagemaker(ctx: Ctx) -> None:
    c = ctx.client("sagemaker")

    def price(itype: str, component: str) -> float | None:
        return ctx.prices.regional("AmazonSageMaker", ctx.region, {"instanceName": itype},
                                   predicate=lambda a: component in str(a.get("usagetype", "")))
    for e in ctx.pages(c, "list_endpoints", "Endpoints"):
        d = ctx.call(c, "describe_endpoint", EndpointName=e["EndpointName"])
        cfg = ctx.step("SageMaker endpoint config", lambda: ctx.call(c, "describe_endpoint_config", EndpointConfigName=d["EndpointConfigName"])) or {}
        types = {v["VariantName"]: v for v in cfg.get("ProductionVariants", [])}
        r = Resource("SageMaker", ctx.region, "endpoint", e["EndpointArn"], e["EndpointName"], str(e.get("EndpointStatus", "")).lower(),
                     e["EndpointArn"], "", created=str(e.get("CreationTime", "")))
        parts, total, unknown = [], 0.0, False
        for v in d.get("ProductionVariants", []):
            spec = types.get(v.get("VariantName"), {})
            itype, n = spec.get("InstanceType"), int(v.get("CurrentInstanceCount") or 0)
            if spec.get("ServerlessConfig"):
                parts.append("serverless variant (per request)")
                continue
            p = price(itype, "Host:") if itype else None
            parts.append(f"{n} × {itype}")
            if p is None:
                unknown = True
            else:
                total += p * n * HOURS_MONTH
        r.config = ", ".join(parts)
        if total:
            r.monthly_estimate, r.estimate_note = total, "Real-time endpoint instance-hours" + ("; some variants unpriced" if unknown else "")
        else:
            r.estimate_note = "Instance pricing lookup unavailable" if unknown else "Serverless inference: billed per request"
        ctx.add(r)
    for nb in ctx.pages(c, "list_notebook_instances", "NotebookInstances"):
        status = nb.get("NotebookInstanceStatus", "")
        p = price(nb.get("InstanceType", ""), "Notebk") if status == "InService" else 0.0
        ctx.add(Resource("SageMaker", ctx.region, "notebook-instance", nb["NotebookInstanceArn"], nb["NotebookInstanceName"], status.lower(),
                         nb["NotebookInstanceArn"], nb.get("InstanceType", ""), monthly_estimate=None if p is None else p * HOURS_MONTH,
                         estimate_note="Stopped: $0 (attached storage still billed)" if status != "InService"
                                       else "Notebook instance-hours" if p is not None else "Instance pricing lookup unavailable"))

    def apps():
        for a in ctx.pages(c, "list_apps", "Apps"):
            if a.get("Status") != "InService":
                continue
            itype = (a.get("ResourceSpec") or {}).get("InstanceType", "")
            ctx.add(Resource("SageMaker", ctx.region, "studio-app", f"{a.get('DomainId')}/{a.get('UserProfileName') or a.get('SpaceName')}/{a['AppName']}",
                             a["AppName"], "inservice", "", f"{a.get('AppType', '')} · {itype}",
                             estimate_note="Running Studio app: billed per instance-hour until shut down"))
    ctx.step("SageMaker Studio apps", apps)


@collector("Kendra", "ai", bill="Amazon Kendra", client="kendra", actions=("kendra:ListIndices",),
           desc="Indexes (Developer ~$810/mo, Enterprise ~$1,008/mo)")
def kendra(ctx: Ctx) -> None:
    c = ctx.client("kendra")
    for x in ctx.pages(c, "list_indices", "IndexConfigurationSummaryItems"):
        edition = x.get("Edition", "")
        rate = RATES["kendra_dev_h"] if edition == "DEVELOPER_EDITION" else RATES["kendra_ent_h"] if edition == "ENTERPRISE_EDITION" else None
        ctx.add(Resource("Kendra", ctx.region, "index", x["Id"], x.get("Name", ""), str(x.get("Status", "")).lower(),
                         ctx.arn("kendra", f"index/{x['Id']}"), edition, monthly_estimate=None if rate is None else rate * HOURS_MONTH,
                         estimate_note=f"{edition} base ${rate}/h; extra capacity units excluded" if rate else "Edition pricing varies; use actual cost",
                         created=str(x.get("CreatedAt", ""))))
