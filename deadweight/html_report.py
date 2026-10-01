"""Self-contained HTML report: one file, no external assets, light/dark, printable.

Layout follows the questions a reader brings to a cost report, in order: what does it cost, where does
the money go, what is it attached to, what is doing nothing, what to do about it, and how complete the
data is. Every chart has a data table next to it; tooltips only repeat what is reachable elsewhere."""
from __future__ import annotations

import html as _html
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone

from .billing import SPECIAL, explained_totals
from .models import Resource, ScanResult

# Usage states → (label, css token, glyph). Status colours carry meaning, so each also has a glyph and a label.
STATES = [
    ("active", "Working", "good", "●"),
    ("low-use", "Low use", "warning", "◐"),
    ("idle", "Idle", "serious", "○"),
    ("stopped-billed", "Stopped, still billed", "serious", "■"),
    ("orphaned", "Orphaned", "critical", "✕"),
    ("stale", "Stale", "muted", "◌"),
    ("clutter", "Unused, free", "muted", "·"),
    ("unknown", "Not evaluated", "neutral", "?"),
]
STATE = {k: (label, tone, glyph) for k, label, tone, glyph in STATES}
WASTE = {"idle", "stopped-billed", "orphaned"}
WORKING = {"active", "low-use"}
SEV = {"high": ("▲", "critical"), "medium": ("◆", "serious"), "low": ("●", "neutral"), "info": ("○", "neutral")}
# Findings rules that imply a state when the scan predates the state engine.
RULE_STATE = {"ebs-unattached": "orphaned", "eip-idle": "orphaned", "lb-no-targets": "orphaned", "route53-empty-zone": "orphaned",
              "nat-idle": "idle", "ec2-idle": "idle", "rds-idle": "idle", "ec2-stopped": "stopped-billed",
              "transfer-stopped": "stopped-billed", "pca-disabled": "stopped-billed", "kms-disabled": "stopped-billed",
              "secret-unused": "stale", "snapshot-old": "stale", "rds-snapshot-old": "stale", "logs-no-retention": "stale"}


def e(x) -> str:
    return _html.escape("" if x is None else str(x), quote=True)


def m(v: float | None, cents: bool | None = None) -> str:
    if v is None:
        return "n/a"
    if cents is None:
        cents = abs(v) < 1000
    if 0 < abs(v) < 0.005:
        return "<$0.01"
    return f"-${abs(v):,.{2 if cents else 0}f}" if v < 0 else f"${v:,.{2 if cents else 0}f}"


def pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v * 100:.0f}%"


# ── data shaping ─────────────────────────────────────────────────────────────

def state_of(r: Resource) -> str:
    s = getattr(r, "usage_state", "") or ""
    if s:
        return "unknown" if s == "unattributed" else s
    rules = (r.details or {}).get("findings") or []
    for rule in rules:
        if rule in RULE_STATE:
            return RULE_STATE[rule]
    return "unknown"


def monthly_value(r: Resource, factor: float) -> float:
    """Per-resource monthly money: CUR actual (scaled to the month) when present, else the list-price estimate."""
    if r.actual_mtd is not None:
        return max(0.0, r.actual_mtd * factor)
    return max(0.0, r.monthly_estimate or 0.0)


def shape(res: ScanResult) -> dict:
    actual = sum(c.actual_mtd for c in res.costs)
    run = sum(c.projected_month for c in res.costs)
    factor = (run / actual) if actual else 1.0
    est, base = explained_totals(res.reconciliation)
    resources = [r for r in res.resources if r.category == "resource"]
    states = {id(r): state_of(r) for r in resources}
    by_bill: dict[str, list[Resource]] = defaultdict(list)
    for r in resources:
        by_bill[r.bill_service].append(r)

    # money flow: bill line → state
    flows: dict[tuple[str, str], float] = defaultdict(float)
    scaled: dict[int, float] = {}        # per-resource money capped at its bill line, so every section adds up the same way
    lines = []
    for row in sorted(res.reconciliation, key=lambda x: x["run_rate"], reverse=True):
        rr = row["run_rate"]
        if rr < 0.01:
            continue
        lines.append(row)
    top = lines[:8]
    rest = lines[8:]
    for row in lines:
        label = row["label"] if row in top else "Other services"
        rr = row["run_rate"]
        if row["status"] in set(SPECIAL.values()):
            flows[(label, "fees")] += rr
            continue
        vals: dict[str, float] = defaultdict(float)
        for r in by_bill.get(row["bill"], []):
            v = monthly_value(r, factor)
            if v:
                vals[states[id(r)]] += v
        tied = sum(vals.values())
        scale = rr / tied if tied > rr and tied else 1.0
        for r in by_bill.get(row["bill"], []):
            scaled[id(r)] = monthly_value(r, factor) * scale
        for st, v in vals.items():
            flows[(label, st)] += v * scale
        if rr - tied * scale > 0.005:
            flows[(label, "untied")] += rr - tied * scale
    state_money: dict[str, float] = defaultdict(float)
    for (_, st), v in flows.items():
        state_money[st] += v

    counts = Counter(states.values())
    billed = lambda r: monthly_value(r, factor) >= 0.5
    quad = {"billed-working": [0, 0.0], "billed-idle": [0, 0.0], "free-working": [0, 0.0], "free-idle": [0, 0.0]}
    for r in resources:
        st = states[id(r)]
        if st == "unknown":
            continue
        working = st in WORKING
        key = ("billed" if billed(r) else "free") + "-" + ("working" if working else "idle")
        quad[key][0] += 1
        quad[key][1] += scaled.get(id(r), monthly_value(r, factor))
    savings = sum((f.monthly_savings or 0) for f in res.findings if f.category != "commitment")
    evaluated = sum(n for st, n in counts.items() if st != "unknown")
    return {"evaluated": evaluated, "actual": actual, "run": run, "factor": factor, "est": est, "base": base, "explained": est / base if base else None,
            "flows": flows, "left": [r["label"] for r in top] + (["Other services"] if rest else []),
            "state_money": state_money, "counts": counts, "quad": quad, "savings": savings, "resources": resources,
            "states": states, "waste": sum(state_money.get(s, 0) for s in WASTE)}


# ── charts ───────────────────────────────────────────────────────────────────

def sankey(d: dict) -> str:
    flows = {k: v for k, v in d["flows"].items() if v > 0.005}
    if not flows:
        return '<p class="empty">No billed spend in this period.</p>'
    left = [l for l in d["left"] if any(k[0] == l for k in flows)]
    right_order = [k for k, *_ in STATES] + ["untied", "fees"]
    right = [r for r in right_order if any(k[1] == r for k in flows)]
    lval = {l: sum(v for (a, _), v in flows.items() if a == l) for l in left}
    rval = {r: sum(v for (_, b), v in flows.items() if b == r) for r in right}
    total = sum(lval.values())
    W, x0, x1, nw = 960, 210, 730, 12
    gap, minh, slot_min = 6, 3, 18       # small nodes keep an 18px slot so their labels never collide
    k = 300 / total

    def stack(names, vals):
        pos, y = {}, 10
        for n in names:
            h = max(minh, vals[n] * k)
            pos[n] = [y, h, y]           # top, height, cursor for link placement
            y += max(h, slot_min) + gap
        return pos, y
    (lp, lend), (rp, rend) = stack(left, lval), stack(right, rval)
    H = max(lend, rend) + 4
    parts = [f'<svg class="sankey" viewBox="0 0 {W} {H:.0f}" role="img" aria-label="Monthly run-rate by bill line, split by what the money is attached to">']
    for (a, b) in sorted(flows, key=lambda t: (left.index(t[0]), right.index(t[1]))):
        v = flows[(a, b)]
        h = max(1.0, v * k)
        ya, yb = lp[a][2], rp[b][2]
        lp[a][2] += h
        rp[b][2] += h
        cx = (x0 + nw + x1) / 2
        path = (f"M{x0 + nw},{ya:.1f} C{cx},{ya:.1f} {cx},{yb:.1f} {x1},{yb:.1f} L{x1},{yb + h:.1f} "
                f"C{cx},{yb + h:.1f} {cx},{ya + h:.1f} {x0 + nw},{ya + h:.1f} Z")
        parts.append(f'<path class="link t-{_tone(b)}" d="{path}" data-tip="{e(a)} → {e(_rlabel(b))}&#10;{m(v)} / month"/>')
    for n in left:
        y, h, _ = lp[n]
        parts.append(f'<rect class="node" x="{x0}" y="{y:.1f}" width="{nw}" height="{h:.1f}" rx="2" data-tip="{e(n)}&#10;{m(lval[n])} / month"/>')
        parts.append(f'<text class="lbl" x="{x0 - 8}" y="{y + max(h, 18) / 2:.1f}" text-anchor="end" dominant-baseline="middle">{e(_trunc(n, 26))}'
                     f'<tspan class="val"> {m(lval[n], False if lval[n] >= 100 else None)}</tspan></text>')
    for n in right:
        y, h, _ = rp[n]
        parts.append(f'<rect class="node t-{_tone(n)}" x="{x1}" y="{y:.1f}" width="{nw}" height="{h:.1f}" rx="2" data-tip="{e(_rlabel(n))}&#10;{m(rval[n])} / month · {rval[n] / total:.0%}"/>')
        parts.append(f'<text class="lbl" x="{x1 + nw + 8}" y="{y + max(h, 18) / 2:.1f}" dominant-baseline="middle">{e(_glyph(n))} {e(_rlabel(n))}'
                     f'<tspan class="val"> {m(rval[n], False if rval[n] >= 100 else None)} · {rval[n] / total:.0%}</tspan></text>')
    parts.append("</svg>")
    rows = "".join(f"<tr><td>{e(a)}</td><td>{e(_rlabel(b))}</td><td class=n>{m(v)}</td></tr>"
                   for (a, b), v in sorted(flows.items(), key=lambda kv: -kv[1]))
    return "".join(parts) + _table_view(["Bill line", "Attached to", "Per month"], rows)


def _rlabel(k: str) -> str:
    return {"untied": "Not tied to a priced resource", "fees": "Tax, support and fees"}.get(k, STATE.get(k, (k,))[0])


def _tone(k: str) -> str:
    return {"untied": "faint", "fees": "faint"}.get(k, STATE.get(k, ("", "neutral"))[1])


def _glyph(k: str) -> str:
    return {"untied": "–", "fees": "§"}.get(k, STATE.get(k, ("", "", "·"))[2])


def _trunc(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _table_view(headers: list[str], rows_html: str) -> str:
    head = "".join(f"<th{' class=n' if i else ''}>{e(h)}</th>" if i == len(headers) - 1 else f"<th>{e(h)}</th>" for i, h in enumerate(headers))
    return f'<details class="tv"><summary>Data table</summary><table><thead><tr>{head}</tr></thead><tbody>{rows_html}</tbody></table></details>'


def quadrant(d: dict) -> str:
    q = d["quad"]
    unknown = d["counts"].get("unknown", 0)
    if d["evaluated"] < max(3, 0.05 * len(d["resources"])):
        return ""      # (almost) no activity data, e.g. an older report: a grid of zeros says nothing

    def cell(key: str, title: str, note: str, hot: bool = False) -> str:
        return (f'<div class="q{" hot" if hot else ""}"><div class="qt">{e(title)}</div>'
                f'<div class="qv">{m(q[key][1], False)}<span>/mo</span></div><div class="qn">{q[key][0]:,} resources · {e(note)}</div></div>')
    grid = ('<div class="quad"><div></div><div class="qh">Doing work</div><div class="qh">Doing nothing</div>'
            '<div class="qr">Costs money</div>' + cell("billed-working", "Billed and working", "expected")
            + cell("billed-idle", "Billed, doing nothing", "idle, orphaned, stopped or stale", hot=True)
            + '<div class="qr">About free</div>' + cell("free-working", "Free and working", "pay-per-use")
            + cell("free-idle", "Free, doing nothing", "clutter to tidy") + '</div>')
    note = f'<p class="note">{unknown:,} resources have no activity signal yet and are left out of this grid.</p>' if unknown else ""
    return grid + note


def spend_bars(res: ScanResult) -> str:
    rows = [r for r in sorted(res.reconciliation, key=lambda x: x["run_rate"], reverse=True) if r["run_rate"] >= 0.01][:14]
    if not rows:
        return '<p class="empty">No billed spend in this period.</p>'
    vmax = max(r["run_rate"] for r in rows)
    out = ['<div class="bars">']
    for r in rows:
        run = r["run_rate"]
        exp = min(run, r["estimate"] or 0.0) if r["status"] not in set(SPECIAL.values()) else 0.0
        w1, w2 = exp / vmax * 78, (run - exp) / vmax * 78       # leave room for the value label
        status = r["status"]
        tip = f"{r['label']}\nrun-rate {m(run)}\nestimated {m(r['estimate'])} · {status}"
        segs = []
        if w1 >= 0.05:
            segs.append(f'<span class="s1" style="width:{w1:.2f}%;border-radius:{"0" if w2 >= 0.05 else "0 4px 4px 0"}"></span>')
        if w2 >= 0.05:
            segs.append(f'<span class="s2" style="width:{w2:.2f}%"></span>')
        out.append(
            f'<div class="bar-row" data-tip="{e(tip)}"><div class="bl">{e(_trunc(r["label"], 34))}</div>'
            f'<div class="bt">{"".join(segs)}<span class="bv">{m(run)}</span></div>'
            f'<div class="bs {e(status.replace(" ", "-"))}">{e(status)}</div></div>')
    out.append('</div><div class="legend"><span><i class="k1"></i>explained by priced resources</span>'
               '<span><i class="k2"></i>not explained (usage, data transfer or not inventoried)</span></div>')
    rows_html = "".join(f"<tr><td>{e(r['label'])}</td><td class=n>{m(r['actual'])}</td><td class=n>{m(r['run_rate'])}</td>"
                        f"<td class=n>{m(r['estimate'])}</td><td>{e(r['status'])}</td></tr>"
                        for top in res.reconciliation for r in [top] + top["children"])
    head = "<tr><th>Bill line</th><th class=n>Actual</th><th class=n>Run-rate</th><th class=n>Estimated</th><th>Status</th></tr>"
    out.append(f'<details class="tv"><summary>Data table</summary><table><thead>{head}</thead><tbody>{rows_html}</tbody></table></details>')
    return "".join(out)


def daily_chart(res: ScanResult) -> str:
    pts = [(d, v) for d, v in res.daily]
    if len(pts) < 2:
        return ""
    W, H, L, R, T, B = 960, 220, 56, 16, 16, 28
    vmax = max(v for _, v in pts) or 1.0
    step = 10 ** math.floor(math.log10(vmax)) if vmax >= 1 else 0.1
    top = math.ceil(vmax / step) * step
    xs = lambda i: L + (W - L - R) * i / (len(pts) - 1)
    ys = lambda v: T + (H - T - B) * (1 - v / top)
    grid = "".join(f'<line class="grid" x1="{L}" x2="{W - R}" y1="{ys(t):.1f}" y2="{ys(t):.1f}"/>'
                   f'<text class="tick" x="{L - 8}" y="{ys(t):.1f}" text-anchor="end" dominant-baseline="middle">{m(t, False)}</text>'
                   for t in (0, top / 2, top))
    line = " ".join(f"{xs(i):.1f},{ys(v):.1f}" for i, (_, v) in enumerate(pts))
    area = f"{xs(0):.1f},{ys(0):.1f} {line} {xs(len(pts) - 1):.1f},{ys(0):.1f}"
    labels = "".join(f'<text class="tick" x="{xs(i):.1f}" y="{H - 8}" text-anchor="middle">{e(pts[i][0][5:])}</text>'
                     for i in sorted({0, len(pts) // 2, len(pts) - 1}))
    lx, ly = xs(len(pts) - 1), ys(pts[-1][1])
    data = json.dumps([[d, round(v, 2)] for d, v in pts])
    svg = (f'<svg class="daily" viewBox="0 0 {W} {H}" role="img" aria-label="Daily spend, last {len(pts)} days" data-series=\'{e(data)}\' '
           f'data-geom="{L},{R},{T},{B},{top}">{grid}<polygon class="area" points="{area}"/><polyline class="line" points="{line}"/>'
           f'<circle class="end" cx="{lx:.1f}" cy="{ly:.1f}" r="4"/>{labels}<line class="xhair" x1="0" x2="0" y1="{T}" y2="{H - B}"/>'
           f'<rect class="hit" x="{L}" y="{T}" width="{W - L - R}" height="{H - T - B}"/></svg>')
    rows = "".join(f"<tr><td>{e(d)}</td><td class=n>{m(v)}</td></tr>" for d, v in pts)
    return svg + _table_view(["Day", "Spend"], rows)


def topology(res: ScanResult, d: dict) -> str:
    rs = d["resources"]
    by_id = {r.resource_id: r for r in rs}
    vpcs = [r for r in rs if r.service == "VPC" and r.resource_type == "vpc"]
    in_vpc = lambda r, v: v in (r.relations.get("vpc") or [])
    blocks = []
    for v in vpcs:
        vid = v.resource_id
        nats = [r for r in rs if r.service == "NAT Gateway" and in_vpc(r, vid) and r.state not in ("deleted", "failed")]
        lbs = [r for r in rs if r.service == "ELB" and in_vpc(r, vid)]
        ips = [r for r in rs if r.service == "Public IPv4" and in_vpc(r, vid)]
        eps = [r for r in rs if r.service == "VPC" and r.resource_type == "vpc-endpoint" and in_vpc(r, vid)]
        ec2 = [r for r in rs if r.service == "EC2" and in_vpc(r, vid)]
        if not (nats or lbs or ips or eps):
            continue
        cost = sum(monthly_value(r, d["factor"]) for r in nats + lbs + ips + eps)
        blocks.append((cost, v, nats, lbs, ips, eps, ec2))
    if not blocks:
        return ""
    blocks.sort(key=lambda b: -b[0])
    out = []
    for cost, v, nats, lbs, ips, eps, ec2 in blocks[:4]:
        cols = [("Ingress · load balancers", [_lb_node(r) for r in lbs]),
                ("Egress · NAT gateways", [_nat_node(r, by_id, d) for r in nats]),
                ("Addresses and endpoints", _misc_nodes(ips, eps, ec2, d))]
        rows = max(1, max(len(c[1]) for c in cols))
        NW, NH, GX, GY = 270, 58, 30, 14
        W = 40 + 3 * NW + 2 * GX + 40
        top = 92
        H = top + rows * (NH + GY) + 40
        svg = [f'<svg class="topo" viewBox="0 0 {W} {H}" role="img" aria-label="Network resources in {e(v.name or v.resource_id)}">',
               f'<rect class="inet" x="{W / 2 - 70}" y="6" width="140" height="28" rx="14"/>'
               f'<text class="nt" x="{W / 2}" y="20" text-anchor="middle" dominant-baseline="middle">Internet</text>',
               f'<rect class="vpc" x="20" y="52" width="{W - 40}" height="{H - 62}" rx="10"/>'
               f'<text class="vt" x="34" y="{H - 20}">{e(v.name or v.resource_id)} · {e(v.config)} · {e(v.region)} · {m(cost)}/mo in network resources</text>']
        for ci, (title, nodes) in enumerate(cols):
            x = 40 + ci * (NW + GX)
            svg.append(f'<text class="ct" x="{x}" y="{top - 4}">{e(title)}</text>')
            linked = [n for n in nodes if n[4]]
            if linked:   # one connector per column: these resources face the internet
                hot = all(n[3] in ("serious", "critical") for n in linked)
                svg.append(f'<path class="edge{" t-serious" if hot else ""}" d="M{x + NW / 2},{top - 18} C{x + NW / 2},{44} {W / 2},{60} {W / 2},{34}"/>')
            for ri, (label, sub, money_, tone, link) in enumerate(nodes):
                y = top + 6 + ri * (NH + GY)
                svg.append(f'<rect class="n t-{tone}" x="{x}" y="{y}" width="{NW}" height="{NH}" rx="6" data-tip="{e(label)}&#10;{e(sub)}&#10;{e(money_)}"/>'
                           f'<rect class="stripe t-{tone}" x="{x}" y="{y}" width="4" height="{NH}" rx="2"/>'
                           f'<text class="nt" x="{x + 14}" y="{y + 20}">{e(_trunc(label, 30))}</text>'
                           f'<text class="ns" x="{x + 14}" y="{y + 40}">{e(_trunc(sub, 34))}</text>'
                           f'<text class="nm" x="{x + NW - 10}" y="{y + 20}" text-anchor="end">{e(money_)}</text>')
        svg.append("</svg>")
        out.append("".join(svg))
    more = f'<p class="note">{len(blocks) - 4} more VPCs are listed in the CSV export.</p>' if len(blocks) > 4 else ""
    return "".join(out) + more


def _state_tone(r: Resource, d: dict) -> str:
    return STATE.get(d["states"].get(id(r), "unknown"), ("", "neutral"))[1]


def _lb_node(r: Resource):
    t, h = r.details.get("targets"), r.details.get("healthy_targets")
    sub = f"{r.resource_type.replace('-load-balancer', '')} · " + (f"{h}/{t} healthy targets" if t is not None else "targets unknown")
    tone = "critical" if t == 0 else "neutral"
    return (r.name or r.resource_id, sub, f"{m(r.monthly_estimate)}/mo", tone, (r.details.get("scheme") != "internal"))


def _nat_node(r: Resource, by_id: dict, d: dict):
    eips = r.relations.get("elastic-ip") or []
    gb = sum((r.details.get(k) or 0) for k in r.details if k.startswith("BytesIn")) / 1024 ** 3
    series_note = f"{gb:,.2f} GB processed in window" if any(k.startswith("BytesIn") for k in r.details) else "traffic not measured"
    cost = (r.monthly_estimate or 0) + 3.65 * len(eips)
    return (r.name or r.resource_id, f"{series_note} · {len(eips)} EIP", f"{m(cost)}/mo", _state_tone(r, d), True)


def _misc_nodes(ips, eps, ec2, d):
    nodes = []
    if ips:
        owners = Counter((r.details.get("interface_type") or "instance") for r in ips)
        nodes.append((f"{len(ips)} public IPv4 addresses", ", ".join(f"{n} {k}" for k, n in owners.most_common(3)),
                      f"{m(sum(r.monthly_estimate or 0 for r in ips))}/mo", "neutral", False))
    if eps:
        nodes.append((f"{len(eps)} VPC endpoints", ", ".join(sorted({(r.name or '').split('.')[-1] for r in eps}))[:40],
                      f"{m(sum(r.monthly_estimate or 0 for r in eps))}/mo", "neutral", False))
    if ec2:
        running = sum(1 for r in ec2 if r.state == "running")
        nodes.append((f"{len(ec2)} EC2 instances", f"{running} running", f"{m(sum(r.monthly_estimate or 0 for r in ec2))}/mo", "neutral", False))
    return nodes


SEV_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}


def grouped_findings(res: ScanResult) -> list[dict]:
    """Findings with the same title collapse into one row (nine unused EIPs are one decision, not nine)."""
    groups: dict[str, list] = defaultdict(list)
    for f in res.findings:
        if f.category != "coverage":
            groups[f.title].append(f)
    out = []
    for title, fs in groups.items():
        fs.sort(key=lambda f: -(f.monthly_savings or 0))
        out.append({"title": title, "items": fs, "savings": sum(f.monthly_savings or 0 for f in fs),
                    "severity": min((f.severity for f in fs), key=lambda s: SEV_RANK.get(s, 9))})
    return sorted(out, key=lambda g: (-g["savings"], SEV_RANK.get(g["severity"], 9)))


def findings_list(res: ScanResult, limit: int = 12, tables: bool = True) -> str:
    groups = grouped_findings(res)
    if not groups:
        return '<p class="empty">No findings.</p>'
    ranked = [f for g in groups for f in g["items"]]
    vmax = max(g["savings"] for g in groups) or 1
    out = ['<ol class="finds">']
    for gr in groups[:limit]:
        g, tone = SEV.get(gr["severity"], ("·", "neutral"))
        fs, first = gr["items"], gr["items"][0]
        n = len(fs)
        who = first.resource_name or first.service
        if n > 1:
            who = f"{n} resources · {who} and {n - 1} more" if n > 2 else f"{who} and {fs[1].resource_name or fs[1].service}"
        each = f" · {m(first.monthly_savings)} each" if n > 1 and len({f.monthly_savings for f in fs}) == 1 and first.monthly_savings else ""
        w = gr["savings"] / vmax * 100
        out.append(f'<li><div class="fh"><span class="sev"><b class="t-{tone}">{g}</b> {e(gr["severity"])}</span><span class="ft">{e(gr["title"])}</span>'
                   f'<span class="fr">{e(who)}</span><span class="fs">{m(gr["savings"]) + "/mo" if gr["savings"] else ""}</span></div>'
                   f'<div class="fb"><span style="width:{w:.1f}%"></span></div><div class="fd">{e(first.detail)}{e(each)}</div></li>')
    out.append("</ol>")
    if not tables:
        more = len(groups) - limit
        return "".join(out) + (f'<p class="note">{more} more findings in the full report.</p>' if more > 0 else "")
    rows = "".join(f"<tr><td>{e(f.severity)}</td><td>{e(f.title)}</td><td>{e(f.resource_name)}</td><td>{e(f.service)}</td>"
                   f"<td>{e(f.region)}</td><td class=n>{m(f.monthly_savings) if f.monthly_savings else ''}</td></tr>" for f in ranked)
    head = "<tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Service</th><th>Region</th><th class=n>Savings/mo</th></tr>"
    out.append(f'<details class="tv"><summary>All {len(ranked)} findings</summary><table><thead>{head}</thead><tbody>{rows}</tbody></table></details>')
    return "".join(out)


def coverage(res: ScanResult) -> str:
    c = Counter(x.get("status", "") for x in res.coverage)
    total = sum(c.values()) or 1
    bad = [x for x in res.coverage if x.get("status") in ("denied", "error", "timeout", "throttled", "unavailable")]
    meter = (f'<div class="meter"><span style="width:{c.get("ok", 0) / total * 100:.1f}%"></span></div>'
             f'<p class="note">{c.get("ok", 0):,} of {total:,} checks answered · '
             + " · ".join(f"{n:,} {e(s)}" for s, n in c.most_common() if s != "ok") + "</p>")
    if not bad:
        return meter
    rows = "".join(f"<tr><td>{e(x.get('status'))}</td><td>{e(x.get('source'))}</td><td>{e(x.get('region'))}</td>"
                   f"<td>{e(x.get('action', ''))}</td><td>{e(str(x.get('detail', ''))[:160])}</td></tr>" for x in bad[:200])
    return meter + (f'<details class="tv"><summary>{len(bad)} failed checks</summary><table><thead><tr><th>Status</th><th>Source</th>'
                    f'<th>Region</th><th>IAM action</th><th>Detail</th></tr></thead><tbody>{rows}</tbody></table></details>')


# ── page ─────────────────────────────────────────────────────────────────────

def headline(res: ScanResult, d: dict) -> str:
    parts = [f"This account runs at <b>{m(d['run'])}</b> a month"]
    if res.forecast is not None:
        parts[0] += f" (AWS forecasts {m(d['actual'] + res.forecast)})"
    parts.append(f"<b>{pct(d['explained'])}</b> of it is explained by resources the scan priced")
    waste = d["waste"]
    if waste >= 1:
        parts.append(f"<b>{m(waste)}</b> a month is attached to resources that are idle, orphaned or stopped")
    top = next((g for g in grouped_findings(res) if g["savings"] >= 1), None)
    if top:
        f, n = top["items"][0], len(top["items"])
        where = f"on {e(f.resource_name or f.service)}" if n == 1 else f"across {n} resources"
        parts.append(f"the largest item is “{e(top['title'])}” {where} ({m(top['savings'])}/mo)")
    return "; ".join(parts) + "."


STYLES = ("report", "brief", "dashboard")


def render(res: ScanResult, style: str = "report") -> str:
    """style: report (full, single column) · brief (one printable page, top items only) ·
    dashboard (wide two-column grid)."""
    style = style if style in STYLES else "report"
    d = shape(res)
    gen = (res.generated_at or datetime.now(timezone.utc)).astimezone()
    acct = res.identity.get("Account", "")
    acct_fmt = f"{acct[:4]}-{acct[4:8]}-{acct[8:]}" if len(acct) == 12 else acct
    period = res.period.label if res.period else ""
    n_regions = len({r.region for r in d["resources"]})
    sources = ["Cost Explorer"] + (["CUR per-resource cost"] if res.meta.get("cur") else []) + \
              (["CloudWatch metrics"] if res.meta.get("metric_queries") else []) + \
              (["AWS recommendations"] if any(f.source != "rule" for f in res.findings) else [])
    high = sum(1 for f in res.findings if f.severity == "high")
    kpis = [("Monthly run-rate", m(d["run"]), f"{m(d['actual'])} so far"),
            ("Explained by resources", pct(d["explained"]), f"{m(d['est'])} of {m(d['base'])}"),
            ("Idle, orphaned or stopped", m(d["waste"]) if d["evaluated"] else "n/a",
             f"{sum(d['counts'].get(st, 0) for st in WASTE)} resources" if d["evaluated"] else "no activity data in this report"),
            ("Findings savings", m(d["savings"]), f"{sum(1 for f in res.findings if f.category != 'coverage')} findings · {high} high"),
            ("Resources", f"{len(d['resources']):,}", f"{n_regions} regions")]
    if style == "brief":
        kpis = kpis[:4]
    S = {}   # id → (title, lede, html, css class)
    S["flow"] = ("Where the money goes", "Each bill line's monthly run-rate, split by the state of the resources that produce it. "
                 "Money no inventoried resource accounts for (usage charges, data transfer, services without a collector) is shown separately.",
                 sankey(d), "wide")
    quad = quadrant(d)
    if quad:
        S["quad"] = ("Billed versus working", "Resources with an activity signal, by whether they cost money and whether they did any "
                     "work in the measurement window.", quad, "")
    else:
        S["flow"] = (S["flow"][0], S["flow"][1] + f" Only {d['evaluated']:,} of {len(d['resources']):,} resources in this data "
                     "have an activity signal, so most show as not evaluated; a new scan collects the signals.", S["flow"][2], S["flow"][3])
    topo = topology(res, d)
    if topo:
        S["topo"] = ("Network plumbing", "NAT gateways, load balancers and public addresses bill by the hour whether or not traffic "
                     "flows. The stripe shows each resource's usage state.", topo, "wide")
    S["bars"] = ("Spend by bill line", "Run-rate per Cost Explorer service, and how much of it inventoried resources explain.",
                 spend_bars(res), "")
    daily = daily_chart(res)
    if daily:
        S["daily"] = ("Daily spend", f"Unblended cost per day, last {len(res.daily)} days.", daily, "")
    S["finds"] = ("Findings", "Ranked by estimated monthly savings. Savings assume the resource is removed or resized as described.",
                  findings_list(res, limit=5 if style == "brief" else 12, tables=style != "brief"), "wide")
    S["cov"] = ("Data coverage", "Every collector and region the scan queried. Failed checks mean resources may be missing, "
                "not that none exist.", coverage(res), "wide")
    order = {"report": ["flow", "quad", "topo", "bars", "daily", "finds", "cov"],
             "brief": ["flow", "quad", "finds"],
             "dashboard": ["flow", "quad", "topo", "bars", "daily", "finds", "cov"]}[style]
    body = "".join(f'<section class="{S[k][3]}" id="{k}"><h2>{e(S[k][0])}</h2><p class="lede">{e(S[k][1])}</p>{S[k][2]}</section>'
                   for k in order if k in S)
    kpi_html = "".join(f'<div class="kpi"><div class="kl">{e(k)}</div><div class="kv">{e(v)}</div><div class="ks">{e(sub)}</div></div>'
                       for k, v, sub in kpis)
    foot = ("" if style == "brief" else
            "<footer><p><b>How to read this.</b> Run-rate is month-to-date actual cost extended to the full month. Estimates use AWS list "
            "prices for each resource's configuration and exclude discounts, data transfer and per-request charges. A resource is "
            "<i>working</i> when its activity metric shows work in the window, <i>idle</i> when it shows none, <i>orphaned</i> when nothing "
            "references it, and <i>not evaluated</i> when no activity signal was available. Savings are estimates; verify ownership before "
            "deleting anything.</p></footer>")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AWS cost report · {e(acct_fmt)} · {e(period)}</title><style>{CSS}</style></head>
<body class="{style}"><main>
<header><div class="eyebrow">AWS cost report · account {e(acct_fmt)} · {e(period)}</div>
<h1>{headline(res, d)}</h1>
<p class="meta">Generated {e(gen.strftime('%d %b %Y, %H:%M'))} by Deadweight · read-only scan · sources: {e(', '.join(sources))}</p></header>
<div class="kpis">{kpi_html}</div>
<div class="sections">{body}</div>
{foot}
</main><div id="tip" role="tooltip"></div><script>{JS}</script></body></html>"""


CSS = """
:root{color-scheme:light;--bg:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;
--ring:rgba(11,11,11,.10);--s1:#2a78d6;--s1b:#b7d3f6;--good:#0ca30c;--warning:#fab219;--serious:#ec835a;--critical:#d03b3b;--neutral:#a3a19a;--faint:#d6d4cc}
@media (prefers-color-scheme:dark){:root:where(:not([data-theme=light])){color-scheme:dark;--bg:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;
--muted:#898781;--grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--s1:#3987e5;--s1b:#184f95;--neutral:#6d6b65;--faint:#383835}}
:root[data-theme=dark]{color-scheme:dark;--bg:#0d0d0d;--surface:#1a1a19;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;--grid:#2c2c2a;--axis:#383835;
--ring:rgba(255,255,255,.10);--s1:#3987e5;--s1b:#184f95;--neutral:#6d6b65;--faint:#383835}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:40px 20px 64px}
.eyebrow{color:var(--muted);font-size:13px;letter-spacing:.02em}
h1{font-size:24px;line-height:1.35;font-weight:500;margin:8px 0 6px;max-width:62ch}h1 b{font-weight:650}
.meta{color:var(--muted);font-size:13px;margin:0}
h2{font-size:17px;font-weight:650;margin:0 0 2px}.lede{color:var(--ink2);margin:0 0 16px;max-width:75ch;font-size:14px}
section{background:var(--surface);border:1px solid var(--ring);border-radius:10px;padding:20px 22px;margin-top:16px}
.kpis{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--ring);border:1px solid var(--ring);border-radius:10px;overflow:hidden;margin-top:24px}
.kpi{background:var(--surface);padding:14px 16px}.kl{color:var(--ink2);font-size:13px}.kv{font-size:26px;font-weight:600;margin:2px 0}.ks{color:var(--muted);font-size:12px}
@media (max-width:820px){.kpis{grid-template-columns:repeat(2,1fr)}}
svg{width:100%;height:auto;display:block;overflow:visible}
.lbl{font-size:14px;fill:var(--ink)}.lbl .val,.tick{fill:var(--muted);font-size:12.5px}
.node{fill:var(--axis)}.link{opacity:.38;transition:opacity .12s}.link:hover{opacity:.7}
.t-good{fill:var(--good)}.t-warning{fill:var(--warning)}.t-serious{fill:var(--serious)}.t-critical{fill:var(--critical)}
.t-muted{fill:var(--neutral)}.t-neutral{fill:var(--neutral)}.t-faint{fill:var(--faint)}
.quad{display:grid;grid-template-columns:96px 1fr 1fr;gap:2px}
.qh,.qr{color:var(--muted);font-size:12px;padding:4px 8px}.qh{text-align:left}.qr{display:flex;align-items:center}
.q{background:var(--bg);border-radius:6px;padding:14px 16px}.q.hot{box-shadow:inset 4px 0 0 var(--critical)}
.qt{color:var(--ink2);font-size:13px}.qv{font-size:24px;font-weight:600}.qv span{font-size:13px;color:var(--muted);font-weight:400;margin-left:2px}.qn{color:var(--muted);font-size:12px}
.topo{margin-bottom:14px}.vpc{fill:none;stroke:var(--axis)}.inet{fill:none;stroke:var(--axis)}.vt,.ct{font-size:12px;fill:var(--muted)}
.n{fill:var(--surface);stroke:var(--grid)}.n.t-critical,.n.t-serious,.n.t-warning,.n.t-good,.n.t-neutral,.n.t-muted{fill:var(--surface)}
.stripe.t-neutral{fill:var(--axis)}.nt{font-size:13px;fill:var(--ink)}.ns{font-size:12px;fill:var(--muted)}.nm{font-size:13px;fill:var(--ink);font-weight:600}
.edge{fill:none;stroke:var(--axis);stroke-width:1.5}.edge.t-critical,.edge.t-serious{stroke:var(--serious)}
.bars{display:grid;gap:6px}.bar-row{display:grid;grid-template-columns:230px 1fr 130px;align-items:center;gap:12px;font-size:13px}
.bl{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.bt{display:flex;align-items:center;gap:2px;height:18px}
.bt span.s1,.bt span.s2{height:14px;display:block}.s1{background:var(--s1);border-radius:0}.s2{background:var(--s1b);border-radius:0 4px 4px 0}
.bv{color:var(--ink2);margin-left:8px;font-variant-numeric:tabular-nums;white-space:nowrap}
.bs{color:var(--muted);font-size:12px}.bs.no-collector,.bs.nothing-found,.bs.discovered-only{color:var(--critical)}
.legend{display:flex;gap:18px;color:var(--ink2);font-size:12px;margin-top:10px}.legend i{display:inline-block;width:12px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}
.k1{background:var(--s1)}.k2{background:var(--s1b)}
.daily .grid{stroke:var(--grid)}.daily .line{fill:none;stroke:var(--s1);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
.daily .area{fill:var(--s1);opacity:.1}.daily .end{fill:var(--s1);stroke:var(--surface);stroke-width:2}.xhair{stroke:var(--axis);visibility:hidden}.hit{fill:transparent}
.finds{list-style:none;margin:0;padding:0;display:grid;gap:14px}.fh{display:grid;grid-template-columns:96px 1fr auto auto;gap:12px;align-items:baseline;font-size:14px}
.sev{font-size:12px;color:var(--ink2)}.sev b{font-weight:400}.sev b.t-critical{color:var(--critical)}.sev b.t-serious{color:var(--serious)}.sev b.t-neutral{color:var(--muted)}
.ft{font-weight:600}.fr{color:var(--ink2);font-size:13px}.fs{font-variant-numeric:tabular-nums;font-weight:600}
.fb{height:4px;margin:6px 0 4px 108px;background:var(--grid);border-radius:2px}.fb span{display:block;height:4px;background:var(--s1);border-radius:2px}
.fd{color:var(--muted);font-size:13px;margin-left:108px}
.meter{height:10px;background:var(--grid);border-radius:5px;overflow:hidden}.meter span{display:block;height:10px;background:var(--good)}
.note,.empty{color:var(--muted);font-size:13px;margin:10px 0 0}
details.tv{margin-top:14px}details.tv summary{cursor:pointer;color:var(--ink2);font-size:13px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}th{text-align:left;color:var(--muted);font-weight:500;border-bottom:1px solid var(--grid);padding:6px 8px}
td{padding:6px 8px;border-bottom:1px solid var(--grid);vertical-align:top}.n,td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
footer{color:var(--ink2);font-size:13px;margin-top:28px;max-width:80ch}
#tip{position:fixed;pointer-events:none;background:var(--surface);color:var(--ink);border:1px solid var(--ring);border-radius:6px;padding:6px 9px;
font-size:12px;white-space:pre;box-shadow:0 2px 8px rgba(0,0,0,.12);display:none;z-index:9}
/* layouts */
body.dashboard main{max-width:1440px}
body.dashboard .sections{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:16px}
body.dashboard .sections section{margin-top:0}body.dashboard section.wide{grid-column:1/-1}
@media (max-width:1100px){body.dashboard .sections{grid-template-columns:1fr}}
body.brief main{max-width:860px}body.brief h1{font-size:21px}body.brief .kpis{grid-template-columns:repeat(4,1fr)}
@media print{html,body{background:#fff}section{break-inside:avoid;border-color:#ddd}details.tv{display:none}#tip{display:none}}
"""

JS = """
const tip=document.getElementById('tip');
function show(t,x,y){tip.textContent=t;tip.style.display='block';const w=tip.offsetWidth;tip.style.left=Math.min(x+14,innerWidth-w-8)+'px';tip.style.top=(y+14)+'px'}
document.querySelectorAll('[data-tip]').forEach(el=>{el.addEventListener('pointermove',ev=>show(el.getAttribute('data-tip'),ev.clientX,ev.clientY));
el.addEventListener('pointerleave',()=>tip.style.display='none')});
document.querySelectorAll('svg.daily').forEach(svg=>{const s=JSON.parse(svg.dataset.series),[L,R,T,B,top]=svg.dataset.geom.split(',').map(Number);
const vb=svg.viewBox.baseVal,hit=svg.querySelector('.hit'),xh=svg.querySelector('.xhair');
hit.addEventListener('pointermove',ev=>{const r=svg.getBoundingClientRect(),x=(ev.clientX-r.left)*vb.width/r.width;
const i=Math.max(0,Math.min(s.length-1,Math.round((x-L)/(vb.width-L-R)*(s.length-1))));const px=L+(vb.width-L-R)*i/(s.length-1);
xh.setAttribute('x1',px);xh.setAttribute('x2',px);xh.style.visibility='visible';show('$'+s[i][1].toLocaleString(undefined,{minimumFractionDigits:2})+'\\n'+s[i][0],ev.clientX,ev.clientY)});
hit.addEventListener('pointerleave',()=>{xh.style.visibility='hidden';tip.style.display='none'})});
"""
