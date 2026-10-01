"""Command line: interactive TUI (default), headless scans for cron/CI, report diffs and IAM policy output."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

REPORT_DIR = Path.cwd() / "deadweight-reports"
SEVERITY = {"high": 0, "medium": 1, "low": 2, "info": 3}


def build_parser() -> argparse.ArgumentParser:
    from . import __version__
    ap = argparse.ArgumentParser(prog="deadweight",
                                 description="Find what you pay AWS for and don't use: read-only inventory, bill "
                                             "reconciliation and idle-resource detection.")
    ap.add_argument("--version", action="version", version=f"deadweight {__version__}")
    ap.add_argument("--report", type=Path, help="open a saved aws-report-*.json in the TUI (offline, no AWS calls)")
    ap.add_argument("--theme", default="aws-nebula", help="TUI theme (aws-nebula, aws-synthwave, aws-daylight, tokyo-night, nord, …)")

    s = ap.add_argument_group("scan scope")
    s.add_argument("--profile", help="AWS profile (default: the SDK's default credential chain)")
    s.add_argument("--role-arn", help="assume this role with ReadOnlyAccess + AWSBillingReadOnlyAccess session policies")
    s.add_argument("--external-id", help="external ID for --role-arn")
    s.add_argument("--regions", help="comma-separated regions (default: every enabled region)")
    s.add_argument("--active-regions", action="store_true", help="only scan regions with spend this month (one Cost Explorer call)")
    s.add_argument("--services", help="comma-separated collectors (see --list-services); default: all default collectors")
    s.add_argument("--exclude-services", help="comma-separated collectors to skip")
    s.add_argument("--all-services", action="store_true", help="include opt-in collectors such as 'Cloud Control (all types)'")
    s.add_argument("--workers", type=int, default=16, help="parallel collector tasks (default 16)")
    s.add_argument("--task-timeout", type=float, default=300.0, help="seconds before one collector task is abandoned (default 300)")
    s.add_argument("--org", action="store_true", help="scan every account in the AWS Organization (run from the management account)")
    s.add_argument("--org-role", default="OrganizationAccountAccessRole", help="role assumed in member accounts")
    s.add_argument("--accounts", help="with --org: comma-separated account IDs to include")

    f = ap.add_argument_group("features")
    f.add_argument("--no-metrics", action="store_true", help="skip CloudWatch utilisation/size metrics")
    f.add_argument("--no-costs", action="store_true", help="skip Cost Explorer (no CE API charges)")
    f.add_argument("--no-cost-tags", action="store_true", help="skip per-tag cost breakdowns")
    f.add_argument("--no-forecast", action="store_true", help="skip Cost Explorer forecast and anomalies")
    f.add_argument("--no-recommendations", action="store_true", help="skip Cost Optimization Hub / Compute Optimizer")
    f.add_argument("--no-cur", action="store_true", help="skip per-resource actuals from Data Exports / CUR")
    f.add_argument("--cur-path", help="read CUR Parquet files from this folder or glob instead of S3")
    f.add_argument("--no-price-cache", action="store_true", help="do not read/write the on-disk Pricing API cache")
    f.add_argument("--no-usage-store", action="store_true",
                   help="do not remember first-seen-idle dates (~/.cache/deadweight/usage-state.json)")

    h = ap.add_argument_group("headless & tooling")
    h.add_argument("--headless", action="store_true", help="scan without the TUI, write reports and exit")
    h.add_argument("--out", type=Path, default=REPORT_DIR, help="output folder (default ./deadweight-reports)")
    h.add_argument("--format", default="json,csv,html", help="report formats: json,csv,html")
    h.add_argument("--html-style", default="report", choices=["report", "brief", "dashboard"],
                   help="HTML layout: report (full), brief (one printable page) or dashboard (wide grid)")
    h.add_argument("--budget", type=float, help="exit 2 when the month's run-rate (or AWS forecast) exceeds this amount")
    h.add_argument("--fail-on", choices=["high", "medium", "low"], help="exit 3 when findings of this severity or worse exist")
    h.add_argument("--diff", nargs=2, type=Path, metavar=("OLD", "NEW"), help="compare two saved reports and exit")
    h.add_argument("--print-policy", action="store_true", help="print the least-privilege IAM policy for the selected collectors")
    h.add_argument("--list-services", action="store_true", help="list every collector and exit")
    h.add_argument("--add-profile", action="store_true",
                   help="interactively create an AWS profile (IAM Identity Center sign-in, access keys or assume-role)")
    return ap


def add_profile_cmd() -> int:
    import getpass

    import boto3

    from . import profiles
    ask = lambda q, d="": (input(f"{q}{f' [{d}]' if d else ''}: ").strip() or d)
    print(f"Add an AWS profile · written to {profiles.config_path()} (a .bak copy is kept)")
    existing = profiles.list_profiles()
    name = profiles.check_name(ask("Profile name", "cost-readonly"))
    if name in existing and ask(f"'{name}' already exists. Replace it? y/N", "n").lower() != "y":
        return 1
    region = ask("Default region", "us-east-1")
    kind = ask("Type: 1) IAM Identity Center (SSO) sign-in  2) access keys  3) assume a role", "1")
    if kind == "2":
        akid, secret = ask("Access key ID"), getpass.getpass("Secret access key: ")
        token = getpass.getpass("Session token (Enter if none): ")
        ident = profiles.identity_for_keys(akid, secret, token)
        if str(ident.get("Arn", "")).endswith(":root"):
            print("Warning: these are root credentials. Prefer an IAM user or role limited to read-only access.")
        profiles.add_access_key_profile(name, akid, secret, token, region)
    elif kind == "3":
        if not existing:
            print("Assume-role needs an existing source profile; add one first.")
            return 1
        source = ask(f"Source profile ({', '.join(existing)})", existing[0])
        role_arn, external = ask("Role ARN"), ask("External ID (Enter if none)")
        kw = {"RoleArn": role_arn, "RoleSessionName": "deadweight-check", **({"ExternalId": external} if external else {})}
        boto3.Session(profile_name=source).client("sts").assume_role(**kw)
        profiles.add_role_profile(name, role_arn, source, region, external)
    else:
        start, sso_region = ask("Start URL (https://…awsapps.com/start)"), ask("Identity Center region", "us-east-1")
        token = profiles.sso_login(name, start, sso_region,
                                   lambda c: print(f"Open {c.url}\nand confirm code {c.user_code} (waiting…)"))
        accounts = profiles.sso_accounts(token, sso_region)
        if not accounts:
            print("This user has no account assignments in IAM Identity Center.")
            return 1
        for i, (aid, aname, _) in enumerate(accounts, 1):
            print(f"  {i}) {aname} ({aid})")
        aid, _, roles = accounts[int(ask("Account", "1")) - 1]
        for i, r in enumerate(roles, 1):
            print(f"  {i}) {r}")
        role = roles[int(ask("Role", "1")) - 1]
        profiles.add_sso_profile(name, name, start, sso_region, aid, role, region)
    ident = profiles.validate(name)
    print(f"Saved '{name}' → account {ident.get('Account')} as {ident.get('Arn')}")
    return 0


def _csv(value: str | None) -> list[str]:
    return [x.strip() for x in (value or "").split(",") if x.strip()]


def options_from(args):
    from .collectors.base import REGISTRY
    from .scanner import ScanOptions
    if args.services:
        services = set(_csv(args.services))
        unknown = services - set(REGISTRY)
        if unknown:
            raise SystemExit(f"Unknown collector(s): {', '.join(sorted(unknown))}. See --list-services.")
    else:
        services = {k for k, s in REGISTRY.items() if s.default or args.all_services}
    services -= set(_csv(args.exclude_services))
    return ScanOptions(
        profile=args.profile, role_arn=args.role_arn, external_id=args.external_id, services=services,
        regions=_csv(args.regions) or None, region_mode="active" if args.active_regions else "all",
        workers=max(1, args.workers), task_timeout=args.task_timeout, metrics=not args.no_metrics, costs=not args.no_costs,
        cost_tags=not args.no_cost_tags, forecast=not args.no_forecast, anomalies=not args.no_forecast,
        recommendations=not args.no_recommendations, cur="off" if args.no_cur else "auto", cur_path=args.cur_path,
        price_cache=not args.no_price_cache, usage_store=not args.no_usage_store, org=args.org, org_role=args.org_role, accounts=_csv(args.accounts) or None)


def _money(v) -> str:
    return "n/a" if v is None else f"${v:,.2f}"


def headless(args) -> int:
    from . import report
    from .billing import explained_totals
    from .scanner import Scanner
    opts = options_from(args)
    last = [0.0]

    def progress(label: str, done: int, total: int) -> None:
        now = time.monotonic()
        if now - last[0] > 2 or done >= total:
            last[0] = now
            print(f"[{done / max(1, total):4.0%}] {label}", file=sys.stderr, flush=True)

    def log(msg: str) -> None:
        if msg.startswith("[error]") or msg.startswith("[warn]"):
            print(msg, file=sys.stderr, flush=True)
    try:
        sc = Scanner(opts, log=log, on_progress=progress)
        res = sc.run()
    except Exception as e:
        print(f"Scan failed: {e}", file=sys.stderr)
        return 1
    files = report.export(res, args.out, tuple(_csv(args.format)), args.html_style)
    actual = sum(c.actual_mtd for c in res.costs)
    run = sum(c.projected_month for c in res.costs)
    forecast = (res.forecast + actual) if res.forecast is not None else None
    est, base = explained_totals(res.reconciliation)
    savings = sum((f.monthly_savings or 0) for f in res.findings)
    print(f"Account {res.identity.get('Account', '?')} · {res.period.label if res.period else ''} · "
          f"{len(res.resources):,} resources · {res.meta.get('duration_s')} s · Cost Explorer ≈ ${res.meta.get('ce_cost', 0):.2f}")
    print(f"MTD {_money(actual)} · run-rate {_money(run)} · AWS forecast {_money(forecast)} · explained "
          f"{(est / base if base else 0):.0%} · potential savings {_money(savings)}/mo · {len(res.findings)} findings")
    for f in res.findings[:10]:
        print(f"  {f.severity:<6} {f.title} · {f.resource_name or f.service} · {_money(f.monthly_savings) if f.monthly_savings else ''}")
    for p in files:
        print(f"wrote {p}")
    code = 0
    if args.budget is not None and max(run, forecast or 0) > args.budget:
        print(f"Budget exceeded: {_money(max(run, forecast or 0))} > {_money(args.budget)}", file=sys.stderr)
        code = 2
    if args.fail_on and any(SEVERITY.get(f.severity, 9) <= SEVERITY[args.fail_on] for f in res.findings):
        code = code or 3
    return code


def diff_cmd(args) -> int:
    from . import report
    a, b = report.load(args.diff[0]), report.load(args.diff[1])
    d = report.diff(a, b)
    ta, tb = d["a"], d["b"]
    if not d["same_account"]:
        print(f"Note: different accounts ({a.identity.get('Account')} vs {b.identity.get('Account')})")
    print(f"{ta['generated_at'][:16]} → {tb['generated_at'][:16]}")
    print(f"resources {d['unique_a']:,} → {d['unique_b']:,} (+{len(d['added'])} / -{len(d['removed'])} / ~{len(d['changed'])})")
    print(f"run-rate {_money(ta['run_rate'])} → {_money(tb['run_rate'])} ({tb['run_rate'] - ta['run_rate']:+,.2f})")
    for row in d["costs"][:10]:
        if abs(row["delta"]) >= 0.01:
            print(f"  {row['label'][:40]:40} {_money(row['a']):>12} → {_money(row['b']):>12}  {row['delta']:+,.2f}")
    for title, items in (("added", d["added"]), ("removed", d["removed"])):
        if items:
            print(f"{title}:")
            for r in items[:25]:
                print(f"  {r.service:<18} {r.region:<15} {r.name or r.resource_id}")
            if len(items) > 25:
                print(f"  … {len(items) - 25} more")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):     # Windows consoles/pipes default to cp1252, which lacks → · ≈
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    args = build_parser().parse_args(argv)
    if args.add_profile:
        try:
            return add_profile_cmd()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled")
            return 1
        except Exception as e:
            print(f"Not saved: {e}", file=sys.stderr)
            return 1
    if args.list_services:
        from .collectors.base import FAMILIES, REGISTRY
        for fam, label in FAMILIES.items():
            print(f"\n{label}")
            for k, s in REGISTRY.items():
                if s.family == fam:
                    print(f"  {k:<28}{'' if s.default else '(opt-in) '}{s.desc}")
        return 0
    if args.print_policy:
        from . import report
        opts = options_from(args)
        print(json.dumps(report.policy(opts.services), indent=2))
        return 0
    if args.diff:
        return diff_cmd(args)
    if args.headless:
        return headless(args)
    from .ui import run_tui
    run_tui(report=args.report, theme=args.theme, options=options_from(args))
    return 0
