"""The Textual application."""
from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import replace
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import Any, Iterable

import boto3
from rich.table import Table
from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.color import Gradient
from textual.containers import Container, Grid, Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen, Screen
from textual.widgets import (Button, Checkbox, ContentSwitcher, Footer, Input, Label, ListView, OptionList, ProgressBar,
                             RadioButton, RadioSet, RichLog, Select, Static, Tab, Tabs)
from textual.widgets.option_list import Option

from . import profiles
from . import report as reports
from .billing import explained_totals
from .collectors.base import FAMILIES, REGISTRY
from .costs import DIMENSIONS
from .models import Finding, Resource, ScanResult, money
from .scanner import Scanner, ScanOptions
from .ui_kit import (COVERAGE_ORDER, FAMILY_LABEL, SPINNER, USAGE_ORDER, fmt_usage, THEME_CYCLE, THEMES, Canvas, Col, DataView, Inspector, KpiCard,
                     NavItem, Pal, _num, family_of, fam_color, fmt_account, fmt_cov_status, fmt_dur, fmt_money, fmt_service,
                     fmt_severity, fmt_sources, fmt_state, fmt_type, hbar, kpi_money, paint_bars, paint_findings, paint_hero,
                     paint_legend, paint_pacing, short_id, trunc)

REPORT_DIR = Path.cwd() / "deadweight-reports"
# Textual 8 renamed the "nothing selected" sentinel from Select.BLANK to Select.NULL.
SELECT_NONE = Select.NULL if hasattr(Select, "NULL") else Select.BLANK
DEFAULT_CHAIN = "__default_chain__"     # env vars, SSO exports, instance/container roles, CloudShell…
ADD_PROFILE = "__add_profile__"

PAGES = [("overview", "◆", "Overview"), ("resources", "▦", "Resources"), ("costs", "$", "Costs"),
         ("findings", "▲", "Findings"), ("analysis", "∑", "Analysis"), ("groups", "⊞", "Groups"),
         ("catalog", "◇", "Catalog"), ("coverage", "◎", "Coverage"), ("compare", "⇄", "Compare"),
         ("activity", "≡", "Activity")]
PAGE_KEYS = "1234567890"
STATUS_COLOR = {"reconciled": "success", "partly explained": "warning", "over-estimated": "warning", "no collector": "error",
                "nothing found": "error", "discovered only": "error", "usage-based": "secondary", "negligible": "faint",
                "not billed yet": "accent"}


# ── modal screens ──────────────────────────────────────────────────────────────

class Pick(Checkbox):
    BUTTON_INNER = "■"


class ServicePicker(ModalScreen[set[str] | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel"), Binding("a", "all", "All"),
                Binding("n", "none", "None"), Binding("d", "defaults", "Defaults"), Binding("ctrl+s", "apply", "Apply")]

    def __init__(self, selected: set[str]):
        super().__init__()
        self.selected = selected

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="picker"):
            yield Static("Scan scope", id="dlg-title")
            yield Static("", id="dlg-sub")
            with VerticalScroll(id="groups-scroll"):
                with Grid(id="groups"):
                    for fam, title in FAMILIES.items():
                        keys = [k for k, s in REGISTRY.items() if s.family == fam]
                        if not keys:
                            continue
                        with Vertical(classes=f"group fam-{fam}") as g:
                            g.border_title = title
                            for k in keys:
                                spec = REGISTRY[k]
                                cb = Pick(k + ("" if spec.default else " · opt-in, slow"), value=k in self.selected, name=k, compact=True)
                                cb.tooltip = spec.desc
                                yield cb
            with Horizontal(id="dlg-buttons"):
                yield Static(Text.assemble(("a", "bold"), " all standard  ", ("n", "bold"), " none  ",
                                           ("esc", "bold"), " cancel  ·  opt-in collectors are ticked by hand"), classes="hint")
                yield Button("Defaults", id="dlg-defaults", compact=True)
                yield Button("Cancel", id="dlg-cancel", compact=True)
                yield Button("Apply", id="dlg-apply", compact=True)

    def on_mount(self) -> None:
        self._count()

    @on(Checkbox.Changed)
    def _count(self) -> None:
        n = sum(1 for b in self.query(Checkbox) if b.value)
        self.query_one("#dlg-sub", Static).update(f"{n} of {len(REGISTRY)} collectors selected  ·  every collector is read-only  ·  hover for details")

    def _set(self, pred) -> None:
        for b in self.query(Checkbox):
            b.value = pred(b.name)

    def action_all(self) -> None: self._set(lambda k: REGISTRY[k].default)      # opt-in collectors stay a deliberate tick
    def action_none(self) -> None: self._set(lambda k: False)
    def action_defaults(self) -> None: self._set(lambda k: REGISTRY[k].default)
    def action_cancel(self) -> None: self.dismiss(None)
    def action_apply(self) -> None: self.dismiss({b.name for b in self.query(Checkbox) if b.value})

    @on(Button.Pressed)
    def _press(self, e: Button.Pressed) -> None:
        {"dlg-defaults": self.action_defaults, "dlg-cancel": self.action_cancel, "dlg-apply": self.action_apply}[e.button.id]()


class OptionsScreen(ModalScreen[ScanOptions | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel"), Binding("ctrl+s", "apply", "Apply")]
    FLAGS = [("metrics", "CloudWatch metrics (sizes, idle detection, NAT/LB usage)"), ("costs", "Cost Explorer (≈ $0.01 per request)"),
             ("cost_tags", "Cost per cost-allocation tag"), ("forecast", "AWS forecast"), ("anomalies", "Cost anomalies"),
             ("recommendations", "AWS recommendations (Cost Optimization Hub / Compute Optimizer)"),
             ("price_cache", "Cache Pricing API answers on disk (7 days)")]

    def __init__(self, opts: ScanOptions):
        super().__init__()
        self.opts = opts

    def compose(self) -> ComposeResult:
        o = self.opts
        with Vertical(id="dialog", classes="options"):
            yield Static("Scan options", id="dlg-title")
            yield Static("Applies to the next scan  ·  nothing here changes your AWS account", id="dlg-sub")
            with VerticalScroll(id="opt-scroll"):
                yield Label("REGIONS", classes="opt-label")
                with RadioSet(id="opt-regions", compact=True):
                    yield RadioButton("Every enabled region", value=o.region_mode == "all" and not o.regions, compact=True)
                    yield RadioButton("Only regions with spend this month (1 Cost Explorer call)", value=o.region_mode == "active", compact=True)
                    yield RadioButton("Only these regions:", value=bool(o.regions), compact=True)
                yield Input(",".join(o.regions or []), placeholder="us-east-1, eu-west-1", id="opt-region-list", compact=True)
                yield Label("CREDENTIALS", classes="opt-label")
                yield Input(o.role_arn or "", placeholder="Role ARN to assume read-only (optional)", id="opt-role", compact=True)
                yield Input(o.external_id or "", placeholder="External ID (optional)", id="opt-external", compact=True)
                yield Pick("Scan every account in the AWS Organization (management account)", o.org, id="opt-org", compact=True)
                yield Input(o.org_role, placeholder="Member-account role name", id="opt-org-role", compact=True)
                yield Label("FEATURES", classes="opt-label")
                for key, label in self.FLAGS:
                    yield Pick(label, bool(getattr(o, key)), id=f"opt-{key}", compact=True)
                yield Pick("Per-resource actuals from Data Exports / CUR (s3:GetObject)", o.cur != "off", id="opt-cur", compact=True)
                yield Label("ENGINE", classes="opt-label")
                with Horizontal(classes="opt-row"):
                    yield Label("Parallel tasks", classes="opt-inline")
                    yield Input(str(o.workers), id="opt-workers", compact=True, type="integer")
                    yield Label("Task timeout (s)", classes="opt-inline")
                    yield Input(str(int(o.task_timeout)), id="opt-timeout", compact=True, type="integer")
            with Horizontal(id="dlg-buttons"):
                yield Static(Text.assemble(("ctrl+s", "bold"), " apply  ", ("esc", "bold"), " cancel"), classes="hint")
                yield Button("Cancel", id="dlg-cancel", compact=True)
                yield Button("Apply", id="dlg-apply", compact=True)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def action_apply(self) -> None:
        q = lambda i: self.query_one(f"#{i}")
        idx = q("opt-regions").pressed_index
        regions = [r.strip() for r in q("opt-region-list").value.split(",") if r.strip()]
        try:
            workers, timeout = max(1, int(q("opt-workers").value or 16)), max(10.0, float(q("opt-timeout").value or 300))
        except ValueError:
            workers, timeout = self.opts.workers, self.opts.task_timeout
        o = replace(self.opts, region_mode="active" if idx == 1 else "all", regions=regions if idx == 2 and regions else None,
                    role_arn=q("opt-role").value.strip() or None, external_id=q("opt-external").value.strip() or None,
                    org=q("opt-org").value, org_role=q("opt-org-role").value.strip() or "OrganizationAccountAccessRole",
                    cur="auto" if q("opt-cur").value else "off", workers=workers, task_timeout=timeout,
                    **{k: q(f"opt-{k}").value for k, _ in self.FLAGS})
        self.dismiss(o)

    @on(Button.Pressed)
    def _press(self, e: Button.Pressed) -> None:
        (self.action_apply if e.button.id == "dlg-apply" else self.action_cancel)()


class ReportPicker(ModalScreen[Path | None]):
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, files: list[Path], title: str = "Open a saved report"):
        super().__init__()
        self.files, self.title_text = files, title

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="reports"):
            yield Static(self.title_text, id="dlg-title")
            yield Static(f"{len(self.files)} export{'s' if len(self.files) != 1 else ''} in ./{REPORT_DIR.name}  ·  offline, no AWS calls", id="dlg-sub")
            opts = []
            for i, p in enumerate(self.files):

                m = re.search(r"(\d{8})-(\d{6})", p.name)
                when = datetime.strptime("".join(m.groups()), "%Y%m%d%H%M%S").strftime("%a %d %b %Y  %H:%M") if m else p.name
                size = p.stat().st_size / 1_048_576
                opts.append(Option(Text.assemble(("◉ " if i == 0 else "○ ", Pal.primary), (when, f"bold {Pal.fg}"),
                                                 (f"   {p.name}", Pal.muted), (f"   {size:.1f} MB", Pal.faint)), id=str(i)))
            yield OptionList(*opts, id="report-list")
            with Horizontal(id="dlg-buttons"):
                yield Static(Text.assemble(("enter", "bold"), " choose  ", ("esc", "bold"), " cancel"), classes="hint")

    @on(OptionList.OptionSelected)
    def _pick(self, e: OptionList.OptionSelected) -> None:
        self.dismiss(self.files[int(e.option.id)])

    def action_cancel(self) -> None:
        self.dismiss(None)


class AddProfileScreen(ModalScreen[str | None]):
    """Create an AWS profile (SSO sign-in, access keys or assume-role) and verify it before closing."""
    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    KINDS = [("pf-sso", "IAM Identity Center (SSO) sign-in"), ("pf-keys", "Access keys (IAM user)"),
             ("pf-role", "Assume a role using another profile")]

    def __init__(self, existing: list[str]):
        super().__init__()
        self.existing = existing
        self._token: str | None = None
        self._accounts: list[tuple[str, str, list[str]]] = []
        self._confirm_overwrite = ""
        self._cancel_signin = False

    def compose(self) -> ComposeResult:
        name = next(n for n in ("cost-readonly", "cost-readonly-2", "cost-readonly-3", "cost-readonly-4") if n not in self.existing)
        with Vertical(id="dialog", classes="profile"):
            yield Static("Add an AWS profile", id="dlg-title")
            cfg = str(profiles.config_path()).replace(str(Path.home()), "~")
            yield Static(f"Writes {cfg} · other profiles are kept · a .bak copy is made", id="dlg-sub")
            with Horizontal(classes="opt-row"):
                yield Label("Profile name", classes="opt-inline")
                yield Input(name, id="pf-name", compact=True)
                yield Label("Default region", classes="opt-inline")
                yield Input("us-east-1", id="pf-region", compact=True)
            with RadioSet(id="pf-kind", compact=True):
                for i, (_, label) in enumerate(self.KINDS):
                    yield RadioButton(label, value=i == 0, compact=True)
            with ContentSwitcher(initial="pf-sso", id="pf-switch"):
                with Vertical(id="pf-sso", classes="pf-pane"):
                    yield Input(placeholder="Start URL, e.g. https://my-org.awsapps.com/start", id="pf-start", compact=True)
                    with Horizontal(classes="opt-row"):
                        yield Label("Identity Center region", classes="opt-inline")
                        yield Input("us-east-1", id="pf-sso-region", compact=True)
                        yield Button("Sign in", id="pf-signin", compact=True)
                    yield Static("", id="pf-code")
                    yield Select([], prompt="Account (sign in first)", id="pf-account", compact=True)
                    yield Select([], prompt="Role", id="pf-rolename", compact=True)
                with Vertical(id="pf-keys", classes="pf-pane"):
                    yield Input(placeholder="Access key ID (AKIA… / ASIA…)", id="pf-akid", compact=True)
                    yield Input(placeholder="Secret access key", id="pf-secret", password=True, compact=True)
                    yield Input(placeholder="Session token (only for temporary keys)", id="pf-token", password=True, compact=True)
                    yield Static("Use keys of an IAM user limited to ReadOnlyAccess + AWSBillingReadOnlyAccess, never root keys.",
                                 classes="pf-note")
                with Vertical(id="pf-role", classes="pf-pane"):
                    yield Select([(p, p) for p in self.existing], prompt="Source profile (signs the AssumeRole call)",
                                 id="pf-source", compact=True)
                    yield Input(placeholder="Role ARN, e.g. arn:aws:iam::123456789012:role/ReadOnly", id="pf-rolearn", compact=True)
                    yield Input(placeholder="External ID (optional)", id="pf-external", compact=True)
            yield Static("", id="pf-status")
            with Horizontal(id="dlg-buttons"):
                yield Static(Text.assemble(("esc", "bold"), " cancel"), classes="hint")
                yield Button("Cancel", id="dlg-cancel", compact=True)
                yield Button("Verify & save", id="dlg-apply", compact=True)

    def _status(self, text: str, tone: str = "muted") -> None:
        self.query_one("#pf-status", Static).update(Text(text, style=getattr(Pal, tone)))

    @property
    def _kind(self) -> str:
        return self.KINDS[max(0, self.query_one("#pf-kind", RadioSet).pressed_index)][0]

    @on(RadioSet.Changed, "#pf-kind")
    def _switch(self) -> None:
        self.query_one("#pf-switch", ContentSwitcher).current = self._kind

    def action_cancel(self) -> None:
        self._cancel_signin = True
        self.dismiss(None)

    @on(Button.Pressed)
    def _press(self, e: Button.Pressed) -> None:
        if e.button.id == "dlg-cancel":
            self.action_cancel()
        elif e.button.id == "pf-signin":
            start, region = self.query_one("#pf-start", Input).value.strip(), self.query_one("#pf-sso-region", Input).value.strip()
            if not start.startswith("https://"):
                self._status("Enter the Identity Center start URL (https://…)", "error")
                return
            e.button.disabled = True
            self._signin(start, region)
        elif e.button.id == "dlg-apply":
            self._save()

    # SSO ---------------------------------------------------------------------------
    @work(thread=True, exclusive=True, group="sso")
    def _signin(self, start: str, region: str) -> None:
        name = self.query_one("#pf-name", Input).value.strip() or "cost-readonly"

        def show(code) -> None:
            self.app.call_from_thread(self.query_one("#pf-code", Static).update, Text.assemble(
                ("Approve sign-in in your browser. Code ", Pal.muted), (code.user_code, f"bold {Pal.primary}"),
                ("\n" + code.url, Pal.secondary)))
        try:
            token = profiles.sso_login(name, start, region, show, cancelled=lambda: self._cancel_signin)
            accounts = profiles.sso_accounts(token, region)
            self.app.call_from_thread(self._signed_in, token, accounts)
        except Exception as ex:
            self.app.call_from_thread(self._status, f"Sign-in failed: {ex}", "error")
            self.app.call_from_thread(setattr, self.query_one("#pf-signin", Button), "disabled", False)

    def _signed_in(self, token: str, accounts: list) -> None:
        self._token, self._accounts = token, accounts
        self.query_one("#pf-code", Static).update(Text(f"Signed in · {len(accounts)} account(s) available", style=Pal.success))
        self.query_one("#pf-account", Select).set_options([(f"{name} · {fmt_account(aid)}", aid) for aid, name, _ in accounts])
        if accounts:
            self.query_one("#pf-account", Select).value = accounts[0][0]

    @on(Select.Changed, "#pf-account")
    def _account(self, e: Select.Changed) -> None:
        roles = next((r for aid, _, r in self._accounts if aid == e.value), [])
        sel = self.query_one("#pf-rolename", Select)
        sel.set_options([(r, r) for r in roles])
        preferred = next((r for r in roles if "readonly" in r.lower() or "viewonly" in r.lower() or "billing" in r.lower()), roles[0] if roles else None)
        if preferred:
            sel.value = preferred

    # save --------------------------------------------------------------------------
    def _save(self) -> None:
        q = lambda i: self.query_one(f"#{i}")
        try:
            name = profiles.check_name(q("pf-name").value)
        except ValueError as ex:
            self._status(str(ex), "error")
            return
        if name in self.existing and self._confirm_overwrite != name:
            self._confirm_overwrite = name
            self._status(f"A profile called '{name}' already exists. Press Verify & save again to replace it.", "warning")
            return
        kind, region = self._kind, q("pf-region").value.strip() or "us-east-1"
        if kind == "pf-sso" and not (self._token and q("pf-account").value not in (SELECT_NONE, None) and q("pf-rolename").value not in (SELECT_NONE, None)):
            self._status("Sign in, then choose an account and a role", "error")
            return
        if kind == "pf-role" and q("pf-source").value is SELECT_NONE:
            self._status("Choose the source profile that signs the AssumeRole call", "error")
            return
        self._status("Verifying…")
        q("dlg-apply").disabled = True
        self._verify_and_write(name, kind, region, {
            "akid": q("pf-akid").value, "secret": q("pf-secret").value, "token": q("pf-token").value,
            "source": q("pf-source").value, "role_arn": q("pf-rolearn").value, "external": q("pf-external").value,
            "start": q("pf-start").value.strip(), "sso_region": q("pf-sso-region").value.strip(),
            "account": q("pf-account").value, "role_name": q("pf-rolename").value})

    @work(thread=True, exclusive=True, group="profile-save")
    def _verify_and_write(self, name: str, kind: str, region: str, v: dict) -> None:
        warn = ""
        try:
            if kind == "pf-keys":
                ident = profiles.identity_for_keys(v["akid"], v["secret"], v["token"])   # verify before anything is written
                if str(ident.get("Arn", "")).endswith(":root"):
                    warn = "These are root credentials. They were saved, but a read-only IAM user or role is strongly preferred."
                profiles.add_access_key_profile(name, v["akid"], v["secret"], v["token"], region)
            elif kind == "pf-role":
                kw = {"RoleArn": v["role_arn"].strip(), "RoleSessionName": "deadweight-check"}
                if v["external"].strip():
                    kw["ExternalId"] = v["external"].strip()
                boto3.Session(profile_name=str(v["source"])).client("sts").assume_role(**kw)
                profiles.add_role_profile(name, v["role_arn"], str(v["source"]), region, v["external"])
            else:
                profiles.add_sso_profile(name, name, v["start"], v["sso_region"], str(v["account"]), str(v["role_name"]), region)
            ident = profiles.validate(name)
            self.app.call_from_thread(self._done, name, ident, warn)
        except Exception as ex:
            self.app.call_from_thread(self._failed, str(ex))

    def _failed(self, msg: str) -> None:
        self.query_one("#dlg-apply", Button).disabled = False
        self._status(f"Not saved: {msg}" if "Not saved" not in msg else msg, "error")

    def _done(self, name: str, ident: dict, warn: str) -> None:
        self.app.notify(f"{name} → account {fmt_account(ident.get('Account', ''))}" + (f"\n{warn}" if warn else ""),
                        title="Profile saved", severity="warning" if warn else "information", timeout=10 if warn else 5)
        self.dismiss(name)


class TextScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape", "close", "Close")]

    def __init__(self, title: str, subtitle: str, body: str):
        super().__init__()
        self.t, self.s, self.body = title, subtitle, body

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog", classes="text"):
            yield Static(self.t, id="dlg-title")
            yield Static(self.s, id="dlg-sub")
            with VerticalScroll(id="text-body"):
                yield Static(Text(self.body, style=Pal.fg))
            with Horizontal(id="dlg-buttons"):
                yield Static(Text.assemble(("esc", "bold"), " close"), classes="hint")

    def action_close(self) -> None:
        self.dismiss(None)


# ── column specs ───────────────────────────────────────────────────────────────

def _status_chip(status: str) -> Text:
    col = getattr(Pal, STATUS_COLOR.get(status, "muted"))
    return Text.assemble(("● ", col), (status, col), no_wrap=True)


def _actual_cell(r: Resource) -> Text:
    if r.actual_mtd is not None:
        return fmt_money(r.actual_mtd, bold=True)
    if r.actual_recent is not None:
        t = fmt_money(r.actual_recent)
        t.append("*", style=Pal.muted)
        return t
    return fmt_money(None)


MULTI_ACCOUNT = {"on": False}

RES_COLS = [
    Col("Service", lambda r: fmt_service(r.service), lambda r: r.service.lower(), width=22),
    Col("Account", lambda r: Text(r.account_id[-4:].rjust(4, "·"), style=Pal.muted), lambda r: r.account_id, width=7,
        show=lambda: MULTI_ACCOUNT["on"]),
    Col("Region", lambda r: Text(r.region, style=Pal.muted), lambda r: r.region, width=14),
    Col("Type", lambda r: Text(fmt_type(r), style=Pal.fg), lambda r: fmt_type(r).lower(), width=20, hide_below=100),
    Col("Name / ID", lambda r: Text(short_id(r), style=f"bold {Pal.fg}" if r.name else Pal.fg), lambda r: short_id(r).lower(), width=20, flex=True),
    Col("State", lambda r: fmt_state(r.state), lambda r: r.state.lower(), width=12),
    Col("Usage", lambda r: fmt_usage(getattr(r, "usage_state", "")), lambda r: USAGE_ORDER.get(getattr(r, "usage_state", ""), 99),
        width=15, hide_below=120),
    Col("Actual", _actual_cell, lambda r: _num(r.actual_mtd if r.actual_mtd is not None else r.actual_recent), width=10, right=True, hide_below=130),
    Col("Est / mo", lambda r: fmt_money(r.monthly_estimate), lambda r: _num(r.monthly_estimate), width=10, right=True),
    Col("Src", fmt_sources, lambda r: len(r.discovery_sources), width=3, hide_below=110),
    Col("!", lambda r: Text("▲", style=f"bold {Pal.warning}") if (r.details or {}).get("findings") else Text(""),
        lambda r: len((r.details or {}).get("findings") or []), width=1, hide_below=110),
]


def _bill_label(x: dict) -> Text:
    if x["_child"]:
        return Text.assemble(("  ↳ ", Pal.faint), (x["label"], Pal.fg), no_wrap=True, overflow="ellipsis")
    return fmt_service(x["label"])


def _explained_cell(x: dict) -> Text:
    if x["explained"] is None:
        return Text("")
    return Text.assemble(hbar(min(1.0, x["explained"]), 10, Pal.secondary, Pal.success, line=True),
                         (f"{x['explained'] * 100:6.0f}%", Pal.warning if x["explained"] > 1.25 else Pal.muted))


COST_COLS = [
    Col("Bill line", _bill_label, lambda x: x["label"].lower(), width=26, flex=True),
    Col("Actual", lambda x: fmt_money(x["actual"], x.get("currency", "USD"), bold=not x["_child"]), lambda x: x["actual"], width=11, right=True),
    Col("Run-rate", lambda x: fmt_money(x["run_rate"], x.get("currency", "USD")), lambda x: x["run_rate"], width=11, right=True),
    Col("Estimated", lambda x: fmt_money(x["estimate"]), lambda x: _num(x["estimate"]), width=11, right=True),
    Col("Explained", _explained_cell, lambda x: _num(x["explained"]), width=17, hide_below=100),
    Col("Status", lambda x: _status_chip(x["status"]), lambda x: x["status"], width=18),
    Col("Res.", lambda x: Text(f"{x['resources']:,}" if x["resources"] else "·", style=Pal.fg if x["resources"] else Pal.faint,
                               justify="right"), lambda x: x["resources"], width=5, right=True, hide_below=115),
]
FINDING_COLS = [
    Col("Severity", lambda f: fmt_severity(f.severity), lambda f: {"high": 0, "medium": 1, "low": 2, "info": 3}.get(f.severity, 9), width=9),
    Col("Finding", lambda f: Text(f.title, style=f"bold {Pal.fg}"), lambda f: f.title.lower(), width=30, flex=True),
    Col("Resource", lambda f: Text(f.resource_name or "—", style=Pal.fg), lambda f: (f.resource_name or "").lower(), width=24, hide_below=110),
    Col("Service", lambda f: fmt_service(f.service) if f.service else Text(""), lambda f: f.service.lower(), width=16),
    Col("Region", lambda f: Text(f.region, style=Pal.muted), lambda f: f.region, width=14, hide_below=125),
    Col("Savings/mo", lambda f: Text(money(f.monthly_savings), style=f"bold {Pal.success}", justify="right") if f.monthly_savings else Text(""),
        lambda f: _num(f.monthly_savings), width=11, right=True),
    Col("Source", lambda f: Text({"rule": "rule", "cost-optimization-hub": "AWS hub", "compute-optimizer": "AWS CO"}.get(f.source, f.source),
                                 style=Pal.muted), lambda f: f.source, width=8, hide_below=140),
]
ANALYSIS_COLS = [
    Col("Billing service", lambda x: fmt_service(x.get("service", "")), lambda x: x.get("service", "").lower(), width=34),
    Col("Dimension", lambda x: Text(x.get("dimension", "").replace("_", " ").lower(), style=Pal.secondary), lambda x: x.get("dimension", ""), width=13),
    Col("Value", lambda x: Text(x.get("value") or "(none)", style=Pal.fg if x.get("value") else Pal.faint), lambda x: (x.get("value") or "").lower(), width=20, flex=True),
    Col("Actual MTD", lambda x: fmt_money(x.get("actual_mtd"), x.get("currency", "USD"), bold=True), lambda x: abs(x.get("actual_mtd") or 0), width=12, right=True),
    Col("Of service", lambda x: Text.assemble(hbar(x["share"], 10, Pal.secondary, Pal.primary, line=True), (f"{(x['share'] or 0) * 100:6.1f}%", Pal.muted)) if x.get("share") is not None else Text(""), lambda x: _num(x.get("share")), width=17, hide_below=95),
]
GROUP_COLS = [
    Col("Group", lambda g: Text(g["name"], style=f"bold {Pal.fg}" if g["name"] != "(untagged)" else Pal.faint), lambda g: g["name"].lower(), width=24, flex=True),
    Col("Resources", lambda g: Text(f"{g['n']:,}", justify="right", style=Pal.fg), lambda g: g["n"], width=9, right=True),
    Col("Est / mo", lambda g: fmt_money(g["est"] or None, bold=True), lambda g: g["est"], width=11, right=True),
    Col("Actual (CUR)", lambda g: fmt_money(g["actual"]), lambda g: _num(g["actual"]), width=12, right=True, hide_below=105),
    Col("Savings", lambda g: Text(money(g["savings"]), style=Pal.success, justify="right") if g["savings"] else Text(""), lambda g: g["savings"], width=10, right=True),
    Col("Top services", lambda g: Text(g["top"], style=Pal.muted), lambda g: g["top"], width=30, hide_below=120),
]
CATALOG_COLS = [
    Col("Service", lambda r: fmt_service(r.service), lambda r: r.service.lower(), width=12),
    Col("Region", lambda r: Text(r.region, style=Pal.muted), lambda r: r.region, width=14),
    Col("Type", lambda r: Text(r.resource_type, style=Pal.fg), lambda r: r.resource_type, width=24, hide_below=90),
    Col("Name / ID", lambda r: Text(short_id(r), style=f"bold {Pal.fg}"), lambda r: short_id(r).lower(), width=20, flex=True),
    Col("State", lambda r: fmt_state(r.state), lambda r: r.state.lower(), width=12),
]
COV_COLS = [
    Col("Status", lambda x: fmt_cov_status(str(x.get("status", ""))), lambda x: x.get("_sev", 99), width=15),
    Col("Source", lambda x: Text(str(x.get("source", "")), style=Pal.fg), lambda x: str(x.get("source", "")).lower(), width=30),
    Col("Region", lambda x: Text(str(x.get("region", "")), style=Pal.muted), lambda x: str(x.get("region", "")), width=14),
    Col("IAM action", lambda x: Text(str(x.get("action", "")), style=Pal.error if x.get("status") == "denied" else Pal.muted),
        lambda x: str(x.get("action", "")), width=30, hide_below=150),
    Col("Detail", lambda x: Text(str(x.get("detail", "")), style=Pal.muted), lambda x: str(x.get("detail", "")).lower(), width=20, flex=True),
]
DIFF_STYLE = {"added": ("+", "success"), "removed": ("−", "error"), "changed": ("~", "warning"), "cost": ("$", "secondary")}
DIFF_COLS = [
    Col("Change", lambda x: Text.assemble((DIFF_STYLE[x["kind"]][0] + " ", f"bold {getattr(Pal, DIFF_STYLE[x['kind']][1])}"),
                                          (x["kind"], getattr(Pal, DIFF_STYLE[x["kind"]][1]))), lambda x: x["kind"], width=10),
    Col("Service", lambda x: fmt_service(x["service"]), lambda x: x["service"].lower(), width=22),
    Col("Region", lambda x: Text(x["region"], style=Pal.muted), lambda x: x["region"], width=14, hide_below=110),
    Col("Name / ID", lambda x: Text(x["name"], style=Pal.fg), lambda x: x["name"].lower(), width=20, flex=True),
    Col("Detail", lambda x: Text(x["detail"], style=Pal.muted), lambda x: x["detail"].lower(), width=30, hide_below=120),
    Col("Δ $/mo", lambda x: Text(f"{x['delta']:+,.2f}", style=Pal.error if x["delta"] > 0 else Pal.success, justify="right") if x["delta"] else Text(""),
        lambda x: x["delta"], width=11, right=True),
]


def _res_hay(r: Resource) -> str:
    return " ".join([r.service, r.region, r.resource_type, r.name, str(r.resource_id), r.state, r.arn, r.config, r.account_id,
                     getattr(r, "usage_state", ""), " ".join(getattr(r, "usage_evidence", None) or []),
                     r.bill_service, " ".join(r.discovery_sources), " ".join(f"{k}={v}" for k, v in r.tags.items()),
                     " ".join(i for ids in r.relations.values() for i in ids), " ".join((r.details or {}).get("findings") or [])])


# ── the app ────────────────────────────────────────────────────────────────────

APP_CSS = """
Screen { background: $background; }
* {
    scrollbar-size-vertical: 1; scrollbar-size-horizontal: 1;
    scrollbar-background: $background; scrollbar-background-hover: $background; scrollbar-background-active: $background;
    scrollbar-color: $panel-lighten-2; scrollbar-color-hover: $primary 60%; scrollbar-color-active: $primary;
    scrollbar-corner-color: $background;
}
#brandbar { height: 1; background: $surface; }
#brand { width: auto; background: $primary; color: $background; text-style: bold; padding: 0 1; }
#crumb { width: auto; padding: 0 1; }
#ident { width: 1fr; text-align: right; padding: 0 1; }
#mode { width: auto; }

#body { height: 1fr; }
#sidebar { width: 28; height: 1fr; background: $surface; padding: 0 1; }
Screen.-narrow #sidebar { width: 24; }
Screen.-short .side-label { margin: 0 0 0 1; }
.side-label { height: 1; margin: 1 0 0 1; color: $text-muted; text-style: bold; }
#nav { height: auto; background: transparent; }
#nav > ListItem { layout: horizontal; height: 1; padding: 0 1; background: transparent; color: $text-muted; }
#nav > ListItem.-hovered { background: $panel; color: $foreground; }
#nav > ListItem.-highlight { background: $primary 14%; color: $primary; text-style: bold; }
#nav:focus > ListItem.-highlight { background: $primary 26%; color: $primary; text-style: bold; }
.nav-label { width: 1fr; }
.nav-count { width: auto; color: $text-muted; text-style: none; }
.nav-count.-alert { color: $error; text-style: bold; }
#profile { margin: 0 0 1 0; }
#profile > SelectCurrent { background: $panel; }
#sidebar Button { width: 1fr; min-width: 0; margin-bottom: 1; background: $panel; color: $foreground; }
#sidebar Button:hover { background: $panel-lighten-1; }
#sidebar Button:focus { text-style: bold; background: $panel-lighten-2; }
Screen.-short #sidebar Button { margin-bottom: 0; }
#scan { background: $primary; color: $background; text-style: bold; }
#scan:hover { background: $primary-lighten-1; }
#scan:focus { background: $primary-lighten-1; color: $background; }
#scan.-cancel { background: $error; color: $background; }
.pair { height: 1; margin-bottom: 1; }
Screen.-short .pair { margin-bottom: 0; }
.pair Button { margin: 0 !important; }
.pair Button:first-of-type { margin-right: 1 !important; }
#totals { dock: bottom; height: auto; padding: 1 1 0 1; border-top: hkey $panel-lighten-1; margin-bottom: 1; }
Screen.-short #totals { display: none; }

#pages { width: 1fr; height: 1fr; padding: 0 1 0 2; }
.page { height: 1fr; }
.page-head { height: 1; margin: 1 0 1 0; }
.toolbar { height: 1; margin-bottom: 1; }
.filter-icon { width: 2; color: $primary; text-style: bold; }
.filter { width: 1fr; background: $surface; }
.filter:focus { background: $panel; }
.count { width: auto; min-width: 16; padding: 0 0 0 2; text-align: right; }
DataView { height: 1fr; }
DataTable { height: 1fr; background: $background; }
DataTable > .datatable--header { background: $background; color: $text-muted; text-style: bold; }
DataTable > .datatable--header-hover { background: $panel; color: $primary; }
DataTable > .datatable--even-row { background: $surface 55%; }
DataTable > .datatable--odd-row { background: $background; }
DataTable > .datatable--hover { background: $panel 50%; }
DataTable > .datatable--cursor { background: $panel; text-style: none; }
DataTable:focus > .datatable--cursor { background: $primary 24%; text-style: bold; }

.split { height: 1fr; layout: vertical; }
Inspector { height: 13; margin-top: 1; padding: 0 1; background: $background;
    border: round $panel-lighten-2; border-title-color: $primary; border-title-style: bold; border-subtitle-color: $text-muted; }
Screen.-short Inspector { height: 9; }
Screen.-xwide .split { layout: horizontal; }
Screen.-xwide Inspector { height: 1fr; width: 52; margin: 0 0 0 1; }
Inspector.-off { display: none; }
.detail { height: auto; max-height: 5; margin-top: 1; padding: 0 1; background: $surface; }

.panel { height: auto; padding: 0 1; background: $background;
    border: round $panel-lighten-2; border-title-color: $primary; border-title-style: bold; border-subtitle-color: $text-muted; }
#page-overview { height: 1fr; padding-right: 1; }
#hero { height: 1fr; min-height: 18; content-align: center middle; }
#page-overview.has-data #hero { display: none; }
#page-overview.has-data #hero.-scanning { display: block; height: auto; padding: 2 0; }
#page-overview #kpis, #page-overview #ov-a, #page-overview #ov-b { display: none; }
#page-overview.has-data #kpis, #page-overview.has-data #ov-a, #page-overview.has-data #ov-b { display: block; }
#kpis { layout: grid; grid-size: 4; grid-gutter: 0 1; height: auto; margin-bottom: 1; }
.kpi { height: auto; padding: 1 2 1 2; background: $surface; border: none; border-left: tall $primary; }
Screen.-short .kpi { padding: 0 2; }
.kpi-title { color: $text-muted; text-style: bold; }
.kpi-digits { width: auto; color: $primary; text-style: bold; }
.kpi-compact { color: $primary; text-style: bold; display: none; }
.kpi-caption { color: $text-muted; }
.tone-secondary { border-left: tall $secondary; }
.tone-secondary .kpi-digits, .tone-secondary .kpi-compact { color: $secondary; }
.tone-accent { border-left: tall $accent; }
.tone-accent .kpi-digits, .tone-accent .kpi-compact { color: $accent; }
.tone-success { border-left: tall $success; }
.tone-success .kpi-digits, .tone-success .kpi-compact { color: $success; }
Screen.-narrow .kpi-digits { display: none; }
Screen.-narrow .kpi-compact { display: block; }
#ov-a { layout: horizontal; height: auto; margin-bottom: 1; }
#ch-services { width: 3fr; margin-right: 1; }
#ov-side { width: 2fr; height: auto; }
#ov-pacing { margin-bottom: 1; }
#ov-b { layout: horizontal; height: auto; margin-bottom: 1; }
#ov-b > Canvas { width: 1fr; }
#ov-mix, #ov-cov { margin-right: 1; }

.dim-tabs { margin-bottom: 1; }
.summary { margin-bottom: 1; }
#log { height: 1fr; background: $background; padding: 0 1;
    border: round $panel-lighten-2; border-title-color: $primary; border-title-style: bold; }

#statusbar { height: 1; background: $surface; }
#spinner { width: 3; padding: 0 0 0 1; }
#progress { width: auto; padding: 0 1; display: none; }
#statusbar.-scanning #progress { display: block; }
#progress Bar { width: 24; }
#activity { width: 1fr; padding: 0 1; }
Footer { background: $surface; }

ModalScreen { align: center middle; background: $background 75%; }
#dialog { width: 110; height: auto; max-height: 92%; padding: 1 2; background: $surface; border: round $primary; }
#dialog.reports, #dialog.text { width: 100; }
#dialog.options { width: 84; }
#dlg-title { height: 1; color: $primary; text-style: bold; }
#dlg-sub { height: 1; color: $text-muted; margin-bottom: 1; }
#groups-scroll { height: auto; max-height: 34; }
#groups { grid-size: 3; grid-gutter: 1 1; grid-rows: auto; height: auto; }
.group { height: auto; padding: 0 1; border: round $panel-lighten-2; border-title-style: bold; }
.group Checkbox, #opt-scroll Checkbox { background: transparent; }
.fam-compute { border-title-color: $primary; }
.fam-storage { border-title-color: $success; }
.fam-database { border-title-color: $secondary; }
.fam-network { border-title-color: $accent; }
.fam-security { border-title-color: $error; }
.fam-integration { border-title-color: $warning; }
.fam-observability, .fam-ai, .fam-discovery { border-title-color: $text-muted; }
#opt-scroll { height: auto; max-height: 30; }
.opt-label { color: $text-muted; text-style: bold; margin-top: 1; }
#opt-scroll Input { margin-bottom: 1; background: $panel; }
#opt-scroll RadioSet { background: transparent; border: none; }
.opt-row { height: 1; }
.opt-inline { width: auto; padding: 0 1 0 0; }
.opt-row Input { width: 10; margin-right: 3; }
#text-body { height: auto; max-height: 30; background: $panel; padding: 0 1; }
#dlg-buttons { height: 1; margin-top: 1; }
#dlg-buttons .hint { width: 1fr; color: $text-muted; }
#dlg-buttons Button { margin-left: 1; min-width: 10; width: auto; padding: 0 2; background: $panel; }
#dlg-buttons #dlg-apply { background: $primary; color: $background; text-style: bold; }
#report-list { height: auto; max-height: 20; background: $surface; border: none; padding: 0; }
#dialog.profile { width: 92; }
#dialog.profile Input, #dialog.profile Select { margin-bottom: 1; }
#dialog.profile Input { background: $panel; }
#dialog.profile .opt-row Input { width: 1fr; }
#dialog.profile RadioSet { background: transparent; border: none; margin-bottom: 1; }
#pf-switch { height: auto; }
.pf-pane { height: auto; }
.pf-note { color: $text-muted; }
#pf-code { height: auto; margin-bottom: 1; }
#pf-status { height: auto; min-height: 1; margin-top: 1; }
#pf-signin { margin-left: 2; min-width: 12; width: auto; padding: 0 2; background: $primary; color: $background; text-style: bold; }
"""


class AwsCostApp(App):
    TITLE = "Deadweight"
    CSS = APP_CSS
    HORIZONTAL_BREAKPOINTS = [(0, "-narrow"), (140, "-wide"), (196, "-xwide")]
    VERTICAL_BREAKPOINTS = [(0, "-short"), (42, "-tall")]
    BINDINGS = [
        Binding("r", "run_scan", "Scan"),
        Binding("x", "cancel_scan", "Cancel", show=False),
        Binding("s", "pick_services", "Services"),
        Binding("g", "scan_options", "Options"),
        Binding("e", "export", "Export"),
        Binding("o", "open_report", "Open"),
        Binding("c", "compare", "Compare"),
        Binding("slash", "focus_filter", "Filter"),
        Binding("i", "toggle_inspector", "Inspector", show=False),
        Binding("p", "show_permissions", "Permissions", show=False),
        Binding("t", "cycle_theme", "Theme"),
        Binding("plus", "add_profile", "Add profile", show=False),
        Binding("q", "quit", "Quit"),
        *[Binding(PAGE_KEYS[n], f"goto({n})", f"Go to {p[2]}", show=False) for n, p in enumerate(PAGES)],
    ]

    def __init__(self, report: Path | None = None, theme_name: str = "aws-nebula", options: ScanOptions | None = None):
        super().__init__()
        self.opts = options or ScanOptions()
        self.result: ScanResult | None = None
        self.identity_info: dict | None = None
        self.identity_error: str | None = None
        self.mode = "idle"
        self.asof: datetime | None = None
        self.report_path: Path | None = None
        self._initial_report, self._theme_name = report, theme_name
        self._scanner: Scanner | None = None
        self._scanning = False
        self._failed: str | None = None
        self._stream: list[Resource] = []
        self._spin_i = 0
        self._scan_t0 = 0.0
        self._log_errors = 0
        self._progress: tuple[str, int, int] = ("", 0, 1)
        self._diff: dict | None = None
        self._report_count = 0
        for t in THEMES:
            self.register_theme(t)

    # compose -------------------------------------------------------------------
    def compose(self) -> ComposeResult:
        try:
            profiles = boto3.Session().available_profiles or []
        except Exception:
            profiles = []
        initial = self.opts.profile if self.opts.profile in profiles else (profiles[0] if profiles else DEFAULT_CHAIN)
        with Horizontal(id="brandbar"):
            yield Static("◆ DEADWEIGHT", id="brand")
            yield Static("", id="crumb")
            yield Static("", id="ident")
            yield Static("", id="mode")
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield Static("NAVIGATE", classes="side-label")
                yield ListView(*[NavItem(p, icon, label) for p, icon, label in PAGES], id="nav", initial_index=0)
                yield Static("CONNECTION", classes="side-label")
                yield Select(self._profile_options(profiles), prompt="AWS profile",
                             id="profile", compact=True, value=initial)
                with Horizontal(classes="pair"):
                    yield Button("", id="services", compact=True)
                    yield Button("Options", id="options", compact=True)
                yield Button("▶  Scan account", id="scan", compact=True)
                with Horizontal(classes="pair"):
                    yield Button("Export", id="export", compact=True)
                    yield Button("Open", id="open", compact=True)
                yield Static("", id="totals")
            with ContentSwitcher(id="pages", initial="page-overview"):
                with VerticalScroll(id="page-overview", classes="page"):
                    yield Static(classes="page-head", id="head-overview")
                    yield Canvas(id="hero")
                    with Grid(id="kpis"):
                        yield KpiCard("MTD ACTUAL", "Cost Explorer", id="k-mtd", tone="primary")
                        yield KpiCard("RUN-RATE", "linear projection", id="k-proj", tone="secondary")
                        yield KpiCard("EXPLAINED", "by resource estimates", id="k-exp", tone="accent")
                        yield KpiCard("SAVINGS / MO", "from findings", id="k-save", tone="success")
                    with Horizontal(id="ov-a"):
                        yield Canvas(id="ch-services", classes="panel")
                        with Vertical(id="ov-side"):
                            yield Canvas(id="ov-pacing", classes="panel")
                            yield Canvas(id="ch-regions", classes="panel")
                    with Horizontal(id="ov-b"):
                        yield Canvas(id="ov-mix", classes="panel")
                        yield Canvas(id="ov-cov", classes="panel")
                        yield Canvas(id="ov-top", classes="panel")
                with Vertical(id="page-resources", classes="page"):
                    yield Static(classes="page-head", id="head-resources")
                    with Container(classes="split"):
                        yield DataView(RES_COLS, haystack=_res_hay, id="dv-resources",
                                       placeholder="filter by service, region, type, name, state, tag, related id or finding   ( -term excludes )")
                        yield Inspector(id="insp-resources")
                with Vertical(id="page-costs", classes="page"):
                    yield Static(classes="page-head", id="head-costs")
                    yield Canvas(id="cost-summary", classes="panel summary")
                    yield DataView(COST_COLS, haystack=lambda x: f"{x['label']} {x['bill']} {x['status']}", id="dv-costs",
                                   placeholder="filter bill lines or status (e.g. 'no collector')")
                with Vertical(id="page-findings", classes="page"):
                    yield Static(classes="page-head", id="head-findings")
                    yield Canvas(id="find-summary", classes="panel summary")
                    yield DataView(FINDING_COLS, id="dv-findings", placeholder="filter findings, resources, services, severity",
                                   haystack=lambda f: f"{f.severity} {f.category} {f.title} {f.resource_name} {f.resource_key} {f.service} {f.region} {f.detail} {f.source}")
                    yield Static("", id="find-detail", classes="detail")
                with Vertical(id="page-analysis", classes="page"):
                    yield Static(classes="page-head", id="head-analysis")
                    yield Tabs(id="dim-tabs", classes="dim-tabs")
                    yield DataView(ANALYSIS_COLS, id="dv-analysis", placeholder="filter billing service, dimension or value",
                                   haystack=lambda x: f"{x.get('service', '')} {x.get('dimension', '')} {x.get('value', '')}")
                with Vertical(id="page-groups", classes="page"):
                    yield Static(classes="page-head", id="head-groups")
                    yield Tabs(id="group-tabs", classes="dim-tabs")
                    yield DataView(GROUP_COLS, id="dv-groups", placeholder="filter groups  ·  enter shows the group's resources",
                                   haystack=lambda g: f"{g['name']} {g['top']}")
                with Vertical(id="page-catalog", classes="page"):
                    yield Static(classes="page-head", id="head-catalog")
                    with Container(classes="split"):
                        yield DataView(CATALOG_COLS, id="dv-catalog", placeholder="filter models, profiles, providers, regions",
                                       haystack=lambda r: f"{r.service} {r.region} {r.resource_type} {r.name} {r.resource_id} {r.state}")
                        yield Inspector(id="insp-catalog")
                with Vertical(id="page-coverage", classes="page"):
                    yield Static(classes="page-head", id="head-coverage")
                    yield Canvas(id="cov-summary", classes="panel summary")
                    yield DataView(COV_COLS, id="dv-coverage", placeholder="filter source, region, status, IAM action or error",
                                   haystack=lambda x: " ".join(str(x.get(k, "")) for k in ("source", "region", "status", "detail", "action", "account")))
                    yield Static("", id="cov-detail", classes="detail")
                with Vertical(id="page-compare", classes="page"):
                    yield Static(classes="page-head", id="head-compare")
                    yield Canvas(id="cmp-summary", classes="panel summary")
                    yield Tabs(Tab("All", id="cmp-all"), Tab("Added", id="cmp-added"), Tab("Removed", id="cmp-removed"),
                               Tab("Changed", id="cmp-changed"), Tab("Cost movers", id="cmp-cost"), id="cmp-tabs", classes="dim-tabs")
                    yield DataView(DIFF_COLS, id="dv-compare", placeholder="filter changes",
                                   haystack=lambda x: f"{x['kind']} {x['service']} {x['region']} {x['name']} {x['detail']}")
                with Vertical(id="page-activity", classes="page"):
                    yield Static(classes="page-head", id="head-activity")
                    yield RichLog(id="log", wrap=True, markup=False, highlight=False, max_lines=5000)
        with Horizontal(id="statusbar"):
            yield Static("", id="spinner")
            yield ProgressBar(total=100, show_eta=False, show_percentage=False, id="progress")
            yield Static("", id="activity")
        yield Footer()

    def on_mount(self) -> None:
        self.theme_changed_signal.subscribe(self, self._theme_changed)
        if self._theme_name in self.available_themes:
            self.theme = self._theme_name
        for wid, title, sub in [("#ch-services", "SPEND BY SERVICE", "month to date"), ("#ov-pacing", "MONTH PACING", "daily trend"),
                                ("#ch-regions", "SPEND BY REGION", "CE REGION"), ("#ov-mix", "INVENTORY MIX", "by service family"),
                                ("#ov-cov", "DISCOVERY COVERAGE", "checks"), ("#ov-top", "TOP SAVINGS", "per month"),
                                ("#cov-summary", "HEALTH", ""), ("#cost-summary", "RECONCILIATION", ""), ("#find-summary", "POTENTIAL SAVINGS", ""),
                                ("#cmp-summary", "COMPARISON", ""), ("#insp-resources", "INSPECTOR", "i to hide"),
                                ("#insp-catalog", "INSPECTOR", "i to hide"), ("#log", "SCAN LOG", "")]:
            w = self.query_one(wid)
            w.border_title, w.border_subtitle = title, sub
        self._spin_timer = self.set_interval(0.08, self._spin, pause=True)
        self._rain_i = 0
        self.set_interval(0.12, self._rain)
        self._report_count = len(list(REPORT_DIR.glob("aws-report-*.json"))) if REPORT_DIR.exists() else 0
        self.repaint_all()
        p = self.query_one("#profile", Select)
        if p.value is not SELECT_NONE:
            self.validate_identity(str(p.value))
        if self._initial_report:
            self.load_report(Path(self._initial_report))

    # theming -------------------------------------------------------------------
    def _theme_changed(self, _theme) -> None:
        self.repaint_all()

    def repaint_all(self) -> None:
        Pal.load(self)
        self.query_one("#progress", ProgressBar).gradient = Gradient.from_colors(Pal.secondary, Pal.primary)
        self.paint_brand(); self.paint_heads(); self.paint_nav(); self.paint_totals(); self.paint_status()
        self.paint_overview(); self.paint_summaries()
        self.query_one("#services", Button).label = f"Svc {len(self.opts.services)}/{len(REGISTRY)}"
        self.query_one("#options", Button).label = {"active": "Opt · active"}.get(self.opts.region_mode, "Options") if not self.opts.regions else f"Opt · {len(self.opts.regions)} rgn"
        for dv in self.query(DataView):
            dv.refresh_view(keep_cursor=True)
        for ins in self.query(Inspector):
            ins.repaint()

    def action_cycle_theme(self) -> None:
        names = [n for n in THEME_CYCLE if n in self.available_themes]
        self.theme = names[(names.index(self.theme) + 1) % len(names)] if self.theme in names else names[0]
        self.notify(f"Theme  ·  {self.theme}", timeout=2)

    # painting ------------------------------------------------------------------
    @property
    def has_data(self) -> bool:
        return self.result is not None

    @property
    def current_page(self) -> str:
        return (self.query_one("#pages", ContentSwitcher).current or "page-overview").removeprefix("page-")

    def paint_brand(self) -> None:
        label = next((l for p, _, l in PAGES if p == self.current_page), "")
        self.query_one("#crumb", Static).update(Text.assemble(("❯ ", Pal.faint), (label, f"bold {Pal.fg}")))
        t = Text(no_wrap=True, overflow="ellipsis", justify="right")
        ident = (self.result.identity if self.mode == "report" and self.result else self.identity_info) or {}
        n_accounts = len((self.result.meta.get("accounts") if self.result else None) or [1])
        if ident.get("Account"):
            arn = str(ident.get("Arn", ""))
            principal = arn.split(":", 5)[5] if arn.count(":") >= 5 else arn
            t.append("account ", style=Pal.muted); t.append(fmt_account(ident["Account"]), style=f"bold {Pal.fg}")
            if n_accounts > 1:
                t.append(f" +{n_accounts - 1} org accounts", style=Pal.secondary)
            t.append("   ", style=Pal.faint)
            if principal == "root":
                t.append(" ROOT ", style=f"bold {Pal.bg} on {Pal.error}")
                t.append(" prefer a read-only role (g)", style=Pal.error)
            else:
                t.append(principal, style=Pal.muted)
        elif self.identity_error:
            t.append("✕ " + trunc(self.identity_error, 90), style=Pal.error)
        else:
            t.append("no identity yet", style=Pal.faint)
        if self.opts.role_arn and self.mode != "report":
            t.append("  ⇢ role " + self.opts.role_arn.rsplit("/", 1)[-1], style=Pal.secondary)
        self.query_one("#ident", Static).update(t)
        if self._scanning:
            _, done, total = self._progress
            chip = (f" {SPINNER[self._spin_i % len(SPINNER)]} SCANNING {done / max(1, total) * 100:3.0f}% ", Pal.primary)
        elif self.mode == "live" and self.asof:
            chip = (f" ● LIVE  {self.asof:%H:%M} ", Pal.success)
        elif self.mode == "report" and self.asof:
            chip = (f" ◉ REPORT  {self.asof:%d %b %H:%M} ", Pal.secondary)
        elif self._failed:
            chip = (" ✕ FAILED ", Pal.error)
        else:
            chip = (" ○ IDLE ", Pal.panel)
        style = f"bold {Pal.bg} on {chip[1]}" if chip[1] != Pal.panel else f"bold {Pal.muted} on {Pal.panel}"
        self.query_one("#mode", Static).update(Text(chip[0], style=style))

    def paint_heads(self) -> None:
        dot = lambda c: ("● ", c)
        period = self.result.period.label if self.result and self.result.period else "month to date"
        heads = {
            "overview": ("Overview", [("spend, pacing, reconciliation and savings at a glance", Pal.muted)]),
            "resources": ("Resources", [("deduplicated across sources   ", Pal.muted), dot(Pal.primary), ("direct  ", Pal.muted),
                                        dot(Pal.secondary), ("explorer  ", Pal.muted), dot(Pal.accent), ("tagging   ", Pal.muted),
                                        ("actual = CUR per resource, * = EC2 last 14 days", Pal.faint)]),
            "costs": ("Costs", [(f"every bill line ({period}) matched to the resources that produce it", Pal.muted)]),
            "findings": ("Findings", [("waste, rightsizing, hygiene and security, with $ impact  ·  enter jumps to the resource", Pal.muted)]),
            "analysis": ("Cost analysis", [("usage type, operation, region, record / purchase / instance type, tags and accounts", Pal.muted)]),
            "groups": ("Groups", [("inventory and estimates grouped by stack, tag, VPC, region or account", Pal.muted)]),
            "catalog": ("AWS catalog", [("Bedrock models & inference profiles available to the account, not deployed resources", Pal.muted)]),
            "coverage": ("Coverage", [("every collector × region; ", Pal.muted), ("p", f"bold {Pal.primary}"),
                                      (" shows an IAM policy for denied calls", Pal.muted)]),
            "compare": ("Compare", [("what changed between a saved report and the current data  ·  ", Pal.muted),
                                    ("c", f"bold {Pal.primary}"), (" picks the baseline", Pal.muted)]),
            "activity": ("Activity", [("scan log, newest at the bottom", Pal.muted)]),
        }
        for page, (title, sub) in heads.items():
            self.query_one(f"#head-{page}", Static).update(
                Text.assemble((title, f"bold {Pal.fg}"), ("   ", ""), *sub, no_wrap=True, overflow="ellipsis"))

    def paint_nav(self) -> None:
        res = self.result
        def item(p) -> Any: return self.query_one(f"#nav-{p}", NavItem)
        n_res = len(res.resources) if res else len(self._stream)
        item("resources").set_count(f"{n_res:,}" if n_res else "")
        item("costs").set_count(f"{len(res.reconciliation):,}" if res and res.reconciliation else "")
        if res and res.findings:
            high = sum(1 for f in res.findings if f.severity == "high")
            item("findings").set_count(f"▲ {high}" if high else f"{len(res.findings)}", alert=bool(high))
        else:
            item("findings").set_count("")
        item("analysis").set_count(f"{len(res.billing_breakdown):,}" if res and res.billing_breakdown else "")
        item("groups").set_count("")
        item("catalog").set_count(f"{len(res.catalog):,}" if res and res.catalog else "")
        if res and res.coverage:
            bad = sum(1 for x in res.coverage if x.get("status") in ("denied", "error", "timeout", "unavailable"))
            item("coverage").set_count(f"✕ {bad}" if bad else "✓", alert=bool(bad))
        else:
            item("coverage").set_count("")
        item("compare").set_count("Δ" if self._diff else "")
        item("activity").set_count(f"✕ {self._log_errors}" if self._log_errors else "", alert=bool(self._log_errors))

    def _totals(self) -> dict:
        res = self.result
        actual = sum(c.actual_mtd for c in res.costs)
        proj = sum(c.projected_month for c in res.costs)
        est, run = explained_totals(res.reconciliation)
        return {"actual": actual, "proj": proj, "explained": (est / run) if run else None, "est": est, "run": run,
                "savings": sum((f.monthly_savings or 0) for f in res.findings),
                "forecast": (actual + res.forecast) if res.forecast is not None else None}

    def paint_totals(self) -> None:
        g = Table.grid(expand=True)
        g.add_column(style=Pal.muted, no_wrap=True); g.add_column(justify="right", no_wrap=True)
        if self.has_data:
            t = self._totals()
            g.add_row("MTD actual", Text(money(t["actual"]), style=f"bold {Pal.primary}"))
            g.add_row("Run-rate", Text(money(t["proj"]), style=f"bold {Pal.fg}"))
            g.add_row("Explained", Text(f"{t['explained']:.0%}" if t["explained"] is not None else "—", style=Pal.accent))
            g.add_row("Savings/mo", Text(money(t["savings"]), style=Pal.success))
            g.add_row("Resources", Text(f"{len(self.result.resources):,}", style=Pal.fg))
        else:
            for k in ("MTD actual", "Run-rate", "Explained", "Savings/mo"):
                g.add_row(k, Text("—", style=Pal.faint))
            g.add_row("Resources", Text(f"{len(self._stream):,}" if self._stream else "—", style=Pal.fg if self._stream else Pal.faint))
        self.query_one("#totals", Static).update(g)

    def paint_status(self) -> None:
        sp, act = self.query_one("#spinner", Static), self.query_one("#activity", Static)
        self.query_one("#statusbar").set_class(self._scanning, "-scanning")
        if self._scanning:
            label, done, total = self._progress
            sp.update(Text(SPINNER[self._spin_i % len(SPINNER)], style=f"bold {Pal.primary}"))
            act.update(Text.assemble((f"{done / max(1, total) * 100:3.0f}%  ", f"bold {Pal.primary}"), (label or "starting…", Pal.fg),
                                     (f"   {done}/{total} tasks  ·  {len(self._stream):,} resources  ·  {fmt_dur(time.monotonic() - self._scan_t0)}  ·  ", Pal.muted),
                                     ("x", f"bold {Pal.primary}"), (" cancels", Pal.muted), no_wrap=True, overflow="ellipsis"))
        elif self._failed:
            sp.update(Text("✕", style=f"bold {Pal.error}"))
            act.update(Text.assemble(("Scan failed  ", f"bold {Pal.error}"), (self._failed, Pal.muted), no_wrap=True, overflow="ellipsis"))
        elif self.has_data:
            res = self.result
            sp.update(Text("✓", style=f"bold {Pal.success}"))
            cancelled = res.meta.get("cancelled")
            what = (("Scan cancelled — partial results" if cancelled else f"Scan complete in {fmt_dur(res.meta.get('duration_s', 0))}")
                    if self.mode == "live" else f"Report {self.report_path.name if self.report_path else ''}")
            bad = sum(1 for c in res.coverage if c.get("status") in ("denied", "error", "timeout"))
            act.update(Text.assemble((what, f"bold {Pal.warning if cancelled else Pal.fg}"),
                                     (f"   {len(res.resources):,} resources  ·  {len(res.findings)} findings  ·  {len(res.coverage):,} checks  ·  ", Pal.muted),
                                     (f"{bad} failed", Pal.error if bad else Pal.muted),
                                     (f"  ·  Cost Explorer ≈ ${res.meta.get('ce_cost', 0):.2f}" if res.meta.get("ce_requests") else "", Pal.muted),
                                     no_wrap=True, overflow="ellipsis"))
        else:
            sp.update(Text("●", style=Pal.faint))
            act.update(Text.assemble(("Ready", f"bold {Pal.fg}"), ("   pick a profile and press ", Pal.muted), ("r", f"bold {Pal.primary}"),
                                     (" to scan, ", Pal.muted), ("o", f"bold {Pal.primary}"), (" to open a saved report, ", Pal.muted),
                                     ("g", f"bold {Pal.primary}"), (" for options", Pal.muted), no_wrap=True))

    def paint_overview(self) -> None:
        page = self.query_one("#page-overview")
        page.set_class(self.has_data, "has-data")
        hero = self.query_one("#hero", Canvas)
        hero.set_class(self._scanning, "-scanning")
        scanning = (self._progress[0], self._progress[1], self._progress[2], len(self._stream)) if self._scanning else None
        hero.paint(lambda w: paint_hero(w, reports=self._report_count, scanning=scanning, frame=self._rain_i,
                                        height=hero.size.height or 99, compact=self.has_data))
        if not self.has_data:
            return
        res, t = self.result, self._totals()
        billed = sum(1 for c in res.costs if c.actual_mtd > 0)
        self.query_one("#k-mtd", KpiCard).set(kpi_money(t["actual"]), f"{billed} billed services")
        self.query_one("#k-proj", KpiCard).set(
            kpi_money(t["proj"]), f"AWS forecast {money(t['forecast'])}" if t["forecast"] is not None else f"+{money(max(0.0, t['proj'] - t['actual']))} by month end")
        exp = t["explained"]
        self.query_one("#k-exp", KpiCard).set(f"{exp * 100:.0f}%" if exp is not None else "-",
                                          f"{money(t['est'])} of {money(t['run'])} run-rate")
        high = sum(1 for f in res.findings if f.severity == "high")
        self.query_one("#k-save", KpiCard).set(kpi_money(t["savings"]), f"{len(res.findings)} findings · {high} high")
        svc = [(c.service, c.actual_mtd) for c in res.costs]
        actual = t["actual"]
        self.query_one("#ch-services", Canvas).paint(lambda w: paint_bars(svc, w, rows=14, total=actual))
        period, forecast, daily = res.period, res.forecast, res.daily
        if period is not None:
            self.query_one("#ov-pacing", Canvas).paint(lambda w: paint_pacing(w, period, actual, t["proj"], forecast, daily))
        regions: dict[str, float] = {}
        for row in res.billing_breakdown:
            if row.get("dimension") == "REGION":
                k = row.get("value") or "(none)"
                regions[k] = regions.get(k, 0.0) + (row.get("actual_mtd") or 0.0)
        reg = sorted(regions.items(), key=lambda kv: kv[1], reverse=True)
        self.query_one("#ch-regions", Canvas).paint(lambda w: paint_bars(reg, w, rows=5, total=sum(regions.values()), ticks=False, empty="No REGION breakdown"))
        fams: dict[str, int] = {}
        for r in res.resources:
            f = family_of(r.service)
            fams[f] = fams.get(f, 0) + 1
        mix = [(FAMILY_LABEL.get(f, f), n, fam_color(f)) for f, n in sorted(fams.items(), key=lambda kv: kv[1], reverse=True)]
        self.query_one("#ov-mix", Canvas).paint(
            lambda w: paint_legend(mix, w, cols=2 if w >= 40 else 1, pct=w < 40) if mix else Text("No resources", style=Pal.faint))
        parts = self._cov_parts()
        n_checks = sum(n for _, n, _ in parts) or 1
        n_ok = next((n for s_, n, _ in parts if s_ == "ok"), 0)
        failed = sum(n for s_, n, _ in parts if s_ in ("denied", "error", "timeout", "unavailable"))
        health = Text.assemble((f"{n_ok / n_checks * 100:.0f}% ok", f"bold {Pal.success if not failed else Pal.fg}"),
                               (f"  ·  {failed} failed · press 8" if failed else "  ·  nothing failed", Pal.muted))
        self.query_one("#ov-cov", Canvas).paint(
            lambda w: paint_legend(parts[:5], w, cols=1, footer=health) if res.coverage else Text("No coverage checks", style=Pal.faint))
        self.query_one("#ov-top", Canvas).paint(lambda w: paint_findings(w, res.findings, n=7))

    def _cov_parts(self) -> list[tuple[str, float, str]]:
        counts: dict[str, int] = Counter(str(x.get("status", "")) for x in (self.result.coverage if self.result else []))
        colors = {"ok": Pal.success, "not-enabled": Pal.warning, "not-available": Pal.faint, "denied": Pal.error,
                  "error": Pal.error, "timeout": Pal.error, "throttled": Pal.warning, "skipped": Pal.faint, "unavailable": Pal.error,
                  "not-configured": Pal.warning}
        return [(s, n, colors.get(s, Pal.muted)) for s, n in sorted(counts.items(), key=lambda kv: COVERAGE_ORDER.get(kv[0], 50) if kv[0] != "ok" else -1)]

    def paint_summaries(self) -> None:
        res = self.result
        box = self.query_one("#cov-summary", Canvas)
        if res and res.coverage:
            parts = self._cov_parts()
            total = sum(n for _, n, _ in parts) or 1
            ok = next((n for s, n, _ in parts if s == "ok"), 0)
            box.border_subtitle = f"{ok / total * 100:.0f}% of {total} checks ok"
            box.paint(lambda w, parts=parts: paint_legend(parts, w, cols=4 if w >= 100 else 2))
        else:
            box.paint(lambda w: Text("No coverage checks yet", style=Pal.faint))
        cs = self.query_one("#cost-summary", Canvas)
        if res and res.reconciliation:
            t = self._totals()
            statuses = Counter(r["status"] for r in res.reconciliation)
            order = ["reconciled", "partly explained", "over-estimated", "usage-based", "discovered only", "nothing found", "no collector"]
            parts = [(s, statuses[s], getattr(Pal, STATUS_COLOR.get(s, "muted"))) for s in order if statuses.get(s)]
            cs.border_subtitle = f"{t['explained']:.0%} of run-rate explained" if t["explained"] is not None else ""

            def paint_costs(w: int, parts=parts, t=t) -> Text:
                head = Text.assemble(("Estimated ", Pal.muted), (money(t["est"]), f"bold {Pal.accent}"), (" of ", Pal.muted),
                                     (money(t["run"]), f"bold {Pal.fg}"), (" monthly run-rate is explained by inventoried resources", Pal.muted),
                                     no_wrap=True, overflow="ellipsis")
                bar = hbar(min(1.0, t["explained"] or 0), w, Pal.secondary, Pal.success)
                legend = paint_legend(parts, w, bar=False, cols=4 if w >= 100 else 2) if parts else Text("")
                return Text("\n", no_wrap=True).join([head, bar, legend])
            cs.paint(paint_costs)
        else:
            cs.paint(lambda w: Text("No cost data yet", style=Pal.faint))
        fs = self.query_one("#find-summary", Canvas)
        if res and res.findings:
            by: dict[str, float] = defaultdict(float)
            counts = Counter(f.category for f in res.findings)
            for f in res.findings:
                by[f.category] += f.monthly_savings or 0
            colors = {"waste": Pal.error, "rightsizing": Pal.warning, "hygiene": Pal.secondary, "security": Pal.primary,
                      "coverage": Pal.muted, "anomaly": Pal.accent}
            parts = [(f"{cat} ({counts[cat]})", round(by[cat], 2), colors.get(cat, Pal.muted)) for cat in counts]
            total = sum(by.values())
            fs.border_subtitle = f"{money(total)}/mo across {len(res.findings)} findings"
            money_parts = [p for p in parts if p[1] > 0] or [(p[0], 0, p[2]) for p in parts]
            fs.paint(lambda w, mp=money_parts, show=total > 0: paint_legend(mp, w, cols=3 if w >= 100 else 2, bar=show))
        else:
            fs.paint(lambda w: Text("No findings" if res else "No findings yet", style=Pal.faint))
        cm = self.query_one("#cmp-summary", Canvas)
        d = self._diff
        if d:
            def paint_cmp(w: int) -> Text:
                a, b = d["a"], d["b"]
                def line(label, va, vb, fmt, good_down=True):
                    delta = (vb or 0) - (va or 0)
                    col = Pal.muted if not delta else (Pal.success if (delta < 0) == good_down else Pal.error)
                    return Text.assemble((label.ljust(18), Pal.muted), (fmt(va).rjust(12), Pal.fg), ("  →  ", Pal.faint),
                                         (fmt(vb).rjust(12), f"bold {Pal.fg}"), (f"   {delta:+,.2f}" if delta else "", col), no_wrap=True)
                pct = lambda v: "—" if v is None else f"{v:.0%}"
                rows = [Text.assemble((f"{a['generated_at'][:16]}  →  {b['generated_at'][:16]}", f"bold {Pal.fg}"),
                                      ("" if d["same_account"] else "   ⚠ different accounts", Pal.warning), no_wrap=True),
                        line("Resources", d["unique_a"], d["unique_b"], lambda v: f"{v:,}", good_down=True),
                        line("Run-rate", a["run_rate"], b["run_rate"], money),
                        line("Estimated", a["estimate"], b["estimate"], money),
                        Text.assemble(("Explained".ljust(18), Pal.muted), (pct(a["explained"]).rjust(12), Pal.fg), ("  →  ", Pal.faint),
                                      (pct(b["explained"]).rjust(12), f"bold {Pal.fg}"), no_wrap=True),
                        Text.assemble((f"+{len(d['added'])} added   −{len(d['removed'])} removed   ~{len(d['changed'])} changed", Pal.muted), no_wrap=True)]
                return Text("\n", no_wrap=True).join(rows)
            cm.paint(paint_cmp)
        else:
            cm.paint(lambda w: Text.assemble(("No comparison yet. Load or scan data, then press ", Pal.faint), ("c", f"bold {Pal.primary}"),
                                             (" to pick a saved report as the baseline.", Pal.faint)))

    def _rain(self) -> None:
        """Advance the hero's rain by one frame, only while the hero is on screen."""
        if self.animation_level == "none" or len(self.screen_stack) > 1 or self.has_data:
            return
        try:
            if self.current_page != "overview":
                return
            hero = self.query_one("#hero", Canvas)
        except NoMatches:                          # the app is shutting down
            return
        self._rain_i += 1
        hero.refresh()

    def _spin(self) -> None:
        self._spin_i += 1
        if self._scanning:
            self.query_one("#spinner", Static).update(Text(SPINNER[self._spin_i % len(SPINNER)], style=f"bold {Pal.primary}"))
            if self._spin_i % 4 == 0:
                self.paint_brand(); self.paint_status()

    # navigation ----------------------------------------------------------------
    @on(ListView.Highlighted, "#nav")
    def _nav(self, e: ListView.Highlighted) -> None:
        if isinstance(e.item, NavItem):
            self.show_page(e.item.page)

    @on(ListView.Selected, "#nav")
    def _nav_select(self, e: ListView.Selected) -> None:
        if isinstance(e.item, NavItem):
            self.show_page(e.item.page, focus=True)

    def show_page(self, page: str, focus=False) -> None:
        self.query_one("#pages", ContentSwitcher).current = f"page-{page}"
        self.paint_brand()
        if focus:
            self.call_after_refresh(self._focus_page)

    def _focus_page(self) -> None:
        from textual.widgets import DataTable
        page = self.query_one(f"#page-{self.current_page}")
        target = next(iter(page.query(DataTable)), None) or next(iter(page.query(RichLog)), None)
        if target:
            target.focus()

    def action_goto(self, n: int) -> None:
        self.query_one("#nav", ListView).index = n
        self.show_page(PAGES[n][0], focus=True)

    def _goto_page(self, page: str) -> None:
        self.action_goto([p for p, _, _ in PAGES].index(page))

    def action_focus_filter(self) -> None:
        dv = next(iter(self.query_one(f"#page-{self.current_page}").query(DataView)), None)
        if dv:
            dv.focus_filter()
        else:
            self.notify("This view has no filter", timeout=2)

    def action_toggle_inspector(self) -> None:
        for ins in self.query(Inspector):
            ins.toggle_class("-off")

    @on(DataView.Highlighted, "#dv-resources")
    def _inspect_resource(self, e) -> None:
        self.query_one("#insp-resources", Inspector).show(e.item)

    @on(DataView.Highlighted, "#dv-catalog")
    def _inspect_catalog(self, e) -> None:
        self.query_one("#insp-catalog", Inspector).show(e.item)

    @on(DataView.Highlighted, "#dv-coverage")
    def _coverage_detail(self, e) -> None:
        x = e.item
        body = (Text.assemble(fmt_cov_status(str(x.get("status", ""))), ("  " + str(x.get("source", "")), f"bold {Pal.fg}"),
                              ("  " + str(x.get("region", "")), Pal.muted), (f"  · {x['action']}" if x.get("action") else "", Pal.error),
                              (f"  · account {x['account']}" if x.get("account") else "", Pal.muted),
                              ("\n" + str(x.get("detail", "") or "—"), Pal.fg))
                if x else Text("Highlight a check to read its full detail", style=Pal.faint))
        self.query_one("#cov-detail", Static).update(body)

    @on(DataView.Highlighted, "#dv-findings")
    def _finding_detail(self, e) -> None:
        f: Finding | None = e.item
        body = (Text.assemble(fmt_severity(f.severity), ("  " + f.title, f"bold {Pal.fg}"),
                              (f"  · {money(f.monthly_savings)}/mo" if f.monthly_savings else "", f"bold {Pal.success}"),
                              (f"  · {f.category} · {f.rule}", Pal.muted), ("\n" + (f.detail or ""), Pal.fg),
                              (f"\n{f.resource_key}" if f.resource_key else "", Pal.faint))
                if f else Text("Highlight a finding to read it  ·  enter opens the resource", style=Pal.faint))
        self.query_one("#find-detail", Static).update(body)

    @on(DataView.Selected, "#dv-findings")
    def _finding_open(self, e) -> None:
        f: Finding = e.item
        if f.resource_key:
            self._goto_page("resources")
            self.query_one("#dv-resources", DataView).set_filter(f.resource_name or f.resource_key)

    @on(DataView.Selected, "#dv-groups")
    def _group_open(self, e) -> None:
        g = e.item
        self._goto_page("resources")
        self.query_one("#dv-resources", DataView).set_filter(g["filter"])

    @on(DataView.Selected, "#dv-costs")
    def _cost_open(self, e) -> None:
        x = e.item
        self._goto_page("resources")
        self.query_one("#dv-resources", DataView).set_filter(x["bill"])

    @on(Tabs.TabActivated, "#dim-tabs")
    def _dimension(self, e: Tabs.TabActivated) -> None:
        dim = (e.tab.id or "dim-ALL").split("-", 1)[1]
        dv = self.query_one("#dv-analysis", DataView)
        key = self._dim_ids.get(dim, dim) if hasattr(self, "_dim_ids") else dim
        dv.predicate = None if dim == "ALL" else (lambda x, d=key: x.get("dimension") == d)
        dv.refresh_view()

    @on(Tabs.TabActivated, "#group-tabs")
    def _group_by(self, e: Tabs.TabActivated) -> None:
        self._fill_groups((e.tab.id or "grp-0").split("-", 1)[1])

    @on(Tabs.TabActivated, "#cmp-tabs")
    def _cmp_tab(self, e: Tabs.TabActivated) -> None:
        kind = (e.tab.id or "cmp-all").removeprefix("cmp-")
        dv = self.query_one("#dv-compare", DataView)
        dv.predicate = None if kind == "all" else (lambda x, k=kind: x["kind"] == k)
        dv.refresh_view()

    # identity ------------------------------------------------------------------
    @on(Select.Changed, "#profile")
    def profile_changed(self, e: Select.Changed) -> None:
        if e.value == ADD_PROFILE:
            # Not a real profile: open the dialog and put the previous choice back.
            e.select.value = getattr(self, "_last_profile", DEFAULT_CHAIN)
            self.action_add_profile()
            return
        self._last_profile = e.value
        if e.value is not SELECT_NONE:
            self.validate_identity(str(e.value))

    @work(thread=True, exclusive=True, group="identity")
    def validate_identity(self, profile: str) -> None:
        try:
            i = boto3.Session(profile_name=None if profile == DEFAULT_CHAIN else profile).client("sts").get_caller_identity()
            self.call_from_thread(self._set_identity, i, None)
        except Exception as ex:
            self.call_from_thread(self._set_identity, None, str(ex))

    def _set_identity(self, ident: dict | None, err: str | None) -> None:
        self.identity_info, self.identity_error = ident, err
        self.paint_brand()

    # profiles ------------------------------------------------------------------------
    @staticmethod
    def _profile_options(names: list[str]) -> list[tuple[str, str]]:
        return [(p, p) for p in names] + [("default credential chain", DEFAULT_CHAIN), ("+ add profile…", ADD_PROFILE)]

    def action_add_profile(self) -> None:
        def done(name: str | None) -> None:
            if not name:
                return
            sel = self.query_one("#profile", Select)
            sel.set_options(self._profile_options(profiles.list_profiles()))
            sel.value = name
            self._last_profile = name
            self.write_log(f"Added AWS profile '{name}'")
        self.push_screen(AddProfileScreen(profiles.list_profiles()), done)

    # services & options ----------------------------------------------------------
    @on(Button.Pressed, "#services")
    def pick(self) -> None: self.action_pick_services()

    @on(Button.Pressed, "#options")
    def opt_btn(self) -> None: self.action_scan_options()

    def action_pick_services(self) -> None:
        def done(v):
            if v is not None:
                self.opts = replace(self.opts, services=v)
                self.repaint_all()
                self.write_log(f"Selected {len(v)} collectors")
        self.push_screen(ServicePicker(set(self.opts.services)), done)

    def action_scan_options(self) -> None:
        def done(o):
            if o is not None:
                self.opts = o
                self.repaint_all()
                regions = "all regions" if not o.regions and o.region_mode == "all" else "active regions" if o.region_mode == "active" else ", ".join(o.regions)
                self.write_log(f"Options: {regions} · {o.workers} workers" + (f" · role {o.role_arn}" if o.role_arn else "")
                               + (" · organization" if o.org else ""))
        self.push_screen(OptionsScreen(self.opts), done)

    # scanning ------------------------------------------------------------------
    @on(Button.Pressed, "#scan")
    def scan_btn(self) -> None:
        self.action_cancel_scan() if self._scanning else self.action_run_scan()

    def action_run_scan(self) -> None:
        if self._scanning:
            self.notify("A scan is already running (x cancels it)", severity="warning")
            return
        p = self.query_one("#profile", Select).value
        if p is SELECT_NONE and not self.opts.role_arn:
            self.notify("Select an AWS profile first", severity="error")
            return
        if not self.opts.services:
            self.notify("Select at least one collector", severity="warning")
            return
        self.run_scan(replace(self.opts, profile=None if p in (SELECT_NONE, DEFAULT_CHAIN) else str(p)))

    def action_cancel_scan(self) -> None:
        if self._scanning and self._scanner is not None:
            self._scanner.cancel()
            self.write_log("Cancelling: finishing in-flight calls…")
            self.notify("Cancelling scan…", timeout=3)

    @work(thread=True, exclusive=True, group="scan")
    def run_scan(self, opts: ScanOptions) -> None:
        def log(msg): self.call_from_thread(self.write_log, msg)
        try:
            self.call_from_thread(self.begin_scan_ui)
            log(f"Starting read-only scan · {'profile ' + repr(opts.profile) if opts.profile else 'default credential chain'} · {len(opts.services)} collectors")
            sc = Scanner(opts, log=log, on_resource=lambda r: self.call_from_thread(self.stream_resource, r),
                         on_progress=lambda l, d, t: self.call_from_thread(self.update_progress, l, d, t))
            self._scanner = sc
            res = sc.run()
            self.call_from_thread(self.finish_scan, res)
        except Exception as e:
            self.call_from_thread(self.scan_failed, str(e))

    def begin_scan_ui(self) -> None:
        self._scanning, self._failed, self.mode = True, None, "scanning"
        self._scan_t0, self._stream, self._log_errors = time.monotonic(), [], 0
        self._progress = ("starting…", 0, 1)
        self.result = None
        btn = self.query_one("#scan", Button); btn.label = "◼  Cancel scan"; btn.add_class("-cancel")
        for dv in self.query(DataView):
            if dv.id != "dv-compare":
                dv.set_items([])
        self.query_one("#log", RichLog).clear()
        self.query_one("#progress", ProgressBar).update(total=100, progress=0)
        self._spin_timer.resume()
        self.repaint_all()

    def stream_resource(self, r: Resource) -> None:
        self._stream.append(r)
        self.query_one("#dv-resources", DataView).append(r)
        self.query_one("#nav-resources", NavItem).set_count(f"{len(self._stream):,}")

    def update_progress(self, label: str, done: int, total: int) -> None:
        self._progress = (label, done, total)
        self.query_one("#progress", ProgressBar).update(total=max(1, total), progress=done)
        self.paint_status(); self.paint_brand()
        if self.current_page == "overview":
            self.paint_overview()

    def _end_scan_ui(self) -> None:
        self._scanning = False
        self._scanner = None
        self._spin_timer.pause()
        btn = self.query_one("#scan", Button); btn.label = "▶  Scan account"; btn.remove_class("-cancel")

    def scan_failed(self, msg: str) -> None:
        self._end_scan_ui()
        self._failed, self.mode = msg, "idle"
        self.write_log("[error] Scan failed: " + msg)
        self.repaint_all()
        self.notify(f"Scan failed: {msg}", severity="error", timeout=10)

    def finish_scan(self, res: ScanResult) -> None:
        self._end_scan_ui()
        self.mode, self.asof = "live", datetime.now()
        self.query_one("#progress", ProgressBar).update(total=100, progress=100)
        self.load_data(res)
        self.write_log(f"Done: {len(res.resources)} resources · {len(res.findings)} findings · {len(res.errors)} failed checks · "
                       f"Cost Explorer {res.meta.get('ce_requests', 0)} requests ≈ ${res.meta.get('ce_cost', 0):.2f}")
        t = self._totals()
        self.notify(f"{len(res.resources):,} resources · {money(t['actual'])} MTD · {money(t['savings'])}/mo savings",
                    title="Scan cancelled — partial results" if res.meta.get("cancelled") else "Scan complete")

    def load_data(self, res: ScanResult) -> None:
        self.result = res
        MULTI_ACCOUNT["on"] = len({r.account_id for r in res.resources if r.account_id}) > 1
        ordered = sorted(res.resources, key=lambda z: (z.service, z.region, z.name or z.resource_id))
        dvr = self.query_one("#dv-resources", DataView)
        dvr.relayout()
        dvr.set_items(ordered)
        rows = []
        for top in res.reconciliation:
            rows.append({**top, "_child": False})
            rows += [{**c, "_child": True} for c in top["children"]]
        self.query_one("#dv-costs", DataView).set_items(rows)
        self.query_one("#dv-findings", DataView).set_items(res.findings)
        totals: dict[tuple, float] = {}
        for r in res.billing_breakdown:
            k = (r.get("service", ""), r.get("dimension", ""))
            totals[k] = totals.get(k, 0.0) + abs(r.get("actual_mtd") or 0)
        breakdown = []
        for r in sorted(res.billing_breakdown, key=lambda z: abs(z.get("actual_mtd", 0)), reverse=True):
            t = totals[(r.get("service", ""), r.get("dimension", ""))]
            breakdown.append({**r, "share": abs(r.get("actual_mtd") or 0) / t if t else None})
        self.query_one("#dv-analysis", DataView).set_items(breakdown)
        self._build_dim_tabs(res)
        self._build_group_tabs(res)
        self.query_one("#dv-catalog", DataView).set_items(
            sorted(res.catalog, key=lambda z: (z.service, z.region, z.resource_type, z.name or z.resource_id)))
        cov = [{**x, "_sev": COVERAGE_ORDER.get(str(x.get("status")), 50)} for x in res.coverage]
        self.query_one("#dv-coverage", DataView).set_items(sorted(cov, key=lambda x: x["_sev"]))
        self.repaint_all()

    def _build_dim_tabs(self, res: ScanResult) -> None:
        tabs = self.query_one("#dim-tabs", Tabs)
        tabs.clear()      # removal is asynchronous, so new tabs get fresh ids
        self._tab_gen = getattr(self, "_tab_gen", 0) + 1
        g = self._tab_gen
        dims = []
        present = {r.get("dimension", "") for r in res.billing_breakdown}
        dims += [d for d in DIMENSIONS if d in present] + sorted(d for d in present if d not in DIMENSIONS)
        self._dim_ids = {}
        tabs.add_tab(Tab("All", id=f"dim{g}-ALL"))
        for i, d in enumerate(dims):
            tid = f"d{i}"
            self._dim_ids[tid] = d
            label = d.replace("TAG:", "tag ").replace("_", " ").lower()
            tabs.add_tab(Tab(label.capitalize() if not d.startswith("TAG:") else label, id=f"dim{g}-{tid}"))

    def _group_keys(self, res: ScanResult) -> list[tuple[str, str]]:
        tag_counts = Counter(k for r in res.resources for k in r.tags if not k.startswith("aws:") or k == "aws:cloudformation:stack-name")
        keys = [("stack", "Stack")] if tag_counts.get("aws:cloudformation:stack-name") else []
        keys += [(f"tag:{k}", f"tag {k}") for k, _ in tag_counts.most_common(8) if k not in ("aws:cloudformation:stack-name", "Name")][:5]
        keys += [("vpc", "VPC"), ("region", "Region"), ("family", "Service family")]
        if MULTI_ACCOUNT["on"]:
            keys.append(("account", "Account"))
        return keys

    def _build_group_tabs(self, res: ScanResult) -> None:
        tabs = self.query_one("#group-tabs", Tabs)
        tabs.clear()
        self._tab_gen = getattr(self, "_tab_gen", 0) + 1
        self._group_defs = self._group_keys(res)
        for i, (_, label) in enumerate(self._group_defs):
            tabs.add_tab(Tab(label, id=f"grp{self._tab_gen}-{i}"))
        if self._group_defs:
            self._fill_groups("0")

    def _fill_groups(self, idx: str) -> None:
        if not self.result or not getattr(self, "_group_defs", None):
            return
        key, _ = self._group_defs[int(idx)]
        savings_by: dict[str, float] = defaultdict(float)
        for f in self.result.findings:
            if f.resource_key:
                savings_by[f.resource_key] += f.monthly_savings or 0

        def group_of(r: Resource) -> tuple[str, str]:
            if key == "stack":
                v = r.tags.get("aws:cloudformation:stack-name", "")
                return (v or "(untagged)", f"aws:cloudformation:stack-name={v}" if v else "")
            if key.startswith("tag:"):
                k = key[4:]
                v = r.tags.get(k, "")
                return (v or "(untagged)", f"{k}={v}" if v else "")
            if key == "vpc":
                v = (r.relations.get("vpc") or [""])[0] or (r.resource_id if r.resource_type == "vpc" else "")
                return (v or "(no VPC)", v)
            if key == "region":
                return (r.region, r.region)
            if key == "family":
                f = FAMILY_LABEL.get(family_of(r.service), "Other")
                return (f, "")
            return (r.account_id or "(unknown)", r.account_id)
        groups: dict[str, dict] = {}
        for r in self.result.resources:
            name, flt = group_of(r)
            g = groups.setdefault(name, {"name": name, "n": 0, "est": 0.0, "actual": None, "savings": 0.0, "svc": Counter(), "filter": flt or name})
            g["n"] += 1
            g["est"] += r.monthly_estimate or 0
            if r.actual_mtd is not None:
                g["actual"] = (g["actual"] or 0) + r.actual_mtd
            g["savings"] += savings_by.get(r.arn or r.resource_id, 0)
            g["svc"][r.service] += 1
        for g in groups.values():
            g["top"] = ", ".join(s for s, _ in g["svc"].most_common(3))
        self.query_one("#dv-groups", DataView).set_items(sorted(groups.values(), key=lambda g: g["est"], reverse=True))

    # logging -------------------------------------------------------------------
    def write_log(self, msg: str) -> None:
        glyph, col = "›", Pal.muted
        if msg.startswith("[error] "):
            msg, glyph, col = msg[8:], "✕", Pal.error
            self._log_errors += 1
            self.query_one("#nav-activity", NavItem).set_count(f"✕ {self._log_errors}", alert=True)
        elif msg.startswith("[warn] "):
            msg, glyph, col = msg[7:], "!", Pal.warning
        elif msg.startswith(("Done", "Export", "Opened", "Wrote")):
            glyph, col = "✓", Pal.success
        for line in str(msg).splitlines() or [""]:
            self.query_one("#log", RichLog).write(Text.assemble((datetime.now().strftime("%H:%M:%S") + "  ", Pal.faint),
                                                                (glyph + " ", f"bold {col}"), (line, Pal.fg if col == Pal.muted else col)))

    # saved reports -------------------------------------------------------------
    @on(Button.Pressed, "#open")
    def open_btn(self) -> None: self.action_open_report()

    def _report_files(self) -> list[Path]:
        return sorted(REPORT_DIR.glob("aws-report-*.json"), key=lambda p: p.name, reverse=True) if REPORT_DIR.exists() else []

    def action_open_report(self) -> None:
        files = self._report_files()
        if not files:
            self.notify(f"No saved reports in {REPORT_DIR}. Run a scan and press e to export one.", severity="warning")
            return
        self.push_screen(ReportPicker(files), lambda p: p and self.load_report(p))

    @work(thread=True, exclusive=True, group="report")
    def load_report(self, path: Path) -> None:
        try:
            res = reports.load(path)
            self.call_from_thread(self._apply_report, Path(path), res)
        except Exception as e:
            self.call_from_thread(self.notify, f"Could not open report: {e}", severity="error", timeout=10)

    def _apply_report(self, path: Path, res: ScanResult) -> None:
        if self._scanning:
            self.notify("Finish the running scan first", severity="warning")
            return
        self.mode, self.report_path, self._failed = "report", path, None
        self.asof = res.generated_at.astimezone() if res.generated_at else datetime.now()
        self.load_data(res)
        self.write_log(f"Opened report {path}" + (" (older report format: re-reconciled and de-duplicated)" if res.meta.get("version", 6) < 6 else ""))
        self.notify(f"{len(res.resources):,} resources · {self.asof:%d %b %Y %H:%M}", title="Report opened")

    # compare -------------------------------------------------------------------
    def action_compare(self) -> None:
        if not self.result:
            self.notify("Open or scan data first; it becomes the 'after' side of the comparison", severity="warning")
            return
        files = [f for f in self._report_files() if f != self.report_path]
        if not files:
            self.notify("No other saved report to compare with", severity="warning")
            return
        self.push_screen(ReportPicker(files, "Compare with which baseline report?"), lambda p: p and self.compare_with(p))

    @work(thread=True, exclusive=True, group="compare")
    def compare_with(self, path: Path) -> None:
        try:
            base = reports.load(path)
            d = reports.diff(base, self.result)
            self.call_from_thread(self._apply_diff, d)
        except Exception as e:
            self.call_from_thread(self.notify, f"Comparison failed: {e}", severity="error", timeout=10)

    def _apply_diff(self, d: dict) -> None:
        self._diff = d
        items = []
        for r in d["added"]:
            items.append({"kind": "added", "service": r.service, "region": r.region, "name": r.name or short_id(r),
                          "detail": r.config, "delta": r.monthly_estimate or 0.0})
        for r in d["removed"]:
            items.append({"kind": "removed", "service": r.service, "region": r.region, "name": r.name or short_id(r),
                          "detail": r.config, "delta": -(r.monthly_estimate or 0.0)})
        for c in d["changed"]:
            r = c["resource"]
            est = next(((a, b) for f, a, b in c["deltas"] if f == "estimate"), None)
            items.append({"kind": "changed", "service": r.service, "region": r.region, "name": r.name or short_id(r),
                          "detail": "; ".join(f"{f}: {a} → {b}" for f, a, b in c["deltas"]),
                          "delta": ((est[1] or 0) - (est[0] or 0)) if est else 0.0})
        for c in d["costs"]:
            if abs(c["delta"]) >= 0.01:
                items.append({"kind": "cost", "service": c["label"], "region": "", "name": c["bill"],
                              "detail": f"run-rate {money(c['a'])} → {money(c['b'])}", "delta": c["delta"]})
        self.query_one("#dv-compare", DataView).set_items(items)
        self.paint_summaries(); self.paint_nav()
        self._goto_page("compare")
        if not d["same_account"]:
            self.notify("The two datasets come from different AWS accounts", severity="warning", timeout=6)

    # permissions -----------------------------------------------------------------
    def action_show_permissions(self) -> None:
        if not self.result:
            self.notify("Scan or open a report first", severity="warning")
            return
        missing = reports.missing_permissions(self.result)
        if missing:
            self.push_screen(TextScreen("Missing IAM permissions", f"{len(missing['Statement'][0]['Action'])} read-only actions were denied in this scan",
                                        json.dumps(missing, indent=2)))
        else:
            full = reports.policy(set(self.opts.services))
            self.push_screen(TextScreen("Least-privilege IAM policy", "nothing was denied; this is the full read-only policy for the selected collectors",
                                        json.dumps(full, indent=2)))

    # export --------------------------------------------------------------------
    @on(Button.Pressed, "#export")
    def export_btn(self) -> None: self.action_export()

    def action_export(self) -> None:
        if not self.result:
            self.notify("Run a scan first", severity="warning")
            return
        files = reports.export(self.result, REPORT_DIR)
        self._report_count = len(list(REPORT_DIR.glob("aws-report-*.json")))
        html_file = next((p for p in files if p.suffix == ".html"), None)
        self.notify(f"{len(files)} files in {REPORT_DIR}" + (f"\n{html_file.name}" if html_file else ""), title="Exported", timeout=8)
        self.write_log("\n".join(f"Wrote {p}" for p in files))

    # command palette -------------------------------------------------------------
    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)
        yield SystemCommand("Scan account", "Run a read-only scan with the selected profile and options", self.action_run_scan)
        yield SystemCommand("Cancel scan", "Stop the running scan and keep partial results", self.action_cancel_scan)
        yield SystemCommand("Add AWS profile", "Sign in with IAM Identity Center, add access keys or an assume-role profile", self.action_add_profile)
        yield SystemCommand("Choose collectors", "Pick which of the collectors run", self.action_pick_services)
        yield SystemCommand("Scan options", "Regions, read-only role, organization, features, parallelism", self.action_scan_options)
        yield SystemCommand("Export report", "Write JSON, CSV and HTML to ./deadweight-reports", self.action_export)
        yield SystemCommand("Open saved report", "Browse a previous export offline", self.action_open_report)
        yield SystemCommand("Compare with saved report", "Show what changed since a previous export", self.action_compare)
        yield SystemCommand("Show IAM permissions", "Missing (denied) actions, or the full least-privilege policy", self.action_show_permissions)
        yield SystemCommand("Toggle inspector", "Show or hide the resource detail panel", self.action_toggle_inspector)
        yield SystemCommand("Cycle theme", "nebula → synthwave → daylight → …", self.action_cycle_theme)
        for n, (_, _, label) in enumerate(PAGES):
            yield SystemCommand(f"Go to {label}", f"Open the {label} view  ({PAGE_KEYS[n]})", partial(self.action_goto, n))


def run_tui(report: Path | None = None, theme: str = "aws-nebula", options: ScanOptions | None = None) -> None:
    AwsCostApp(report=report, theme_name=theme, options=options).run()
