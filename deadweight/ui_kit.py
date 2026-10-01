"""Look & feel shared by every screen: themes, palette, formatting helpers, painters and generic widgets."""
from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import date
from functools import lru_cache, partial
import re
from typing import Any, Callable

from rich.align import Align
from rich.console import Group
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.color import Color
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.message import Message
from textual.theme import Theme
from textual.widget import Widget
from textual.widgets import DataTable, Digits, Input, Label, ListItem, Static

from .collectors.base import REGISTRY
from .models import Resource, money

THEMES = [
    Theme(name="aws-nebula", dark=True,
          primary="#FF9F1C", secondary="#8B7CFF", accent="#2DE2C4",
          success="#3DDC97", warning="#FFC857", error="#FF5D73",
          foreground="#DCE3EE", background="#0A0E15", surface="#10161F", panel="#1A2230",
          variables={"footer-key-foreground": "#FF9F1C", "input-selection-background": "#FF9F1C 35%",
                     "block-cursor-text-style": "bold"}),
    Theme(name="aws-synthwave", dark=True,
          primary="#FF4FD8", secondary="#7B61FF", accent="#00E5FF",
          success="#00F5A0", warning="#FFD166", error="#FF3864",
          foreground="#F2E9FF", background="#0C0517", surface="#140A24", panel="#221238",
          variables={"footer-key-foreground": "#FF4FD8", "input-selection-background": "#FF4FD8 35%"}),
    Theme(name="aws-daylight", dark=False,
          primary="#D86F00", secondary="#5B4FE0", accent="#0E9384",
          success="#1E9E61", warning="#B7791F", error="#D3334C",
          foreground="#1B2333", background="#F8F6F1", surface="#EFECE4", panel="#E2DDD2",
          variables={"footer-key-foreground": "#D86F00", "input-selection-background": "#D86F00 30%"}),
]
THEME_CYCLE = ["aws-nebula", "aws-synthwave", "aws-daylight", "tokyo-night", "catppuccin-mocha", "nord", "gruvbox", "dracula"]

WORDMARK = ("█▀▄ █▀▀ ▄▀█ █▀▄ █ █ █ █▀▀ █ █▀▀ █ █ ▀█▀",
            "█▄▀ ██▄ █▀█ █▄▀ ▀▄▀▄▀ ██▄ █ █▄█ █▀█  █ ")
# The cloud the money falls out of: a filled silhouette, with a-w-s drawn on it in the theme's primary colour.
CLOUD = ("               ▄▄████▄▄         ",
         "       ▄▄███▄▄██████████▄       ",
         "     ▄████████████████████▄▄▄   ",
         "   ▄█████████████████████████▄  ",
         "   ███████████████████████████  ",
         "   ███████████████████████████  ",
         "    ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀   ")
CLOUD_AWS = ("▄▀█ █ █ █ █▀", "█▀█ ▀▄▀▄▀ ▄█")      # overlaid on the two full rows, centred
CLOUD_AWS_ROW = 4
RAIN_COLUMNS = range(5, 28, 2)
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class Pal:
    """Concrete colours of the active theme, for Rich renderables drawn in Python."""
    primary = secondary = accent = success = warning = error = "#888888"
    fg = muted = faint = bg = panel = ai = obs = "#888888"

    @classmethod
    def load(cls, app: App) -> None:
        v = app.get_css_variables()
        def c(key, default="#888888"):
            try: return Color.parse(v[key]).hex
            except Exception: return default
        cls.primary, cls.secondary, cls.accent = c("primary"), c("secondary"), c("accent")
        cls.success, cls.warning, cls.error = c("success"), c("warning"), c("error")
        cls.fg, cls.bg, cls.panel = c("foreground", "#DDDDDD"), c("background", "#000000"), c("panel")
        fg, bg = Color.parse(cls.fg), Color.parse(cls.bg)
        cls.muted, cls.faint = fg.blend(bg, 0.42).hex, fg.blend(bg, 0.72).hex
        cls.ai = Color.parse(cls.secondary).blend(Color.parse(cls.error), 0.45).hex
        cls.obs = Color.parse(cls.accent).blend(Color.parse(cls.secondary), 0.5).hex
        ramp.cache_clear()


# Service → family, used for the coloured tick that prefixes every service name.
# Short keywords match whole tokens; longer ones match substrings. First rule wins.
FAMILY_RULES = [
    ("ai", ("bedrock", "sagemaker", "comprehend", "rekognition", "textract", "polly", "transcribe", "kendra")),
    ("storage", ("s3", "ebs", "ecr", "efs", "fsx", "container registry", "storage", "file system", "backup", "glacier", "snapshot")),
    ("database", ("rds", "dynamodb", "elasticache", "opensearch", "memorydb", "redshift", "database", "aurora", "docdb", "athena", "glue", "neptune", "timestream")),
    ("security", ("kms", "iam", "acm", "waf", "key management", "secret", "certificate", "guardduty", "security", "shield", "cognito", "inspector", "macie", "wafv2")),
    ("integration", ("sqs", "sns", "ses", "ssm", "queue", "notification", "events", "eventbridge", "step functions", "states", "email", "systems manager", "appsync", "scheduler")),
    ("observability", ("cloudwatch", "logs", "xray", "x-ray", "cloudtrail", "config", "explorer", "cost explorer", "monitoring")),
    ("network", ("vpc", "nat", "elb", "elastic ip", "load balanc", "elasticloadbalancing", "api gateway", "apigateway", "cloudfront", "route53", "route 53", "cloud map", "servicediscovery", "virtual private cloud", "transit", "global accelerator", "direct connect")),
    ("compute", ("ec2", "ecs", "eks", "compute", "lambda", "container service", "kubernetes", "fargate", "apprunner", "batch", "autoscaling", "lightsail")),
]
FAMILY_LABEL = {"compute": "Compute", "storage": "Storage", "database": "Database", "network": "Networking",
                "security": "Security", "integration": "Integration", "ai": "AI / ML",
                "observability": "Observability", "other": "Other"}


@lru_cache(maxsize=2048)
def family_of(name: str) -> str:
    spec = REGISTRY.get(name)
    if spec is not None:      # collectors declare their family
        return spec.family if spec.family in FAMILY_LABEL else "other"
    s = name.lower()
    s = s[4:] if s.startswith("aws/") else s
    toks = set(re.split(r"[^a-z0-9]+", s))
    for fam, kws in FAMILY_RULES:
        for kw in kws:
            if (kw in toks) if len(kw) <= 4 else (kw in s):
                return fam
    return "other"


def fam_color(name_or_family: str) -> str:
    fam = name_or_family if name_or_family in FAMILY_LABEL else family_of(name_or_family)
    return {"compute": Pal.primary, "storage": Pal.success, "database": Pal.secondary, "network": Pal.accent,
            "security": Pal.error, "integration": Pal.warning, "ai": Pal.ai, "observability": Pal.obs,
            }.get(fam, Pal.muted)


# ── formatting helpers ─────────────────────────────────────────────────────────

EIGHTHS = " ▏▎▍▌▋▊▉"
SPARK = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], width: int, c1: str, c2: str) -> Text:
    """Column chart in one text row; values are resampled to `width` columns."""
    t = Text(no_wrap=True)
    if not values or width <= 0:
        return t
    if len(values) > width:
        step = len(values) / width
        values = [max(values[int(i * step):max(int(i * step) + 1, int((i + 1) * step))]) for i in range(width)]
    hi = max(values) or 1.0
    colors = ramp(c1, c2, 8)
    for v in values:
        level = 0 if v <= 0 else min(7, int(v / hi * 7.999))
        t.append(SPARK[level], style=colors[level])
    return t


@lru_cache(maxsize=512)
def ramp(c1: str, c2: str, n: int) -> tuple[str, ...]:
    a, b = Color.parse(c1), Color.parse(c2)
    return tuple(a.blend(b, i / max(1, n - 1)).hex for i in range(max(1, n)))


def hbar(frac: float | None, width: int, c1: str, c2: str, *, line=False) -> Text:
    """Gradient bar with 1/8-cell precision; the colour heats up along the track."""
    width = max(1, width)
    frac = 0.0 if not frac or frac != frac else max(0.0, min(1.0, frac))
    cells = frac * width
    full = int(cells)
    part = int(round((cells - full) * 8))
    if part == 8: full, part = full + 1, 0
    colors = ramp(c1, c2, width)
    t = Text(no_wrap=True)
    glyph = "━" if line else "█"
    for i in range(min(full, width)): t.append(glyph, style=colors[i])
    used = min(full, width)
    if used < width and part:
        t.append(("╸" if part >= 4 else "") if line else EIGHTHS[part], style=colors[used])
        used += 1 if (not line or part >= 4) else 0
    if used < width: t.append(("─" if line else "·") * (width - used), style=Pal.faint)
    return t


def stacked(parts: list[tuple[str, float, str]], width: int) -> Text:
    """One-line proportional bar; every non-zero part keeps at least one cell."""
    total = sum(n for _, n, _ in parts)
    t = Text(no_wrap=True)
    if total <= 0: return Text("·" * width, style=Pal.faint)
    raw = [n / total * width for _, n, _ in parts]
    cells = [max(1, int(r)) if n > 0 else 0 for r, (_, n, _) in zip(raw, parts)]
    live = [i for i, (_, n, _) in enumerate(parts) if n > 0]
    by_rem = sorted(live, key=lambda i: raw[i] - int(raw[i]), reverse=True)
    i = 0
    while sum(cells) < width and by_rem: cells[by_rem[i % len(by_rem)]] += 1; i += 1
    while sum(cells) > width:
        j = max(live, key=lambda k: cells[k])
        if cells[j] <= 1: break
        cells[j] -= 1
    for (_, _, col), c in zip(parts, cells): t.append("█" * c, style=col)
    return t


def trunc(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: max(0, n - 1)] + "…"


def fmt_money(v: float | None, currency="USD", *, bold=False, left=False) -> Text:
    j = "left" if left else "right"
    if v is None: return Text("n/a", style=f"italic {Pal.faint}", justify=j)
    if v == 0: return Text(money(0.0, currency), style=Pal.faint, justify=j)
    if 0 < v < 0.005: return Text("<" + money(0.01, currency), style=Pal.muted, justify=j)
    return Text(money(v, currency), style=f"bold {Pal.fg}" if bold else Pal.fg, justify=j)


def kpi_money(v: float) -> str:
    return f"${v:,.0f}" if abs(v) >= 10_000 else f"${v:,.2f}"


def fmt_service(name: str) -> Text:
    t = Text("▍", style=fam_color(name), no_wrap=True, overflow="ellipsis")
    if name.startswith("AWS/"):
        t.append("AWS/", style=Pal.faint); t.append(name[4:], style=Pal.fg)
    else:
        t.append(name, style=f"bold {Pal.fg}")
    return t


def fmt_type(r: Resource) -> str:
    t = r.resource_type
    if ":" in t and r.service.lower().endswith(t.split(":", 1)[0].lower()):
        t = t.split(":", 1)[1]
    return t


def short_id(r: Resource) -> str:
    if r.name: return r.name
    rid = str(r.resource_id)
    if rid.startswith("arn:"):
        parts = rid.split(":", 5)
        if len(parts) == 6: return parts[5]
    if rid.startswith("https://"): return rid.rsplit("/", 1)[-1]
    return rid


OK_STATES = {"running", "active", "available", "in-use", "deployed", "ready", "enabled", "associated", "issued",
             "inservice", "attached", "succeeded", "complete", "completed", "healthy", "provisioned"}
WARN_STATES = {"stopped", "stopping", "idle", "pending", "creating", "updating", "modifying", "provisioning",
               "inactive", "disabled", "shutting-down", "rebooting", "backing-up", "maintenance"}
BAD_STATES = {"failed", "error", "deleting", "deleted", "terminated", "impaired", "unhealthy", "incompatible-parameters",
              "inaccessible-encryption-credentials", "storage-full", "pending_deletion", "pendingdeletion"}


def fmt_state(s: str) -> Text:
    k = (s or "").lower()
    if not k: return Text("—", style=Pal.faint)
    if k == "discovered": g, c, tc = "◌", Pal.secondary, Pal.muted
    elif k in OK_STATES: g, c, tc = "●", Pal.success, Pal.fg
    elif k in BAD_STATES: g, c, tc = "✕", Pal.error, Pal.error
    elif k in WARN_STATES: g, c, tc = "◐", Pal.warning, Pal.warning
    else: g, c, tc = "○", Pal.muted, Pal.fg
    return Text.assemble((g + " ", c), (k, tc), no_wrap=True)


def source_color(src: str) -> str:
    return Pal.secondary if src == "Resource Explorer" else Pal.accent if src == "Tagging API" else Pal.primary


def fmt_sources(r: Resource) -> Text:
    s = set(r.discovery_sources)
    direct = any(x not in ("Resource Explorer", "Tagging API") for x in s)
    t = Text(no_wrap=True)
    for on, col in ((direct, Pal.primary), ("Resource Explorer" in s, Pal.secondary), ("Tagging API" in s, Pal.accent)):
        t.append("●" if on else "·", style=col if on else Pal.faint)
    return t


COVERAGE_STYLE = {"ok": ("✓", "success"), "denied": ("⊘", "error"), "error": ("✕", "error"), "timeout": ("◷", "error"),
                  "throttled": ("≈", "warning"), "not-enabled": ("○", "warning"), "not-available": ("◌", "muted"),
                  "skipped": ("–", "muted"), "sdk-unsupported": ("◌", "muted"),
                  # statuses used by older reports
                  "unavailable": ("✕", "error"), "not-configured": ("○", "warning")}
COVERAGE_ORDER = {"denied": 0, "error": 1, "timeout": 2, "throttled": 3, "unavailable": 4, "not-enabled": 5,
                  "not-configured": 6, "not-available": 7, "sdk-unsupported": 8, "skipped": 9, "ok": 10}
SEVERITY_STYLE = {"high": ("▲", "error"), "medium": ("◆", "warning"), "low": ("●", "secondary"), "info": ("○", "muted")}


USAGE_STYLE = {"active": ("●", "working", "success"), "low-use": ("◐", "low use", "warning"), "idle": ("○", "idle", "warning"),
               "stopped-billed": ("■", "stopped, billed", "error"), "orphaned": ("✕", "orphaned", "error"),
               "stale": ("◌", "stale", "muted"), "clutter": ("·", "unused, free", "muted"), "unknown": ("?", "not evaluated", "faint"),
               "unattributed": ("?", "unattributed", "faint")}
USAGE_ORDER = {k: i for i, k in enumerate(["orphaned", "stopped-billed", "idle", "low-use", "stale", "clutter", "active", "unknown",
                                           "unattributed", ""])}


def fmt_usage(state: str) -> Text:
    if not state:
        return Text("")
    g, label, key = USAGE_STYLE.get(state, ("·", state, "muted"))
    col = getattr(Pal, key)
    return Text.assemble((g + " ", f"bold {col}"), (label, col if key != "faint" else Pal.faint), no_wrap=True)


def fmt_severity(sev: str) -> Text:
    g, key = SEVERITY_STYLE.get(sev, ("·", "muted"))
    col = getattr(Pal, key)
    return Text.assemble((g + " ", f"bold {col}"), (sev, col), no_wrap=True)


def fmt_cov_status(status: str) -> Text:
    g, key = COVERAGE_STYLE.get(status, ("·", "muted"))
    col = getattr(Pal, key)
    return Text.assemble((g + " ", f"bold {col}"), (status, col))


def fmt_account(acct: str) -> str:
    a = str(acct or "")
    return f"{a[:4]}-{a[4:8]}-{a[8:]}" if len(a) == 12 and a.isdigit() else a


def fmt_dur(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 60}m {sec % 60:02d}s" if sec >= 60 else f"{sec}s"


def _plain(x) -> str:
    return x.plain if isinstance(x, Text) else str(x)


def _num(v):
    return float("-inf") if v is None else v


def _kv(rows, key_style=None) -> Table:
    g = Table.grid(padding=(0, 2))
    g.add_column(style=key_style or Pal.muted, no_wrap=True)
    g.add_column(overflow="fold")
    for k, v in rows: g.add_row(k, v if isinstance(v, Text) else Text(str(v), style=Pal.fg))
    return g


def _section(title: str) -> Rule:
    return Rule(Text(f" {title} ", style=f"bold {Pal.muted}"), align="left", style=Pal.faint, characters="─")


# ── painters (width-aware Rich renderables) ────────────────────────────────────

def paint_cloud(frame: int, rain_rows: int) -> Text:
    """A cloud with `aws` on it, raining: mostly water, now and then a dollar.
    One multi-line Text, so the rows keep their columns when the block is centred."""
    t = Text(no_wrap=True)
    left = (len(CLOUD[0]) - len(CLOUD_AWS[0])) // 2
    for y, row in enumerate(CLOUD):
        if y in (CLOUD_AWS_ROW, CLOUD_AWS_ROW + 1):          # half-block letters: primary on the cloud colour
            t.append(row[:left], style=Pal.faint)
            t.append(CLOUD_AWS[y - CLOUD_AWS_ROW], style=f"bold {Pal.primary} on {Pal.faint}")
            t.append(row[left + len(CLOUD_AWS[0]):], style=Pal.faint)
        else:
            t.append(row, style=Pal.faint)
        t.append("\n")
    grid = [[(" ", "")] * len(CLOUD[0]) for _ in range(rain_rows)]
    for i, x in enumerate(RAIN_COLUMNS):
        cycle = rain_rows + 1 + (i * 5) % 3                 # rows on screen plus a short pause before the next drop
        y = (frame // (1 + i % 2) + i * 7) % cycle          # every other column falls at half speed
        if y >= rain_rows:
            continue
        if i % 4 == 2:
            grid[y][x] = ("$", f"bold {Pal.success}")
        else:
            grid[y][x] = ("│", Pal.secondary)
            if y:
                grid[y - 1][x] = ("╵", Pal.muted)
    for n, cells in enumerate(grid):
        for ch, style in cells:
            t.append(ch, style=style)
        if n < len(grid) - 1:
            t.append("\n")
    return t


def paint_hero(width: int, *, reports: int, scanning: tuple | None, frame: int = 0, height: int = 99, compact: bool = False) -> Group:
    stops = (Pal.primary, Pal.error, Pal.secondary)
    out = [Text("")]
    # Height budget, in order of importance: wordmark and steps, the cloud with two rows of rain, the key hints,
    # the feature line, then more rain. The hints repeat what the footer already shows.
    wide = width >= 96
    steps_rows = 1 if width >= 50 else 2
    hint_rows = 1 if wide else 2 if width >= 50 else 3
    spare = height - (9 if scanning else 6 + steps_rows)
    rain = 0
    if not compact and width >= len(CLOUD[0]) + 4 and spare >= len(CLOUD) + 3:
        rain, spare = 2, spare - len(CLOUD) - 3
    show_hint = spare >= 1 + hint_rows
    spare -= (1 + hint_rows) if show_hint else 0
    show_feats = spare >= 2
    spare -= 2 if show_feats else 0
    if rain:
        out += [Align.center(paint_cloud(frame, rain + max(0, min(2, spare)))), Text("")]
    mark = Text(no_wrap=True)
    for y, row in enumerate(WORDMARK):
        n = len(row)
        for i, ch in enumerate(row):
            f = i / max(1, n - 1)
            col = ramp(stops[0], stops[1], 16)[int(f * 2 * 15)] if f < 0.5 else ramp(stops[1], stops[2], 16)[int((f - 0.5) * 2 * 15)]
            mark.append(ch, style=f"bold {col}")
        if y < len(WORDMARK) - 1:
            mark.append("\n")
    out.append(Align.center(mark))
    tagline = "what you pay for  ·  what you use  ·  what just sits there" if width >= 60 else "find what you pay for and don't use"
    out += [Text(""), Text(tagline, style=Pal.muted, justify="center"), Text("")]
    if scanning:
        label, done, total, found = scanning
        pct = done / max(1, total)
        bw = min(48, max(10, width - 20))
        bar = Text(justify="center", no_wrap=True); bar.append_text(hbar(pct, bw, Pal.secondary, Pal.primary))
        bar.append(f"  {pct * 100:3.0f}%", style=f"bold {Pal.primary}")
        out += [bar, Text(""), Text.assemble((trunc(label, 60), Pal.fg), ("   ·   ", Pal.faint), (f"{found:,} resources found", f"bold {Pal.fg}"), justify="center")]
        return Group(*out)
    def step(n, *parts):
        return Text.assemble((f" {n} ", f"bold {Pal.bg} on {Pal.primary}"), " ", *parts)
    k = lambda s: (s, f"bold {Pal.primary}")
    steps = Table.grid(padding=(0, 4 if wide else 2))
    if wide:
        steps.add_row(step(1, ("choose a profile, or ", Pal.muted), k("+"), (" to add one", Pal.muted)),
                      step(2, ("press ", Pal.muted), k("r"), (" to scan", Pal.muted)),
                      step(3, ("press ", Pal.muted), k("e"), (" to export", Pal.muted)))
    else:           # narrow terminals: one line, keys only
        steps.add_row(step(1, ("profile, ", Pal.muted), k("+"), (" adds one", Pal.muted)), step(2, k("r"), (" scan", Pal.muted)),
                      step(3, k("e"), (" export", Pal.muted)))
    out.append(Align.center(steps))
    if not show_hint:
        return Group(*out)
    out.append(Text(""))
    hint = Text.assemble(("or press ", Pal.muted), k("o"), (f" to browse {reports} saved report{'s' if reports != 1 else ''} offline" if reports else " to browse saved reports offline", Pal.muted),
                         ("   ·   ", Pal.faint), k("ctrl+p"), (" command palette", Pal.muted), ("   ·   ", Pal.faint), k("t"), (" theme", Pal.muted), justify="center")
    out.append(hint)
    if not show_feats:
        return Group(*out)
    out.append(Text(""))
    names = [f"{len(REGISTRY)} collectors", "bill reconciliation", "idle detection", "read-only"]
    while names and sum(len(n) + 5 for n in names) > width: names.pop()   # drop features rather than crop them
    feats = Text(justify="center", no_wrap=True)
    for i, f in enumerate(names):
        if i: feats.append("   ")
        feats.append("◆ ", style=(Pal.primary, Pal.secondary, Pal.accent, Pal.success)[i]); feats.append(f, style=Pal.faint)
    out.append(feats)
    return Group(*out)


def paint_bars(items: list[tuple[str, float]], width: int, *, rows: int, total: float | None = None,
               ticks=True, empty="No billed spend this month") -> Text:
    items = [(l, v) for l, v in items if v and v > 0][:rows]
    if not items: return Text(empty, style=Pal.faint)
    total = total or sum(v for _, v in items) or 1.0
    vmax = max(v for _, v in items) or 1.0
    vals = [money(v) for _, v in items]
    vw = max(len(s) for s in vals)
    lw = min(max(len(l) for l, _ in items) + (1 if ticks else 0), max(10, width // 3))
    bw = max(4, width - lw - vw - 9)
    lines = []
    for (label, v), vs in zip(items, vals):
        t = Text(no_wrap=True, overflow="crop")
        if ticks:
            t.append("▍", style=fam_color(label)); t.append(trunc(label, lw - 1).ljust(lw - 1), style=Pal.fg)
        else:
            t.append(trunc(label, lw).ljust(lw), style=Pal.fg)
        t.append(" "); t.append_text(hbar(v / vmax, bw, Pal.secondary, Pal.primary))
        t.append(" " + vs.rjust(vw), style=f"bold {Pal.fg}")
        t.append(f"{v / total * 100:6.1f}%", style=Pal.muted)
        lines.append(t)
    return Text("\n", no_wrap=True, overflow="crop").join(lines)


def paint_pacing(width: int, period, mtd: float, proj: float, forecast: float | None = None,
                 daily: list | None = None) -> Text:
    days, elapsed = period.days_in_month, period.elapsed_days
    frac = 1.0 if period.complete else elapsed / days
    def row(label, val, style):
        return Text.assemble((label, Pal.muted), (val.rjust(max(1, width - len(label))), style), no_wrap=True)
    head = f"{period.start:%b %Y} complete" if period.complete else f"Day {elapsed} of {days} · {period.start:%b %Y}"
    lines = [Text.assemble((head, f"bold {Pal.fg}"), (f"{frac * 100:.0f}%".rjust(max(1, width - len(head))), Pal.muted), no_wrap=True),
             hbar(frac, width, Pal.accent, Pal.primary),
             row("Actual" if period.complete else "MTD actual", money(mtd), f"bold {Pal.primary}")]
    if not period.complete:
        lines.append(row("Run-rate (month)", money(proj), f"bold {Pal.fg}"))
        if forecast is not None:
            lines.append(row("AWS forecast (month)", money(mtd + forecast), f"bold {Pal.secondary}"))
        else:
            lines.append(row("Still to land", "+" + money(max(0.0, proj - mtd)), Pal.fg))
    lines.append(row("Daily average", money(mtd / max(1, elapsed)), Pal.fg))
    if daily and len(daily) > 1:
        vals = [v for _, v in daily]
        label = f"{len(vals)}d "
        lines.append(Text.assemble((label, Pal.muted), sparkline(vals, max(4, width - len(label)), Pal.secondary, Pal.primary),
                                   no_wrap=True))
    return Text("\n", no_wrap=True).join(lines)


def paint_findings(width: int, findings: list, n: int = 7) -> Text:
    top = sorted((f for f in findings if f.monthly_savings), key=lambda f: f.monthly_savings or 0, reverse=True)[:n]
    if not top:
        return Text("No savings findings — nice." if findings is not None else "", style=Pal.faint)
    vals = [money(f.monthly_savings) for f in top]
    vw = max(len(v) for v in vals)
    lines = []
    for f, v in zip(top, vals):
        g, key = SEVERITY_STYLE.get(f.severity, ("·", "muted"))
        t = Text(no_wrap=True, overflow="crop")
        t.append(g + " ", style=getattr(Pal, key))
        label = f"{f.title} · {f.resource_name or f.service}"
        t.append(trunc(label, max(4, width - vw - 3)).ljust(max(4, width - vw - 3)), style=Pal.fg)
        t.append(" " + v.rjust(vw), style=f"bold {Pal.success}")
        lines.append(t)
    return Text("\n", no_wrap=True).join(lines)


def paint_legend(parts: list[tuple[str, float, str]], width: int, *, bar=True, cols=None, pct=True,
                 footer: Text | None = None) -> Text:
    total = sum(n for _, n, _ in parts) or 1
    cols = cols or (2 if width >= 60 else 1)
    cw = (width - (cols - 1) * 3) // cols
    cells = []
    for label, n, col in parts:
        num = f"{n:,.0f}" if float(n).is_integer() else f"{n:,.2f}"
        right = f"{num}  {n / total * 100:4.0f}%" if pct else num
        t = Text(no_wrap=True, overflow="crop")
        t.append("■ ", style=col)
        t.append(trunc(label, max(1, cw - len(right) - 3)).ljust(max(1, cw - len(right) - 2)), style=Pal.fg)
        t.append(right, style=Pal.muted)
        cells.append(t)
    lines = [stacked(parts, width), Text("")] if bar else []
    for i in range(0, len(cells), cols):
        row = Text(no_wrap=True)
        for j, c in enumerate(cells[i:i + cols]):
            if j: row.append("   ")
            row.append_text(c)
        lines.append(row)
    if footer is not None: lines += [Text(""), footer]
    return Text("\n", no_wrap=True).join(lines)


def paint_top(width: int, resources: list[Resource], n=6) -> Text:
    top = sorted((r for r in resources if r.monthly_estimate), key=lambda r: r.monthly_estimate or 0, reverse=True)[:n]
    if not top: return Text("No priced resources", style=Pal.faint)
    vals = [money(r.monthly_estimate) for r in top]
    vw = max(len(v) for v in vals)
    lines = []
    for r, v in zip(top, vals):
        t = Text(no_wrap=True, overflow="crop")
        t.append("▍", style=fam_color(r.service))
        name = f"{r.service} · {short_id(r)}"
        t.append(trunc(name, max(4, width - vw - 3)).ljust(max(4, width - vw - 3)), style=Pal.fg)
        t.append(" " + v.rjust(vw), style=f"bold {Pal.fg}")
        lines.append(t)
    return Text("\n", no_wrap=True).join(lines)


def render_resource(r: Resource, width: int):
    fam = fam_color(r.service)
    head = Text.assemble(("▍", fam), (r.service, f"bold {fam}"), ("  " + r.resource_type, Pal.muted))
    title = Text(r.name or short_id(r), style=f"bold {Pal.fg}", overflow="fold")
    rows = [("Region", r.region)]
    if str(r.resource_id) != r.arn: rows.append(("ID", str(r.resource_id)))
    if r.account_id:
        rows.append(("Account", fmt_account(r.account_id)))
    if r.created:
        rows.append(("Created", str(r.created)[:19]))
    ident = _kv(rows + [("ARN", r.arn or "—"), ("Config", r.config or "—")])
    cost_rows = []
    if r.actual_mtd is not None:
        cost_rows.append(("Actual MTD", Text.assemble(fmt_money(r.actual_mtd, bold=True, left=True), ("  (CUR)", Pal.muted))))
    if r.actual_recent is not None:
        actual = fmt_money(r.actual_recent, left=True)
        actual.append(" " + r.actual_recent_period, style=Pal.muted)
        cost_rows.append(("Actual*", actual))
    cost_rows += [("Est / mo", fmt_money(r.monthly_estimate, bold=True, left=True)), ("Basis", Text(r.estimate_note, style=Pal.muted))]
    if r.bill_service:
        cost_rows.append(("Bill line", Text(r.bill_service + (f" › {r.usage_family}" if r.usage_family else ""), style=Pal.fg)))
    cost = _kv(cost_rows)
    metrics = (r.details or {}).get("metrics") or {}
    metric_rows = [(k.replace("_", " "), Text("no data" if v is None else f"{v:,.2f}", style=Pal.fg)) for k, v in metrics.items()
                   if not k.startswith("bytes:") or v]
    chips = Text()
    for s in (r.discovery_sources or ["unknown"]):
        chips.append(f" {s} ", style=f"bold {Pal.bg} on {source_color(s)}"); chips.append(" ")
    rel = _kv([(k, Text(", ".join(v[:4]) + (f" +{len(v) - 4}" if len(v) > 4 else ""), style=Pal.fg)) for k, v in r.relations.items() if v]) \
        if any(r.relations.values()) else None
    finds = (r.details or {}).get("findings") or []
    tags = _kv(sorted(r.tags.items()), key_style=Pal.secondary) if r.tags else Text("no tags", style=Pal.faint)
    col1 = [head, title, fmt_state(r.state), _section("IDENTITY"), ident]
    col2 = []
    usage = getattr(r, "usage_state", "") or ""
    if usage:
        line = fmt_usage(usage)
        conf = getattr(r, "usage_confidence", "") or ""
        if conf:
            line.append(f"  · {conf} confidence", style=Pal.muted)
        for o in getattr(r, "usage_overlays", None) or []:
            line.append(f"  [{o}]", style=Pal.secondary)
        col2 += [_section("USAGE"), line]
        for ev in (getattr(r, "usage_evidence", None) or [])[:6]:
            col2.append(Text("  " + str(ev), style=Pal.muted, overflow="fold"))
        col2.append(Text(""))
    col2 += [_section("COST"), cost]
    if finds:
        col2 += [Text(""), _section("FINDINGS"), Text("  ".join(f"▲ {f}" for f in finds), style=Pal.warning)]
    if metric_rows:
        col2 += [Text(""), _section("METRICS · 14 d"), _kv(metric_rows)]
    col3 = [_section("DISCOVERY"), chips]
    if rel is not None:
        col3 += [Text(""), _section("RELATED"), rel]
    col3 += [Text(""), _section("TAGS"), tags]
    if width >= 110:
        g = Table.grid(expand=True, padding=(0, 3))
        g.add_column(ratio=5); g.add_column(ratio=4); g.add_column(ratio=4)
        g.add_row(Group(*col1), Group(*col2), Group(*col3))
        return g
    return Group(*col1, Text(""), *col2, Text(""), *col3)


# ── widgets ────────────────────────────────────────────────────────────────────

class Canvas(Widget):
    """Re-renders through `painter(width)` on every resize or theme change."""
    DEFAULT_CSS = "Canvas { height: auto; }"

    def __init__(self, painter: Callable[[int], Any] | None = None, **kw):
        super().__init__(**kw)
        self.painter = painter

    def paint(self, painter: Callable[[int], Any]) -> None:
        self.painter = painter
        self.refresh(layout=True)

    def _make(self, width: int):
        if self.painter is None: return Text("")
        try: return self.painter(max(8, width))
        except Exception as e: return Text(f"⚠ {e}", style=Pal.error)

    def get_content_height(self, container, viewport, width: int) -> int:
        r = self._make(width)
        if isinstance(r, Text): return r.plain.count("\n") + 1
        opts = self.app.console.options.update_width(max(1, width))
        return len(self.app.console.render_lines(r, opts, pad=False))

    def render(self):
        return self._make(self.content_size.width)


class NavItem(ListItem):
    def __init__(self, page: str, icon: str, label: str):
        super().__init__(id=f"nav-{page}")
        self.page, self._text = page, f"{icon}  {label}"

    def compose(self) -> ComposeResult:
        yield Label(self._text, classes="nav-label")
        yield Label("", classes="nav-count")

    def set_count(self, text: str | Text, alert=False) -> None:
        c = self.query_one(".nav-count", Label)
        c.update(text); c.set_class(alert, "-alert")


class KpiCard(Vertical):
    def __init__(self, title: str, caption: str, *, id: str, tone: str):
        super().__init__(id=id, classes=f"kpi tone-{tone}")
        self._title, self._caption = title, caption

    def compose(self) -> ComposeResult:
        yield Label(self._title, classes="kpi-title")
        yield Digits("-", classes="kpi-digits")
        yield Label("-", classes="kpi-compact")
        yield Label(self._caption, classes="kpi-caption")

    def set(self, value: str, caption: str | Text | None = None) -> None:
        self.query_one(Digits).update(value)
        self.query_one(".kpi-compact", Label).update(value)
        if caption is not None: self.query_one(".kpi-caption", Label).update(caption)


@dataclass
class Col:
    label: str
    cell: Callable[[Any], Any]
    sort: Callable[[Any], Any] | None = None
    width: int = 10           # fixed width, or minimum width when flex
    right: bool = False
    flex: bool = False        # takes the remaining horizontal space
    hide_below: int = 0       # dropped when the view is narrower than this
    show: Callable[[], bool] | None = None   # dynamic visibility (e.g. Account only in multi-account scans)


class DataView(Vertical):
    """Filterable, sortable, responsive table: filter box + DataTable."""
    BINDINGS = [Binding("escape", "focus_table", "Table", show=False)]

    class Highlighted(Message):
        def __init__(self, view: "DataView", item: Any) -> None:
            self.view, self.item = view, item
            super().__init__()

        @property
        def control(self) -> "DataView":
            return self.view

    class Selected(Message):
        """Enter (or a click on the cursor row) on an item."""
        def __init__(self, view: "DataView", item: Any) -> None:
            self.view, self.item = view, item
            super().__init__()

        @property
        def control(self) -> "DataView":
            return self.view

    def __init__(self, cols: list[Col], *, haystack: Callable[[Any], str], placeholder: str, **kw):
        super().__init__(**kw)
        self.cols, self.haystack, self.placeholder = cols, haystack, placeholder
        self.items: list[Any] = []
        self.view: list[Any] = []
        self.query_text = ""
        self.predicate: Callable[[Any], bool] | None = None
        self.sort_col: int | None = None
        self.sort_rev = False
        self._hay: dict[int, str] = {}
        self._layout: tuple | None = None
        self._pending: tuple | None = None
        self._filter_timer = self._resize_timer = None
        self._loaded = 0      # rows of self.view currently in the DataTable
        self._gen = 0         # bumps on every refresh so stale batch loaders stop

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Label("⌕", classes="filter-icon")
            yield Input(placeholder=self.placeholder, classes="filter", compact=True)
            yield Static("", classes="count")
        yield DataTable(cursor_type="row", zebra_stripes=True, cursor_foreground_priority="renderable")

    @property
    def table(self) -> DataTable:
        return self.query_one(DataTable)

    # layout ------------------------------------------------------------------
    def _compute_layout(self, width: int) -> tuple:
        vis = [i for i, c in enumerate(self.cols) if width >= c.hide_below and (c.show is None or c.show())]
        fixed = sum(self.cols[i].width for i in vis if not self.cols[i].flex)
        nflex = sum(1 for i in vis if self.cols[i].flex) or 1
        free = width - 3 - fixed - 2 * len(vis)
        return tuple((i, max(self.cols[i].width, free // nflex) if self.cols[i].flex else self.cols[i].width) for i in vis)

    def on_resize(self, event) -> None:
        if self.size.width < 20: return
        layout = self._compute_layout(self.size.width)
        if layout != (self._pending or self._layout):
            # _layout always describes the columns actually in the table; the new one is
            # applied by _rebuild, so rows streamed in meanwhile still match the columns.
            self._pending = layout
            if self._resize_timer: self._resize_timer.stop()
            self._resize_timer = self.set_timer(0.04, self._rebuild)

    def relayout(self) -> None:
        """Recompute visible columns (after a `show` condition changed)."""
        if self.size.width >= 20:
            self._pending = self._compute_layout(self.size.width)
            self._rebuild()

    def _rebuild(self) -> None:
        if self._pending is not None: self._layout, self._pending = self._pending, None
        if self._layout is None: return
        t = self.table
        t.clear(columns=True)
        for i, w in self._layout:
            c = self.cols[i]
            label = c.label.upper()
            if i == self.sort_col: label = f"{label} {'▼' if self.sort_rev else '▲'}"
            t.add_column(Text(label, justify="right" if c.right else "left"), width=w, key=str(i))
        self.refresh_view(keep_cursor=True)

    # data --------------------------------------------------------------------
    def _match(self, item, terms) -> bool:
        if self.predicate and not self.predicate(item): return False
        if not terms: return True
        h = self._hay.get(id(item))
        if h is None: h = self._hay[id(item)] = self.haystack(item).lower()
        return all((t[1:] not in h) if t.startswith("-") and len(t) > 1 else (t in h) for t in terms)

    def _cells(self, item) -> list:
        out = []
        for i, w in self._layout:
            v = self.cols[i].cell(item)
            if isinstance(v, Text) and v.cell_len > w: v.truncate(w, overflow="ellipsis")
            out.append(v)
        return out

    def set_items(self, items) -> None:
        self.items = list(items)
        self._hay.clear()
        self.refresh_view()

    def append(self, item) -> None:
        self.items.append(item)
        if self._match(item, self.query_text.lower().split()):
            self.view.append(item)
            # While a batch load is running the loader picks new rows up; otherwise add directly.
            if self._layout is not None and self._loaded == len(self.view) - 1:
                self.table.add_row(*self._cells(item))
                self._loaded += 1
        self._update_count()

    def refresh_view(self, keep_cursor=False) -> None:
        terms = self.query_text.lower().split()
        view = [x for x in self.items if self._match(x, terms)]
        if self.sort_col is not None:
            c = self.cols[self.sort_col]
            key = c.sort or (lambda x, c=c: _plain(c.cell(x)).lower())
            view.sort(key=key, reverse=self.sort_rev)
        self.view = view
        self._update_count()
        if self._layout is None: return
        t = self.table
        row = t.cursor_row if keep_cursor else 0
        t.clear()
        self._gen += 1
        self._loaded = 0
        if view:
            # Large tables load progressively so the UI never freezes: the first batch (enough to keep
            # the cursor in view) now, the rest in the background.
            self._load_rows(min(len(view), max(150, row + 50)))
            t.move_cursor(row=min(max(row, 0), self._loaded - 1), animate=False)
            if self._loaded < len(view):
                self.set_timer(0.02, partial(self._load_more, self._gen))
        self._emit(t.cursor_row if view else -1)

    BATCH = 400

    def _load_rows(self, upto: int) -> None:
        if upto > self._loaded:
            self.table.add_rows(self._cells(x) for x in self.view[self._loaded:upto])
            self._loaded = upto

    def _load_more(self, gen: int) -> None:
        if gen != self._gen or self._layout is None:
            return
        self._load_rows(min(len(self.view), self._loaded + self.BATCH))
        if self._loaded < len(self.view):
            self.set_timer(0.02, partial(self._load_more, gen))

    def _update_count(self) -> None:
        n, m = len(self.view), len(self.items)
        self.query_one(".count", Static).update(
            Text.assemble((f"{n:,}", f"bold {Pal.fg}"), (f" of {m:,}" if n != m else " rows", Pal.muted)))

    def _emit(self, row: int) -> None:
        self.post_message(self.Highlighted(self, self.view[row] if 0 <= row < len(self.view) else None))

    # events ------------------------------------------------------------------
    @on(DataTable.RowHighlighted)
    def _row(self, e: DataTable.RowHighlighted) -> None:
        e.stop(); self._emit(e.cursor_row)

    @on(DataTable.RowSelected)
    def _selected(self, e: DataTable.RowSelected) -> None:
        e.stop()
        if 0 <= e.cursor_row < len(self.view):
            self.post_message(self.Selected(self, self.view[e.cursor_row]))

    @on(DataTable.HeaderSelected)
    def _header(self, e: DataTable.HeaderSelected) -> None:
        e.stop()
        i = int(str(e.column_key.value))
        if self.sort_col == i: self.sort_rev = not self.sort_rev
        else: self.sort_col, self.sort_rev = i, self.cols[i].right
        self._rebuild()

    @on(Input.Changed)
    def _filter(self, e: Input.Changed) -> None:
        e.stop()
        self.query_text = e.value
        if self._filter_timer: self._filter_timer.stop()
        self._filter_timer = self.set_timer(0.12, self.refresh_view)

    @on(Input.Submitted)
    def _submit(self, e: Input.Submitted) -> None:
        e.stop(); self.table.focus()

    def action_focus_table(self) -> None:
        self.table.focus()

    def focus_filter(self) -> None:
        self.query_one(Input).focus()

    def set_filter(self, text: str) -> None:
        self.query_one(Input).value = text      # Input.Changed refreshes the view


class Inspector(VerticalScroll):
    """Details for the highlighted row; docks right on very wide terminals, below otherwise."""
    def __init__(self, **kw):
        super().__init__(**kw)
        self.item: Resource | None = None

    def compose(self) -> ComposeResult:
        yield Canvas(self._paint)

    def _paint(self, width: int):
        if self.item is None:
            return Text("Highlight a row to inspect it  ·  i toggles this panel", style=Pal.faint)
        return render_resource(self.item, width)

    def show(self, item: Resource | None) -> None:
        if item is self.item: return
        self.item = item
        self.repaint()
        self.scroll_home(animate=False)

    def repaint(self) -> None:
        self.query_one(Canvas).refresh(layout=True)


# ── modal screens ──────────────────────────────────────────────────────────────

