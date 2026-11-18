"""Template helpers: {% badge %}, {% sev %}, {% help 'topic#anchor' %}, {% asset %}, |ago, |bps, |get_item."""
import os

from django import template
from django.utils import timezone
from django.utils.html import format_html

register = template.Library()


@register.filter
def ago(dt):
    if not dt:
        return "never"
    secs = max(0, int((timezone.now() - dt).total_seconds()))
    if secs < 60:
        return f"{secs}s ago"
    if secs < 3600:
        return f"{secs // 60}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


@register.filter
def bps(v):
    """Bits per second for people: 12.4 Mb/s."""
    try:
        v = float(v or 0)
    except (TypeError, ValueError):
        return "–"
    for unit in ("b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s"):
        if v < 1000:
            return f"{v:.0f} {unit}" if unit == "b/s" else f"{v:.1f} {unit}"
        v /= 1000
    return f"{v:.1f} Pb/s"


@register.filter
def uptime(secs):
    if not secs:
        return "–"
    d, r = divmod(int(secs), 86400)
    h, r = divmod(r, 3600)
    return f"{d}d {h}h" if d else f"{h}h {r // 60}m"


@register.filter
def get_item(d, k):
    try:
        return d.get(k)
    except AttributeError:
        return None


_BADGE = {
    "added": "info", "removed": "bad", "gone": "warn", "moved": "warn", "fixed": "ok", "disabled": "muted",
    "up": "ok", "ok": "ok", "done": "ok", "pass": "ok", "passed": "ok", "resolved": "ok", "online": "ok", "connected": "ok",
    "closed": "muted", "full": "ok", "yes": "ok", "compliant": "ok",
    "partial": "warn", "warn": "warn", "warning": "warn", "acknowledged": "warn", "waiting": "warn", "medium": "warn",
    "in_progress": "info", "running": "info", "queued": "muted", "pending": "muted", "new": "info", "planned": "muted",
    "beta": "info", "manual": "warn", "snmp": "info", "scheduled": "info", "draft": "muted", "approved": "info",
    "bad": "bad", "down": "bad", "failed": "bad", "fail": "bad", "error": "bad", "auth_failed": "bad", "unreachable": "bad", "open": "bad",
    "offline": "bad", "critical": "bad", "high": "bad", "err-disabled": "bad", "none": "muted", "unknown": "muted",
    "accepted": "muted", "cancelled": "muted", "skipped": "muted", "low": "muted", "info": "muted", "notconnect": "muted",
}
_LABEL = {"auth_failed": "Login failed", "in_progress": "In progress", "err-disabled": "Err-disabled", "notconnect": "Not connected"}


@register.simple_tag
def badge(kind, text=None):
    key = str(kind).lower()
    css = _BADGE.get(key, "muted")
    label = text or _LABEL.get(key) or str(kind).replace("_", " ").capitalize()
    return format_html('<span class="badge badge-{}"><i class="dotmark"></i>{}</span>', css, label)


@register.simple_tag
def sev(level):
    level = (level or "info").lower()
    return format_html('<span class="sev sev-{}">{}</span>', level, level)


@register.simple_tag
def help(ref, label="?"):
    return format_html('<button type="button" class="help-q" data-help="{}" title="What is this?">{}</button>', ref, label)


@register.simple_tag
def asset(path):
    from django.contrib.staticfiles import finders
    from django.templatetags.static import static
    found = finders.find(path)
    try:
        return f"{static(path)}?v={int(os.path.getmtime(found))}" if found else static(path)
    except OSError:
        return static(path)


@register.filter
def score_tone(v):
    if v is None:
        return "muted"
    return "ok" if v >= 85 else "warn" if v >= 60 else "bad"


@register.filter
def split_pairs(value):
    """"a:Alpha,b:Beta" -> [("a", "Alpha"), ("b", "Beta")]"""
    return [tuple(p.split(":", 1)) for p in str(value).split(",") if ":" in p]


@register.filter
def diffclass(line):
    if line.startswith(("+++", "---")):
        return "hdr"
    if line.startswith("@@"):
        return "hdr"
    if line.startswith("+"):
        return "add"
    if line.startswith("-"):
        return "del"
    return ""


@register.simple_tag
def sparkline(values, width=160, height=34, maxv=100):
    """Tiny inline SVG line for a list of numbers (None skipped)."""
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return ""
    step = width / (len(vals) - 1)
    pts = " ".join(f"{i * step:.1f},{height - 2 - (v / maxv) * (height - 4):.1f}" for i, v in enumerate(vals))
    return format_html('<svg class="spark" width="{}" height="{}" viewBox="0 0 {} {}"><polyline points="{}"/></svg>', width, height, width, height, pts)


@register.filter
def split(value, sep=","):
    return str(value).split(sep)


@register.simple_tag(takes_context=True)
def export_link(context, label="Export CSV"):
    """A button that downloads the current list (same filters) as CSV."""
    from django.utils.html import format_html
    request = context.get("request")
    q = request.GET.copy() if request else {}
    if request:
        q["export"] = "csv"
        q.pop("page", None)
    return format_html('<a class="btn" href="?{}" title="Download this list, with the current filters, as a CSV file">{}</a>', q.urlencode() if request else "export=csv", label)
