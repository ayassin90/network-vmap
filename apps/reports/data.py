"""Numbers for the capacity report and the weekly summary."""
from collections import defaultdict
from datetime import timedelta

from django.db.models import Count
from django.utils import timezone

from apps.inventory.models import Device, Endpoint, Interface, InterfaceSample


def _p95(vals):
    if not vals:
        return 0
    vals = sorted(vals)
    return vals[min(len(vals) - 1, int(round(0.95 * (len(vals) - 1))))]


def uplinks(days=7):
    now = timezone.now()
    since, prev = now - timedelta(days=days), now - timedelta(days=2 * days)
    ifs = {i.pk: i for i in Interface.objects.filter(mode__in=("trunk", "routed"), oper_up=True).select_related("device") if i.is_physical or i.name.lower().startswith("port-channel")}
    cur, old = defaultdict(list), defaultdict(list)
    for iid, ts, a, b in InterfaceSample.objects.filter(interface_id__in=list(ifs), ts__gte=prev).values_list("interface_id", "ts", "in_bps", "out_bps"):
        (cur if ts >= since else old)[iid].append(max(a, b))
    rows = []
    for iid, i in ifs.items():
        vals = cur.get(iid) or ([max(i.in_rate_bps, i.out_rate_bps)] if (i.in_rate_bps or i.out_rate_bps) else [])
        if not vals:
            continue
        p95, peak = _p95(vals), max(vals)
        prev95 = _p95(old.get(iid, []))
        cap = (i.speed_mbps or 0) * 1_000_000
        rows.append({"i": i, "p95": p95, "peak": peak, "avg": sum(vals) / len(vals), "samples": len(vals),
                     "util95": round(100 * p95 / cap, 1) if cap else None, "growth": round(100 * (p95 - prev95) / prev95) if prev95 else None})
    rows.sort(key=lambda r: -(r["util95"] or 0))
    return rows


def ports(days=30):
    since = timezone.now() - timedelta(days=days)
    seen = set(Endpoint.objects.filter(last_seen__gte=since).values_list("device_id", "interface"))
    active = set(InterfaceSample.objects.filter(ts__gte=since).values_list("interface_id", flat=True).distinct())
    out = []
    for d in Device.objects.filter(enabled=True).order_by("hostname"):
        acc = [i for i in d.interfaces.all() if i.is_physical and i.mode == "access"]
        if not acc:
            continue
        connected = sum(1 for i in acc if i.oper_up)
        unused = [i for i in acc if not i.oper_up and (d.pk, i.short) not in seen and i.pk not in active]
        poe = (d.facts or {}).get("poe") or {}
        out.append({"d": d, "total": len(acc), "connected": connected, "free": len(acc) - connected, "unused": len(unused),
                    "unused_names": [i.short for i in unused][:40], "pct": round(100 * connected / len(acc)) if acc else 0,
                    "poe_used": poe.get("used"), "poe_avail": poe.get("available")})
    return out


def summary(days=7):
    from apps.alerts.models import Alert, Case
    from apps.changes.models import ChangeRequest
    from apps.checks.models import Finding
    from apps.jobs.models import Job
    from apps.psirt.models import DeviceAdvisory
    now = timezone.now()
    since = now - timedelta(days=days)
    devs = Device.objects.filter(enabled=True)
    return {
        "days": days, "since": since, "now": now,
        "devices": devs.count(), "down": devs.filter(status__in=("down", "auth_failed", "error")),
        "alerts_open": dict(Alert.objects.filter(status="open", suppressed=False).values_list("severity").annotate(n=Count("id"))),
        "alerts_new": Alert.objects.filter(first_seen__gte=since).count(),
        "alerts_top": Alert.objects.filter(status="open", suppressed=False, severity__in=("critical", "high")).select_related("device")[:10],
        "findings_new": Finding.objects.filter(first_seen__gte=since, status="open", severity__in=("critical", "high")).select_related("device")[:15],
        "findings_fixed": Finding.objects.filter(resolved_at__gte=since).count(),
        "psirt": DeviceAdvisory.objects.filter(status="open", advisory__severity__in=("critical", "high")).values("device").distinct().count(),
        "lifecycle": Finding.objects.filter(category="lifecycle", status="open", severity__in=("high", "medium")).select_related("device")[:10],
        "changes": ChangeRequest.objects.filter(created_at__gte=since).values_list("status").annotate(n=Count("id")),
        "pending": ChangeRequest.objects.filter(status="pending").count(),
        "cases_open": Case.objects.exclude(status__in=("resolved", "closed")).count(),
        "jobs_failed": Job.objects.filter(status="failed", finished_at__gte=since).count(),
        "uplinks": uplinks(days)[:8],
        "scores": {k: round(sum(v) / len(v)) if v else None for k, v in (
            ("security", [d.security_score for d in devs if d.security_score is not None]),
            ("health", [d.health_score for d in devs if d.health_score is not None]),
            ("compliance", [d.compliance_score for d in devs if d.compliance_score is not None]))},
    }


def send_summary(force=False):
    """Email the weekly summary to the configured recipients. Returns a message."""
    from django.conf import settings
    from django.core.mail import send_mail
    from django.template.loader import render_to_string

    from apps.core.models import AppSetting
    to = [x.strip() for x in AppSetting.get("report_recipients", "").split(",") if x.strip()]
    if not to:
        return "No recipients set (Settings → Weekly report recipients)."
    if not settings.EMAIL_HOST:
        return "SMTP is not configured on the server (SMTP_HOST)."
    ctx = summary()
    ctx["base"] = AppSetting.get("public_url", "").rstrip("/")
    html = render_to_string("reports/summary_email.html", ctx)
    text = f"Network VMap weekly summary: {ctx['devices']} devices, {sum(ctx['alerts_open'].values())} open alerts. Open {ctx['base']}/reports/summary/"
    send_mail(f"[VMap] Weekly network summary {ctx['now']:%d %b %Y}", text, None, to, html_message=html)
    AppSetting.put("report_last_sent", ctx["now"].date().isoformat())
    return f"Sent to {', '.join(to)}."


def maybe_send():
    from apps.core.models import AppSetting
    now = timezone.localtime()
    if not AppSetting.get("report_recipients"):
        return
    if now.weekday() != AppSetting.get_int("report_weekday", 0) or now.hour != AppSetting.get_int("report_hour", 7):
        return
    if AppSetting.get("report_last_sent") == now.date().isoformat():
        return
    send_summary()


def audit():
    """Everything an auditor asks for, on one page: posture, open security findings by check, standards compliance,
    vendor advisories, unsupported hardware and software. Built to be printed or saved as PDF."""
    from django.db.models import Avg, Count
    from django.utils import timezone

    from apps.checks.models import ComplianceResult, Finding
    from apps.inventory.models import Device
    from apps.psirt.models import DeviceAdvisory
    devs = Device.objects.filter(enabled=True).select_related("site")
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sec = Finding.objects.filter(status="open", category__in=("security", "best_practice")).select_related("device")
    checks = {}
    for f in sec:
        g = checks.setdefault(f.check_id, {"id": f.check_id, "title": f.title, "severity": f.severity, "category": f.category,
                                           "recommendation": f.recommendation, "devices": set()})
        g["devices"].add(f.device.hostname)
    checks = sorted(checks.values(), key=lambda g: (rank.get(g["severity"], 9), -len(g["devices"])))
    for g in checks:
        g["devices"] = sorted(g["devices"])
    accepted = Finding.objects.filter(status="accepted").select_related("device").order_by("device__hostname")
    comp = []
    latest = {}
    for r in ComplianceResult.objects.select_related("device", "standard").order_by("ran_at"):
        latest[(r.device_id, r.standard_id)] = r
    by_std = {}
    for r in latest.values():
        s = by_std.setdefault(r.standard.name, {"name": r.standard.name, "devices": 0, "compliant": 0, "failed_rules": 0})
        s["devices"] += 1
        s["compliant"] += 1 if not r.failed else 0
        s["failed_rules"] += r.failed
    comp = sorted(by_std.values(), key=lambda s: s["name"])
    psirt = list(DeviceAdvisory.objects.filter(status="open").values("advisory__advisory_id", "advisory__title", "advisory__severity", "advisory__url")
                 .annotate(n=Count("device", distinct=True)).order_by("-n"))
    for p in psirt:
        p["devices"] = sorted(DeviceAdvisory.objects.filter(status="open", advisory__advisory_id=p["advisory__advisory_id"]).values_list("device__hostname", flat=True))
    psirt.sort(key=lambda p: (rank.get(p["advisory__severity"], 9), -p["n"]))
    life = Finding.objects.filter(status="open", category="lifecycle").select_related("device").order_by("severity", "device__hostname")
    scores = devs.aggregate(sec=Avg("security_score"), comp=Avg("compliance_score"), health=Avg("health_score"))
    from apps.checks.models import PostureResult
    from apps.checks.posture import FW_ORDER, fleet
    prs = list(PostureResult.objects.filter(device__in=devs).select_related("device"))
    standards = []
    for fw in FW_ORDER:
        f = fleet(prs, fw)
        standards.append({"key": fw, "name": f["framework"]["name"], "pct": next(x["pct"] for x in f["frameworks"] if x["key"] == fw),
                          "n_controls": f["n_controls"], "evaluated": f["n_evaluated"],
                          "failing": [c for c in f["controls"] if c["fail"]]})
    sev = {s: sec.filter(severity=s).count() for s in rank}
    return {"generated": timezone.now(), "devices": devs.count(), "by_vendor": devs.values("vendor").annotate(n=Count("id")).order_by("-n"),
            "scores": scores, "sev": sev, "standards": standards, "checks": checks, "accepted": accepted, "compliance": comp, "psirt": psirt, "life": life,
            "worst": devs.exclude(security_score=None).order_by("security_score")[:10]}
