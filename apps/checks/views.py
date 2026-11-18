from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.core.permissions import has_role, role_required
from apps.inventory.models import Device, Site

from .engine import run_all
from .models import SEVERITIES, ComplianceResult, Finding, Standard, StandardRule
from .rules import RULES


def findings(request):
    cat = request.GET.get("cat", "")
    qs = Finding.objects.select_related("device").filter(status=request.GET.get("status", "open"))
    if cat:
        qs = qs.filter(category=cat)
    else:
        qs = qs.filter(category__in=("security", "best_practice"))
    if request.GET.get("sev"):
        qs = qs.filter(severity=request.GET["sev"])
    if request.GET.get("site"):
        qs = qs.filter(device__site_id=request.GET["site"])
    view = request.GET.get("view", "by_check")
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(device__hostname__icontains=q) | Q(detail__icontains=q))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    groups = []
    if view == "by_check":
        bucket = {}
        for f in qs:
            g = bucket.setdefault(f.check_id, {"check_id": f.check_id, "title": f.title, "severity": f.severity, "category": f.category,
                                               "recommendation": f.recommendation, "remediation": f.remediation, "items": []})
            g["items"].append(f)
        for g in bucket.values():
            g["n_devices"] = len({f.device_id for f in g["items"]})
        groups = sorted(bucket.values(), key=lambda g: (rank[g["severity"]], -g["n_devices"]))
    from apps.core.export import csv_response, wants_csv
    if wants_csv(request):
        return csv_response("findings", ["device", "mgmt_ip", "site", "category", "severity", "check", "title", "on", "detail", "recommendation",
                                         "first_seen", "status"],
                            ([f.device.hostname, f.device.mgmt_ip, f.device.site.name if f.device.site else "", f.category, f.severity, f.check_id,
                              f.title, f.key, f.detail, f.recommendation, f.first_seen.isoformat() if getattr(f, "first_seen", None) else "", f.status]
                             for f in sorted(qs.select_related("device__site"), key=lambda f: (rank[f.severity], f.device.hostname))))
    page = Paginator(sorted(qs, key=lambda f: (rank[f.severity], f.device.hostname)), 200).get_page(request.GET.get("page"))
    stats = {s: Finding.objects.filter(status="open", category__in=("security", "best_practice"), severity=s).count() for s, _ in SEVERITIES}
    worst = Device.objects.exclude(security_score=None).order_by("security_score")[:8]
    return render(request, "checks/findings.html", {"groups": groups, "page": page, "view": view, "cat": cat, "stats": stats,
                                                    "sites": Site.objects.all(), "q": q, "worst": worst, "rules": RULES})


@role_required("operator")
@require_POST
def finding_action(request, pk):
    f = get_object_or_404(Finding, pk=pk)
    act = request.POST.get("action")
    if act == "accept":
        f.status, f.accepted_by, f.accepted_note = "accepted", request.user.username, request.POST.get("note", "")
    elif act == "reopen":
        f.status = "open"
    f.save()
    messages.success(request, "Finding updated.")
    return redirect(request.META.get("HTTP_REFERER") or "checks:findings")


@role_required("operator")
@require_POST
def rerun(request):
    n = 0
    for d in Device.objects.filter(enabled=True):
        run_all(d)
        from apps.alerts.engine import evaluate_device
        evaluate_device(d)
        n += 1
    messages.success(request, f"Checks re-run on {n} devices using their last collected data.")
    return redirect(request.META.get("HTTP_REFERER") or "checks:findings")


def standards(request):
    stds = Standard.objects.annotate(n_rules=Count("rules"))
    rows = []
    for s in stds:
        res = list(ComplianceResult.objects.filter(standard=s))
        rows.append({"s": s, "devices": len(res), "avg": round(sum(r.score for r in res) / len(res)) if res else None,
                     "failing": sum(1 for r in res if r.failed)})
    return render(request, "checks/standards.html", {"rows": rows})


@role_required("admin")
def standard_new(request):
    if request.method == "POST":
        s = Standard.objects.create(name=request.POST["name"].strip()[:120], description=request.POST.get("description", ""),
                                    platforms=request.POST.get("platforms", "cisco_ios,cisco_iosxe"))
        return redirect("checks:standard", s.pk)
    return render(request, "checks/standard_new.html")


def standard(request, pk):
    s = get_object_or_404(Standard, pk=pk)
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators can change standards.")
            return redirect("checks:standard", pk)
        act = request.POST.get("action")
        if act == "meta":
            s.name = request.POST.get("name", s.name)[:120]
            s.description = request.POST.get("description", "")
            s.platforms = request.POST.get("platforms", s.platforms)
            s.roles = request.POST.get("roles", "")
            s.enabled = bool(request.POST.get("enabled"))
            s.save()
        elif act in ("add", "edit"):
            import re
            try:
                re.compile(request.POST.get("pattern", ""))
                if request.POST.get("section"):
                    re.compile(request.POST["section"])
            except re.error as exc:
                messages.error(request, f"Invalid regular expression: {exc}")
                return redirect("checks:standard", pk)
            r = StandardRule(standard=s) if act == "add" else get_object_or_404(StandardRule, pk=request.POST.get("id"), standard=s)
            for f in ("name", "kind", "pattern", "section", "applies_if", "severity", "remediation", "explanation"):
                setattr(r, f, request.POST.get(f, ""))
            r.order = r.order or s.rules.count() + 1
            r.save()
        elif act == "delete_rule":
            StandardRule.objects.filter(pk=request.POST.get("id"), standard=s).delete()
        elif act == "delete":
            s.delete()
            return redirect("checks:standards")
        elif act == "run":
            for d in Device.objects.filter(enabled=True):
                run_all(d)
            messages.success(request, "Standards evaluated on all devices.")
        return redirect("checks:standard", pk)
    results = ComplianceResult.objects.filter(standard=s).select_related("device").order_by("passed")
    rule_fail = {}
    for r in results:
        for dt in r.details:
            if not dt["ok"]:
                rule_fail[dt["rule"]] = rule_fail.get(dt["rule"], 0) + 1
    rules = list(s.rules.all())
    for r in rules:
        r.failing = rule_fail.get(r.pk, 0)
    return render(request, "checks/standard.html", {"s": s, "rules": rules, "results": results, "kinds": StandardRule.KINDS,
                                                   "severities": SEVERITIES, "edit": s.rules.filter(pk=request.GET.get("edit") or 0).first()})


def compliance(request, pk, device):
    r = get_object_or_404(ComplianceResult.objects.select_related("device", "standard"), standard_id=pk, device_id=device)
    return render(request, "checks/compliance.html", {"r": r, "now": timezone.now()})
