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
    from .engine import rescore
    rescore(f.device)
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


# ------------------------------------------------------------------ hardening posture and check catalogue
FAMILY_LABEL = {"cisco_ios": "Cisco IOS / IOS-XE", "cisco_nxos": "Cisco NX-OS", "arista_eos": "Arista EOS", "aruba_aoscx": "Aruba AOS-CX",
                "aruba_aoss": "Aruba AOS-S", "huawei_vrp": "Huawei VRP", "juniper_junos": "Juniper Junos", "fortiswitch": "FortiSwitch"}


def posture(request):
    from . import posture as P
    from .controls import FRAMEWORKS
    from .models import PostureResult
    fw = request.GET.get("fw") if request.GET.get("fw") in FRAMEWORKS else "cisv8"
    devs = Device.objects.filter(enabled=True)
    if request.GET.get("site"):
        devs = devs.filter(site_id=request.GET["site"])
    if request.GET.get("role"):
        devs = devs.filter(role=request.GET["role"])
    if request.GET.get("platform"):
        devs = devs.filter(platform=request.GET["platform"])
    prs = PostureResult.objects.filter(device__in=devs).select_related("device", "device__site")
    data = P.fleet(prs, fw)
    from apps.core.export import csv_response, wants_csv
    if wants_csv(request):
        return csv_response(f"posture-{fw}", ["framework", "control", "title", "checks", "passing", "failing", "accepted", "compliance_pct",
                                              "failing_devices", "failing_checks"],
                            ([FRAMEWORKS[fw]["name"], c["id"], c["title"], c["n_checks"], c["ok"] - c["accepted"], c["fail"], c["accepted"],
                              c["pct"], " ".join(d.hostname for d in c["fail_devices"]),
                              " ".join(x["r"].id for x in c["rows"] if x["fail"])] for c in data["controls"]))
    plats = sorted(set(Device.objects.filter(enabled=True).values_list("platform", flat=True)))
    return render(request, "checks/posture.html", {**data, "sites": Site.objects.all(), "roles": Device.ROLES,
                                                   "platforms": plats, "n_rules": len(RULES)})


def catalog(request):
    from . import posture as P
    from .controls import DOMAINS, FRAMEWORKS
    rows = list(RULES)
    fam, dom, sev, fw, q = (request.GET.get(k, "") for k in ("family", "domain", "sev", "fw", "q"))
    if fam:
        rows = [r for r in rows if fam in r.families]
    if dom:
        rows = [r for r in rows if r.domain == dom]
    if sev:
        rows = [r for r in rows if r.severity == sev]
    ctl = request.GET.get("control", "")
    if fw in FRAMEWORKS and ctl:
        rows = [r for r in rows if ctl in r.controls.get(fw, [])]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r.id.lower() or ql in r.title.lower() or ql in r.why.lower()
                or any(ql == c.lower() for ids in r.controls.values() for c in ids)]
    from apps.core.export import csv_response, wants_csv
    if wants_csv(request):
        return csv_response("check-catalogue", ["id", "title", "severity", "category", "domain", "platforms", "switches_only", "cis_controls_v8",
                                                "nist_800_53", "iso_27001", "pci_dss", "nist_csf", "cis_benchmark", "why", "fix", "remediation"],
                            ([r.id, r.title, r.severity, r.category, DOMAINS.get(r.domain, r.domain), " ".join(r.families), "yes" if r.switch_only else "",
                              " ".join(r.controls.get("cisv8", [])), " ".join(r.controls.get("nist", [])), " ".join(r.controls.get("iso", [])),
                              " ".join(r.controls.get("pci", [])), " ".join(r.controls.get("csf", [])), " ".join(r.controls.get("cis", [])),
                              r.why, r.fix, r.snippet] for r in rows))
    fam_counts = {f: sum(1 for r in RULES if f in r.families) for f in FAMILY_LABEL}
    return render(request, "checks/catalog.html", {"rows": rows, "n_all": len(RULES), "families": FAMILY_LABEL, "fam_counts": fam_counts,
                                                   "domains": DOMAINS, "frameworks": FRAMEWORKS, "topics": P.topic_rows(),
                                                   "fam": fam, "dom": dom, "sev": sev, "fw": fw, "control": ctl, "q": q, "severities": SEVERITIES})
