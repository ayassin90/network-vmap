from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_POST

from apps.core.models import AuditLog
from apps.core.permissions import has_role, role_required
from apps.drivers.registry import drivers
from apps.inventory.models import Device, Site
from apps.jobs.models import Job

from .models import SoftwareImage, UpgradePlan, UpgradeTarget


def plan_list(request):
    plans = UpgradePlan.objects.select_related("image")
    versions = {}
    for d in Device.objects.exclude(os_version=""):
        versions.setdefault((d.platform, d.model.split("-")[0] if d.model else "", d.os_version), []).append(d)
    vrows = sorted(([k[0], k[1], k[2], len(v)] for k, v in versions.items()), key=lambda r: (r[0], r[1], r[2]))
    return render(request, "upgrades/list.html", {"plans": plans, "images": SoftwareImage.objects.all(), "vrows": vrows})


def images(request):
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators can manage images.")
            return redirect("upgrades:images")
        if request.POST.get("action") == "delete":
            img = get_object_or_404(SoftwareImage, pk=request.POST.get("id"))
            if img.plans.exists():
                messages.error(request, "This image is used by a plan.")
            else:
                img.delete()
            return redirect("upgrades:images")
        p = request.POST
        size = p.get("size_bytes") or None
        SoftwareImage.objects.create(name=p["name"], platforms=",".join(p.getlist("platforms")) or "cisco_iosxe", model_match=p.get("model_match", ""),
                                     version=p["version"].strip(), filename=p["filename"].strip(), md5=p.get("md5", "").strip().lower(),
                                     size_bytes=int(size) if size else None, transfer_url=p["transfer_url"].strip(), notes=p.get("notes", ""))
        messages.success(request, "Image added.")
        return redirect("upgrades:images")
    up = [d for d in drivers().values() if d.upgrade_supported()]
    return render(request, "upgrades/images.html", {"images": SoftwareImage.objects.all(), "platforms": up})


@role_required("operator")
def plan_new(request):
    img = SoftwareImage.objects.filter(pk=request.GET.get("image") or request.POST.get("image") or 0).first()
    if request.method == "POST" and img:
        ids = request.POST.getlist("devices")
        if not ids:
            messages.error(request, "Pick at least one device.")
        else:
            plan = UpgradePlan.objects.create(
                name=request.POST.get("name") or f"{img.version} rollout", image=img, mode=request.POST.get("mode", "stage"),
                allow_reload=bool(request.POST.get("allow_reload")), dry_run=bool(request.POST.get("dry_run")),
                max_parallel=int(request.POST.get("max_parallel") or 5), stop_on_failures=int(request.POST.get("stop_on_failures") or 1),
                scheduled_for=parse_datetime(request.POST.get("scheduled_for") or "") or None, created_by=request.user.username)
            for d in Device.objects.filter(pk__in=ids):
                UpgradeTarget.objects.create(plan=plan, device=d, from_version=d.os_version)
            AuditLog.log(request, "upgrade.plan", plan.name, f"{len(ids)} devices")
            return redirect("upgrades:plan", plan.pk)
    cands = []
    if img:
        for d in Device.objects.filter(enabled=True).select_related("site"):
            if img.fits(d):
                d.same = d.os_version == img.version
                cands.append(d)
    return render(request, "upgrades/new.html", {"img": img, "images": SoftwareImage.objects.all(), "cands": cands, "sites": Site.objects.all()})


def plan(request, pk):
    p = get_object_or_404(UpgradePlan.objects.select_related("image"), pk=pk)
    if request.method == "POST":
        if not has_role(request.user, "operator"):
            messages.error(request, "You need the operator role.")
            return redirect("upgrades:plan", pk)
        act = request.POST.get("action")
        if act == "approve" and p.status == "draft":
            if not p.dry_run and not has_role(request.user, "admin"):
                messages.error(request, "A live (not dry-run) plan must be approved by an administrator.")
            else:
                p.status, p.approved_by = "approved", request.user.username
                p.save()
                AuditLog.log(request, "upgrade.approve", p.name)
                messages.success(request, "Approved. It starts " + (f"at {p.scheduled_for:%Y-%m-%d %H:%M}." if p.scheduled_for else "within 30 seconds."))
        elif act == "pause" and p.status == "running":
            p.status = "paused"
            p.save()
        elif act == "resume" and p.status == "paused":
            p.status = "running"
            p.save()
        elif act == "cancel" and p.status not in ("done", "failed", "cancelled"):
            p.status = "cancelled"
            p.save()
            p.targets.filter(status="pending").update(status="skipped")
            Job.objects.filter(ref__startswith="upgrade:", status="queued", ref__in=[f"upgrade:{t.pk}:{s}" for t in p.targets.all() for s in UpgradeTarget.STAGES]).update(status="cancelled")
        elif act == "retry":
            t = get_object_or_404(UpgradeTarget, pk=request.POST.get("target"), plan=p)
            t.status, t.stage, t.postcheck_tries = "pending", "", 0
            t.note("retry requested by " + request.user.username)
            t.save()
            if p.status in ("failed", "paused", "done"):
                p.status = "running"
                p.save()
        elif act == "delete" and p.status in ("draft", "done", "failed", "cancelled"):
            p.delete()
            return redirect("upgrades:list")
        return redirect("upgrades:plan", pk)
    targets = list(p.targets.select_related("device"))
    for t in targets:
        cur = UpgradeTarget.STAGES.index(t.stage) if t.stage in UpgradeTarget.STAGES else -1
        states = []
        for i, s in enumerate(UpgradeTarget.STAGES):
            if t.status == "pending" or i > cur:
                cls = "vn-skipped" if t.status in ("done", "skipped") else "vn-todo"
            elif i < cur:
                cls = "vn-done"
            else:
                cls = {"running": "vn-active", "waiting": "vn-active", "failed": "vn-failed", "done": "vn-done"}.get(t.status, "vn-todo")
            states.append((s, cls))
        t.states = states
    return render(request, "upgrades/plan.html", {"p": p, "targets": targets, "counts": p.counts(), "now": timezone.now(),
                                                 "stages": UpgradeTarget.STAGES})
