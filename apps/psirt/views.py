from django.contrib import messages
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.models import AppSetting
from apps.core.permissions import role_required

from .models import Advisory, DeviceAdvisory


def advisory_list(request):
    qs = Advisory.objects.annotate(n=Count("hits", filter=Q(hits__status="open")))
    if request.GET.get("all") != "1":
        qs = qs.filter(n__gt=0)
    if request.GET.get("sev"):
        qs = qs.filter(severity=request.GET["sev"])
    stats = {s: DeviceAdvisory.objects.filter(status="open", advisory__severity=s).values("device").distinct().count()
             for s in ("critical", "high", "medium")}
    return render(request, "psirt/list.html", {"advisories": qs.order_by("-n", "-cvss"), "stats": stats,
                                               "configured": bool(AppSetting.get("openvuln_client_id")),
                                               "last_sync": AppSetting.get("openvuln_last_sync"),
                                               "versions": DeviceAdvisory.objects.filter(status="open").values("device__os_type", "device__os_version").annotate(n=Count("device", distinct=True), a=Count("advisory", distinct=True)).order_by("-a")[:20]})


def advisory_detail(request, pk):
    a = get_object_or_404(Advisory, pk=pk)
    return render(request, "psirt/detail.html", {"a": a, "hits": a.hits.select_related("device").order_by("status", "device__hostname")})


@role_required("operator")
@require_POST
def hit_action(request, pk):
    h = get_object_or_404(DeviceAdvisory, pk=pk)
    if request.POST.get("status") in dict(DeviceAdvisory.STATUS):
        h.status = request.POST["status"]
        h.note = request.POST.get("note", h.note)
        h.save()
    return redirect(request.META.get("HTTP_REFERER") or "psirt:list")


@role_required("operator")
@require_POST
def sync(request):
    from .sync import sync_openvuln
    try:
        messages.success(request, sync_openvuln())
    except Exception as exc:  # noqa: BLE001
        messages.error(request, f"Sync failed: {exc}")
    return redirect("psirt:list")
