from django.contrib import messages
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from apps.core.models import AuditLog
from apps.core.permissions import has_role, role_required

from .models import Collector, Job


def job_list(request):
    qs = Job.objects.select_related("device", "collector")
    for f in ("status", "kind"):
        if request.GET.get(f):
            qs = qs.filter(**{f: request.GET[f]})
    if request.GET.get("collector"):
        qs = qs.filter(collector_id=request.GET["collector"])
    stats = {s: Job.objects.filter(status=s).count() for s in ("queued", "running", "failed")}
    return render(request, "jobs/list.html", {"page": Paginator(qs, 100).get_page(request.GET.get("page")), "stats": stats,
                                             "kinds": Job.KINDS, "statuses": Job.STATUS})


def job_detail(request, pk):
    j = get_object_or_404(Job.objects.select_related("device", "collector"), pk=pk)
    return render(request, "jobs/detail.html", {"j": j, "spec": j.public_spec(), "auto": j.status in ("queued", "running")})


@role_required("operator")
@require_POST
def job_cancel(request, pk):
    Job.objects.filter(pk=pk, status="queued").update(status="cancelled")
    return redirect("jobs:detail", pk)


def collectors(request):
    token = None
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators manage collectors.")
            return redirect("jobs:collectors")
        act = request.POST.get("action")
        if act == "create":
            name = request.POST.get("name", "").strip()
            if not name or Collector.objects.filter(name=name).exists():
                messages.error(request, "Give the collector a unique name.")
            else:
                c = Collector(name=name, description=request.POST.get("description", ""))
                token = c.new_token()
                c.save()
                AuditLog.log(request, "collector.create", name)
                request.session["new_token"] = {"id": c.pk, "token": token}
                return redirect("jobs:collector", c.pk)
        elif act == "delete":
            Collector.objects.filter(pk=request.POST.get("id")).delete()
            return redirect("jobs:collectors")
    return render(request, "jobs/collectors.html", {"collectors": Collector.objects.all()})


def collector(request, pk):
    c = get_object_or_404(Collector, pk=pk)
    token = None
    nt = request.session.pop("new_token", None)
    if nt and nt.get("id") == c.pk:
        token = nt["token"]
    if request.method == "POST" and has_role(request.user, "admin"):
        act = request.POST.get("action")
        if act == "rotate":
            token = c.new_token()
            c.save()
            AuditLog.log(request, "collector.rotate", c.name)
            messages.success(request, "New token created. The old one stops working now.")
        elif act == "toggle":
            c.enabled = not c.enabled
            c.save()
    server = request.build_absolute_uri("/").rstrip("/")
    return render(request, "jobs/collector.html", {"c": c, "token": token, "server": server,
                                                  "jobs": c.jobs.select_related("device")[:30], "devices": c.devices.all()[:100]})
