from django.contrib import messages
from django.shortcuts import redirect, render

from apps.core.permissions import has_role

from . import data


def capacity(request):
    days = int(request.GET.get("days") or 7)
    return render(request, "reports/capacity.html", {"uplinks": data.uplinks(days), "ports": data.ports(30), "days": days})


def summary(request):
    if request.method == "POST" and has_role(request.user, "admin"):
        try:
            messages.info(request, data.send_summary(force=True))
        except Exception as exc:  # noqa: BLE001
            messages.error(request, f"Sending failed: {exc}")
        return redirect("reports:summary")
    return render(request, "reports/summary.html", data.summary(int(request.GET.get("days") or 7)))


def audit(request):
    return render(request, "reports/audit.html", data.audit())
