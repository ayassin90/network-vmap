from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from apps.core.permissions import has_role

from . import engine
from .models import Snapshot


def index(request):
    if request.method == "POST" and has_role(request.user, "operator"):
        s = engine.take(label=request.POST.get("label", "")[:120], kind="manual", user=request.user.username)
        messages.success(request, f"Snapshot taken: {s.summary.get('devices', 0)} devices, {s.summary.get('interfaces', 0)} ports.")
        return redirect("snapshots:detail", s.pk)
    snaps = list(Snapshot.objects.defer("blob")[:200])
    return render(request, "snapshots/index.html", {"snaps": snaps})


def detail(request, pk):
    s = get_object_or_404(Snapshot, pk=pk)
    if request.method == "POST" and has_role(request.user, "admin") and request.POST.get("action") == "delete":
        s.delete()
        messages.success(request, "Snapshot deleted.")
        return redirect("snapshots:index")
    st = s.data
    q = (request.GET.get("q") or "").strip().lower()
    devices = sorted(st["devices"].items())
    if q:
        devices = [(h, d) for h, d in devices if q in h.lower() or q in (d.get("ip") or "") or q in (d.get("model") or "").lower()]
    host = request.GET.get("device")
    ports = sorted(st["interfaces"].get(host, {}).items()) if host else []
    return render(request, "snapshots/detail.html", {"s": s, "devices": devices, "links": st["links"], "host": host, "ports": ports,
                                                     "routes": st["routes"].get(host, []) if host else [], "q": q,
                                                     "findings": st["findings"].get(host, []) if host else []})


def compare(request):
    snaps = list(Snapshot.objects.defer("blob")[:200])
    a_id, b_id = request.GET.get("a"), request.GET.get("b") or "now"
    if not a_id and snaps:
        a_id = str(snaps[0].pk)
    ctx = {"snaps": snaps, "a_id": a_id, "b_id": b_id}
    if a_id:
        a = get_object_or_404(Snapshot, pk=a_id)
        if b_id == "now":
            b_state, b_label = engine.capture_state(), "now"
        else:
            b = get_object_or_404(Snapshot, pk=b_id)
            b_state, b_label = b.data, str(b)
            if b.taken_at < a.taken_at:
                a, b = b, a
                b_state, b_label = b.data, str(b)
        ctx.update({"a": a, "b_label": b_label, "d": engine.diff(a.data, b_state)})
    return render(request, "snapshots/compare.html", ctx)
