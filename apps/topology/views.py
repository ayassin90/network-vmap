import json

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_POST

from apps.core.permissions import has_role
from apps.inventory.models import Site

from . import graph
from .models import Layout


def _page(request, kind):
    layouts = Layout.objects.filter(kind=kind)
    current = None
    if request.GET.get("layout"):
        current = layouts.filter(pk=request.GET["layout"]).first()
    if not current:
        current = layouts.filter(name="Default").first()
    return render(request, "topology/view.html", {
        "kind": kind, "sites": Site.objects.all(), "layouts": layouts, "layout": current,
        "layout_json": {"id": current.pk, "name": current.name, "positions": current.positions, "hidden": current.hidden,
                        "labels": current.labels, "options": current.options, "site": current.site_id} if current else {},
        "can_edit": has_role(request.user, "operator"),
    })


def l2(request):
    return _page(request, "l2")


def l3(request):
    return _page(request, "l3")


def data(request, kind):
    site = Site.objects.filter(pk=request.GET.get("site") or 0).first()
    if kind == "l3":
        return JsonResponse(graph.l3(site))
    return JsonResponse(graph.l2(site, endpoints=request.GET.get("endpoints") == "1"))


@require_POST
def save(request):
    if not has_role(request.user, "operator"):
        return JsonResponse({"error": "operator role needed"}, status=403)
    body = json.loads(request.body)
    kind = body.get("kind") if body.get("kind") in ("l2", "l3") else "l2"
    name = (body.get("name") or "Default").strip()[:120]
    lay = Layout.objects.filter(pk=body.get("id")).first() if body.get("id") else None
    if not lay or lay.name != name:
        lay, _ = Layout.objects.get_or_create(kind=kind, name=name)
    lay.positions = body.get("positions") or {}
    lay.hidden = body.get("hidden") or []
    lay.labels = body.get("labels") or {}
    lay.options = body.get("options") or {}
    lay.site = Site.objects.filter(pk=body.get("site") or 0).first()
    lay.updated_by = request.user.username
    lay.save()
    return JsonResponse({"id": lay.pk, "name": lay.name})


@require_POST
def delete(request, pk):
    if not has_role(request.user, "operator"):
        return JsonResponse({"error": "operator role needed"}, status=403)
    get_object_or_404(Layout, pk=pk).delete()
    return JsonResponse({"ok": True})


def path_view(request):
    from .path import hop_issues, trace
    src, dst = request.GET.get("src", "").strip(), request.GET.get("dst", "").strip()
    res = trace(src, dst) if src and dst else None
    issues = hop_issues(res["hops"]) if res else []
    ids = ",".join(str(h["device"].pk) for h in res["hops"]) if res else ""
    return render(request, "topology/path.html", {"src": src, "dst": dst, "res": res, "issues": issues, "ids": ids})
