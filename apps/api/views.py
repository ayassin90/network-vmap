"""REST API v1. Authenticate with  Authorization: Token <token>  (tokens are created on Settings → API tokens).
Read endpoints work with any token; write endpoints need a token that is not read-only and a user with the operator role."""
import json
from functools import wraps

from django.contrib import messages
from django.db import IntegrityError
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from apps.core.crypto import token_hash
from apps.core.models import AuditLog
from apps.core.permissions import has_role, role_required

from .models import ApiToken


def api(write=False):
    def deco(fn):
        @csrf_exempt
        @wraps(fn)
        def inner(request, *a, **kw):
            auth = request.META.get("HTTP_AUTHORIZATION", "")
            raw = auth.split(" ", 1)[1].strip() if auth.lower().startswith(("token ", "bearer ")) else ""
            tok = ApiToken.objects.select_related("user").filter(token_hash=token_hash(raw)).first() if raw else None
            if not tok or not tok.user.is_active:
                return JsonResponse({"error": "missing or invalid token"}, status=401)
            if write and (tok.read_only or not has_role(tok.user, "operator")):
                return JsonResponse({"error": "this token is read-only"}, status=403)
            ApiToken.objects.filter(pk=tok.pk).update(last_used=timezone.now())
            request.user, request.api_token = tok.user, tok
            try:
                return fn(request, *a, **kw)
            except ValueError as exc:
                return JsonResponse({"error": str(exc)}, status=400)
        return inner
    return deco


def page(request, qs, fn):
    limit = min(int(request.GET.get("limit") or 100), 1000)
    offset = int(request.GET.get("offset") or 0)
    total = qs.count()
    return JsonResponse({"count": total, "limit": limit, "offset": offset, "results": [fn(x) for x in qs[offset:offset + limit]]})


def _iso(dt):
    return dt.isoformat() if dt else None


def device_json(d):
    return {"id": d.pk, "hostname": d.hostname, "mgmt_ip": d.mgmt_ip, "platform": d.platform, "vendor": d.vendor, "model": d.model,
            "serial": d.serial, "os_version": d.os_version, "role": d.role, "site": d.site.name if d.site else None, "status": d.status,
            "security_score": d.security_score, "health_score": d.health_score, "compliance_score": d.compliance_score,
            "cpu": d.cpu, "memory_pct": d.mem_pct, "last_collected": _iso(d.last_collected), "tags": d.tag_list}


def iface_json(i):
    return {"id": i.pk, "name": i.name, "short": i.short, "description": i.description, "status": i.status, "admin_up": i.admin_up,
            "oper_up": i.oper_up, "mode": i.mode, "access_vlan": i.access_vlan, "native_vlan": i.native_vlan, "trunk_vlans": i.trunk_vlans,
            "speed_mbps": i.speed_mbps, "duplex": i.duplex, "ip": i.ip, "port_channel": i.port_channel, "in_bps": i.in_rate_bps,
            "out_bps": i.out_rate_bps, "utilization": i.utilization, "crc": i.crc, "in_errors": i.in_errors, "out_errors": i.out_errors,
            "out_drops": i.out_drops, "poe_watts": i.poe_watts}


@api()
def index(request):
    return JsonResponse({"version": 1, "endpoints": [
        "GET /api/v1/devices/?q=&site=&status=&platform=", "POST /api/v1/devices/", "GET /api/v1/devices/<id>/",
        "GET /api/v1/devices/<id>/interfaces/", "GET /api/v1/devices/<id>/config/", "POST /api/v1/devices/<id>/collect/",
        "GET /api/v1/endpoints/?q=", "GET /api/v1/findings/?status=&category=&severity=&device=", "GET /api/v1/alerts/?status=&severity=",
        "POST /api/v1/alerts/<id>/ack/", "GET /api/v1/routes/lookup/?ip=", "GET /api/v1/path/?src=&dst="]})


@api()
def devices(request):
    from apps.inventory.models import Credential, Device, Site
    if request.method == "POST":
        if request.api_token.read_only or not has_role(request.user, "operator"):
            return JsonResponse({"error": "this token is read-only"}, status=403)
        b = json.loads(request.body or "{}")
        if not b.get("mgmt_ip"):
            raise ValueError("mgmt_ip is required")
        try:
            d = Device.objects.create(
                hostname=b.get("hostname") or b["mgmt_ip"], mgmt_ip=b["mgmt_ip"], platform=b.get("platform", "cisco_iosxe"), role=b.get("role", "unknown"),
                site=Site.objects.filter(name=b.get("site")).first() if b.get("site") else None,
                ssh_credential=Credential.objects.filter(name=b.get("ssh_credential")).first() if b.get("ssh_credential") else None,
                snmp_credential=Credential.objects.filter(name=b.get("snmp_credential")).first() if b.get("snmp_credential") else None,
                tags=",".join(b.get("tags", [])))
        except IntegrityError:
            return JsonResponse({"error": "a device with this mgmt_ip exists"}, status=409)
        AuditLog.log(request.user, "api.device.add", d.hostname)
        if b.get("collect", True):
            from apps.jobs.services import enqueue_collect
            enqueue_collect(d, request.user)
        return JsonResponse(device_json(d), status=201)
    qs = Device.objects.select_related("site").order_by("hostname")
    g = request.GET
    if g.get("q"):
        qs = qs.filter(Q(hostname__icontains=g["q"]) | Q(mgmt_ip__icontains=g["q"]) | Q(serial__icontains=g["q"]))
    for f in ("status", "platform", "role"):
        if g.get(f):
            qs = qs.filter(**{f: g[f]})
    if g.get("site"):
        qs = qs.filter(site__name=g["site"])
    return page(request, qs, device_json)


@api()
def device(request, pk):
    from apps.inventory.models import Device
    d = get_object_or_404(Device.objects.select_related("site"), pk=pk)
    out = device_json(d)
    out.update(neighbors=[{"local": n.local_interface, "remote": n.remote_name, "remote_port": n.remote_port, "remote_ip": n.remote_ip,
                           "remote_device_id": n.remote_device_id} for n in d.neighbors.all()],
               env=d.env, open_findings=d.findings.filter(status="open").count(), open_alerts=d.alerts.exclude(status="resolved").count())
    return JsonResponse(out)


@api()
def device_interfaces(request, pk):
    from apps.inventory.models import Interface
    return page(request, Interface.objects.filter(device_id=pk).order_by("name"), iface_json)


@api()
def device_config(request, pk):
    from apps.inventory.models import Device
    d = get_object_or_404(Device, pk=pk)
    s = d.latest_config
    return JsonResponse({"device": d.hostname, "collected_at": _iso(s.collected_at) if s else None, "config": s.text if s else None})


@api(write=True)
def device_collect(request, pk):
    from apps.inventory.models import Device
    from apps.jobs.services import enqueue_collect
    d = get_object_or_404(Device, pk=pk)
    j = enqueue_collect(d, request.user)
    return JsonResponse({"queued": bool(j) or d.demo, "job_id": j.pk if j else None}, status=202)


@api()
def endpoints(request):
    from apps.inventory.models import Endpoint
    qs = Endpoint.objects.select_related("device")
    q = request.GET.get("q", "")
    if q:
        h = "".join(c for c in q.lower() if c in "0123456789abcdef")
        qs = qs.filter(Q(ip__startswith=q) | Q(name__icontains=q) | (Q(mac__contains=h) if len(h) >= 4 else Q(pk=None)))
    return page(request, qs, lambda e: {"mac": e.mac_display, "ip": e.ip, "name": e.name, "kind": e.kind, "device": e.device.hostname if e.device else None,
                                        "device_id": e.device_id, "interface": e.interface, "vlan": e.vlan, "first_seen": _iso(e.first_seen),
                                        "last_seen": _iso(e.last_seen), "moves": e.moves})


@api()
def findings(request):
    from apps.checks.models import Finding
    qs = Finding.objects.select_related("device").filter(status=request.GET.get("status", "open"))
    for f in ("category", "severity", "check_id"):
        if request.GET.get(f):
            qs = qs.filter(**{f: request.GET[f]})
    if request.GET.get("device"):
        qs = qs.filter(device_id=request.GET["device"])
    return page(request, qs, lambda f: {"id": f.pk, "device": f.device.hostname, "device_id": f.device_id, "category": f.category,
                                        "check_id": f.check_id, "key": f.key, "severity": f.severity, "title": f.title, "detail": f.detail,
                                        "remediation": f.remediation, "first_seen": _iso(f.first_seen), "last_seen": _iso(f.last_seen)})


@api()
def alerts(request):
    from apps.alerts.models import Alert
    st = request.GET.get("status", "active")
    qs = Alert.objects.select_related("device")
    qs = qs.exclude(status="resolved") if st == "active" else qs.filter(status=st)
    if request.GET.get("severity"):
        qs = qs.filter(severity=request.GET["severity"])
    return page(request, qs, lambda a: {"id": a.pk, "severity": a.severity, "title": a.title, "detail": a.detail, "status": a.status,
                                        "device": a.device.hostname if a.device else None, "suppressed": a.suppressed, "count": a.count,
                                        "first_seen": _iso(a.first_seen), "last_seen": _iso(a.last_seen), "case": a.case_id})


@api(write=True)
def alert_ack(request, pk):
    from apps.alerts.models import Alert
    a = get_object_or_404(Alert, pk=pk)
    if a.status == "open":
        a.status, a.acknowledged_by = "acknowledged", request.user.username
        a.save(update_fields=["status", "acknowledged_by"])
    return JsonResponse({"id": a.pk, "status": a.status})


@api()
def route_lookup(request):
    import ipaddress

    from apps.inventory.models import Device
    from apps.topology.path import lookup
    ip = ipaddress.ip_address(request.GET.get("ip", "").strip())
    out = []
    for d in Device.objects.filter(routes__isnull=False).distinct():
        for r in lookup(d, ip):
            out.append({"device": d.hostname, "vrf": r.vrf, "prefix": r.prefix, "protocol": r.protocol_name, "next_hop": r.next_hop, "interface": r.interface})
    return JsonResponse({"ip": str(ip), "results": out})


@api()
def path(request):
    from apps.topology.path import trace
    r = trace(request.GET.get("src", ""), request.GET.get("dst", ""))
    return JsonResponse({"ok": r["ok"], "warnings": r["warnings"], "notes": r["notes"],
                         "hops": [{"device": h["device"].hostname, "device_id": h["device"].pk, "layer": h["layer"], "in": h["in"], "out": h["out"],
                                   "note": h["note"]} for h in r["hops"]]})


@role_required("admin")
def tokens(request):
    new = None
    if request.method == "POST":
        if request.POST.get("action") == "revoke":
            ApiToken.objects.filter(pk=request.POST.get("id")).delete()
            messages.success(request, "Token revoked.")
            return redirect("api:tokens")
        t = ApiToken(name=request.POST.get("name") or "token", user=request.user, read_only=not request.POST.get("write"))
        new = t.issue()
        t.save()
        AuditLog.log(request, "api.token.create", t.name)
    base = request.build_absolute_uri("/").rstrip("/")
    return render(request, "api/tokens.html", {"tokens": ApiToken.objects.select_related("user"), "new": new, "base": base})
