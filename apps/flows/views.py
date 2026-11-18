from datetime import timedelta

from django.db.models import Count, F, Q, Sum
from django.shortcuts import render
from django.utils import timezone

from apps.inventory.models import Device, Endpoint, Interface

from .decode import PROTOS, app_name
from .models import FlowStat

WINDOWS = {"15m": 15, "1h": 60, "6h": 360, "24h": 1440, "7d": 10080}


def _names(ips):
    """IP -> friendly label (endpoint name or the switch port it sits on, or the device that owns it)."""
    out = {}
    for e in Endpoint.objects.filter(ip__in=ips).select_related("device"):
        out[e.ip] = e.name or (f"{e.device.hostname} {e.interface}" if e.device else "")
    for d in Device.objects.filter(mgmt_ip__in=ips):
        out[d.mgmt_ip] = d.hostname
    return out


def traffic(request):
    win = request.GET.get("w") if request.GET.get("w") in WINDOWS else "1h"
    since = timezone.now() - timedelta(minutes=WINDOWS[win])
    qs = FlowStat.objects.filter(ts__gte=since)
    dev_id = request.GET.get("device")
    ip = (request.GET.get("ip") or "").strip()
    port = request.GET.get("port")
    ifx = request.GET.get("if")
    if dev_id:
        qs = qs.filter(device_id=dev_id)
    if ifx:
        qs = qs.filter(Q(in_if=int(ifx)) | Q(out_if=int(ifx)))
    if ip:
        qs = qs.filter(Q(src=ip) | Q(dst=ip))
    if port:
        qs = qs.filter(port=int(port))
    total = qs.aggregate(b=Sum("bytes"), p=Sum("packets"), f=Sum("flows"))
    secs = WINDOWS[win] * 60
    talkers = list(qs.values("src").annotate(b=Sum("bytes")).order_by("-b")[:15])
    dests = list(qs.values("dst").annotate(b=Sum("bytes")).order_by("-b")[:15])
    convs = list(qs.values("src", "dst", "proto", "port").annotate(b=Sum("bytes"), p=Sum("packets")).order_by("-b")[:20])
    apps = list(qs.values("proto", "port").annotate(b=Sum("bytes"), n=Count("src", distinct=True)).order_by("-b")[:15])
    exporters = list(qs.values("device_id", "exporter").annotate(b=Sum("bytes")).order_by("-b"))
    names = _names({r["src"] for r in talkers + convs} | {r["dst"] for r in dests + convs})
    tb = total["b"] or 0
    for r in talkers:
        r["name"], r["pct"], r["bps"] = names.get(r["src"], ""), round(100 * r["b"] / tb, 1) if tb else 0, r["b"] * 8 // secs
    for r in dests:
        r["name"], r["pct"], r["bps"] = names.get(r["dst"], ""), round(100 * r["b"] / tb, 1) if tb else 0, r["b"] * 8 // secs
    for r in convs:
        r["src_name"], r["dst_name"], r["app"], r["bps"] = names.get(r["src"], ""), names.get(r["dst"], ""), app_name(r["proto"], r["port"]), r["b"] * 8 // secs
    for r in apps:
        r["app"], r["pct"], r["bps"] = app_name(r["proto"], r["port"]), round(100 * r["b"] / tb, 1) if tb else 0, r["b"] * 8 // secs
    devs = {d.pk: d for d in Device.objects.filter(pk__in=[e["device_id"] for e in exporters if e["device_id"]])}
    for e in exporters:
        e["dev"] = devs.get(e["device_id"])
        e["bps"] = e["b"] * 8 // secs
    ifaces = []
    if dev_id:
        idx = {i.if_index: i for i in Interface.objects.filter(device_id=dev_id).exclude(if_index=None)}
        for r in qs.values("in_if").annotate(b=Sum("bytes")).order_by("-b")[:12]:
            ifaces.append({"idx": r["in_if"], "i": idx.get(r["in_if"]), "b": r["b"], "bps": r["b"] * 8 // secs})
    # per-minute series for the chart
    from django.db.models.functions import TruncHour
    hourly = WINDOWS[win] >= 1440
    step = 3600 if hourly else 60
    series = list((qs.annotate(t=TruncHour("ts")).values("t") if hourly else qs.annotate(t=F("ts")).values("t"))
                  .annotate(b=Sum("bytes")).order_by("t"))
    peak = max((s["b"] for s in series), default=0)
    for s in series:
        s["ts"] = s["t"]
        s["h"] = round(100 * s["b"] / peak) if peak else 0
        s["bps"] = s["b"] * 8 // step
    return render(request, "flows/traffic.html", {
        "w": win, "windows": list(WINDOWS), "total": total, "avg_bps": tb * 8 // secs, "talkers": talkers, "dests": dests, "convs": convs,
        "apps": apps, "exporters": exporters, "ifaces": ifaces, "series": series, "hourly": hourly, "dev_id": dev_id, "ip": ip, "port": port, "ifx": ifx,
        "devices": Device.objects.filter(pk__in=FlowStat.objects.values("device_id").distinct()).order_by("hostname"),
        "any": FlowStat.objects.exists()})
