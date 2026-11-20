import difflib
import ipaddress
import json
import re
from datetime import timedelta

from django.contrib import messages
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import Count, F, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.checks.models import ComplianceResult, Finding
from apps.core.models import AuditLog
from apps.core.permissions import has_role, role_required
from apps.drivers.base import FEATURES, LEVELS
from apps.drivers.registry import drivers, get_driver
from apps.jobs import services
from apps.jobs.models import Job

from .forms import BulkAddForm, CredentialForm, DeviceForm, DiscoveryForm, SiteForm
from .models import ConfigSnapshot, Credential, Device, DiscoveryRun, Interface, Route, Site, Vlan


def device_list(request):
    qs = Device.objects.select_related("site", "collector").annotate(
        n_alerts=Count("alerts", filter=Q(alerts__status="open"), distinct=True))
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(hostname__icontains=q) | Q(mgmt_ip__icontains=q) | Q(model__icontains=q) | Q(serial__icontains=q)
                       | Q(os_version__icontains=q) | Q(tags__icontains=q))
    for f in ("site", "status", "platform", "role"):
        if request.GET.get(f):
            qs = qs.filter(**{f"{f}_id" if f == "site" else f: request.GET[f]})
    sort = request.GET.get("sort", "hostname")
    if sort.lstrip("-") in ("hostname", "mgmt_ip", "model", "os_version", "status", "security_score", "health_score", "compliance_score", "last_collected", "cpu"):
        qs = qs.order_by(F(sort.lstrip("-")).desc(nulls_last=True) if sort.startswith("-") else F(sort).asc(nulls_last=True))
    from apps.core.export import csv_response, wants_csv
    if wants_csv(request):
        return csv_response("devices", ["hostname", "mgmt_ip", "vendor", "platform", "model", "serial", "software", "role", "site", "status",
                                        "security", "compliance", "health", "cpu", "memory", "last_collected", "tags"],
                            ([d.hostname, d.mgmt_ip, d.vendor, d.platform, d.model, d.serial, d.os_version, d.role, d.site.name if d.site else "",
                              d.status, d.security_score, d.compliance_score, d.health_score, d.cpu, d.mem_pct,
                              d.last_collected.isoformat() if d.last_collected else "", d.tags] for d in qs))
    page = Paginator(qs, 100).get_page(request.GET.get("page"))
    return render(request, "inventory/list.html", {
        "page": page, "q": q, "sites": Site.objects.all(), "sort": sort, "statuses": Device.STATUS, "roles": Device.ROLES,
        "platforms": sorted({(d.platform, get_driver(d.platform).label) for d in Device.objects.only("platform")}),
        "total": Device.objects.count()})


@role_required("operator")
@require_POST
def bulk(request):
    ids = request.POST.getlist("ids")
    devs = Device.objects.filter(pk__in=ids)
    act = request.POST.get("action")
    if act == "collect":
        n = sum(1 for d in devs if services.enqueue_collect(d, request.user) or d.demo)
        messages.success(request, f"Collection queued for {n} device(s).")
    elif act == "test":
        for d in devs:
            services.enqueue_test(d, request.user)
        messages.success(request, f"Connection tests queued for {devs.count()} device(s).")
    elif act == "delete" and has_role(request.user, "admin"):
        n = devs.count()
        AuditLog.log(request, "device.bulk_delete", detail=", ".join(devs.values_list("hostname", flat=True))[:2000])
        devs.delete()
        messages.success(request, f"{n} device(s) deleted.")
    elif act == "site":
        devs.update(site=Site.objects.filter(pk=request.POST.get("site") or 0).first())
        messages.success(request, "Site updated.")
    elif act == "role":
        devs.update(role=request.POST.get("role", "unknown"))
        messages.success(request, "Role updated.")
    return redirect(request.META.get("HTTP_REFERER") or "inventory:list")


@role_required("operator")
def device_add(request):
    form = DeviceForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        try:
            d = form.save()
        except IntegrityError:
            form.add_error("mgmt_ip", "A device with this address already exists.")
        else:
            AuditLog.log(request, "device.add", d.hostname)
            if request.POST.get("collect_now"):
                services.enqueue_collect(d, request.user)
            messages.success(request, f"{d.hostname} added." + (" Collection queued." if request.POST.get("collect_now") else ""))
            return redirect("inventory:detail", d.pk)
    return render(request, "inventory/form.html", {"form": form, "title": "Add a device", "collect_option": True})


@role_required("operator")
def device_edit(request, pk):
    d = get_object_or_404(Device, pk=pk)
    form = DeviceForm(request.POST or None, instance=d)
    if request.method == "POST" and form.is_valid():
        form.save()
        AuditLog.log(request, "device.edit", d.hostname)
        messages.success(request, "Saved.")
        return redirect("inventory:detail", d.pk)
    return render(request, "inventory/form.html", {"form": form, "title": f"Edit {d.hostname}", "device": d})


@role_required("operator")
def bulk_add(request):
    form = BulkAddForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        cd = form.cleaned_data
        added, skipped = 0, []
        for line in cd["lines"].splitlines():
            parts = [p.strip() for p in line.split(",")]
            if not parts or not parts[0]:
                continue
            host = parts[0]
            name = parts[1] if len(parts) > 1 and parts[1] else host
            if Device.objects.filter(mgmt_ip=host).exists():
                skipped.append(host)
                continue
            d = Device.objects.create(hostname=name[:120], mgmt_ip=host, platform=cd["platform"], role=cd["role"], site=cd["site"],
                                      ssh_credential=cd["ssh_credential"], snmp_credential=cd["snmp_credential"], collector=cd["collector"])
            if cd["collect_now"]:
                services.enqueue_collect(d, request.user)
            added += 1
        AuditLog.log(request, "device.bulk_add", detail=f"{added} added")
        messages.success(request, f"{added} device(s) added." + (f" Already present: {', '.join(skipped[:10])}." if skipped else ""))
        return redirect("inventory:list")
    return render(request, "inventory/form.html", {"form": form, "title": "Add many devices", "help_ref": "devices#bulk"})


def device_detail(request, pk):
    d = get_object_or_404(Device.objects.select_related("site", "ssh_credential", "snmp_credential", "collector"), pk=pk)
    tab = request.GET.get("tab", "overview")
    ctx = {"d": d, "tab": d and tab, "drv": d.driver}
    ifs = d.interfaces.all()
    ctx["counts"] = {
        "interfaces": ifs.count(), "neighbors": d.neighbors.count(), "routes": d.routes.count(), "vlans": d.vlans.count(),
        "configs": d.configs.count(), "findings": d.findings.filter(status="open").count(),
        "psirt": d.advisories.filter(status="open").count(), "jobs": d.jobs.count(), "endpoints": d.endpoints.count(), "stp": d.stp.count(),
    }
    if tab == "overview":
        ctx["sev_counts"] = {s: d.findings.filter(status="open", severity=s).count() for s in ("critical", "high", "medium", "low")}
        ctx["top_findings"] = sorted(d.findings.filter(status="open"), key=lambda f: -f.rank)[:6]
        ctx["port_summary"] = {
            "up": ifs.filter(oper_up=True).count(), "down": ifs.filter(oper_up=False, admin_up=True).count(),
            "disabled": ifs.filter(admin_up=False).count(), "trunk": ifs.filter(mode="trunk").count(),
            "access": ifs.filter(mode="access").count(), "routed": ifs.filter(mode="routed").count(),
            "errdis": ifs.filter(status="err-disabled").count()}
        ctx["alerts"] = d.alerts.exclude(status="resolved")[:8]
        ctx["modules"] = (d.facts or {}).get("modules", [])[:30]
        ctx["optics"] = d.optics.all()
        samples = list(d.samples.order_by("-ts")[:120])[::-1]
        ctx["cpu_series"] = [x.cpu for x in samples]
        ctx["mem_series"] = [x.mem for x in samples]
        ctx["poe"] = (d.facts or {}).get("poe")
        ctx["windows"] = __import__("apps.alerts.models", fromlist=["windows_for"]).windows_for(d)
        ctx["changes"] = d.change_targets.select_related("change").order_by("-change__created_at")[:5]
        ctx["upgrade_images"] = [i for i in __import__("apps.upgrades.models", fromlist=["SoftwareImage"]).SoftwareImage.objects.all() if i.fits(d)][:5]
    elif tab == "interfaces":
        ctx["interfaces"] = sorted(ifs, key=lambda i: (not i.is_physical, i.name))
        ctx["if_issues"] = {f.key.lower(): f for f in d.findings.filter(category="interface", status="open")}
        ctx["nbr_map"] = {n.local_interface.lower(): n for n in d.neighbors.all()}
    elif tab == "neighbors":
        ctx["neighbors"] = d.neighbors.select_related("remote_device")
    elif tab == "routes":
        ctx["routes"] = d.routes.all()
        ctx["ospf"] = (d.facts or {}).get("ospf", [])
    elif tab == "vlans":
        ctx["vlans"] = d.vlans.all()
    elif tab == "config":
        ctx["configs"] = d.configs.all()[:50]
        ctx["latest"] = d.latest_config
    elif tab == "findings":
        ctx["findings"] = sorted(d.findings.exclude(status="resolved"), key=lambda f: (-f.rank, f.category))
        ctx["resolved"] = d.findings.filter(status="resolved")[:30]
    elif tab == "posture":
        from apps.checks.posture import device_view
        ctx.update(device_view(d))
        ctx["show"] = request.GET.get("show", "")
        ctx["fwsel"] = request.GET.get("fw", "")
    elif tab == "standards":
        ctx["results"] = ComplianceResult.objects.filter(device=d).select_related("standard")
    elif tab == "psirt":
        ctx["advisories"] = d.advisories.select_related("advisory").order_by("status", "-advisory__cvss")
    elif tab == "jobs":
        ctx["jobs"] = d.jobs.all()[:50]
    elif tab == "endpoints":
        from .models import Endpoint
        ctx["endpoints"] = Endpoint.objects.filter(device=d).order_by("interface")
        ctx["macs"] = d.macs.order_by("interface", "vlan")[:2000]
    elif tab == "stp":
        ctx["stp"] = d.stp.all()
    elif tab == "commands":
        ctx["cmd_jobs"] = d.jobs.filter(kind="command").exclude(ref="poll")[:10]
    return render(request, "inventory/detail.html", ctx)


@role_required("operator")
@require_POST
def device_action(request, pk):
    d = get_object_or_404(Device, pk=pk)
    act = request.POST.get("action")
    try:
        if act == "collect":
            j = services.enqueue_collect(d, request.user)
            messages.success(request, "Demo device refreshed." if d.demo else ("Collection queued." if j else "A collection is already queued or the device has no credential."))
        elif act == "poll":
            j = services.enqueue_poll(d, request.user)
            messages.success(request, "Poll queued." if j else "Nothing to poll (needs SNMP, or SSH on a supported platform), or a poll is already queued.")
        elif act == "test":
            j = services.enqueue_test(d, request.user)
            return redirect("jobs:detail", j.pk)
        elif act == "commands":
            j = services.enqueue_commands(d, request.POST.get("commands", "").splitlines(), request.user)
            return redirect("jobs:detail", j.pk)
        elif act == "delete" and has_role(request.user, "admin"):
            AuditLog.log(request, "device.delete", d.hostname)
            d.delete()
            messages.success(request, "Device deleted.")
            return redirect("inventory:list")
    except ValueError as exc:
        messages.error(request, str(exc))
    return redirect(request.META.get("HTTP_REFERER") or "inventory:detail", pk)


def config_view(request, pk, snap):
    d = get_object_or_404(Device, pk=pk)
    s = get_object_or_404(ConfigSnapshot, pk=snap, device=d)
    other = None
    if request.GET.get("vs"):
        other = ConfigSnapshot.objects.filter(pk=request.GET["vs"], device=d).first()
    else:
        other = d.configs.filter(collected_at__lt=s.collected_at).first()
    diff = None
    if other and request.GET.get("full") != "1":
        diff = list(difflib.unified_diff(other.text.splitlines(), s.text.splitlines(), lineterm="", n=3,
                                         fromfile=f"{other.collected_at:%Y-%m-%d %H:%M}", tofile=f"{s.collected_at:%Y-%m-%d %H:%M}"))
    return render(request, "inventory/config.html", {"d": d, "s": s, "other": other, "diff": diff, "versions": d.configs.all()[:50]})


def interface_detail(request, pk, ipk):
    i = get_object_or_404(Interface.objects.select_related("device"), pk=ipk, device_id=pk)
    samples = list(i.samples.order_by("-ts")[:600])[::-1]
    pts = [{"t": s.ts.isoformat(), "i": s.in_bps, "o": s.out_bps, "e": s.errors} for s in samples]
    nbr = i.device.neighbors.filter(local_interface__iexact=i.short).first()
    from .models import Endpoint, Transceiver
    extra = {"endpoints": Endpoint.objects.filter(device=i.device, interface__iexact=i.short),
             "optic": Transceiver.objects.filter(device=i.device, interface__iexact=i.short).first(),
             "flaps": len([t for t in (i.flap_log or []) if t > (timezone.now() - timedelta(hours=24)).isoformat()]),
             "can_change": i.device.driver.changes_supported(), "vlan_choices": i.device.vlans.all(),
             "recent_changes": i.device.change_targets.filter(change__kind="port", config__icontains=f"interface {i.name}\n").select_related("change")[:5]}
    return render(request, "inventory/interface.html", {**extra, "i": i, "d": i.device, "samples_json": json.dumps(pts), "nbr": nbr,
                                                        "findings": i.device.findings.filter(key__iexact=i.short).exclude(status="resolved")})


def interfaces(request):
    qs = Interface.objects.select_related("device").filter(device__enabled=True)
    f = request.GET.get("f", "issues")
    if f == "issues":
        keys = {(dev, key.lower()) for dev, key in Finding.objects.filter(category="interface", status="open").values_list("device_id", "key")}
        ids = [i.pk for i in qs.filter(device_id__in={k[0] for k in keys}).only("id", "device_id", "short") if (i.device_id, i.short.lower()) in keys]
        qs = qs.filter(pk__in=ids)
    elif f == "half":
        qs = qs.filter(duplex__icontains="half", oper_up=True)
    elif f == "errors":
        qs = qs.filter(Q(crc__gt=0) | Q(in_errors__gt=0) | Q(out_errors__gt=0)).order_by("-crc")
    elif f == "errdis":
        qs = qs.filter(status="err-disabled")
    elif f == "util":
        qs = [i for i in qs.filter(oper_up=True).exclude(speed_mbps=None) if (i.utilization or 0) >= 50]
    elif f == "trunks":
        qs = qs.filter(mode="trunk")
    elif f == "top":
        qs = qs.filter(oper_up=True).order_by(-(F("in_rate_bps") + F("out_rate_bps")))[:100]
    elif f == "all":
        pass
    q = request.GET.get("q", "").strip()
    if q and not isinstance(qs, list):
        qs = qs.filter(Q(device__hostname__icontains=q) | Q(name__icontains=q) | Q(description__icontains=q))
    if isinstance(qs, list):
        qs.sort(key=lambda i: -(i.utilization or 0))
    issues = {}
    for fi in Finding.objects.filter(category="interface", status="open"):
        issues.setdefault((fi.device_id, fi.key.lower()), []).append(fi)
    from apps.core.export import csv_response, wants_csv
    if wants_csv(request):
        rows = qs if isinstance(qs, list) else qs.order_by("device__hostname", "name")
        return csv_response("interfaces", ["device", "interface", "description", "status", "mode", "access_vlan", "native_vlan", "trunk_vlans",
                                           "speed_mbps", "duplex", "in_bps", "out_bps", "utilisation_pct", "crc", "in_errors", "out_errors",
                                           "issues"],
                            ([i.device.hostname, i.name, i.description, i.status, i.mode, i.access_vlan, i.native_vlan, i.trunk_vlans,
                              i.speed_mbps, i.duplex, i.in_rate_bps, i.out_rate_bps, i.utilization, i.crc, i.in_errors, i.out_errors,
                              "; ".join(f.title for f in issues.get((i.device_id, i.short.lower()), []))] for i in rows))
    page = Paginator(qs if isinstance(qs, list) else qs.order_by("device__hostname", "name") if f not in ("errors", "top") else qs, 200).get_page(request.GET.get("page"))
    for i in page:
        i.issues = issues.get((i.device_id, i.short.lower()), [])
    stats = {
        "half": Interface.objects.filter(duplex__icontains="half", oper_up=True).count(),
        "errdis": Interface.objects.filter(status="err-disabled").count(),
        "crc": Interface.objects.filter(crc__gt=0).count(),
        "issues": Finding.objects.filter(category="interface", status="open").count(),
        "mismatch": Finding.objects.filter(check_id__in=("IF-SPEEDMM", "IF-DUPLEXMM", "IF-MODEMM", "IF-NATIVEMM"), status="open").count(),
    }
    return render(request, "inventory/interfaces.html", {"page": page, "f": f, "q": q, "stats": stats})


def routes(request):
    qs = Route.objects.select_related("device")
    lookup = request.GET.get("lookup", "").strip()
    dev = request.GET.get("device")
    proto = request.GET.get("proto", "")
    matches = None
    if dev:
        qs = qs.filter(device_id=dev)
    if proto:
        qs = qs.filter(protocol__startswith=proto)
    if lookup:
        try:
            addr = ipaddress.ip_address(lookup.split("/")[0])
        except ValueError:
            messages.error(request, "Enter an IP address to look up, e.g. 10.20.30.40.")
        else:
            best = {}
            for r in qs:
                n = r.network
                if n and addr.version == n.version and addr in n:
                    cur = best.get((r.device_id, r.vrf))
                    if not cur or n.prefixlen > cur[0].network.prefixlen:
                        best[(r.device_id, r.vrf)] = [r]
                    elif n.prefixlen == cur[0].network.prefixlen:
                        cur.append(r)
            matches = [r for rs in best.values() for r in rs]
    from apps.core.export import csv_response, wants_csv
    if wants_csv(request):
        return csv_response("routes", ["device", "vrf", "protocol", "prefix", "next_hop", "interface", "distance", "metric"],
                            ([r.device.hostname, r.vrf, r.protocol, r.prefix, r.next_hop, r.interface, r.distance, r.metric]
                             for r in (matches if matches is not None else qs.order_by("device__hostname", "vrf", "prefix"))))
    page = Paginator(qs.order_by("device__hostname", "vrf", "prefix"), 300).get_page(request.GET.get("page"))
    protos = Route.objects.values("protocol").annotate(n=Count("id")).order_by("-n")[:15]
    return render(request, "inventory/routes.html", {"page": page, "lookup": lookup, "matches": matches, "devices": Device.objects.all(),
                                                     "dev": dev, "proto": proto, "protos": protos})


def discovery(request):
    form = DiscoveryForm(request.POST or None, initial={"name": "Discovery", "max_depth": 3})
    if request.method == "POST":
        if not has_role(request.user, "operator"):
            messages.error(request, "You need the operator role.")
        elif form.is_valid():
            run = form.save(commit=False)
            run.created_by = request.user.username
            run.save()
            started = 0
            for seed in [s.strip() for s in run.seeds.splitlines() if s.strip()]:
                d, created = Device.objects.get_or_create(mgmt_ip=seed, defaults={
                    "hostname": seed, "platform": "cisco_ios" if run.platform == "auto" else run.platform, "site": run.site,
                    "ssh_credential": run.ssh_credential, "snmp_credential": run.snmp_credential, "collector": run.collector,
                    "discovery": run, "discovery_depth": 0})
                if not created:
                    d.discovery, d.discovery_depth = run, 0
                    d.save(update_fields=["discovery", "discovery_depth"])
                services.enqueue_collect(d, request.user)
                started += 1
            run.note(f"started with {started} seed(s), depth {run.max_depth}")
            return redirect("inventory:discovery_detail", run.pk)
    return render(request, "inventory/discovery.html", {"form": form, "runs": DiscoveryRun.objects.annotate(n=Count("devices"))[:30]})


def discovery_detail(request, pk):
    run = get_object_or_404(DiscoveryRun, pk=pk)
    if request.method == "POST" and has_role(request.user, "operator"):
        run.status = "cancelled"
        run.save(update_fields=["status"])
        run.note("cancelled by " + request.user.username)
    devs = run.devices.all()
    return render(request, "inventory/discovery_detail.html", {"run": run, "devices": devs,
                                                               "jobs": Job.objects.filter(device__discovery=run)[:100]})


def setup(request):
    site_form = SiteForm(prefix="s")
    cred_form = CredentialForm(prefix="c")
    edit_cred = None
    if request.GET.get("cred"):
        edit_cred = Credential.objects.filter(pk=request.GET["cred"]).first()
        cred_form = CredentialForm(prefix="c", instance=edit_cred)
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators can change sites and credentials.")
            return redirect("inventory:setup")
        what = request.POST.get("what")
        if what == "site":
            site_form = SiteForm(request.POST, prefix="s")
            if site_form.is_valid():
                site_form.save()
                messages.success(request, "Site added.")
                return redirect("inventory:setup")
        elif what == "cred":
            inst = Credential.objects.filter(pk=request.POST.get("id") or 0).first()
            cred_form = CredentialForm(request.POST, prefix="c", instance=inst)
            if cred_form.is_valid():
                c = cred_form.save()
                AuditLog.log(request, "credential.save", c.name)
                messages.success(request, f"Credential {c.name} saved.")
                return redirect("inventory:setup")
        elif what == "del_site":
            Site.objects.filter(pk=request.POST.get("id")).delete()
            return redirect("inventory:setup")
        elif what == "del_cred":
            Credential.objects.filter(pk=request.POST.get("id")).delete()
            return redirect("inventory:setup")
    return render(request, "inventory/setup.html", {
        "sites": Site.objects.annotate(n=Count("devices")), "creds": Credential.objects.all(), "site_form": site_form,
        "cred_form": cred_form, "edit_cred": edit_cred})


def platforms(request):
    ds = sorted(drivers().values(), key=lambda d: ({"supported": 0, "beta": 1, "snmp": 2, "planned": 3}[d.status], d.vendor, d.label))
    counts = dict(Device.objects.values_list("platform").annotate(n=Count("id")))
    rows = [{"d": d, "levels": [LEVELS[d.feature_level(k)] + (d.feature_level(k),) for k, _l, _x in FEATURES], "n": counts.get(d.key, 0)} for d in ds]
    return render(request, "inventory/platforms.html", {"rows": rows, "features": FEATURES, "levels": LEVELS})


def platform(request, key):
    d = drivers().get(key)
    if not d:
        raise Http404
    feats = [{"key": k, "label": l, "desc": x, "level": d.feature_level(k), "lv": LEVELS[d.feature_level(k)]} for k, l, x in FEATURES]
    return render(request, "inventory/platform.html", {"d": d, "feats": feats, "devices": Device.objects.filter(platform=key)[:50],
                                                       "commands": d.collect_commands()})


# ------------------------------------------------------------------ endpoints, spanning tree, VLANs
def endpoints(request):
    from .models import ArpEntry, Endpoint, EndpointEvent
    q = request.GET.get("q", "").strip()
    qs = Endpoint.objects.select_related("device")
    hits = None
    if q:
        hexq = re.sub(r"[^0-9a-fA-F]", "", q).lower()
        cond = Q(ip__startswith=q) | Q(name__icontains=q) | Q(interface__iexact=q) | Q(device__hostname__icontains=q)
        if len(hexq) >= 4 and re.fullmatch(r"[0-9a-fA-F:.\-]+", q):
            cond |= Q(mac__contains=hexq)
        qs = qs.filter(cond)
        hits = list(qs[:200])
        if not hits and re.match(r"^\d+\.\d+\.\d+\.\d+$", q):      # known only from ARP (e.g. behind a router)
            arp = ArpEntry.objects.filter(ip=q).select_related("device").first()
            if arp:
                hits = list(Endpoint.objects.filter(mac=arp.mac))
                if not hits:
                    messages.info(request, f"{q} is {arp.mac} in the ARP table of {arp.device.hostname}, but that MAC is not on any access port VMap manages.")
    kind = request.GET.get("kind")
    if kind:
        qs = qs.filter(kind=kind)
    from apps.core.export import csv_response, wants_csv
    if wants_csv(request):
        return csv_response("endpoints", ["mac", "ip", "name", "kind", "switch", "port", "vlan", "first_seen", "last_seen", "moves"],
                            ([e.mac, e.ip, e.name, e.kind, e.device.hostname if e.device else "", e.interface, e.vlan, e.first_seen.isoformat(),
                              e.last_seen.isoformat(), e.moves] for e in qs))
    page = Paginator(qs, 100).get_page(request.GET.get("page"))
    events = EndpointEvent.objects.select_related("endpoint", "endpoint__device")[:15]
    stats = {"total": Endpoint.objects.count(), "moved": Endpoint.objects.filter(moves__gt=0).count(),
             "today": Endpoint.objects.filter(first_seen__gte=timezone.now() - timedelta(days=1)).count(),
             "phones": Endpoint.objects.filter(kind="phone").count(), "aps": Endpoint.objects.filter(kind="ap").count()}
    return render(request, "inventory/endpoints.html", {"page": page, "q": q, "hits": hits, "events": events, "stats": stats, "kind": kind})


def endpoint(request, pk):
    from .models import Endpoint, MacEntry
    ep = get_object_or_404(Endpoint.objects.select_related("device"), pk=pk)
    seen = MacEntry.objects.filter(mac=ep.mac).select_related("device").order_by("device__hostname")
    return render(request, "inventory/endpoint.html", {"ep": ep, "seen": seen, "events": ep.events.all()[:100]})


def stp(request):
    from .models import StpVlan
    rows = {}
    devs_by_mac = {}
    for s in StpVlan.objects.select_related("device"):
        if s.bridge_mac:
            devs_by_mac[s.bridge_mac] = s.device
    for s in StpVlan.objects.select_related("device").order_by("vlan", "device__hostname"):
        r = rows.setdefault(s.vlan, {"vlan": s.vlan, "roots": {}, "devices": [], "blocked": 0, "tc_max": 0, "tc_dev": None})
        r["roots"].setdefault(s.root_mac, s.root_prio)
        r["devices"].append(s)
        r["blocked"] += len(s.blocked)
        if (s.tc_count or 0) > r["tc_max"]:
            r["tc_max"], r["tc_dev"] = s.tc_count, s
    for r in rows.values():
        r["root_list"] = [{"mac": m, "prio": p, "device": devs_by_mac.get(m)} for m, p in r["roots"].items()]
    vlan = request.GET.get("vlan")
    detail = rows.get(int(vlan)) if vlan and vlan.isdigit() else None
    findings = Finding.objects.filter(category="stp", status="open").select_related("device")
    return render(request, "inventory/stp.html", {"rows": sorted(rows.values(), key=lambda r: r["vlan"]), "detail": detail,
                                                  "findings": findings})


def vlans(request):
    from apps.checks.engine import expand_vlans
    data = {}
    for v in Vlan.objects.select_related("device"):
        r = data.setdefault(v.vid, {"vid": v.vid, "names": {}, "devices": set(), "access": 0, "trunks": 0})
        r["names"][v.name] = r["names"].get(v.name, 0) + 1
        r["devices"].add(v.device.hostname)
    for i in Interface.objects.filter(mode="access").exclude(access_vlan=""):
        if i.access_vlan.isdigit() and int(i.access_vlan) in data:
            data[int(i.access_vlan)]["access"] += 1
        elif i.access_vlan.isdigit():
            data.setdefault(int(i.access_vlan), {"vid": int(i.access_vlan), "names": {}, "devices": set(), "access": 0, "trunks": 0})["access"] += 1
    trunk_sets = [(i, expand_vlans(i.trunk_vlans)) for i in Interface.objects.filter(mode="trunk", oper_up=True)]
    for vid, r in data.items():
        r["trunks"] = sum(1 for _i, s in trunk_sets if vid in s)
        r["n_devices"] = len(r["devices"])
        r["name_list"] = sorted(r["names"].items(), key=lambda kv: -kv[1])
    findings = Finding.objects.filter(category="vlan", status="open").select_related("device")
    return render(request, "inventory/vlans.html", {"rows": sorted(data.values(), key=lambda r: r["vid"]), "findings": findings})
