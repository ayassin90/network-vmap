"""Capture the network state into a snapshot, and compare two states."""
import hashlib
from datetime import timedelta

from django.utils import timezone

from apps.core.models import AppSetting


def capture_state():
    from apps.checks.models import Finding
    from apps.inventory.models import Device, Endpoint, Interface, Neighbor, Route
    devs = {}
    by_id = {}
    for d in Device.objects.filter(demo=False).select_related("site") or Device.objects.select_related("site"):
        cfg = d.latest_config
        by_id[d.pk] = d.hostname
        devs[d.hostname] = {"ip": d.mgmt_ip, "platform": d.platform, "vendor": d.vendor, "model": d.model, "serial": d.serial,
                            "version": d.os_version, "role": d.role, "site": d.site.name if d.site else "", "status": d.status,
                            "config": hashlib.sha1((cfg.text if cfg else "").encode()).hexdigest()[:12] if cfg else "",
                            "security": d.security_score, "compliance": d.compliance_score}
    ifs = {}
    for i in Interface.objects.filter(device_id__in=by_id).order_by("device_id", "name"):
        vlan = i.access_vlan if i.mode == "access" else (f"T:{i.native_vlan}/{i.trunk_vlans}" if i.mode == "trunk" else "")
        ifs.setdefault(by_id[i.device_id], {})[i.short] = [i.status, i.mode, vlan, i.speed_mbps or 0, i.duplex, i.description[:60]]
    links = sorted({tuple(sorted([(by_id[n.device_id], n.local_interface), (by_id.get(n.remote_device_id) or n.remote_name, n.remote_port)]))
                    for n in Neighbor.objects.filter(device_id__in=by_id).exclude(remote_device=None)})
    routes = {}
    for r in Route.objects.filter(device_id__in=by_id).exclude(protocol="L"):
        routes.setdefault(by_id[r.device_id], []).append(f"{r.vrf}|{r.prefix}|{r.protocol}|{r.next_hop or r.interface}")
    for k in routes:
        routes[k].sort()
    eps = {e.mac: [by_id.get(e.device_id, ""), e.interface, e.vlan, e.ip] for e in Endpoint.objects.filter(device_id__in=by_id)}
    finds = {}
    for f in Finding.objects.filter(device_id__in=by_id, status="open").values("device_id", "check_id", "key", "severity"):
        finds.setdefault(by_id[f["device_id"]], []).append(f"{f['severity']}|{f['check_id']}|{f['key']}")
    for k in finds:
        finds[k].sort()
    return {"devices": devs, "interfaces": ifs, "links": [list(map(list, l)) for l in links], "routes": routes, "endpoints": eps, "findings": finds}


def summarize(state):
    return {"devices": len(state["devices"]), "interfaces": sum(len(v) for v in state["interfaces"].values()),
            "up": sum(1 for v in state["interfaces"].values() for p in v.values() if p[0] == "connected"),
            "links": len(state["links"]), "routes": sum(len(v) for v in state["routes"].values()), "endpoints": len(state["endpoints"]),
            "findings": sum(len(v) for v in state["findings"].values())}


def take(label="", kind="auto", user=""):
    from .models import Snapshot
    st = capture_state()
    s = Snapshot(label=label, kind=kind, created_by=user, summary=summarize(st))
    s.data = st
    s.save()
    return s


def maybe_take():
    from .models import Snapshot
    hours = AppSetting.get_int("snapshot_interval_hours", 24)
    if hours <= 0:
        return None
    last = Snapshot.objects.filter(kind="auto").first()
    now = timezone.now()
    snap = None
    if not last or now - last.taken_at >= timedelta(hours=hours):
        snap = take(kind="auto")
    keep = AppSetting.get_int("snapshot_retention_days", 90)
    Snapshot.objects.filter(taken_at__lt=now - timedelta(days=keep)).delete()
    return snap


FIELDS = ["status", "mode", "VLAN", "speed", "duplex", "description"]


def diff(a, b):
    """What changed from state a (older) to state b (newer). Every list is ready to print."""
    out = {"devices_added": [], "devices_removed": [], "device_changes": [], "port_changes": [], "links_added": [], "links_removed": [],
           "routes": [], "endpoints_new": [], "endpoints_gone": [], "endpoints_moved": [], "findings_new": [], "findings_fixed": []}
    da, db = a["devices"], b["devices"]
    out["devices_added"] = sorted(set(db) - set(da))
    out["devices_removed"] = sorted(set(da) - set(db))
    labels = {"version": "software", "config": "configuration", "status": "status", "model": "model", "serial": "serial", "ip": "management IP",
              "role": "role", "site": "site", "security": "security score", "compliance": "compliance score"}
    for h in sorted(set(da) & set(db)):
        for k, label in labels.items():
            if da[h].get(k) != db[h].get(k):
                out["device_changes"].append({"device": h, "what": label, "before": da[h].get(k), "after": db[h].get(k)})
        pa, pb = a["interfaces"].get(h, {}), b["interfaces"].get(h, {})
        for p in sorted(set(pa) | set(pb)):
            x, y = pa.get(p), pb.get(p)
            if x == y:
                continue
            if not x or not y:
                out["port_changes"].append({"device": h, "port": p, "what": "port", "before": "absent" if not x else "present", "after": "absent" if not y else "present"})
                continue
            for i, f in enumerate(FIELDS):
                if x[i] != y[i]:
                    out["port_changes"].append({"device": h, "port": p, "what": f, "before": x[i], "after": y[i]})
        ra, rb = set(a["routes"].get(h, [])), set(b["routes"].get(h, []))
        for r in sorted(rb - ra):
            out["routes"].append({"device": h, "change": "added", "route": r.split("|")})
        for r in sorted(ra - rb):
            out["routes"].append({"device": h, "change": "removed", "route": r.split("|")})
        fa, fb = set(a["findings"].get(h, [])), set(b["findings"].get(h, []))
        out["findings_new"] += [{"device": h, "finding": f.split("|")} for f in sorted(fb - fa)]
        out["findings_fixed"] += [{"device": h, "finding": f.split("|")} for f in sorted(fa - fb)]
    la, lb = {tuple(map(tuple, l)) for l in a["links"]}, {tuple(map(tuple, l)) for l in b["links"]}
    out["links_added"] = [list(l) for l in sorted(lb - la)]
    out["links_removed"] = [list(l) for l in sorted(la - lb)]
    ea, eb = a["endpoints"], b["endpoints"]
    out["endpoints_new"] = [[m] + eb[m] for m in sorted(set(eb) - set(ea))]
    out["endpoints_gone"] = [[m] + ea[m] for m in sorted(set(ea) - set(eb))]
    out["endpoints_moved"] = [[m] + ea[m][:2] + eb[m][:2] for m in sorted(set(ea) & set(eb)) if ea[m][:2] != eb[m][:2]]
    out["total"] = sum(len(v) for v in out.values() if isinstance(v, list))
    return out
