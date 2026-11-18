"""Build the layer 2 and layer 3 graphs as JSON for the topology view."""
import ipaddress
from collections import defaultdict

from apps.checks.models import Finding
from apps.inventory.models import Device, Interface, Neighbor

ROLE_TIER = {"router": 0, "core": 1, "datacenter": 2, "distribution": 2, "access": 3}


_EXTRA = {}


def _port(i):
    if not i:
        return None
    ex = _EXTRA.get((i.device_id, i.short.lower()), {})
    return {"stp_blocked": ex.get("blk", []), "rx": ex.get("rx"), "tx": ex.get("tx"), "optic": ex.get("pid", ""),
            "poe": f"{i.poe_watts or 0} W {i.poe_device}".strip() if i.poe_oper.lower() == "on" else (i.poe_oper if i.poe_oper else ""),
            "flaps": len(i.flap_log or []),"name": i.name, "short": i.short, "description": i.description, "status": i.status, "up": i.oper_up,
            "mode": i.mode, "access_vlan": i.access_vlan, "native_vlan": i.native_vlan, "voice_vlan": i.voice_vlan,
            "trunk_vlans": i.trunk_vlans[:200], "speed": i.speed, "speed_mbps": i.speed_mbps, "duplex": i.duplex,
            "media": i.media, "ip": i.ip, "port_channel": i.port_channel, "in_bps": i.in_rate_bps, "out_bps": i.out_rate_bps,
            "util": i.utilization, "crc": i.crc, "in_errors": i.in_errors, "out_errors": i.out_errors, "drops": i.out_drops,
            "late_collisions": i.late_collisions, "mtu": i.mtu}


def _node(d, alerts):
    return {"id": f"d{d.pk}", "type": "device", "label": d.hostname, "device_id": d.pk, "ip": d.mgmt_ip, "model": d.model,
            "version": d.os_version, "platform": d.platform, "vendor": d.vendor, "role": d.role, "site": d.site.name if d.site else "",
            "status": d.status, "security": d.security_score, "health": d.health_score, "compliance": d.compliance_score,
            "alerts": alerts.get(d.pk, 0), "tier": ROLE_TIER.get(d.role), "kind": "router" if d.role == "router" else "switch",
            "demo": d.demo}


def _devices(site):
    qs = Device.objects.select_related("site").filter(enabled=True)
    return qs.filter(site=site) if site else qs


def _alert_counts():
    from apps.alerts.models import Alert
    out = defaultdict(int)
    for dev in Alert.objects.filter(status="open").values_list("device_id", flat=True):
        out[dev] += 1
    return out


def l2(site=None, endpoints=False):
    devs = list(_devices(site))
    ids = {d.pk for d in devs}
    alerts = _alert_counts()
    nodes = {f"d{d.pk}": _node(d, alerts) for d in devs}
    ifs = {(i.device_id, i.short.lower()): i for i in Interface.objects.filter(device_id__in=ids)}
    load_extra(ids)
    bad_ports = defaultdict(list)
    for f in Finding.objects.filter(device_id__in=ids, category="interface", status="open").values("device_id", "key", "severity", "title"):
        bad_ports[(f["device_id"], f["key"].lower())].append({"severity": f["severity"], "title": f["title"]})
    links = {}
    for n in Neighbor.objects.filter(device_id__in=ids):
        a = f"d{n.device_id}"
        if n.remote_device_id and n.remote_device_id in ids:
            b = f"d{n.remote_device_id}"
        else:
            if n.remote_device_id:            # managed but filtered out by site: show as a stub
                kind = "switch"
            else:
                kind = n.kind
            if kind in ("phone", "ap", "host", "unknown") and not endpoints:
                continue
            b = f"x:{n.remote_name.split('.')[0].lower()}"
            nodes.setdefault(b, {"id": b, "type": "external", "label": n.remote_name.split(".")[0][:40], "ip": n.remote_ip,
                                 "model": n.remote_platform[:80], "kind": kind, "tier": 3 if kind in ("phone", "ap", "host") else None,
                                 "status": "unmanaged", "managed_elsewhere": bool(n.remote_device_id)})
        pa, pb = n.local_interface, n.remote_port
        key = tuple(sorted([(a, pa.lower()), (b, pb.lower())]))
        if key in links:
            links[key]["protocols"].add(n.protocol)
            continue
        ia = ifs.get((n.device_id, pa.lower()))
        ib = ifs.get((n.remote_device_id, pb.lower())) if n.remote_device_id else None
        mode = (ia.mode if ia and ia.mode not in ("unknown", "virtual") else None) or (ib.mode if ib and ib.mode not in ("unknown", "virtual") else None) or "unknown"
        issues = bad_ports.get((n.device_id, pa.lower()), []) + (bad_ports.get((n.remote_device_id, pb.lower()), []) if n.remote_device_id else [])
        up = (ia.oper_up if ia else True) and (ib.oper_up if ib else True)
        speed = (ia.speed_mbps if ia else None) or (ib.speed_mbps if ib else None)
        util = max([u for u in ((ia.utilization if ia else None), (ib.utilization if ib else None)) if u is not None] or [0])
        links[key] = {"source": a, "target": b, "source_port": pa, "target_port": pb, "mode": mode, "up": up, "speed": speed,
                      "util": util, "port_channel": (ia.port_channel if ia else "") or (ib.port_channel if ib else ""),
                      "issues": issues, "protocols": {n.protocol}, "a": _port(ia), "b": _port(ib),
                      "a_issues": bad_ports.get((n.device_id, pa.lower()), []),
                      "b_issues": bad_ports.get((n.remote_device_id, pb.lower()), []) if n.remote_device_id else []}
    out = []
    for lk in links.values():
        lk["protocols"] = sorted(lk["protocols"])
        out.append(lk)
    _infer_tiers(nodes, out)
    return {"nodes": list(nodes.values()), "links": out}


def _infer_tiers(nodes, links):
    """Devices without a role get a tier from their position: most-connected switches on top."""
    deg = defaultdict(int)
    adj = defaultdict(set)
    for l in links:
        if nodes.get(l["target"], {}).get("type") == "device":
            deg[l["source"]] += 1
            deg[l["target"]] += 1
            adj[l["source"]].add(l["target"])
            adj[l["target"]].add(l["source"])
    known = [n for n in nodes.values() if n.get("tier") is not None and n["type"] == "device"]
    top = min([n["tier"] for n in known] or [0])
    roots = [n["id"] for n in known if n["tier"] == top]
    if not roots:
        devs = [n for n in nodes.values() if n["type"] == "device"]
        if devs:
            top = max(deg[n["id"]] for n in devs)
            roots = [n["id"] for n in devs if deg[n["id"]] == top and top > 0] or [devs[0]["id"]]
    dist = {r: 0 for r in roots}
    queue = list(roots)
    while queue:
        cur = queue.pop(0)
        for nb in adj[cur]:
            if nb not in dist:
                dist[nb] = dist[cur] + 1
                queue.append(nb)
    for n in nodes.values():
        if n.get("tier") is None:
            if n["type"] == "device":
                n["tier"] = min(dist.get(n["id"], 2) + (top if known else 0), 4)
            else:
                parents = [l["source"] for l in links if l["target"] == n["id"]]
                n["tier"] = min(6, max([nodes[p].get("tier") or 0 for p in parents] or [2]) + 1)


def l3(site=None):
    devs = list(_devices(site).prefetch_related("interfaces"))
    alerts = _alert_counts()
    nodes, links = {}, []
    subnets = defaultdict(list)
    for d in devs:
        l3ifs = [i for i in d.interfaces.all() if i.ip and not i.name.lower().startswith(("loopback", "null", "mgmt"))]
        loops = [i.ip for i in d.interfaces.all() if i.ip and i.name.lower().startswith("loopback")]
        routes = d.routes.all()
        protos = defaultdict(int)
        for r in routes:
            protos[r.protocol_name] += 1
        dynamic = any(p not in ("Connected", "Local") for p in protos)
        routed_ports = [i for i in l3ifs if not i.name.lower().startswith("vlan")]
        if not dynamic and not routed_ports and len(l3ifs) <= 1:
            continue                      # a layer 2 switch with only a management address
        n = _node(d, alerts)
        if n["tier"] is None:
            n["tier"] = 2
        n.update({"loopbacks": loops, "route_counts": dict(protos), "routes": sum(protos.values()),
                  "default_via": next((r.next_hop for r in routes if r.prefix in ("0.0.0.0/0",)), "")})
        nodes[n["id"]] = n
        for i in l3ifs:
            try:
                net = ipaddress.ip_interface(i.ip).network
            except ValueError:
                continue
            if net.prefixlen == 32:
                continue
            subnets[str(net)].append((n["id"], i))
    ospf_addrs = set()
    for d in devs:
        for o in (d.facts or {}).get("ospf", []) or []:
            if o.get("address"):
                ospf_addrs.add(o["address"])
    for net, members in subnets.items():
        ips = {i.ip.split("/")[0] for _, i in members}
        dyn = bool(ips & ospf_addrs)
        if len(members) == 2 and ipaddress.ip_network(net).prefixlen >= 29:
            (a, ia), (b, ib) = members
            links.append({"source": a, "target": b, "source_port": ia.short, "target_port": ib.short, "mode": "routed",
                          "subnet": net, "up": ia.oper_up and ib.oper_up, "ospf": dyn, "a": _port(ia), "b": _port(ib),
                          "a_issues": [], "b_issues": [], "issues": []})
            continue
        sid = f"n:{net}"
        vlan = next((i.name[4:] for _, i in members if i.name.lower().startswith("vlan")), "")
        nodes[sid] = {"id": sid, "type": "subnet", "label": net, "kind": "subnet", "vlan": vlan,
                      "tier": max((nodes[m].get("tier") or 0) for m, _ in members) + 1,
                      "members": [{"device": nodes[m]["label"], "ip": i.ip, "port": i.short} for m, i in members], "status": "up"}
        for m, i in members:
            links.append({"source": m, "target": sid, "source_port": i.short, "target_port": "", "mode": "l3member",
                          "subnet": net, "up": i.oper_up, "ospf": dyn, "a": _port(i), "b": None, "a_issues": [], "b_issues": [], "issues": []})
    return {"nodes": list(nodes.values()), "links": links}


def load_extra(ids):
    from apps.inventory.models import StpVlan, Transceiver
    _EXTRA.clear()
    for s in StpVlan.objects.filter(device_id__in=ids):
        for p in s.ports:
            if p.get("state", "").upper().startswith("BLK"):
                _EXTRA.setdefault((s.device_id, p["interface"].lower()), {}).setdefault("blk", []).append(s.vlan)
    for o in Transceiver.objects.filter(device_id__in=ids):
        _EXTRA.setdefault((o.device_id, o.interface.lower()), {}).update(rx=o.rx, tx=o.tx, pid=o.pid)
