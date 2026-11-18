"""Path trace between two IP addresses using what VMap has collected: endpoint locations (MAC/ARP), the layer 2
neighbour graph (only links that carry the VLAN and are not blocked by spanning tree), and the routing tables."""
import ipaddress
from collections import deque

from apps.checks.engine import expand_vlans
from apps.inventory.models import ArpEntry, Device, Endpoint, Interface, Neighbor, Route, StpVlan


def _ip(s):
    try:
        return ipaddress.ip_address(s.strip())
    except (ValueError, AttributeError):
        return None


def owner_of(ip):
    """(device, interface) that owns this IP address, if any."""
    for i in Interface.objects.exclude(ip="").select_related("device"):
        if i.ip.split("/")[0] == str(ip):
            return i.device, i
    d = Device.objects.filter(mgmt_ip=str(ip)).first()
    return (d, None) if d else (None, None)


def gateways_for(ip):
    out = []
    for i in Interface.objects.exclude(ip="").filter(oper_up=True).select_related("device"):
        try:
            net = ipaddress.ip_interface(i.ip).network
        except ValueError:
            continue
        if ip in net and net.prefixlen < 32:
            out.append((i.device, i, net))
    out.sort(key=lambda x: (x[0].role != "core", x[0].hostname))
    return out


def locate(ip):
    dev, iface = owner_of(ip)
    if dev:
        return {"kind": "device", "device": dev, "interface": iface.short if iface else "", "vlan": _vlan_of_iface(iface)}
    ep = Endpoint.objects.filter(ip=str(ip)).select_related("device").first()
    if not ep:
        a = ArpEntry.objects.filter(ip=str(ip)).first()
        if a:
            ep = Endpoint.objects.filter(mac=a.mac).select_related("device").first()
    if ep and ep.device:
        return {"kind": "endpoint", "device": ep.device, "interface": ep.interface, "vlan": ep.vlan, "endpoint": ep}
    return None


def _vlan_of_iface(i):
    if i and i.name.lower().startswith("vlan"):
        try:
            return int(i.name[4:])
        except ValueError:
            return None
    return None


def _carries(i, vlan):
    if not i or not i.oper_up:
        return False
    if vlan is None:
        return True
    if i.mode == "trunk":
        return vlan in expand_vlans(i.trunk_vlans)
    if i.mode == "access":
        return str(i.access_vlan) == str(vlan)
    return False


def l2_path(src, dst, vlan):
    """Shortest forwarding path between two switches inside one VLAN. Returns [(device, in_port, out_port)] or None."""
    if src.pk == dst.pk:
        return [(src, "", "")]
    blocked = set()
    if vlan is not None:
        for s in StpVlan.objects.filter(vlan=vlan):
            for p in s.ports:
                if p.get("state", "").upper().startswith("BLK"):
                    blocked.add((s.device_id, p["interface"].lower()))
    ifs = {(i.device_id, i.short.lower()): i for i in Interface.objects.all()}
    adj = {}
    for n in Neighbor.objects.exclude(remote_device=None):
        a = ifs.get((n.device_id, n.local_interface.lower()))
        b = ifs.get((n.remote_device_id, n.remote_port.lower()))
        if not (_carries(a, vlan) and _carries(b, vlan)):
            continue
        if (n.device_id, n.local_interface.lower()) in blocked or (n.remote_device_id, n.remote_port.lower()) in blocked:
            continue
        adj.setdefault(n.device_id, []).append((n.remote_device_id, n.local_interface, n.remote_port))
    prev = {src.pk: None}
    q = deque([src.pk])
    while q:
        cur = q.popleft()
        if cur == dst.pk:
            break
        for nb, lp, rp in sorted(adj.get(cur, []), key=lambda x: x[1]):
            if nb not in prev:
                prev[nb] = (cur, lp, rp)
                q.append(nb)
    if dst.pk not in prev:
        return None
    chain, cur = [], dst.pk
    while prev[cur]:
        p, lp, rp = prev[cur]
        chain.append((p, lp, cur, rp))
        cur = p
    chain.reverse()
    devs = {d.pk: d for d in Device.objects.filter(pk__in=[c[0] for c in chain] + [dst.pk])}
    hops, last_in = [], ""
    for p, lp, nxt, rp in chain:
        hops.append((devs[p], last_in, lp))
        last_in = rp
    hops.append((devs[dst.pk], last_in, ""))
    return hops


def lookup(device, ip):
    best = []
    for r in Route.objects.filter(device=device):
        n = r.network
        if n and ip.version == n.version and ip in n:
            if not best or n.prefixlen > best[0].network.prefixlen:
                best = [r]
            elif n.prefixlen == best[0].network.prefixlen:
                best.append(r)
    return best


def trace(src_s, dst_s):
    src_ip, dst_ip = _ip(src_s), _ip(dst_s)
    res = {"hops": [], "warnings": [], "notes": [], "ok": False, "src": None, "dst": None}
    if not src_ip or not dst_ip:
        res["warnings"].append("Enter two IP addresses.")
        return res
    s, d = locate(src_ip), locate(dst_ip)
    res["src"], res["dst"] = s, d
    if not s:
        res["warnings"].append(f"{src_ip} was not found: it is not a device address and no switch has it in its MAC/ARP tables.")
        return res

    def add(dev, layer, inp, out, note=""):
        res["hops"].append({"device": dev, "layer": layer, "in": inp, "out": out, "note": note})

    src_gws = gateways_for(src_ip)
    same = [g for g in src_gws if dst_ip in g[2]]
    if same and d:                                                 # same subnet: pure layer 2
        vlan = s.get("vlan") or _vlan_of_iface(same[0][1])
        path = l2_path(s["device"], d["device"], vlan)
        if not path:
            res["warnings"].append(f"No forwarding layer 2 path in VLAN {vlan} between {s['device'].hostname} and {d['device'].hostname}.")
            return res
        for i, (dev, inp, out) in enumerate(path):
            add(dev, "L2", inp or (s["interface"] if i == 0 else ""), out or (d["interface"] if i == len(path) - 1 else ""), f"VLAN {vlan}")
        res["ok"] = True
        return res
    if s["kind"] == "device" and not s.get("vlan"):
        cur = s["device"]
    else:
        if not src_gws:
            res["warnings"].append(f"No managed router or layer 3 switch has an interface in the subnet of {src_ip}.")
            return res
        gw_dev, gw_if, net = src_gws[0]
        vlan = s.get("vlan") or _vlan_of_iface(gw_if)
        path = l2_path(s["device"], gw_dev, vlan)
        if path is None:
            res["warnings"].append(f"No forwarding layer 2 path in VLAN {vlan} from {s['device'].hostname} to the gateway {gw_dev.hostname}.")
            return res
        for i, (dev, inp, out) in enumerate(path[:-1]):
            add(dev, "L2", inp or (s["interface"] if i == 0 else ""), out, f"VLAN {vlan}")
        res["l2_into_gw"] = path[-1][1]
        if len(src_gws) > 1:
            res["notes"].append(f"{len(src_gws)} devices have an address in {net} (first-hop redundancy); the trace uses {gw_dev.hostname}.")
        cur = gw_dev
    seen, in_port = set(), res.pop("l2_into_gw", "")
    for _ in range(16):
        if cur.pk in seen:
            res["warnings"].append(f"Routing loop: {cur.hostname} appears twice.")
            break
        seen.add(cur.pk)
        own_dev, own_if = owner_of(dst_ip)
        if own_dev and own_dev.pk == cur.pk:
            add(cur, "L3", in_port, own_if.short if own_if else "", f"{dst_ip} is an address of this device")
            res["ok"] = True
            return res
        conn = [g for g in gateways_for(dst_ip) if g[0].pk == cur.pk]
        if conn:
            add(cur, "L3", in_port, conn[0][1].short, f"{dst_ip} is directly connected ({conn[0][2]})")
            if d and d["device"].pk != cur.pk:
                vlan = d.get("vlan") or _vlan_of_iface(conn[0][1])
                path = l2_path(cur, d["device"], vlan)
                if path is None:
                    res["warnings"].append(f"No forwarding layer 2 path in VLAN {vlan} from {cur.hostname} to {d['device'].hostname}.")
                    return res
                for i, (dev, inp, out) in enumerate(path[1:], start=1):
                    add(dev, "L2", inp, out or (d["interface"] if i == len(path) - 1 else ""), f"VLAN {vlan}")
            res["ok"] = True
            return res
        routes = lookup(cur, dst_ip)
        if not routes:
            add(cur, "L3", in_port, "", "no route")
            res["warnings"].append(f"{cur.hostname} has no route to {dst_ip} (not even a default route): traffic is dropped here.")
            return res
        r = routes[0]
        note = f"{r.prefix} via {r.next_hop or 'connected'} ({r.protocol_name})" + (f", +{len(routes) - 1} equal-cost" if len(routes) > 1 else "")
        nh = _ip(r.next_hop) if r.next_hop else None
        nxt, nif = owner_of(nh) if nh else (None, None)
        from apps.inventory.models import short_ifname
        add(cur, "L3", in_port, short_ifname(r.interface), note)
        if not nxt:
            res["notes"].append(f"Leaves the managed network at {cur.hostname} towards {r.next_hop or r.interface}.")
            res["ok"] = True
            return res
        cur, in_port = nxt, (nif.short if nif else "")
    res["warnings"].append("Stopped after 16 hops.")
    return res


def hop_issues(hops):
    """Open interface findings on the ports the path uses."""
    from apps.checks.models import Finding
    out = []
    for h in hops:
        for p in (h["in"], h["out"]):
            if not p:
                continue
            for f in Finding.objects.filter(device=h["device"], category="interface", status="open", key__iexact=p):
                out.append((h["device"], p, f))
    return out
