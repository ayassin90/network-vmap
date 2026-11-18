"""Write normalised driver output into the database."""
import difflib
import hashlib
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from .models import (ArpEntry, ConfigSnapshot, Device, Endpoint, EndpointEvent, Interface, InterfaceSample, MacEntry, Neighbor, Route,
                     StpVlan, Transceiver, Vlan, short_ifname)

IF_FIELDS = [f.name for f in Interface._meta.get_fields()
             if getattr(f, "concrete", False) and f.name not in ("id", "device", "name", "short", "updated_at",
                                                                 "c_in_octets", "c_out_octets", "c_in_errors", "c_ts", "err_delta",
                                                                 "flap_log", "resets", "link_transitions", "poe_admin", "poe_oper",
                                                                 "poe_watts", "poe_device", "poe_class")]


@transaction.atomic
def apply(device, data):
    """Full collection result -> device. Returns a short summary string."""
    facts = data.get("facts") or {}
    for f in ("vendor", "model", "serial", "os_type", "os_version", "image", "reload_reason"):
        if facts.get(f):
            setattr(device, f, str(facts[f])[:200])
    if facts.get("uptime_seconds"):
        device.uptime_seconds = facts["uptime_seconds"]
    if facts.get("hostname") and (device.hostname in ("", device.mgmt_ip) or device.facts.get("hostname_from_device", True)):
        device.hostname = facts["hostname"][:120]
    keep = {k: v for k, v in facts.items() if k in ("modules", "stack_members", "install_mode", "sys_descr", "sys_object_id")}
    device.facts = {**device.facts, **keep, "ospf": (data.get("extra") or {}).get("ospf", device.facts.get("ospf", []))}
    # IOS and IOS-XE share a driver; switch to the right one once `show version` tells us.
    if device.platform == "cisco_ios" and facts.get("os_type") == "iosxe":
        device.platform = "cisco_iosxe"
    elif device.platform == "cisco_iosxe" and facts.get("os_type") == "ios":
        device.platform = "cisco_ios"

    if device.role == "unknown":
        device.role = infer_role(device, data)
    n_if = sync_interfaces(device, data.get("interfaces"), full=True) if data.get("interfaces") else 0
    if data.get("neighbors") is not None:
        Neighbor.objects.filter(device=device).delete()
        Neighbor.objects.bulk_create([Neighbor(device=device, **{k: (str(v)[:200] if k != "remote_description" else str(v))
                                                                 for k, v in n.items()}) for n in data["neighbors"] if n.get("remote_name")])
    if data.get("routes") is not None:
        Route.objects.filter(device=device).delete()
        Route.objects.bulk_create([Route(device=device, **r) for r in data["routes"]], batch_size=2000)
    if data.get("vlans"):
        Vlan.objects.filter(device=device).delete()
        seen = set()
        Vlan.objects.bulk_create([Vlan(device=device, **v) for v in data["vlans"] if v["vid"] and not (v["vid"] in seen or seen.add(v["vid"]))])
    apply_extras(device, data)
    changed = save_config(device, data.get("config")) if data.get("config") else None
    device.status = "up"
    device.last_error = ""
    device.last_collected = timezone.now()
    device.save()
    resolve_neighbors()
    parts = [f"{n_if} interfaces", f"{len(data.get('neighbors') or [])} neighbours", f"{len(data.get('routes') or [])} routes"]
    if changed:
        parts.append("config changed")
    return ", ".join(parts)


def sync_interfaces(device, rows, full=False):
    existing = {i.name: i for i in device.interfaces.all()}
    now = timezone.now()
    seen = set()
    for r in rows:
        name = r.get("name")
        if not name or name in seen:
            continue
        seen.add(name)
        obj = existing.get(name) or Interface(device=device, name=name)
        before = obj.in_errors + obj.crc + obj.out_errors if obj.pk else None
        was_up = obj.oper_up if obj.pk else None
        for k, v in r.items():
            if k in IF_FIELDS and v is not None:
                setattr(obj, k, v if not isinstance(v, str) else v[:240])
        obj.short = short_ifname(name)
        track_flaps(obj, was_up, r, now)
        after = obj.in_errors + obj.crc + obj.out_errors
        obj.err_delta = max(0, after - before) if before is not None and after >= before else 0
        obj.save()
        if obj.oper_up and obj.is_physical and (obj.in_rate_bps or obj.out_rate_bps or obj.err_delta):
            InterfaceSample.objects.create(interface=obj, ts=now, in_bps=obj.in_rate_bps, out_bps=obj.out_rate_bps, errors=obj.err_delta)
    if full:
        stale = [i.pk for n, i in existing.items() if n not in seen]
        Interface.objects.filter(pk__in=stale).delete()
    return len(seen)


def apply_snmp_poll(device, res):
    """Counter deltas -> rates, error deltas and samples."""
    w = res.get("walk", {})
    idx = lambda k: {a: b for a, b in w.get(k) or []}  # noqa: E731
    names, oper, admin = idx("ifName"), idx("ifOperStatus"), idx("ifAdminStatus")
    hin, hout, ine, oute, ind, outd, hs = (idx(k) for k in ("ifHCInOctets", "ifHCOutOctets", "ifInErrors", "ifOutErrors",
                                                            "ifInDiscards", "ifOutDiscards", "ifHighSpeed"))
    by_index = {str(i.if_index): i for i in device.interfaces.exclude(if_index=None)}
    by_short = {i.short.lower(): i for i in device.interfaces.all()}
    now = timezone.now()
    n = 0
    for ifi, name in names.items():
        obj = by_index.get(ifi) or by_short.get(short_ifname(name or "").lower())
        if not obj:
            continue
        obj.if_index = int(ifi)
        if ifi in oper:
            new_up = oper[ifi] == 1
            if obj.oper_up != new_up and obj.admin_up:
                obj.flap_log = [t for t in (obj.flap_log or []) if t > (now - timedelta(hours=24)).isoformat()] + [now.isoformat()]
            obj.oper_up = new_up
        if ifi in admin:
            obj.admin_up = admin[ifi] == 1
        if hs.get(ifi):
            obj.speed_mbps = hs[ifi]
        i_oct, o_oct, errs = hin.get(ifi), hout.get(ifi), (ine.get(ifi) or 0) + (oute.get(ifi) or 0)
        if obj.c_ts and i_oct is not None and obj.c_in_octets is not None:
            dt = max(1.0, (now - obj.c_ts).total_seconds())
            di = i_oct - obj.c_in_octets if i_oct >= obj.c_in_octets else 0
            do = o_oct - obj.c_out_octets if o_oct is not None and obj.c_out_octets is not None and o_oct >= obj.c_out_octets else 0
            obj.in_rate_bps, obj.out_rate_bps = int(di * 8 / dt), int(do * 8 / dt)
            obj.err_delta = max(0, errs - (obj.c_in_errors or 0)) if obj.c_in_errors is not None and errs >= obj.c_in_errors else 0
            if obj.is_physical and obj.oper_up:
                InterfaceSample.objects.create(interface=obj, ts=now, in_bps=obj.in_rate_bps, out_bps=obj.out_rate_bps, errors=obj.err_delta)
        obj.c_in_octets, obj.c_out_octets, obj.c_in_errors, obj.c_ts = i_oct, o_oct, errs, now
        obj.in_errors = ine.get(ifi, obj.in_errors) or 0
        obj.out_errors = oute.get(ifi, obj.out_errors) or 0
        obj.in_discards = ind.get(ifi, obj.in_discards) or 0
        obj.out_drops = outd.get(ifi, obj.out_drops) or 0
        obj.save()
        n += 1
    h = snmp_health(w)
    if h:
        apply_health(device, h, save=True)
    device.last_polled = now
    device.status = "up"
    device.save(update_fields=["last_polled", "status"])
    return f"{n} interfaces polled" + (f", CPU {device.cpu}%" if h.get("cpu") is not None else "")


ENV_STATE = {1: "OK", 2: "Warning", 3: "Critical", 4: "Shutdown", 5: "Not Present", 6: "Not Functioning"}


def snmp_health(w):
    """CISCO-PROCESS-MIB, CISCO-MEMORY-POOL-MIB, CISCO-ENVMON-MIB, or HOST-RESOURCES-MIB processor load."""
    h = {}
    cpu = [v for _k, v in w.get("cpu5min") or [] if isinstance(v, int)] or [v for _k, v in w.get("hrProcessorLoad") or [] if isinstance(v, int)]
    if cpu:
        h["cpu"] = round(sum(cpu) / len(cpu))
    used = {k: v for k, v in w.get("memUsed") or []}
    free = {k: v for k, v in w.get("memFree") or []}
    if used.get("1") is not None and free.get("1") is not None and (used["1"] + free["1"]):
        h["mem_pct"] = round(100 * used["1"] / (used["1"] + free["1"]))
    temps = [v for _k, v in w.get("envTempValue") or [] if isinstance(v, int)]
    if temps:
        h["temp"] = max(temps)
    names = {k: v for k, v in w.get("envFanDescr") or []}
    if w.get("envFanState"):
        h["fans"] = [{"name": names.get(k, f"Fan {k}"), "status": ENV_STATE.get(v, str(v))} for k, v in w["envFanState"]]
    names = {k: v for k, v in w.get("envPsuDescr") or []}
    if w.get("envPsuState"):
        h["psus"] = [{"name": names.get(k, f"PSU {k}"), "pid": "", "status": ENV_STATE.get(v, str(v))} for k, v in w["envPsuState"]]
    return h


def save_config(device, text):
    digest = hashlib.sha256(text.encode()).hexdigest()
    last = device.configs.order_by("-collected_at").first()
    if last and last.sha256 == digest:
        return False
    added = removed = 0
    if last:
        for line in difflib.unified_diff(last.text.splitlines(), text.splitlines(), lineterm="", n=0):
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1
    ConfigSnapshot.objects.create(device=device, text=text, sha256=digest, added=added, removed=removed)
    # keep the last 50 versions
    old = list(device.configs.order_by("-collected_at").values_list("pk", flat=True)[50:])
    if old:
        ConfigSnapshot.objects.filter(pk__in=old).delete()
    return bool(last)


def resolve_neighbors():
    """Link each neighbour row to a managed device (by management IP, interface IP or hostname)."""
    by_ip, by_name = {}, {}
    for d in Device.objects.only("id", "mgmt_ip", "hostname"):
        by_ip[d.mgmt_ip] = d.pk
        by_name[d.hostname.split(".")[0].lower()] = d.pk
    for ip, dev in Interface.objects.exclude(ip="").values_list("ip", "device_id"):
        by_ip.setdefault(ip.split("/")[0], dev)
    updates = []
    for n in Neighbor.objects.only("id", "remote_ip", "remote_name", "remote_device_id", "device_id"):
        target = by_ip.get(n.remote_ip) or by_name.get(n.remote_name.split(".")[0].split("(")[0].lower())
        if target == n.device_id:
            target = None
        if target != n.remote_device_id:
            n.remote_device_id = target
            updates.append(n)
    if updates:
        Neighbor.objects.bulk_update(updates, ["remote_device"], batch_size=500)



def infer_role(device, data):
    """A first guess so maps and checks work before anyone sets roles. Users can always change it."""
    import re
    model = (device.model or "").upper()
    routes = data.get("routes") or []
    dynamic = any(r["protocol"][:1] in ("O", "D", "B", "i") for r in routes)
    if re.search(r"ISR|ASR|C8[0-9]{3}|C1[01][0-9]{2}|CSR|ISR4", model):
        return "router"
    if re.search(r"N[3579]K|NEXUS", model):
        return "datacenter"
    if re.search(r"C9[56]\d\d|C68|C45|WS-C4[59]|8[34]\d\d|6400", model) or (dynamic and len(routes) > 3):
        return "core"
    if re.search(r"C9[23]\d\d|WS-C2960|WS-C3[56]|C1000|C1300|6[0-3]00|4100I|JL\d{3}A", model):
        return "access"
    return "unknown"


def track_flaps(obj, was_up, r, now):
    """Record link up/down changes: seen directly between two polls, or counted by the device (resets, link transitions)."""
    log = [t for t in (obj.flap_log or []) if t > (now - timedelta(hours=24)).isoformat()]
    changes = 0
    if was_up is not None and was_up != obj.oper_up:
        changes = 1
    for field in ("resets", "link_transitions"):
        new = r.get(field)
        if new is None:
            continue
        old = getattr(obj, field)
        if obj.pk and old is not None and new > old:
            changes = max(changes, min(new - old, 20))
        setattr(obj, field, new)
    log += [now.isoformat()] * changes
    obj.flap_log = log[-50:]


def apply_health(device, h, save=False):
    """CPU / memory / temperature / fans / PSUs from SSH or SNMP. Keeps a sample for the charts."""
    if not h:
        return
    from .models import DeviceSample
    now = timezone.now()
    if h.get("cpu") is not None:
        device.cpu = max(0, min(100, int(h["cpu"])))
    if h.get("mem_pct") is not None:
        device.mem_pct = max(0, min(100, int(h["mem_pct"])))
    if h.get("temp") is not None:
        device.temp_c = int(h["temp"])
    env = dict(device.env or {})
    for k in ("fans", "psus", "temp_state", "temps"):
        if k in h:
            env[k] = h[k]
    device.env = env
    device.health_at = now
    last = device.samples.order_by("-ts").first()
    if not last or (now - last.ts).total_seconds() > 60:
        DeviceSample.objects.create(device=device, ts=now, cpu=device.cpu, mem=device.mem_pct)
    if save:
        device.save(update_fields=["cpu", "mem_pct", "temp_c", "env", "health_at"])


def apply_extras(device, data):
    if data.get("health"):
        apply_health(device, data["health"])
    if data.get("macs") is not None:
        MacEntry.objects.filter(device=device).delete()
        MacEntry.objects.bulk_create([MacEntry(device=device, vlan=m["vlan"], mac=m["mac"], interface=m["interface"][:60], type=m["type"][:24])
                                      for m in data["macs"] if m.get("mac")], batch_size=2000)
    if data.get("arp") is not None:
        ArpEntry.objects.filter(device=device).delete()
        ArpEntry.objects.bulk_create([ArpEntry(device=device, ip=a["ip"], mac=a["mac"], interface=a["interface"][:60]) for a in data["arp"]],
                                     batch_size=2000)
    if data.get("stp") is not None:
        StpVlan.objects.filter(device=device).delete()
        StpVlan.objects.bulk_create([StpVlan(device=device, vlan=x["vlan"], root_mac=x.get("root_mac") or "", root_prio=x.get("root_prio"),
                                             bridge_mac=x.get("bridge_mac") or "", bridge_prio=x.get("bridge_prio"), is_root=x.get("is_root", False),
                                             root_port=x.get("root_port") or "", root_cost=x.get("root_cost"), tc_count=x.get("tc_count"),
                                             tc_ago=x.get("tc_ago") or "", tc_from=x.get("tc_from") or "", ports=x.get("ports", []))
                                     for x in data["stp"]])
    if data.get("optics") is not None:
        Transceiver.objects.filter(device=device).delete()
        Transceiver.objects.bulk_create([Transceiver(device=device, interface=o["interface"], pid=o.get("pid", "")[:60], serial=o.get("serial", "")[:60],
                                                     description=o.get("description", "")[:120], temp=o.get("temp"), volt=o.get("volt"),
                                                     bias=o.get("bias"), tx=o.get("tx"), rx=o.get("rx"), flags=o.get("flags", {}))
                                         for o in data["optics"]])
    if data.get("poe") is not None:
        poe = data["poe"]
        device.facts = {**device.facts, "poe": {"available": poe.get("available"), "used": poe.get("used")}}
        ports = {p["interface"].lower(): p for p in poe.get("ports", [])}
        for i in device.interfaces.all():
            p = ports.get(i.short.lower())
            if p:
                i.poe_admin, i.poe_oper, i.poe_watts = p["admin"][:10], p["oper"][:12], p["watts"]
                i.poe_device, i.poe_class = p["device"][:60], p["cls"][:6]
                i.save(update_fields=["poe_admin", "poe_oper", "poe_watts", "poe_device", "poe_class"])
    if data.get("macs") is not None or data.get("arp") is not None:
        update_endpoints(device)


def edge_ports(device):
    """Ports where an endpoint can be: access ports with no switch or router behind them."""
    uplinks = {n.local_interface.lower() for n in device.neighbors.all() if n.kind in ("switch", "router") or n.remote_device_id}
    return {i.short.lower(): i for i in device.interfaces.all()
            if i.is_physical and i.mode in ("access", "unknown") and i.short.lower() not in uplinks and not i.port_channel}


def update_endpoints(device):
    now = timezone.now()
    edges = edge_ports(device)
    nbr = {n.local_interface.lower(): n for n in device.neighbors.all()}
    arp = {}
    for ip, mac in ArpEntry.objects.values_list("ip", "mac"):
        arp[mac] = ip
    events = []
    baseline = not Endpoint.objects.filter(device=device).exists()     # first scan of this switch: no "new device" noise
    for m in MacEntry.objects.filter(device=device):
        port = edges.get(m.interface.lower())
        if not port or m.type.startswith("static") or m.type in ("cpu", "self"):
            continue
        n = nbr.get(m.interface.lower())
        is_announcer = n and n.kind in ("phone", "ap") and (m.vlan == (int(port.voice_vlan) if port.voice_vlan.isdigit() else -1) or n.kind == "ap")
        ep, created = Endpoint.objects.get_or_create(mac=m.mac, defaults={"device": device, "interface": port.short, "vlan": m.vlan})
        where = f"{device.hostname} {port.short}"
        if created and not baseline:
            events.append(EndpointEvent(endpoint=ep, kind="new", to_where=where, at=now))
        elif (ep.device_id, ep.interface.lower()) != (device.pk, port.short.lower()):
            old = f"{ep.device.hostname if ep.device else '?'} {ep.interface}"
            events.append(EndpointEvent(endpoint=ep, kind="moved", from_where=old, to_where=where, at=now))
            ep.moves += 1
        ep.device, ep.interface, ep.vlan, ep.last_seen = device, port.short, m.vlan, now
        if is_announcer:
            ep.name, ep.kind = n.remote_name[:120], n.kind
        elif not ep.kind:
            ep.kind = "host"
        ip = arp.get(m.mac)
        if ip and ip != ep.ip:
            if ep.ip:
                events.append(EndpointEvent(endpoint=ep, kind="ip", from_where=ep.ip, to_where=ip, at=now))
            ep.ip = ip
        ep.save()
    if events:
        EndpointEvent.objects.bulk_create(events)
        from apps.alerts.engine import endpoint_events
        endpoint_events(events)
    # IPs learned on L3 devices for endpoints seen elsewhere
    for ep in Endpoint.objects.filter(mac__in=list(arp.keys()), ip=""):
        ep.ip = arp[ep.mac]
        ep.save(update_fields=["ip"])
