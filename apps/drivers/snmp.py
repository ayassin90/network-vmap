"""Vendor-neutral SNMP collection: system facts, IF-MIB interfaces and counters, EtherLike duplex, LLDP-MIB and
CISCO-CDP-MIB neighbours, IP-MIB addresses and routes, Q-BRIDGE / Cisco VTP VLANs. Works for any switch that
speaks standard MIBs, which is how platforms without an SSH driver still get topology and interface health."""
import ipaddress
import re

from apps.inventory.models import short_ifname

SYSTEM = {"sysDescr": "1.3.6.1.2.1.1.1.0", "sysObjectID": "1.3.6.1.2.1.1.2.0", "sysUpTime": "1.3.6.1.2.1.1.3.0",
          "sysName": "1.3.6.1.2.1.1.5.0"}

POLL_WALKS = {
    "ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
    "ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
    "ifInDiscards": "1.3.6.1.2.1.2.2.1.13",
    "ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
    "ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "cpu5min": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",
    "memUsed": "1.3.6.1.4.1.9.9.48.1.1.1.5",
    "memFree": "1.3.6.1.4.1.9.9.48.1.1.1.6",
    "envTempValue": "1.3.6.1.4.1.9.9.13.1.3.1.3",
    "envFanDescr": "1.3.6.1.4.1.9.9.13.1.4.1.2",
    "envFanState": "1.3.6.1.4.1.9.9.13.1.4.1.3",
    "envPsuDescr": "1.3.6.1.4.1.9.9.13.1.5.1.2",
    "envPsuState": "1.3.6.1.4.1.9.9.13.1.5.1.3",
    "hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2",
}

COLLECT_WALKS = dict(POLL_WALKS, **{
    "ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "ifType": "1.3.6.1.2.1.2.2.1.3",
    "ifMtu": "1.3.6.1.2.1.2.2.1.4",
    "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    "dot3Duplex": "1.3.6.1.2.1.10.7.2.1.19",
    "dot3FCS": "1.3.6.1.2.1.10.7.2.1.3",
    "dot3Late": "1.3.6.1.2.1.10.7.2.1.8",
    "dot3Single": "1.3.6.1.2.1.10.7.2.1.4",
    "lldpLocPortId": "1.0.8802.1.1.2.1.3.7.1.3",
    "lldpLocPortDesc": "1.0.8802.1.1.2.1.3.7.1.4",
    "lldpRemPortId": "1.0.8802.1.1.2.1.4.1.1.7",
    "lldpRemPortDesc": "1.0.8802.1.1.2.1.4.1.1.8",
    "lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "lldpRemSysDesc": "1.0.8802.1.1.2.1.4.1.1.10",
    "lldpRemCapEn": "1.0.8802.1.1.2.1.4.1.1.12",
    "lldpRemManAddr": "1.0.8802.1.1.2.1.4.2.1.3",
    "cdpDeviceId": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
    "cdpDevicePort": "1.3.6.1.4.1.9.9.23.1.2.1.1.7",
    "cdpPlatform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8",
    "cdpAddress": "1.3.6.1.4.1.9.9.23.1.2.1.1.4",
    "cdpCaps": "1.3.6.1.4.1.9.9.23.1.2.1.1.9",
    "ipAdEntIfIndex": "1.3.6.1.2.1.4.20.1.2",
    "ipAdEntNetMask": "1.3.6.1.2.1.4.20.1.3",
    "ipCidrRouteIfIndex": "1.3.6.1.2.1.4.24.4.1.5",
    "ipCidrRouteProto": "1.3.6.1.2.1.4.24.4.1.7",
    "ipRouteNextHop": "1.3.6.1.2.1.4.21.1.7",
    "ipRouteMask": "1.3.6.1.2.1.4.21.1.11",
    "ipRouteProto": "1.3.6.1.2.1.4.21.1.9",
    "ipRouteIfIndex": "1.3.6.1.2.1.4.21.1.2",
    "vtpVlanName": "1.3.6.1.4.1.9.9.46.1.3.1.1.4.1",
    "qVlanName": "1.3.6.1.2.1.17.7.1.4.3.1.1",
    "ciscoTrunk": "1.3.6.1.4.1.9.9.46.1.6.1.1.14",
    "ciscoAccessVlan": "1.3.6.1.4.1.9.9.68.1.2.2.1.2",
})

PROTO = {1: "other", 2: "L", 3: "S", 4: "icmp", 8: "R", 9: "i", 13: "O", 14: "B", 16: "D"}
VENDOR_HINTS = [("cisco", "Cisco"), ("aruba", "Aruba"), ("procurve", "HPE Aruba"), ("comware", "HPE Comware"), ("h3c", "H3C"),
                ("huawei", "Huawei"), ("junos", "Juniper"), ("juniper", "Juniper"), ("arista", "Arista"), ("dell", "Dell"),
                ("extreme", "Extreme"), ("ruckus", "Ruckus"), ("icx", "Ruckus"), ("fortiswitch", "Fortinet"), ("mikrotik", "MikroTik"),
                ("ubiquiti", "Ubiquiti"), ("edgeswitch", "Ubiquiti"), ("netgear", "Netgear"), ("allied", "Allied Telesis"),
                ("alcatel", "Alcatel-Lucent"), ("omniswitch", "Alcatel-Lucent"), ("zyxel", "Zyxel"), ("tp-link", "TP-Link"),
                ("d-link", "D-Link"), ("mellanox", "NVIDIA"), ("cumulus", "NVIDIA"), ("ruijie", "Ruijie"), ("zte", "ZTE")]


def _idx(rows):
    return {k: v for k, v in rows or []}


def _mac(v):
    if isinstance(v, str) and v.startswith("hex:"):
        h = v[4:]
        if len(h) == 12:
            return ".".join(h[i:i + 4] for i in (0, 4, 8))
    return v or ""


def _hexip(v):
    if isinstance(v, str) and v.startswith("hex:") and len(v) == 12:
        return ".".join(str(int(v[4 + i:6 + i], 16)) for i in (0, 2, 4, 6))
    return v if isinstance(v, str) and re.match(r"^\d+\.\d+\.\d+\.\d+$", v or "") else ""


def guess_vendor(descr):
    d = (descr or "").lower()
    for hint, name in VENDOR_HINTS:
        if hint in d:
            return name
    return ""


def guess_version(descr):
    m = re.search(r"Version\s+([\w.()\-]+)", descr or "", re.I)
    return m.group(1).rstrip(",") if m else ""


def parse_collect(res):
    """Raw SNMP result -> normalised data (same shape as the SSH drivers)."""
    g, w = res.get("get", {}), res.get("walk", {})
    descr = g.get("sysDescr") or ""
    data = {"facts": {"hostname": (g.get("sysName") or "").split(".")[0], "vendor": guess_vendor(descr),
                      "os_version": guess_version(descr), "uptime_seconds": int(g.get("sysUpTime") or 0) // 100 or None,
                      "sys_descr": descr[:500], "sys_object_id": g.get("sysObjectID", "")},
            "interfaces": [], "neighbors": [], "routes": [], "vlans": []}
    names = _idx(w.get("ifName")) or _idx(w.get("ifDescr"))
    descrs, alias, oper, admin = _idx(w.get("ifDescr")), _idx(w.get("ifAlias")), _idx(w.get("ifOperStatus")), _idx(w.get("ifAdminStatus"))
    hs, mtu, mac = _idx(w.get("ifHighSpeed")), _idx(w.get("ifMtu")), _idx(w.get("ifPhysAddress"))
    ine, oute, ind, outd = _idx(w.get("ifInErrors")), _idx(w.get("ifOutErrors")), _idx(w.get("ifInDiscards")), _idx(w.get("ifOutDiscards"))
    dup, fcs, late, coll = _idx(w.get("dot3Duplex")), _idx(w.get("dot3FCS")), _idx(w.get("dot3Late")), _idx(w.get("dot3Single"))
    trunk, accv = _idx(w.get("ciscoTrunk")), _idx(w.get("ciscoAccessVlan"))
    iftype = _idx(w.get("ifType"))
    ips = {}
    masks = _idx(w.get("ipAdEntNetMask"))
    for ip, ifi in w.get("ipAdEntIfIndex") or []:
        try:
            plen = ipaddress.ip_network(f"0.0.0.0/{masks.get(ip, '255.255.255.255')}").prefixlen
        except ValueError:
            plen = 32
        ips[str(ifi)] = f"{ip}/{plen}"
    for i, name in names.items():
        if iftype.get(i) not in (None, 6, 24, 53, 117, 161, 136, 131, 62, 69):   # ethernet, loopback, virtual, lag, vlan, tunnel
            continue
        d = {2: "half", 3: "full"}.get(dup.get(i), "")
        sp = hs.get(i) or None
        mode = "trunk" if trunk.get(i) == 1 else ("access" if i in accv else "unknown")
        if iftype.get(i) in (24, 53, 136, 131):
            mode = "virtual"
        elif i in ips and mode == "unknown":
            mode = "routed"
        data["interfaces"].append({
            "name": name or descrs.get(i, f"if{i}"), "if_index": int(i), "description": alias.get(i, "") or "",
            "admin_up": admin.get(i) == 1, "oper_up": oper.get(i) == 1,
            "status": "disabled" if admin.get(i) == 2 else ("connected" if oper.get(i) == 1 else "notconnect"),
            "mode": mode, "access_vlan": str(accv.get(i, "")) if mode == "access" else "", "speed": f"{sp}Mb/s" if sp else "",
            "duplex": d, "speed_mbps": sp, "mtu": mtu.get(i), "mac": _mac(mac.get(i)), "ip": ips.get(i, ""),
            "in_errors": ine.get(i, 0) or 0, "out_errors": oute.get(i, 0) or 0, "crc": fcs.get(i, 0) or 0,
            "late_collisions": late.get(i, 0) or 0, "collisions": coll.get(i, 0) or 0,
            "in_discards": ind.get(i, 0) or 0, "out_drops": outd.get(i, 0) or 0,
        })
    # LLDP: index timeMark.localPortNum.remIndex
    locport = _idx(w.get("lldpLocPortDesc")) or _idx(w.get("lldpLocPortId"))
    rn, rp, rpd, rsd, rcap = (_idx(w.get(k)) for k in ("lldpRemSysName", "lldpRemPortId", "lldpRemPortDesc", "lldpRemSysDesc", "lldpRemCapEn"))
    mgmt = {}
    for idx, _v in w.get("lldpRemManAddr") or []:
        parts = idx.split(".")
        if len(parts) >= 9 and parts[3] == "1" and parts[4] == "4":
            mgmt[".".join(parts[:3])] = ".".join(parts[5:9])
    for idx, name in rn.items():
        parts = idx.split(".")
        if len(parts) < 3:
            continue
        loc = locport.get(parts[1], "") or names.get(parts[1], "")
        data["neighbors"].append({"protocol": "lldp", "local_interface": short_ifname(loc), "remote_name": name or "",
                                  "remote_port": short_ifname(str(rpd.get(idx) or rp.get(idx) or "")), "remote_ip": mgmt.get(idx, ""),
                                  "remote_platform": (rsd.get(idx) or "")[:120], "remote_description": rsd.get(idx) or "",
                                  "capabilities": _lldp_caps(rcap.get(idx))})
    # CDP: index ifIndex.deviceIndex
    cid, cport, cplat, caddr = (_idx(w.get(k)) for k in ("cdpDeviceId", "cdpDevicePort", "cdpPlatform", "cdpAddress"))
    for idx, name in cid.items():
        ifi = idx.split(".")[0]
        data["neighbors"].append({"protocol": "cdp", "local_interface": short_ifname(names.get(ifi, "")), "remote_name": name or "",
                                  "remote_port": short_ifname(cport.get(idx, "") or ""), "remote_ip": _hexip(caddr.get(idx)),
                                  "remote_platform": cplat.get(idx, "") or "", "remote_description": "",
                                  "capabilities": "Switch" if "switch" in (cplat.get(idx) or "").lower() else ""})
    # Routes
    proto = _idx(w.get("ipCidrRouteProto"))
    cifi = _idx(w.get("ipCidrRouteIfIndex"))
    for idx, pr in proto.items():
        p = idx.split(".")
        if len(p) < 13:
            continue
        try:
            plen = ipaddress.ip_network(f"0.0.0.0/{'.'.join(p[4:8])}").prefixlen
        except ValueError:
            continue
        nh = ".".join(p[9:13])
        data["routes"].append({"vrf": "default", "protocol": PROTO.get(pr, str(pr)) if pr != 2 or nh != "0.0.0.0" else "C",
                               "prefix": f"{'.'.join(p[0:4])}/{plen}", "next_hop": "" if nh == "0.0.0.0" else nh,
                               "interface": names.get(str(cifi.get(idx)), ""), "distance": None, "metric": None, "age": ""})
    if not data["routes"]:
        nh_t, mask_t, pr_t, if_t = (_idx(w.get(k)) for k in ("ipRouteNextHop", "ipRouteMask", "ipRouteProto", "ipRouteIfIndex"))
        for dest, nh in nh_t.items():
            try:
                plen = ipaddress.ip_network(f"0.0.0.0/{mask_t.get(dest, '255.255.255.255')}").prefixlen
            except ValueError:
                continue
            pr = pr_t.get(dest)
            data["routes"].append({"vrf": "default", "protocol": "C" if pr == 2 else PROTO.get(pr, str(pr)),
                                   "prefix": f"{dest}/{plen}", "next_hop": "" if pr == 2 else nh,
                                   "interface": names.get(str(if_t.get(dest)), ""), "distance": None, "metric": None, "age": ""})
    vl = _idx(w.get("vtpVlanName")) or _idx(w.get("qVlanName"))
    for vid, name in vl.items():
        if vid.isdigit():
            data["vlans"].append({"vid": int(vid), "name": name or "", "status": "active", "ports": ""})
    return data


def _lldp_caps(v):
    """LLDP capability BITS: first octet, MSB first = other, repeater, bridge, WLAN AP, router, phone, DOCSIS, station."""
    if v is None or v == "":
        return ""
    if isinstance(v, int):
        first = v & 0xFF
    elif isinstance(v, str) and v.startswith("hex:"):
        try:
            first = int(v[4:6] or "0", 16)
        except ValueError:
            return ""
    else:
        first = ord(str(v)[0])
    names = ["Other", "Repeater", "Bridge", "WLAN", "Router", "Phone", "DOCSIS", "Station"]
    return ",".join(n for i, n in enumerate(names) if first & (0x80 >> i))
