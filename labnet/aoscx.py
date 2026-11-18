"""Aruba AOS-CX command output for the lab network (formats follow ntc-templates' test fixtures)."""
import re

from .network import VLANS, coloned, mac_for


def _nat(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def r_system(d):
    up = d.get("uptime_text_cx") or "3 weeks, 2 days, 4 hours, 12 minutes"
    return f"""Hostname           : {d['name']}
System Description : {d['ver']}
System Contact     :
System Location    : HQ 2nd floor

Vendor             : Aruba
Product Name       : {d['model']}
Chassis Serial Nbr : {d['serial']}
Base MAC Address   : {coloned(d['base_mac']).replace(':', '')[:6]}-{coloned(d['base_mac']).replace(':', '')[6:]}
ArubaOS-CX Version : {d['ver']}

Time Zone          : UTC

Up Time            : {up}
CPU Util (%)       : {d['health']['cpu']}
Memory Usage (%)   : {round(100 * d['health']['mem_used'] / d['health']['mem_total'])}
"""


def r_module(d):
    pid = d["model"].split()[0]
    return f"""Management Modules
==================

     Product                                        Serial
Name Number  Description                            Number     Status
---- ------- -------------------------------------- ---------- ----------------
1/1  {pid}  {' '.join(d['model'].split()[1:])[:38]:<38} {d['serial']:<10} Active (local)
"""


def r_interface(d):
    out = []
    for name, p in sorted(d["ports"].items(), key=lambda kv: _nat(kv[0])):
        up = p["status"] == "connected"
        admin = "down" if p["status"] == "disabled" else "up"
        lines = [f"Interface {name} is {'up' if up else 'down'} ", f" Admin state is {admin}"]
        if not up:
            lines.append(" State information: " + ("Administratively down" if admin == "down" else "Waiting for link"))
        lines += [f" Link transitions: {p.get('resets', 1)}", f" Description: {p['desc']}",
                  f" Hardware: Ethernet, MAC Address: {coloned(mac_for(d['name'], name))} ", " MTU 1500 ",
                  f" Type {'SFP+SR' if p.get('sfp') or p['speed'] >= 10000 else '1GbT'}", f" {'Half' if p['duplex'] == 'half' else 'Full'}-duplex ",
                  " qos trust none", f" Speed {p['speed'] if up else 0} Mb/s ", " Auto-negotiation is on", " Flow-control: off ", " Error-control: off "]
        if p["mode"] == "trunk":
            lines += [" VLAN Mode: native-untagged", f" Native VLAN: {p['native']}", f" Allowed VLAN List: {p['allowed']}"]
        else:
            lines += [" VLAN Mode: access", f" Access VLAN: {p['vlan']}"]
        lines += [" Rx", f"   {1234567 if up else 0:>10} total packets          {987654321 if up else 0:>12} total bytes",
                  "            0   unicast packets", "            0   multicast packets", "            0   broadcast packets",
                  f"   {p['in_err']:>10} errors                  {0:>12} dropped", f"   {p['crc']:>10} CRC/FCS",
                  " Tx", f"   {2345678 if up else 0:>10} total packets          {1987654321 if up else 0:>12} total bytes",
                  "            0   unicast packets", "            0   multicast packets", "            0   broadcast packets",
                  f"   {p['out_err']:>10} errors                  {p['drops']:>12} dropped", f"   {p['coll']:>10} collision", ""]
        out.append("\n".join(lines))
    vl = f"""Interface vlan99 is up
 Admin state is up
 Description: MGMT
 Hardware: Ethernet, MAC Address: {coloned(d['base_mac'])}
 IPv4 address {d['ip']}/24
 MTU 1500
"""
    return "\n".join(out) + "\n" + vl


def r_lldp(d):
    ents = []
    for local, other, rport in d["lldp"]:
        ents.append(f"""--------------------------------------------------------------------------------
Port                           : {local}
Neighbor Entries               : 1
Neighbor Entries Deleted       : 0
Neighbor Entries Dropped       : 0
Neighbor Entries Aged-Out      : 0
Neighbor Chassis-Name          : {other['name']}.campus.local
Neighbor Chassis-Description   : Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version {other['ver']}
Neighbor Chassis-ID            : {coloned(other['base_mac'])}
Neighbor Management-Address    : {other['ip']}
Chassis Capabilities Available : Bridge, Router
Chassis Capabilities Enabled   : Bridge, Router
Neighbor Port-ID               : {rport}
Neighbor Port-Desc             : {rport}
Neighbor Port VLAN ID          : 1
TTL                            : 120
""")
    return f"""LLDP Neighbor Information
=========================
Total Neighbor Entries          : {len(ents)}
Total Neighbor Entries Deleted  : 0
Total Neighbor Entries Dropped  : 0
Total Neighbor Entries Aged-Out : 0
""" + "".join(ents)


def r_vlan(d):
    rows = ["-" * 114, "VLAN  Name                              Status  Reason                  Type        Interfaces                    ", "-" * 114]
    for v, n in VLANS.items():
        ports = [k for k, p in d["ports"].items() if p["mode"] == "access" and p["vlan"] == v] + \
                [k for k, p in d["ports"].items() if p["mode"] == "trunk"]
        name = "DEFAULT_VLAN_1" if v == 1 else n
        rows.append(f"{v:<5} {name:<33} up      ok                      {'default' if v == 1 else 'static':<11} {','.join(ports[:6])}")
    return "\n".join(rows) + "\n"


def r_mac(d):
    rows = ["MAC age-time            : 300 seconds", f"Number of MAC addresses : {len(d['macs'])}", "",
            "MAC Address          VLAN     Type                      Port", "--------------------------------------------------------------"]
    for vlan, mac, port, _t in d["macs"]:
        rows.append(f"{coloned(mac)}    {vlan:<8} dynamic                   {port}")
    return "\n".join(rows) + "\n"


def r_arp(d):
    return ("IPv4 Address     MAC                Port         Physical Port              State      VRF\n" + "-" * 114 +
            "\nTotal Number Of ARP Entries Listed- 0.\n" + "-" * 114 + "\n")


def r_route(d):
    return f"""Displaying ipv4 routes selected for forwarding

'[x/y]' denotes [distance/metric]

0.0.0.0/0, vrf default
	via  10.0.99.1,  [1/0],  static
{d['ip'].rsplit('.', 1)[0]}.0/24, vrf default
	via  vlan99,  [0/0],  connected
{d['ip']}/32, vrf default
	via  vlan99,  [0/0],  local
"""


def r_config(d):
    L = ["Current configuration:", "!", f"!Version ArubaOS-CX {d['ver']}", "!export-password: default", f"hostname {d['name']}",
         "user admin group administrators password ciphertext AQBapXXXX", "ntp server 10.50.1.1 iburst", "ntp enable", "!",
         "ssh server vrf default", "ssh server vrf mgmt", "snmp-server vrf default", "snmp-server community vmap-lab", "!",
         "logging 10.50.1.20 severity info", "!", "spanning-tree"]
    for v, n in VLANS.items():
        if v != 1:
            L += [f"vlan {v}", f"    name {n}"]
    for name, p in sorted(d["ports"].items(), key=lambda kv: _nat(kv[0])):
        L.append(f"interface {name}")
        if p["desc"]:
            L.append(f"    description {p['desc']}")
        L.append("    shutdown" if p["status"] == "disabled" else "    no shutdown")
        if p["mode"] == "trunk":
            L += [f"    vlan trunk native {p['native']}", f"    vlan trunk allowed {p['allowed']}"]
        else:
            L.append(f"    vlan access {p['vlan']}")
        if p.get("poe_off"):
            L.append("    no power-over-ethernet")
        L += ["    " + x for x in p.get("extra", [])]
        L.append("    exit")
    L += ["interface vlan 99", f"    ip address {d['ip']}/24", "    exit", "ip route 0.0.0.0/0 10.0.99.1", "!", "https-server vrf mgmt"]
    L += list(d.get("extra_global", []))
    removed = set(d.get("removed_global", []))
    return "\n".join(l for l in L if l.startswith(" ") or l.strip() not in removed) + "\n"


def commands(D):
    return {"show system": r_system, "show module": r_module, "show interface": r_interface, "show lldp neighbor-info detail": r_lldp,
            "show vlan": r_vlan, "show mac-address-table": r_mac, "show arp all-vrfs": r_arp, "show ip route all-vrfs": r_route,
            "show running-config": r_config}


def outputs_for(d, D):
    keymap = {"system": "show system", "module": "show module", "interfaces": "show interface", "lldp": "show lldp neighbor-info detail",
              "vlan": "show vlan", "mac": "show mac-address-table", "arp": "show arp all-vrfs", "route": "show ip route all-vrfs",
              "running": "show running-config"}
    c = commands(D)
    return {k: c[v](d) for k, v in keymap.items()}
