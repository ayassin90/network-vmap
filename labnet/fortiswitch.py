"""Fortinet FortiSwitch (standalone FortiSwitchOS) command output for the lab network."""
import re

from .ios import sys_descr
from .network import VLANS, _carries, coloned, mac_for


def _nat(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def ports(d):
    return sorted(d["ports"].items(), key=lambda kv: _nat(kv[0]))


def r_status(d):
    return f"""Version: FortiSwitch-{d['model'][3:]} {d['ver']},build0453,230719 (GA)
Serial-Number: {d['serial']}
BIOS version: 04000006
System Part-Number: P23452-03
Burn in MAC: {coloned(d['base_mac'])}
Hostname: {d['name']}
Distribution: International
Branch point: 453
System time: Thu Nov 12 08:58:12 2026
"""


def r_perf(d):
    h = d["health"]
    up = d.get("uptime_text") or "41 days, 3 hours, 12 minutes"
    return f"""CPU states: {h['cpu'] - 2}% user {2}% system 0% nice {100 - h['cpu']}% idle
Memory states: {round(100 * h['mem_used'] / h['mem_total'])}% used
Average network usage: 1 kbps in 1 minute, 1 kbps in 10 minutes, 1 kbps in 30 minutes
Uptime: {up.replace(', ', ',  ')}
"""


def r_summary(d):
    rows = [" Portname    Status  Tpid  Vlan  Duplex  Speed  Flags         Discard", " __________  ______  ____  ____  ______  _____  ____________  _________", ""]
    for name, p in ports(d):
        up = p["status"] == "connected"
        spd = {10: "10M", 100: "100M", 1000: "1G", 10000: "10G"}.get(p["speed"], "1G")
        vlan = p["native"] if p["mode"] == "trunk" else p["vlan"]
        rows.append(f" {name:<11} {'up' if up else 'down':<7} 8100  {vlan:<5} {p['duplex'] if up else 'full':<7} {spd:<6} {'QS,  ,' if name.endswith(('49', '50', '51', '52')) else '  ,  ,':<13} none")
    return "\n".join(rows) + "\n"


def r_stats(d):
    out = []
    for name, p in ports(d):
        up = p["status"] == "connected"
        admin = "down" if p["status"] == "disabled" else "up"
        out.append(f"""Port({name}) is Admin {admin}, line protocol is {'up' if up else 'down'}
Interface Type is Serial Gigabit Media Independent Interface(SGMII/SerDes)
Address is {coloned(mac_for(d['name'], name)).upper()}, loopback is not set
MTU 9216 bytes, Encapsulation IEEE 802.3/Ethernet-II
{p['duplex']}-duplex, {p['speed'] if up else 0} Mb/s, link type is auto
input rate {p['in_bps']} bps, output rate {p['out_bps']} bps
input  : 7516191 bytes, 59081 packets, {p['in_err']} errors, 0 drops, 0 oversizes
         51862 unicasts, 5986 multicasts, 1233 broadcasts, 0 unknowns
         0 undersizes, 0 fragments, 0 jabbers, {p['crc']} fcs_errors
output : 15426094 bytes, 90122 packets, {p['out_err']} errors, {p['drops']} drops, 0 oversizes
         79236 unicasts, 9672 multicasts, 1214 broadcasts
         {p['coll']} collisions, {p['late']} late collisions, 0 excessive collisions
""")
    return "\n".join(out)


def r_lldp(d):
    out = []
    for local, other, rport in d["lldp"]:
        out.append(f"""Neighbor learned on port {local} by LLDP protocol
Last change 3 days ago
Last packet received 7 seconds ago

Chassis ID: {coloned(other['base_mac'])}  (mac)
System Name: {other['name']}
System Description:
{sys_descr(other)}

Time To Live: 120 seconds
System Capabilities: BR
Enabled Capabilities: BR
Management IP Address: {other['ip']}
Port ID: {rport}  (ifName)
Port Description: {rport}
""")
    return "\n".join(out)


def r_route(d):
    return f"""Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP
       O - OSPF, IA - OSPF inter area
       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2
       E1 - OSPF external type 1, E2 - OSPF external type 2
       i - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area
       * - candidate default

S*      0.0.0.0/0 [10/0] via 10.0.99.1, internal, 6w0d
C       10.0.99.0/24 is directly connected, internal
"""


def r_mac(d):
    out = []
    for vlan, mac, port, _t in sorted(d["macs"], key=lambda r: (r[0], r[1])):
        out.append(f"MAC: {coloned(mac)}  VLAN: {vlan} Trunk: {port}(port-id {re.sub(r'\D', '', port) or 0})\nFlags: 0x00000440 [ used ]")
    return "\n".join(out) + "\n"


def r_arp(d):
    return f"Address           Age(min)   Hardware Addr      Interface\n10.0.99.1         0          {coloned(mac_for('CORE-2', 'base', oui='00a3d1'))}  internal\n"


def r_console(d):
    return "mode                : batch\nbaudrate            : 9600\noutput              : standard\nlogin               : enable\n"


def r_config(d):
    f = d["flags"]
    L = [f"#config-version=FS1E48-{d['ver'][1:]}-FW-build0453-230719:opmode=0:vdom=0", "#conf_file_ver=1234567890", "#buildno=0453", "#global_vdom=1",
         "config system global", f'    set hostname "{d["name"]}"']
    allow = "ping https ssh snmp" + (" http" if f.get("http") else "") + (" telnet" if f.get("telnet") else "")
    L += ["end", "config system interface", '    edit "mgmt"', f"        set ip {d['ip']} 255.255.255.0", f"        set allowaccess {allow}", "    next",
          '    edit "internal"', "        set ip 10.0.99.20 255.255.255.0", f"        set allowaccess {allow}", "    next", "end",
          "config system ntp", '    set ntpsync enable', "    config ntpserver", "        edit 1", '            set server "10.50.1.1"', "        next", "    end", "end",
          "config log syslogd setting", "    set status enable", '    set server "10.50.1.20"', "end",
          "config system snmp community", "    edit 1", '        set name "vmap-lab"', "    next"]
    if f.get("snmp_public"):
        L += ["    edit 2", '        set name "public"', "    next"]
    L += ["end", "config switch vlan"]
    for v, n in VLANS.items():
        L += [f"    edit {v}", f'        set description "{n}"', "    next"]
    L += ["end", "config switch physical-port"]
    for name, p in ports(d):
        L.append(f'    edit "{name}"')
        if p["desc"]:
            L.append(f'        set description "{p["desc"]}"')
        if p["status"] == "disabled":
            L.append("        set status down")
        if p.get("poe_off"):
            L.append("        set poe-status disable")
        L += ["        " + x for x in p.get("extra", [])]
        L.append("    next")
    L += ["end", "config switch interface"]
    for i, (name, p) in enumerate(ports(d), start=1):
        L.append(f'    edit "{name}"')
        if p["mode"] == "trunk":
            L += [f"        set native-vlan {p['native']}", f"        set allowed-vlans {p['allowed']}"]
        else:
            L.append(f"        set native-vlan {p['vlan']}")
            L.append("        set edge-port enabled")
        L += [f"        set snmp-index {i}", "    next"]
    L += ["end"]
    L += list(d.get("extra_global", []))
    removed = set(d.get("removed_global", []))
    return "\n".join(l for l in L if l.startswith(" ") or l.strip() not in removed) + "\n"


def commands(D):
    return {"get system status": r_status, "get system performance status": r_perf, "diagnose switch physical-ports summary": r_summary,
            "diagnose switch physical-ports stats list": r_stats, "get switch lldp neighbors-detail": r_lldp,
            "get router info routing-table all": r_route, "diagnose switch mac-address list": r_mac, "get system arp": r_arp,
            "show": r_config, "show full-configuration": r_config, "get system console": r_console}


KEYMAP = {"status": "get system status", "perf": "get system performance status", "summary": "diagnose switch physical-ports summary",
          "stats": "diagnose switch physical-ports stats list", "lldp": "get switch lldp neighbors-detail",
          "route": "get router info routing-table all", "mac": "diagnose switch mac-address list", "arp": "get system arp", "running": "show"}


def outputs_for(d, D):
    c = commands(D)
    return {k: c[v](d) for k, v in KEYMAP.items()}
