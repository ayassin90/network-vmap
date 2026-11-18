"""Huawei VRP (S series) command output for the lab network (formats follow ntc-templates' fixtures)."""
import re

from .network import VLANS, mac_for


def _nat(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def hmac(m):
    return f"{m[0:4]}-{m[4:8]}-{m[8:12]}"


def short(n):
    return n.replace("XGigabitEthernet", "XGE").replace("GigabitEthernet", "GE")


def r_version(d):
    up = d.get("uptime_text") or "32 days, 4 hours, 11 minutes"
    return f"""Huawei Versatile Routing Platform Software
VRP (R) software, Version 5.170 ({d['model'].split('-')[0]} {d['ver']})
Copyright (C) 2000-2021 HUAWEI TECH Co., Ltd.
HUAWEI {d['model']} Routing Switch uptime is {up}

ES5D2T52S002 0(Master) : uptime is {up}
DDR             Memory Size : 1024  M bytes
FLASH Total     Memory Size : 512   M bytes
"""


def r_device(d):
    h = d["health"]
    rows = [f"{d['model'].split('-')[0]}'s Device status:", "-" * 91,
            "Slot  Card   Type                     Online   Power Register     Alarm     Primary        ", "-" * 91,
            f"0     -      {d['model']:<24} Present  On    Registered   Normal    Master         "]
    for i, (_slot, pid, st) in enumerate(h["psus"], start=1):
        rows.append(f"PWR{i}  -      {('PAC600S12-CB' if pid else 'N/A'):<24} {'Present' if st != 'Not Present' else 'Absent':<8} {'On' if st == 'OK' else 'Off':<5} Registered   {'Normal' if st == 'OK' else 'Abnormal':<9} NA             ")
    for i, (_n, st) in enumerate(h["fans"], start=1):
        rows.append(f"FAN{i}  -      {'FAN-031A-B':<24} Present  On    Registered   {'Normal' if st == 'OK' else 'Abnormal':<9} NA             ")
    return "\n".join(rows) + "\n"


def r_interface(d):
    out = []
    for name, p in sorted(d["ports"].items(), key=lambda kv: _nat(kv[0])):
        st = {"connected": "UP", "disabled": "Administratively DOWN"}.get(p["status"], "DOWN")
        out.append(f"""{name} current state : {st}
Line protocol current state : {'UP' if st == 'UP' else 'DOWN'}
Description:{p['desc']}
Switch Port, PVID : {p['native'] if p['mode'] == 'trunk' else p['vlan']:>4}, TPID : 8100(Hex), The Maximum Frame Length is 9216
IP Sending Frames' Format is PKTFMT_ETHNT_2, Hardware address is {hmac(mac_for(d['name'], name))}
Last physical up time   : 2026-11-01 10:00:00
Last physical down time : 2026-10-30 08:00:00
Current system time: 2026-11-12 08:58:12
Port Mode: {'COMMON FIBER' if 'XG' in name else 'COMMON COPPER'}
Speed : {p['speed'] or 1000},  Loopback: NONE
Duplex: {p['duplex'].upper()},  Negotiation: ENABLE
Mdi   : AUTO,  Clock   : -
Last 300 seconds input rate {p['in_bps']} bits/sec, {p['in_bps'] // 4000} packets/sec
Last 300 seconds output rate {p['out_bps']} bits/sec, {p['out_bps'] // 4000} packets/sec
Input peak rate 0 bits/sec,Record time: -
Output peak rate 0 bits/sec,Record time: -

Input:  1234567 packets, 987654321 bytes
  Unicast:                  0,  Multicast:                   0
  Broadcast:                0,  Jumbo:                       -
  Discard:                  0,  Total Error:          {p['in_err']:>10}

  CRC:              {p['crc']:>10},  Giants:                      0
  Jabbers:                  0,  Throttles:                   0
  Runts:                    0,  Symbols:                     0
  Ignoreds:                 0,  Frames:                      0

Output:  2345678 packets, 1987654321 bytes
  Unicast:                  0,  Multicast:                   0
  Broadcast:                0,  Jumbo:                       -
  Discard:          {p['drops']:>10},  Total Error:          {p['out_err']:>10}

  Collisions:       {p['coll']:>10},  ExcessiveCollisions:         0
  Late Collisions:  {p['late']:>10},  Deferreds:                   0
    Input bandwidth utilization  :    0%
    Output bandwidth utilization :    0%
""")
    out.append(f"""Vlanif99 current state : UP
Line protocol current state : UP
Description:MGMT
Route Port,The Maximum Transmit Unit is 1500
Internet Address is {d['ip']}/24
IP Sending Frames' Format is PKTFMT_ETHNT_2, Hardware address is {hmac(d['base_mac'])}
Current system time: 2026-11-12 08:58:12
""")
    return "\n".join(out)


def r_port_vlan(d):
    rows = ["Port                        Link Type    PVID  Trunk VLAN List", "-" * 79]
    for name, p in sorted(d["ports"].items(), key=lambda kv: _nat(kv[0])):
        if p["mode"] == "trunk":
            rows.append(f"{name:<27} {'trunk':<12} {p['native']:<5} {p['allowed'].replace(',', ' ')}")
        else:
            rows.append(f"{name:<27} {'access':<12} {p['vlan']:<5} -")
    return "\n".join(rows) + "\n"


def r_lldp(d):
    out = []
    for local, other, rport in d["lldp"]:
        out.append(f"""{local} has 1 neighbor(s):

Neighbor index :1
Chassis type   :macAddress
Chassis ID     :{hmac(other['base_mac'])}
Port ID type   :interfaceName
Port ID        :{rport}
Port description    :{rport}
System name         :{other['name']}.campus.local
System description  :Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version {other['ver']}
System capabilities supported   :bridge router
System capabilities enabled     :bridge router
Management address type  :ipV4
Management address       :{other['ip']}
Expired time   :104s
""")
    return "\n".join(out)


def r_vlan(d):
    rows = [f"The total number of VLANs is: {len(VLANS)}", "-" * 80, "U: Up;         D: Down;         TG: Tagged;         UT: Untagged;",
            "MP: Vlan-mapping;               ST: Vlan-stacking;", "#: ProtocolTransparent-vlan;    *: Management-vlan;", "-" * 80, "",
            "VID  Type    Ports", "-" * 80]
    for v in VLANS:
        ut = [short(n) + ("(U)" if p["status"] == "connected" else "(D)") for n, p in sorted(d["ports"].items(), key=lambda kv: _nat(kv[0]))
              if p["mode"] == "access" and p["vlan"] == v]
        rows.append(f"{v:<4} common  UT:{'     '.join(ut[:4])}" if ut else f"{v:<4} common  ")
    rows += ["", "VID  Status  Property      MAC-LRN Statistics Description", "-" * 80]
    for v, n in VLANS.items():
        rows.append(f"{v:<4} enable  default       enable  disable    {n}")
    return "\n".join(rows) + "\n"


def r_mac(d):
    rows = ["-" * 79, "MAC Address    VLAN/VSI/BD                       Learned-From        Type", "-" * 79]
    for vlan, mac, port, _t in d["macs"]:
        rows.append(f"{hmac(mac)} {str(vlan) + '/-/-':<33} {short(port):<19} dynamic")
    rows += ["", "-" * 79, f"Total items displayed = {len(d['macs'])}"]
    return "\n".join(rows) + "\n"


def r_arp(d):
    return ("IP ADDRESS      MAC ADDRESS     EXPIRE(M) TYPE        INTERFACE   VPN-INSTANCE\n                                    VLAN/CEVLAN(SIP/DIP)\n" + "-" * 78 +
            f"\n{d['ip']:<15} {hmac(d['base_mac'])}            I -         Vlanif99\n" + "-" * 78 + "\nTotal:1         Dynamic:0       Static:0     Interface:1\n")


def r_route(d):
    net = d["ip"].rsplit(".", 1)[0] + ".0/24"
    return f"""Route Flags: R - relay, D - download to fib
------------------------------------------------------------------------------
Routing Tables: Public
         Destinations : 3        Routes : 3

Destination/Mask    Proto   Pre  Cost      Flags NextHop         Interface

        0.0.0.0/0   Static  60   0          RD   10.0.99.1       Vlanif99
{net:>17}   Direct  0    0           D   {d['ip']:<15} Vlanif99
{d['ip'] + '/32':>17}   Direct  0    0           D   127.0.0.1       Vlanif99
"""


def r_cpu(d):
    return f"CPU Usage Stat. Cycle: 60 (Second)\nCPU Usage            : {d['health']['cpu']}% Max: 45%\nCPU Usage Stat. Time : 2026-11-12  08:58:12\n"


def r_mem(d):
    h = d["health"]
    return f"Memory utilization statistics at 2026-11-12 08:58:12\nSystem Total Memory Is: {h['mem_total']} bytes\nTotal Memory Used Is: {h['mem_used']} bytes\nMemory Using Percentage Is: {round(100 * h['mem_used'] / h['mem_total'])}%\n"


def r_config(d):
    f = d["flags"]
    L = ["!Software Version V200R021C00SPC100", "#", f"sysname {d['name']}", "#", "vlan batch " + " ".join(str(v) for v in VLANS if v != 1), "#",
         "stp mode rstp", "#", "aaa", " local-user admin password irreversible-cipher $1c$xxx", " local-user admin privilege level 15", "#"]
    if f.get("telnet"):
        L += ["telnet server enable"]
    L += ["stelnet server enable", "ssh user admin authentication-type password", "#", "snmp-agent", "snmp-agent community read cipher %^%#xyz%^%#",
          "snmp-agent sys-info version v2c", "#", "ntp-service unicast-server 10.50.1.1", "info-center loghost 10.50.1.20", "#"]
    for name, p in sorted(d["ports"].items(), key=lambda kv: _nat(kv[0])):
        L.append(f"interface {name}")
        if p["desc"]:
            L.append(f" description {p['desc']}")
        if p["mode"] == "trunk":
            L += [" port link-type trunk", f" port trunk allow-pass vlan {p['allowed'].replace(',', ' ')}"]
        else:
            L += [" port link-type access", f" port default vlan {p['vlan']}"]
        if p["status"] == "disabled":
            L.append(" shutdown")
        if p.get("poe_off"):
            L.append(" undo poe enable")
        L += [" " + x for x in p.get("extra", [])]
        L.append("#")
    L += ["interface Vlanif99", f" ip address {d['ip']} 255.255.255.0", "#", "ip route-static 0.0.0.0 0.0.0.0 10.0.99.1", "#",
          "user-interface vty 0 4", " authentication-mode aaa", " protocol inbound " + ("all" if f.get("telnet") else "ssh"), "#"]
    L += list(d.get("extra_global", []))
    removed = set(d.get("removed_global", []))
    return "\n".join(l for l in L if l.startswith(" ") or l.strip() not in removed) + "\nreturn\n"


def r_esn(d):
    return f"ESN of slot 0: {d['serial']}\n"


def commands(D):
    return {"display esn": r_esn, "display version": r_version, "display device": r_device, "display current-configuration": r_config,
            "display interface": r_interface, "display port vlan": r_port_vlan, "display lldp neighbor": r_lldp, "display vlan": r_vlan,
            "display mac-address": r_mac, "display arp all": r_arp, "display ip routing-table": r_route, "display cpu-usage": r_cpu,
            "display memory-usage": r_mem}


def outputs_for(d, D):
    keymap = {"esn": "display esn", "version": "display version", "device": "display device", "running": "display current-configuration", "interfaces": "display interface",
              "port_vlan": "display port vlan", "lldp": "display lldp neighbor", "vlan": "display vlan", "mac": "display mac-address",
              "arp": "display arp all", "route": "display ip routing-table", "cpu": "display cpu-usage", "mem": "display memory-usage"}
    c = commands(D)
    return {k: c[v](d) for k, v in keymap.items()}
