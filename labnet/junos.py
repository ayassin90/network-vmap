"""Juniper Junos (EX, ELS) command output for the lab network."""
import re

from .ios import sys_descr
from .network import VLANS, _carries, coloned, mac_for


def _nat(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def ports(d):
    return sorted(d["ports"].items(), key=lambda kv: _nat(kv[0]))


def vname(v):
    return VLANS.get(v, f"VLAN{v}")


def r_version(d):
    return f"""fpc0:
--------------------------------------------------------------------------
Hostname: {d['name']}
Model: {d['model'].lower()}
Junos: {d['ver']}
JUNOS OS Kernel 32-bit  [20230601.0b9b2ab_builder_stable_11]
JUNOS OS libs [20230601.0b9b2ab_builder_stable_11]
JUNOS OS runtime [20230601.0b9b2ab_builder_stable_11]
JUNOS OS time zone information [20230601.0b9b2ab_builder_stable_11]
JUNOS EX  Software Suite [{d['ver']}]
JUNOS Packet Forwarding Engine Support (EX34XX) [{d['ver']}]
JUNOS Web Management Platform Package [{d['ver']}]

"""


def r_hardware(d):
    rows = ["Hardware inventory:", "Item             Version  Part number  Serial number     Description",
            f"Chassis                                {d['serial']:<17} {d['model']}", "Pseudo CB 0",
            "Routing Engine 0          BUILTIN      BUILTIN           RE-EX2300-48P",
            f"FPC 0            REV 11   650-059881   {d['serial']:<17} {d['model']}",
            "  CPU                     BUILTIN      BUILTIN           FPC CPU",
            "  PIC 0                   BUILTIN      BUILTIN           48x10/100/1000 Base-T",
            f"  PIC 1          REV 11   650-059881   {d['serial']:<17} 4x10G SFP/SFP+",
            "    Xcvr 0       REV 01   740-021308   AS90PGH           SFP+-10G-SR"]
    for i, (_s, pid, st) in enumerate(d["health"]["psus"]):
        if st != "Not Present":
            rows.append(f"Power Supply {i}   REV 01   640-060603   1EDE240012{i}       JPSU-920-AC-AFO")
    rows.append("Fan Tray 0                                               Fan Module, Airflow Out (AFO)")
    return "\n".join(rows) + "\n"


def r_env(d):
    h = d["health"]
    rows = ["Class Item                           Status     Measurement"]
    for i, (_s, _pid, st) in enumerate(h["psus"]):
        status = {"OK": "OK", "Not Present": "Absent"}.get(st, "Failed")
        rows.append(f"{'Power' if i == 0 else '     '} FPC 0 Power Supply {i}           {status}")
    temp_status = "OK" if h["temp_state"] == "GREEN" else "Check"
    rows += [f"Temp  FPC 0 GEPHY Front Left         {temp_status:<10} {h['temp']} degrees C / {h['temp'] * 9 // 5 + 32} degrees F",
             f"      FPC 0 Maxim Sensor             OK         {h['temp'] - 4} degrees C / {(h['temp'] - 4) * 9 // 5 + 32} degrees F"]
    for i, (_n, st) in enumerate(h["fans"]):
        rows.append(f"{'Fans' if i == 0 else '    '}  FPC 0 Fan Tray 0 Fan {i}         {'OK' if st == 'OK' else 'Failed':<10} {'Spinning at normal speed' if st == 'OK' else 'Not spinning'}")
    return "\n".join(rows) + "\n"


def r_re(d):
    h = d["health"]
    pct = round(100 * h["mem_used"] / h["mem_total"])
    return f"""Routing Engine status:
    Temperature                 {h['temp']} degrees C / {h['temp'] * 9 // 5 + 32} degrees F
    CPU temperature             {h['temp'] + 4} degrees C / {(h['temp'] + 4) * 9 // 5 + 32} degrees F
    Total memory              {h['mem_total'] // 2**20} MB Max  {h['mem_used'] // 2**20} MB used ({pct:>3} percent)
      Control plane memory    {h['mem_total'] // 2**20} MB Max  {h['mem_used'] // 2**20} MB used ({pct:>3} percent)
    5 sec CPU utilization:
      User                      {h['cpu'] - 2} percent
      Background                 0 percent
      Kernel                     2 percent
      Interrupt                  0 percent
      Idle                      {100 - h['cpu']} percent
    CPU utilization:
      User                      {h['cpu'] - 3} percent
      Background                 0 percent
      Kernel                     3 percent
      Interrupt                  0 percent
      Idle                      {100 - h['cpu']} percent
    Model                          RE-EX2300-48P
    Serial ID                      {d['serial']}
    Start time                     2026-10-02 08:00:00 UTC
    Uptime                         {d.get('uptime_text') or '41 days, 3 hours, 12 minutes'}
    Last reboot reason             0x2000:hypervisor reboot
"""


def r_interfaces(d):
    out = []
    for i, (name, p) in enumerate(ports(d)):
        up = p["status"] == "connected"
        admin = "Administratively down" if p["status"] == "disabled" else "Enabled"
        spd = {100: "100mbps", 1000: "1000mbps", 10000: "10Gbps"}.get(p["speed"], "Auto")
        mac = coloned(mac_for(d["name"], name))
        b = [f"Physical interface: {name}, {admin}, Physical link is {'Up' if up else 'Down'}",
             f"  Interface index: {650 + i}, SNMP ifIndex: {514 + i}, Generation: 141"]
        if p["desc"]:
            b.append(f"  Description: {p['desc']}")
        b += [f"  Link-level type: Ethernet, MTU: {p.get('mtu', 1514)}, Link-mode: {'Half' if p['duplex'] == 'half' else 'Full'}-duplex, Speed: {spd if up else 'Auto'}, BPDU Error: None,",
              "  Loop Detect PDU Error: None, Ethernet-Switching Error: None, MAC-REWRITE Error: None, Loopback: Disabled,",
              "  Source filtering: Disabled, Flow control: Enabled, Auto-negotiation: Enabled, Remote fault: Online",
              f"  Device flags   : Present Running{'' if up else ' Down'}", "  Interface flags: SNMP-Traps Internal: 0x4000", "  Link flags     : None",
              "  CoS queues     : 12 supported, 12 maximum usable queues", "  Hold-times     : Up 0 ms, Down 0 ms",
              f"  Current address: {mac}, Hardware address: {mac}",
              f"  Last flapped   : {'2026-10-02 08:00:00 UTC (6w0d 00:58 ago)' if up else 'Never'}", "  Statistics last cleared: Never",
              "  Traffic statistics:",
              f"   Input  bytes  :            987654321          {p['in_bps']:>10} bps",
              f"   Output bytes  :           1987654321          {p['out_bps']:>10} bps",
              f"   Input  packets:              1234567          {p['in_bps'] // 8000:>10} pps",
              f"   Output packets:              2345678          {p['out_bps'] // 8000:>10} pps",
              "  Input errors:",
              f"    Errors: {p['in_err']}, Drops: 0, Framing errors: {p['crc']}, Runts: 0, Policed discards: 0, L3 incompletes: 0, L2 channel errors: 0,",
              "    L2 mismatch timeouts: 0, FIFO errors: 0, Resource errors: 0",
              "  Output errors:",
              f"    Carrier transitions: {p.get('resets', 2)}, Errors: {p['out_err']}, Drops: {p['drops']}, Collisions: {p['coll']}, Aged packets: 0, FIFO errors: 0,",
              "    HS link CRC errors: 0, MTU errors: 0, Resource errors: 0",
              "  MAC statistics:                      Receive         Transmit",
              "    Total octets                     987654321       1987654321",
              f"    CRC/Align errors                {p['crc']:>10}                0",
              f"    Late collisions                          0       {p['late']:>10}",
              f"  Logical interface {name}.0 (Index {555 + i}) (SNMP ifIndex {600 + i}) (Generation 160)",
              "    Flags: Up SNMP-Traps 0x4004000 Encapsulation: Ethernet-Bridge",
              "    Protocol eth-switch, MTU: 1514", ""]
        out.append("\n".join(b))
    out.append(f"""Physical interface: irb, Enabled, Physical link is Up
  Interface index: 640, SNMP ifIndex: 501, Generation: 129
  Link-level type: Ethernet, MTU: 1514
  Current address: {coloned(d['base_mac'])}, Hardware address: {coloned(d['base_mac'])}
  Logical interface irb.99 (Index 560) (SNMP ifIndex 540) (Generation 170)
    Flags: Up SNMP-Traps 0x4000 Encapsulation: ENET2
    Protocol inet, MTU: 1500
      Addresses, Flags: Is-Preferred Is-Primary
        Destination: 10.0.99/24, Local: {d['ip']}, Broadcast: 10.0.99.255
""")
    return "\n".join(out)


def r_lldp(d):
    rows = ["Local Interface    Parent Interface    Chassis Id          Port info          System Name"]
    for local, other, rport in d["lldp"]:
        rows.append(f"{local:<18} {'-':<19} {coloned(other['base_mac']):<19} {rport:<18} {other['name']}")
    return "\n".join(rows) + "\n"


def r_lldp_detail(d):
    out = []
    for local, other, rport in d["lldp"]:
        out.append(f"""LLDP Neighbor Information:
Local Information:
Index: 1 Time to live: 120 Time mark: Thu Nov 12 08:58:12 2026 Age: 7 secs
Local Interface    : {local}
Parent Interface   : -
Local Port ID      : 514
Ageout Count       : 0

Neighbour Information:
Chassis type       : Mac address
Chassis ID         : {coloned(other['base_mac'])}
Port type          : Interface name
Port ID            : {rport}
Port description   : {rport}
System name        : {other['name']}

System Description : {sys_descr(other)}

System capabilities
        Supported  : Bridge Router
        Enabled    : Bridge Router

Management Info
        Type              : IPv4
        Address           : {other['ip']}
        Port ID           : 5
        Subtype           : 2
        Interface Subtype : ifIndex(2)
        OID               : 1.3.6.1.2.1.31.1.1.1.1.5
""")
    return "\n".join(out)


def r_route(d):
    return f"""
inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)
+ = Active Route, - = Last Active, * = Both

0.0.0.0/0          *[Static/5] 6w0d 00:58:12
                    >  to 10.0.99.1 via irb.99
10.0.99.0/24       *[Direct/0] 6w0d 00:58:12
                    >  via irb.99
{d['ip'] + '/32':<18} *[Local/0] 6w0d 00:58:12
                       Local via irb.99
"""


def r_mac(d):
    rows = ["", "MAC flags (S - static MAC, D - dynamic MAC, L - locally learned, P - Persistent static", "           SE - statistics enabled, NM - non configured MAC, R - remote PE MAC, O - ovsdb MAC)",
            "", "", f"Ethernet switching table : {len(d['macs'])} entries, {len(d['macs'])} learned", "Routing instance : default-switch",
            "   Vlan                MAC                 MAC         Age    Logical                NH        RTR",
            "   name                address             flags              interface              Index     ID"]
    for vlan, mac, port, _t in sorted(d["macs"], key=lambda r: (r[0], r[1])):
        rows.append(f"   {vname(vlan):<19} {coloned(mac):<19} D             -   {port + '.0':<22} 0         0")
    return "\n".join(rows) + "\n"


def r_arp(d):
    return ("MAC Address       Address         Interface                Flags\n"
            f"{coloned(mac_for('CORE-2', 'base', oui='00a3d1'))} 10.0.99.1       irb.99 [xe-0/1/0.0]      none\n"
            "Total entries: 1\n")


def r_config(d):
    f = d["flags"]
    L = [f"set version {d['ver']}", f"set system host-name {d['name']}", 'set system root-authentication encrypted-password "$6$abc$def"',
         "set system login user vmap uid 2000", "set system login user vmap class super-user",
         'set system login user vmap authentication encrypted-password "$6$xyz$uvw"', "set system services ssh root-login deny"]
    if f.get("telnet"):
        L.append("set system services telnet")
    if f.get("http"):
        L.append("set system services web-management http")
    L += ["set system syslog user * any emergency", "set system syslog host 10.50.1.20 any notice", "set system syslog file messages any notice",
          "set system ntp server 10.50.1.1", "set snmp community vmap-lab authorization read-only"]
    if f.get("snmp_public"):
        L.append("set snmp community public authorization read-only")
    for name, p in ports(d):
        if p["desc"]:
            L.append(f"set interfaces {name} description \"{p['desc']}\"" if " " in p["desc"] else f"set interfaces {name} description {p['desc']}")
        if p["status"] == "disabled":
            L.append(f"set interfaces {name} disable")
        if p["mode"] == "trunk":
            L.append(f"set interfaces {name} native-vlan-id {p['native']}")
            L.append(f"set interfaces {name} unit 0 family ethernet-switching interface-mode trunk")
            for v in VLANS:
                if v not in (1, 999) and _carries(p, v):
                    L.append(f"set interfaces {name} unit 0 family ethernet-switching vlan members {vname(v)}")
        else:
            L.append(f"set interfaces {name} unit 0 family ethernet-switching interface-mode access")
            L.append(f"set interfaces {name} unit 0 family ethernet-switching vlan members {vname(p['vlan'])}")
        L += [x for x in p.get("extra", [])]
        if p.get("poe_off"):
            L.append(f"set poe interface {name} disable")
    L += [f"set interfaces irb unit 99 family inet address {d['ip']}/24", "set protocols lldp interface all", "set protocols lldp-med interface all"]
    L += [f"set protocols rstp interface {n} edge" for n, p in ports(d) if p["mode"] == "access"]
    L += ["set protocols rstp bpdu-block-on-edge", "set routing-options static route 0.0.0.0/0 next-hop 10.0.99.1"]
    for v, n in VLANS.items():
        if v != 1:
            L.append(f"set vlans {n} vlan-id {v}")
    L.append("set vlans MGMT l3-interface irb.99")
    L += list(d.get("extra_global", []))
    removed = set(d.get("removed_global", []))
    return "\n".join(l for l in L if l not in removed) + "\n"


def r_storage(d):
    files = d.setdefault("flash", {})
    used = 600 + sum(files.values()) // 2**20
    return f"""fpc0:
--------------------------------------------------------------------------
Filesystem              Size       Used      Avail  Capacity  Mounted on
/dev/gpt/junos          1.3G       {used}M      {1300 - used}M       {used * 100 // 1300}%  /.mount
tmpfs                   668M        28K       668M        0%  /.mount/tmp
"""


def r_tmp(d):
    files = d.setdefault("flash", {})
    rows = ["/var/tmp/:"] + [f"{n}" for n in files] + ["vi.recover/"]
    return "\n".join(rows) + "\n"


def commands(D):
    return {"show version": r_version, "show chassis hardware": r_hardware, "show chassis environment": r_env,
            "show chassis routing-engine": r_re, "show interfaces extensive": r_interfaces, "show lldp neighbors": r_lldp,
            "show lldp neighbors detail": r_lldp_detail, "show route table inet.0": r_route, "show ethernet-switching table": r_mac,
            "show arp no-resolve": r_arp, "show configuration | display set": r_config, "show system storage": r_storage,
            "file list /var/tmp/": r_tmp}


KEYMAP = {"version": "show version", "hardware": "show chassis hardware", "env": "show chassis environment", "re": "show chassis routing-engine",
          "interfaces": "show interfaces extensive", "lldp": "show lldp neighbors", "route": "show route table inet.0",
          "mac": "show ethernet-switching table", "arp": "show arp no-resolve", "running": "show configuration | display set"}


def outputs_for(d, D):
    c = commands(D)
    return {k: c[v](d) for k, v in KEYMAP.items()}
