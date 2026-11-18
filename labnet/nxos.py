"""Cisco NX-OS (Nexus 9000) command output for the lab network, in the formats ntc-templates' cisco_nxos templates read."""
import re

from .ios import sys_descr
from .network import VLANS, _carries, dotted, mac_for


def _nat(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def short(n):
    return n.replace("Ethernet", "Eth")


def ports(d):
    return sorted(d["ports"].items(), key=lambda kv: _nat(kv[0]))


def mgmt0(d):
    return d["ip"]


def r_version(d):
    up = d.get("uptime_text") or "41 day(s), 3 hour(s), 12 minute(s), 9 second(s)"
    m = re.match(r"(\d+) days, (\d+) hours, (\d+) minutes", up)
    if m:
        up = f"{m.group(1)} day(s), {m.group(2)} hour(s), {m.group(3)} minute(s), 7 second(s)"
    v = d["ver"]
    fname = "nxos." + v.replace("(", ".").replace(")", "") + ".bin"
    return f"""Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Copyright (C) 2002-2021, Cisco and/or its affiliates.
All rights reserved.

Software
  BIOS: version 07.69
  NXOS: version {v}
  BIOS compile time:  04/08/2021
  NXOS image file is: bootflash:///{fname}
  NXOS compile time:  10/22/2021 12:00:00 [10/22/2021 21:54:12]


Hardware
  cisco Nexus9000 C93180YC-FX Chassis
  Intel(R) Xeon(R) CPU D-1528 @ 1.90GHz with 24569356 kB of memory.
  Processor Board ID {d['serial']}

  Device name: {d['name']}
  bootflash:   53298520 kB
Kernel uptime is {up}

Last reset at 123456 usecs after Mon Oct 02 08:00:00 2026
  Reason: Reset Requested by CLI command reload
  System version: {v}
  Service:

plugin
  Core Plugin, Ethernet Plugin

Active Package(s):

"""


def r_inventory(d):
    rows = [f'NAME: "Chassis",  DESCR: "Nexus9000 C93180YC-FX Chassis"',
            f"PID: {d['model']}      ,  VID: V03 ,  SN: {d['serial']}", "",
            'NAME: "Slot 1",  DESCR: "48x10/25G + 6x40/100G Ethernet Module"',
            f"PID: {d['model']}      ,  VID: V03 ,  SN: {d['serial']}", ""]
    for i, (slot, pid, st) in enumerate(d["health"]["psus"], start=1):
        rows += [f'NAME: "Power Supply {i}",  DESCR: "Nexus9000 C93180YC-FX Chassis Power Supply"',
                 f"PID: NXA-PAC-650W-PE    ,  VID: V01 ,  SN: LIT2{i}3456{i}", ""]
    for i, (n, st) in enumerate(d["health"]["fans"], start=1):
        rows += [f'NAME: "Fan {i}",  DESCR: "Nexus9000 C93180YC-FX Chassis Fan Module"', "PID: NXA-FAN-30CFM-B    ,  VID: V01 ,  SN: N/A", ""]
    return "\n".join(rows) + "\n"


def _status(p):
    return {"connected": "connected", "notconnect": "notconnec", "disabled": "disabled", "err-disabled": "down"}.get(p["status"], "notconnec")


def r_status(d):
    rows = ["", "-" * 80, "Port          Name               Status    Vlan      Duplex  Speed   Type", "-" * 80]
    for name, p in ports(d):
        vlan = "routed" if p["routed"] else ("trunk" if p["mode"] == "trunk" else str(p["vlan"]))
        spd = {1000: "1000", 10000: "10G", 25000: "25G", 40000: "40G", 100000: "100G"}.get(p["speed"], str(p["speed"] or "auto"))
        if p["status"] != "connected":
            spd = "auto"
        rows.append(f"{short(name):<13} {p['desc'][:18]:<18} {_status(p):<9} {vlan:<9} {p['duplex'] if p['status'] == 'connected' else 'auto':<7} {spd:<7} {p.get('media', '10Gbase-SR')}")
    rows.append(f"{'mgmt0':<13} {'--':<18} {'connected':<9} {'routed':<9} {'full':<7} {'1000':<7} --")
    return "\n".join(rows) + "\n"


def r_interface(d):
    out = []
    for name, p in ports(d):
        up = p["status"] == "connected"
        admin = "down" if p["status"] == "disabled" else "up"
        state = "up" if up else ("down (Administratively down)" if admin == "down" else
                                 "down (err-disabled)" if p["status"] == "err-disabled" else "down (Link not connected)")
        mac = dotted(mac_for(d["name"], name))
        spd = f"{p['speed'] // 1000} Gb/s" if up and p["speed"] >= 1000 else ("auto-speed" if not up else f"{p['speed']} Mb/s")
        bw = (p["speed"] or 10000) * 1000
        block = [f"{name} is {state}", f"admin state is {admin}, Dedicated Interface",
                 f"  Hardware: 100/1000/10000/25000 Ethernet, address: {mac} (bia {mac})"]
        if p["desc"]:
            block.append(f"  Description: {p['desc']}")
        if p.get("ip"):
            block.append(f"  Internet Address is {p['ip']}")
        block += [f"  MTU {p.get('mtu', 9216 if not p.get('ip') else 1500)} bytes, BW {bw} Kbit , DLY 10 usec",
                  "  reliability 255/255, txload 1/255, rxload 1/255", "  Encapsulation ARPA, medium is broadcast",
                  f"  Port mode is {'routed' if p['routed'] else p['mode']}",
                  f"  {p['duplex'] if up else 'auto'}-duplex, {spd}, media type is {'10G' if 'Ethernet1/4' in name or '/5' in name else '25G'}",
                  "  Beacon is turned off", "  Auto-Negotiation is turned on  FEC mode is Auto",
                  "  Input flow-control is off, output flow-control is off", "  Auto-mdix is turned off",
                  "  Rate mode is dedicated", "  Switchport monitor is off", "  EtherType is 0x8100",
                  "  EEE (efficient-ethernet) : n/a", "    admin fec state is auto, oper fec state is off",
                  f"  Last link flapped {'3week(s) 2day(s)' if up else 'never'}",
                  '  Last clearing of "show interface" counters never',
                  f"  {p.get('resets', 2)} interface resets",
                  "  Load-Interval #1: 30 seconds",
                  f"    30 seconds input rate {p['in_bps']} bits/sec, {p['in_bps'] // 8000} packets/sec",
                  f"    30 seconds output rate {p['out_bps']} bits/sec, {p['out_bps'] // 8000} packets/sec",
                  "    input rate 0 bps, 0 pps; output rate 0 bps, 0 pps",
                  "  Load-Interval #2: 5 minute (300 seconds)",
                  f"    300 seconds input rate {p['in_bps']} bits/sec, {p['in_bps'] // 8000} packets/sec",
                  f"    300 seconds output rate {p['out_bps']} bits/sec, {p['out_bps'] // 8000} packets/sec",
                  "  RX", "    112233 unicast packets  4455 multicast packets  12 broadcast packets",
                  "    116700 input packets  98765432 bytes", "    0 jumbo packets  0 storm suppression bytes",
                  f"    0 runts  0 giants  {p['crc']} CRC  0 no buffer",
                  f"    {p['in_err']} input error  0 short frame  0 overrun   0 underrun  0 ignored",
                  "    0 watchdog  0 bad etype drop  0 bad proto drop  0 if down drop",
                  f"    0 input with dribble  {p['drops']} input discard", "    0 Rx pause", "  TX",
                  "    223344 unicast packets  5566 multicast packets  34 broadcast packets",
                  "    228944 output packets  123456789 bytes", "    0 jumbo packets",
                  f"    {p['out_err']} output error  {p['coll']} collision  0 deferred  {p['late']} late collision",
                  "    0 lost carrier  0 no carrier  0 babble  0 output discard", "    0 Tx pause", ""]
        out.append("\n".join(block))
    out.append(f"""mgmt0 is up
admin state is up,
  Hardware: GigabitEthernet, address: {dotted(d['base_mac'])} (bia {dotted(d['base_mac'])})
  Internet Address is {mgmt0(d)}/24
  MTU 1500 bytes, BW 1000000 Kbit, DLY 10 usec
  reliability 255/255, txload 1/255, rxload 1/255
  Encapsulation ARPA, medium is broadcast
  full-duplex, 1000 Mb/s
  Auto-Negotiation is turned on
  Auto-mdix is turned off
  EtherType is 0x0000
  1 minute input rate 1200 bits/sec, 1 packets/sec
  1 minute output rate 2400 bits/sec, 2 packets/sec
  Rx
    123 input packets 0 unicast packets 12 multicast packets
    0 broadcast packets 4567 bytes
  Tx
    234 output packets 0 unicast packets 0 multicast packets
    0 broadcast packets 8910 bytes
""")
    return "\n".join(out)


def r_switchport(d):
    out = []
    for name, p in ports(d):
        if p["routed"]:
            continue
        mode = "trunk" if p["mode"] == "trunk" else "access"
        vn = VLANS.get(p["vlan"], f"VLAN{p['vlan']:04d}")
        out.append(f"""Name: {short(name)}
  Switchport: Enabled
  Switchport Monitor: Not enabled
  Switchport Isolated : Not enabled
  Switchport Block Multicast: Not enabled
  Switchport Block Unicast: Not enabled
  Operational Mode: {mode}
  Access Mode VLAN: {p['vlan'] if mode == 'access' else 1} ({vn if mode == 'access' else 'default'})
  Trunking Native Mode VLAN: {p['native']} ({VLANS.get(p['native'], 'default')})
  Trunking VLANs Allowed: {p['allowed'] if mode == 'trunk' else '1-4094'}
  Voice VLAN: none
  Extended Trust State : not trusted [COS = 0]
  Administrative private-vlan primary host-association: none
  Administrative private-vlan secondary host-association: none
""")
    return "\n".join(out)


def r_cdp(d, D=None):
    out = []
    for local, other, rport in d["cdp"]:
        caps = "Router Switch IGMP Filtering Supports-STP-Dispute"
        out.append(f"""----------------------------------------
Device ID:{other['name']}.campus.local
System Name: {other['name']}

Interface address(es):
    IPv4 Address: {other['ip']}
Platform: cisco {other['model']}, Capabilities: {caps}
Interface: {short(local)}, Port ID (outgoing port): {rport}
Holdtime: 152 sec

Version:
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version {other['ver']}, RELEASE SOFTWARE (fc1)

Advertisement Version: 2

Native VLAN: 1
Duplex: full

MTU: 1500
Mgmt address(es):
    IPv4 Address: {other['ip']}
""")
    return "\n".join(out)


def r_lldp(d):
    out = []
    for local, other, rport in d["lldp"]:
        caps = "B, R" if other["role"] != "access" else "B"
        out.append(f"""Chassis id: {dotted(other['base_mac'])}
Port id: {rport}
Local Port id: {short(local)}
Port Description: {rport}
System Name: {other['name']}
System Description: {sys_descr(other)}
Time remaining: 102 seconds
System Capabilities: {caps}
Enabled Capabilities: {caps}
Management Address: {other['ip']}
Management Address IPV6: not advertised
Vlan ID: not advertised
""")
    return ("Capability codes:\n  (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device\n  (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other\n"
            "Device ID            Local Intf      Hold-time  Capability  Port ID\n\n" + "\n".join(out) + f"\nTotal entries displayed: {len(out)}\n")


def r_route(d):
    out = ["IP Route Table for VRF \"default\"", "'*' denotes best ucast next-hop", "'**' denotes best mcast next-hop",
           "'[x/y]' denotes [preference/metric]", "'%<string>' in via output denotes VRF <string>", ""]
    out += ["0.0.0.0/0, ubest/mbest: 1/0", "    *via 10.0.99.1, [1/0], 6w0d, static", ""]
    for name, p in ports(d):
        if p.get("ip"):
            ip, ln = p["ip"].split("/")
            net = ip.rsplit(".", 1)[0] + "." + str(int(ip.rsplit(".", 1)[1]) & ~1) if ln == "31" else ip
            out += [f"{net}/{ln}, ubest/mbest: 1/0, attached", f"    *via {ip}, {short(name)}, [0/0], 6w0d, direct", "",
                    f"{ip}/32, ubest/mbest: 1/0, attached", f"    *via {ip}, {short(name)}, [0/0], 6w0d, local", ""]
    out += ["", "IP Route Table for VRF \"management\"", "'*' denotes best ucast next-hop", "'**' denotes best mcast next-hop",
            "'[x/y]' denotes [preference/metric]", "'%<string>' in via output denotes VRF <string>", "",
            f"{d['ip'].rsplit('.', 1)[0]}.0/24, ubest/mbest: 1/0, attached", f"    *via {d['ip']}, mgmt0, [0/0], 6w0d, direct", ""]
    return "\n".join(out) + "\n"


def r_vlan(d):
    rows = ["", "VLAN Name                             Status    Ports", "---- -------------------------------- --------- -------------------------------"]
    for v, n in VLANS.items():
        members = [short(nm) for nm, p in ports(d) if not p["routed"] and ((p["mode"] == "access" and p["vlan"] == v) or (p["mode"] == "trunk" and _carries(p, v)))]
        chunks = [", ".join(members[i:i + 5]) for i in range(0, len(members), 5)] or [""]
        rows.append(f"{v:<4} {n:<32} active    {chunks[0]}")
        for c in chunks[1:]:
            rows.append(" " * 48 + c)
    return "\n".join(rows) + "\n"


def r_portchannel(d):
    return ("Flags:  D - Down        P - Up in port-channel (members)\n        I - Individual  H - Hot-standby (LACP only)\n"
            "        s - Suspended   r - Module-removed\n        b - BFD Session Wait\n        S - Switched    R - Routed\n"
            "        U - Up (port-channel)\n        p - Up in delay-lacp mode (member)\n        M - Not in use. Min-links not met\n"
            "--------------------------------------------------------------------------------\n"
            "Group Port-       Type     Protocol  Member Ports\n      Channel\n"
            "--------------------------------------------------------------------------------\n")


def r_mac(d):
    rows = ["Legend:", "        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC",
            "        age - seconds since last seen,+ - primary entry using vPC Peer-Link,", "        (T) - True, (F) - False, C - ControlPlane MAC, ~ - vsan",
            "   VLAN     MAC Address      Type      age     Secure NTFY Ports", "---------+-----------------+--------+---------+------+----+------------------"]
    for vlan, mac, port, _t in sorted(d["macs"], key=lambda r: (r[0], r[1])):
        rows.append(f"*   {vlan:<5}  {dotted(mac)}   dynamic  0         F      F    {short(port)}")
    return "\n".join(rows) + "\n"


def r_arp(d):
    rows = ["", "Flags: * - Adjacencies learnt on non-active FHRP router", "", f"IP ARP Table for context default",
            f"Total number of entries: {len(d['arp']) + 1}", "Address         Age       MAC Address     Interface       Flags"]
    rows.append(f"10.255.1.0      00:05:12  {dotted(mac_for('DC-LEAF-1', 'Ethernet50/1'))}  Ethernet1/50")
    return "\n".join(rows) + "\n"


def r_resources(d):
    h = d["health"]
    used_k, total_k = h["mem_used"] // 1024, h["mem_total"] // 1024
    return f"""Load average:   1 minute: 0.42   5 minutes: 0.51   15 minutes: 0.48
Processes   :   901 total, 1 running
CPU states  :   {h['cpu']}.00% user,   1.50% kernel,   {100 - h['cpu'] - 1.5:.2f}% idle
        CPU0 states  :   {h['cpu']}.00% user,   1.00% kernel,   {100 - h['cpu'] - 1:.2f}% idle
Memory usage:   {total_k}K total,   {used_k}K used,   {total_k - used_k}K free
Kernel vmalloc:   0K total,   0K free
Kernel buffers:   12345K Used
Kernel cached :   456789K Used

Current memory status: OK
"""


def r_env(d):
    h = d["health"]
    rows = ["Power Supply:", "Voltage: 12.0 Volts", "Power                              Actual        Actual        Total",
            "Supply    Model                    Output     Input      Capacity    Status", "                                    (Watts )     (Watts )     (Watts )",
            "-------  -------------------  -----------  -----------  -----------  --------------"]
    for i, (_s, pid, st) in enumerate(h["psus"], start=1):
        status = "Ok" if st == "OK" else "Shutdown"
        rows.append(f"{i:<8} {'NXA-PAC-650W-PE':<20} {'112 W' if st == 'OK' else '0 W':>11}  {'126 W' if st == 'OK' else '0 W':>11}  {'650 W':>11}  {status}")
    rows += ["", "Fan:", "---------------------------------------------------------------------------",
             "Fan             Model                Hw     Direction       Status", "---------------------------------------------------------------------------"]
    for i, (n, st) in enumerate(h["fans"], start=1):
        rows.append(f"Fan{i}(sys_fan{i})  NXA-FAN-30CFM-B      --     front-to-back   {'Ok' if st == 'OK' else 'Failure'}")
    rows += ["", "Temperature:", "--------------------------------------------------------------------",
             "Module   Sensor        MajorThresh   MinorThres   CurTemp     Status", "                        (Celsius)     (Celsius)    (Celsius)",
             "--------------------------------------------------------------------",
             f"1        FRONT           80              70          {h['temp']}         {'Normal' if h['temp'] < 50 else 'Minor'}",
             f"1        BACK            70              42          {h['temp'] - 6}         Normal"]
    return "\n".join(rows) + "\n"


def r_config(d):
    f = d["flags"]
    L = ["!Command: show running-config", "!Running configuration last done at: Mon Oct 02 08:00:00 2026", "", f"version {d['ver']} Bios:version 07.69",
         f"hostname {d['name']}", "vdc " + d["name"] + " id 1", "", "feature lldp", "feature interface-vlan", "feature lacp"]
    if f.get("telnet"):
        L.append("feature telnet")
    L += ["", "username admin password 5 $5$KFQ... role network-admin", "ip domain-lookup",
          "snmp-server user admin network-admin auth md5 0x123 priv 0x123 localizedkey"]
    if f.get("snmp_public"):
        L.append("snmp-server community public group network-operator")
    L += ["ntp server 10.50.1.1 use-vrf management", "logging server 10.50.1.20 6 use-vrf management", ""]
    L += [f"vlan 1,{','.join(str(v) for v in VLANS if v != 1)}"]
    for v, n in VLANS.items():
        if v != 1:
            L += [f"vlan {v}", f"  name {n}"]
    L += ["", "spanning-tree port type edge bpduguard default", "vrf context management", "  ip route 0.0.0.0/0 " + d["ip"].rsplit(".", 1)[0] + ".254", ""]
    for name, p in ports(d):
        L.append(f"interface {name}")
        if p["desc"]:
            L.append(f"  description {p['desc']}")
        if p["routed"]:
            L += ["  no switchport", f"  mtu {p.get('mtu', 1500)}", f"  ip address {p['ip']}"]
        elif p["mode"] == "trunk":
            L += ["  switchport", "  switchport mode trunk", f"  switchport trunk allowed vlan {p['allowed']}"]
        else:
            L += ["  switchport", f"  switchport access vlan {p['vlan']}", "  spanning-tree port type edge"]
        L += ["  " + x for x in p.get("extra", [])]
        L.append("  shutdown" if p["status"] == "disabled" else "  no shutdown")
        L.append("")
    L += ["interface mgmt0", "  vrf member management", f"  ip address {d['ip']}/24", "line console", "line vty", "  exec-timeout 15"]
    L += list(d.get("extra_global", []))
    removed = set(d.get("removed_global", []))
    return "\n".join(l for l in L if l.startswith(" ") or l.strip() not in removed) + "\n"


def r_dir(d, fs="bootflash:"):
    files = d.setdefault("flash", {})
    rows = [f"       4096    Oct 02 08:00:00 2026  .rpmstore/", "    1946021888    Oct 02 08:00:00 2026  nxos." + d["ver"].replace("(", ".").replace(")", "") + ".bin"]
    for n, sz in files.items():
        rows.append(f"{sz:>14}    Nov 12 08:00:00 2026  {n}")
    used = sum(files.values()) + 1946021888
    return "\n".join(rows) + f"\n\nUsage for {fs}//sup-local\n {used} bytes used\n {53298520 * 1024 - used} bytes free\n {53298520 * 1024} bytes total\n"


def commands(D):
    return {"show version": r_version, "show inventory": r_inventory, "show running-config": r_config, "show interface": r_interface,
            "show interface status": r_status, "show interface switchport": r_switchport, "show cdp neighbors detail": lambda d: r_cdp(d, D),
            "show lldp neighbors detail": r_lldp, "show ip route vrf all": r_route, "show ip route": r_route, "show vlan brief": r_vlan,
            "show port-channel summary": r_portchannel, "show ip ospf neighbors vrf all": lambda d: "", "show mac address-table": r_mac,
            "show ip arp": r_arp, "show system resources": r_resources, "show environment": r_env}


KEYMAP = {"version": "show version", "inventory": "show inventory", "running": "show running-config", "interfaces": "show interface",
          "status": "show interface status", "switchport": "show interface switchport", "cdp": "show cdp neighbors detail",
          "lldp": "show lldp neighbors detail", "route": "show ip route vrf all", "vlan": "show vlan brief", "etherchannel": "show port-channel summary",
          "ospf": "show ip ospf neighbors vrf all", "mac": "show mac address-table", "arp": "show ip arp", "cpu": "show system resources",
          "env": "show environment"}


def outputs_for(d, D):
    c = commands(D)
    return {k: c[v](d) for k, v in KEYMAP.items()}
