"""Arista EOS command output for the lab network, in the formats ntc-templates' arista_eos templates read."""
import re

from .ios import sys_descr
from .network import VLANS, _carries, dotted, mac_for


def _nat(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def short(n):
    return n.replace("Ethernet", "Et").replace("Port-Channel", "Po")


def ports(d):
    return sorted(d["ports"].items(), key=lambda kv: _nat(kv[0]))


def _rate(bps):
    if bps >= 10**9:
        return f"{bps / 10**9:.1f} Gbps"
    if bps >= 10**6:
        return f"{bps / 10**6:.1f} Mbps"
    return f"{bps / 1000:.1f} kbps"


def r_version(d):
    h = d["health"]
    up = d.get("uptime_text") or "41 days, 3 hours, 12 minutes"
    m = re.match(r"(\d+) days, (\d+) hours, (\d+) minutes", up)
    up = f"{m.group(1)} days, {m.group(2)} hours and {m.group(3)} minutes" if m else up
    return f"""Arista {d['model']}
Hardware version: 11.02
Serial number: {d['serial']}
Hardware MAC address: {dotted(d['base_mac'])}
System MAC address: {dotted(d['base_mac'])}

Software image version: {d['ver']}
Architecture: x86_64
Internal build version: {d['ver']}-30069463.4292F
Internal build ID: 2b7bc5f1-9d17-4f43-9c1f-1d1e9d5ba1f0
Image format version: 3.0
Image optimization: Strata-4GB

Uptime: {up}
Total memory: {h['mem_total'] // 1024} kB
Free memory: {(h['mem_total'] - h['mem_used']) // 1024} kB

"""


def r_status(d):
    rows = ["Port       Name                Status       Vlan     Duplex Speed  Type            Flags Encapsulation"]
    for name, p in ports(d):
        vlan = "routed" if p["routed"] else ("trunk" if p["mode"] == "trunk" else str(p["vlan"]))
        st = {"connected": "connected", "disabled": "disabled", "err-disabled": "errdisabled"}.get(p["status"], "notconnect")
        up = p["status"] == "connected"
        spd = {1000: "1G", 10000: "10G", 25000: "25G", 40000: "40G", 100000: "100G"}.get(p["speed"], "auto") if up else "auto"
        dup = ("full" if p["duplex"] == "full" else "half") if up else "auto"
        rows.append(f"{short(name):<10} {p['desc'][:19]:<19} {st:<12} {vlan:<8} {dup:<6} {spd:<6} {p.get('media', '25GBASE-CR'):<15}")
    return "\n".join(rows) + "\n"


def r_interfaces(d):
    out = []
    for name, p in ports(d):
        up = p["status"] == "connected"
        if p["status"] == "disabled":
            head = f"{name} is administratively down, line protocol is down (disabled)"
        elif p["status"] == "err-disabled":
            head = f"{name} is down, line protocol is down (errdisabled)"
        else:
            head = f"{name} is {'up' if up else 'down'}, line protocol is {'up (connected)' if up else 'down (notconnect)'}"
        mac = dotted(mac_for(d["name"], name))
        spd = {1000: "1Gb/s", 10000: "10Gb/s", 25000: "25Gb/s", 100000: "100Gb/s"}.get(p["speed"], "unconfigured speed")
        b = [head, f"  Hardware is Ethernet, address is {mac} (bia {mac})"]
        if p["desc"]:
            b.append(f"  Description: {p['desc']}")
        if p.get("ip"):
            b += [f"  Internet address is {p['ip']}", "  Broadcast address is 255.255.255.255", "  Address determined by manual configuration",
                  f"  IP MTU {p.get('mtu', 1500)} bytes , BW {(p['speed'] or 100000) * 1000} kbit"]
        else:
            b.append(f"  Ethernet MTU {p.get('mtu', 9214)} bytes, BW {(p['speed'] or 25000) * 1000} kbit")
        b += [f"  {'Full' if p['duplex'] == 'full' else 'Half'}-duplex, {spd if up else 'unconfigured speed'}, auto negotiation: off, uni-link: n/a",
              f"  {'Up' if up else 'Down'} 3 days, 4 hours, 12 minutes, 1 second", "  Loopback Mode : None",
              f"  {p.get('resets', 2)} link status changes since last clear", '  Last clearing of "show interface" counters never',
              f"  5 minutes input rate {_rate(p['in_bps'])} (0.1% with framing overhead), {p['in_bps'] // 8000} packets/sec",
              f"  5 minutes output rate {_rate(p['out_bps'])} (0.0% with framing overhead), {p['out_bps'] // 8000} packets/sec",
              "     1234567 packets input, 987654321 bytes", "     Received 12 broadcasts, 345 multicast", "     0 runts, 0 giants",
              f"     {p['in_err']} input errors, {p['crc']} CRC, 0 alignment, 0 symbol, {p['drops']} input discards", "     0 PAUSE input",
              "     2345678 packets output, 1987654321 bytes", "     Sent 23 broadcasts, 456 multicast",
              f"     {p['out_err']} output errors, {p['coll']} collisions", f"     {p['late']} late collision, 0 deferred, 0 output discards",
              "     0 PAUSE output"]
        out.append("\n".join(b))
    out.append(f"""Management1 is up, line protocol is up (connected)
  Hardware is Ethernet, address is {dotted(d['base_mac'])} (bia {dotted(d['base_mac'])})
  Internet address is {d['ip']}/24
  Broadcast address is 255.255.255.255
  Address determined by manual configuration
  IP MTU 1500 bytes , BW 1000000 kbit
  Full-duplex, 1Gb/s, auto negotiation: on, uni-link: n/a
  Up 41 days, 3 hours, 12 minutes, 1 second
  Loopback Mode : None
  1 link status changes since last clear
  Last clearing of "show interface" counters never
  5 minutes input rate 1.2 kbps (0.0% with framing overhead), 1 packets/sec
  5 minutes output rate 2.4 kbps (0.0% with framing overhead), 2 packets/sec
     12345 packets input, 1234567 bytes
     Received 12 broadcasts, 34 multicast
     0 runts, 0 giants
     0 input errors, 0 CRC, 0 alignment, 0 symbol, 0 input discards
     0 PAUSE input
     23456 packets output, 2345678 bytes
     Sent 1 broadcasts, 2 multicast
     0 output errors, 0 collisions
     0 late collision, 0 deferred, 0 output discards
     0 PAUSE output""")
    return "\n".join(out) + "\n"


def r_switchport(d):
    out = []
    for name, p in ports(d):
        if p["routed"]:
            continue
        mode = "trunk" if p["mode"] == "trunk" else "static access"
        out.append(f"""Name: {short(name)}
Switchport: Enabled
Administrative Mode: {mode}
Operational Mode: {mode}
MAC Address Learning: enabled
Dot1q ethertype/TPID: 0x8100 (active)
Dot1q Vlan Tag Required (Administrative/Operational): No/No
Access Mode VLAN: {p['vlan'] if mode != 'trunk' else 1} ({VLANS.get(p['vlan'], 'inactive') if mode != 'trunk' else 'default'})
Trunking Native Mode VLAN: {p['native']} ({VLANS.get(p['native'], 'default')})
Administrative Native VLAN tagging: disabled
Trunking VLANs Enabled: {p['allowed'] if mode == 'trunk' else 'ALL'}
Static Trunk Groups:
Dynamic Trunk Groups:
Source interface filtering: enabled
""")
    return "\n".join(out)


def r_lldp(d):
    out = []
    for local, other, rport in d["lldp"]:
        caps = "Bridge, Router" if other["role"] != "access" else "Bridge"
        out.append(f"""Interface {local} detected 1 LLDP neighbors:

  Neighbor {dotted(other['base_mac'])}/"{rport}", age 7 seconds
  Discovered 3 days, 4:05:00 ago; Last changed 3 days, 4:05:00 ago
  - Chassis ID type: MAC address (4)
    Chassis ID     : {dotted(other['base_mac'])}
  - Port ID type: Interface name (5)
    Port ID     : "{rport}"
  - Time To Live: 120 seconds
  - Port Description: "{rport}"
  - System Name: "{other['name']}"
  - System Description: "{sys_descr(other)}"
  - System Capabilities : {caps}
    Enabled Capabilities: {caps}
  - Management Address Subtype: IPv4 (1)
    Management Address        : {other['ip']}
    Interface Number Subtype  : ifIndex (2)
    Interface Number          : 5
    OID String                :
""")
    return "\n".join(out)


def r_route(d):
    rows = ["", "VRF: default", "Codes: C - connected, S - static, K - kernel,", "       O - OSPF, IA - OSPF inter area, E1 - OSPF external type 1,",
            "       E2 - OSPF external type 2, B - Other BGP Routes,", "       B I - iBGP, B E - eBGP, NG - Nexthop Group Static Route", "",
            "Gateway of last resort:", " S        0.0.0.0/0 [1/0] via 10.0.99.1, Vlan99", ""]
    for name, p in ports(d):
        if p.get("ip"):
            ip, ln = p["ip"].split("/")
            net = ip.rsplit(".", 1)[0] + "." + str(int(ip.rsplit(".", 1)[1]) & ~1) if ln == "31" else ip
            rows.append(f" C        {net}/{ln} is directly connected, {name}")
    rows.append(f" C        10.0.99.0/24 is directly connected, Vlan99")
    return "\n".join(rows) + "\n\n"


def r_vlan(d):
    rows = ["VLAN  Name                             Status    Ports", "----- -------------------------------- --------- -------------------------------"]
    for v, n in VLANS.items():
        members = [short(nm) for nm, p in ports(d) if not p["routed"] and ((p["mode"] == "access" and p["vlan"] == v) or (p["mode"] == "trunk" and _carries(p, v)))]
        chunks = [", ".join(members[i:i + 4]) for i in range(0, len(members), 4)] or [""]
        rows.append(f"{v:<5} {n:<32} active    {chunks[0]}".rstrip())
        for c in chunks[1:]:
            rows.append(" " * 49 + c)
    return "\n".join(rows) + "\n"


def r_mac(d):
    rows = ["          Mac Address Table", "------------------------------------------------------------------", "",
            "Vlan    Mac Address       Type        Ports      Moves   Last Move", "----    -----------       ----        -----      -----   ---------"]
    for vlan, mac, port, _t in sorted(d["macs"], key=lambda r: (r[0], r[1])):
        rows.append(f"{vlan:>4}    {dotted(mac)}    DYNAMIC     {short(port):<10} 1       3 days, 4:05:11 ago")
    rows.append(f"Total Mac Addresses for this criterion: {len(d['macs'])}")
    return "\n".join(rows) + "\n"


def r_arp(d):
    return ("Address         Age (sec)  Hardware Addr   Interface\n"
            f"10.255.1.1        0:00:07  {dotted(mac_for('DC-LEAF-2', 'Ethernet1/50'))}  Ethernet50/1\n"
            f"10.0.99.1         0:01:12  {dotted(mac_for('CORE-1', 'base', oui='00a3d1'))}  Vlan99, Ethernet49/1\n")


def r_cpu(d):
    h = d["health"]
    return f"""top - 08:58:12 up 41 days,  3:12,  0 users,  load average: 0.31, 0.42, 0.40
Tasks: 301 total,   1 running, 300 sleeping,   0 stopped,   0 zombie
%Cpu(s): {h['cpu']}.0 us,  1.2 sy,  0.0 ni, {99 - h['cpu']}.8 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem : {h['mem_total'] // 1024} total, {(h['mem_total'] - h['mem_used']) // 1024} free, {h['mem_used'] // 1024} used
"""


def r_env_power(d):
    rows = ["Power                                Input    Output   Output", "Supply Model            Capacity   Current  Current   Power Status",
            "------ ---------------- -------- -------- -------- -------- -------------"]
    for i, (_s, pid, st) in enumerate(d["health"]["psus"], start=1):
        ok = st == "OK"
        rows.append(f"{i:<6} {pid:<16} {'500W':>8} {'0.62A' if ok else '0.00A':>8} {'9.80A' if ok else '0.00A':>8} {'118.0W' if ok else '0.0W':>8} {'Ok' if ok else 'Power Loss'}")
    return "\n".join(rows) + "\n"


def r_env_cooling(d):
    rows = ["System cooling status is: " + ("Ok" if all(st == "OK" for _n, st in d["health"]["fans"]) else "Fan Failure"),
            "Ambient temperature: 24C", "Airflow: port-side intake", "", "                 Config Actual        Speed",
            "Fan Status       Speed  Speed  Uptime Stability Uptime", "---- ------------ ------ ------ ------ --------- -------"]
    for i, (_n, st) in enumerate(d["health"]["fans"], start=1):
        rows.append(f"{i}/1  {'Ok' if st == 'OK' else 'Failed':<12} 50%    50%    41 days Stable    41 days")
    return "\n".join(rows) + "\n"


def r_env_temp(d):
    t = d["health"]["temp"]
    return (f"System temperature status is: {'Ok' if t < 50 else 'Overheating'}\n\n"
            "                                         Alert  Critical               Alert\n"
            "Sensor   Description                Temp  Limit  Limit    State        Count Last Alert\n"
            "------- ------------------------- ------ ------ -------- ------------ ----- ----------\n"
            f"1       CPU core                  {t:>5}C   95C      105C ok               0 never\n")


def r_config(d):
    f = d["flags"]
    L = ["! Command: show running-config", "! device: " + d["name"] + f" ({d['model']}, EOS-{d['ver']})", "!", "! boot system flash:/EOS-" + d["ver"] + ".swi", "!",
         "no aaa root", "!", "username admin privilege 15 role network-admin secret sha512 $6$abc", "!", "transceiver qsfp default-mode 4x10G", "!",
         f"hostname {d['name']}", "ip name-server vrf default 10.50.1.53", "!", "spanning-tree mode mstp", "!"]
    if f.get("telnet"):
        L += ["management telnet", "   no shutdown", "!"]
    L += ["management api http-commands", "   no shutdown", "!", "snmp-server community vmap-lab ro"]
    if f.get("snmp_public"):
        L.append("snmp-server community public ro")
    L += ["!", "ntp server 10.50.1.1", "logging host 10.50.1.20", "!"]
    for v, n in VLANS.items():
        if v != 1:
            L += [f"vlan {v}", f"   name {n}", "!"]
    for name, p in ports(d):
        L.append(f"interface {name}")
        if p["desc"]:
            L.append(f"   description {p['desc']}")
        if p["status"] == "disabled":
            L.append("   shutdown")
        if p["routed"]:
            L += [f"   mtu {p.get('mtu', 1500)}", "   no switchport", f"   ip address {p['ip']}"]
        elif p["mode"] == "trunk":
            L += [f"   switchport trunk allowed vlan {p['allowed']}", "   switchport mode trunk"]
        else:
            L += [f"   switchport access vlan {p['vlan']}", "   spanning-tree portfast"]
            if p.get("bpdu"):
                L.append("   spanning-tree bpduguard enable")
        L += ["   " + x for x in p.get("extra", [])]
        L.append("!")
    L += ["interface Management1", f"   ip address {d['ip']}/24", "!", "interface Vlan99", "   ip address 10.0.99.21/24", "!",
          "ip routing", "!", "ip route 0.0.0.0/0 10.0.99.1", "!"]
    L += list(d.get("extra_global", []))
    L.append("end")
    removed = set(d.get("removed_global", []))
    return "\n".join(l for l in L if l.startswith(" ") or l.strip() not in removed) + "\n"


def r_dir(d, fs="flash:"):
    files = d.setdefault("flash", {})
    rows = [f"Directory of {fs}/", "", f"       -rwx   912345678           Oct  2 08:00  EOS-{d['ver']}.swi"]
    for n, sz in files.items():
        rows.append(f"       -rwx {sz:>11}           Nov 12 08:00  {n}")
    return "\n".join(rows) + f"\n\n3957878784 bytes total ({3957878784 - 912345678 - sum(files.values())} bytes free)\n"


def r_boot(d):
    return f"Software image: flash:/{d.get('boot_file') or 'EOS-' + d['ver'] + '.swi'}\nConsole speed: (not set)\nAboot password (encrypted): (not set)\nMemory test iterations: (not set)\n"


def commands(D):
    return {"show version": r_version, "show running-config": r_config, "show interfaces": r_interfaces, "show interfaces status": r_status,
            "show interfaces switchport": r_switchport, "show lldp neighbors detail": r_lldp, "show ip route vrf all": r_route, "show ip route": r_route,
            "show vlan": r_vlan, "show mac address-table": r_mac, "show ip arp vrf all": r_arp, "show ip arp": r_arp,
            "show processes top once": r_cpu, "show environment power": r_env_power, "show environment cooling": r_env_cooling,
            "show environment temperature": r_env_temp, "show boot-config": r_boot}


KEYMAP = {"version": "show version", "running": "show running-config", "interfaces": "show interfaces", "status": "show interfaces status",
          "switchport": "show interfaces switchport", "lldp": "show lldp neighbors detail", "route": "show ip route vrf all", "vlan": "show vlan",
          "mac": "show mac address-table", "arp": "show ip arp vrf all", "cpu": "show processes top once", "power": "show environment power",
          "cooling": "show environment cooling", "temp": "show environment temperature"}


def outputs_for(d, D):
    c = commands(D)
    return {k: c[v](d) for k, v in KEYMAP.items()}
