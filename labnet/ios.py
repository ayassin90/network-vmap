"""Cisco IOS / IOS-XE command output for the lab network: pure functions over the device dict from network.py."""
import ipaddress
import re

from .network import VLANS, P, coloned, dotted, mac_for, stp_view

SHORT = {"GigabitEthernet": "Gi", "TenGigabitEthernet": "Te", "Port-channel": "Po", "Vlan": "Vl", "Loopback": "Lo"}


def short(n):
    for k, v in SHORT.items():
        if n.startswith(k):
            return v + n[len(k):]
    return n


def _natkey(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def _mask(cidr):
    return str(ipaddress.ip_interface(cidr).netmask)


def r_version(d):
    up = d.get("uptime_text") or ("1 year, 12 weeks, 3 days, 4 hours, 22 minutes" if d["role"] != "core" else "34 weeks, 2 days, 11 hours, 5 minutes")
    if d["os_type"] == "ios":
        return f"""Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version {d['ver']}, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2020 by Cisco Systems, Inc.
Compiled Thu 23-Apr-20 09:02 by prod_rel_team

ROM: Bootstrap program is C2960X boot loader
BOOTLDR: C2960X Boot Loader (C2960X-HBOOT-M) Version 15.2(3r)E1, RELEASE SOFTWARE (fc1)

{d['name']} uptime is {up}
System returned to ROM by power-on
System image file is "flash:{d.get('image') or 'c2960x-universalk9-mz.152-7.E4.bin'}"
Last reload reason: power-on

cisco {d['model']} (APM86XXX) processor (revision B0) with 524288K bytes of memory.
Processor board ID {d['serial']}
Last reset from power-on
1 Virtual Ethernet interface
52 Gigabit Ethernet interfaces
The password-recovery mechanism is enabled.

512K bytes of flash-simulated non-volatile configuration memory.
Base ethernet MAC Address       : 00:A3:D1:55:00:00
Model number                    : {d['model']}
System serial number            : {d['serial']}

Switch Ports Model                     SW Version            SW Image
------ ----- -----                     ----------            ----------
*    1 52    {d['model']:<25} {d['ver']:<21} C2960X-UNIVERSALK9-M

Configuration register is 0xF
"""
    train = {"17.9.4a": "Cupertino", "17.6.4": "Bengaluru", "17.3.4a": "Amsterdam"}.get(d["ver"], "Cupertino")
    soft = "ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M)" if d["role"] == "router" else "Catalyst L3 Switch Software (CAT9K_IOSXE)"
    tail = "" if d["role"] == "router" else f"""
Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 {('28' if 'C9500' in d['model'] else '65'):<5} {d['model']:<18} {d['ver']:<17} CAT9K_IOSXE           INSTALL
"""
    image = "bootflash:packages.conf" if d["role"] == "router" else "flash:packages.conf"
    return f"""Cisco IOS XE Software, Version {d['ver']}
Cisco IOS Software [{train}], {soft}, Version {d['ver']}, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Fri 14-Jul-23 03:16 by mcpre

ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.6.1r[FC2], RELEASE SOFTWARE (P)

{d['name']} uptime is {up}
Uptime for this control processor is {up}
System returned to ROM by Reload Command
System image file is "{image}"
Last reload reason: Reload Command

cisco {d['model']} (X86) processor with 1392780K/6147K bytes of memory.
Processor board ID {d['serial']}
1 Virtual Ethernet interface
52 Gigabit Ethernet interfaces
8 Ten Gigabit Ethernet interfaces
2048K bytes of non-volatile configuration memory.
16777216K bytes of physical memory.

Base Ethernet MAC Address          : 00:a3:d1:11:22:00
Model Number                       : {d['model']}
System Serial Number               : {d['serial']}
{tail}
Configuration register is 0x102
"""


def all_ifaces(d):
    out = []
    for name, p in sorted(d["ports"].items(), key=lambda kv: _natkey(kv[0])):
        out.append((name, p))
    chans = sorted({p["channel"] for p in d["ports"].values() if p["channel"]})
    for c in chans:
        mem = [p for p in d["ports"].values() if p["channel"] == c]
        out.append((f"Port-channel{c}", P(mode="trunk", allowed=mem[0]["allowed"], native=mem[0]["native"], speed=sum(m["speed"] for m in mem),
                                           in_bps=sum(m["in_bps"] for m in mem), out_bps=sum(m["out_bps"] for m in mem), desc="PO1-CORE-PEER",
                                           media="N/A", portfast=False, bpdu=False)))
    for v, ip in sorted(d["svis"].items()):
        out.append((f"Vlan{v}", P(mode="virtual", ip=ip, desc=VLANS.get(v, ""), media="", portfast=False, bpdu=False)))
    if not d["svis"] and d["role"] == "access":
        out.append(("Vlan99", P(mode="virtual", ip=f"{d['ip']}/24", desc="MGMT", media="", portfast=False, bpdu=False)))
    if d["loop"]:
        out.append(("Loopback0", P(mode="virtual", ip=f"{d['loop']}/32", desc="ROUTER-ID", media="", portfast=False, bpdu=False)))
    return out



def r_interfaces(d):
    blocks = []
    for name, p in all_ifaces(d):
        st = p["status"]
        if st == "disabled":
            head = f"{name} is administratively down, line protocol is down (disabled)"
        elif st == "err-disabled":
            head = f"{name} is down, line protocol is down (err-disabled)"
        elif st == "notconnect":
            head = f"{name} is down, line protocol is down (notconnect)"
        else:
            head = f"{name} is up, line protocol is up" + (" (connected)" if not name.startswith(("Vlan", "Loopback")) else "")
        hw = "Ethernet SVI" if name.startswith("Vlan") else "Loopback" if name.startswith("Loopback") else \
            "EtherChannel" if name.startswith("Port") else ("Ten Gigabit Ethernet" if "Ten" in name else "Gigabit Ethernet")
        speed = p["speed"] or 1000
        sp = f"{speed // 1000}Gb/s" if speed >= 1000 else f"{speed}Mb/s"
        mac = dotted(mac_for(d["name"], name))
        lines = [head, f"  Hardware is {hw}, address is {mac} (bia {mac})"]
        if p["desc"]:
            lines.append(f"  Description: {p['desc']}")
        if p["ip"]:
            lines.append(f"  Internet address is {p['ip']}")
        lines += [f"  MTU 1500 bytes, BW {speed * 1000} Kbit/sec, DLY 10 usec, ", "     reliability 255/255, txload 1/255, rxload 1/255",
                  "  Encapsulation ARPA, loopback not set", "  Keepalive set (10 sec)"]
        if not name.startswith(("Vlan", "Loopback")):
            dup = "Half-duplex" if p["duplex"] == "half" else "Full-duplex"
            lines.append(f"  {dup}, {sp}, link type is auto, media type is {p['media']}" if st == "connected" else f"  Auto-duplex, Auto-speed, media type is {p['media']}")
        lines += ["  ARP type: ARPA, ARP Timeout 04:00:00", "  Last input 00:00:01, output 00:00:00, output hang never",
                  '  Last clearing of "show interface" counters never',
                  f"  Input queue: 0/2000/0/0 (size/max/drops/flushes); Total output drops: {p['drops']}",
                  "  Queueing strategy: fifo", "  Output queue: 0/40 (size/max)",
                  f"  5 minute input rate {p['in_bps']} bits/sec, {p['in_bps'] // 4000} packets/sec",
                  f"  5 minute output rate {p['out_bps']} bits/sec, {p['out_bps'] // 4000} packets/sec",
                  "     1234567 packets input, 987654321 bytes, 0 no buffer", "     Received 12345 broadcasts (2345 multicasts)",
                  f"     0 runts, 0 giants, 0 throttles ",
                  f"     {p['in_err']} input errors, {p['crc']} CRC, 0 frame, 0 overrun, 0 ignored",
                  "     0 watchdog, 2345 multicast, 0 pause input", "     0 input packets with dribble condition detected",
                  "     2345678 packets output, 1987654321 bytes, 0 underruns",
                  f"     {p['out_err']} output errors, {p['coll']} collisions, {p['resets']} interface resets",
                  "     0 unknown protocol drops", f"     0 babbles, {p['late']} late collision, 0 deferred",
                  "     0 lost carrier, 0 no carrier, 0 pause output", "     0 output buffer failures, 0 output buffers swapped out"]
        blocks.append("\n".join(lines))
    return "\n".join(blocks) + "\n"


def r_status(d):
    rows = ["", "Port         Name               Status       Vlan       Duplex  Speed Type "]
    for name, p in all_ifaces(d):
        if name.startswith(("Vlan", "Loopback")):
            continue
        vl = "trunk" if p["mode"] == "trunk" else "routed" if p["routed"] else str(p["vlan"])
        if p["status"] == "connected":
            dup = ("a-" if p["mode"] == "access" else "") + p["duplex"]
            sp = ("a-" if p["mode"] == "access" else "") + (str(p["speed"]) if p["speed"] < 10000 else f"{p['speed'] // 1000}G")
        else:
            dup, sp = "auto", "auto"
        rows.append(f"{short(name):<12} {p['desc'][:18]:<18} {p['status']:<12} {vl:<10} {dup:>6} {sp:>6} {p['media']}")
    return "\n".join(rows) + "\n"


def r_switchport(d):
    out = []
    for name, p in all_ifaces(d):
        if name.startswith(("Vlan", "Loopback")):
            continue
        if p["routed"]:
            out.append(f"Name: {short(name)}\nSwitchport: Disabled\n")
            continue
        if p["mode"] == "trunk":
            adm, op = "trunk", "trunk" if p["status"] == "connected" else "down"
        elif p["nomode"]:
            adm, op = "dynamic auto", "static access" if p["status"] == "connected" else "down"
        else:
            adm, op = "static access", "static access" if p["status"] == "connected" else "down"
        out.append(f"""Name: {short(name)}
Switchport: Enabled
Administrative Mode: {adm}
Operational Mode: {op}
Administrative Trunking Encapsulation: dot1q
Operational Trunking Encapsulation: {'dot1q' if p['mode'] == 'trunk' else 'native'}
Negotiation of Trunking: {'Off' if p['mode'] == 'trunk' and not d['flags'].get('legacy') else 'On'}
Access Mode VLAN: {p['vlan']} ({VLANS.get(p['vlan'], 'VLAN')})
Trunking Native Mode VLAN: {p['native']} ({VLANS.get(p['native'], 'VLAN')})
Administrative Native VLAN tagging: enabled
Voice VLAN: {f"{p['voice']} (VOICE)" if p['voice'] else 'none'}
Administrative private-vlan host-association: none
Administrative private-vlan mapping: none
Administrative private-vlan trunk native VLAN: none
Administrative private-vlan trunk Native VLAN tagging: enabled
Administrative private-vlan trunk encapsulation: dot1q
Administrative private-vlan trunk normal VLANs: none
Administrative private-vlan trunk associations: none
Administrative private-vlan trunk mappings: none
Operational private-vlan: none
Trunking VLANs Enabled: {p['allowed']}
Pruning VLANs Enabled: 2-1001
Capture Mode Disabled
Capture VLANs Allowed: ALL

Protected: false
Unknown unicast blocked: disabled
Unknown multicast blocked: disabled
Appliance trust: none
""")
    return "\n".join(out)


def r_cdp(d, devs=None):
    out = []
    for local, other, rport in d["cdp"]:
        if "ports" in other:
            name, ip, plat, caps = other["name"] + ".campus.local", other["ip"], f"cisco {other['model']}", \
                "Router Switch IGMP" if other["role"] != "access" or other["svis"] else "Switch IGMP"
            if other["role"] == "router":
                caps = "Router IGMP"
            native = other["ports"].get(rport, {}).get("native", 1)
            duplex = other["ports"].get(rport, {}).get("duplex", "full")
        else:
            name, ip, plat, caps, native, duplex = other["name"], other["ip"], other["platform"], other["caps"], 0, "full"
        out.append(f"""-------------------------
Device ID: {name}
Entry address(es):
  IP address: {ip}
Platform: {plat},  Capabilities: {caps}
Interface: {local},  Port ID (outgoing port): {rport}
Holdtime : 142 sec

Version :
Cisco IOS Software

advertisement version: 2
Native VLAN: {native}
Duplex: {duplex}
Management address(es):
  IP address: {ip}
""")
    return "\n".join(out)


def r_route(d):
    if not d["routes"] and not d["svis"] and d["role"] == "access":
        return "Default gateway is 10.0.99.1\n\nHost               Gateway           Last Use    Total Uses  Interface\nICMP redirect cache is empty\n"
    lines = ["Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP",
             "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area ",
             "       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2",
             "       E1 - OSPF external type 1, E2 - OSPF external type 2, m - OMP",
             "       i - IS-IS, su - IS-IS summary, L1 - IS-IS level-1, L2 - IS-IS level-2",
             "       ia - IS-IS inter area, * - candidate default, U - per-user static route",
             "       o - ODR, P - periodic downloaded static route, H - NHRP, l - LISP",
             "       + - replicated route, % - next hop override, p - overrides from PfR", "",
             f"Gateway of last resort is {d['routes'][0][3]} to network 0.0.0.0", ""]
    for code, pfx, ad, nh, iface in d["routes"]:
        if pfx == "0.0.0.0/0":
            lines.append(f"{code:<9} {pfx} [{ad}] via {nh}" + (f", 1w2d, {iface}" if iface else ""))
    lines.append("      10.0.0.0/8 is variably subnetted, 20 subnets, 4 masks")
    conn = []
    for name, p in all_ifaces(d):
        if p["ip"] and not p["ip"].startswith("203."):
            net = ipaddress.ip_interface(p["ip"]).network
            if net.prefixlen < 32:
                conn.append(("C", str(net), name))
            conn.append(("L", p["ip"].split("/")[0] + "/32", name))
    for code, pfx, name in conn:
        lines.append(f"{code:<8} {pfx} is directly connected, {name}")
    for code, pfx, ad, nh, iface in d["routes"]:
        if pfx != "0.0.0.0/0":
            lines.append(f"{code:<8} {pfx} [{ad}] via {nh}, 1w2d, {iface}")
    if any(p["ip"] and p["ip"].startswith("203.") for p in d["ports"].values()):
        lines.append("      203.0.113.0/24 is variably subnetted, 2 subnets, 2 masks")
        lines.append("C        203.0.113.0/30 is directly connected, GigabitEthernet0/0/0")
        lines.append("L        203.0.113.2/32 is directly connected, GigabitEthernet0/0/0")
    return "\n".join(lines) + "\n"


def r_vlan(d):
    if d["role"] == "router":
        return "% Invalid input detected at '^' marker.\n"
    rows = ["", "VLAN Name                             Status    Ports", "---- -------------------------------- --------- -------------------------------"]
    for v, n in VLANS.items():
        ports = [short(k) for k, p in sorted(d["ports"].items(), key=lambda kv: _natkey(kv[0])) if p["mode"] == "access" and not p["routed"] and p["vlan"] == v]
        chunks = [ports[i:i + 4] for i in range(0, len(ports), 4)] or [[]]
        rows.append(f"{v:<4} {n:<32} active    {', '.join(chunks[0])}")
        for c in chunks[1:]:
            rows.append(" " * 48 + ", ".join(c))
    return "\n".join(rows) + "\n"


def r_etherchannel(d):
    chans = sorted({p["channel"] for p in d["ports"].values() if p["channel"]})
    head = """Flags:  D - down        P - bundled in port-channel
        I - stand-alone s - suspended
        H - Hot-standby (LACP only)
        R - Layer3      S - Layer2
        U - in use      f - failed to allocate aggregator

Number of channel-groups in use: %d
Number of aggregators:           %d

Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
""" % (len(chans), len(chans))
    rows = []
    for c in chans:
        mem = [short(k) + "(P)" for k, p in sorted(d["ports"].items()) if p["channel"] == c]
        rows.append(f"{c:<6} Po{c}(SU)         LACP        " + "      ".join(mem))
    return head + "\n".join(rows) + "\n"


def r_ospf(d):
    if not d["ospf"]:
        return ""
    rows = ["", "Neighbor ID     Pri   State           Dead Time   Address         Interface"]
    for nid, st, addr, iface in d["ospf"]:
        rows.append(f"{nid:<15} {1:>3}   {st:<15} 00:00:35    {addr:<15} {iface}")
    return "\n".join(rows) + "\n"


def r_inventory(d):
    out = (f'NAME: "Chassis", DESCR: "Cisco {d["model"]} Chassis"\nPID: {d["model"]:<18}, VID: V02  , SN: {d["serial"]}\n\n'
           f'NAME: "Power Supply Module 0", DESCR: "Switch 1 - Power Supply A"\nPID: PWR-C1-715WAC     , VID: V02  , SN: DCC2231G1{d["serial"][-3:]}\n\n')
    for name, p in sorted(d["ports"].items(), key=lambda kv: _natkey(kv[0])):
        if p.get("sfp") and p["status"] != "notconnect":
            pid, descr = p["sfp"]
            sn = "AVD" + mac_for(d["name"], name, "sfp")[6:].upper() + "X"
            out += f'NAME: "{name}", DESCR: "{descr}"\nPID: {pid:<18}, VID: V01  , SN: {sn}\n\n'
    return out


def r_config(d):
    f = d["flags"]
    legacy = f.get("legacy")
    L = ["version " + (d["ver"][:4] if not legacy else "15.2"), "service timestamps debug datetime msec", "service timestamps log datetime msec"]
    if d["role"] != "access" or not legacy:
        L.append("service password-encryption")
    L += ["!", f"hostname {d['name']}", "!"]
    if legacy:
        L += ["enable password 7 0822455D0A16", "!", "username admin privilege 15 password 7 094F471A1A0A"]
    else:
        L += ["enable algorithm-type scrypt secret 9 $9$abc$xyz", "!", "username netadmin privilege 15 algorithm-type scrypt secret 9 $9$def$uvw",
              "aaa new-model", "aaa authentication login default group tacacs+ local", "aaa authorization exec default group tacacs+ local"]
    L += ["!", "ip domain name campus.local"]
    if not legacy:
        L += ["no ip domain lookup", "login block-for 120 attempts 5 within 60", "ip ssh version 2", "no ip source-route"]
    if d["role"] == "access" and f.get("dhcp_snoop") and not legacy:
        L += ["ip dhcp snooping vlan 10,20,30,40", "ip dhcp snooping"]
    if d["role"] != "router":
        L += ["!", "spanning-tree mode " + ("pvst" if legacy else "rapid-pvst"), "spanning-tree extend system-id"]
        if not legacy:
            L += ["errdisable recovery cause bpduguard", "errdisable recovery interval 300"]
        for v, n in VLANS.items():
            if v != 1:
                L += [f"vlan {v}", f" name {n}", "!"]
    if d["role"] in ("core", "router") and not legacy:
        L += ["archive", " log config", "  logging enable", "  hidekeys", "!"]
    if not legacy:
        L.append("no vstack")
    for name, p in all_ifaces(d):
        L.append(f"interface {name}")
        if p["desc"]:
            L.append(f" description {p['desc']}")
        if name.startswith(("Vlan", "Loopback")):
            L.append(f" ip address {p['ip'].split('/')[0]} {_mask(p['ip'])}")
            if name.startswith("Vlan") and d["role"] == "core" and name != "Vlan99":
                L.append(" ip helper-address 10.0.99.50")
        elif p["routed"]:
            L += [" no switchport", f" ip address {p['ip'].split('/')[0]} {_mask(p['ip'])}"]
            if not p["ip"].startswith("203."):
                L.append(" ip ospf network point-to-point")
        elif p["mode"] == "trunk":
            if p["native"] != 1:
                L.append(f" switchport trunk native vlan {p['native']}")
            if p["allowed"] != "ALL":
                L.append(f" switchport trunk allowed vlan {p['allowed']}")
            L.append(" switchport mode trunk")
            if not legacy:
                L.append(" switchport nonegotiate")
            if p["channel"]:
                L.append(f" channel-group {p['channel']} mode active")
            if p["speed"] == 100 and p["duplex"] == "half":
                L += [" speed 100", " duplex half"]
            elif p["speed"] == 100:
                L += [" speed 100", " duplex full"]
        else:
            L.append(f" switchport access vlan {p['vlan']}")
            if not p["nomode"]:
                L.append(" switchport mode access")
            if p["voice"]:
                L.append(f" switchport voice vlan {p['voice']}")
            if p["duplex"] == "half":
                L.append(" duplex half")
            if p["storm"]:
                L += [" storm-control broadcast level 1.00", " storm-control action trap"]
            if p["portfast"]:
                L.append(" spanning-tree portfast")
            if p["bpdu"]:
                L.append(" spanning-tree bpduguard enable")
        if p["status"] == "disabled":
            L.append(" shutdown")
        if p.get("poe_off"):
            L.append(" power inline never")
        L += [" " + x for x in p.get("extra", [])]
        if p.get("removed"):
            gone = set(p["removed"])
            idx = max(i for i, l in enumerate(L) if l.startswith("interface "))
            L[idx + 1:] = [l for l in L[idx + 1:] if l.strip() not in gone]
        L.append("!")
    if d["role"] in ("core", "router"):
        L += ["router ospf 1", f" router-id {d['loop']}", " passive-interface default"]
        for name, p in all_ifaces(d):
            if p["routed"] and not (p["ip"] or "").startswith("203."):
                L.append(f" no passive-interface {name}")
        L += [" network 10.0.0.0 0.255.255.255 area 0"]
        if d["role"] == "router":
            L.append(" default-information originate")
        L.append("!")
    if d["role"] == "router":
        L += ["ip route 0.0.0.0 0.0.0.0 203.0.113.1", "!"]
    if d["role"] == "access":
        L += ["ip default-gateway 10.0.99.1", "!"]
    if f.get("http"):
        L += ["ip http server", "ip http authentication local", "ip http secure-server"]
    else:
        L += ["no ip http server", "no ip http secure-server"]
    L.append("!")
    if not legacy:
        L += ["ip access-list standard MGMT", " permit 10.0.99.0 0.0.0.255", " permit 10.50.0.0 0.0.255.255", "!"]
    if f.get("snmp_public"):
        L.append("snmp-server community public RO")
    elif not legacy:
        L += ["snmp-server group NMS v3 priv", "snmp-server community Xk9-campus-ro RO MGMT"]
    else:
        L.append("snmp-server community campus-ro RO")
    if not legacy:
        L += ["snmp-server location HQ", "!", "tacacs server ISE-1", " address ipv4 10.50.1.10", " key 7 1234567890ABCDEF", "!",
              "logging buffered 64000 informational", "logging host 10.50.1.20", "!"]
    L += ["banner login ^C", "Authorised access only. Activity is logged.", "^C", "!"] if not legacy else ["!"]
    L += ["line con 0", " exec-timeout " + ("0 0" if legacy else "10 0"), " logging synchronous"]
    L += ["line vty 0 4"]
    if not legacy:
        L += [" access-class MGMT in", " exec-timeout 10 0", " transport input ssh"]
    else:
        L += [" password 7 060506324F41", " login", " transport input all"]
    L += ["line vty 5 15"]
    L += [" access-class MGMT in", " transport input ssh"] if not legacy else [" login", " transport input telnet ssh"]
    L.append("!")
    if not legacy:
        L += ["ntp server 10.50.1.1", "ntp server 10.50.1.2"]
    L += ["!"] + list(d.get("extra_global", [])) + ["!", "end"]
    removed = set(d.get("removed_global", []))
    L = [l for l in L if l.startswith(" ") or l.strip() not in removed]
    return "Building configuration...\n\nCurrent configuration : 12345 bytes\n!\n" + "\n".join(L) + "\n"




def sys_descr(o):
    """What a device advertises as its LLDP system description / SNMP sysDescr."""
    v = o["vendor"]
    if v == "aruba":
        return f"Aruba {o['model']} {o['ver']}"
    if v == "huawei":
        return f"Huawei Versatile Routing Platform Software VRP (R) software, Version 5.170 ({o['model']} {o['ver']})"
    if v == "juniper":
        return (f"Juniper Networks, Inc. {o['model'].lower()} Ethernet Switch, kernel JUNOS {o['ver']}, Build date: 2023-06-01 00:00:00 UTC "
                "Copyright (c) 1996-2023 Juniper Networks, Inc.")
    if v == "aruba_aoss":
        return f"Aruba {o['model']} Switch, revision {o['ver']}, ROM WC.16.01.0010 (/ws/swbuildm/rel_tacoma_qaoff/code/build/anm(swbuildm_rel_tacoma_qaoff_rel_tacoma))"
    if v == "fortinet":
        return f"FortiSwitch-{o['model'][3:]} {o['ver']},build0453,230719 (GA)"
    if v == "arista":
        return f"Arista Networks EOS version {o['ver']} running on an Arista Networks {o['model']}"
    if o.get("os_type") == "nxos":
        return f"Cisco Nexus Operating System (NX-OS) Software {o['ver']}"
    return f"Cisco IOS Software, {o['model']}"


def r_lldp(d, devs=None):
    out = []
    for local, other, rport in d["lldp"]:
        caps = "B,R" if other["role"] != "access" else "B"
        desc = sys_descr(other)
        out.append(f"""------------------------------------------------
Local Intf: {short(local)}
Chassis id: {dotted(other['base_mac'])}
Port id: {rport}
Port Description: {rport}
System Name: {other['name']}

System Description: 
{desc}

Time remaining: 109 seconds
System Capabilities: {caps}
Enabled Capabilities: {caps}
Management Addresses:
    IP: {other['ip']}
Auto Negotiation - not supported
Physical media capabilities - not advertised
Media Attachment Unit type - not advertised
Vlan ID: - not advertised
""")
    if not out:
        return ""
    return "\n".join(out) + f"\n\nTotal entries displayed: {len(out)}\n"


def r_mac(d):
    rows = ["          Mac Address Table", "-------------------------------------------", "",
            "Vlan    Mac Address       Type        Ports", "----    -----------       --------    -----"]
    for vlan, mac, port, typ in sorted(d["macs"], key=lambda r: (r[0], r[1])):
        rows.append(f"{vlan:>4}    {dotted(mac)}    {typ:<11} {short(port)}")
    rows.append(f"Total Mac Addresses for this criterion: {len(d['macs'])}")
    return "\n".join(rows) + "\n"


def r_arp(d):
    if not d["arp"]:
        return ""
    rows = ["Protocol  Address          Age (min)  Hardware Addr   Type   Interface"]
    for ip, mac, iface in d["arp"]:
        rows.append(f"Internet  {ip:<16} {'12':>9}   {dotted(mac)}  ARPA   {iface}")
    return "\n".join(rows) + "\n"


def _stp(d):
    return d.get("_stp") or {}


def r_stp(d):
    out = []
    for v, s in sorted(_stp(d).items()):
        out.append(f"""VLAN{v:04d}
  Spanning tree enabled protocol rstp
  Root ID    Priority    {s['root_prio']}
             Address     {dotted(s['root_mac'])}
""" + ("             This bridge is the root\n" if s["is_root"] else f"""             Cost        {s['cost']}
             Port        1 ({s['root_port']})
""") + f"""             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    {s['my_prio']}  (priority {s['my_prio'] - v} sys-id-ext {v})
             Address     {dotted(s['my_mac'])}
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec
             Aging Time  300 sec

Interface           Role Sts Cost      Prio.Nbr Type
------------------- ---- --- --------- -------- --------------------------------""")
        for i, (p, (role, st)) in enumerate(sorted(s["roles"].items(), key=lambda kv: _natkey(kv[0])), start=1):
            out.append(f"{short(p):<19} {role} {st} {2 if 'Ten' in p else 4:<9} 128.{i:<4} P2p")
        out.append("\n")
    return "\n".join(out)


def r_stp_root(d):
    rows = ["                                        Root    Hello Max Fwd", "Vlan                   Root ID          Cost    Time  Age Dly  Root Port",
            "---------------- -------------------- --------- ----- --- ---  ------------"]
    for v, s in sorted(_stp(d).items()):
        rows.append(f"VLAN{v:04d}         {s['root_prio']:>5} {dotted(s['root_mac'])} {s['cost']:>9} {2:>4} {20:>4} {15:>3}  {short(s['root_port'])}")
    return "\n".join(rows) + "\n"


def r_stp_detail(d):
    out = []
    for v, s in sorted(_stp(d).items()):
        out.append(f" VLAN{v:04d} is executing the rstp compatible Spanning Tree protocol")
        out.append(f"  Bridge Identifier has priority {s['my_prio'] - v}, sysid {v}, address {dotted(s['my_mac'])}")
        out.append(f"  Number of topology changes {s['tc']} last change occurred {s['tc_ago']} ago")
        if s["tc_from"]:
            out.append(f"          from {s['tc_from']}")
    return "\n".join(out) + "\n"


def r_transceiver(d):
    rows = ["If device is externally calibrated, only calibrated values are printed.",
            "++ : high alarm, +  : high warning, -  : low warning, -- : low alarm.",
            "NA or N/A: not applicable, Tx: transmit, Rx: receive.", "mA: milliamperes, dBm: decibels (milliwatts).", "",
            "                                           Optical   Optical",
            "            Temperature  Voltage  Current  Tx Power  Rx Power",
            "Port        (Celsius)    (Volts)  (mA)     (dBm)     (dBm)",
            "---------   -----------  -------  -------  --------  --------"]
    for name, p in sorted(d["ports"].items(), key=lambda kv: _natkey(kv[0])):
        if not p.get("sfp") or p["status"] == "notconnect":
            continue
        h = int(mac_for(d["name"], name, "dom")[6:8], 16)
        rx = p.get("sfp_rx", round(-2.0 - (h % 30) / 10, 1))
        flag = " --" if rx <= -14 else (" -" if rx <= -10 else "")
        rows.append(f"{short(name):<11} {30 + h % 12:>6}.{h % 10}       {3.28:.2f}     {5.5 + (h % 20) / 10:.1f}     {-2.1 - (h % 9) / 10:>5.1f}     {rx:>5.1f}{flag}")
    return "\n".join(rows) + "\n"


def r_power(d):
    poe = [(n, p) for n, p in sorted(d["ports"].items(), key=lambda kv: _natkey(kv[0])) if n.startswith("GigabitEthernet1/0/")]
    if not poe or d["role"] != "access":
        return "% Invalid input detected at '^' marker.\n"
    used = sum(p["poe"][2] for _, p in poe if p.get("poe") and not p.get("poe_off") and not p.get("poe_fault") and p["status"] == "connected")
    rows = ["", "Module   Available     Used     Remaining", "          (Watts)     (Watts)    (Watts)", "------   ---------   --------   ---------",
            f"1           740.0      {used:>5.1f}       {740 - used:>5.1f}",
            "Interface Admin  Oper       Power   Device              Class Max", "                            (Watts)",
            "--------- ------ ---------- ------- ------------------- ----- ----"]
    for n, p in poe:
        admin = "off" if p.get("poe_off") else "auto"
        if p.get("poe") and p.get("poe_fault"):
            rows.append(f"{short(n):<9} {admin:<6} {'faulty':<10} {0.0:>5.1f}   {'n/a':<19} {'n/a':<5} 30.0")
        elif p.get("poe") and p["status"] == "connected" and not p.get("poe_off"):
            rows.append(f"{short(n):<9} {admin:<6} {'on':<10} {p['poe'][2]:>5.1f}   {p['poe'][0]:<19} {p['poe'][1]:<5} 30.0")
        else:
            rows.append(f"{short(n):<9} {admin:<6} {'off':<10} {0.0:>5.1f}   {'n/a':<19} {'n/a':<5} 30.0")
    return "\n".join(rows) + "\n"


def r_dir(d, fs="flash:"):
    files = d.setdefault("flash", {"packages.conf": 7531, "vlan.dat": 3436, "nvram_config": 2097152})
    rows = [f"Directory of {fs}/", ""]
    for i, (n, size) in enumerate(sorted(files.items()), start=1):
        rows.append(f"{1000 + i:>7}  -rw-  {size:>12}  Nov 11 2026 08:00:00 +00:00  {n}")
    total, used = 11353194496, sum(files.values())
    rows += ["", f"{total} bytes total ({total - used - 2_400_000_000} bytes free)"]
    return "\n".join(rows) + "\n"


def r_cpu(d):
    c = d["health"]["cpu"]
    return f"CPU utilization for five seconds: {c + 2}%/0%; one minute: {c + 1}%; five minutes: {c}%\n"


def r_mem(d):
    h = d["health"]
    return f"Processor Pool Total: {h['mem_total']:>11} Used: {h['mem_used']:>11} Free: {h['mem_total'] - h['mem_used']:>11}\n"


def r_env(d):
    h = d["health"]
    out = [f"{n} is {st}" for n, st in h["fans"]]
    out += [f"SYSTEM TEMPERATURE is {'OK' if h['temp_state'] == 'GREEN' else 'WARNING'}",
            f"System Temperature Value: {h['temp']} Degree Celsius", f"System Temperature State: {h['temp_state']}",
            "Yellow Threshold : 46 Degree Celsius", "Red Threshold    : 56 Degree Celsius", "",
            "SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts",
            "--  ------------------  ----------  ---------------  -------  -------  -----"]
    for slot, pid, st in h["psus"]:
        if st == "Not Present":
            out.append(f"{slot:<3} Not Present")
        else:
            out.append(f"{slot:<3} {pid:<19} DCC{slot}{d['serial'][-5:]:<5}  {st:<16} {'Good' if st == 'OK' else 'Bad':<8} {'Good' if st == 'OK' else 'n/a':<8} 715")
    return "\n".join(out) + "\n"


# command -> renderer. The mock switch and the demo loader both use this table.
def commands(D):
    return {
        "show version": r_version, "show inventory": r_inventory, "show running-config": r_config,
        "show interfaces": r_interfaces, "show interfaces status": r_status, "show interfaces switchport": r_switchport,
        "show cdp neighbors detail": lambda d: r_cdp(d, D), "show lldp neighbors detail": r_lldp, "show ip route": r_route,
        "show vlan brief": r_vlan, "show etherchannel summary": lambda d: r_etherchannel(d) if any(p["channel"] for p in d["ports"].values()) else "",
        "show ip ospf neighbor": r_ospf, "show mac address-table": r_mac, "show ip arp": r_arp,
        "show spanning-tree": r_stp, "show spanning-tree root": r_stp_root, "show spanning-tree detail": r_stp_detail,
        "show interfaces transceiver": r_transceiver, "show power inline": r_power,
        "show processes cpu": r_cpu, "show processes memory": r_mem, "show environment all": r_env,
    }


def outputs_for(d, D):
    """The collection keys used by apps/drivers/cisco.py -> rendered text."""
    d["_stp"] = stp_view(D, d)
    c = commands(D)
    keymap = {"version": "show version", "inventory": "show inventory", "running": "show running-config", "interfaces": "show interfaces",
              "status": "show interfaces status", "switchport": "show interfaces switchport", "cdp": "show cdp neighbors detail",
              "lldp": "show lldp neighbors detail", "route": "show ip route", "vlan": "show vlan brief", "etherchannel": "show etherchannel summary",
              "ospf": "show ip ospf neighbor", "mac": "show mac address-table", "arp": "show ip arp", "stp": "show spanning-tree",
              "stp_root": "show spanning-tree root", "stp_detail": "show spanning-tree detail", "transceiver": "show interfaces transceiver",
              "power": "show power inline", "cpu": "show processes cpu", "mem": "show processes memory", "env": "show environment all"}
    out = {k: c[v](d) for k, v in keymap.items()}
    if d["role"] == "router":
        for k in ("vlan", "stp", "stp_root", "stp_detail", "power", "mac"):
            out[k] = ""
    return out
