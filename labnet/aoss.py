"""Aruba AOS-S (ProCurve: 2530/2930F/3810M/5400R) command output for the lab network."""
import re

from .ios import sys_descr
from .network import VLANS, _carries, mac_for


def _nat(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", s)]


def ports(d):
    return sorted(d["ports"].items(), key=lambda kv: _nat(kv[0]))


def hpmac(m):
    return f"{m[0:6]}-{m[6:12]}"


def ranges(nums):
    nums = sorted(int(n) for n in nums)
    out, i = [], 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out.append(str(nums[i]) if i == j else f"{nums[i]}-{nums[j]}")
        i = j + 1
    return ",".join(out)


def model_pid(d):
    pid, _, name = d["model"].partition(" ")
    return pid, name


def r_system(d):
    h = d["health"]
    up = d.get("uptime_text") or "41 days"
    days = up.split(",")[0]
    return f"""
 Status and Counters - General System Information

  System Name        : {d['name']}
  System Contact     :
  System Location    : Building 9

  MAC Age Time (sec) : 300

  Time Zone          : 0
  Daylight Time Rule : None

  Software revision  : {d['ver']:<20} Base MAC Addr      : {hpmac(d['base_mac'])}
  ROM Version        : WC.16.01.0010        Serial Number      : {d['serial']}

  Up Time            : {days:<20} Memory   - Total   : {h['mem_total']:,}
  CPU Util (%)       : {h['cpu']:<20}           Free    : {h['mem_total'] - h['mem_used']:,}

  IP Mgmt  - Pkts Rx : 1,234,567            Packet   - Total   : 6600
             Pkts Tx : 1,122,334            Buffers    Free    : 4877
                                                       Lowest  : 4810
                                                       Missed  : 0
"""


def r_modules(d):
    pid, name = model_pid(d)
    return f"""
 Status and Counters - Module Information

  Chassis: {name} {pid}         Serial Number:   {d['serial']}

  Slot     Module Description                  Serial Number    Status
  -------- ----------------------------------- ---------------- -------
"""


def r_brief(d):
    rows = ["", " Status and Counters - Port Status", "", "                          | Intrusion                           MDI  Flow Bcast",
            "  Port         Type       | Alert     Enabled Status Mode       Mode Ctrl Limit",
            "  ------------ ---------- + --------- ------- ------ ---------- ---- ---- -----"]
    for name, p in ports(d):
        up = p["status"] == "connected"
        typ = "SFP+SR" if int(name) > 48 else "100/1000T"
        mode = {10: "10", 100: "100", 1000: "1000", 10000: "10Gig"}.get(p["speed"], "1000") + ("HDx" if p["duplex"] == "half" else "FDx")
        if int(name) > 48:
            mode = "10GigFD"
        rows.append(f"  {name:<12} {typ:<10} | No        {'No ' if p['status'] == 'disabled' else 'Yes'}     {'Up  ' if up else 'Down'}   {mode:<10} {'NA  ' if int(name) > 48 else 'MDIX'} off  0")
    return "\n".join(rows) + "\n"


def r_counters(d):
    rows = ["", " Status and Counters - Port Counters", "", "                                                                 Flow Bcast",
            "  Port         Total Bytes    Total Frames   Errors Rx Drops Tx  Ctrl Limit",
            "  ------------ -------------- -------------- --------- --------- ---- -----"]
    for name, p in ports(d):
        rows.append(f"  {name:<12} {'2,123,456,789':<14} {'1,234,567':<14} {p['in_err'] + p['crc']:<9,} {p['drops']:<9,} off  0")
    return "\n".join(rows) + "\n"


def r_lldp(d):
    out = ["", " LLDP Remote Device Information Detail", ""]
    for local, other, rport in d["lldp"]:
        out.append(f"""  Local Port   : {local}
  ChassisType  : mac-address
  ChassisId    : {hpmac(other['base_mac'])}
  PortType     : interface-name
  PortId       : {rport}
  SysName      : {other['name']}
  System Descr : {sys_descr(other)}
  PortDescr    : {rport}
  Pvid         : 1

  System Capabilities Supported  : bridge, router
  System Capabilities Enabled    : bridge, router

  Remote Management Address
     Type    : ipv4
     Address : {other['ip']}

------------------------------------------------------------------------------
""")
    return "\n".join(out)


def r_route(d):
    return """
                                IP Route Entries

  Destination        Gateway         VLAN Type      Sub-Type   Metric     Dist.
  ------------------ --------------- ---- --------- ---------- ---------- -----
  0.0.0.0/0          10.0.99.1       99   static               1          1
  10.0.99.0/24       VLAN99          99   connected            1          0
  127.0.0.0/8        reject               static               0          0
  127.0.0.1/32       lo0                  connected            1          0
"""


def r_mac(d):
    rows = ["", " Status and Counters - Port Address Table", "", "  MAC Address   Port   VLAN", "  ------------- ------ ----"]
    for vlan, mac, port, _t in sorted(d["macs"], key=lambda r: (r[0], r[1])):
        rows.append(f"  {hpmac(mac)} {port:<6} {vlan}")
    return "\n".join(rows) + "\n"


def r_arp(d):
    return ("\n IP ARP table\n\n  IP Address       MAC Address       Type    Port\n  ---------------  ----------------- ------- ----\n"
            f"  10.0.99.1        {hpmac(mac_for('CORE-1', 'base', oui='00a3d1'))}     dynamic 49\n")


def r_power(d):
    rows = ["", " Power Supply Status:", "", "  Member  PS#   Model     Serial      State           AC/DC  + V        Wattage   Max",
            "  ------- ----- --------- ----------- --------------- ----------------- --------- ------"]
    for i, (_s, _pid, st) in enumerate(d["health"]["psus"][:1], start=1):
        rows.append(f"  1       {i}     JL256A    {d['serial']} {'Powered' if st == 'OK' else 'Aux Failed':<15} AC 120V/240V        45       370")
    return "\n".join(rows) + "\n\n  1 / 1 supply bays delivering power.\n"


def r_fans(d):
    rows = ["", " Fan Information", "  Num  | State        | Failures  ", "-------+--------------+----------"]
    for i, (_n, st) in enumerate(d["health"]["fans"][:2], start=1):
        rows.append(f"Sys-{i}  | {'Fan OK' if st == 'OK' else 'Fan Failed':<12} | {0 if st == 'OK' else 1}")
    return "\n".join(rows) + "\n\n0 / 2 Fans in Failure State\n0 / 2 Fans have been in Failure State\n"


def r_temp(d):
    t = d["health"]["temp"]
    return (f"\n System Air Temperatures\n  Temp   | Current  Max  Min\n  Sensor | Temp     Temp Temp   Threshold OverTemp\n"
            f"  -------+---------+-----+-----+----------+---------\n  Chassis | {t}C     {t + 6}C  {t - 10}C  55C        NO\n")


def r_flash(d):
    sec = d.get("secondary_version") or d["ver"]
    return f"""Image           Size (bytes) Date     Version
--------------- ------------ -------- --------------------
Primary Image   :   29871622 08/14/23 {d['ver']}
Secondary Image :   29871622 08/14/23 {sec}

Boot ROM Version
----------------
Primary Boot ROM Version   : WC.16.01.0010
Secondary Boot ROM Version : WC.16.01.0010

Default Boot Image   : {d.get('default_boot', 'Primary')}
Default Boot ROM     : Primary
"""


def r_version(d):
    return f"""Image stamp:    /ws/swbuildm/rel_tacoma_qaoff/code/build/anm(swbuildm_rel_tacoma_qaoff_rel_tacoma)
                Aug 14 2023 10:20:00
                {d['ver']}
                1026
Boot Image:     {d.get('default_boot', 'Primary')}

Boot ROM Version:    WC.16.01.0010
Active Boot ROM:     Primary
"""


def r_config(d):
    f = d["flags"]
    pid, _name = model_pid(d)
    L = [f"; {pid} Configuration Editor; Created on release #{d['ver']}", "; Ver #14:41.44.00.04.19.02.13.98.82.34.61.18.28.f3.84.9c.63.ff.37.27:05",
         f'hostname "{d["name"]}"', f"module 1 type {pid.lower()}", 'snmp-server community "vmap-lab" unrestricted']
    if f.get("snmp_public"):
        L.append('snmp-server community "public" unrestricted')
    if not f.get("telnet"):
        L.append("no telnet-server")
    if not f.get("http"):
        L.append("no web-management")
    L += ["timesync ntp", "ntp unicast", "ntp server 10.50.1.1 iburst", "ntp enable", "logging 10.50.1.20", "ip default-gateway 10.0.99.1"]
    for name, p in ports(d):
        lines = []
        if p["desc"]:
            lines.append(f'   name "{p["desc"]}"')
        if p["status"] == "disabled":
            lines.append("   disable")
        if p.get("poe_off"):
            lines.append("   no power-over-ethernet")
        lines += ["   " + x for x in p.get("extra", [])]
        if lines:
            L += [f"interface {name}"] + lines + ["   exit"]
    for v, n in VLANS.items():
        untagged = [nm for nm, p in ports(d) if p["mode"] == "access" and p["vlan"] == v]
        tagged = [nm for nm, p in ports(d) if p["mode"] == "trunk" and v != p["native"] and _carries(p, v) and v not in (999,)]
        if v == 1:
            untagged += [nm for nm, p in ports(d) if p["mode"] == "trunk" and p["native"] == 1]
        L += [f"vlan {v}", f'   name "{"DEFAULT_VLAN" if v == 1 else n}"']
        if untagged:
            L.append(f"   untagged {ranges(untagged)}")
        if tagged:
            L.append(f"   tagged {ranges(tagged)}")
        if v == 99:
            L.append(f"   ip address {d['ip']} 255.255.255.0")
        else:
            L.append("   no ip address")
        L.append("   exit")
    edge = ranges(nm for nm, p in ports(d) if p["mode"] == "access")
    L += ["spanning-tree", f"spanning-tree {edge} admin-edge-port"]
    if f.get("bpdu", True):
        pass
    L += ["password manager", "password operator"]
    L += list(d.get("extra_global", []))
    removed = set(d.get("removed_global", []))
    return "\n".join(l for l in L if l.startswith(" ") or l.strip() not in removed) + "\n"


def commands(D):
    return {"show system": r_system, "show modules": r_modules, "show interfaces brief": r_brief, "show interfaces": r_counters,
            "show lldp info remote-device detail": r_lldp, "show ip route": r_route, "show mac-address": r_mac, "show arp": r_arp,
            "show system power-supply": r_power, "show system fans": r_fans, "show system temperature": r_temp,
            "show running-config": r_config, "show flash": r_flash, "show version": r_version}


KEYMAP = {"system": "show system", "modules": "show modules", "brief": "show interfaces brief", "counters": "show interfaces",
          "lldp": "show lldp info remote-device detail", "route": "show ip route", "mac": "show mac-address", "arp": "show arp",
          "power": "show system power-supply", "fans": "show system fans", "temp": "show system temperature", "running": "show running-config"}


def outputs_for(d, D):
    c = commands(D)
    return {k: c[v](d) for k, v in KEYMAP.items()}
