"""The sample campus as plain data (no Django). Used by the demo loader and by the mock-switch lab (tools/mocklab).

Two Catalyst 9500 cores (Po1), four Catalyst 9300 access switches dual-homed to the cores, a 2960-X daisy-chained behind
ACC-4 (duplex mismatch), an Aruba CX 6300 (ACC-6, LLDP), and an ISR 4331 WAN router. Phones, APs, PCs and printers sit
on access ports. Problems are planted on purpose so every check has something to find."""
import hashlib
import random

VLANS = {1: "default", 10: "USERS", 20: "VOICE", 30: "WIFI", 40: "PRINTERS", 60: "SERVERS", 99: "MGMT", 999: "NATIVE-UNUSED"}
DEMO_IPS = {"ACC-7": "10.0.99.17", "CORE-1": "10.0.99.1", "CORE-2": "10.0.99.2", "WAN-RTR": "10.255.255.1", "ACC-1": "10.0.99.11", "ACC-2": "10.0.99.12",
            "ACC-3": "10.0.99.13", "ACC-4": "10.0.99.14", "ACC-5": "10.0.99.15", "ACC-6": "10.0.99.16", "ACC-8": "10.0.99.18",
            "ACC-9": "10.0.99.19", "ACC-10": "10.0.99.20", "DC-LEAF-1": "10.0.99.21", "DC-LEAF-2": "10.0.99.22"}
LAB_IPS = {"ACC-7": "172.31.99.17", "CORE-1": "172.31.99.1", "CORE-2": "172.31.99.2", "WAN-RTR": "172.31.99.3", "ACC-1": "172.31.99.11", "ACC-2": "172.31.99.12",
           "ACC-3": "172.31.99.13", "ACC-4": "172.31.99.14", "ACC-5": "172.31.99.15", "ACC-6": "172.31.99.16", "ACC-8": "172.31.99.18",
           "ACC-9": "172.31.99.19", "ACC-10": "172.31.99.20", "DC-LEAF-1": "172.31.99.21", "DC-LEAF-2": "172.31.99.22"}


def mac_for(*parts, oui="00a3d1"):
    h = hashlib.md5("|".join(map(str, parts)).encode()).hexdigest()
    return f"{oui}{h[:6]}"


def dotted(m):
    return f"{m[0:4]}.{m[4:8]}.{m[8:12]}"


def coloned(m):
    return ":".join(m[i:i + 2] for i in range(0, 12, 2))


def P(**kw):
    base = dict(desc="", mode="access", vlan=10, voice=None, native=1, allowed="ALL", status="connected", speed=1000, duplex="full",
                crc=0, in_err=0, out_err=0, late=0, coll=0, drops=0, in_bps=0, out_bps=0, ip=None, channel=None, media="10/100/1000BaseTX",
                portfast=True, bpdu=True, storm=False, nomode=False, routed=False, resets=2, sfp=None, poe=None, extra=[], removed=[],
                flap=False)
    base.update(kw)
    base["extra"] = list(base["extra"])
    base["removed"] = list(base["removed"])
    return base


def build(ips=None):
    ips = ips or DEMO_IPS
    rnd = random.Random(7)
    D = {}

    def dev(name, model, ver, role, os_type="iosxe", vendor="cisco", **flags):
        D[name] = {"name": name, "ip": ips[name], "model": model, "ver": ver, "role": role, "os_type": os_type, "vendor": vendor,
                   "ports": {}, "cdp": [], "lldp": [], "routes": [], "ospf": [], "svis": {}, "loop": None, "flags": flags,
                   "serial": "FOC" + str(rnd.randint(2200, 2299)) + "X" + str(rnd.randint(1000, 9999)),
                   "base_mac": mac_for(name, "base", oui="00a3d1" if vendor == "cisco" else "883a30"),
                   "stp_prio": {}, "macs": [], "arp": [], "extra_global": [], "removed_global": [], "files": {}, "uptime_s": 0}
        return D[name]

    c1 = dev("CORE-1", "C9500-24Y4C", "17.9.4a", "core", loop="10.255.255.11")
    c2 = dev("CORE-2", "C9500-24Y4C", "17.9.4a", "core", loop="10.255.255.12", snmp_public=True)
    wan = dev("WAN-RTR", "ISR4331/K9", "17.3.4a", "router", loop="10.255.255.1")
    accs = [dev(f"ACC-{i}", "C9300-48P", "17.6.4", "access", http=(i in (1, 3)), dhcp_snoop=(i != 2), bpdu=(i != 3)) for i in range(1, 5)]
    a5 = dev("ACC-5", "WS-C2960X-48FPD-L", "15.2(7)E4", "access", os_type="ios", legacy=True, http=True)
    a6 = dev("ACC-6", "JL665A 6300F 48G CL4 PoE 4SFP56 Sw", "FL.10.11.1021", "access", os_type="aoscx", vendor="aruba")
    a6["serial"] = "SG" + str(rnd.randint(10, 99)) + "KLM" + str(rnd.randint(1000, 9999))
    a7 = dev("ACC-7", "S5735-L48P4X-A", "V200R021C00SPC100", "access", os_type="vrp", vendor="huawei", telnet=True)
    a7["serial"] = "2102353XYZ10L" + str(rnd.randint(1000, 9999))
    # second wave of vendors (own random stream so the original lab stays identical)
    r2 = random.Random(11)
    keep = rnd.getstate()
    a8 = dev("ACC-8", "EX2300-48P", "21.4R3-S5.4", "access", os_type="junos", vendor="juniper", telnet=False)
    a8["serial"] = "JW36" + str(r2.randint(10000000, 99999999))
    a8["base_mac"] = mac_for("ACC-8", "base", oui="2c6bf5")
    a9 = dev("ACC-9", "JL256A 2930F-48G-PoE+-4SFP+", "WC.16.10.0012", "access", os_type="aoss", vendor="aruba_aoss", http=True, telnet=True)
    a9["serial"] = "SG9" + str(r2.randint(10, 99)) + "J0" + str(r2.randint(1000, 9999))
    a9["base_mac"] = mac_for("ACC-9", "base", oui="9c8cd8")
    a10 = dev("ACC-10", "FS-148F", "v7.2.5", "access", os_type="fortiswitch", vendor="fortinet", http=True)
    a10["serial"] = "S148FFTF2" + str(r2.randint(1000000, 9999999))
    a10["base_mac"] = mac_for("ACC-10", "base", oui="704ca5")
    l1 = dev("DC-LEAF-1", "DCS-7050SX3-48YC8", "4.29.2F", "datacenter", os_type="eos", vendor="arista")
    l1["serial"] = "JPE2" + str(r2.randint(1000000, 9999999))
    l1["base_mac"] = mac_for("DC-LEAF-1", "base", oui="444ca8")
    l2 = dev("DC-LEAF-2", "N9K-C93180YC-FX", "9.3(8)", "datacenter", os_type="nxos", snmp_public=True)
    l2["serial"] = "FDO2" + str(r2.randint(1000000, 9999999))
    rnd.setstate(keep)
    # STP design: CORE-1 root for odd-ish VLANs, CORE-2 for the others. VLAN 1 nobody tuned -> lowest MAC wins (ACC-5).
    for v in VLANS:
        c1["stp_prio"][v] = 24576 if v in (10, 30, 99, 999) else 28672
        c2["stp_prio"][v] = 24576 if v in (20, 40) else 28672
    a5["stp_prio"][40] = 4096          # someone tuned the wrong switch: an old access switch is root bridge for VLAN 40

    def link(x, px, y, py, proto="cdp", **kw):
        x["ports"][px] = P(**kw.get("a", kw.get("both", {})))
        y["ports"][py] = P(**kw.get("b", kw.get("both", {})))
        x[proto if x["vendor"] == "cisco" or proto == "lldp" else "lldp"].append((px, y, py))
        y[proto if y["vendor"] == "cisco" or proto == "lldp" else "lldp"].append((py, x, px))

    sr = dict(sfp=("SFP-10G-SR", "SFP-10GBase-SR"))
    trunk = dict(mode="trunk", native=1, allowed="10,20,30,40,99", speed=10000, media="SFP-10GBase-SR", portfast=False, bpdu=False, **sr)
    for n in (1, 2):
        link(c1, f"TenGigabitEthernet1/0/{n}", c2, f"TenGigabitEthernet1/0/{n}",
             both=dict(trunk, desc="PO1-CORE-PEER", channel=1, in_bps=rnd.randint(800, 1500) * 10**6, out_bps=rnd.randint(800, 1500) * 10**6))
    for i, acc in enumerate(accs, start=1):
        load = rnd.randint(40, 900) * 10**6
        link(c1, f"TenGigabitEthernet1/0/{4 + i}", acc, "TenGigabitEthernet1/1/1",
             a=dict(trunk, desc=f"{acc['name']}:Te1/1/1", in_bps=load, out_bps=load // 3),
             b=dict(trunk, desc="CORE-1:Te1/0/%d" % (4 + i), in_bps=load // 3, out_bps=load))
        nat_b = 999 if acc["name"] == "ACC-3" else 1
        allowed_b = "10,20,30,99" if acc["name"] == "ACC-2" else "10,20,30,40,99"      # VLAN 40 missing on one end
        link(c2, f"TenGigabitEthernet1/0/{4 + i}", acc, "TenGigabitEthernet1/1/2",
             a=dict(trunk, desc=f"{acc['name']}:Te1/1/2", in_bps=load // 4, out_bps=load // 9),
             b=dict(trunk, desc="" if acc["name"] == "ACC-2" else "CORE-2:Te1/0/%d" % (4 + i), native=nat_b, allowed=allowed_b,
                    in_bps=load // 9, out_bps=load // 4))
    c2["ports"]["TenGigabitEthernet1/0/7"]["sfp_rx"] = -15.8            # dirty fibre towards ACC-3: low-alarm light
    accs[3]["ports"]["TenGigabitEthernet1/1/1"]["sfp_rx"] = -10.9       # ACC-4 uplink: low warning
    # Aruba CX access switch, LLDP only
    link(c2, "TenGigabitEthernet1/0/9", a6, "1/1/49", proto="lldp",
         a=dict(trunk, desc="ACC-6:1/1/49", in_bps=95 * 10**6, out_bps=31 * 10**6),
         b=dict(trunk, desc="CORE-2", media="SFP+SR", in_bps=31 * 10**6, out_bps=95 * 10**6))
    # Huawei access switch on CORE-1, LLDP only
    link(c1, "TenGigabitEthernet1/0/10", a7, "XGigabitEthernet0/0/1", proto="lldp",
         a=dict(trunk, desc="ACC-7:XGE0/0/1", in_bps=44 * 10**6, out_bps=12 * 10**6),
         b=dict(trunk, desc="CORE-1", allowed="10,20,30,40,99", media="SFP+SR", in_bps=12 * 10**6, out_bps=44 * 10**6))
    # data centre leaves: Arista on CORE-1 (LLDP), Nexus on CORE-2 (CDP), routed /31 between them
    dctrunk = dict(trunk, allowed="60,99", speed=10000)
    link(c1, "TenGigabitEthernet1/0/11", l1, "Ethernet49/1", proto="lldp",
         a=dict(dctrunk, desc="DC-LEAF-1:Et49/1", in_bps=2100 * 10**6, out_bps=900 * 10**6),
         b=dict(dctrunk, desc="CORE-1", media="10GBASE-SR", in_bps=900 * 10**6, out_bps=2100 * 10**6))
    link(c2, "TenGigabitEthernet1/0/11", l2, "Ethernet1/49",
         a=dict(dctrunk, desc="DC-LEAF-2:Eth1/49", in_bps=1500 * 10**6, out_bps=700 * 10**6),
         b=dict(dctrunk, desc="CORE-2:Te1/0/11", media="10G", in_bps=700 * 10**6, out_bps=1500 * 10**6))
    link(l1, "Ethernet50/1", l2, "Ethernet1/50", proto="lldp",
         a=dict(mode="routed", routed=True, ip="10.255.1.0/31", speed=100000, desc="DC-LEAF-2 p2p", media="100GBASE-SR4", in_bps=300 * 10**6, out_bps=310 * 10**6, portfast=False, bpdu=False),
         b=dict(mode="routed", routed=True, ip="10.255.1.1/31", speed=100000, desc="DC-LEAF-1 p2p", media="100G", in_bps=310 * 10**6, out_bps=300 * 10**6, portfast=False, bpdu=False, mtu=1500))
    l1["ports"]["Ethernet50/1"]["mtu"] = 9214          # MTU mismatch on the leaf-to-leaf link
    # Juniper EX on CORE-2, Aruba 2930F on CORE-1, FortiSwitch on CORE-2 (all LLDP)
    link(c2, "TenGigabitEthernet1/0/10", a8, "xe-0/1/0", proto="lldp",
         a=dict(trunk, desc="ACC-8:xe-0/1/0", in_bps=64 * 10**6, out_bps=21 * 10**6),
         b=dict(trunk, desc="CORE-2", media="10GBASE-SR", in_bps=21 * 10**6, out_bps=64 * 10**6))
    link(c1, "TenGigabitEthernet1/0/12", a9, "49", proto="lldp",
         a=dict(trunk, desc="ACC-9:49", in_bps=88 * 10**6, out_bps=30 * 10**6),
         b=dict(trunk, desc="CORE-1", allowed="10,20,30,40,99", native=1, media="SFP+SR", in_bps=30 * 10**6, out_bps=88 * 10**6))
    link(c2, "TenGigabitEthernet1/0/12", a10, "port49", proto="lldp",
         a=dict(trunk, desc="ACC-10:port49", in_bps=52 * 10**6, out_bps=17 * 10**6),
         b=dict(trunk, desc="CORE-2", allowed="10,20,30,99", media="10GBASE-SR", in_bps=17 * 10**6, out_bps=52 * 10**6))   # VLAN 40 missing
    # WAN: routed /30s; CORE-1 uplink is busy (87%)
    lx = dict(sfp=("GLC-LH-SMD", "1000BaseLX SFP"))
    link(c1, "TenGigabitEthernet1/0/24", wan, "GigabitEthernet0/0/1",
         a=dict(mode="routed", routed=True, ip="10.255.0.2/30", speed=1000, media="SFP-1000BaseLX", desc="WAN-RTR:Gi0/0/1", in_bps=871 * 10**6, out_bps=402 * 10**6, drops=48211, portfast=False, bpdu=False, **lx),
         b=dict(mode="routed", routed=True, ip="10.255.0.1/30", speed=1000, media="SFP-1000BaseLX", desc="CORE-1:Te1/0/24", in_bps=402 * 10**6, out_bps=871 * 10**6, portfast=False, bpdu=False, **lx))
    link(c2, "TenGigabitEthernet1/0/24", wan, "GigabitEthernet0/0/2",
         a=dict(mode="routed", routed=True, ip="10.255.0.6/30", speed=1000, media="SFP-1000BaseLX", desc="WAN-RTR:Gi0/0/2", in_bps=120 * 10**6, out_bps=60 * 10**6, portfast=False, bpdu=False, **lx),
         b=dict(mode="routed", routed=True, ip="10.255.0.5/30", speed=1000, media="SFP-1000BaseLX", desc="CORE-2:Te1/0/24", in_bps=60 * 10**6, out_bps=120 * 10**6, portfast=False, bpdu=False, **lx))
    wan["ports"]["GigabitEthernet0/0/0"] = P(mode="routed", routed=True, ip="203.0.113.2/30", desc="ISP-A circuit 44821", speed=1000, in_bps=390 * 10**6, out_bps=180 * 10**6, portfast=False, bpdu=False)
    link(accs[3], "GigabitEthernet1/0/48", a5, "GigabitEthernet1/0/49",
         a=dict(trunk, speed=100, duplex="full", media="10/100/1000BaseTX", desc="ACC-5 daisy chain", crc=8421, in_err=9120, in_bps=61 * 10**6, out_bps=22 * 10**6, sfp=None),
         b=dict(trunk, speed=100, duplex="half", media="1000BaseSX SFP", desc="ACC-4", late=3311, coll=50211, out_err=3311, in_bps=22 * 10**6, out_bps=61 * 10**6, sfp=("GLC-SX-MMD", "1000BaseSX SFP")))

    # access ports
    for acc in accs + [a5]:
        legacy = acc["flags"].get("legacy")
        for n in range(1, 48 if not legacy else 49):
            name = f"GigabitEthernet1/0/{n}"
            if name in acc["ports"]:
                continue
            used = rnd.random() < 0.62
            p = P(desc=f"{'PH' if n <= 4 else 'PC'}-{acc['name'][-1]}{n:02d}" if used else "", vlan=10, voice=20,
                  status="connected" if used else "notconnect", speed=1000 if used else 0, in_bps=rnd.randint(5, 9000) * 1000 if used else 0,
                  out_bps=rnd.randint(5, 40000) * 1000 if used else 0, bpdu=acc["flags"].get("bpdu", True) and not legacy,
                  storm=acc["name"] == "ACC-1", portfast=not legacy)
            if n == 47 and not legacy:
                p.update(desc="AP-" + acc["name"], vlan=30, voice=None, status="connected", speed=1000, in_bps=rnd.randint(50, 200) * 10**6,
                         out_bps=rnd.randint(10, 80) * 10**6, poe=("C9120AXI-E", 4, 25.5))
            if n in (40, 41, 42) and not used:
                p.update(status="disabled", vlan=999, voice=None)
            if legacy and n > 30:
                p.update(nomode=True)
            if used and n <= 4 and not legacy:
                p["poe"] = ("IP Phone 8865", 2, 6.3)
            acc["ports"][name] = p
        if not legacy:
            acc["ports"].setdefault("GigabitEthernet1/0/48", P(status="notconnect", speed=0))
    accs[0]["ports"]["GigabitEthernet1/0/3"].update(desc="PRINTER-2F", vlan=40, voice=None, status="connected", speed=100, duplex="half", coll=1820, in_bps=120000, out_bps=80000, poe=None)
    accs[0]["ports"]["GigabitEthernet1/0/7"].update(desc="CONF-ROOM", status="err-disabled", speed=0)
    accs[0]["ports"]["GigabitEthernet1/0/22"].update(desc="HOTDESK-22 (flapping)", status="connected", speed=1000, flap=True, resets=57, portfast=False)
    accs[1]["ports"]["GigabitEthernet1/0/12"].update(desc="PC-212 (cable?)", status="connected", speed=1000, crc=15234, in_err=15240)
    accs[1]["ports"]["GigabitEthernet1/0/30"].update(desc="AP-2F-EAST", vlan=30, voice=None, status="connected", speed=1000, poe=("AIR-AP3802I-E", 4, 0.0), poe_fault=True)
    accs[2]["ports"]["GigabitEthernet1/0/9"].update(vlan=1, voice=None, desc="LAB-BENCH", status="connected", speed=1000)
    accs[2]["ports"]["GigabitEthernet1/0/15"].update(vlan=50, voice=None, desc="CCTV (VLAN 50?)", status="connected", speed=100)
    a5["ports"]["GigabitEthernet1/0/5"].update(desc="OLD-PC", status="connected", speed=10, duplex="half", in_bps=1200000, out_bps=900000)
    for n in range(1, 25):
        name = f"1/1/{n}"
        used = rnd.random() < 0.6
        a6["ports"][name] = P(desc=f"PC-6{n:02d}" if used else "", vlan=10, voice=None, status="connected" if used else "notconnect",
                              speed=1000 if used else 0, in_bps=rnd.randint(5, 9000) * 1000 if used else 0, out_bps=rnd.randint(5, 40000) * 1000 if used else 0,
                              bpdu=False, portfast=False)
    for n in range(1, 25):
        name = f"GigabitEthernet0/0/{n}"
        used = rnd.random() < 0.55
        a7["ports"][name] = P(desc=f"PC-7{n:02d}" if used else "", vlan=10, voice=None, status="connected" if used else "notconnect",
                              speed=1000 if used else 0, in_bps=rnd.randint(5, 9000) * 1000 if used else 0,
                              out_bps=rnd.randint(5, 40000) * 1000 if used else 0, bpdu=False, portfast=False)
    a7["ports"]["GigabitEthernet0/0/9"].update(desc="PRINTER-7F", vlan=40, status="connected", speed=100, duplex="half", coll=310, in_bps=40000, out_bps=20000)
    a7["ports"]["GigabitEthernet0/0/14"].update(desc="CAM-LOBBY", status="connected", speed=1000, crc=2210, in_err=2214)
    def edge(sw, names, prefix, vlan=10, rate=(5, 9000), used_p=0.6, servers=False):
        for i, name in enumerate(names, start=1):
            used = r2.random() < used_p
            sw["ports"][name] = P(desc=f"{prefix}{i:02d}" if used else "", vlan=vlan, voice=None, status="connected" if used else "notconnect",
                                  speed=(25000 if servers else 1000) if used else 0, in_bps=r2.randint(*rate) * 1000 if used else 0,
                                  out_bps=r2.randint(*rate) * 4000 if used else 0, bpdu=not servers, portfast=True,
                                  media="25GBASE-CR" if servers else "10/100/1000BaseTX")
    edge(a8, [f"ge-0/0/{n}" for n in range(0, 24)], "PC-8")
    edge(a9, [str(n) for n in range(1, 25)], "PC-9")
    edge(a10, [f"port{n}" for n in range(1, 25)], "PC-10")
    edge(l1, [f"Ethernet{n}" for n in range(1, 17)], "ESX-A", vlan=60, rate=(20000, 900000), used_p=0.8, servers=True)
    edge(l2, [f"Ethernet1/{n}" for n in range(1, 17)], "ESX-B", vlan=60, rate=(20000, 900000), used_p=0.8, servers=True)
    a8["ports"]["ge-0/0/7"].update(desc="PC-807 (half duplex)", status="connected", speed=100, duplex="half", coll=940, in_bps=400000, out_bps=200000)
    a9["ports"]["5"].update(desc="KIOSK-LOBBY", status="connected", speed=1000, crc=5120, in_err=5121)
    a9["ports"]["12"].update(desc="", status="connected", speed=1000, vlan=1)                 # user port left in VLAN 1
    a10["ports"]["port3"].update(desc="PRINTER-10F", vlan=40, status="connected", speed=100)   # VLAN 40 not on the uplink: printer isolated
    l1["ports"]["Ethernet7"].update(desc="ESX-A07 vmnic1", status="connected", speed=10000, duplex="full", crc=72, in_err=72)
    l2["ports"]["Ethernet1/9"].update(desc="ESX-B09 vmnic0", status="err-disabled", speed=0)
    for dv in D.values():
        for p in dv["ports"].values():
            if p["status"] != "connected":
                p.update(in_bps=0, out_bps=0)

    # endpoints: phones and APs via CDP, and the MAC/ARP tables
    hosts = []           # (switch, port, vlan, mac, ip, kind)
    for acc in accs + [a5, a6, a7, a8, a9, a10, l1, l2]:
        for pname, p in acc["ports"].items():
            if p["mode"] != "access" or p["status"] != "connected" or p["routed"]:
                continue
            n = pname.rsplit("/", 1)[-1]
            if p.get("poe") and p["poe"][0].startswith("IP Phone"):
                pm = mac_for(acc["name"], pname, "phone", oui="00a3d1")
                hosts.append((acc, pname, 20, pm, f"10.10.20.{rnd.randint(10, 250)}", "phone"))
                acc["cdp"].append((pname, {"name": "SEP" + pm.upper(), "ip": hosts[-1][4], "platform": "Cisco IP Phone 8865",
                                           "caps": "Host Phone Two-port Mac Relay"}, "Port 1"))
            if p.get("poe") and p["vlan"] == 30:
                am = mac_for(acc["name"], pname, "ap", oui="00a3d1")
                hosts.append((acc, pname, 30, am, f"10.10.30.{rnd.randint(10, 250)}", "ap"))
                acc["cdp"].append((pname, {"name": f"AP-{acc['name']}-{n}", "ip": hosts[-1][4], "platform": "cisco " + p["poe"][0],
                                           "caps": "Router Trans-Bridge Source-Route-Bridge IGMP"}, "GigabitEthernet0"))
                continue
            if acc in (l1, l2):
                hosts.append((acc, pname, 60, mac_for(acc["name"], pname, "srv", oui="005056"), f"10.10.60.{r2.randint(10, 250)}", "server"))
                continue
            oui = (rnd if acc in accs + [a5, a6, a7] else r2).choice(["3cd92b", "f8bc12", "005056", "b827eb", "a4bb6d", "6a1f3e"])   # HP, Dell, VMware, RPi, Dell, random
            hosts.append((acc, pname, p["vlan"], mac_for(acc["name"], pname, "pc", oui=oui), f"10.10.{p['vlan']}.{rnd.randint(10, 250)}", "pc"))
    D["_hosts"] = hosts
    # hardware health: CPU, memory, temperature, fans, power supplies (a few problems planted)
    for name, dv in D.items():
        if name.startswith("_") or not isinstance(dv, dict):
            continue
        dv["health"] = {"cpu": 9 + rnd.randint(0, 14), "mem_total": 1588213280, "mem_used": 420654648 + rnd.randint(0, 200) * 10**6,
                        "temp": 34 + rnd.randint(0, 6), "temp_state": "GREEN",
                        "fans": [("FAN 1", "OK"), ("FAN 2", "OK"), ("FAN 3", "OK")],
                        "psus": [("1A", "PWR-C1-715WAC", "OK"), ("1B", "PWR-C1-715WAC", "OK")]}
    D["CORE-1"]["health"]["cpu"] = 87
    D["CORE-2"]["health"]["psus"][1] = ("1B", "PWR-C4-950WAC-R", "No Input Power")
    D["ACC-3"]["health"]["fans"][1] = ("FAN 2", "FAULTY")
    D["ACC-5"]["health"].update(temp=51, temp_state="YELLOW", psus=[("1A", "PWR-C2-640WAC", "OK"), ("1B", "Not Present", "Not Present")])
    D["WAN-RTR"]["health"]["mem_used"] = int(1588213280 * 0.93)
    D["ACC-8"]["health"]["temp"] = 58
    D["ACC-8"]["health"]["temp_state"] = "YELLOW"
    D["DC-LEAF-2"]["health"]["fans"][2] = ("FAN 3", "FAULTY")
    D["DC-LEAF-1"]["health"]["psus"] = [("1", "PWR-500AC-F", "OK"), ("2", "PWR-500AC-F", "No Input Power")]
    D["ACC-10"]["health"]["cpu"] = 91
    for dv in (a8, a9, a10, l1, l2):
        dv["routes"] = [("S*", "0.0.0.0/0", "1/0", "10.0.99.1", "")]
    up_of = {}
    for acc in accs:
        up_of[acc["name"]] = [("CORE-1", "TenGigabitEthernet1/0/%d" % (4 + accs.index(acc) + 1), "TenGigabitEthernet1/1/1"),
                              ("CORE-2", "TenGigabitEthernet1/0/%d" % (4 + accs.index(acc) + 1), "TenGigabitEthernet1/1/2")]
    up_of["ACC-5"] = [("ACC-4", "GigabitEthernet1/0/48", "GigabitEthernet1/0/49")]
    up_of["ACC-6"] = [("CORE-2", "TenGigabitEthernet1/0/9", "1/1/49")]
    up_of["ACC-7"] = [("CORE-1", "TenGigabitEthernet1/0/10", "XGigabitEthernet0/0/1")]
    up_of["ACC-8"] = [("CORE-2", "TenGigabitEthernet1/0/10", "xe-0/1/0")]
    up_of["ACC-9"] = [("CORE-1", "TenGigabitEthernet1/0/12", "49")]
    up_of["ACC-10"] = [("CORE-2", "TenGigabitEthernet1/0/12", "port49")]
    up_of["DC-LEAF-1"] = [("CORE-1", "TenGigabitEthernet1/0/11", "Ethernet49/1")]
    up_of["DC-LEAF-2"] = [("CORE-2", "TenGigabitEthernet1/0/11", "Ethernet1/49")]
    for sw, pname, vlan, mac, ip, kind in hosts:
        sw["macs"].append((vlan, mac, pname, "DYNAMIC"))
        chain = [(sw["name"], None)]
        cur = sw["name"]
        while cur in up_of:                                   # every switch up the chain learns it on its downlink
            for upname, downport, upport in up_of[cur][:1]:
                D[cur]["macs"].append((vlan, mac, upport, "DYNAMIC"))
                D[upname]["macs"].append((vlan, mac, downport, "DYNAMIC"))
                cur = upname
        other = "CORE-2" if cur == "CORE-1" else "CORE-1"          # the other core learns it across Po1
        D[other]["macs"].append((vlan, mac, "Port-channel1", "DYNAMIC"))
        for core in ("CORE-1", "CORE-2"):
            D[core]["arp"].append((ip, mac, f"Vlan{vlan}"))

    # L3
    for core, last, lo in ((c1, 2, "10.255.255.11"), (c2, 3, "10.255.255.12")):
        for v in (10, 20, 30, 40, 60):
            core["svis"][v] = f"10.10.{v}.{last}/24"
        core["svis"][99] = f"10.0.99.{last - 1}/24"
        core["loop"] = lo
    wan["loop"] = "10.255.255.1"
    for core, nh, wanif in ((c1, "10.255.0.1", "TenGigabitEthernet1/0/24"), (c2, "10.255.0.5", "TenGigabitEthernet1/0/24")):
        core["routes"] = [("O*E2", "0.0.0.0/0", "110/1", nh, wanif), ("O", "10.255.255.1/32", "110/2", nh, wanif),
                          ("O", "10.255.0.4/30" if core is c1 else "10.255.0.0/30", "110/2", nh, wanif),
                          ("O", "10.255.255.12/32" if core is c1 else "10.255.255.11/32", "110/3", nh, wanif)]
        core["ospf"] = [("10.255.255.1", "FULL/  -", nh, wanif)]
        core["arp"].append((nh, mac_for("WAN-RTR", wanif), wanif))
    wan["routes"] = [("S*", "0.0.0.0/0", "1/0", "203.0.113.1", "")]
    for v in (10, 20, 30, 40, 60):
        wan["routes"].append(("O", f"10.10.{v}.0/24", "110/2", "10.255.0.2", "GigabitEthernet0/0/1"))
        wan["routes"].append(("O", f"10.10.{v}.0/24", "110/2", "10.255.0.6", "GigabitEthernet0/0/2"))
    wan["routes"] += [("O", "10.0.99.0/24", "110/2", "10.255.0.2", "GigabitEthernet0/0/1"),
                      ("O", "10.255.255.11/32", "110/2", "10.255.0.2", "GigabitEthernet0/0/1"),
                      ("O", "10.255.255.12/32", "110/2", "10.255.0.6", "GigabitEthernet0/0/2")]
    wan["ospf"] = [("10.255.255.11", "FULL/  -", "10.255.0.2", "GigabitEthernet0/0/1"), ("10.255.255.12", "FULL/  -", "10.255.0.6", "GigabitEthernet0/0/2")]
    wan["arp"] = [("203.0.113.1", "0011223344aa", "GigabitEthernet0/0/0")]
    return D


# ------------------------------------------------------------------ spanning tree, computed from the design above
def stp_view(D, dev):
    """Per VLAN: (root_prio, root_mac, root_port, cost, my_prio, my_mac, port roles {port: (role, state)}, tc_count, tc_ago, tc_from)."""
    out = {}
    if dev["role"] == "router" or dev["vendor"] != "cisco":
        return out
    switches = [d for k, d in D.items() if not k.startswith("_") and d["role"] != "router" and d["vendor"] == "cisco"]
    for v in VLANS:
        if v in (1, 999):                 # not carried on any trunk
            continue

        def bid(d):
            return (d["stp_prio"].get(v, 32768) + v, d["base_mac"])
        root = min(switches, key=bid)
        roles = {}
        root_port, cost = "", 0
        if dev is not root:
            ups = [(p, q) for p, q in dev["ports"].items() if q["mode"] == "trunk" and q["status"] == "connected" and q["allowed"] != "" and _carries(q, v)]
            # prefer the port facing the root, else the uplink with the lowest name
            facing = [p for p, q in ups if any(n[0] == p and n[1] is root for n in dev["cdp"] + dev["lldp"])]
            root_port = (facing or sorted(p for p, _ in ups) or [""])[0]
            cost = 2 if facing else 4
            nbr = {n[0]: n[1] for n in dev["cdp"] + dev["lldp"] if isinstance(n[1], dict) and "role" in n[1]}
            root_down = root["role"] == "access"
            for p, q in ups:
                towards_access = nbr.get(p, {}).get("role") == "access"
                if p == root_port:
                    roles[p] = ("Root", "FWD")
                elif q.get("channel") or dev["role"] != "access" or towards_access or root_down:
                    roles[p] = ("Desg", "FWD")
                else:
                    roles[p] = ("Altn", "BLK")
        else:
            for p, q in dev["ports"].items():
                if q["mode"] == "trunk" and q["status"] == "connected" and _carries(q, v):
                    roles[p] = ("Desg", "FWD")
        for p, q in dev["ports"].items():
            if q["mode"] == "access" and q["status"] == "connected" and q["vlan"] == v:
                roles[p] = ("Desg", "FWD")
        tc, ago, frm = 3, "2d04h", ""
        if dev["name"] == "ACC-1" and v == 10:
            tc, ago, frm = 1520, "00:03:12", "GigabitEthernet1/0/22"
        out[v] = dict(root_prio=root["stp_prio"].get(v, 32768) + v, root_mac=root["base_mac"], root_port=root_port, cost=cost,
                      my_prio=dev["stp_prio"].get(v, 32768) + v, my_mac=dev["base_mac"], roles=roles, tc=tc, tc_ago=ago, tc_from=frm,
                      is_root=dev is root)
    return out


def _carries(q, v):
    a = str(q.get("allowed", "ALL")).upper()
    if a in ("ALL", ""):
        return True
    for part in a.split(","):
        b = part.split("-")
        if (len(b) == 2 and int(b[0]) <= v <= int(b[1])) or (len(b) == 1 and b[0].isdigit() and int(b[0]) == v):
            return True
    return False
