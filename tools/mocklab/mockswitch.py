#!/usr/bin/env python3
"""A pretend Cisco IOS / IOS-XE or Aruba AOS-CX switch for testing VMap end to end: SSH on port 22 (paramiko) and SNMP v2c on
udp/161, serving one device of the lab network (labnet/). It keeps state: shut a port, change a VLAN, push config, save a
rollback point and restore it, copy and verify an image, install it and reload (the switch goes away and comes back on the new
version). Counters grow over time, one port flaps, one port keeps getting CRC errors.

    LAB_DEVICE=CORE-1 LAB_IPS=lab python mockswitch.py
Env: LAB_DEVICE, LAB_IPS (lab|demo), LAB_USER (vmap), LAB_PASSWORD (vmap-lab), LAB_COMMUNITY (vmap-lab), SSH_PORT (22), SNMP_PORT (161)
"""
import asyncio
import copy
import hashlib
import logging
import os
import re
import socket
import sys
import threading
import time

import paramiko

sys.path.insert(0, os.environ.get("LABNET_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")))
from labnet import aoscx, aoss, eos, fortiswitch, huawei, ios, junos, nxos  # noqa: E402
from labnet.network import DEMO_IPS, LAB_IPS, build, mac_for, stp_view  # noqa: E402

log = logging.getLogger("mockswitch")
NAME = os.environ.get("LAB_DEVICE", "CORE-1")
USER, PASSWORD = os.environ.get("LAB_USER", "vmap"), os.environ.get("LAB_PASSWORD", "vmap-lab")
COMMUNITY = os.environ.get("LAB_COMMUNITY", "vmap-lab")
D = build(LAB_IPS if os.environ.get("LAB_IPS", "lab") == "lab" else DEMO_IPS)
DEV = D[NAME]
CX = DEV["vendor"] == "aruba"
HW = DEV["vendor"] == "huawei"
OS = DEV["os_type"]
NX, EOS, JUN, AOSS, FSW = OS == "nxos", OS == "eos", OS == "junos", OS == "aoss", OS == "fortiswitch"
MOD = {"aoscx": aoscx, "vrp": huawei, "junos": junos, "aoss": aoss, "fortiswitch": fortiswitch, "eos": eos, "nxos": nxos}.get(OS, ios)
ENTERPRISE = {"cisco": 9, "aruba": 47196, "aruba_aoss": 11, "huawei": 2011, "juniper": 2636, "arista": 30065, "fortinet": 12356}[DEV["vendor"]]
START = time.time()
STATE = {"boot_at": time.time(), "reboot_until": 0, "lock": threading.Lock()}
BASE = copy.deepcopy(DEV["ports"])


# ------------------------------------------------------------------ live state: time-dependent counters, flaps, reboots
def tick():
    now = time.time()
    h = DEV.get("health")
    if h:
        base = h.setdefault("cpu_base", h["cpu"])
        h["cpu"] = max(1, min(100, base + int(6 * __import__("math").sin(now / 60)) ))
    up = int(now - STATE["boot_at"]) + (0 if DEV.get("rebooted") else 3 * 86400 + 4 * 3600)
    d, rem = divmod(up, 86400)
    h, rem = divmod(rem, 3600)
    DEV["uptime_text"] = f"{d} days, {h} hours, {rem // 60} minutes"
    DEV["uptime_text_cx"] = f"{d} days, {h} hours, {rem // 60} minutes"
    for name, p in DEV["ports"].items():
        b = BASE.get(name, {})
        if p.get("flap") and not p.get("admin_down"):
            phase = int((now - START) // 90)
            p["status"] = "connected" if phase % 2 == 0 else "notconnect"
            p["resets"] = b.get("resets", 0) + phase
        if b.get("crc") and name.endswith(("1/0/12", "1/0/48")):          # still taking errors
            grow = int((now - START) / 20)
            p["crc"] = b["crc"] + grow
            p["in_err"] = b.get("in_err", 0) + grow


def uptime_ticks():
    return int((time.time() - STATE["boot_at"]) * 100)


def octets(p, direction):
    rate = p["in_bps"] if direction == "in" else p["out_bps"]
    if p["status"] != "connected":
        rate = 0
    return int(10 ** 12 + rate * (time.time() - START) / 8) % (2 ** 64)


# ------------------------------------------------------------------ syslog and traps towards VMap
SYSLOG = os.environ.get("LAB_SYSLOG", "")
_seq = {"n": 100}
_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def syslog(sev, mnemonic, text):
    if not SYSLOG or OS not in ("ios", "iosxe", "eos"):
        return
    _seq["n"] += 1
    msg = f"<{23 * 8 + sev}>{_seq['n']}: *{time.strftime('%b %d %H:%M:%S', time.gmtime())}.000: %{mnemonic}: {text}"
    try:
        _udp.sendto(msg.encode(), (SYSLOG, 5514))
    except OSError:
        pass


def trap(oid, ifindex=None, ifname=None):
    if not SYSLOG:
        return
    from pyasn1.codec.ber import encoder
    from pysnmp.proto import api
    m = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
    pdu = m.SNMPv2TrapPDU()
    m.apiTrapPDU.set_defaults(pdu)
    vbs = [((1, 3, 6, 1, 2, 1, 1, 3, 0), m.TimeTicks(uptime_ticks())), ((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), m.ObjectIdentifier(oid))]
    if ifindex:
        vbs += [((1, 3, 6, 1, 2, 1, 2, 2, 1, 1, ifindex), m.Integer(ifindex)), ((1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, ifindex), m.OctetString(ifname or ""))]
    m.apiTrapPDU.set_varbinds(pdu, vbs)
    msg = m.Message()
    m.apiMessage.set_defaults(msg)
    m.apiMessage.set_community(msg, COMMUNITY)
    m.apiMessage.set_pdu(msg, pdu)
    try:
        _udp.sendto(encoder.encode(msg), (SYSLOG, 1162))
    except OSError:
        pass


def if_index(name):
    ports = sorted(DEV["ports"], key=lambda n: [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", n)])
    return ports.index(name) + 1 if name in ports else None


def watcher():
    """Emit what a real switch would log: link changes, a recurring PoE fault, coldStart after a reload."""
    prev = {n: p["status"] for n, p in DEV["ports"].items()}
    was_rebooting, last_poe = False, 0
    while True:
        time.sleep(3)
        with STATE["lock"]:
            tick()
            if rebooting():
                was_rebooting = True
                continue
            if was_rebooting:
                was_rebooting = False
                trap((1, 3, 6, 1, 6, 3, 1, 1, 5, 1))
                syslog(5, "SYS-5-RESTART", f"System restarted --\nCisco IOS Software, Version {DEV['ver']}")
            for n, p in DEV["ports"].items():
                st = p["status"]
                if st != prev.get(n) and "connected" in (st, prev.get(n)):
                    up = st == "connected"
                    syslog(3, "LINK-3-UPDOWN", f"Interface {n}, changed state to {'up' if up else 'down'}")
                    syslog(5, "LINEPROTO-5-UPDOWN", f"Line protocol on Interface {n}, changed state to {'up' if up else 'down'}")
                    trap((1, 3, 6, 1, 6, 3, 1, 1, 5, 4 if up else 3), if_index(n), ios.short(n))
                prev[n] = st
            if NAME == "ACC-2" and time.time() - last_poe > 300:
                last_poe = time.time()
                syslog(3, "ILPOWER-3-CONTROLLER_PORT_ERR", "Controller port error, Interface Gi1/0/30: Power Controller reports power Imax error detected")


def rebooting():
    return time.time() < STATE["reboot_until"]


def reboot(seconds=40):
    syslog(5, "SYS-5-RELOAD", "Reload requested by vmap on vty0. Reload Reason: Reload Command.")
    STATE["reboot_until"] = time.time() + seconds
    STATE["boot_at"] = STATE["reboot_until"]
    DEV["rebooted"] = True
    if DEV.get("pending_version"):
        DEV["ver"] = DEV.pop("pending_version")
    log.warning("reloading for %ss, version after boot: %s", seconds, DEV["ver"])


def version_from_file(f):
    m = re.search(r"\.(\d{2})\.(\d{2})\.(\d{2})([a-z]?)\.", f)
    if m:
        return f"{int(m.group(1))}.{int(m.group(2))}.{int(m.group(3))}{m.group(4)}"
    m = re.search(r"\.(\d)(\d)(\d)-(\d+)\.(\w+?)\.bin", f)
    if m:
        return f"{m.group(1)}{m.group(2)}.{m.group(3)}({m.group(4)}){m.group(5)}"
    m = re.search(r"([A-Z]{2})_(\d+)_(\d+)_(\d+)", f)
    if m:
        return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
    for rx, fmt in ((r"nxos\.(\d+)\.(\d+)\.(\d+)\.bin", "{0}.{1}({2})"), (r"EOS-([\d.]+\w*)\.swi", "{0}"),
                    (r"-(\d+\.\d+R[\w.-]+?)(?:-signed)?\.tgz", "{0}"), (r"-(v\d+\.\d+\.\d+)-build", "{0}"),
                    (r"(V\d{3}R\d{3}C\d{2}(?:SPC\d{3})?)", "{0}")):
        m = re.search(rx, f)
        if m:
            return fmt.format(*m.groups())
    return ""


# ------------------------------------------------------------------ NetFlow v9 / IPFIX / v5 exporter (cores, WAN router, one Huawei)
FLOW_KIND = {"CORE-1": 9, "CORE-2": 9, "WAN-RTR": 10, "ACC-7": 5}.get(NAME)
_FIELDS = [(8, 4), (12, 4), (4, 1), (7, 2), (11, 2), (10, 2), (14, 2), (1, 4), (2, 4)]       # src dst proto sport dport in out bytes pkts


def _conversations():
    """Synthetic but stable conversations built from the lab's hosts: users to servers, users to the internet, server backups."""
    import random
    rnd = random.Random(NAME)
    hosts = [h for h in D["_hosts"] if h[5] in ("pc", "phone", "ap")]
    servers = [h for h in D["_hosts"] if h[5] == "server"] or hosts[:4]
    internet = ["142.250.74.46", "52.97.146.162", "13.107.42.14", "151.101.1.140", "104.16.132.229", "8.8.8.8", "1.1.1.1", "20.190.160.1"]
    convs = []
    for h in rnd.sample(hosts, min(40, len(hosts))):
        srv = rnd.choice(servers)
        convs.append((h[4], srv[4], 6, rnd.randint(49152, 65000), rnd.choice([443, 445, 3389, 22, 1433, 8080]), rnd.randint(20, 900) * 1000))
        convs.append((h[4], rnd.choice(internet), rnd.choice([6, 6, 17]), rnd.randint(49152, 65000), 443, rnd.randint(50, 4000) * 1000))
        if rnd.random() < .3:
            convs.append((h[4], "8.8.8.8", 17, rnd.randint(49152, 65000), 53, rnd.randint(1, 8) * 1000))
    for s_ in servers[:6]:
        convs.append((s_[4], "10.10.60.250", 6, rnd.randint(49152, 65000), 873, rnd.randint(20, 120) * 10**6))       # nightly-ish backup
    if NAME == "WAN-RTR":
        convs = [c for c in convs if not c[1].startswith("10.")]
    return convs


def _flow_payload(seq, recs):
    import struct
    up = (uptime_ticks() * 10 + 10000) & 0xFFFFFFFF
    now = int(time.time())
    if FLOW_KIND == 5:
        body = b"".join(struct.pack("!4s4s4sHHIIIIHHBBBBHHBBH", socket.inet_aton(r[0]), socket.inet_aton(r[1]), b"\0" * 4, r[5], r[6], r[8], r[7],
                                    up - 10000, up, r[3], r[4], 0, 0x18, r[2], 0, 0, 0, 24, 24, 0) for r in recs[:30])
        return struct.pack("!HHIIIIBBH", 5, min(len(recs), 30), up, now, 0, seq, 0, 0, 0) + body
    tmpl = struct.pack("!HH", 256, len(_FIELDS)) + b"".join(struct.pack("!HH", t, l) for t, l in _FIELDS)
    data = b"".join(socket.inet_aton(r[0]) + socket.inet_aton(r[1]) + struct.pack("!BHHHHII", r[2], r[3], r[4], r[5], r[6], r[7], r[8]) for r in recs)
    pad = (4 - len(data) % 4) % 4
    if FLOW_KIND == 9:
        sets = struct.pack("!HH", 0, 4 + len(tmpl)) + tmpl + struct.pack("!HH", 256, 4 + len(data) + pad) + data + b"\0" * pad
        return struct.pack("!HHIIII", 9, len(recs) + 1, up, now, seq, 1) + sets
    sets = struct.pack("!HH", 2, 4 + len(tmpl)) + tmpl + struct.pack("!HH", 256, 4 + len(data) + pad) + data + b"\0" * pad
    return struct.pack("!HHIII", 10, 16 + len(sets), now, seq, 1) + sets


def flow_exporter():
    if not FLOW_KIND or not SYSLOG:
        return
    convs = _conversations()
    idx = {n: i for i, n in enumerate(sorted(DEV["ports"], key=lambda n: [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", n)]), start=1)}
    uplinks = [idx[n] for n, p in DEV["ports"].items() if p["mode"] in ("trunk", "routed")] or [1]
    seq = 0
    while True:
        time.sleep(10)
        if rebooting():
            continue
        import random
        recs = []
        for i, (src, dst, proto, sport, dport, bps) in enumerate(convs):
            b = int(bps * 10 / 8 * random.uniform(0.6, 1.4))
            if b <= 0:
                continue
            pk = max(1, b // 900)
            recs.append((src, dst, proto, sport, dport, uplinks[i % len(uplinks)], uplinks[(i + 1) % len(uplinks)], b, pk))
        for k in range(0, len(recs), 24):
            seq += 1
            try:
                _udp.sendto(_flow_payload(seq, recs[k:k + 24]), (SYSLOG, 2055))
            except OSError:
                pass


# ------------------------------------------------------------------ CLI
def full_ifname(n):
    for full, short in (("TenGigabitEthernet", "Te"), ("GigabitEthernet", "Gi"), ("Port-channel", "Po"), ("FastEthernet", "Fa"),
                        ("Ethernet", "Eth"), ("Ethernet", "Et")):
        if n.startswith(short) and not n.startswith(full):
            return full + n[len(short):]
    return n


def pipe(text, flt):
    m = re.match(r"(include|exclude|begin|section|count|grep|match)\s+(.*)", flt.strip())
    if not m:
        return text
    kind, rx = m.group(1), re.compile(m.group(2))
    lines = text.splitlines()
    if kind in ("include", "grep", "match"):
        return "\n".join(l for l in lines if rx.search(l)) + "\n"
    if kind == "exclude":
        return "\n".join(l for l in lines if not rx.search(l)) + "\n"
    if kind == "begin":
        for i, l in enumerate(lines):
            if rx.search(l):
                return "\n".join(lines[i:]) + "\n"
        return ""
    if kind == "count":
        return f"Number of lines which match regexp = {sum(1 for l in lines if rx.search(l))}\n"
    out, keep = [], False
    for l in lines:
        if not l.startswith(" "):
            keep = bool(rx.search(l))
        if keep:
            out.append(l)
    return "\n".join(out) + "\n"


class Session:
    def __init__(self, chan):
        self.chan = chan
        self.mode = "exec"          # exec | config | if
        self.iface = None
        self.pending = None         # (prompt-answer handler)
        self.pending_cfg = []       # Junos candidate configuration (applied on commit)
        self.ctx, self.edit, self.section = [], None, ""      # FortiSwitch config block context

    def prompt(self):
        if JUN:
            return f"\n[edit]\n{USER}@{NAME}# " if self.mode != "exec" else f"{USER}@{NAME}> "
        if AOSS:
            return {"exec": f"{NAME}# ", "config": f"{NAME}(config)# ", "if": f"{NAME}(eth-{self.iface})# ", "vlan": f"{NAME}(vlan-{self.iface})# "}.get(self.mode, f"{NAME}(config)# ")
        if FSW:
            ctx = getattr(self, "ctx", [])
            return f"{NAME} ({ctx[-1]}) # " if ctx else f"{NAME} # "
        if HW:
            return {"exec": f"<{NAME}>", "config": f"[{NAME}]", "if": f"[{NAME}-{self.iface or 'Vlanif99'}]", "line": f"[{NAME}-ui-vty0-4]"}[self.mode]
        return {"exec": f"{NAME}#", "config": f"{NAME}(config)#", "if": f"{NAME}(config-if)#", "line": f"{NAME}(config-line)#"}[self.mode]

    def send(self, text):
        self.chan.sendall(text.replace("\r\n", "\n").replace("\n", "\r\n").encode())

    def run(self):
        self.send("\n" + self.prompt())
        buf = b""
        while True:
            data = self.chan.recv(4096)
            if not data:
                return
            for ch in data:
                c = bytes([ch])
                if c in (b"\r", b"\n"):
                    if c == b"\n" and buf == b"" and getattr(self, "_last_cr", False):
                        self._last_cr = False
                        continue
                    self._last_cr = c == b"\r"
                    line = buf.decode(errors="ignore")
                    buf = b""
                    self.send("\n")
                    out = self.handle(line)
                    if out is None:          # session closes (reload)
                        time.sleep(0.5)
                        self.chan.close()
                        return
                    if out:
                        self.send(out if out.endswith("\n") else out + "\n")
                    self.send(self.pending[0] if self.pending else self.prompt())
                elif c in (b"\x7f", b"\x08"):
                    buf = buf[:-1]
                else:
                    self._last_cr = False
                    buf += c
                    self.chan.sendall(c)

    # ---- dispatch
    def handle(self, line):
        with STATE["lock"]:
            tick()
            if self.pending:
                _p, fn = self.pending
                self.pending = None
                return fn(line.strip())
            s = line.strip()
            if not s:
                return ""
            if self.mode != "exec":
                return self.config_line(s)
            return self.exec_line(s)

    def ask(self, question, fn):
        self.pending = (question, fn)
        return ""

    def exec_line(self, s):
        if HW:
            return self.hw_exec(s)
        if JUN:
            return self.jun_exec(s)
        if AOSS:
            return self.aoss_exec(s)
        if FSW:
            return self.fsw_exec(s)
        if EOS and s.startswith("terminal width"):
            return "Width set to 511 columns."
        if EOS and s.startswith("terminal length"):
            return "Pagination disabled."
        if s.startswith(("terminal ", "no page", "terminal length")):
            return ""
        if s in ("configure terminal", "config t", "conf t", "configure"):
            self.mode = "config"
            return "Enter configuration commands, one per line.  End with CNTL/Z."
        if s == "show clock":
            return time.strftime("*%H:%M:%S.000 UTC %a %b %d %Y")
        if s in ("write memory", "copy running-config startup-config", "wr"):
            return "Copying configuration: [Success]" if CX else "Building configuration...\n[OK]"
        cmd, _, flt = s.partition(" | ")
        cmd = re.sub(r"\s+", " ", cmd)
        table = MOD.commands(D)
        if cmd in table:
            if OS in ("ios", "iosxe"):
                DEV["_stp"] = stp_view(D, DEV)
            out = table[cmd](DEV)
            return pipe(out, flt) if flt else out
        m = re.match(r"dir( (\S+))?$", cmd)
        if m and not CX:
            return MOD.r_dir(DEV, m.group(2) or ("bootflash:" if NX else "flash:"))
        return self.special(cmd)

    def special(self, s):
        files = DEV.setdefault("flash", {"packages.conf": 7531, "vlan.dat": 3436} if OS in ("ios", "iosxe") else {})
        snapkeys = ("ports", "flags", "extra_global", "removed_global")
        m = re.match(r"checkpoint (\S+)$", s)
        if m and NX:
            DEV.setdefault("saved", {})[m.group(1)] = copy.deepcopy({k: v for k, v in DEV.items() if k in snapkeys})
            return "...........\nDone"
        m = re.match(r"rollback running-config checkpoint (\S+)", s)
        if m and NX:
            snap = DEV.get("saved", {}).get(m.group(1))
            if not snap:
                return "Rollback failed: checkpoint not found"
            DEV.update(copy.deepcopy(snap))
            return "Note: Applying config parallelly may fail Rollback verification\nCollecting Running-Config\n#Generating Rollback Patch\nExecuting Rollback Patch\n#Rollback completed successfully."
        m = re.match(r"install all nxos bootflash:(\S+)", s)
        if m and NX:
            f = m.group(1)
            if f not in files:
                return f"Install has failed. Return code 0x40930011 (Image file does not exist)."

            def go(_a):
                DEV["pending_version"] = version_from_file(f) or DEV["ver"]
                self.send("Install is in progress, please wait.\nPerforming runtime checks.\n[####################] 100% -- SUCCESS\n"
                          "Setting boot variables.\n[####################] 100% -- SUCCESS\nFinishing the upgrade, switch will reboot in 10 seconds.\n")
                reboot()
                return None
            return self.ask(f"Images will be upgraded according to following table:\nModule  Image  Running-Version  New-Version  Upg-Required\n"
                            f"1       nxos   {DEV['ver']}  {version_from_file(f)}  yes\n\nSwitch will be reloaded for disruptive upgrade.\n"
                            "Do you want to continue with the installation (y/n)?  [n] ", go)
        m = re.match(r"show install all impact nxos bootflash:(\S+)", s)
        if m and NX:
            return "Compatibility check is done:\nModule  bootable          Impact  Install-type  Reason\n1       yes      disruptive         reset  Default upgrade is not hitless"
        m = re.match(r"copy running-config flash:(\S+)", s)
        if m and EOS:
            DEV.setdefault("saved", {})[m.group(1)] = copy.deepcopy({k: v for k, v in DEV.items() if k in snapkeys})
            files[m.group(1)] = 13603
            return "Copy completed successfully."
        m = re.match(r"copy (\S+://\S+) flash:(\S*)", s)
        if m and EOS:
            fname = m.group(1).rsplit("/", 1)[-1]
            time.sleep(3)
            files[m.group(2) or fname] = 912000000 + len(fname)
            return "Copy completed successfully."
        m = re.match(r"copy running-config (flash|bootflash|checkpoint):?\s*(\S+)", s)
        if m:
            name = m.group(2).split(":")[-1]
            snap = copy.deepcopy({k: v for k, v in DEV.items() if k in ("ports", "flags", "extra_global", "removed_global")})
            if CX:
                DEV.setdefault("checkpoints", {})[name] = snap
                return "Copying configuration: [Success]"

            def done(_ans):
                DEV.setdefault("saved", {})[name] = snap
                files[name] = 13603
                return "13603 bytes copied in 0.214 secs (63565 bytes/sec)"
            return self.ask(f"Destination filename [{name}]? ", done)
        m = re.match(r"copy checkpoint (\S+) running-config", s)
        if m and CX:
            snap = DEV.get("checkpoints", {}).get(m.group(1))
            if not snap:
                return "Checkpoint not found."
            DEV.update(copy.deepcopy(snap))
            return "Copying configuration: [Success]"
        m = re.match(r"configure replace (?:flash|bootflash):(\S+)( force)?", s)
        if m:
            snap = DEV.get("saved", {}).get(m.group(1))
            if not snap:
                return f"%Error opening flash:{m.group(1)} (No such file or directory)"
            DEV.update(copy.deepcopy(snap))
            return "Total number of passes: 1\nRollback Done"
        m = re.match(r"copy (\S+://\S+) (\S+)", s)
        if m:
            url, dst = m.groups()
            fname = url.rsplit("/", 1)[-1]
            if CX and dst == "secondary":
                def go(_a):
                    time.sleep(3)
                    DEV["secondary_version"] = version_from_file(fname) or "FL.10.13.1000"
                    return f"Copying image to secondary...\nVerifying and writing system firmware...\nSuccess"
                return self.ask("The secondary image will be deleted.\n\nDo you want to continue (y/n)? ", go)
            if "nonexistent" in url:
                return f"%Error opening {url} (No such file or directory)"
            target = dst.split(":")[-1] or fname

            def got(_a):
                time.sleep(3)
                files[target] = 457000000 + len(target)
                return f"Accessing {url}...\nLoading {fname} !!!!!!!!!!!!!!!!!!!!\n[OK - {files[target]} bytes]\n\n{files[target]} bytes copied in 3.112 secs"
            return self.ask(f"Destination filename [{target}]? ", got)
        m = re.match(r"verify /md5 (?:flash|bootflash):(\S+)", s)
        if m:
            f = m.group(1)
            if f not in files:
                return f"%Error opening flash:{f} (No such file or directory)"
            return f"....................Done!\nverify /md5 (flash:{f}) = {hashlib.md5(f.encode()).hexdigest()}"
        m = re.match(r"install add file (?:flash|bootflash):(\S+)( activate commit.*)?", s)
        if m:
            f = m.group(1)
            if f not in files:
                return "FAILED: install_add : flash:" + f + " not found"
            DEV["pending_version"] = version_from_file(f)
            if not m.group(2):
                return "install_add: Adding PACKAGE\n--- Starting Add ---\nSUCCESS: install_add"
            self.send("install_add_activate_commit: START\n--- Starting Add ---\nSUCCESS: Finished Add\n--- Starting Activate ---\n"
                      "Performing Activate on all members\nSUCCESS: Finished Activate\n--- Starting Commit ---\nSUCCESS: Finished Commit\n"
                      "Chassis 1 reloading, reason - Reload command\n")
            reboot()
            return None
        if s == "show images" and CX:
            return (f"---------------------------------------------------------------------------\nArubaOS-CX Primary Image\n"
                    f"---------------------------------------------------------------------------\nVersion : {DEV['ver']}\n\n"
                    f"---------------------------------------------------------------------------\nArubaOS-CX Secondary Image\n"
                    f"---------------------------------------------------------------------------\nVersion : {DEV.get('secondary_version', '')}\n")
        if s.startswith("boot system secondary") and CX:
            def go(_a):
                if DEV.get("secondary_version"):
                    DEV["pending_version"] = DEV["secondary_version"]
                reboot()
                return None
            return self.ask("Do you want to save the current configuration (y/n)? ", lambda a: self.ask("This will reboot the entire switch.\nDo you want to continue (y/n)? ", go))
        if s.startswith("boot set-default"):
            return "Default boot image set to secondary."
        if s == "reload":
            def go(_a):
                if DEV.get("boot_file"):
                    DEV["pending_version"] = version_from_file(DEV["boot_file"]) or DEV["ver"]
                reboot()
                return None
            return self.ask("Proceed with reload? [confirm]", go)
        if s.startswith("show install summary"):
            return f"[ Chassis 1 ] Installed Package(s) Information:\nIMG   C    {DEV['ver']}\n"
        return "                ^\n% Invalid input detected at '^' marker."

    def hw_exec(self, s):
        if s.startswith("screen-length"):
            return "Info: The configuration takes effect on the current user terminal interface only."
        if s in ("system-view", "sys"):
            self.mode = "config"
            return "Enter system view, return user view with return command."
        if s == "save":
            return self.ask("The current configuration will be written to the device. Are you sure to continue?[Y/N]",
                            lambda a: "Now saving the current configuration to the slot 0.\nInfo: Save the configuration successfully.")
        cmd, _, flt = s.partition(" | ")
        table = huawei.commands(D)
        if cmd in table:
            out = table[cmd](DEV)
            return pipe(out, flt) if flt else out
        return self.hw_special(cmd)

    def hw_special(self, s):
        files = DEV.setdefault("flash", {})
        if s in ("dir flash:", "dir flash:/", "dir"):
            rows = ["Directory of flash:/", "", "  Idx  Attr     Size(Byte)  Date        Time(LMT)  FileName",
                    f"    0  -rw-     {58342400:>10,}  Oct 02 2026 08:00:00   {DEV['model'].split('-')[0]}-{DEV['ver']}.cc", "    1  -rw-          3,684  Nov 12 2026 08:00:00   vrpcfg.zip"]
            for i, (n, sz) in enumerate(files.items(), start=2):
                rows.append(f"    {i}  -rw-     {sz:>10,}  Nov 12 2026 08:00:00   {n}")
            used = (58342400 + sum(files.values())) // 1024
            return "\n".join(rows) + f"\n\n1,090,732 KB total ({1090732 - used:,} KB free)"
        m = re.match(r"dir flash:/(\S+)$", s)
        if m:
            f = m.group(1)
            if f not in files:
                return f"Error: File can't be found."
            return f"Directory of flash:/\n\n  Idx  Attr     Size(Byte)  Date        Time(LMT)  FileName\n    0  -rw-     {files[f]:>10,}  Nov 12 2026 08:00:00   {f}\n\n1,090,732 KB total (431,616 KB free)"
        m = re.match(r"tftp (\S+) get (\S+) flash:/(\S+)", s) or re.match(r"sftp client-transfile get host-ip (\S+) .*sourcefile (\S+) destination flash:/(\S+)", s)
        if m:
            if "nonexistent" in m.group(2):
                return "Error: Failed to download the file: File not found."
            time.sleep(3)
            files[m.group(3)] = 61865984 + len(m.group(3))
            return f"Info: Transfer file in binary mode.\nDownloading the file from the remote TFTP server. Please wait...\n  100%\nTFTP: Downloading the file successfully.\n {files[m.group(3)]} byte(s) received in 3 second(s)."
        m = re.match(r"startup system-software flash:/(\S+)", s)
        if m:
            if m.group(1) not in files:
                return "Error: The file does not exist."
            DEV["boot_file"] = m.group(1)
            return "Info: Succeeded in setting the software for booting system."
        if s == "display startup":
            return f"MainBoard:\n  Configured startup system software:        flash:/{DEV['model'].split('-')[0]}-{DEV['ver']}.cc\n  Startup system software:                   flash:/{DEV['model'].split('-')[0]}-{DEV['ver']}.cc\n  Next startup system software:              flash:/{DEV.get('boot_file') or DEV['model'].split('-')[0] + '-' + DEV['ver'] + '.cc'}"
        if s == "reboot":
            def go(a):
                if not a.lower().startswith("y"):
                    return "Info: The system did not reboot."
                if DEV.get("boot_file"):
                    DEV["pending_version"] = version_from_file(DEV["boot_file"]) or DEV["ver"]
                reboot()
                return None
            return self.ask("Info: The system is comparing the configuration, please wait.\nSystem will reboot! Continue ? [Y/N]:", go)
        return "              ^\nError: Unrecognized command found at '^' position."

    def hw_config(self, s):
        if s == "return":
            self.mode, self.iface = "exec", None
            return ""
        if s == "quit":
            self.mode, self.iface = ("config", None) if self.mode in ("if", "line") else ("exec", None)
            return ""
        if "bogus" in s or "INVALID" in s:
            return "              ^\nError: Unrecognized command found at '^' position."
        m = re.match(r"interface (\S+)$", s)
        if m:
            self.mode, self.iface = "if", m.group(1) if m.group(1) in DEV["ports"] else None
            return ""
        if s.startswith("user-interface"):
            self.mode = "line"
            return ""
        if self.mode == "if" and self.iface:
            p = DEV["ports"][self.iface]
            mapped = {"undo shutdown": "no shutdown", "undo poe enable": "power inline never", "poe enable": "power inline auto",
                      "undo description": "no description", "port link-type access": "switchport mode access"}.get(s, s)
            mv = re.match(r"port default vlan (\d+)", s)
            if mv:
                mapped = f"switchport access vlan {mv.group(1)}"
            self.port_cmd(p, mapped if not mapped.startswith("undo ") else "no " + mapped[5:])
            return ""
        if self.mode in ("line", "if"):
            return ""
        return self.global_cmd(s if not s.startswith("undo ") else "no " + s[5:])

    # ------------------------------------------------------------ Juniper Junos: staged candidate, applied on commit
    def snap(self):
        return copy.deepcopy({k: v for k, v in DEV.items() if k in ("ports", "flags", "extra_global", "removed_global")})

    def jun_exec(self, s):
        if s.startswith("set cli screen-width"):
            return "Screen width set to 511"
        if s.startswith("set cli screen-length"):
            return "Screen length set to 0"
        if s.startswith("set cli complete-on-space"):
            return "Disabling complete-on-space"
        if s in ("configure", "configure private", "edit"):
            self.mode, self.pending_cfg = "config", []
            return "Entering configuration mode"
        if s in ("exit", "quit"):
            return None
        files = DEV.setdefault("flash", {})
        table = MOD.commands(D)
        if s in table:
            return table[s](DEV)
        cmd, _, flt = s.partition(" | ")
        if cmd in table:
            return pipe(table[cmd](DEV), flt)
        m = re.match(r"file copy (\S+) /var/tmp/(\S+)", s)
        if m:
            if "nonexistent" in m.group(1):
                return f"error: file-fetch failed\nerror: could not fetch {m.group(1)}"
            time.sleep(3)
            files[m.group(2)] = 381000000 + len(m.group(2))
            return f"/var/tmp/{m.group(2)}                     100% of  363 MB   12 MBps 00:30"
        m = re.match(r"file checksum md5 /var/tmp/(\S+)", s)
        if m:
            if m.group(1) not in files:
                return f"error: could not resolve file: /var/tmp/{m.group(1)}"
            return f"MD5 (/var/tmp/{m.group(1)}) = {hashlib.md5(m.group(1).encode()).hexdigest()}"
        m = re.match(r"request system software add /var/tmp/(\S+)( no-validate)?( reboot)?", s)
        if m:
            f = m.group(1)
            if f not in files:
                return f"error: file does not exist: /var/tmp/{f}"
            DEV["pending_version"] = version_from_file(f) or DEV["ver"]
            if not m.group(3):
                return f"Installing package '/var/tmp/{f}' ...\nVerified {f} signed by PackageProductionECP256_2023 method ECDSA256+SHA256\nInstall completed\nWARNING: A reboot is required to install the software"
            self.send(f"Installing package '/var/tmp/{f}' ...\nInstall completed\nRebooting ...\nshutdown: [pid 3021]\nShutdown NOW!\n")
            reboot()
            return None
        if s == "request system reboot":
            return self.ask("Reboot the system ? [yes,no] (no) ", lambda a: (reboot(), None)[1] if a.startswith("y") else "")
        if s == "show system commit":
            return f"0   2026-11-12 08:00:00 UTC by {USER} via cli\n1   2026-10-02 08:00:00 UTC by root via cli"
        return f"                  ^\nunknown command."

    def jun_config(self, s):
        if s in ("exit configuration-mode", "exit", "quit", "top exit"):
            def leave(_a=None):
                self.mode, self.pending_cfg = "exec", []
                return "Exiting configuration mode"
            if self.pending_cfg:
                return self.ask("The configuration has been changed but not committed\nExit with uncommitted changes? [yes,no] (yes) ", leave)
            return leave()
        if s.startswith("commit"):
            for fn in self.pending_cfg:
                fn()
            self.pending_cfg = []
            return "commit complete"
        if s in ("show | compare", "show|compare"):
            return ""
        if s.startswith("rollback"):
            self.pending_cfg = []
            return "load complete"
        m = re.match(r"save /var/tmp/(\S+)", s)
        if m:
            DEV.setdefault("saved", {})[m.group(1)] = self.snap()
            return f"Wrote 123 lines of configuration to '/var/tmp/{m.group(1)}'"
        m = re.match(r"load override /var/tmp/(\S+)", s)
        if m:
            snap = DEV.get("saved", {}).get(m.group(1))
            if not snap:
                return f"error: Could not open configuration file: /var/tmp/{m.group(1)}"
            self.pending_cfg = [lambda: DEV.update(copy.deepcopy(snap))]
            return "load complete"
        m = re.match(r"(set|delete) (.+)$", s)
        if not m or "bogus" in s or "INVALID" in s:
            return f"                ^\nsyntax error."
        verb, rest = m.groups()
        vid_of = {n: v for v, n in junos.VLANS.items()}
        mi = re.match(r"interfaces (\S+) (.+)$", rest)
        canon = None
        if mi and mi.group(1) in DEV["ports"]:
            ifn, tail = mi.groups()
            if tail == "disable":
                canon = "shutdown" if verb == "set" else "no shutdown"
            elif tail.startswith("description"):
                canon = f"description {tail[12:].strip(chr(34))}" if verb == "set" else "no description"
            elif tail.endswith("interface-mode access"):
                canon = "switchport mode access"
            elif "vlan members" in tail:
                v = tail.split("vlan members", 1)[1].strip()
                canon = "" if verb == "delete" else f"switchport access vlan {v if v.isdigit() else vid_of.get(v, 1)}"
            else:
                canon = f"set interfaces {ifn} {tail}" if verb == "set" else f"no set interfaces {ifn} {tail}"
            p = DEV["ports"][ifn]
            self.pending_cfg.append(lambda p=p, c=canon: c and self.port_cmd(p, c))
            return ""
        mp = re.match(r"poe interface (\S+) disable", rest)
        if mp and mp.group(1) in DEV["ports"]:
            p = DEV["ports"][mp.group(1)]
            self.pending_cfg.append(lambda p=p, v=verb: self.port_cmd(p, "power inline never" if v == "set" else "power inline auto"))
            return ""
        flags = {"system services telnet": "telnet", "system services web-management http": "http", "snmp community public authorization read-only": "snmp_public"}
        if rest in flags:
            self.pending_cfg.append(lambda k=flags[rest], v=verb: DEV["flags"].__setitem__(k, v == "set"))
            return ""
        line = "set " + rest

        def glob(v=verb, line=line):
            if v == "set" and line not in DEV["extra_global"]:
                DEV["extra_global"].append(line)
            elif v == "delete":
                if line in DEV["extra_global"]:
                    DEV["extra_global"].remove(line)
                else:
                    DEV["removed_global"].append(line)
        self.pending_cfg.append(glob)
        return ""

    # ------------------------------------------------------------ Aruba AOS-S
    def aoss_exec(self, s):
        if s.startswith(("terminal ", "no page", "page")) or s == "enable":
            return ""
        if s in ("configure", "configure terminal", "config"):
            self.mode = "config"
            return ""
        if s in ("logout", "exit"):
            return None
        if s in ("write memory", "write mem"):
            return ""
        table = MOD.commands(D)
        cmd, _, flt = s.partition(" | ")
        if cmd in table:
            return pipe(table[cmd](DEV), flt) if flt else table[cmd](DEV)
        m = re.match(r"copy (tftp|sftp) flash (\S+) (\S+) (primary|secondary)", s)
        if m:
            f = m.group(3)

            def go(a):
                if not a.lower().startswith("y"):
                    return ""
                if "nonexistent" in f:
                    return "TFTP download failed: file not found"
                time.sleep(3)
                DEV["secondary_version"] = version_from_file(f) or DEV["ver"]
                return "00,104,857 bytes received\nValidating and Writing System Software to the Filesystem ..."
            return self.ask(f"The {m.group(4).title()} OS Image will be deleted, continue [y/n]? ", go)
        if s.startswith("boot set-default flash"):
            DEV["default_boot"] = s.split()[-1].title()
            return ""
        if s.startswith("boot system flash"):
            which = s.split()[-1]

            def go(a):
                if not a.lower().startswith("y"):
                    return ""
                if which == "secondary" and DEV.get("secondary_version"):
                    DEV["pending_version"] = DEV["secondary_version"]
                    DEV["secondary_version"] = DEV["ver"]
                reboot()
                return None
            return self.ask(f"System will be rebooted from {which} image. Do you want to continue [y/n]? ", go)
        return f"Invalid input: {s.split()[0]}"

    def aoss_config(self, s):
        if s == "end":
            self.mode, self.iface = "exec", None
            return ""
        if s == "exit":
            self.mode, self.iface = ("config", None) if self.mode in ("if", "vlan") else ("exec", None)
            return ""
        if "bogus" in s or "INVALID" in s:
            return f"Invalid input: {s.split()[0]}"
        m = re.match(r"vlan (\d+) untagged (\S+)$", s)
        if m:
            for n in m.group(2).split(","):
                if n in DEV["ports"]:
                    self.port_cmd(DEV["ports"][n], f"switchport access vlan {m.group(1)}")
            return ""
        m = re.match(r"vlan (\d+)$", s)
        if m:
            self.mode, self.iface = "vlan", m.group(1)
            return ""
        m = re.match(r"interface (\S+)$", s)
        if m:
            self.mode, self.iface = "if", m.group(1)
            return ""
        if self.mode == "vlan":
            m = re.match(r"untagged (\S+)", s)
            if m and m.group(1) in DEV["ports"]:
                self.port_cmd(DEV["ports"][m.group(1)], f"switchport access vlan {self.iface}")
            return ""
        if self.mode == "if" and self.iface in DEV["ports"]:
            p = DEV["ports"][self.iface]
            canon = {"disable": "shutdown", "enable": "no shutdown", "no name": "no description"}.get(s, s)
            mn = re.match(r'name "?([^"]*)"?$', s)
            if mn:
                canon = f"description {mn.group(1)}"
            self.port_cmd(p, canon)
            return ""
        f = DEV["flags"]
        if s in ("no telnet-server", "telnet-server"):
            f["telnet"] = not s.startswith("no ")
        elif s in ("no web-management", "web-management"):
            f["http"] = not s.startswith("no ")
        elif re.match(r'no snmp-server community "?public"?', s):
            f["snmp_public"] = False
        else:
            return self.global_cmd(s)
        return ""

    # ------------------------------------------------------------ FortiSwitch: config blocks, changes apply at once
    def fsw_exec(self, s):
        table = MOD.commands(D)
        cmd, _, flt = s.partition(" | ")
        if cmd in table:
            return pipe(table[cmd](DEV), flt) if flt else table[cmd](DEV)
        if s.startswith("config "):
            self.mode, self.ctx, self.edit = "config", [s[7:].split()[-1]], None
            self.section = s[7:]
            return ""
        m = re.match(r"execute restore image tftp (\S+) (\S+)", s)
        if m:
            f = m.group(1)

            def go(a):
                if not a.lower().startswith("y"):
                    return ""
                if "nonexistent" in f:
                    return "Download image failed."
                DEV["pending_version"] = version_from_file(f) or DEV["ver"]
                self.send("Please wait...\nConnect to tftp server " + m.group(2) + " ...\n#########################\nGet image from tftp server OK.\nCheck image OK.\nThis operation will reboot the system !\n")
                reboot()
                return None
            return self.ask("This operation will replace the current firmware version!\nDo you want to continue? (y/n)", go)
        if s == "execute reboot":
            return self.ask("This operation will reboot the system !\nDo you want to continue? (y/n)", lambda a: (reboot(), None)[1] if a.startswith("y") else "")
        if s in ("exit", "quit"):
            return None
        return "Unknown action 0\nCommand fail. Return code -1"

    def fsw_config(self, s):
        if "bogus" in s or "INVALID" in s:
            return f"command parse error before '{s.split()[-1]}'\nCommand fail. Return code -61"
        if s.startswith("config "):
            self.ctx.append(s[7:].split()[-1])
            return ""
        m = re.match(r'edit "?([^"]+)"?$', s)
        if m:
            self.edit = m.group(1)
            self.ctx.append(self.edit)
            return ""
        if s == "next":
            if self.edit:
                self.ctx.pop()
                self.edit = None
            return ""
        if s in ("end", "abort"):
            if self.edit:
                self.ctx.pop()
                self.edit = None
            if self.ctx:
                self.ctx.pop()
            if not self.ctx:
                self.mode = "exec"
            return ""
        sect = self.section
        p = DEV["ports"].get(self.edit or "")
        if p is not None and sect.endswith("physical-port"):
            canon = {"set status down": "shutdown", "set status up": "no shutdown", "unset description": "no description",
                     "set poe-status disable": "power inline never", "set poe-status enable": "power inline auto"}.get(s)
            md = re.match(r'set description "?([^"]*)"?', s)
            if md:
                canon = f"description {md.group(1)}"
            self.port_cmd(p, canon or s)
            return ""
        if p is not None and sect.endswith("switch interface"):
            mv = re.match(r"set native-vlan (\d+)", s)
            if mv:
                self.port_cmd(p, f"switchport access vlan {mv.group(1)}")
            elif s == "unset allowed-vlans":
                p["allowed"], p["mode"] = "", "access"
            return ""
        if sect.endswith("system interface") and s.startswith("set allowaccess"):
            DEV["flags"]["http"] = " http" in s
            DEV["flags"]["telnet"] = " telnet" in s
            return ""
        return ""

    def config_line(self, s):
        if HW:
            return self.hw_config(s)
        if JUN:
            return self.jun_config(s)
        if AOSS:
            return self.aoss_config(s)
        if FSW:
            return self.fsw_config(s)
        if s in ("end", "\x1a"):
            self.mode, self.iface = "exec", None
            if getattr(self, "changed", False):
                self.changed = False
                syslog(5, "SYS-5-CONFIG_I", f"Configured from console by {USER} on vty0 (172.31.99.250)")
            return ""
        if s not in ("exit",) and not s.startswith("do "):
            self.changed = True
        if s == "exit":
            if self.mode in ("if", "line"):
                self.mode, self.iface = "config", None
            else:
                self.mode = "exec"
            return ""
        if s.startswith("do "):
            return self.exec_line(s[3:])
        if "bogus" in s or "INVALID" in s:
            return "                ^\n% Invalid input detected at '^' marker."
        m = re.match(r"interface (\S+.*)$", s)
        if m:
            name = full_ifname(m.group(1).replace(" ", "")) if not CX else m.group(1).strip()
            if name in DEV["ports"]:
                self.mode, self.iface = "if", name
                return ""
            self.mode, self.iface = "if", None           # SVIs etc: accept, ignore
            return ""
        if re.match(r"line (vty|con)", s):
            self.mode = "line"
            return ""
        if self.mode == "line":
            DEV.setdefault("line_cfg", []).append(s)
            return ""
        if self.mode == "if":
            if self.iface:
                self.port_cmd(DEV["ports"][self.iface], s)
            return ""
        return self.global_cmd(s)

    def port_cmd(self, p, s):
        if s == "shutdown":
            p["prev_status"] = p["status"] if p["status"] != "disabled" else p.get("prev_status", "connected")
            p["status"], p["admin_down"] = "disabled", True
        elif s == "no shutdown":
            p["status"], p["admin_down"] = p.pop("prev_status", "connected" if p["speed"] else "notconnect"), False
        elif m := re.match(r"(?:switchport access vlan|vlan access) (\d+)", s):
            p["vlan"], p["mode"] = int(m.group(1)), "access"
        elif s == "switchport mode access":
            p["mode"], p["nomode"] = "access", False
        elif s.startswith("description "):
            p["desc"] = s[12:]
        elif s == "no description":
            p["desc"] = ""
        elif s in ("power inline never", "no power-over-ethernet"):
            p["poe_off"] = True
        elif s in ("power inline auto", "power-over-ethernet"):
            p["poe_off"] = False
        elif s == "spanning-tree portfast":
            p["portfast"] = True
        elif s == "spanning-tree bpduguard enable":
            p["bpdu"] = True
        elif s.startswith("storm-control broadcast"):
            p["storm"] = True
        elif s.startswith("no "):
            if s[3:] in p["extra"]:
                p["extra"].remove(s[3:])
            else:
                p["removed"].append(s[3:])
        elif s not in p["extra"]:
            p["extra"].append(s)

    def global_cmd(self, s):
        f = DEV["flags"]
        if s in ("no ip http server", "no ip http secure-server"):
            f["http"] = False
        elif s in ("ip http server", "ip http secure-server"):
            f["http"] = True
        elif re.match(r"no snmp-server community public", s):
            f["snmp_public"] = False
        elif m := re.match(r"boot system (?:flash|bootflash):(\S+)", s):
            DEV["boot_file"] = m.group(1)
        elif s.startswith(("no boot system", "hostname ")):
            pass
        elif s.startswith("no "):
            if s[3:] in DEV["extra_global"]:
                DEV["extra_global"].remove(s[3:])
            else:
                DEV["removed_global"].append(s[3:])
        elif s not in DEV["extra_global"]:
            DEV["extra_global"].append(s)
        return ""


# ------------------------------------------------------------------ SSH server
HOST_KEY = paramiko.RSAKey.generate(2048)


class Server(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        if rebooting():
            return paramiko.AUTH_FAILED
        if username == USER and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        syslog(4, "SEC_LOGIN-4-LOGIN_FAILED", f"Login failed [user: {username}] [Source: 0.0.0.0] [localport: 22] [Reason: Login Authentication Failed]")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, *a):
        return True


def serve_conn(sock):
    try:
        if rebooting():
            sock.close()
            return
        t = paramiko.Transport(sock)
        t.add_server_key(HOST_KEY)
        t.start_server(server=Server())
        chan = t.accept(30)
        if chan is None:
            t.close()
            return
        Session(chan).run()
        t.close()
    except Exception as exc:  # noqa: BLE001
        log.info("ssh session ended: %s", exc)


def ssh_main(port):
    # group-exchange key exchange (netmiko's Fortinet driver offers nothing else) needs the OpenSSH moduli file
    for f in (os.path.join(os.path.dirname(os.path.abspath(__file__)), "moduli"), "/etc/ssh/moduli"):
        if os.path.exists(f) and paramiko.Transport.load_server_moduli(f):
            break
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(50)
    log.info("%s: SSH on %s, SNMP community %s", NAME, port, COMMUNITY)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve_conn, args=(c,), daemon=True).start()


# ------------------------------------------------------------------ SNMP agent
def mib():
    """Sorted [(oid tuple, value)] built from the current state."""
    from pysnmp.proto import api
    m = api.PROTOCOL_MODULES[api.SNMP_VERSION_2C]
    tick()
    rows = []
    descr = f"Cisco IOS Software, Version {DEV['ver']}" if OS in ("ios", "iosxe") else ios.sys_descr(DEV)
    rows += [((1, 3, 6, 1, 2, 1, 1, 1, 0), m.OctetString(descr)), ((1, 3, 6, 1, 2, 1, 1, 2, 0), m.ObjectIdentifier((1, 3, 6, 1, 4, 1, ENTERPRISE))),
             ((1, 3, 6, 1, 2, 1, 1, 3, 0), m.TimeTicks(uptime_ticks())), ((1, 3, 6, 1, 2, 1, 1, 5, 0), m.OctetString(NAME))]
    ports = sorted(DEV["ports"].items(), key=lambda kv: [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", kv[0])])
    for idx, (name, p) in enumerate(ports, start=1):
        short = {"vrp": huawei.short, "nxos": nxos.short, "ios": ios.short, "iosxe": ios.short}.get(OS, lambda n: n)(name)
        up = p["status"] == "connected"
        mac = bytes.fromhex(mac_for(NAME, name))
        cols = {
            (2, 2, 1, 1): m.Integer(idx), (2, 2, 1, 2): m.OctetString(name), (2, 2, 1, 3): m.Integer(6), (2, 2, 1, 4): m.Integer(1500),
            (2, 2, 1, 5): m.Gauge32(min(p["speed"] * 10 ** 6, 4294967295)), (2, 2, 1, 6): m.OctetString(mac),
            (2, 2, 1, 7): m.Integer(2 if p["status"] == "disabled" else 1), (2, 2, 1, 8): m.Integer(1 if up else 2),
            (2, 2, 1, 13): m.Counter32(0), (2, 2, 1, 14): m.Counter32(p["in_err"] + p["crc"]), (2, 2, 1, 19): m.Counter32(p["drops"]),
            (2, 2, 1, 20): m.Counter32(p["out_err"]),
            (31, 1, 1, 1, 1): m.OctetString(short), (31, 1, 1, 1, 6): m.Counter64(octets(p, "in")), (31, 1, 1, 1, 10): m.Counter64(octets(p, "out")),
            (31, 1, 1, 1, 15): m.Gauge32(p["speed"] if up else 0), (31, 1, 1, 1, 18): m.OctetString(p["desc"]),
            (10, 7, 2, 1, 3): m.Counter32(p["crc"]), (10, 7, 2, 1, 8): m.Counter32(p["late"]),
            (10, 7, 2, 1, 19): m.Integer(2 if p["duplex"] == "half" else 3),
        }
        for col, val in cols.items():
            rows.append(((1, 3, 6, 1, 2, 1) + col + (idx,), val))
    h = DEV.get("health") or {}
    if h:
        if OS not in ("ios", "iosxe"):
            rows.append(((1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2, 1), m.Integer(h["cpu"])))
        else:
            rows += [((1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 8, 1), m.Gauge32(h["cpu"])),
                     ((1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 5, 1), m.Gauge32(h["mem_used"])),
                     ((1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 6, 1), m.Gauge32(h["mem_total"] - h["mem_used"])),
                     ((1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 3, 1, 3, 1), m.Gauge32(h["temp"]))]
            state = {"OK": 1, "FAULTY": 6, "No Input Power": 3, "Not Present": 5}
            for i, (n, st) in enumerate(h["fans"], start=1):
                rows += [((1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 4, 1, 2, i), m.OctetString(n)),
                         ((1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 4, 1, 3, i), m.Integer(state.get(st, 2)))]
            for i, (slot, _pid, st) in enumerate(h["psus"], start=1):
                rows += [((1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 5, 1, 2, i), m.OctetString(f"Switch 1 - Power Supply {slot[-1]}")),
                         ((1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 5, 1, 3, i), m.Integer(state.get(st, 2)))]
    rows.sort(key=lambda r: r[0])
    return rows


def snmp_answer(whole):
    from pyasn1.codec.ber import decoder, encoder
    from pysnmp.proto import api
    if rebooting():
        return None
    ver = int(api.decodeMessageVersion(whole))
    pm = api.PROTOCOL_MODULES[ver]
    req, _ = decoder.decode(whole, asn1Spec=pm.Message())
    if str(pm.apiMessage.get_community(req)) != COMMUNITY:
        return None
    rsp = pm.apiMessage.get_response(req)
    qpdu, rpdu = pm.apiMessage.get_pdu(req), pm.apiMessage.get_pdu(rsp)
    table = mib()
    oids = [o for o, _ in table]

    def nxt(oid):
        t = tuple(oid)
        for o, v in table:
            if o > t:
                return o, v
        return t, pm.EndOfMibView("")

    out = []
    if qpdu.isSameTypeWith(pm.GetRequestPDU()):
        d = dict(table)
        for oid, _v in pm.apiPDU.get_varbinds(qpdu):
            out.append((oid, d.get(tuple(oid), pm.NoSuchInstance(""))))
    elif qpdu.isSameTypeWith(pm.GetNextRequestPDU()):
        for oid, _v in pm.apiPDU.get_varbinds(qpdu):
            out.append(nxt(oid))
    elif ver == api.SNMP_VERSION_2C and qpdu.isSameTypeWith(pm.GetBulkRequestPDU()):
        nonrep = int(pm.apiBulkPDU.get_non_repeaters(qpdu))
        maxrep = min(int(pm.apiBulkPDU.get_max_repetitions(qpdu)), 50)
        vbs = pm.apiBulkPDU.get_varbinds(qpdu)
        for oid, _v in vbs[:nonrep]:
            out.append(nxt(oid))
        cur = [tuple(o) for o, _ in vbs[nonrep:]]
        for _ in range(maxrep):
            row = [nxt(o) for o in cur]
            out += row
            cur = [tuple(o) for o, _ in row]
            if all(o not in oids for o in cur):
                break
    else:
        return None
    pm.apiPDU.set_varbinds(rpdu, out)
    return encoder.encode(rsp)


class SnmpProto(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.t = transport

    def datagram_received(self, data, addr):
        try:
            with STATE["lock"]:
                ans = snmp_answer(data)
            if ans:
                self.t.sendto(ans, addr)
        except Exception as exc:  # noqa: BLE001
            log.info("snmp error: %s", exc)


def snmp_main(port):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(loop.create_datagram_endpoint(SnmpProto, local_addr=("0.0.0.0", port)))
    loop.run_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=f"%(asctime)s {NAME} %(message)s")
    threading.Thread(target=snmp_main, args=(int(os.environ.get("SNMP_PORT", "161")),), daemon=True).start()
    threading.Thread(target=watcher, daemon=True).start()
    threading.Thread(target=flow_exporter, daemon=True).start()
    ssh_main(int(os.environ.get("SSH_PORT", "22")))
