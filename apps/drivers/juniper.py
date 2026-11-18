"""Juniper Junos (EX / QFX, ELS) over SSH. Configuration is read in `display set` form, which the checks engine treats as
one global line per statement. Changes are committed, and rolled back with `load override` of a saved copy."""
import re

from .base import Driver, blocks, iface, num, to_int
from .cisco import norm_mac, text_uptime


def _vlan_map(cfg):
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"^set vlans (\S+) vlan-id (\d+)", cfg or "", re.M)}


class JuniperJunos(Driver):
    key = "juniper_junos"
    vendor = "Juniper"
    label = "Juniper Junos (EX / QFX)"
    family = "juniper_junos"
    os_type = "junos"
    netmiko_type = "juniper_junos"
    ntc_platform = "juniper_junos"
    status = "beta"
    models = "EX2300, EX3400, EX4100, EX4300, EX4400, EX4650, QFX5100/5110/5120 (ELS)"
    notes = ("Collection over SSH: version, chassis hardware and environment, CPU/memory, interfaces with errors, port modes and VLANs "
             "(from the configuration), LLDP, routes, MAC/ARP, configuration backup in `display set` form, security checks. Changes are "
             "committed; a copy of the configuration is saved to /var/tmp first so it can be restored with `load override`. "
             "New driver: please report anything that looks wrong.")
    upgrade_notes = ("The package is copied to /var/tmp, MD5-verified (`file checksum md5`), installed with `request system software add` and "
                     "activated by a reboot. Virtual Chassis: all members upgrade and reboot together unless you use NSSU (not automated).")
    features = {"ssh_collect": "full", "snmp": "full", "neighbors": "full", "vlans": "full", "routes": "full", "interfaces": "full",
                "config": "full", "security": "partial", "standards": "full", "psirt": "planned", "upgrade": "partial"}
    config_fail = r"^\s*(error:|syntax error|unknown command|missing argument)"
    flash = "/var/tmp/"

    def collect_commands(self):
        return [{"key": "version", "cmd": "show version"}, {"key": "hardware", "cmd": "show chassis hardware"},
                {"key": "env", "cmd": "show chassis environment"}, {"key": "re", "cmd": "show chassis routing-engine"},
                {"key": "running", "cmd": "show configuration | display set", "timeout": 180},
                {"key": "interfaces", "cmd": "show interfaces extensive", "timeout": 240}, {"key": "lldp", "cmd": "show lldp neighbors"},
                {"key": "route", "cmd": "show route table inet.0", "timeout": 120}] + self.mac_commands()

    def mac_commands(self):
        return [{"key": "mac", "cmd": "show ethernet-switching table", "timeout": 120}, {"key": "arp", "cmd": "show arp no-resolve", "timeout": 120},
                {"key": "running", "cmd": "show configuration | display set", "timeout": 180}]

    def poll_commands(self):
        return [{"key": "interfaces", "cmd": "show interfaces extensive", "timeout": 240},
                {"key": "running", "cmd": "show configuration | display set", "timeout": 180}]

    def parse(self, o):
        p = self.ntc_platform
        data = {"facts": {}, "interfaces": [], "neighbors": [], "routes": [], "vlans": [], "extra": {}}
        v = (self.ntc(p, "show version", o.get("version", "")) or [{}])[0]
        cfg = o.get("running", "")
        if o.get("version"):
            data["facts"] = {"hostname": v.get("hostname", ""), "vendor": "Juniper", "model": (v.get("model") or "").upper(),
                             "os_type": "junos",
                             "os_version": (v.get("junos_version") or "").strip()
                             or (re.search(r"\[(\d+\.\d+[RX][\w.-]+)\]", o.get("version", "")) or [None, ""])[1],
                             "uptime_seconds": text_uptime((re.search(r"Uptime\s+(.+)", o.get("re", "")) or [None, ""])[1])}
        m = re.search(r"^Chassis\s+(\S+)\s+(.+)$", o.get("hardware", ""), re.M)
        if m:
            data["facts"]["serial"] = m.group(1)
            data["facts"].setdefault("model", m.group(2).strip())
        mods = [{"name": " ".join(m.group(1).split()), "descr": m.group(5).strip(), "pid": m.group(3), "serial": m.group(4)}
                for m in re.finditer(r"^\s*((?:FPC|PIC|Power Supply|Xcvr)\s+\d+)\s+(REV \d+\s+)?(\S+)\s+(\S+)\s+(.+)$", o.get("hardware", ""), re.M)
                if m.group(3) != "BUILTIN"]
        if mods:
            data["facts"]["modules"] = mods
        if cfg:
            data["config"] = "\n".join(l for l in cfg.splitlines() if l.startswith("set ")) + "\n"
            m = re.search(r"^set system host-name (\S+)", cfg, re.M)
            if m:
                data["facts"]["hostname"] = m.group(1)
        data["interfaces"] = self.parse_interfaces(o)
        for r in self.ntc(p, "show lldp neighbors", o.get("lldp", "")):
            data["neighbors"].append({"protocol": "lldp", "local_interface": r.get("local_interface", ""), "remote_name": r.get("neighbor_name", ""),
                                      "remote_port": _short(r.get("neighbor_interface", "")), "remote_ip": "", "remote_platform": "",
                                      "remote_description": "", "capabilities": "Bridge Router"})
        cur = None
        for line in o.get("route", "").splitlines():
            m = re.match(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+[*+-]?\[(\w+)/(\d+)\]", line)
            if m:
                cur = {"vrf": "default", "protocol": {"Direct": "C", "Local": "L", "Static": "S", "OSPF": "O", "BGP": "B"}.get(m.group(2), m.group(2)),
                       "prefix": m.group(1), "distance": int(m.group(3)), "metric": None, "next_hop": "", "interface": "", "age": ""}
                data["routes"].append(cur)
                continue
            m = re.match(r"^\s+>?\s*(?:to (\S+) )?via (\S+)", line)
            if m and cur:
                cur["next_hop"], cur["interface"] = m.group(1) or "", m.group(2)
        vmap = _vlan_map(cfg)
        for name, vid in sorted(vmap.items(), key=lambda kv: kv[1]):
            members = sorted({m.group(1) for m in re.finditer(rf"^set interfaces (\S+) unit 0 family ethernet-switching vlan members {re.escape(name)}$", cfg, re.M)})
            data["vlans"].append({"vid": vid, "name": name, "status": "active", "ports": ", ".join(members)})
        data.update(self.parse_extras(o))
        data["health"] = self.parse_health(o)
        return data

    def parse_interfaces(self, o):
        cfg = o.get("running", "")
        vmap = _vlan_map(cfg)
        out = []
        for name, b in blocks(o.get("interfaces", ""), r"^Physical interface: ([^,]+),").items():
            if not re.match(r"^(ge|xe|et|mge|ae)-", name):
                if name == "irb":
                    for lm in re.finditer(r"Logical interface (irb\.\d+).*?Local: (\S+),", b, re.S):
                        out.append(iface(lm.group(1), mode="virtual", oper_up=True, status="connected", ip=lm.group(2) + "/24"))
                continue
            head = b.splitlines()[0]
            admin = "Administratively down" not in head
            up = head.rstrip().endswith("Up")
            mode_m = re.search(rf"^set interfaces {re.escape(name)} unit 0 family ethernet-switching interface-mode (\w+)", cfg, re.M)
            members = [m.group(1) for m in re.finditer(rf"^set interfaces {re.escape(name)} unit 0 family ethernet-switching vlan members (\S+)", cfg, re.M)]
            ids = [str(vmap.get(x, x)) for x in members]
            mode = (mode_m.group(1) if mode_m else ("access" if members else "unknown"))
            if re.search(rf"^set interfaces {re.escape(name)} unit 0 family inet address", cfg, re.M):
                mode = "routed"
            native = num(rf"set interfaces {re.escape(name)} native-vlan-id (\d+)", cfg, 1)
            lm = re.search(r"Link-mode: (\w+)-duplex, Speed: (\S+?),", b)
            spd = lm.group(2) if lm and up else ""
            mbps = None
            if spd:
                n = num(r"(\d+)", spd)
                mbps = n * 1000 if "gbps" in spd.lower() else n
            desc = (re.search(r"^\s+Description: (.+)$", b, re.M) or [None, ""])[1].strip()
            out.append(iface(name, description=desc, admin_up=admin, oper_up=up and admin,
                             status="disabled" if not admin else ("connected" if up else "notconnect"), mode=mode,
                             access_vlan=ids[0] if mode == "access" and ids else "", native_vlan=str(native) if mode == "trunk" else "",
                             trunk_vlans=",".join(sorted(ids, key=lambda x: int(x) if x.isdigit() else 0)) if mode == "trunk" else "",
                             speed=spd, duplex=lm.group(1).lower() if lm and up else "", speed_mbps=mbps,
                             mtu=num(r"MTU: (\d+)", b) or None, mac=(re.search(r"Current address: (\S+),", b) or [None, ""])[1],
                             in_errors=num(r"Input errors:\s+Errors: (\d+)", b), out_errors=num(r"Output errors:\s+Carrier transitions: \d+, Errors: (\d+)", b),
                             crc=num(r"CRC/Align errors\s+(\d+)", b), runts=num(r"Runts: (\d+)", b), collisions=num(r"Collisions: (\d+)", b),
                             late_collisions=num(r"Late collisions\s+\d+\s+(\d+)", b), in_discards=num(r"Input errors:\s+Errors: \d+, Drops: (\d+)", b),
                             out_drops=num(r"Output errors:.*?Drops: (\d+)", b.replace("\n", " ")),
                             in_rate_bps=num(r"Input  bytes\s*:\s*\d+\s+(\d+) bps", b), out_rate_bps=num(r"Output bytes\s*:\s*\d+\s+(\d+) bps", b),
                             last_flap=(re.search(r"Last flapped\s*: (.+)", b) or [None, ""])[1].strip(),
                             resets=num(r"Carrier transitions: (\d+)", b, None)))
        return out

    def parse_health(self, o):
        h = {}
        re_ = o.get("re", "")
        m = re.search(r"CPU utilization:.*?Idle\s+(\d+) percent", re_, re.S)
        if m:
            h["cpu"] = 100 - int(m.group(1))
        m = re.search(r"Total memory.*?\(\s*(\d+) percent\)", re_)
        if m:
            h["mem_pct"] = int(m.group(1))
        env = o.get("env", "")
        temps = [int(t) for t in re.findall(r"(\d+) degrees C", env)]
        if temps:
            h["temp"] = max(temps)
        bad_temp = re.search(r"^\S*\s+FPC \d+ .*?\s+(Check|Failed|Absent)\s+\d+ degrees", env, re.M)
        h["temp_state"] = "YELLOW" if bad_temp else "GREEN"
        h["psus"] = [{"name": m.group(1), "pid": "", "status": "Not Present" if m.group(2) == "Absent" else m.group(2)}
                     for m in re.finditer(r"FPC \d+ (Power Supply \d+)\s+(\w+)", env)]
        h["fans"] = [{"name": m.group(1), "status": m.group(2)} for m in re.finditer(r"FPC \d+ (Fan Tray \d+ Fan \d+)\s+(\w+)", env)]
        return h

    def parse_extras(self, o, data=None):
        out = {}
        vmap = _vlan_map(o.get("running", ""))
        if "mac" in o:
            out["macs"] = []
            for m in re.finditer(r"^\s+(\S+)\s+([0-9a-f:]{17})\s+(\S+)\s+\S+\s+(\S+)", o.get("mac", ""), re.M):
                vlan = vmap.get(m.group(1)) or to_int(re.sub(r"\D", "", m.group(1)), None)
                out["macs"].append({"vlan": vlan, "mac": norm_mac(m.group(2)), "interface": m.group(4).split(".")[0],
                                    "type": "dynamic" if "D" in m.group(3) else "static"})
        if "arp" in o:
            out["arp"] = [{"ip": r.get("ip_address"), "mac": norm_mac(r.get("mac_address")), "interface": r.get("interface", "")}
                          for r in self.ntc(self.ntc_platform, "show arp no-resolve", o.get("arp", "")) if norm_mac(r.get("mac_address"))]
        return out

    def parse_poll(self, outputs):
        return self.parse_interfaces(outputs)

    # ---- changes: every change ends with a commit
    def port_commands(self, action, interface, value=""):
        i = interface
        if action == "shutdown":
            return [f"set interfaces {i} disable", "commit"], None
        if action == "no_shutdown":
            return [f"delete interfaces {i} disable", "commit"], None
        if action == "bounce":
            return [f"set interfaces {i} disable", "commit"], [f"delete interfaces {i} disable", "commit"]
        if action == "access_vlan":
            return [f"delete interfaces {i} unit 0 family ethernet-switching vlan members",
                    f"set interfaces {i} unit 0 family ethernet-switching interface-mode access",
                    f"set interfaces {i} unit 0 family ethernet-switching vlan members {int(value)}", "commit"], None
        if action == "description":
            return [f'set interfaces {i} description "{value}"' if value else f"delete interfaces {i} description", "commit"], None
        if action == "poe_off":
            return [f"set poe interface {i} disable", "commit"], None
        if action == "poe_on":
            return [f"delete poe interface {i} disable", "commit"], None
        if action == "poe_cycle":
            return [f"set poe interface {i} disable", "commit"], [f"delete poe interface {i} disable", "commit"]
        raise ValueError(action)

    def backup_steps(self, name):
        return [{"label": f"save rollback point /var/tmp/{name}", "cmd": f"save /var/tmp/{name}", "mode": "config", "timeout": 120,
                 "fail_on": r"error:"}]

    def rollback_steps(self, name):
        return [{"label": f"roll back to /var/tmp/{name}", "cmd": f"load override /var/tmp/{name}\ncommit", "mode": "config", "timeout": 300,
                 "fail_on": r"error:"}]

    def save_steps(self):
        return []          # a commit is persistent

    def upgrade_steps(self, stage, device, image, ctx):
        dst = f"/var/tmp/{image.filename}"
        if stage == "precheck":
            return [{"key": "version", "cmd": "show version"}, {"key": "dir", "cmd": "show system storage", "timeout": 60},
                    {"key": "files", "cmd": "file list /var/tmp/"}], []
        if stage == "transfer":
            return [], [{"label": f"file copy {image.transfer_url_masked} {dst}", "cmd": f"file copy {image.transfer_url} {dst}", "timeout": 5400,
                         "fail_on": r"error|failed|No such file"}]
        if stage == "verify":
            return [{"key": "md5", "cmd": f"file checksum md5 {dst}", "timeout": 900}], []
        if stage == "activate":
            cmd = f"request system software add {dst} no-validate" + (" reboot" if ctx.get("allow_reload") else "")
            return [], [{"cmd": cmd, "timeout": 3600, "drop_ok": True, "expect": r"(?i)reboot|install completed|will be activated",
                         "fail_on": r"(?i)ERROR|failed"}]
        if stage == "postcheck":
            return [{"key": "version", "cmd": "show version"}], []
        raise ValueError(stage)

    def precheck(self, out, image):
        """(free bytes or None, image already on the switch?) from the precheck outputs."""
        m = re.search(r"^/dev/\S+\s+\S+\s+\S+\s+([\d.]+)([KMG])\s+\d+%\s+/\.mount\s*$", out.get("dir", ""), re.M)
        free = int(float(m.group(1)) * {"K": 2**10, "M": 2**20, "G": 2**30}[m.group(2)]) if m else None
        return free, image.filename in out.get("files", "")


def _short(port):
    from apps.inventory.models import short_ifname
    return short_ifname(port)
