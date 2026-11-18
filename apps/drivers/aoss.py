"""Aruba AOS-S / ProCurve (2530, 2540, 2930F/M, 3810M, 5400R) over SSH. Port VLAN membership comes from the `vlan` blocks of the
running configuration, which is how AOS-S models it (untagged = access/native, tagged = trunk)."""
import re
from urllib.parse import urlparse

from .base import Driver, iface, num, to_int
from .cisco import norm_mac, text_uptime


def expand(spec):
    out = []
    for part in re.split(r",", spec or ""):
        part = part.strip()
        m = re.match(r"^([A-Za-z]*)(\d+)-\1?(\d+)$", part)
        if m:
            out += [f"{m.group(1)}{n}" for n in range(int(m.group(2)), int(m.group(3)) + 1)]
        elif part:
            out.append(part)
    return out


def vlan_membership(cfg):
    """{port: {"untagged": vid, "tagged": [vids]}} and {vid: name} from `vlan N ... exit` blocks."""
    ports, names = {}, {}
    for m in re.finditer(r"^vlan (\d+)\n(.*?)^\s+exit", cfg or "", re.M | re.S):
        vid, body = int(m.group(1)), m.group(2)
        n = re.search(r'name "([^"]*)"', body)
        names[vid] = n.group(1) if n else ""
        for u in re.findall(r"^\s+untagged (\S+)", body, re.M):
            for p in expand(u):
                ports.setdefault(p, {"untagged": None, "tagged": []})["untagged"] = vid
        for t in re.findall(r"^\s+tagged (\S+)", body, re.M):
            for p in expand(t):
                ports.setdefault(p, {"untagged": None, "tagged": []})["tagged"].append(vid)
    return ports, names


class ArubaAOSS(Driver):
    key = "aruba_aoss"
    vendor = "HPE Aruba"
    label = "Aruba AOS-S / ProCurve"
    family = "aruba_aoss"
    os_type = "aoss"
    netmiko_type = "hp_procurve"
    ntc_platform = "hp_procurve"
    status = "beta"
    models = "2530, 2540, 2920, 2930F, 2930M, 3810M, 5400R zl2"
    notes = ("Collection over SSH: system and serial, port status, speed/duplex and errors, VLAN membership, LLDP, routes, MAC/ARP, CPU, "
             "memory, power, fans and temperature, configuration backup, security checks, port changes. AOS-S has no configuration "
             "rollback from the CLI, so changes run without an automatic rollback point. New driver: please report anything that looks wrong.")
    upgrade_notes = ("The image is copied to the secondary flash over TFTP or SFTP (`copy tftp flash … secondary`), checked with `show flash`, "
                     "and activated with `boot system flash secondary` (reboot). Stacks (VSF/backplane) reboot all members together.")
    features = {"ssh_collect": "full", "snmp": "full", "neighbors": "full", "vlans": "full", "routes": "full", "interfaces": "full",
                "config": "full", "security": "partial", "standards": "full", "psirt": "planned", "upgrade": "partial"}
    md5_verify = False
    config_fail = r"^\s*(Invalid input|Ambiguous input|Incomplete input|Value \S+ is invalid)"

    def collect_commands(self):
        return [{"key": "system", "cmd": "show system"}, {"key": "modules", "cmd": "show modules"},
                {"key": "running", "cmd": "show running-config", "timeout": 180}, {"key": "brief", "cmd": "show interfaces brief"},
                {"key": "counters", "cmd": "show interfaces"}, {"key": "lldp", "cmd": "show lldp info remote-device detail", "timeout": 120},
                {"key": "route", "cmd": "show ip route"}, {"key": "power", "cmd": "show system power-supply"},
                {"key": "fans", "cmd": "show system fans"}, {"key": "temp", "cmd": "show system temperature"}] + self.mac_commands()

    def mac_commands(self):
        return [{"key": "mac", "cmd": "show mac-address", "timeout": 120}, {"key": "arp", "cmd": "show arp", "timeout": 60}]

    def poll_commands(self):
        return [{"key": "brief", "cmd": "show interfaces brief"}, {"key": "counters", "cmd": "show interfaces"},
                {"key": "running", "cmd": "show running-config", "timeout": 180}]

    def parse(self, o):
        data = {"facts": {}, "interfaces": [], "neighbors": [], "routes": [], "vlans": [], "extra": {}}
        s = o.get("system", "")
        if s:
            data["facts"] = {"hostname": (re.search(r"System Name\s*:\s*(\S+)", s) or [None, ""])[1], "vendor": "Aruba", "os_type": "aoss",
                             "os_version": (re.search(r"Software revision\s*:\s*(\S+)", s) or [None, ""])[1],
                             "serial": (re.search(r"Serial Number\s*:\s*(\S+)", s) or [None, ""])[1],
                             "uptime_seconds": text_uptime((re.search(r"Up Time\s*:\s*(.+?)\s{2,}", s) or [None, ""])[1])}
        m = re.search(r"Chassis:\s*(.+?)\s+(J[A-Z]\d{3,4}A)\s", o.get("modules", ""))
        if m:
            data["facts"]["model"] = f"{m.group(2)} {m.group(1)}"
        cfg = o.get("running", "")
        if cfg:
            data["config"] = "\n".join(l for l in cfg.splitlines() if not l.startswith("; Ver #")).strip() + "\n"
        data["interfaces"] = self.parse_interfaces(o)
        for b in re.split(r"^-{20,}\s*$", o.get("lldp", ""), flags=re.M):
            lp = re.search(r"Local Port\s*:\s*(\S+)", b)
            if not lp:
                continue
            def field(name):            # values may be empty: never run onto the next line
                m = re.search(rf"^[ \t]*{name}[ \t]*:[ \t]*(.*?)[ \t]*$", b, re.M)
                return m.group(1) if m else ""
            desc = field(r"System Descr")
            name = field("SysName") or field("ChassisId")
            port = field("PortId")
            if field("PortType") == "mac-address":
                port = port.replace(" ", "")
            data["neighbors"].append({"protocol": "lldp", "local_interface": lp.group(1), "remote_name": name, "remote_port": _short(port),
                                      "remote_ip": (re.search(r"Address[ \t]*:[ \t]*(\d+\.\d+\.\d+\.\d+)", b) or [None, ""])[1],
                                      "remote_platform": desc[:120], "remote_description": desc,
                                      "capabilities": field("System Capabilities Enabled")})
        for m in re.finditer(r"^\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)\s+(\d*)\s+(static|connected|ospf|rip|bgp)\s+(\S*)\s+(\d+)\s+(\d+)\s*$",
                             o.get("route", ""), re.M):
            if m.group(1).startswith("127."):
                continue
            gw = m.group(2)
            proto = {"connected": "C", "static": "S", "ospf": "O", "rip": "R", "bgp": "B"}[m.group(4)]
            data["routes"].append({"vrf": "default", "protocol": proto, "prefix": m.group(1), "distance": int(m.group(7)), "metric": int(m.group(6)),
                                   "next_hop": gw if re.match(r"\d+\.", gw) else "", "interface": f"VLAN{m.group(3)}" if m.group(3) else gw, "age": ""})
        members, names = vlan_membership(cfg)
        for vid, name in sorted(names.items()):
            ports = [p for p, mm in members.items() if mm["untagged"] == vid or vid in mm["tagged"]]
            data["vlans"].append({"vid": vid, "name": name, "status": "active", "ports": ", ".join(ports)})
        data.update(self.parse_extras(o))
        h = {}
        m = re.search(r"CPU Util \(%\)\s*:\s*(\d+)", s)
        if m:
            h["cpu"] = int(m.group(1))
        tot, free = re.search(r"Memory\s+-\s+Total\s*:\s*([\d,]+)", s), re.search(r"^\s.*?Free\s*:\s*([\d,]+)", s, re.M)
        if tot and free and to_int(tot.group(1)):
            h["mem_pct"] = round(100 * (to_int(tot.group(1)) - to_int(free.group(1))) / to_int(tot.group(1)))
        h["psus"] = [{"name": f"PS {m.group(1)}", "pid": m.group(2), "status": m.group(3)}
                     for m in re.finditer(r"^\s+\d+\s+(\d+)\s+(\S+)\s+\S+\s+(Powered|Aux Failed|Failed|Not Powered|Permanent Failure)", o.get("power", ""), re.M)]
        h["fans"] = [{"name": m.group(1), "status": m.group(2).strip()} for m in re.finditer(r"^(Sys-\d+)\s+\|\s+(.+?)\s+\|", o.get("fans", ""), re.M)]
        t = re.search(r"Chassis\s*\|\s*(\d+)C\s+\S+\s+\S+\s+\S+\s+(YES|NO)", o.get("temp", ""))
        if t:
            h["temp"], h["temp_state"] = int(t.group(1)), "RED" if t.group(2) == "YES" else "GREEN"
        data["health"] = h
        return data

    def parse_interfaces(self, o):
        members, _names = vlan_membership(o.get("running", ""))
        cfg = o.get("running", "")
        cnt = {m.group(1): m for m in re.finditer(r"^\s+(\S+)\s+[\d,]+\s+[\d,]+\s+([\d,]+)\s+([\d,]+)\s+\S+\s+\d+\s*$", o.get("counters", ""), re.M)}
        out = []
        for m in re.finditer(r"^\s+(\S+)\s+(\S+)\s+\|\s+\S+\s+(Yes|No)\s+(Up|Down)\s+(\S+)\s+(\S+)", o.get("brief", ""), re.M):
            name, typ, enabled, link, pmode = m.group(1).rstrip("*"), m.group(2), m.group(3) == "Yes", m.group(4) == "Up", m.group(5)
            if name == "Port":
                continue
            mm = members.get(name, {"untagged": None, "tagged": []})
            mode = "trunk" if mm["tagged"] else ("access" if mm["untagged"] else "unknown")
            sm = re.match(r"(\d+)(Gig)?(FDx|HDx|FD|HD)", pmode)
            mbps = (int(sm.group(1)) * (1000 if sm.group(2) else 1)) if sm and link else None
            body = re.search(rf"^interface {re.escape(name)}\n(.*?)^\s+exit", cfg, re.M | re.S)
            desc = (re.search(r'name "([^"]*)"', body.group(1)) or [None, ""])[1] if body else ""
            c = cnt.get(name)
            out.append(iface(name, description=desc, admin_up=enabled, oper_up=link and enabled,
                             status="disabled" if not enabled else ("connected" if link else "notconnect"), mode=mode,
                             access_vlan=str(mm["untagged"] or "") if mode == "access" else "",
                             native_vlan=str(mm["untagged"] or "") if mode == "trunk" else "",
                             trunk_vlans=",".join(str(v) for v in sorted(mm["tagged"] + ([mm["untagged"]] if mm["untagged"] else []))) if mode == "trunk" else "",
                             speed=pmode if link else "", duplex=("half" if sm and sm.group(3).startswith("H") else "full") if link else "",
                             speed_mbps=mbps, media=typ, in_errors=to_int(c.group(2)) if c else 0, crc=to_int(c.group(2)) if c else 0,
                             out_drops=to_int(c.group(3)) if c else 0))
        return out

    def parse_extras(self, o, data=None):
        out = {}
        if "mac" in o:
            out["macs"] = [{"vlan": int(m.group(3)), "mac": norm_mac(m.group(1)), "interface": m.group(2), "type": "dynamic"}
                           for m in re.finditer(r"^\s+([0-9a-f]{6}-[0-9a-f]{6})\s+(\S+)\s+(\d+)\s*$", o.get("mac", ""), re.M)]
        if "arp" in o:
            out["arp"] = [{"ip": m.group(1), "mac": norm_mac(m.group(2)), "interface": m.group(4)}
                          for m in re.finditer(r"^\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{6}-[0-9a-f]{6})\s+(\S+)\s+(\S+)", o.get("arp", ""), re.M)]
        return out

    def parse_poll(self, outputs):
        return self.parse_interfaces(outputs)

    # ---- changes
    def port_commands(self, action, interface, value=""):
        head = [f"interface {interface}"]
        if action == "shutdown":
            return head + ["disable"], None
        if action == "no_shutdown":
            return head + ["enable"], None
        if action == "bounce":
            return head + ["disable"], head + ["enable"]
        if action == "access_vlan":
            return [f"vlan {int(value)} untagged {interface}"], None
        if action == "description":
            return head + [f'name "{value}"' if value else "no name"], None
        if action == "poe_off":
            return head + ["no power-over-ethernet"], None
        if action == "poe_on":
            return head + ["power-over-ethernet"], None
        if action == "poe_cycle":
            return head + ["no power-over-ethernet"], head + ["power-over-ethernet"]
        raise ValueError(action)

    def backup_steps(self, name):
        return []

    def rollback_steps(self, name):
        return []

    def save_steps(self):
        return [{"cmd": "write memory", "timeout": 120}]

    def upgrade_steps(self, stage, device, image, ctx):
        if stage in ("precheck", "postcheck"):
            return [{"key": "version", "cmd": "show version"}, {"key": "dir", "cmd": "show flash"}], []
        if stage == "transfer":
            u = urlparse(image.transfer_url)
            path = u.path.lstrip("/")
            if u.scheme == "tftp":
                cmd = f"copy tftp flash {u.hostname} {path} secondary"
            elif u.scheme in ("sftp", "scp"):
                cmd = f"copy sftp flash {u.username or 'vmap'}@{u.hostname} {path} secondary"
            else:
                raise ValueError("AOS-S copies images over TFTP or SFTP: use a tftp:// or sftp:// URL for this image.")
            ans = [[r"(?i)continue \[y/n\]", "y"]] + ([[r"(?i)password", u.password]] if u.password else [])
            return [], [{"label": f"copy {image.transfer_url_masked} secondary", "cmd": cmd, "answers": ans, "timeout": 3600,
                         "fail_on": r"(?i)error|failed|not found|timed out"}]
        if stage == "verify":
            return [{"key": "flash", "cmd": "show flash"}], []
        if stage == "activate":
            if not ctx.get("allow_reload"):
                return [], [{"cmd": "boot set-default flash secondary", "timeout": 60}]
            return [], [{"cmd": "write memory", "timeout": 120},
                        {"cmd": "boot system flash secondary", "fire_and_forget": True, "answers": [[r"(?i)continue \[y/n\]", "y"], [r"(?i)save .*\[y/n\]", "n"]]}]
        raise ValueError(stage)

    def precheck(self, out, image):
        sec = re.search(r"Secondary Image\s*:\s*\d+\s+\S+\s+(\S+)", out.get("dir", ""))
        return None, bool(sec and image.version and sec.group(1) == image.version)

    def verify_ok(self, out, image):
        sec = re.search(r"Secondary Image\s*:\s*\d+\s+\S+\s+(\S+)", out.get("flash", ""))
        return (bool(sec and (not image.version or sec.group(1) == image.version)),
                f"secondary flash holds {sec.group(1) if sec else 'nothing'}")


def _short(port):
    from apps.inventory.models import short_ifname
    return short_ifname(port)
