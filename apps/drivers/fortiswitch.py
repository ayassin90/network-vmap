"""Fortinet FortiSwitch in standalone mode (FortiSwitchOS CLI) over SSH. FortiLink-managed switches are configured from the
FortiGate; VMap can still read them, but changes should be made on the FortiGate."""
import re
from urllib.parse import urlparse

from .base import Driver, blocks, iface, num, to_int
from .cisco import norm_mac, text_uptime


def config_section(cfg, path):
    """Body of `config <path> ... end` (top level)."""
    m = re.search(rf"^config {re.escape(path)}\n(.*?)^end$", cfg or "", re.M | re.S)
    return m.group(1) if m else ""


def edits(body):
    """{name: body} for each `edit "name" ... next` in a config section."""
    return {m.group(1).strip('"'): m.group(2) for m in re.finditer(r'^\s{4}edit ("?[^"\n]+"?)\n(.*?)^\s{4}next', body, re.M | re.S)}


class FortiSwitch(Driver):
    key = "fortiswitch"
    vendor = "Fortinet"
    label = "FortiSwitch (standalone)"
    family = "fortiswitch"
    os_type = "fortiswitch"
    netmiko_type = "fortinet"
    ntc_platform = "fortinet"
    status = "beta"
    models = "FortiSwitch 100E/F, 200E/F, 400E, 500 series, 1000 series, 3000 series (standalone mode)"
    notes = ("Collection over SSH in standalone mode: status and serial, port status, errors and rates, native and allowed VLANs, LLDP, "
             "routes, MAC/ARP, CPU and memory, configuration backup, security checks, port changes (no rollback point: FortiSwitchOS "
             "has no CLI configuration replace). FortiLink-managed switches: collect them read-only and change them on the FortiGate.")
    upgrade_notes = ("`execute restore image tftp <file> <server>` copies, installs and reboots in one step, so copy and activation happen "
                     "together in the activate stage (reload must be allowed). FortiLink switches are upgraded from the FortiGate.")
    features = {"ssh_collect": "full", "snmp": "full", "neighbors": "full", "vlans": "full", "routes": "full", "interfaces": "full",
                "config": "full", "security": "partial", "standards": "full", "psirt": "planned", "upgrade": "partial"}
    md5_verify = False
    config_fail = r"^\s*(Command fail|command parse error|Unknown action|node_check_object fail|value parse error)"

    def collect_commands(self):
        return [{"key": "status", "cmd": "get system status"}, {"key": "perf", "cmd": "get system performance status"},
                {"key": "running", "cmd": "show", "timeout": 180}, {"key": "summary", "cmd": "diagnose switch physical-ports summary"},
                {"key": "stats", "cmd": "diagnose switch physical-ports stats list", "timeout": 120},
                {"key": "lldp", "cmd": "get switch lldp neighbors-detail", "timeout": 120},
                {"key": "route", "cmd": "get router info routing-table all"}] + self.mac_commands()

    def mac_commands(self):
        return [{"key": "mac", "cmd": "diagnose switch mac-address list", "timeout": 120}, {"key": "arp", "cmd": "get system arp"}]

    def poll_commands(self):
        return [{"key": "summary", "cmd": "diagnose switch physical-ports summary"},
                {"key": "stats", "cmd": "diagnose switch physical-ports stats list", "timeout": 120}, {"key": "running", "cmd": "show", "timeout": 180}]

    def parse(self, o):
        data = {"facts": {}, "interfaces": [], "neighbors": [], "routes": [], "vlans": [], "extra": {}}
        s = o.get("status", "")
        if s:
            m = re.search(r"Version:\s*Forti(\w+)-(\S+)\s+(v[\d.]+)", s)
            data["facts"] = {"hostname": (re.search(r"Hostname:\s*(\S+)", s) or [None, ""])[1], "vendor": "Fortinet",
                             "model": ({"Switch": "FS-", "Gate": "FG-"}.get(m.group(1), "") + m.group(2)) if m else "", "os_type": "fortiswitch", "os_version": m.group(3) if m else "",
                             "serial": (re.search(r"Serial-Number:\s*(\S+)", s) or [None, ""])[1],
                             "uptime_seconds": text_uptime((re.search(r"Uptime:\s*(.+)", o.get("perf", "")) or [None, ""])[1])}
        cfg = o.get("running", "")
        if cfg:
            data["config"] = "\n".join(l for l in cfg.splitlines() if not l.startswith("#conf_file_ver")).strip() + "\n"
        data["interfaces"] = self.parse_interfaces(o)
        for b in re.split(r"(?=^Neighbor learned on port)", o.get("lldp", ""), flags=re.M):
            lp = re.match(r"Neighbor learned on port (\S+)", b)
            if not lp:
                continue
            desc = (re.search(r"System Description:\s*\n(.+)", b) or [None, ""])[1].strip()
            data["neighbors"].append({"protocol": "lldp", "local_interface": lp.group(1), "remote_name": (re.search(r"System Name:\s*(\S+)", b) or [None, ""])[1],
                                      "remote_port": _short((re.search(r"Port ID:\s*(\S+)", b) or [None, ""])[1]),
                                      "remote_ip": (re.search(r"Management IP Address:\s*(\S+)", b) or [None, ""])[1], "remote_platform": desc[:120],
                                      "remote_description": desc, "capabilities": _caps((re.search(r"Enabled Capabilities:\s*(\S+)", b) or [None, ""])[1])})
        for line in o.get("route", "").splitlines():
            m = re.match(r"^([A-Z][A-Z0-9]*\*?)\s+(\d+\.\d+\.\d+\.\d+/\d+)\s+(?:\[(\d+)/(\d+)\] via (\S+?), (\S+?)(?:,|$)|is directly connected, (\S+))", line)
            if m:
                data["routes"].append({"vrf": "default", "protocol": m.group(1).rstrip("*"), "prefix": m.group(2), "distance": to_int(m.group(3), None),
                                       "metric": to_int(m.group(4), None), "next_hop": m.group(5) or "", "interface": m.group(6) or m.group(7) or "", "age": ""})
        for vid, body in edits(config_section(cfg, "switch vlan")).items():
            data["vlans"].append({"vid": to_int(vid), "name": (re.search(r'set description "([^"]*)"', body) or [None, ""])[1], "status": "active", "ports": ""})
        data.update(self.parse_extras(o))
        h = {}
        pf = o.get("perf", "")
        m = re.search(r"CPU states:.*?(\d+)% idle", pf)
        if m:
            h["cpu"] = 100 - int(m.group(1))
        m = re.search(r"Memory states:\s*(\d+)% used", pf)
        if m:
            h["mem_pct"] = int(m.group(1))
        data["health"] = h
        return data

    def parse_interfaces(self, o):
        cfg = o.get("running", "")
        phys, swif = edits(config_section(cfg, "switch physical-port")), edits(config_section(cfg, "switch interface"))
        stats = blocks(o.get("stats", ""), r"^Port\((\S+?)\)")
        out = []
        for m in re.finditer(r"^\s(port\d+|\S+)\s+(up|down)\s+\w+\s+(\d+)\s+(\w+)\s+(\S+)", o.get("summary", ""), re.M):
            name, link, vlan, duplex, spd = m.group(1), m.group(2) == "up", m.group(3), m.group(4), m.group(5)
            pb, sb, st = phys.get(name, ""), swif.get(name, ""), stats.get(name, "")
            admin = "set status down" not in pb
            allowed = (re.search(r"set allowed-vlans (\S+)", sb) or [None, ""])[1]
            native = (re.search(r"set native-vlan (\d+)", sb) or [None, vlan])[1]
            mode = "trunk" if allowed else "access"
            n = num(r"(\d+)", spd)
            mbps = (n * 1000 if spd.upper().endswith("G") else n) if link else None
            out.append(iface(name, description=(re.search(r'set description "([^"]*)"', pb) or [None, ""])[1], admin_up=admin,
                             oper_up=link and admin, status="disabled" if not admin else ("connected" if link else "notconnect"), mode=mode,
                             access_vlan=native if mode == "access" else "", native_vlan=native if mode == "trunk" else "",
                             trunk_vlans=allowed, speed=spd if link else "", duplex=duplex if link else "", speed_mbps=mbps,
                             mtu=num(r"MTU (\d+) bytes", st) or None, mac=(re.search(r"Address is (\S+),", st) or [None, ""])[1],
                             in_errors=num(r"input\s+:.*?(\d+) errors", st), out_errors=num(r"output\s+:.*?(\d+) errors", st),
                             crc=num(r"(\d+) fcs_errors", st), collisions=num(r"(\d+) collisions", st), late_collisions=num(r"(\d+) late collisions", st),
                             in_discards=num(r"input\s+:.*?(\d+) drops", st), out_drops=num(r"output\s+:.*?(\d+) drops", st),
                             in_rate_bps=num(r"input rate (\d+) bps", st), out_rate_bps=num(r"output rate (\d+) bps", st)))
        return out

    def parse_extras(self, o, data=None):
        out = {}
        if "mac" in o:
            out["macs"] = [{"vlan": int(m.group(2)), "mac": norm_mac(m.group(1)), "interface": m.group(3), "type": "dynamic"}
                           for m in re.finditer(r"^MAC:\s*([0-9a-f:]{17})\s+VLAN:\s*(\d+)\s+Trunk:\s*([^\s(]+)", o.get("mac", ""), re.M)]
        if "arp" in o:
            out["arp"] = [{"ip": m.group(1), "mac": norm_mac(m.group(2)), "interface": m.group(3)}
                          for m in re.finditer(r"^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+([0-9a-f:]{17})\s+(\S+)", o.get("arp", ""), re.M)]
        return out

    def parse_poll(self, outputs):
        return self.parse_interfaces(outputs)

    # ---- changes: FortiOS-style config blocks, applied as they are entered
    def port_commands(self, action, interface, value=""):
        phys = ["config switch physical-port", f'edit "{interface}"']
        if action == "shutdown":
            return phys + ["set status down", "next", "end"], None
        if action == "no_shutdown":
            return phys + ["set status up", "next", "end"], None
        if action == "bounce":
            return phys + ["set status down", "next", "end"], phys + ["set status up", "next", "end"]
        if action == "access_vlan":
            return ["config switch interface", f'edit "{interface}"', f"set native-vlan {int(value)}", "unset allowed-vlans", "next", "end"], None
        if action == "description":
            return phys + [f'set description "{value}"' if value else "unset description", "next", "end"], None
        if action == "poe_off":
            return phys + ["set poe-status disable", "next", "end"], None
        if action == "poe_on":
            return phys + ["set poe-status enable", "next", "end"], None
        if action == "poe_cycle":
            return phys + ["set poe-status disable", "next", "end"], phys + ["set poe-status enable", "next", "end"]
        raise ValueError(action)

    def backup_steps(self, name):
        return []

    def rollback_steps(self, name):
        return []

    def save_steps(self):
        return []          # FortiSwitchOS saves configuration changes immediately

    def upgrade_steps(self, stage, device, image, ctx):
        if stage in ("precheck", "postcheck"):
            return [{"key": "version", "cmd": "get system status"}], []
        if stage in ("transfer", "verify"):
            return [{"key": "version", "cmd": "get system status"}], []
        if stage == "activate":
            if not ctx.get("allow_reload"):
                raise ValueError("FortiSwitch installs and reboots in one step: allow the reload in the plan.")
            u = urlparse(image.transfer_url)
            if u.scheme != "tftp":
                raise ValueError("Standalone FortiSwitch upgrades are pulled over TFTP: use a tftp:// URL for this image.")
            return [], [{"cmd": f"execute restore image tftp {u.path.lstrip('/')} {u.hostname}", "fire_and_forget": True,
                         "answers": [[r"\(y/n\)", "y"]]}]
        raise ValueError(stage)

    def precheck(self, out, image):
        return None, False


def _caps(code):
    return " ".join({"B": "Bridge", "R": "Router", "W": "WLAN", "T": "Telephone", "S": "Station"}.get(c, "") for c in code).strip()


def _short(port):
    from apps.inventory.models import short_ifname
    return short_ifname(port)
