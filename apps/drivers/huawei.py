"""Huawei VRP (S-series campus switches, CloudEngine) over SSH, parsed with ntc-templates plus a few regular expressions."""
import re
from urllib.parse import urlparse

from apps.inventory.models import short_ifname

from .base import Driver, norm_duplex, to_int
from .cisco import norm_mac, rate_to_bps, text_uptime

EXPAND = (("XGE", "XGigabitEthernet"), ("40GE", "40GE"), ("100GE", "100GE"), ("25GE", "25GE"), ("GE", "GigabitEthernet"), ("Eth-Trunk", "Eth-Trunk"),
          ("MEth", "MEth"))


def expand(name):
    for s, full in EXPAND:
        if name.startswith(s) and not name.startswith(full) and name[len(s):len(s) + 1].isdigit():
            return full + name[len(s):]
    return name


def hshort(name):
    return short_ifname(expand(name or ""))


def _num(rx, text, nth=0):
    found = re.findall(rx, text or "")
    return to_int(found[nth]) if len(found) > nth else 0


class HuaweiVRP(Driver):
    key = "huawei_vrp"
    vendor = "Huawei"
    label = "Huawei VRP (S series / CloudEngine)"
    family = "huawei_vrp"
    os_type = "vrp"
    netmiko_type = "huawei"
    ntc_platform = "huawei_vrp"
    status = "beta"
    models = "S5700, S5720, S5730, S5735, S6720, S6730, S7700, S12700, CloudEngine S and CE series"
    notes = ("Collection over SSH: version, hardware (power supplies and fans), interfaces and errors, LLDP neighbours, VLANs and port modes, "
             "routes, MAC/ARP for the endpoint finder, CPU and memory, configuration backup and standards, port actions. VRP has no live "
             "configuration rollback from the CLI, so changes on Huawei are applied without an automatic rollback point. New driver: "
             "please report anything that looks wrong.")
    upgrade_notes = ("The .cc file is downloaded to flash: over TFTP or SFTP, its presence and size are checked, `startup system-software` "
                     "selects it for the next boot, and `reboot` activates it. iStack/CSS stacks reboot all members together: plan a window.")
    features = {"ssh_collect": "full", "snmp": "full", "neighbors": "full", "vlans": "full", "routes": "full", "interfaces": "full",
                "config": "full", "security": "partial", "standards": "full", "psirt": "planned", "upgrade": "partial"}
    config_fail = r"^\s*Error:"
    md5_verify = False
    flash = "flash:/"

    def collect_commands(self):
        return [{"key": "version", "cmd": "display version"}, {"key": "esn", "cmd": "display esn"}, {"key": "device", "cmd": "display device"},
                {"key": "running", "cmd": "display current-configuration", "timeout": 180},
                {"key": "interfaces", "cmd": "display interface", "timeout": 180}, {"key": "port_vlan", "cmd": "display port vlan"},
                {"key": "lldp", "cmd": "display lldp neighbor", "timeout": 120}, {"key": "vlan", "cmd": "display vlan"},
                {"key": "route", "cmd": "display ip routing-table", "timeout": 120},
                {"key": "cpu", "cmd": "display cpu-usage"}, {"key": "mem", "cmd": "display memory-usage"}] + self.mac_commands()

    def mac_commands(self):
        return [{"key": "mac", "cmd": "display mac-address", "timeout": 120}, {"key": "arp", "cmd": "display arp all", "timeout": 120}]

    def poll_commands(self):
        return [{"key": "interfaces", "cmd": "display interface", "timeout": 180}, {"key": "port_vlan", "cmd": "display port vlan"}]

    def parse(self, o):
        p = self.ntc_platform
        data = {"facts": {}, "interfaces": [], "neighbors": [], "routes": [], "vlans": [], "extra": {}}
        v = (self.ntc(p, "display version", o.get("version", "")) or [{}])[0]
        if v:
            prod = (v.get("product_version") or "").split()
            data["facts"] = {"vendor": "Huawei", "model": re.sub(r"\s+Routing Switch$", "", v.get("model", "")).strip(), "os_type": "vrp",
                             "os_version": prod[-1] if prod else v.get("vrp_version", ""), "uptime_seconds": text_uptime(v.get("uptime", ""))}
        m = re.search(r"ESN of (?:slot|device)[^:]*:\s*(\S+)", o.get("esn", ""))
        if m:
            data["facts"]["serial"] = m.group(1)
        rows = self.ntc(p, "display device", o.get("device", ""))
        if rows:
            data["facts"]["modules"] = [{"name": r.get("slot", ""), "descr": "", "pid": r.get("pid", ""), "serial": ""} for r in rows
                                        if not r.get("slot", "").startswith(("PWR", "FAN"))]
        if o.get("running"):
            data["config"] = o["running"].strip() + "\n"
            m = re.search(r"^sysname (\S+)", data["config"], re.M)
            if m:
                data["facts"]["hostname"] = m.group(1)
        data["interfaces"] = self.parse_interfaces(o)
        for r in self.ntc(p, "display lldp neighbor", o.get("lldp", "")):
            desc = r.get("neighbor_description") or ""
            desc = " ".join(desc) if isinstance(desc, list) else desc
            data["neighbors"].append({"protocol": "lldp", "local_interface": hshort(r.get("local_interface", "")),
                                      "remote_name": r.get("neighbor_name", "") or r.get("chassis_id", ""),
                                      "remote_port": short_ifname(r.get("neighbor_port_id") or r.get("neighbor_interface", "")),
                                      "remote_ip": r.get("mgmt_address", ""), "remote_platform": desc[:120], "remote_description": desc,
                                      "capabilities": r.get("capabilities", "")})
        for line in o.get("route", "").splitlines():
            m = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+\S*\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s*$", line)
            if m:
                proto = {"Direct": "C", "Static": "S", "OSPF": "O", "BGP": "B", "ISIS": "i", "RIP": "R"}.get(m.group(2), m.group(2))
                if m.group(2) == "Direct" and m.group(1).endswith("/32"):
                    proto = "L"
                data["routes"].append({"vrf": "default", "protocol": proto, "prefix": m.group(1), "distance": int(m.group(3)),
                                       "metric": int(m.group(4)), "next_hop": "" if proto in ("C", "L") else m.group(5),
                                       "interface": m.group(6), "age": ""})
        for r in self.ntc(p, "display vlan", o.get("vlan", "")):
            data["vlans"].append({"vid": to_int(r.get("vlan_id")), "name": r.get("vlan_description", ""), "status": r.get("vlan_status", ""),
                                  "ports": ", ".join(r.get("interface") or [])})
        data.update(self.parse_extras(o))
        h = {}
        m = re.search(r"CPU Usage\s*:\s*(\d+)%", o.get("cpu", ""))
        if m:
            h["cpu"] = int(m.group(1))
        m = re.search(r"Memory Using Percentage Is:\s*(\d+)%", o.get("mem", ""))
        if m:
            h["mem_pct"] = int(m.group(1))
        fans, psus = [], []
        for r in rows:
            slot = r.get("slot", "")
            status = "Not Present" if r.get("online_status", "").lower() == "absent" else ("OK" if r.get("alarm_status", "").lower() == "normal" else r.get("alarm_status", ""))
            if slot.startswith("FAN"):
                fans.append({"name": slot, "status": status})
            elif slot.startswith("PWR"):
                psus.append({"name": slot, "pid": r.get("pid", ""), "status": status})
        if fans:
            h["fans"] = fans
        if psus:
            h["psus"] = psus
        if h:
            data["health"] = h
        return data

    def parse_interfaces(self, o):
        p = self.ntc_platform
        raw = o.get("interfaces", "")
        blocks, name, buf = {}, None, []
        for line in raw.splitlines():
            m = re.match(r"^(\S+) current state :", line)
            if m:
                if name:
                    blocks[name] = "\n".join(buf)
                name, buf = m.group(1), [line]
            elif name:
                buf.append(line)
        if name:
            blocks[name] = "\n".join(buf)
        pv = {hshort(r.get("interface", "")): r for r in self.ntc(p, "display port vlan", o.get("port_vlan", ""))}
        members = {}
        for r in self.ntc(p, "display interface", raw):
            for m in r.get("aggregated_interfaces") or []:
                members[hshort(m)] = r.get("interface", "")
        out = []
        for r in self.ntc(p, "display interface", raw):
            name = r.get("interface", "")
            sh = hshort(name)
            blk = blocks.get(name, "")
            link = (r.get("link_status") or "").upper()
            up = link == "UP"
            admin = "ADMINISTRATIVELY" not in link
            v = pv.get(sh, {})
            lt = (v.get("link_type") or "").lower()
            if name.lower().startswith(("vlanif", "loopback", "meth", "null", "nve")):
                mode = "virtual"
            elif r.get("port_type", "").lower().startswith("route") or r.get("ip_address"):
                mode = "routed"
            elif lt in ("trunk", "hybrid"):
                mode = "trunk"
            elif lt == "access":
                mode = "access"
            else:
                mode = "unknown"
            spd = to_int(r.get("speed"), None)
            out.append({
                "name": name, "description": r.get("interface_description", ""), "admin_up": admin, "oper_up": up,
                "status": "connected" if up else ("disabled" if not admin else "notconnect"), "mode": mode,
                "access_vlan": v.get("vlan_id", "") if mode == "access" else "", "native_vlan": v.get("vlan_id", "") if mode == "trunk" else "",
                "voice_vlan": "", "trunk_vlans": ",".join(" ".join(v.get("trunk_vlan_list") or []).split()) if mode == "trunk" else "",
                "speed": f"{spd}Mb/s" if up and spd else "", "duplex": norm_duplex(r.get("duplex")) if up else "", "speed_mbps": spd if up else None,
                "media": r.get("port_mode", ""), "mtu": to_int(r.get("mtu")) or None, "mac": r.get("mac_address", ""), "ip": r.get("ip_address", ""),
                "port_channel": hshort(members.get(name, "")) if members.get(name) else "",
                "in_errors": _num(r"Total Error:\s*(\d+)", blk, 0), "out_errors": _num(r"Total Error:\s*(\d+)", blk, 1),
                "crc": _num(r"CRC:\s*(\d+)", blk), "runts": _num(r"Runts:\s*(\d+)", blk), "giants": _num(r"Giants:\s*(\d+)", blk),
                "frame": 0, "overrun": 0, "collisions": _num(r"\bCollisions:\s*(\d+)", blk), "late_collisions": _num(r"Late Collisions:\s*(\d+)", blk),
                "in_discards": _num(r"Discard:\s*(\d+)", blk, 0), "out_drops": _num(r"Discard:\s*(\d+)", blk, 1),
                "in_rate_bps": rate_to_bps((re.search(r"input rate (\d+ bits/sec)", blk) or [None, "0"])[1]),
                "out_rate_bps": rate_to_bps((re.search(r"output rate (\d+ bits/sec)", blk) or [None, "0"])[1]),
                "last_input": "", "last_flap": (re.search(r"Last physical down time\s*:\s*(.+)", blk) or [None, ""])[1].strip(),
            })
        return out

    def parse_extras(self, o, data=None):
        p, out = self.ntc_platform, {}
        if "mac" in o:
            out["macs"] = [{"vlan": to_int(r.get("vlan_id"), None), "mac": norm_mac(r.get("destination_address")),
                            "interface": hshort(r.get("destination_port", "")), "type": r.get("type", "")}
                           for r in self.ntc(p, "display mac-address", o.get("mac", "")) if r.get("destination_address")]
        if "arp" in o:
            out["arp"] = [{"ip": r.get("ip_address"), "mac": norm_mac(r.get("mac_address")), "interface": r.get("interface", "")}
                          for r in self.ntc(p, "display arp all", o.get("arp", "")) if norm_mac(r.get("mac_address"))]
        return out

    def parse_poll(self, outputs):
        return self.parse_interfaces(outputs)

    # ---- changes
    def port_commands(self, action, interface, value=""):
        head = [f"interface {interface}"]
        if action == "shutdown":
            return head + ["shutdown"], None
        if action == "no_shutdown":
            return head + ["undo shutdown"], None
        if action == "bounce":
            return head + ["shutdown"], head + ["undo shutdown"]
        if action == "access_vlan":
            return head + ["port link-type access", f"port default vlan {int(value)}"], None
        if action == "description":
            return head + [f"description {value}" if value else "undo description"], None
        if action == "poe_off":
            return head + ["undo poe enable"], None
        if action == "poe_on":
            return head + ["poe enable"], None
        if action == "poe_cycle":
            return head + ["undo poe enable"], head + ["poe enable"]
        raise ValueError(action)

    def backup_steps(self, name):
        return []

    def rollback_steps(self, name):
        return []

    def save_steps(self):
        return [{"cmd": "save", "answers": [[r"\[Y/N\]", "y"]], "timeout": 120, "fail_on": r"Error:"}]

    def upgrade_steps(self, stage, device, image, ctx):
        dst = f"flash:/{image.filename}"
        if stage == "precheck":
            return [{"key": "version", "cmd": "display version"}, {"key": "dir", "cmd": "dir flash:", "timeout": 60}], []
        if stage == "transfer":
            u = urlparse(image.transfer_url)
            path = u.path.lstrip("/")
            if u.scheme == "tftp":
                cmd = f"tftp {u.hostname} get {path} {dst}"
            elif u.scheme in ("sftp", "scp"):
                cmd = (f"sftp client-transfile get host-ip {u.hostname} username {u.username or 'vmap'} password {u.password or ''} "
                       f"sourcefile {path} destination {dst}")
            else:
                raise ValueError("Huawei VRP downloads images over TFTP or SFTP: use a tftp:// or sftp:// URL for this image.")
            return [], [{"label": f"download {image.transfer_url_masked} to {dst}", "cmd": cmd, "timeout": 5400,
                         "answers": [[r"(?i)overwrite.*\[Y/N\]|continue.*\[Y/N\]", "y"]], "fail_on": r"(?i)Error:|failed|timed out"}]
        if stage == "verify":
            return [{"key": "file", "cmd": f"dir {dst}", "timeout": 60}], []
        if stage == "activate":
            steps = [{"cmd": f"startup system-software {dst}", "timeout": 600, "answers": [[r"\[Y/N\]", "y"]], "fail_on": r"Error:"}] + self.save_steps()
            if ctx.get("allow_reload"):
                steps.append({"cmd": "reboot", "fire_and_forget": True, "answers": [[r"(?i)save.*\[Y/N\]", "n"], [r"Continue\s*\?\s*\[Y/N\]", "y"]]})
            return [], steps
        if stage == "postcheck":
            return [{"key": "version", "cmd": "display version"}], []
        raise ValueError(stage)

    def precheck(self, out, image):
        m = re.search(r"\(([\d,]+) KB free\)", out.get("dir", ""))
        free = int(m.group(1).replace(",", "")) * 1024 if m else None
        return free, image.filename in out.get("dir", "")

    def verify_ok(self, out, image):
        m = re.search(rf"\s([\d,]+)\s+\w{{3}}\s+\d+\s+\d{{4}}\s+[\d:]+\s+{re.escape(image.filename)}", out.get("file", ""))
        if not m:
            return False, f"{image.filename} is not on flash after the download"
        size = int(m.group(1).replace(",", ""))
        if image.size_bytes and size != image.size_bytes:
            return False, f"size on flash is {size:,} bytes, expected {image.size_bytes:,}"
        return True, f"{image.filename} is on flash ({size:,} bytes)"
