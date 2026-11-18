"""Cisco IOS, IOS-XE (Catalyst) and NX-OS (Nexus) drivers. Output is parsed with ntc-templates (TextFSM) plus a few
regular expressions for counters the templates do not expose (collisions, late collisions, output drops)."""
import re

from apps.inventory.models import short_ifname

from .base import Driver, norm_duplex, speed_to_mbps, to_int

CONFIG_NOISE = re.compile(r"^(Building configuration|Current configuration|! Last configuration change|! NVRAM config last|"
                          r"ntp clock-period|! No configuration change since).*$\n?", re.M)


def clean_config(text):
    return CONFIG_NOISE.sub("", text or "").strip() + "\n"


def uptime_seconds(row):
    total = 0
    for k, mult in (("uptime_years", 31536000), ("uptime_weeks", 604800), ("uptime_days", 86400),
                    ("uptime_hours", 3600), ("uptime_minutes", 60)):
        total += to_int(row.get(k)) * mult
    if not total and row.get("uptime"):
        return text_uptime(row["uptime"])
    return total or None


def text_uptime(s):
    total = 0
    for n, unit in re.findall(r"(\d+)\s*(year|week|day|hour|minute|second)", s or ""):
        total += int(n) * {"year": 31536000, "week": 604800, "day": 86400, "hour": 3600, "minute": 60, "second": 1}[unit]
    return total or None


def rate_to_bps(s):
    """'1234 bits/sec', '4.52 Kbps', '1.2 Mbps' -> int bps."""
    m = re.search(r"([\d.]+)\s*([kmg]?)(bps|bits)", (s or "").lower())
    if not m:
        return to_int(s)
    return int(float(m.group(1)) * {"": 1, "k": 1e3, "m": 1e6, "g": 1e9}[m.group(2)])


def split_blocks(text):
    """Split `show interfaces` into {interface name: block text}."""
    blocks, name, buf = {}, None, []
    for line in (text or "").splitlines():
        m = re.match(r"^(\S+) is (up|down|administratively down|deleted)", line)
        if m:
            if name:
                blocks[name] = "\n".join(buf)
            name, buf = m.group(1), [line]
        elif name:
            buf.append(line)
    if name:
        blocks[name] = "\n".join(buf)
    return blocks


def norm_mac(m):
    h = re.sub(r"[^0-9a-fA-F]", "", m or "").lower()
    return h if len(h) == 12 else ""


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_transceivers(text):
    """`show interfaces transceiver` (no TextFSM template): values may be followed by ++ + - -- threshold markers."""
    out = []
    for line in (text or "").splitlines():
        tok = line.split()
        if len(tok) < 6 or not re.match(r"^(Te|Gi|Twe|Fo|Hu|Fi|Tw|Eth)\S*\d$", tok[0]):
            continue
        vals, flags = [], []
        for t in tok[1:]:
            if t in ("++", "+", "-", "--"):
                if flags:
                    flags[-1] = t
                continue
            try:
                vals.append(float(t))
                flags.append("")
            except ValueError:
                vals.append(None)
                flags.append("")
        if len(vals) < 5:
            continue
        names = ["temp", "volt", "bias", "tx", "rx"]
        row = {"interface": short_ifname(tok[0])}
        row.update(dict(zip(names, vals[:5])))
        row["flags"] = {n: f for n, f in zip(names, flags[:5]) if f}
        out.append(row)
    return out


def parse_health(cpu, mem, env):
    h = {}
    m = re.search(r"five minutes:\s*(\d+)%", cpu or "")
    if m:
        h["cpu"] = int(m.group(1))
    m = re.search(r"Total:\s*(\d+)\s+Used:\s*(\d+)", mem or "")
    if m and int(m.group(1)):
        h["mem_pct"] = round(100 * int(m.group(2)) / int(m.group(1)))
    fans, psus = [], []
    for line in (env or "").splitlines():
        m = re.match(r"^\s*(FAN\s*\S*(?:\s\d+)?)\s+is\s+(.+?)\s*$", line, re.I)
        if m:
            fans.append({"name": m.group(1).strip(), "status": m.group(2).strip()})
            continue
        m = re.match(r"^\s*(\d+[A-Z])\s+(\S+)\s+\S+\s+(OK|Good|No Input Power|Bad|Faulty|Failed|Not Present|Disabled)\b", line, re.I)
        if m:
            psus.append({"name": m.group(1), "pid": m.group(2), "status": m.group(3)})
            continue
        m = re.match(r"^\s*(\d+[A-Z])\s+Not Present", line, re.I)
        if m:
            psus.append({"name": m.group(1), "pid": "", "status": "Not Present"})
    m = re.search(r"Temperature Value:\s*(\d+)", env or "", re.I)
    if m:
        h["temp"] = int(m.group(1))
    m = re.search(r"Temperature State:\s*(\w+)", env or "", re.I)
    if m:
        h["temp_state"] = m.group(1).upper()
    if fans:
        h["fans"] = fans
    if psus:
        h["psus"] = psus
    return h


def parse_stp(ports, roots, detail):
    by = {}
    for r in roots:
        v = to_int(re.sub(r"\D", "", r.get("vlan_id", "")), None)
        if v is None:
            continue
        by[v] = {"vlan": v, "root_prio": to_int(r.get("priority"), None), "root_mac": norm_mac(r.get("root_id")),
                 "root_cost": to_int(r.get("root_cost"), 0), "root_port": short_ifname(r.get("root_port", "")), "ports": []}
    cur = None
    for line in (detail or "").splitlines():
        m = re.search(r"VLAN0*(\d+) is executing", line)
        if m:
            cur = by.setdefault(int(m.group(1)), {"vlan": int(m.group(1)), "ports": []})
            continue
        if cur is None:
            continue
        m = re.search(r"Bridge Identifier has priority (\d+), sysid (\d+), address (\S+)", line)
        if m:
            cur["bridge_prio"] = int(m.group(1)) + int(m.group(2))
            cur["bridge_mac"] = norm_mac(m.group(3))
        m = re.search(r"Number of topology changes (\d+) last change occurred (\S+) ago", line)
        if m:
            cur["tc_count"], cur["tc_ago"] = int(m.group(1)), m.group(2)
        m = re.search(r"^\s+from (\S+)", line)
        if m:
            cur["tc_from"] = short_ifname(m.group(1))
    for r in ports:
        v = to_int(r.get("vlan_id"), None)
        if v is None:
            continue
        by.setdefault(v, {"vlan": v, "ports": []})["ports"].append({"interface": short_ifname(r.get("interface", "")), "role": r.get("role", ""),
                                                                     "state": r.get("status", ""), "cost": to_int(r.get("cost"), None)})
    for s in by.values():
        s["is_root"] = bool(s.get("bridge_mac") and s.get("bridge_mac") == s.get("root_mac")) or (not s.get("root_port") and s.get("root_cost") == 0)
    return list(by.values())


def _num(rx, text):
    m = re.search(rx, text or "", re.I)
    return to_int(m.group(1)) if m else 0


class CiscoIOS(Driver):
    key = "cisco_ios"
    vendor = "Cisco"
    label = "Cisco IOS (Catalyst classic)"
    family = "cisco_ios"
    os_type = "ios"
    netmiko_type = "cisco_ios"
    ntc_platform = "cisco_ios"
    status = "supported"
    models = "Catalyst 2960 / 2960-X / 2960-XR, 3560, 3750, 4500 (IOS), IE switches, ISR G2 routers"
    notes = "Fully supported over SSH, with SNMP for throughput. Needs privilege 15 (or an enable secret) to read the configuration."
    upgrade_notes = ("Bundle mode: the image is copied to flash (HTTP, HTTPS, SCP, FTP or TFTP), its MD5 is verified, the boot "
                     "variable is set, the configuration is saved and, if you allow it, the switch is reloaded. Stacks of "
                     "2960-X/3750 need the `archive download-sw` method instead, so treat stacked units as manual for now.")
    features = {"ssh_collect": "full", "snmp": "full", "neighbors": "full", "vlans": "full", "routes": "full",
                "interfaces": "full", "config": "full", "security": "full", "standards": "full", "psirt": "full", "upgrade": "partial"}
    flash = "flash:"

    def collect_commands(self):
        return [
            {"key": "version", "cmd": "show version"},
            {"key": "inventory", "cmd": "show inventory"},
            {"key": "running", "cmd": "show running-config", "timeout": 180},
            {"key": "interfaces", "cmd": "show interfaces", "timeout": 180},
            {"key": "status", "cmd": "show interfaces status"},
            {"key": "switchport", "cmd": "show interfaces switchport", "timeout": 120},
            {"key": "cdp", "cmd": "show cdp neighbors detail"},
            {"key": "lldp", "cmd": "show lldp neighbors detail"},
            {"key": "route", "cmd": "show ip route", "timeout": 180},
            {"key": "vlan", "cmd": "show vlan brief"},
            {"key": "etherchannel", "cmd": "show etherchannel summary"},
            {"key": "ospf", "cmd": "show ip ospf neighbor"},
        ] + self.extra_commands()

    def extra_commands(self):
        return [
            {"key": "mac", "cmd": "show mac address-table", "timeout": 120},
            {"key": "arp", "cmd": "show ip arp", "timeout": 120},
            {"key": "stp", "cmd": "show spanning-tree", "timeout": 120},
            {"key": "stp_root", "cmd": "show spanning-tree root"},
            {"key": "stp_detail", "cmd": "show spanning-tree detail | include executing|Bridge Identifier|topology changes|from"},
            {"key": "transceiver", "cmd": "show interfaces transceiver"},
            {"key": "power", "cmd": "show power inline"},
        ] + self.health_commands()

    def health_commands(self):
        return [{"key": "cpu", "cmd": "show processes cpu | include CPU utilization"},
                {"key": "mem", "cmd": "show processes memory | include Processor Pool"},
                {"key": "env", "cmd": "show environment all"}]

    def mac_commands(self):
        return [{"key": "mac", "cmd": "show mac address-table", "timeout": 120}, {"key": "arp", "cmd": "show ip arp", "timeout": 120}]

    def poll_commands(self):
        return [{"key": "interfaces", "cmd": "show interfaces", "timeout": 180}, {"key": "status", "cmd": "show interfaces status"}]

    # ------------------------------------------------------------ parsing
    def parse(self, o):
        p = self.ntc_platform
        data = {"facts": {}, "interfaces": [], "neighbors": [], "routes": [], "vlans": [], "extra": {}}
        ver_text = o.get("version", "")
        ver = (self.ntc(p, "show version", ver_text) or [{}])[0]
        if ver_text:
            is_xe = bool(re.search(r"IOS[ -]XE|Cisco IOS XE", ver_text))
            hw = ver.get("hardware") or []
            sn = ver.get("serial") or []
            data["facts"] = {
                "hostname": ver.get("hostname", ""),
                "vendor": "Cisco",
                "model": hw[0] if hw else "",
                "serial": sn[0] if sn else "",
                "os_type": "iosxe" if is_xe else "ios",
                "os_version": ver.get("version", ""),
                "image": ver.get("running_image", "") or ver.get("software_image", ""),
                "uptime_seconds": uptime_seconds(ver),
                "reload_reason": ver.get("reload_reason", ""),
                "stack_members": len(hw) if len(hw) > 1 else 1,
                "install_mode": "install" if re.search(r"\bINSTALL\b", ver_text) else "bundle",
            }
        mods = self.ntc(p, "show inventory", o.get("inventory", ""))
        if mods:
            data["facts"]["modules"] = [{"name": m.get("name", ""), "descr": m.get("descr", ""), "pid": m.get("pid", ""),
                                         "serial": m.get("sn", "")} for m in mods]
            if not data["facts"].get("serial") and mods[0].get("sn"):
                data["facts"]["serial"] = mods[0]["sn"]
            if not data["facts"].get("model") and mods[0].get("pid"):
                data["facts"]["model"] = mods[0]["pid"]
        if o.get("running"):
            data["config"] = clean_config(o["running"])
            m = re.search(r"^hostname (\S+)", data["config"], re.M)
            if m:
                data["facts"]["hostname"] = m.group(1)
        data["interfaces"] = self.parse_interfaces(o)
        data["neighbors"] = self.parse_neighbors(o)
        data["routes"] = self.parse_routes(o.get("route", ""))
        for v in self.ntc(p, "show vlan", o.get("vlan", "")):
            data["vlans"].append({"vid": to_int(v.get("vlan_id")), "name": v.get("vlan_name") or v.get("name", ""),
                                  "status": v.get("status", ""), "ports": ", ".join(v.get("interfaces") or [])})
        data.update(self.parse_extras(o, data))
        data["extra"]["ospf"] = [{"neighbor_id": r.get("neighbor_id"), "state": r.get("state"), "address": r.get("ip_address"),
                                  "interface": r.get("interface")} for r in self.ntc(p, "show ip ospf neighbor", o.get("ospf", ""))]
        return data

    def parse_interfaces(self, o):
        p = self.ntc_platform
        raw = o.get("interfaces", "")
        blocks = split_blocks(raw)
        rows = self.ntc(p, "show interfaces", raw)
        status = {short_ifname(r.get("port", "")): r for r in self.ntc(p, "show interfaces status", o.get("status", ""))}
        swp = {short_ifname(r.get("interface", "")): r for r in self.ntc(p, "show interfaces switchport", o.get("switchport", ""))}
        members = {}
        for r in self.ntc(p, "show etherchannel summary", o.get("etherchannel", "")):
            for mem in r.get("member_interface") or []:
                members[short_ifname(mem)] = short_ifname(r.get("bundle_name", ""))
        out = []
        for r in rows:
            name = r.get("interface", "")
            sh = short_ifname(name)
            blk = blocks.get(name, "")
            st = status.get(sh, {})
            sw = swp.get(sh, {})
            link, proto = (r.get("link_status") or "").lower(), (r.get("protocol_status") or "").lower()
            stat = st.get("status", "")
            if not stat:
                stat = "disabled" if "administratively" in link else ("err-disabled" if "err-disabled" in proto else
                                                                      ("connected" if proto.startswith("up") else "notconnect"))
            duplex = norm_duplex(st.get("duplex") or r.get("duplex"))
            speed = st.get("speed") or r.get("speed", "")
            mode = "unknown"
            opmode = (sw.get("mode") or "").lower()
            if sw:
                if (sw.get("switchport") or "").lower().startswith("disabled"):
                    mode = "routed"
                elif "trunk" in opmode or (opmode == "down" and "trunk" in (sw.get("admin_mode") or "").lower()):
                    mode = "trunk"
                else:
                    mode = "access"
            elif st.get("vlan_id") == "trunk":
                mode = "trunk"
            elif st.get("vlan_id") == "routed" or (r.get("ip_address") and not re.match(r"(?i)vlan|loopback|tunnel", name)):
                mode = "routed"
            elif st.get("vlan_id", "").isdigit():
                mode = "access"
            if re.match(r"(?i)^(vlan|loopback|tunnel|null|bdi|nve)", name):
                mode = "virtual"
            ip = f"{r['ip_address']}/{r.get('prefix_length') or 32}" if r.get("ip_address") else ""
            out.append({
                "name": name, "description": r.get("description", "") or st.get("name", ""),
                "admin_up": "administratively" not in link and stat != "disabled",
                "oper_up": proto.startswith("up"), "status": stat, "mode": mode,
                "access_vlan": (sw.get("access_vlan") or (st.get("vlan_id") if mode == "access" else "") or "") if mode == "access" else "",
                "native_vlan": sw.get("native_vlan", "") if mode == "trunk" else "",
                "voice_vlan": "" if (sw.get("voice_vlan") or "none").lower() == "none" else sw.get("voice_vlan", ""),
                "trunk_vlans": ",".join(sw.get("trunking_vlans") or []) if mode == "trunk" else "",
                "speed": speed, "duplex": duplex, "speed_mbps": speed_to_mbps(speed, r.get("bandwidth")) if r.get("speed") or st else None,
                "media": r.get("media_type") or st.get("type", ""), "mtu": to_int(r.get("mtu")) or None,
                "mac": r.get("mac_address", ""), "ip": ip, "port_channel": members.get(sh, ""),
                "in_errors": to_int(r.get("input_errors")), "out_errors": to_int(r.get("output_errors")),
                "crc": to_int(r.get("crc")), "runts": to_int(r.get("runts")), "giants": to_int(r.get("giants")),
                "frame": to_int(r.get("frame")), "overrun": to_int(r.get("overrun")),
                "collisions": _num(r"(\d+) collisions", blk), "late_collisions": _num(r"(\d+) late collision", blk),
                "in_discards": _num(r"(\d+) input discards|(\d+) ignored", blk),
                "out_drops": _num(r"Total output drops: (\d+)", blk) or to_int(r.get("queue_output_drops")),
                "in_rate_bps": to_int(r.get("input_rate")), "out_rate_bps": to_int(r.get("output_rate")),
                "last_input": r.get("last_input", ""), "last_flap": "",
                "resets": _num(r"(\d+) interface resets", blk) if blk else None,
            })
        return out

    def parse_neighbors(self, o):
        p = self.ntc_platform
        out = []
        for r in self.ntc(p, "show cdp neighbors detail", o.get("cdp", "")):
            out.append({"protocol": "cdp", "local_interface": short_ifname(r.get("local_interface", "")),
                        "remote_name": r.get("neighbor_name", ""), "remote_port": short_ifname(r.get("neighbor_interface", "")),
                        "remote_ip": r.get("mgmt_address", ""), "remote_platform": r.get("platform", ""),
                        "remote_description": r.get("neighbor_description", ""), "capabilities": r.get("capabilities", "")})
        seen = {(n["local_interface"], n["remote_name"].split(".")[0].lower()) for n in out}
        for r in self.ntc(p, "show lldp neighbors detail", o.get("lldp", "")):
            name = r.get("neighbor_name", "") or r.get("chassis_id", "")
            local = short_ifname(r.get("local_interface", ""))
            if (local, name.split(".")[0].lower()) in seen:
                continue
            out.append({"protocol": "lldp", "local_interface": local, "remote_name": name,
                        "remote_port": short_ifname(r.get("neighbor_port_id") or r.get("neighbor_interface", "")),
                        "remote_ip": r.get("mgmt_address", ""), "remote_platform": r.get("platform", "") or (r.get("neighbor_description", "")[:120]),
                        "remote_description": r.get("neighbor_description", ""), "capabilities": r.get("capabilities", "")})
        return out

    def parse_routes(self, text):
        out = []
        for r in self.ntc(self.ntc_platform, "show ip route", text):
            if not r.get("network"):
                continue
            out.append({"vrf": r.get("vrf") or "default", "protocol": (r.get("protocol", "") + " " + r.get("type", "")).strip(),
                        "prefix": f"{r['network']}/{r.get('prefix_length') or 32}",
                        "distance": to_int(r.get("distance"), None), "metric": to_int(r.get("metric"), None),
                        "next_hop": r.get("nexthop_ip", ""), "interface": r.get("nexthop_if", ""), "age": r.get("uptime", "")})
        return out

    # ------------------------------------------------------------ MAC / ARP / STP / optics / PoE
    def parse_extras(self, o, data=None):
        p = self.ntc_platform
        out = {}
        if "mac" in o:
            out["macs"] = [{"vlan": to_int(r.get("vlan_id"), None), "mac": norm_mac(r.get("destination_address")),
                            "interface": short_ifname((r.get("destination_port") or [""])[0]), "type": (r.get("type") or "").lower()}
                           for r in self.ntc(p, "show mac address-table", o.get("mac", "")) if r.get("destination_address")]
        if "arp" in o:
            out["arp"] = [{"ip": r.get("ip_address"), "mac": norm_mac(r.get("mac_address")), "interface": r.get("interface", "")}
                          for r in self.ntc(p, "show ip arp", o.get("arp", "")) if norm_mac(r.get("mac_address"))]
        if o.get("stp") or o.get("stp_root"):
            out["stp"] = parse_stp(self.ntc(p, "show spanning-tree", o.get("stp", "")), self.ntc(p, "show spanning-tree root", o.get("stp_root", "")),
                                   o.get("stp_detail", ""))
        if "transceiver" in o:
            out["optics"] = parse_transceivers(o.get("transceiver", ""))
            mods = (data or {}).get("facts", {}).get("modules", [])
            for m in mods:
                for opt in out["optics"]:
                    if short_ifname(m["name"]) == opt["interface"]:
                        opt.update(pid=m["pid"], serial=m["serial"], description=m["descr"])
            have = {x["interface"] for x in out["optics"]}
            for m in mods:
                sh = short_ifname(m["name"])
                if re.match(r"^(Te|Gi|Twe|Fo|Hu|Fi|Tw)\d", sh) and sh not in have:
                    out["optics"].append({"interface": sh, "pid": m["pid"], "serial": m["serial"], "description": m["descr"]})
        if any(k in o for k in ("cpu", "mem", "env")):
            out["health"] = parse_health(o.get("cpu", ""), o.get("mem", ""), o.get("env", ""))
        if o.get("power") and "Invalid" not in o.get("power", ""):
            rows = self.ntc(p, "show power inline", o["power"])
            m = re.search(r"^\s*\d+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", o["power"], re.M)
            out["poe"] = {"available": float(m.group(1)) if m else None, "used": float(m.group(2)) if m else None,
                          "ports": [{"interface": short_ifname(r.get("interface", "")), "admin": r.get("admin_status", ""),
                                     "oper": r.get("operational_status", ""), "watts": _f(r.get("power")), "device": r.get("device", ""),
                                     "cls": r.get("class", "")} for r in rows]}
        return out

    # ------------------------------------------------------------ changes
    def port_commands(self, action, interface, value=""):
        """Configuration lines for a one-port change. bounce/poe_cycle are two-phase: (lines, lines_after)."""
        head = [f"interface {interface}"]
        if action == "shutdown":
            return head + ["shutdown"], None
        if action == "no_shutdown":
            return head + ["no shutdown"], None
        if action == "bounce":
            return head + ["shutdown"], head + ["no shutdown"]
        if action == "access_vlan":
            return head + ["switchport mode access", f"switchport access vlan {int(value)}"], None
        if action == "description":
            return head + [f"description {value}" if value else "no description"], None
        if action == "poe_off":
            return head + ["power inline never"], None
        if action == "poe_on":
            return head + ["power inline auto"], None
        if action == "poe_cycle":
            return head + ["power inline never"], head + ["power inline auto"]
        raise ValueError(action)

    def backup_steps(self, name):
        return [{"label": f"save rollback point flash:{name}", "cmd": f"copy running-config flash:{name}",
                 "answers": [[r"Destination filename", ""], [r"over\s?write|\[confirm\]", "y"]], "timeout": 120, "fail_on": r"%Error"}]

    def rollback_steps(self, name):
        return [{"label": f"roll back to flash:{name}", "cmd": f"configure replace flash:{name} force", "timeout": 300,
                 "answers": [[r"\[no\]|\(y/n\)|proceed", "y"]], "fail_on": r"%Error|Rollback aborted"}]

    def save_steps(self):
        return [{"cmd": "write memory", "answers": [[r"\[confirm\]", ""]], "timeout": 120, "fail_on": r"%Error"}]

    config_fail = r"^\s*% ?(Invalid|Incomplete|Ambiguous)"

    # ------------------------------------------------------------ upgrades
    def upgrade_steps(self, stage, device, image, ctx):
        """Return (commands, steps) for one stage. ctx carries what earlier stages learned (flash name, mode, …)."""
        fs = ctx.get("filesystem") or self.flash
        dst = f"{fs}{image.filename}"
        if stage == "precheck":
            return [{"key": "version", "cmd": "show version"}, {"key": "dir", "cmd": f"dir {fs}", "timeout": 60}], []
        if stage == "transfer":
            return [], [{"label": f"copy {image.transfer_url_masked} {dst}", "cmd": f"copy {image.transfer_url} {dst}",
                         "answers": [[r"Destination filename", ""], [r"over\s?write|\[confirm\]", "y"]],
                         "timeout": 5400, "fail_on": r"%Error|Error opening|No such file|Not enough space|timed out|Invalid"}]
        if stage == "verify":
            return [{"key": "md5", "cmd": f"verify /md5 {dst}", "timeout": 900}], []
        if stage == "activate":
            steps = [{"cmd": f"no boot system\nboot system {dst}", "mode": "config", "fail_on": r"% ?Invalid"},
                     {"cmd": "write memory", "answers": [[r"\[confirm\]", ""]], "timeout": 120}]
            if ctx.get("allow_reload"):
                steps.append({"cmd": "reload", "fire_and_forget": True,
                              "answers": [[r"Save\?|modified", "no"], [r"\[confirm\]|proceed", ""]]})
            return [], steps
        if stage == "postcheck":
            return [{"key": "version", "cmd": "show version"}], []
        raise ValueError(stage)


class CiscoIOSXE(CiscoIOS):
    key = "cisco_iosxe"
    label = "Cisco IOS-XE (Catalyst 9000 / 3650 / 3850)"
    os_type = "iosxe"
    family = "cisco_ios"
    models = "Catalyst 9200, 9300, 9400, 9500, 9600, 3650, 3850, IE3x00, ISR 1000/4000, ASR 1000, C8000"
    notes = "Fully supported over SSH, with SNMP for throughput. Install mode and bundle mode are both detected."
    upgrade_notes = ("Install mode (the default on Catalyst 9000): the image is copied, MD5-verified and activated with "
                     "`install add file … activate commit`, which reloads the switch (all stack members together). Bundle mode "
                     "uses the boot variable instead. Allow the reload in the plan, or activation stops before it.")
    features = dict(CiscoIOS.features, upgrade="full")

    def upgrade_steps(self, stage, device, image, ctx):
        if stage == "activate" and ctx.get("install_mode") == "install":
            dst = f"{ctx.get('filesystem') or self.flash}{image.filename}"
            if not ctx.get("allow_reload"):
                return [], [{"cmd": f"install add file {dst}", "timeout": 3600,
                             "answers": [[r"\[y/n\]|proceed\?", "y"]], "fail_on": r"FAILED|%Error|Invalid"}]
            return [], [{"cmd": "write memory", "answers": [[r"\[confirm\]", ""]], "timeout": 120},
                        {"cmd": f"install add file {dst} activate commit prompt-level none", "timeout": 3600, "drop_ok": True,
                         "answers": [[r"\[y/n\]|proceed\?", "y"]], "expect": r"(?i)reload|SUCCESS", "fail_on": r"FAILED|%Error|Invalid"}]
        return super().upgrade_steps(stage, device, image, ctx)


class CiscoNXOS(CiscoIOS):
    key = "cisco_nxos"
    label = "Cisco NX-OS (Nexus)"
    family = "cisco_nxos"
    os_type = "nxos"
    netmiko_type = "cisco_nxos"
    ntc_platform = "cisco_nxos"
    status = "beta"
    models = "Nexus 3000, 5000, 7000, 9000 (NX-OS mode)"
    notes = "Collection, topology and checks work; parsing is newer than IOS, so please report anything that looks wrong."
    upgrade_notes = ("The image is copied to bootflash, verified, then `install all nxos bootflash:<image>` runs, which reloads "
                     "the switch. On vPC pairs, upgrade one peer at a time (max parallel = 1 per pair).")
    features = dict(CiscoIOS.features, upgrade="partial")
    flash = "bootflash:"

    def collect_commands(self):
        return [
            {"key": "version", "cmd": "show version"},
            {"key": "inventory", "cmd": "show inventory"},
            {"key": "running", "cmd": "show running-config", "timeout": 180},
            {"key": "interfaces", "cmd": "show interface", "timeout": 180},
            {"key": "status", "cmd": "show interface status"},
            {"key": "switchport", "cmd": "show interface switchport", "timeout": 120},
            {"key": "cdp", "cmd": "show cdp neighbors detail"},
            {"key": "lldp", "cmd": "show lldp neighbors detail"},
            {"key": "route", "cmd": "show ip route vrf all", "timeout": 180},
            {"key": "vlan", "cmd": "show vlan brief"},
            {"key": "etherchannel", "cmd": "show port-channel summary"},
            {"key": "ospf", "cmd": "show ip ospf neighbors vrf all"},
            {"key": "cpu", "cmd": "show system resources"},
            {"key": "env", "cmd": "show environment"},
        ] + self.mac_commands()

    def poll_commands(self):
        return [{"key": "interfaces", "cmd": "show interface", "timeout": 180}, {"key": "status", "cmd": "show interface status"},
                {"key": "switchport", "cmd": "show interface switchport", "timeout": 120}]

    def parse_poll(self, outputs):
        return self.parse(outputs)["interfaces"]

    def parse_extras(self, o, data=None):
        p, out = self.ntc_platform, {}
        if "mac" in o:
            out["macs"] = [{"vlan": to_int(r.get("vlan_id"), None), "mac": norm_mac(r.get("mac_address")),
                            "interface": short_ifname(r.get("ports", "")), "type": (r.get("type") or "").lower()}
                           for r in self.ntc(p, "show mac address-table", o.get("mac", "")) if norm_mac(r.get("mac_address"))]
        if "arp" in o:
            out["arp"] = [{"ip": r.get("ip_address"), "mac": norm_mac(r.get("mac_address")), "interface": r.get("interface", "")}
                          for r in self.ntc(p, "show ip arp", o.get("arp", "")) if norm_mac(r.get("mac_address"))]
        return out

    @staticmethod
    def parse_health_nx(cpu, env):
        h = {}
        m = re.search(r"CPU states\s*:\s*([\d.]+)% user,\s*([\d.]+)% kernel", cpu or "")
        if m:
            h["cpu"] = round(float(m.group(1)) + float(m.group(2)))
        m = re.search(r"Memory usage:\s*(\d+)K total,\s*(\d+)K used", cpu or "")
        if m and int(m.group(1)):
            h["mem_pct"] = round(100 * int(m.group(2)) / int(m.group(1)))
        psus = [{"name": f"PSU {m.group(1)}", "pid": m.group(2), "status": m.group(3)}
                for m in re.finditer(r"^(\d+)\s+(\S+)\s+\d+ W\s+\d+ W\s+\d+ W\s+(\S+)", env or "", re.M)]
        fans = [{"name": m.group(1), "status": m.group(2)} for m in re.finditer(r"^(Fan\d+)\(\S+\)\s+\S+\s+\S+\s+\S+\s+(\S+)", env or "", re.M)]
        temps = [(int(m.group(1)), m.group(2)) for m in re.finditer(r"^\d+\s+\S+\s+\d+\s+\d+\s+(\d+)\s+(\S+)", env or "", re.M)]
        if psus:
            h["psus"] = psus
        if fans:
            h["fans"] = fans
        if temps:
            h["temp"] = max(t for t, _ in temps)
            h["temp_state"] = "GREEN" if all(st.lower() == "normal" for _, st in temps) else ("RED" if any(st.lower() == "major" for _, st in temps) else "YELLOW")
        return h

    def backup_steps(self, name):
        cp = name.replace(".cfg", "")
        return [{"label": f"save checkpoint {cp}", "cmd": f"checkpoint {cp}", "timeout": 120, "fail_on": r"% ?(Invalid|Error)|failed"}]

    def rollback_steps(self, name):
        cp = name.replace(".cfg", "")
        return [{"label": f"roll back to checkpoint {cp}", "cmd": f"rollback running-config checkpoint {cp}", "timeout": 300,
                 "fail_on": r"Rollback failed|% ?(Invalid|Error)"}]

    def save_steps(self):
        return [{"cmd": "copy running-config startup-config", "timeout": 120, "fail_on": r"% ?Error|failed"}]

    def parse(self, o):
        p = self.ntc_platform
        data = {"facts": {}, "interfaces": [], "neighbors": [], "routes": [], "vlans": [], "extra": {}}
        ver = (self.ntc(p, "show version", o.get("version", "")) or [{}])[0]
        if o.get("version"):
            model = ""
            m = re.search(r"cisco (Nexus\s?\S+.*?) [Cc]hassis", o["version"])
            if m:
                model = m.group(1).strip()
            data["facts"] = {"hostname": ver.get("hostname", ""), "vendor": "Cisco", "model": model or ver.get("platform", ""),
                             "serial": ver.get("serial", ""), "os_type": "nxos", "os_version": ver.get("os", ""),
                             "image": ver.get("boot_image", ""), "uptime_seconds": text_uptime(ver.get("uptime", "")),
                             "reload_reason": ver.get("last_reboot_reason", "")}
        mods = self.ntc(p, "show inventory", o.get("inventory", ""))
        if mods:
            data["facts"]["modules"] = [{"name": m.get("name", ""), "descr": m.get("descr", ""), "pid": m.get("pid", ""),
                                         "serial": m.get("sn", "")} for m in mods]
        if o.get("running"):
            data["config"] = clean_config(re.sub(r"^!(Command|Running configuration|Time):.*$\n?", "", o["running"], flags=re.M))
        swp = {short_ifname(r.get("interface", "")): r for r in self.ntc(p, "show interface switchport", o.get("switchport", ""))}
        stat = {short_ifname(r.get("port", "")): r for r in self.ntc(p, "show interface status", o.get("status", ""))}
        members = {}
        for r in self.ntc(p, "show port-channel summary", o.get("etherchannel", "")):
            bundle = short_ifname(r.get("bundle_name") or r.get("bundle_iface") or "")
            for mem in r.get("phys_iface") or r.get("member_interface") or []:
                members[short_ifname(re.sub(r"\(.*\)", "", mem))] = bundle
        for r in self.ntc(p, "show interface", o.get("interfaces", "")):
            name = r.get("interface", "")
            sh = short_ifname(name)
            sw, st = swp.get(sh, {}), stat.get(sh, {})
            link = (r.get("link_status") or "").lower()
            mode = (r.get("mode") or sw.get("mode") or "").lower()
            mode = "trunk" if "trunk" in mode else "access" if "access" in mode else "routed" if "routed" in mode or r.get("ip_address") else "unknown"
            if re.match(r"(?i)^(vlan|loopback|tunnel|nve|mgmt)", name):
                mode = "virtual"
            speed = r.get("speed", "") or st.get("speed", "")
            out_row = {
                "name": name, "description": r.get("description", ""), "admin_up": (r.get("admin_state") or "up").lower() != "down",
                "oper_up": link.startswith("up"),
                "status": "err-disabled" if "err-disabled" in link else ("disabled" if "administratively" in link else
                          {"notconnec": "notconnect", "sfpAbsent": "notconnect", "xcvrAbsen": "notconnect", "down": "notconnect"}.get(
                              st.get("status", ""), st.get("status", "")) or ("connected" if link.startswith("up") else "notconnect")),
                "mode": mode, "access_vlan": sw.get("access_vlan", "") if mode == "access" else "",
                "native_vlan": sw.get("native_vlan", "") if mode == "trunk" else "",
                "voice_vlan": "", "trunk_vlans": ((sw.get("trunking_vlans", "") if isinstance(sw.get("trunking_vlans"), str) else ",".join(sw.get("trunking_vlans") or []))
                                                  if mode == "trunk" else ""),
                "speed": speed, "duplex": norm_duplex(r.get("duplex") or st.get("duplex")),
                "speed_mbps": speed_to_mbps(speed, r.get("bandwidth")), "media": r.get("media_type", ""), "mtu": to_int(r.get("mtu")) or None,
                "mac": r.get("mac_address", ""), "ip": f"{r['ip_address']}/{r.get('prefix_length') or 32}" if r.get("ip_address") else "",
                "port_channel": members.get(sh, ""),
                "in_errors": to_int(r.get("input_errors")), "out_errors": to_int(r.get("output_errors")), "crc": to_int(r.get("crc")),
                "runts": to_int(r.get("runts")), "giants": to_int(r.get("giants")), "frame": 0, "overrun": to_int(r.get("overrun")),
                "collisions": to_int(r.get("collisions")), "late_collisions": to_int(r.get("late_collisions")),
                "in_discards": to_int(r.get("input_discards")), "out_drops": to_int(r.get("output_discards")),
                "in_rate_bps": rate_to_bps(r.get("bandwidth_input_rate", "")), "out_rate_bps": rate_to_bps(r.get("bandwidth_output_rate", "")),
                "last_input": "", "last_flap": r.get("last_link_flapped", ""),
            }
            data["interfaces"].append(out_row)
        data["neighbors"] = self.parse_neighbors(o)
        for r in self.ntc(p, "show ip route", o.get("route", "")):
            if r.get("network"):
                proto = r.get("protocol", "")
                proto = {"direct": "C", "local": "L", "static": "S", "hsrp": "C", "bgp": "B", "eigrp": "D", "rip": "R"}.get(
                    proto.split("-")[0].lower(), "O" if proto.lower().startswith("ospf") else proto)
                data["routes"].append({"vrf": r.get("vrf") or "default", "protocol": proto,
                                       "prefix": f"{r['network']}/{r.get('prefix_length') or 32}", "distance": to_int(r.get("distance"), None),
                                       "metric": to_int(r.get("metric"), None), "next_hop": "" if proto in ("C", "L") else r.get("nexthop_ip", ""),
                                       "interface": r.get("nexthop_if", ""), "age": r.get("uptime", "")})
        for v in self.ntc(p, "show vlan brief", o.get("vlan", "")) or self.ntc(p, "show vlan", o.get("vlan", "")):
            data["vlans"].append({"vid": to_int(v.get("vlan_id")), "name": v.get("vlan_name") or v.get("name", ""),
                                  "status": v.get("status", ""), "ports": ", ".join(v.get("interfaces") or [])})
        data.update(self.parse_extras(o, data))
        h = self.parse_health_nx(o.get("cpu"), o.get("env"))
        if h:
            data["health"] = h
        return data

    def upgrade_steps(self, stage, device, image, ctx):
        fs = self.flash
        if stage == "activate":
            if not ctx.get("allow_reload"):
                return [], [{"cmd": f"show install all impact nxos {fs}{image.filename}", "timeout": 1800}]
            return [], [{"cmd": "copy running-config startup-config", "timeout": 120},
                        {"cmd": f"install all nxos {fs}{image.filename}", "timeout": 3600, "drop_ok": True,
                         "expect": r"(?i)switch will reboot|reloading|Install has been successful",
                         "answers": [[r"Do you want to continue|\(y/n\)", "y"]], "fail_on": r"Install has failed|Pre-upgrade check failed"}]
        return super().upgrade_steps(stage, device, image, dict(ctx, filesystem=fs))
