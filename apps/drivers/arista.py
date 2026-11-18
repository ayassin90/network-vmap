"""Arista EOS (7000 series, 720XP/750 campus) over SSH, parsed with ntc-templates plus a few regular expressions."""
import re

from apps.inventory.models import short_ifname

from .base import Driver, blocks, iface, norm_duplex, num, speed_to_mbps, to_int
from .cisco import CiscoIOS, clean_config, norm_mac, rate_to_bps, text_uptime


def ashort(name):
    """Arista abbreviates Ethernet as Et and Port-Channel as Po: normalise to the Eth1 / Po1 short names used everywhere else."""
    m = re.match(r"^(Et|Po|Ma)(\d.*)$", name or "")
    if m:
        name = {"Et": "Ethernet", "Po": "Port-Channel", "Ma": "Management"}[m.group(1)] + m.group(2)
    return short_ifname(name)


class AristaEOS(Driver):
    key = "arista_eos"
    vendor = "Arista"
    label = "Arista EOS"
    family = "arista_eos"
    os_type = "eos"
    netmiko_type = "arista_eos"
    ntc_platform = "arista_eos"
    status = "beta"
    models = "7010, 7020, 7050X/X3, 7060X, 7280R, 7300, 720XP, 722XP, 750 series"
    notes = ("Collection over SSH: version and serial, interfaces with errors and rates, switchport modes, LLDP, routes (all VRFs), VLANs, "
             "MAC/ARP, CPU/memory, power supplies, fans and temperature, configuration backup, security checks, port changes with a "
             "rollback point (`configure replace`). New driver: please report anything that looks wrong.")
    upgrade_notes = ("The .swi image is copied to flash:, MD5-verified, set with `boot system flash:<image>` and activated by a reload. "
                     "MLAG pairs: upgrade one peer at a time (max parallel = 1 per pair); Smart System Upgrade is not used.")
    features = {"ssh_collect": "full", "snmp": "full", "neighbors": "full", "vlans": "full", "routes": "full", "interfaces": "full",
                "config": "full", "security": "partial", "standards": "full", "psirt": "planned", "upgrade": "partial"}
    flash = "flash:"

    def collect_commands(self):
        return [{"key": "version", "cmd": "show version"}, {"key": "running", "cmd": "show running-config", "timeout": 180},
                {"key": "interfaces", "cmd": "show interfaces", "timeout": 180}, {"key": "status", "cmd": "show interfaces status"},
                {"key": "switchport", "cmd": "show interfaces switchport", "timeout": 120},
                {"key": "lldp", "cmd": "show lldp neighbors detail", "timeout": 120}, {"key": "route", "cmd": "show ip route vrf all", "timeout": 120},
                {"key": "vlan", "cmd": "show vlan"}, {"key": "cpu", "cmd": "show processes top once"},
                {"key": "power", "cmd": "show environment power"}, {"key": "cooling", "cmd": "show environment cooling"},
                {"key": "temp", "cmd": "show environment temperature"}] + self.mac_commands()

    def mac_commands(self):
        return [{"key": "mac", "cmd": "show mac address-table", "timeout": 120}, {"key": "arp", "cmd": "show ip arp vrf all", "timeout": 120}]

    def poll_commands(self):
        return [{"key": "interfaces", "cmd": "show interfaces", "timeout": 180}, {"key": "status", "cmd": "show interfaces status"}]

    def parse(self, o):
        p = self.ntc_platform
        data = {"facts": {}, "interfaces": [], "neighbors": [], "routes": [], "vlans": [], "extra": {}}
        v = (self.ntc(p, "show version", o.get("version", "")) or [{}])[0]
        if o.get("version"):
            data["facts"] = {"vendor": "Arista", "model": v.get("model", ""),
                             "serial": v.get("serial_number", ""), "os_type": "eos", "os_version": v.get("image", ""),
                             "uptime_seconds": text_uptime(v.get("uptime", ""))}
        if o.get("running"):
            data["config"] = clean_config(re.sub(r"^! (Command|device|boot system).*$\n?", "", o["running"], flags=re.M))
            m = re.search(r"^hostname (\S+)", data["config"], re.M)
            if m:
                data["facts"]["hostname"] = m.group(1)
        data["interfaces"] = self.parse_interfaces(o)
        for r in self.ntc(p, "show lldp neighbors detail", o.get("lldp", "")):
            data["neighbors"].append({"protocol": "lldp", "local_interface": short_ifname(r.get("local_interface", "")),
                                      "remote_name": r.get("neighbor_name", "") or r.get("chassis_id", ""),
                                      "remote_port": short_ifname(r.get("neighbor_interface", "")), "remote_ip": r.get("mgmt_address", ""),
                                      "remote_platform": (r.get("neighbor_description") or "")[:120],
                                      "remote_description": r.get("neighbor_description", ""), "capabilities": _caps(o.get("lldp", ""), r)})
        for r in self.ntc(p, "show ip route", o.get("route", "")):
            hops, ifs = r.get("next_hop") or [""], r.get("interface") or [""]
            for i, nh in enumerate(hops):
                proto = (r.get("protocol") or "").strip()
                data["routes"].append({"vrf": r.get("vrf") or "default", "protocol": proto, "prefix": f"{r['network']}/{r.get('prefix_length') or 32}",
                                       "distance": to_int(r.get("distance"), None), "metric": to_int(r.get("metric"), None),
                                       "next_hop": "" if nh == "connected" else nh, "interface": (ifs[i] if i < len(ifs) else "").split(",")[0].strip(),
                                       "age": ""})
        for r in self.ntc(p, "show vlan", o.get("vlan", "")):
            data["vlans"].append({"vid": to_int(r.get("vlan_id")), "name": r.get("vlan_name", ""), "status": r.get("status", ""),
                                  "ports": ", ".join(r.get("interfaces") or [])})
        data.update(self.parse_extras(o))
        h = {}
        m = re.search(r"%Cpu\(s\):\s*([\d.]+)\s*us,\s*([\d.]+)\s*sy", o.get("cpu", ""))
        if m:
            h["cpu"] = round(float(m.group(1)) + float(m.group(2)))
        if v.get("total_memory") and v.get("free_memory"):
            tot, free = to_int(v["total_memory"]), to_int(v["free_memory"])
            if tot:
                h["mem_pct"] = round(100 * (tot - free) / tot)
        psus = [{"name": f"PSU {m.group(1)}", "pid": m.group(2), "status": m.group(3).strip()}
                for m in re.finditer(r"^(\d+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+?)\s*$", o.get("power", ""), re.M)]
        fans = [{"name": f"Fan {m.group(1)}", "status": m.group(2)} for m in re.finditer(r"^(\d+/\d+)\s+(\S+)\s+\d+%", o.get("cooling", ""), re.M)]
        t = re.search(r"System temperature status is:\s*(\S+)", o.get("temp", ""))
        cur = re.findall(r"^\d+\s+.+?\s+([\d.]+)C\s", o.get("temp", ""), re.M)
        if psus:
            h["psus"] = psus
        if fans:
            h["fans"] = fans
        if t:
            h["temp_state"] = "GREEN" if t.group(1).lower() == "ok" else "RED"
        if cur:
            h["temp"] = round(max(float(c) for c in cur))
        if h:
            data["health"] = h
        return data

    def parse_interfaces(self, o):
        p = self.ntc_platform
        raw = o.get("interfaces", "")
        blk = blocks(raw, r"^(\S+) is ")
        st = {ashort(r.get("port", "")): r for r in self.ntc(p, "show interfaces status", o.get("status", ""))}
        sw = {}
        for name, b in blocks(o.get("switchport", ""), r"^Name:\s+(\S+)").items():
            sw[ashort(name)] = {"mode": (re.search(r"Operational Mode:\s*(.+)", b) or [None, ""])[1].strip(),
                                      "access": num(r"Access Mode VLAN:\s*(\d+)", b), "native": num(r"Trunking Native Mode VLAN:\s*(\d+)", b),
                                      "allowed": (re.search(r"Trunking VLANs Enabled:\s*(\S+)", b) or [None, ""])[1]}
        out = []
        for r in self.ntc(p, "show interfaces", raw):
            name = r.get("interface", "")
            sh = short_ifname(name)
            b, s, w = blk.get(name, ""), st.get(sh, {}), sw.get(sh)
            link, proto = (r.get("link_status") or "").lower(), (r.get("protocol_status") or "").lower()
            status = s.get("status") or ("connected" if proto.startswith("up") else "notconnect")
            status = {"errdisabled": "err-disabled"}.get(status, status)
            if "administratively" in link:
                status = "disabled"
            if re.match(r"(?i)^(vlan|loopback|management|vxlan)", name):
                mode = "virtual"
            elif w:
                mode = "trunk" if "trunk" in w["mode"] else "access"
            elif r.get("ip_address") or s.get("vlan_id") == "routed":
                mode = "routed"
            else:
                mode = "unknown"
            up = proto.startswith("up")
            dm = re.search(r"^\s+(\w+)-duplex,\s*([^,]+),", b, re.M)
            spd = dm.group(2).strip() if dm and up else ""
            out.append(iface(name, description=r.get("description", ""), admin_up="administratively" not in link, oper_up=up, status=status,
                             mode=mode, access_vlan=str(w["access"]) if w and mode == "access" else "",
                             native_vlan=str(w["native"]) if w and mode == "trunk" else "",
                             trunk_vlans=(w["allowed"] if w and mode == "trunk" else ""), speed=spd, duplex=norm_duplex(dm.group(1)) if dm and up else "",
                             speed_mbps=speed_to_mbps(spd) if spd else None, media=s.get("type", ""), mtu=to_int(r.get("mtu")) or None,
                             mac=r.get("mac_address", ""), ip=r.get("ip_address", ""),
                             in_errors=num(r"(\d+) input errors", b), out_errors=num(r"(\d+) output errors", b), crc=num(r"(\d+) CRC", b),
                             runts=num(r"(\d+) runts", b), giants=num(r"(\d+) giants", b), collisions=num(r"(\d+) collisions", b),
                             late_collisions=num(r"(\d+) late collision", b), in_discards=num(r"(\d+) input discards", b),
                             out_drops=num(r"(\d+) output discards", b),
                             in_rate_bps=rate_to_bps((re.search(r"input rate ([\d.]+ \w?bps)", b) or [None, "0"])[1]),
                             out_rate_bps=rate_to_bps((re.search(r"output rate ([\d.]+ \w?bps)", b) or [None, "0"])[1]),
                             last_flap=r.get("last_link_flapped", ""), resets=to_int(r.get("link_status_change"), None)))
        return out

    def parse_extras(self, o, data=None):
        p, out = self.ntc_platform, {}
        if "mac" in o:
            out["macs"] = [{"vlan": to_int(r.get("vlan_id"), None), "mac": norm_mac(r.get("mac_address")),
                            "interface": ashort((r.get("destination_port") or [""])[0]), "type": (r.get("type") or "").lower()}
                           for r in self.ntc(p, "show mac address-table", o.get("mac", "")) if r.get("mac_address")]
        if "arp" in o:
            out["arp"] = [{"ip": r.get("ip_address"), "mac": norm_mac(r.get("mac_address")), "interface": (r.get("interface") or "").split(",")[0]}
                          for r in self.ntc(p, "show ip arp", o.get("arp", "")) if norm_mac(r.get("mac_address"))]
        return out

    def parse_poll(self, outputs):
        return self.parse_interfaces(outputs)

    # ---- changes (IOS-like CLI)
    def port_commands(self, action, interface, value=""):
        if action == "poe_off":
            return [f"interface {interface}", "poe disabled"], None
        if action == "poe_on":
            return [f"interface {interface}", "no poe disabled"], None
        if action == "poe_cycle":
            return [f"interface {interface}", "poe disabled"], [f"interface {interface}", "no poe disabled"]
        return CiscoIOS.port_commands(self, action, interface, value)

    def backup_steps(self, name):
        return [{"label": f"save rollback point flash:{name}", "cmd": f"copy running-config flash:{name}", "timeout": 120, "fail_on": r"% ?Error"}]

    def rollback_steps(self, name):
        return [{"label": f"roll back to flash:{name}", "cmd": f"configure replace flash:{name}", "timeout": 300, "fail_on": r"% ?Error|failed"}]

    def save_steps(self):
        return [{"cmd": "write memory", "timeout": 120, "fail_on": r"% ?Error"}]

    def upgrade_steps(self, stage, device, image, ctx):
        dst = f"flash:{image.filename}"
        if stage == "precheck":
            return [{"key": "version", "cmd": "show version"}, {"key": "dir", "cmd": "dir flash:", "timeout": 60}], []
        if stage == "transfer":
            return [], [{"label": f"copy {image.transfer_url_masked} {dst}", "cmd": f"copy {image.transfer_url} {dst}", "timeout": 5400,
                         "fail_on": r"% ?Error|No such file|not enough space"}]
        if stage == "verify":
            return [{"key": "md5", "cmd": f"verify /md5 {dst}", "timeout": 900}], []
        if stage == "activate":
            steps = [{"cmd": f"boot system {dst}", "mode": "config", "fail_on": r"% ?(Invalid|Error)"}, {"cmd": "write memory", "timeout": 120}]
            if ctx.get("allow_reload"):
                steps.append({"cmd": "reload", "fire_and_forget": True, "answers": [[r"Save\?|modified", "yes"], [r"\[confirm\]|Proceed", ""]]})
            return [], steps
        if stage == "postcheck":
            return [{"key": "version", "cmd": "show version"}], []
        raise ValueError(stage)


def _caps(text, r):
    """Enabled capabilities for one neighbour from the raw LLDP text (the template does not capture them)."""
    name = r.get("neighbor_name", "")
    i = text.find(f'System Name: "{name}"')
    m = re.search(r"Enabled Capabilities:\s*(.+)", text[i:]) if i >= 0 else None
    return m.group(1).strip() if m else ""
