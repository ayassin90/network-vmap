"""Aruba AOS-CX (CX 4100i/6000/6100/6200/6300/6400/8xxx/9300/10000) over SSH, parsed with ntc-templates."""
import re

from apps.inventory.models import short_ifname

from .base import Driver, norm_duplex, speed_to_mbps, to_int
from .cisco import norm_mac


class ArubaCX(Driver):
    key = "aruba_aoscx"
    vendor = "HPE Aruba"
    label = "Aruba AOS-CX"
    family = "aruba_aoscx"
    os_type = "aoscx"
    netmiko_type = "aruba_aoscx"
    ntc_platform = "aruba_aoscx"
    status = "beta"
    models = "CX 4100i, 6000, 6100, 6200, 6300, 6400, 8100, 8320, 8325, 8360, 9300, 10000"
    notes = ("Collection over SSH: inventory, interfaces and errors, LLDP neighbours, VLANs, routes, MAC and ARP tables, configuration. "
             "Spanning-tree and optics views are not read yet. New driver: please report anything that looks wrong.")
    upgrade_notes = ("The image is copied to the secondary partition (`copy <url> secondary`), then `boot system secondary` reloads the switch. "
                     "AOS-CX checks the image signature itself, so no MD5 step. VSF stacks reboot all members together.")
    features = {"ssh_collect": "full", "snmp": "full", "neighbors": "full", "vlans": "full", "routes": "full", "interfaces": "full",
                "config": "full", "security": "partial", "standards": "full", "psirt": "planned", "upgrade": "partial"}
    md5_verify = False
    config_fail = r"^\s*(Invalid input|% ?Invalid|Incomplete command)"
    flash = "secondary"

    def collect_commands(self):
        return [{"key": "system", "cmd": "show system"}, {"key": "module", "cmd": "show module"},
                {"key": "running", "cmd": "show running-config", "timeout": 180}, {"key": "interfaces", "cmd": "show interface", "timeout": 180},
                {"key": "lldp", "cmd": "show lldp neighbor-info detail"}, {"key": "route", "cmd": "show ip route all-vrfs", "timeout": 120},
                {"key": "vlan", "cmd": "show vlan"}] + self.mac_commands()

    def mac_commands(self):
        return [{"key": "mac", "cmd": "show mac-address-table", "timeout": 120}, {"key": "arp", "cmd": "show arp all-vrfs", "timeout": 120}]

    def poll_commands(self):
        return [{"key": "interfaces", "cmd": "show interface", "timeout": 180}]

    def parse(self, o):
        p = self.ntc_platform
        data = {"facts": {}, "interfaces": [], "neighbors": [], "routes": [], "vlans": [], "extra": {}}
        sysi = (self.ntc(p, "show system", o.get("system", "")) or [{}])[0]
        if sysi:
            prod = sysi.get("product", "")
            up = (to_int(sysi.get("uptime_weeks")) * 604800 + to_int(sysi.get("uptime_days")) * 86400 +
                  to_int(sysi.get("uptime_hours")) * 3600 + to_int(sysi.get("uptime_minutes")) * 60)
            data["facts"] = {"hostname": sysi.get("hostname", ""), "vendor": "Aruba", "model": prod, "serial": sysi.get("serial", ""),
                             "os_type": "aoscx", "os_version": sysi.get("version", ""), "uptime_seconds": up or None}
        mods = self.ntc(p, "show module", o.get("module", ""))
        if mods:
            data["facts"]["modules"] = [{"name": m.get("module", ""), "descr": m.get("cardtype", ""), "pid": m.get("model", ""),
                                         "serial": m.get("serial", "")} for m in mods]
        if o.get("running"):
            data["config"] = re.sub(r"^Current configuration:\s*\n", "", o["running"]).strip() + "\n"
        data["interfaces"] = self.parse_interfaces(o)
        for r in self.ntc(p, "show lldp neighbor-info detail", o.get("lldp", "")):
            data["neighbors"].append({"protocol": "lldp", "local_interface": short_ifname(r.get("local_interface", "")),
                                      "remote_name": r.get("neighbor_name", "") or r.get("chassis_id", ""),
                                      "remote_port": short_ifname(r.get("neighbor_port_id") or r.get("neighbor_interface", "")),
                                      "remote_ip": r.get("mgmt_address", ""), "remote_platform": (r.get("neighbor_description") or "")[:120],
                                      "remote_description": r.get("neighbor_description", ""),
                                      "capabilities": r.get("capabilities", "")})
        for r in self.ntc(p, "show ip route all-vrfs", o.get("route", "")):
            vias, metrics, protos = r.get("interface") or [""], r.get("metric") or [""], r.get("status") or [""]
            for i, via in enumerate(vias):
                proto = protos[i] if i < len(protos) else ""
                m = re.match(r"\[(\d+)/(\d+)\]", metrics[i] if i < len(metrics) else "")
                is_ip = bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", via))
                data["routes"].append({"vrf": r.get("vrf") or "default", "protocol": {"connected": "C", "local": "L", "static": "S", "ospf": "O",
                                                                                       "bgp": "B"}.get(proto, proto),
                                       "prefix": f"{r['ip_address']}/{r.get('prefix_length') or 32}", "next_hop": via if is_ip else "",
                                       "interface": "" if is_ip else via, "distance": int(m.group(1)) if m else None,
                                       "metric": int(m.group(2)) if m else None, "age": ""})
        for v in self.ntc(p, "show vlan", o.get("vlan", "")):
            data["vlans"].append({"vid": to_int(v.get("vlan_id")), "name": v.get("vlan_name", ""), "status": v.get("status", ""),
                                  "ports": ", ".join(v.get("interfaces") or [])})
        data.update(self.parse_extras(o))
        hc = {}
        m = re.search(r"CPU Util \(%\)\s*:\s*(\d+)", o.get("system", ""))
        if m:
            hc["cpu"] = int(m.group(1))
        m = re.search(r"Memory Usage \(%\)\s*:\s*(\d+)", o.get("system", ""))
        if m:
            hc["mem_pct"] = int(m.group(1))
        if hc:
            data["health"] = hc
        return data

    def parse_interfaces(self, o):
        out, members = [], {}
        rows = self.ntc(self.ntc_platform, "show interface", o.get("interfaces", ""))
        for r in rows:
            for m in r.get("aggregated_interfaces") or []:
                members[m] = r.get("interface", "")
        for r in rows:
            name = r.get("interface", "")
            mode_raw = (r.get("vlan_mode") or "").lower()
            if name.lower().startswith(("vlan", "loopback")):
                mode = "virtual"
            elif r.get("ip_address"):
                mode = "routed"
            elif "native" in mode_raw or "trunk" in mode_raw:
                mode = "trunk"
            elif mode_raw == "access":
                mode = "access"
            else:
                mode = "unknown"
            up = (r.get("link_status") or "").lower() == "up"
            admin = (r.get("link_admin") or "up").lower() != "down"
            spd = r.get("speed", "")
            out.append({
                "name": name, "description": r.get("interface_desc", ""), "admin_up": admin, "oper_up": up,
                "status": "connected" if up else ("disabled" if not admin else "notconnect"), "mode": mode,
                "access_vlan": r.get("vlan_access", "") if mode == "access" else "", "native_vlan": r.get("vlan_native", "") if mode == "trunk" else "",
                "voice_vlan": "", "trunk_vlans": ",".join(r.get("vlan_trunk") or []) if mode == "trunk" else "",
                "speed": spd if up else "", "duplex": norm_duplex(r.get("duplex")) if up else "", "speed_mbps": speed_to_mbps(spd) if up else None,
                "media": r.get("if_type", ""), "mtu": to_int(r.get("mtu")) or None, "mac": r.get("mac_address", ""),
                "ip": r.get("ip_address", ""), "port_channel": members.get(name, ""),
                "in_errors": to_int(r.get("rx_errors")), "out_errors": to_int(r.get("tx_errors")), "crc": to_int(r.get("rx_crc_fcs")),
                "runts": 0, "giants": 0, "frame": 0, "overrun": 0, "collisions": to_int(r.get("tx_collision")), "late_collisions": 0,
                "in_discards": to_int(r.get("rx_dropped")), "out_drops": to_int(r.get("tx_dropped")), "in_rate_bps": 0, "out_rate_bps": 0,
                "last_input": "", "last_flap": "", "link_transitions": to_int(r.get("link_transitions"), None),
            })
        return out

    def parse_extras(self, o, data=None):
        p, out = self.ntc_platform, {}
        if "mac" in o:
            out["macs"] = [{"vlan": to_int(r.get("vlan_id"), None), "mac": norm_mac(r.get("mac_address")), "interface": r.get("port", ""),
                            "type": r.get("type", "")} for r in self.ntc(p, "show mac-address-table", o.get("mac", "")) if r.get("mac_address")]
        if "arp" in o:
            out["arp"] = [{"ip": r.get("ip_address"), "mac": norm_mac(r.get("mac_address")), "interface": r.get("port_id", "")}
                          for r in self.ntc(p, "show arp all-vrfs", o.get("arp", "")) if norm_mac(r.get("mac_address"))]
        return out

    def parse_poll(self, outputs):
        return self.parse_interfaces(outputs)

    # ---- changes
    def port_commands(self, action, interface, value=""):
        head = [f"interface {interface}"]
        if action == "shutdown":
            return head + ["shutdown"], None
        if action == "no_shutdown":
            return head + ["no shutdown"], None
        if action == "bounce":
            return head + ["shutdown"], head + ["no shutdown"]
        if action == "access_vlan":
            return head + [f"vlan access {int(value)}"], None
        if action == "description":
            return head + [f"description {value}" if value else "no description"], None
        if action == "poe_off":
            return head + ["no power-over-ethernet"], None
        if action == "poe_on":
            return head + ["power-over-ethernet"], None
        if action == "poe_cycle":
            return head + ["no power-over-ethernet"], head + ["power-over-ethernet"]
        raise ValueError(action)

    def backup_steps(self, name):
        return [{"label": f"save checkpoint {name}", "cmd": f"copy running-config checkpoint {name}", "timeout": 120, "fail_on": r"error|failed"}]

    def rollback_steps(self, name):
        return [{"label": f"restore checkpoint {name}", "cmd": f"copy checkpoint {name} running-config", "timeout": 300,
                 "answers": [[r"\(y/n\)", "y"]], "fail_on": r"error|failed"}]

    def save_steps(self):
        return [{"cmd": "write memory", "timeout": 120}]

    def upgrade_steps(self, stage, device, image, ctx):
        if stage in ("precheck", "postcheck"):
            return [{"key": "version", "cmd": "show system"}], []
        if stage == "transfer":
            return [], [{"label": f"copy {image.transfer_url_masked} secondary", "cmd": f"copy {image.transfer_url} secondary",
                         "answers": [[r"\(y/n\)", "y"]], "timeout": 3600, "fail_on": r"(?i)error|failed|not found"}]
        if stage == "verify":
            return [{"key": "images", "cmd": "show images"}], []
        if stage == "activate":
            if not ctx.get("allow_reload"):
                return [], [{"cmd": "boot set-default secondary", "timeout": 60}]
            return [], [{"cmd": "write memory", "timeout": 120},
                        {"cmd": "boot system secondary", "fire_and_forget": True, "answers": [[r"\(y/n\)", "y"]]}]
        raise ValueError(stage)
