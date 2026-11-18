"""Driver contract. Each platform says which commands to run, how to read their output, which features it supports,
and how a software upgrade is done on it. Parsing turns vendor output into one normalised shape:

  {"facts": {hostname, vendor, model, serial, os_type, os_version, image, uptime_seconds, reload_reason, modules: [...]},
   "interfaces": [{name, description, admin_up, oper_up, status, mode, access_vlan, native_vlan, voice_vlan, trunk_vlans,
                   speed, duplex, speed_mbps, media, mtu, mac, ip, port_channel, in_errors, out_errors, crc, runts, giants,
                   frame, overrun, collisions, late_collisions, in_discards, out_drops, in_rate_bps, out_rate_bps,
                   last_input, last_flap}],
   "neighbors": [{protocol, local_interface, remote_name, remote_port, remote_ip, remote_platform, remote_description, capabilities}],
   "routes": [{vrf, protocol, prefix, distance, metric, next_hop, interface, age}],
   "vlans": [{vid, name, status, ports}],
   "config": "...", "extra": {...}}
"""
import re

# Feature catalogue shown on the Platform guide. Order matters (columns).
FEATURES = [
    ("ssh_collect", "SSH inventory", "Model, serial, software version, uptime and modules read over SSH."),
    ("snmp", "SNMP polling", "Interface throughput, errors and status polled over SNMP v2c / v3 every few minutes."),
    ("neighbors", "Neighbour discovery", "CDP and LLDP neighbours, used to draw the layer 2 topology and to crawl the network."),
    ("vlans", "VLANs & port modes", "VLAN list and whether each port is access, trunk or routed (drawn differently on the map)."),
    ("routes", "Routing table", "The IP routing table, used for the layer 3 topology and the routing view."),
    ("interfaces", "Interface health", "Errors, CRC, drops, half duplex, speed and duplex mismatches, err-disabled ports, utilisation."),
    ("config", "Config backup", "Running configuration saved on every collection, with change history and diffs."),
    ("security", "Security checks", "Built-in security and best-practice rules evaluated against the configuration."),
    ("standards", "Config standards", "Your own required / forbidden configuration lines checked on every collection."),
    ("psirt", "PSIRT matching", "Known vendor security advisories matched to the running software version."),
    ("upgrade", "Remote upgrade", "Image copy, verification, activation and post-checks run from VMap."),
]
LEVELS = {
    "full": ("Supported", "ok"),
    "partial": ("Partial", "warn"),
    "snmp": ("Via SNMP", "info"),
    "manual": ("Manual", "warn"),
    "planned": ("Planned", "muted"),
    "none": ("Not possible", "muted"),
}


class Driver:
    key = "generic"
    vendor = "Generic"
    label = "Generic SNMP device"
    family = "generic"           # rule family used by security checks
    os_type = ""                 # PSIRT os type (ios, iosxe, nxos …)
    netmiko_type = "generic"
    ntc_platform = ""
    status = "planned"           # supported | beta | snmp | planned
    models = ""
    notes = ""
    upgrade_notes = ""
    features = {}
    md5_verify = True
    flash = ""
    config_fail = r"^\s*% ?(Invalid|Incomplete|Ambiguous)"

    def mac_commands(self):
        return []

    def parse_extras(self, o, data=None):
        return {}

    def port_commands(self, action, interface, value=""):
        raise NotImplementedError("Port changes are not supported on this platform yet.")

    def changes_supported(self):
        return type(self).port_commands is not Driver.port_commands

    # ---- collection
    def collect_commands(self):
        return []

    def poll_commands(self):
        """Light SSH poll for throughput when no SNMP credential is set."""
        return []

    def parse(self, outputs):
        return {}

    def snmp_collect_spec(self):
        from .snmp import COLLECT_WALKS, SYSTEM
        return {"get": SYSTEM, "walk": COLLECT_WALKS}

    def snmp_poll_spec(self):
        from .snmp import POLL_WALKS
        return {"walk": POLL_WALKS}

    def parse_snmp(self, res):
        from .snmp import parse_collect
        return parse_collect(res)

    def parse_poll(self, outputs):
        return self.parse(outputs).get("interfaces", [])

    # ---- upgrades
    def upgrade_supported(self):
        return self.features.get("upgrade") in ("full", "partial")

    def upgrade_steps(self, stage, device, image, ctx):
        raise NotImplementedError

    # ---- helpers
    def feature_level(self, key):
        return self.features.get(key, "planned")

    @staticmethod
    def ntc(platform, command, text):
        if not text:
            return []
        from ntc_templates.parse import parse_output
        try:
            return parse_output(platform=platform, command=command, data=text)
        except Exception:  # noqa: BLE001 - an unknown format must not break the whole collection
            return []


def to_int(v, default=0):
    try:
        return int(str(v).replace(",", "").strip())
    except (TypeError, ValueError):
        return default


def speed_to_mbps(speed, bandwidth=""):
    """'1000Mb/s', 'a-1000', '10Gb/s', '100', 'auto' -> Mb/s or None."""
    s = (speed or "").lower().replace("a-", "").replace("auto-speed", "").strip()
    m = re.search(r"([\d.]+)\s*([mgk]?)", s)
    if m and m.group(1):
        n = float(m.group(1))
        unit = m.group(2)
        if "g" in s and unit != "m":
            n *= 1000
        elif unit == "k":
            n /= 1000
        if n >= 1:
            return int(n)
    b = re.search(r"(\d+)\s*kbit", (bandwidth or "").lower())
    if b:
        return max(1, int(b.group(1)) // 1000)
    return None


def norm_duplex(d):
    d = (d or "").lower()
    if "half" in d:
        return "half"
    if "full" in d:
        return "full"
    if "auto" in d:
        return "auto"
    return d.strip()


def iface(name, **kw):
    """A normalised interface row with every key present (see the module docstring)."""
    row = {"name": name, "description": "", "admin_up": True, "oper_up": False, "status": "notconnect", "mode": "unknown",
           "access_vlan": "", "native_vlan": "", "voice_vlan": "", "trunk_vlans": "", "speed": "", "duplex": "", "speed_mbps": None,
           "media": "", "mtu": None, "mac": "", "ip": "", "port_channel": "", "in_errors": 0, "out_errors": 0, "crc": 0, "runts": 0,
           "giants": 0, "frame": 0, "overrun": 0, "collisions": 0, "late_collisions": 0, "in_discards": 0, "out_drops": 0,
           "in_rate_bps": 0, "out_rate_bps": 0, "last_input": "", "last_flap": ""}
    row.update(kw)
    return row


def num(rx, text, default=0):
    m = re.search(rx, text or "")
    return to_int(next((g for g in m.groups() if g is not None), default)) if m else default


def vlan_list(text):
    """'10,20-22' -> '10,20,21,22' kept compact for storage; returns the input normalised (spaces removed)."""
    return ",".join(p for p in re.split(r"[,\s]+", (text or "").strip()) if p)


def blocks(text, start_rx):
    """Split text into {key: block} where each block starts with a line matching start_rx (group 1 is the key)."""
    out, key, buf = {}, None, []
    r = re.compile(start_rx)
    for line in (text or "").splitlines():
        m = r.match(line)
        if m:
            if key is not None:
                out[key] = "\n".join(buf)
            key, buf = m.group(1), [line]
        elif key is not None:
            buf.append(line)
    if key is not None:
        out[key] = "\n".join(buf)
    return out
