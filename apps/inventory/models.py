"""What we know about the network: sites, credentials, devices and everything collected from them."""
import ipaddress
import re

from django.db import models
from django.utils import timezone

from apps.core.crypto import decrypt, encrypt


class Site(models.Model):
    name = models.CharField(max_length=100, unique=True)
    location = models.CharField(max_length=200, blank=True)
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class Credential(models.Model):
    KINDS = [("ssh", "SSH (username / password)"), ("snmp2", "SNMP v2c"), ("snmp3", "SNMP v3")]
    AUTH = [("", "None"), ("sha", "SHA"), ("sha256", "SHA-256"), ("md5", "MD5")]
    PRIV = [("", "None"), ("aes", "AES-128"), ("aes256", "AES-256"), ("des", "DES")]
    name = models.CharField(max_length=100, unique=True)
    kind = models.CharField(max_length=6, choices=KINDS, default="ssh")
    username = models.CharField(max_length=100, blank=True)
    _password = models.TextField(blank=True, db_column="password")
    _enable = models.TextField(blank=True, db_column="enable")
    _community = models.TextField(blank=True, db_column="community")
    auth_proto = models.CharField(max_length=8, choices=AUTH, blank=True)
    _auth_key = models.TextField(blank=True, db_column="auth_key")
    priv_proto = models.CharField(max_length=8, choices=PRIV, blank=True)
    _priv_key = models.TextField(blank=True, db_column="priv_key")
    port = models.PositiveIntegerField(default=0, help_text="0 = default (22 for SSH, 161 for SNMP)")

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.get_kind_display()})"

    def _p(name):  # noqa: N805 - small property factory
        return property(lambda self: decrypt(getattr(self, name)), lambda self, v: setattr(self, name, encrypt(v)))
    password = _p("_password")
    enable = _p("_enable")
    community = _p("_community")
    auth_key = _p("_auth_key")
    priv_key = _p("_priv_key")
    del _p

    def snmp_spec(self):
        if self.kind == "snmp2":
            return {"version": "2c", "community": self.community, "port": self.port or 161}
        if self.kind == "snmp3":
            return {"version": "3", "username": self.username, "auth_proto": self.auth_proto, "auth_key": self.auth_key,
                    "priv_proto": self.priv_proto, "priv_key": self.priv_key, "port": self.port or 161}
        return None


class Device(models.Model):
    ROLES = [("core", "Core"), ("distribution", "Distribution"), ("access", "Access"), ("datacenter", "Data centre"),
             ("router", "Router / WAN"), ("unknown", "Not set")]
    STATUS = [("unknown", "Unknown"), ("up", "Up"), ("down", "Unreachable"), ("auth_failed", "Login failed"), ("error", "Error")]

    hostname = models.CharField(max_length=120)
    mgmt_ip = models.CharField("Management IP / host", max_length=255)
    site = models.ForeignKey(Site, null=True, blank=True, on_delete=models.SET_NULL, related_name="devices")
    platform = models.CharField(max_length=40, default="cisco_iosxe")
    role = models.CharField(max_length=14, choices=ROLES, default="unknown")
    ssh_credential = models.ForeignKey(Credential, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    snmp_credential = models.ForeignKey(Credential, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    collector = models.ForeignKey("jobs.Collector", null=True, blank=True, on_delete=models.SET_NULL, related_name="devices",
                                  help_text="Leave empty to reach the device from this server directly.")
    tags = models.CharField(max_length=300, blank=True)
    enabled = models.BooleanField(default=True)
    demo = models.BooleanField(default=False)
    notes = models.TextField(blank=True)
    discovery = models.ForeignKey("inventory.DiscoveryRun", null=True, blank=True, on_delete=models.SET_NULL, related_name="devices")
    discovery_depth = models.PositiveSmallIntegerField(default=0)

    vendor = models.CharField(max_length=40, blank=True)
    model = models.CharField(max_length=80, blank=True)
    serial = models.CharField(max_length=80, blank=True)
    os_type = models.CharField(max_length=20, blank=True)
    os_version = models.CharField(max_length=60, blank=True)
    image = models.CharField(max_length=200, blank=True)
    uptime_seconds = models.BigIntegerField(null=True, blank=True)
    reload_reason = models.CharField(max_length=200, blank=True)
    facts = models.JSONField(default=dict, blank=True)

    status = models.CharField(max_length=12, choices=STATUS, default="unknown")
    last_collected = models.DateTimeField(null=True, blank=True)
    last_polled = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    cpu = models.PositiveSmallIntegerField(null=True, blank=True, help_text="CPU % (5 minute average)")
    mem_pct = models.PositiveSmallIntegerField(null=True, blank=True)
    temp_c = models.SmallIntegerField(null=True, blank=True)
    env = models.JSONField(default=dict, blank=True, help_text="fans, power supplies, temperature state")
    health_at = models.DateTimeField(null=True, blank=True)
    security_score = models.PositiveSmallIntegerField(null=True, blank=True)
    compliance_score = models.PositiveSmallIntegerField(null=True, blank=True)
    health_score = models.PositiveSmallIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["hostname"]
        constraints = [models.UniqueConstraint(fields=["mgmt_ip"], name="uniq_device_mgmt_ip")]

    def __str__(self):
        return self.hostname

    @property
    def driver(self):
        from apps.drivers.registry import get_driver
        return get_driver(self.platform)

    @property
    def tag_list(self):
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    @property
    def latest_config(self):
        return self.configs.order_by("-collected_at").first()

    def is_l3(self):
        return self.routes.exclude(protocol="L").exists() or self.interfaces.filter(mode="routed").exists() \
            or self.interfaces.filter(name__istartswith="vlan", ip__gt="").count() > 1


def short_ifname(name):
    """GigabitEthernet1/0/1 -> Gi1/0/1, the form CDP and the topology use."""
    if not name:
        return ""
    m = re.match(r"^([A-Za-z\-]+)\s*([\d/.:]+.*)$", name.strip())
    if not m:
        return name
    head, tail = m.groups()
    table = {"gigabitethernet": "Gi", "tengigabitethernet": "Te", "fastethernet": "Fa", "twentyfivegige": "Twe",
             "twentyfivegigabitethernet": "Twe", "fortygigabitethernet": "Fo", "hundredgige": "Hu", "hundredgigabitethernet": "Hu",
             "ethernet": "Eth", "port-channel": "Po", "portchannel": "Po", "vlan": "Vl", "loopback": "Lo", "tunnel": "Tu",
             "appgigabitethernet": "Ap", "twogigabitethernet": "Tw", "fivegigabitethernet": "Fi", "mgmt": "mgmt",
             "serial": "Se", "management": "Ma", "bdi": "BDI", "nve": "nve", "xgigabitethernet": "XGE", "eth-trunk": "Eth-Trunk",
             "vlanif": "Vlanif", "meth": "MEth"}
    return table.get(head.lower(), head) + tail


class Interface(models.Model):
    MODES = [("access", "Access"), ("trunk", "Trunk"), ("routed", "Routed"), ("virtual", "Virtual"), ("unknown", "Unknown")]
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="interfaces")
    name = models.CharField(max_length=80)
    short = models.CharField(max_length=40, db_index=True)
    description = models.CharField(max_length=240, blank=True)
    admin_up = models.BooleanField(default=True)
    oper_up = models.BooleanField(default=False)
    status = models.CharField(max_length=20, blank=True, help_text="connected, notconnect, err-disabled, disabled …")
    mode = models.CharField(max_length=10, choices=MODES, default="unknown")
    access_vlan = models.CharField(max_length=10, blank=True)
    native_vlan = models.CharField(max_length=10, blank=True)
    voice_vlan = models.CharField(max_length=10, blank=True)
    trunk_vlans = models.TextField(blank=True)
    speed = models.CharField(max_length=30, blank=True)
    duplex = models.CharField(max_length=30, blank=True)
    speed_mbps = models.PositiveIntegerField(null=True, blank=True)
    media = models.CharField(max_length=80, blank=True)
    mtu = models.PositiveIntegerField(null=True, blank=True)
    mac = models.CharField(max_length=20, blank=True)
    ip = models.CharField(max_length=50, blank=True, help_text="address/prefix")
    port_channel = models.CharField(max_length=40, blank=True)
    if_index = models.PositiveIntegerField(null=True, blank=True)

    in_errors = models.BigIntegerField(default=0)
    out_errors = models.BigIntegerField(default=0)
    crc = models.BigIntegerField(default=0)
    runts = models.BigIntegerField(default=0)
    giants = models.BigIntegerField(default=0)
    frame = models.BigIntegerField(default=0)
    overrun = models.BigIntegerField(default=0)
    collisions = models.BigIntegerField(default=0)
    late_collisions = models.BigIntegerField(default=0)
    in_discards = models.BigIntegerField(default=0)
    out_drops = models.BigIntegerField(default=0)
    in_rate_bps = models.BigIntegerField(default=0)
    out_rate_bps = models.BigIntegerField(default=0)
    last_input = models.CharField(max_length=40, blank=True)
    last_flap = models.CharField(max_length=60, blank=True)
    # previous SNMP counters, for rate and error deltas
    c_in_octets = models.BigIntegerField(null=True, blank=True)
    c_out_octets = models.BigIntegerField(null=True, blank=True)
    c_in_errors = models.BigIntegerField(null=True, blank=True)
    c_ts = models.DateTimeField(null=True, blank=True)
    err_delta = models.BigIntegerField(default=0, help_text="new errors since the previous poll")
    resets = models.BigIntegerField(default=0)
    link_transitions = models.BigIntegerField(null=True, blank=True)
    flap_log = models.JSONField(default=list, blank=True, help_text="ISO times of recent up/down changes (24 h)")
    poe_admin = models.CharField(max_length=10, blank=True)
    poe_oper = models.CharField(max_length=12, blank=True)
    poe_watts = models.FloatField(null=True, blank=True)
    poe_device = models.CharField(max_length=60, blank=True)
    poe_class = models.CharField(max_length=6, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "name"]
        unique_together = [("device", "name")]

    def __str__(self):
        return f"{self.device.hostname} {self.short}"

    @property
    def utilization(self):
        if not self.speed_mbps:
            return None
        return round(100 * max(self.in_rate_bps, self.out_rate_bps) / (self.speed_mbps * 1_000_000), 1)

    @property
    def total_errors(self):
        return self.in_errors + self.out_errors

    @property
    def is_physical(self):
        return not re.match(r"^(vlan|loopback|tunnel|port-channel|null|nve|bdi|mgmt|management|meth|eth-trunk)", self.name.lower())

    @property
    def half_duplex(self):
        return "half" in self.duplex.lower()


class Neighbor(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="neighbors")
    protocol = models.CharField(max_length=6, default="cdp")
    local_interface = models.CharField(max_length=80)
    remote_name = models.CharField(max_length=200)
    remote_port = models.CharField(max_length=120, blank=True)
    remote_ip = models.CharField(max_length=60, blank=True)
    remote_platform = models.CharField(max_length=200, blank=True)
    remote_description = models.TextField(blank=True)
    capabilities = models.CharField(max_length=200, blank=True)
    remote_device = models.ForeignKey(Device, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "local_interface"]

    @property
    def kind(self):
        """What sits at the other end, for the topology icon."""
        caps, plat = self.capabilities.lower(), self.remote_platform.lower()
        letters = {c.strip() for c in self.capabilities.replace(",", " ").split() if len(c.strip()) == 1}
        caps += " " + " ".join({"b": "bridge", "r": "router", "t": "phone", "w": "wlan", "s": "station", "c": "docsis"}.get(x.lower(), "")
                               for x in letters)
        if "phone" in caps or "phone" in plat or plat.startswith("cisco ip phone"):
            return "phone"
        if "air-" in plat or "c91" in plat and "ap" in plat or "access point" in plat or "trans-bridge" in caps or "wlan" in caps:
            return "ap"
        if "router" in caps and "switch" not in caps:
            return "router"
        if "switch" in caps or "bridge" in caps:
            return "switch"
        if "host" in caps or "station" in caps:
            return "host"
        return "unknown"


class Route(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="routes")
    vrf = models.CharField(max_length=60, blank=True, default="default")
    protocol = models.CharField(max_length=10, help_text="Code as shown by the device: C, L, S, O, D, B …")
    prefix = models.CharField(max_length=50)
    distance = models.PositiveIntegerField(null=True, blank=True)
    metric = models.BigIntegerField(null=True, blank=True)
    next_hop = models.CharField(max_length=50, blank=True)
    interface = models.CharField(max_length=80, blank=True)
    age = models.CharField(max_length=30, blank=True)

    class Meta:
        ordering = ["device", "vrf", "prefix"]

    PROTO_NAMES = {"C": "Connected", "L": "Local", "S": "Static", "O": "OSPF", "D": "EIGRP", "B": "BGP", "R": "RIP",
                   "i": "IS-IS", "E": "EGP", "M": "Mobile", "direct": "Connected", "local": "Local", "static": "Static",
                   "ospf": "OSPF", "eigrp": "EIGRP", "bgp": "BGP", "hsrp": "HSRP", "am": "ARP"}

    @property
    def protocol_name(self):
        p = self.protocol.strip()
        return self.PROTO_NAMES.get(p) or self.PROTO_NAMES.get(p[:1]) or self.PROTO_NAMES.get(p.split("-")[0].lower(), p)

    @property
    def network(self):
        try:
            return ipaddress.ip_network(self.prefix, strict=False)
        except ValueError:
            return None


class Vlan(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="vlans")
    vid = models.PositiveIntegerField()
    name = models.CharField(max_length=80, blank=True)
    status = models.CharField(max_length=20, blank=True)
    ports = models.TextField(blank=True)

    class Meta:
        ordering = ["device", "vid"]
        unique_together = [("device", "vid")]


class ConfigSnapshot(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="configs")
    collected_at = models.DateTimeField(default=timezone.now, db_index=True)
    text = models.TextField()
    sha256 = models.CharField(max_length=64)
    added = models.PositiveIntegerField(default=0)
    removed = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-collected_at"]


class InterfaceSample(models.Model):
    """One throughput / error point per interface per poll; kept for the throughput charts (default 14 days)."""
    interface = models.ForeignKey(Interface, on_delete=models.CASCADE, related_name="samples")
    ts = models.DateTimeField(default=timezone.now, db_index=True)
    in_bps = models.BigIntegerField(default=0)
    out_bps = models.BigIntegerField(default=0)
    errors = models.BigIntegerField(default=0)

    class Meta:
        ordering = ["ts"]


class DiscoveryRun(models.Model):
    """Seed addresses + credentials; every switch or router found through CDP/LLDP is added and collected in turn."""
    STATUS = [("running", "Running"), ("done", "Done"), ("cancelled", "Cancelled")]
    name = models.CharField(max_length=120)
    seeds = models.TextField(help_text="One IP or hostname per line")
    platform = models.CharField(max_length=40, default="auto")
    ssh_credential = models.ForeignKey(Credential, null=True, on_delete=models.SET_NULL, related_name="+")
    snmp_credential = models.ForeignKey(Credential, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    site = models.ForeignKey(Site, null=True, blank=True, on_delete=models.SET_NULL)
    collector = models.ForeignKey("jobs.Collector", null=True, blank=True, on_delete=models.SET_NULL)
    max_depth = models.PositiveSmallIntegerField(default=3)
    include = models.CharField(max_length=200, blank=True, help_text="Only follow neighbours inside these subnets (comma separated). Empty = any.")
    status = models.CharField(max_length=10, choices=STATUS, default="running")
    created_by = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    log = models.TextField(blank=True)

    class Meta:
        ordering = ["-created_at"]

    def note(self, line):
        self.log = (self.log + f"{timezone.now():%H:%M:%S} {line}\n")[-20000:]
        self.save(update_fields=["log"])

    def allows(self, ip):
        if not self.include.strip():
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net in self.include.split(","):
            try:
                if addr in ipaddress.ip_network(net.strip(), strict=False):
                    return True
            except ValueError:
                continue
        return False


class MacEntry(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="macs")
    vlan = models.PositiveIntegerField(null=True, blank=True)
    mac = models.CharField(max_length=12, db_index=True)
    interface = models.CharField(max_length=60)
    type = models.CharField(max_length=24, blank=True)

    class Meta:
        indexes = [models.Index(fields=["device", "interface"])]


class ArpEntry(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="arps")
    ip = models.CharField(max_length=45, db_index=True)
    mac = models.CharField(max_length=12, db_index=True)
    interface = models.CharField(max_length=60, blank=True)


def fmt_mac(m):
    return ":".join(m[i:i + 2] for i in range(0, 12, 2)) if m and len(m) == 12 else (m or "")


OUI = {"005056": "VMware", "000c29": "VMware", "000569": "VMware", "001c14": "VMware", "080027": "VirtualBox", "525400": "QEMU/KVM",
       "00155d": "Microsoft Hyper-V", "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
       "28cdc1": "Raspberry Pi", "2ccf67": "Raspberry Pi"}


class Endpoint(models.Model):
    """Something plugged into an edge (access) port: where it is now and where it has been."""
    mac = models.CharField(max_length=12, unique=True)
    ip = models.CharField(max_length=45, blank=True, db_index=True)
    name = models.CharField(max_length=120, blank=True, help_text="From CDP/LLDP when the endpoint announces itself")
    kind = models.CharField(max_length=12, blank=True)
    device = models.ForeignKey(Device, null=True, blank=True, on_delete=models.SET_NULL, related_name="endpoints")
    interface = models.CharField(max_length=60, blank=True)
    vlan = models.PositiveIntegerField(null=True, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now, db_index=True)
    moves = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-last_seen"]

    @property
    def mac_display(self):
        return fmt_mac(self.mac)

    @property
    def vendor(self):
        if not self.mac:
            return ""
        if int(self.mac[:2], 16) & 0x02:
            return "Private / randomised MAC"
        return OUI.get(self.mac[:6], "")


class EndpointEvent(models.Model):
    KINDS = [("new", "First seen"), ("moved", "Moved"), ("ip", "IP changed")]
    endpoint = models.ForeignKey(Endpoint, on_delete=models.CASCADE, related_name="events")
    kind = models.CharField(max_length=6, choices=KINDS)
    at = models.DateTimeField(default=timezone.now, db_index=True)
    from_where = models.CharField(max_length=160, blank=True)
    to_where = models.CharField(max_length=160, blank=True)

    class Meta:
        ordering = ["-at"]


class Transceiver(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="optics")
    interface = models.CharField(max_length=60)
    pid = models.CharField(max_length=60, blank=True)
    serial = models.CharField(max_length=60, blank=True)
    description = models.CharField(max_length=120, blank=True)
    temp = models.FloatField(null=True, blank=True)
    volt = models.FloatField(null=True, blank=True)
    bias = models.FloatField(null=True, blank=True)
    tx = models.FloatField(null=True, blank=True)
    rx = models.FloatField(null=True, blank=True)
    flags = models.JSONField(default=dict, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["device", "interface"]

    @property
    def health(self):
        f = self.flags or {}
        if any(v in ("--", "++") for v in f.values()):
            return "alarm"
        if any(v in ("-", "+") for v in f.values()):
            return "warning"
        if self.rx is not None and self.rx < -20:
            return "alarm"
        return "ok" if self.rx is not None else "unknown"


class StpVlan(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="stp")
    vlan = models.PositiveIntegerField()
    root_mac = models.CharField(max_length=12, blank=True)
    root_prio = models.PositiveIntegerField(null=True, blank=True)
    bridge_mac = models.CharField(max_length=12, blank=True)
    bridge_prio = models.PositiveIntegerField(null=True, blank=True)
    is_root = models.BooleanField(default=False)
    root_port = models.CharField(max_length=60, blank=True)
    root_cost = models.PositiveIntegerField(null=True, blank=True)
    tc_count = models.PositiveIntegerField(null=True, blank=True)
    tc_ago = models.CharField(max_length=30, blank=True)
    tc_from = models.CharField(max_length=60, blank=True)
    ports = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["vlan", "device"]
        unique_together = [("device", "vlan")]

    @property
    def blocked(self):
        return [p["interface"] for p in self.ports if p.get("state", "").upper().startswith("BLK")]

    @property
    def tc_seconds(self):
        """'00:03:12' or '2d04h' or '1w2d' -> seconds since the last topology change."""
        import re
        t = self.tc_ago or ""
        m = re.match(r"^(\d+):(\d+):(\d+)$", t)
        if m:
            return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
        total = 0
        for n, u in re.findall(r"(\d+)([ywdhm])", t):
            total += int(n) * {"y": 31536000, "w": 604800, "d": 86400, "h": 3600, "m": 60}[u]
        return total or None


class DeviceSample(models.Model):
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="samples")
    ts = models.DateTimeField(default=timezone.now, db_index=True)
    cpu = models.PositiveSmallIntegerField(null=True, blank=True)
    mem = models.PositiveSmallIntegerField(null=True, blank=True)

    class Meta:
        ordering = ["ts"]
