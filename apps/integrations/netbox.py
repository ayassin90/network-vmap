"""NetBox synchronisation (REST API, NetBox 3.x and 4.x).

Push: VMap is the source of truth for what is plugged in. Creates or updates manufacturers, device types, device roles,
platforms, sites, devices (serial, status, platform), their interfaces (type, description, enabled, MTU, MAC), management
IP addresses (set as primary IP) and cables between devices that see each other over CDP/LLDP.
Import: NetBox is the source of truth for what should be managed: devices with a primary IP become VMap devices."""
import re

import requests
from django.utils import timezone
from django.utils.text import slugify

from apps.core.models import AppSetting

ROLE_COLORS = {"core": "e53935", "distribution": "fb8c00", "access": "43a047", "datacenter": "1e88e5", "router": "8e24aa", "firewall": "c62828",
               "wireless": "00897b", "unknown": "9e9e9e"}


class NetBoxError(Exception):
    pass


class NetBox:
    def __init__(self, url=None, token=None, verify=None, dry=False):
        self.url = (url or AppSetting.get("netbox_url", "")).rstrip("/")
        self.token = token or AppSetting.get("netbox_token", "")
        self.verify = (AppSetting.get("netbox_verify_tls", "1") == "1") if verify is None else verify
        self.dry = dry
        self.log, self.stats = [], {}
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Token {self.token}", "Accept": "application/json", "Content-Type": "application/json"})
        self._cache = {}

    def note(self, msg):
        self.log.append(f"{timezone.localtime():%H:%M:%S} {msg}")

    def count(self, k):
        self.stats[k] = self.stats.get(k, 0) + 1

    def req(self, method, path, **kw):
        if not self.url or not self.token:
            raise NetBoxError("NetBox URL and token are not set (Settings → NetBox).")
        r = self.s.request(method, f"{self.url}/api/{path.lstrip('/')}", timeout=20, verify=self.verify, **kw)
        if r.status_code >= 400:
            raise NetBoxError(f"{method} {path}: HTTP {r.status_code} {r.text[:300]}")
        return r.json() if r.content else {}

    def all(self, path, **params):
        out, params = [], dict(params, limit=500)
        data = self.req("GET", path, params=params)
        out += data.get("results", [])
        while data.get("next"):
            nxt = data["next"].split("/api/", 1)[1]
            data = self.req("GET", nxt)
            out += data.get("results", [])
        return out

    def status(self):
        return self.req("GET", "status/")

    def ensure(self, path, lookup, create, update=None, label=""):
        """Find an object by `lookup` (query params) or create it; patch `update` fields that differ. Returns the object (or a
        placeholder in dry-run)."""
        key = (path, tuple(sorted(lookup.items())))
        if key in self._cache and not update:
            return self._cache[key]
        found = self.req("GET", path, params=lookup).get("results", [])
        obj = found[0] if found else None
        kind = path.strip("/").split("/")[-1]
        if not obj:
            self.count(f"{kind} created")
            self.note(f"create {kind} {label or create}")
            obj = {"id": None, **create} if self.dry else self.req("POST", path, json=create)
        elif update:
            diff = {k: v for k, v in update.items() if _val(obj.get(k)) != v}
            if diff:
                self.count(f"{kind} updated")
                self.note(f"update {kind} {label}: {', '.join(diff)}")
                if not self.dry:
                    obj = self.req("PATCH", f"{path}{obj['id']}/", json=diff)
        self._cache[key] = obj
        return obj

    # ---------------------------------------------------------------- push
    def push(self, devices=None):
        from apps.inventory.models import Device, Neighbor
        devs = list(devices or Device.objects.filter(enabled=True, demo=False).select_related("site"))
        default_site = AppSetting.get("netbox_site_default", "")
        nb_dev = {}
        for d in devs:
            site_name = d.site.name if d.site else default_site
            if not site_name:
                self.note(f"skip {d.hostname}: no site (set a default NetBox site in Settings)")
                self.count("devices skipped")
                continue
            site = self.ensure("dcim/sites/", {"slug": slugify(site_name)[:100]}, {"name": site_name, "slug": slugify(site_name)[:100], "status": "active"},
                               label=site_name)
            vendor = d.vendor or d.driver.vendor or "Unknown"
            mfr = self.ensure("dcim/manufacturers/", {"slug": slugify(vendor)}, {"name": vendor, "slug": slugify(vendor)}, label=vendor)
            model = (d.model or "Unknown").strip()[:100]
            dtype = self.ensure("dcim/device-types/", {"slug": slugify(f"{vendor}-{model}")[:100]},
                                {"manufacturer": mfr["id"], "model": model, "slug": slugify(f"{vendor}-{model}")[:100]}, label=model)
            role_name = d.get_role_display() if d.role else "Unknown"
            role = self.ensure("dcim/device-roles/", {"slug": slugify(role_name)}, {"name": role_name, "slug": slugify(role_name),
                                                                                     "color": ROLE_COLORS.get(d.role, "9e9e9e")}, label=role_name)
            plat = self.ensure("dcim/platforms/", {"slug": slugify(d.platform)}, {"name": d.driver.label[:100], "slug": slugify(d.platform)}, label=d.platform)
            want = {"device_type": dtype["id"], "role": role["id"], "site": site["id"], "platform": plat["id"], "serial": (d.serial or "")[:50],
                    "status": "active" if d.status in ("up", "unknown") else "offline",
                    "comments": f"Managed by Network VMap. Software {d.os_version}."}
            existing = self.req("GET", "dcim/devices/", params={"name": d.hostname}).get("results", [])
            if existing:
                obj = existing[0]
                upd = {k: v for k, v in want.items() if k not in ("comments",) and _val(obj.get(k if k != "role" else ("role" if "role" in obj else "device_role"))) != v}
                if upd:
                    self.count("devices updated")
                    self.note(f"update device {d.hostname}: {', '.join(upd)}")
                    if not self.dry:
                        obj = self.req("PATCH", f"dcim/devices/{obj['id']}/", json=upd)
            else:
                self.count("devices created")
                self.note(f"create device {d.hostname}")
                body = dict(want, name=d.hostname)
                if self.dry:
                    obj = {"id": None, **body}
                else:
                    try:
                        obj = self.req("POST", "dcim/devices/", json=body)
                    except NetBoxError as exc:            # NetBox 3.x calls the role device_role
                        if "role" not in str(exc):
                            raise
                        body["device_role"] = body.pop("role")
                        obj = self.req("POST", "dcim/devices/", json=body)
            nb_dev[d.pk] = obj
            self.push_interfaces(d, obj)
        self.push_cables(nb_dev, Neighbor.objects.filter(device__in=nb_dev.keys(), remote_device__in=nb_dev.keys()))
        return self.stats

    def push_interfaces(self, d, nbd):
        if not nbd.get("id"):
            self.stats["interfaces (dry run)"] = self.stats.get("interfaces (dry run)", 0) + d.interfaces.count()
            return
        have = {i["name"]: i for i in self.all("dcim/interfaces/", device_id=nbd["id"])}
        mgmt_iface = None
        for i in d.interfaces.all():
            want = {"type": _iftype(i), "description": (i.description or "")[:200], "enabled": bool(i.admin_up)}
            if i.mtu:
                want["mtu"] = i.mtu
            obj = have.get(i.name)
            if not obj:
                self.count("interfaces created")
                if not self.dry:
                    obj = self.req("POST", "dcim/interfaces/", json=dict(want, device=nbd["id"], name=i.name))
            else:
                diff = {k: v for k, v in want.items() if _val(obj.get(k)) != v}
                if diff:
                    self.count("interfaces updated")
                    if not self.dry:
                        obj = self.req("PATCH", f"dcim/interfaces/{obj['id']}/", json=diff)
            if obj and i.ip:
                ip = self.ensure("ipam/ip-addresses/", {"address": i.ip}, {"address": i.ip, "assigned_object_type": "dcim.interface",
                                                                          "assigned_object_id": obj["id"], "status": "active"}, label=i.ip)
                if i.ip.split("/")[0] == d.mgmt_ip:
                    mgmt_iface = ip
        if mgmt_iface and mgmt_iface.get("id") and _val(nbd.get("primary_ip4")) != mgmt_iface["id"] and not self.dry:
            self.req("PATCH", f"dcim/devices/{nbd['id']}/", json={"primary_ip4": mgmt_iface["id"]})
            self.count("primary IPs set")

    def push_cables(self, nb_dev, neighbors):
        if self.dry:
            return
        done = set()
        for n in neighbors:
            a, b = nb_dev.get(n.device_id), nb_dev.get(n.remote_device_id)
            if not a or not b or not a.get("id") or not b.get("id"):
                continue
            key = tuple(sorted([(a["id"], n.local_interface), (b["id"], n.remote_port)]))
            if key in done:
                continue
            done.add(key)
            ia = self._iface(a["id"], n.local_interface, n.device)
            ib = self._iface(b["id"], n.remote_port, n.remote_device)
            if not ia or not ib or ia.get("cable") or ib.get("cable"):
                continue
            try:
                self.req("POST", "dcim/cables/", json={"a_terminations": [{"object_type": "dcim.interface", "object_id": ia["id"]}],
                                                       "b_terminations": [{"object_type": "dcim.interface", "object_id": ib["id"]}], "status": "connected",
                                                       "label": "VMap"})
                self.count("cables created")
            except NetBoxError as exc:
                self.note(f"cable {n.device.hostname} {n.local_interface} ↔ {n.remote_device.hostname} {n.remote_port} not created: {exc}")

    def _iface(self, dev_id, short, device):
        full = device.interfaces.filter(short__iexact=short).first() if device else None
        name = full.name if full else short
        r = self.req("GET", "dcim/interfaces/", params={"device_id": dev_id, "name": name}).get("results", [])
        return r[0] if r else None

    # ---------------------------------------------------------------- import
    def import_devices(self, site_slug="", role_slug="", ssh_credential=None, snmp_credential=None, platform_default="cisco_iosxe"):
        from apps.drivers.registry import drivers
        from apps.inventory.models import Device, Site
        params = {"has_primary_ip": "true", "status": "active"}
        if site_slug:
            params["site"] = site_slug
        if role_slug:
            params["role"] = role_slug
        known = {d.key for d in drivers().values()}
        added = 0
        for nd in self.all("dcim/devices/", **params):
            ip = ((nd.get("primary_ip4") or nd.get("primary_ip") or {}).get("address") or "").split("/")[0]
            if not ip or Device.objects.filter(mgmt_ip=ip).exists():
                continue
            plat = (nd.get("platform") or {}).get("slug", "") or ""
            plat = plat if plat in known else _guess_platform((nd.get("device_type") or {}).get("manufacturer", {}).get("name", ""), plat) or platform_default
            site_name = (nd.get("site") or {}).get("name", "")
            site = Site.objects.get_or_create(name=site_name)[0] if site_name else None
            role = slugify((nd.get("role") or nd.get("device_role") or {}).get("name", "")).replace("-", "")
            self.note(f"import {nd['name']} {ip} as {plat}")
            if not self.dry:
                Device.objects.create(hostname=nd["name"][:120], mgmt_ip=ip, platform=plat, site=site, ssh_credential=ssh_credential,
                                      snmp_credential=snmp_credential, role=role if role in dict(Device.ROLES) else "unknown",
                                      tags="netbox")
            added += 1
        self.stats["devices imported"] = added
        return added


def _val(v):
    if isinstance(v, dict):
        return v.get("id", v.get("value"))
    return v


def _mac(m):
    h = re.sub(r"[^0-9a-fA-F]", "", m or "")
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper() if len(h) == 12 else ""


def _iftype(i):
    n, sp = i.name.lower(), i.speed_mbps or 0
    if i.mode == "virtual" or n.startswith(("vlan", "loopback", "irb", "vlanif", "tunnel", "nve", "management", "mgmt", "meth")):
        return "virtual"
    if n.startswith(("port-channel", "eth-trunk", "ae")) or re.match(r"po\d", n):
        return "lag"
    media = (i.media or "").lower()
    fiber = any(x in media for x in ("sfp", "sr", "lr", "lx", "sx", "base-x", "qsfp"))
    if sp >= 100000 or n.startswith(("hundredgig", "hu", "et-")):
        return "100gbase-x-qsfp28"
    if sp >= 40000 or n.startswith(("fortygig", "fo")):
        return "40gbase-x-qsfpp"
    if sp >= 25000 or n.startswith(("twentyfivegig", "twe")):
        return "25gbase-x-sfp28"
    if sp >= 10000 or n.startswith(("tengig", "te", "xe-", "xgigabit")):
        return "10gbase-x-sfpp" if fiber or not media else "10gbase-t"
    if fiber:
        return "1000base-x-sfp"
    return "1000base-t"


def _guess_platform(vendor, slug):
    t = f"{vendor} {slug}".lower()
    for hint, key in (("nx", "cisco_nxos"), ("ios-xe", "cisco_iosxe"), ("iosxe", "cisco_iosxe"), ("ios", "cisco_ios"), ("aruba", "aruba_aoscx"),
                      ("aos-cx", "aruba_aoscx"), ("procurve", "aruba_aoss"), ("aos-s", "aruba_aoss"), ("huawei", "huawei_vrp"), ("juniper", "juniper_junos"),
                      ("junos", "juniper_junos"), ("arista", "arista_eos"), ("fortinet", "fortiswitch"), ("cisco", "cisco_iosxe")):
        if hint in t:
            return key
    return ""


def run(kind="push", user="", **kw):
    from .models import SyncRun
    sr = SyncRun.objects.create(kind=kind, created_by=user)
    nb = NetBox(dry=(kind == "dryrun"))
    try:
        if kind == "import":
            nb.import_devices(**kw)
        else:
            nb.push()
        sr.ok = True
    except Exception as exc:  # noqa: BLE001
        nb.note(f"stopped: {exc}")
    sr.stats, sr.log, sr.finished_at = nb.stats, "\n".join(nb.log), timezone.now()
    sr.save()
    return sr
