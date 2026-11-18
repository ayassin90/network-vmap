"""Neighbour crawl: after a device from a discovery run is collected, its CDP/LLDP neighbours that are switches or
routers (and inside the allowed subnets) become new devices and are collected in turn, up to max depth."""
import re

from apps.drivers.registry import detect_platform

from .models import Device


def platform_from_neighbor(n, default):
    plat = f"{n.remote_platform} {n.remote_description}"
    if re.search(r"N[3579]K|Nexus|NX-OS", plat, re.I):
        return "cisco_nxos"
    if re.search(r"C9[2-6]\d\d|C38[0-9]0|C36[0-9]0|IOS[ -]XE|IE-3[2-4]00", plat, re.I):
        return "cisco_iosxe"
    if re.search(r"cisco|WS-C", plat, re.I):
        return "cisco_ios"
    if re.search(r"Huawei|VRP \(R\)|\bS57\d\d|\bS67\d\d|CloudEngine", plat, re.I):
        return "huawei_vrp"
    if re.search(r"revision [A-Z]{2}\.\d+\.\d+|ProCurve|\b(2530|2540|2920|2930[FM]|3810M|5400R)\b", plat):
        return "aruba_aoss"
    if re.search(r"Aruba.*(\bJL\d{3}A\b|\b(4100i|6[0-4]00F?|8[0-4]\d\d)\b|\b(FL|GL|LL|DL|PL|ML)\.\d+\.\d+)|ArubaOS-CX|AOS-CX", plat, re.I):
        return "aruba_aoscx"
    return detect_platform(plat) or default


def crawl(device):
    run = device.discovery
    if not run or run.status != "running" or device.discovery_depth >= run.max_depth:
        return 0
    from apps.jobs.services import enqueue_collect
    added = 0
    for n in device.neighbors.filter(remote_device=None).exclude(remote_ip=""):
        if n.kind not in ("switch", "router"):
            continue
        if not run.allows(n.remote_ip):
            continue
        if Device.objects.filter(mgmt_ip=n.remote_ip).exists():
            continue
        plat = platform_from_neighbor(n, "cisco_ios" if run.platform == "auto" else run.platform)
        from apps.drivers.registry import get_driver
        if not (plat and get_driver(plat).collect_commands()) and not run.snmp_credential:
            run.note(f"skipped {n.remote_name} ({n.remote_ip}): {plat or 'unknown platform'} has no SSH driver yet and needs an SNMP credential")
            continue
        d = Device.objects.create(hostname=n.remote_name.split(".")[0].split("(")[0][:120], mgmt_ip=n.remote_ip, platform=plat or "generic_snmp",
                                  site=run.site or device.site, ssh_credential=run.ssh_credential, snmp_credential=run.snmp_credential,
                                  collector=run.collector, discovery=run, discovery_depth=device.discovery_depth + 1)
        enqueue_collect(d, run.created_by)
        run.note(f"found {d.hostname} ({d.mgmt_ip}) via {device.hostname} {n.local_interface}, depth {d.discovery_depth}")
        added += 1
    return added
