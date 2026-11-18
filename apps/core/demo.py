"""Sample campus network, generated as real CLI output (labnet/) and pushed through the same parsers, checks and alert rules as a
live device. Nothing is sent to any device. Load with `manage.py load_demo`, remove with `manage.py load_demo --clear`.
The same network can be run as real SSH/SNMP mock switches: see tools/mocklab."""
import random
from datetime import timedelta

from django.utils import timezone

from labnet import aoscx, aoss, eos, fortiswitch, huawei, ios, junos, nxos
from labnet.network import DEMO_IPS, build


PLATFORMS = {"aoscx": ("aruba_aoscx", aoscx), "vrp": ("huawei_vrp", huawei), "junos": ("juniper_junos", junos), "aoss": ("aruba_aoss", aoss),
             "fortiswitch": ("fortiswitch", fortiswitch), "eos": ("arista_eos", eos), "nxos": ("cisco_nxos", nxos),
             "ios": ("cisco_ios", ios), "iosxe": ("cisco_iosxe", ios)}


def platform_of(d):
    return PLATFORMS[d["os_type"]][0]


def outputs_for(d, devs):
    return PLATFORMS[d["os_type"]][1].outputs_for(d, devs)


# ------------------------------------------------------------------ load / refresh
def load(clear_only=False):
    from apps.alerts.engine import evaluate_device, ensure_rules
    from apps.inventory import sync
    from apps.inventory.models import Device, InterfaceSample, Site
    from apps.jobs.ingest import analyse
    Device.objects.filter(demo=True).delete()
    if clear_only:
        Site.objects.filter(name="HQ Campus (demo)", devices=None).delete()
        return 0
    ensure_rules()
    site, _ = Site.objects.get_or_create(name="HQ Campus (demo)", defaults={"location": "Sample data"})
    devs = build(DEMO_IPS)
    objs = {}
    for name, d in devs.items():
        if name.startswith("_"):
            continue
        obj, _ = Device.objects.update_or_create(mgmt_ip=d["ip"], defaults=dict(
            hostname=name, platform=platform_of(d), role=d["role"], site=site, demo=True,
            tags="demo"))
        objs[name] = obj
    for name, d in devs.items():
        if name.startswith("_"):
            continue
        data = objs[name].driver.parse(outputs_for(d, devs))
        sync.apply(objs[name], data)
    # history: 24 h of 5-minute samples for every busy port, plus an older config version on CORE-2
    now = timezone.now()
    for obj in objs.values():
        for i in obj.interfaces.filter(oper_up=True).exclude(in_rate_bps=0):
            if not (i.mode == "trunk" or i.mode == "routed" or i.in_rate_bps > 50_000_000):
                continue
            rows = []
            for k in range(288, 0, -1):
                t = now - timedelta(minutes=5 * k)
                hour = t.hour + t.minute / 60
                shape = 0.25 + 0.75 * max(0, min(1, (1 - abs(hour - 13) / 7)))
                jitter = random.uniform(0.85, 1.15)
                rows.append(InterfaceSample(interface=i, ts=t, in_bps=int(i.in_rate_bps * shape * jitter), out_bps=int(i.out_rate_bps * shape * jitter),
                                            errors=random.randint(0, 40) if i.crc else 0))
            InterfaceSample.objects.bulk_create(rows)
    c2 = objs["CORE-2"]
    snap = c2.latest_config
    if snap:
        old = snap.text.replace("snmp-server community public RO\n", "snmp-server community Xk9-campus-ro RO MGMT\n")
        from apps.inventory.models import ConfigSnapshot
        ConfigSnapshot.objects.create(device=c2, text=old, sha256="demo-old", collected_at=now - timedelta(days=3))
        snap.added, snap.removed = 1, 1
        snap.collected_at = now - timedelta(minutes=20)
        snap.save()
    demo_extras(objs, now)
    for obj in objs.values():
        analyse(obj)
    for obj in objs.values():          # interface checks again, now that every neighbour exists
        from apps.checks.engine import run_interface_checks
        run_interface_checks(obj)
        evaluate_device(obj)
    return len(objs)


def refresh_device(device):
    """"Collect now" on a demo device: regenerate its output and push it through the pipeline again."""
    from apps.alerts.engine import evaluate_device
    from apps.inventory import sync
    from apps.jobs.ingest import analyse
    devs = build(DEMO_IPS)
    d = devs.get(device.hostname)
    if not d:
        return
    sync.apply(device, device.driver.parse(outputs_for(d, devs)))
    analyse(device)
    evaluate_device(device)


def demo_extras(objs, now):
    """Lifecycle, contracts, golden versions, a flapping port and endpoint history, so every page has something to show."""
    from datetime import date

    from apps.inventory.models import Endpoint, EndpointEvent
    from apps.lifecycle.models import Contract, HardwareLifecycle, SoftwareStandard
    HardwareLifecycle.objects.filter(source="demo").delete()
    SoftwareStandard.objects.filter(notes="demo").delete()
    Contract.objects.filter(source="demo").delete()
    for pid, eos, ldos, repl in (("WS-C2960X-48FPD-L", date(2022, 10, 30), date(2026, 10, 31), "C9200L-48P-4X"),
                                 ("ISR4331/K9", date(2023, 11, 7), date(2028, 11, 30), "C8300-1N1S-4T2X"),
                                 ("GLC-SX-MMD", date(2024, 2, 1), date(2027, 1, 31), "GLC-SX-MMD="),
                                 ("C9300-48P", None, None, "")):
        if eos or ldos:
            HardwareLifecycle.objects.create(pid=pid, end_of_sale=eos, last_day_of_support=ldos, replacement=repl, source="demo",
                                             description="Demo dates for illustration only")
    SoftwareStandard.objects.create(platform="cisco_iosxe", model_match="^C9300", recommended="17.9.5", minimum="17.6.6", notes="demo")
    SoftwareStandard.objects.create(platform="cisco_iosxe", model_match="^C9500", recommended="17.9.5", minimum="17.9.4a", notes="demo")
    SoftwareStandard.objects.create(platform="aruba_aoscx", model_match="", recommended="FL.10.13.1000", minimum="FL.10.10.1000", notes="demo")
    serials = [o.serial for n, o in objs.items() if n not in ("ACC-5", "ACC-6") and o.serial]
    Contract.objects.create(number="DEMO-SNT-100200", vendor="Cisco", level="SNT 8x5xNBD", end=date.today() + timedelta(days=400),
                            serials="\n".join(serials[:-1]), source="demo")
    Contract.objects.create(number="DEMO-SNT-100201", vendor="Cisco", level="SNT 8x5xNBD", end=date.today() + timedelta(days=40),
                            serials=serials[-1], source="demo")
    i = objs["ACC-1"].interfaces.filter(short="Gi1/0/22").first()
    if i:
        i.flap_log = [(now - timedelta(minutes=m)).isoformat() for m in (4, 9, 15, 22, 31, 38, 47, 55)]
        i.save(update_fields=["flap_log"])
    ep = Endpoint.objects.filter(device=objs["ACC-2"]).first()
    if ep:
        ep.moves = 1
        ep.first_seen = now - timedelta(days=3)
        ep.save()
        EndpointEvent.objects.create(endpoint=ep, kind="moved", from_where="ACC-3 Gi1/0/31", to_where=f"ACC-2 {ep.interface}", at=now - timedelta(hours=5))
