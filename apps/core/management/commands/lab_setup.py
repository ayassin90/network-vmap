"""Prepare VMap for the mock-switch lab (docker-compose.lab.yml): site, credentials, sample lifecycle data, a test image,
short reload timers, and a discovery from the seed switch. Idempotent."""
import hashlib
from datetime import date, timedelta

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Set up and discover the mock-switch lab (172.31.99.0/24)."

    def add_arguments(self, parser):
        parser.add_argument("--clear-demo", action="store_true", help="Remove the offline demo devices first")
        parser.add_argument("--seed", default="172.31.99.1")

    def handle(self, *a, clear_demo=False, seed="172.31.99.1", **kw):
        from apps.core.demo import load
        from apps.core.models import AppSetting
        from apps.inventory.models import Credential, Device, DiscoveryRun, Site
        from apps.jobs.services import enqueue_collect
        from apps.lifecycle.models import Contract, HardwareLifecycle, SoftwareStandard
        from apps.upgrades.models import SoftwareImage
        from labnet.network import LAB_IPS, build
        if clear_demo:
            load(clear_only=True)
        site, _ = Site.objects.get_or_create(name="Mock lab", defaults={"location": "docker-compose.lab.yml, 172.31.99.0/24"})
        ssh, _ = Credential.objects.get_or_create(name="lab-ssh", defaults={"kind": "ssh", "username": "vmap"})
        ssh.password = "vmap-lab"
        ssh.save()
        snmp, _ = Credential.objects.get_or_create(name="lab-snmp", defaults={"kind": "snmp2"})
        snmp.community = "vmap-lab"
        snmp.save()
        for pid, eos, ldos, repl in (("WS-C2960X-48FPD-L", date(2022, 10, 30), date(2026, 10, 31), "C9200L-48P-4X"),
                                     ("ISR4331/K9", date(2023, 11, 7), date(2028, 11, 30), "C8300-1N1S-4T2X"),
                                     ("GLC-SX-MMD", date(2024, 2, 1), date(2027, 1, 31), "GLC-SX-MMD=")):
            HardwareLifecycle.objects.get_or_create(pid=pid, defaults={"end_of_sale": eos, "last_day_of_support": ldos, "replacement": repl,
                                                                       "source": "demo", "description": "Sample dates for the lab"})
        for pid, eos, ldos, repl in (("EX2300-48P", date(2025, 6, 30), date(2030, 6, 30), "EX4100-48P"),
                                     ("JL256A", date(2025, 10, 31), date(2030, 10, 31), "R8N85A (CX 6000)")):
            HardwareLifecycle.objects.get_or_create(pid=pid, defaults={"end_of_sale": eos, "last_day_of_support": ldos, "replacement": repl,
                                                                       "source": "demo", "description": "Sample dates for the lab"})
        for plat, model, rec, mn in (("cisco_iosxe", "^C9300", "17.9.5", "17.6.6"), ("cisco_iosxe", "^C9500", "17.9.5", "17.9.4a"),
                                     ("aruba_aoscx", "", "FL.10.13.1000", "FL.10.10.1000"), ("juniper_junos", "", "22.4R3-S2", "21.4R3-S5"),
                                     ("arista_eos", "", "4.30.4M", "4.28.0F"), ("cisco_nxos", "", "9.3(10)", "9.3(8)"),
                                     ("aruba_aoss", "", "WC.16.11.0012", "WC.16.10.0010"), ("huawei_vrp", "", "V200R022C00SPC500", "V200R021C00SPC100"),
                                     ("fortiswitch", "", "v7.4.3", "v7.2.0")):
            SoftwareStandard.objects.get_or_create(platform=plat, model_match=model, defaults={"recommended": rec, "minimum": mn, "notes": "lab"})
        lab = build(LAB_IPS)
        serials = [d["serial"] for n, d in lab.items() if not n.startswith("_") and n not in ("ACC-5", "ACC-6")]
        Contract.objects.get_or_create(number="LAB-SNT-100200", defaults={"vendor": "Cisco", "level": "SNT 8x5xNBD", "source": "demo",
                                                                          "end": date.today() + timedelta(days=400), "serials": "\n".join(serials[:-1])})
        Contract.objects.get_or_create(number="LAB-SNT-100201", defaults={"vendor": "Cisco", "level": "SNT 8x5xNBD", "source": "demo",
                                                                          "end": date.today() + timedelta(days=40), "serials": serials[-1]})
        fn = "cat9k_iosxe.17.09.05.SPA.bin"
        SoftwareImage.objects.get_or_create(filename=fn, defaults={
            "name": "Catalyst 9300 17.9.5 (lab)", "platforms": "cisco_iosxe", "model_match": "^C9300", "version": "17.9.5",
            "md5": hashlib.md5(fn.encode()).hexdigest(), "size_bytes": 457000000, "transfer_url": f"http://10.50.1.30/images/{fn}",
            "notes": "The mock switches pretend to download it; the MD5 matches what they report."})
        for fn, name, plats, model, ver, url, size, md5 in (
                ("EOS-4.30.4M.swi", "Arista EOS 4.30.4M (lab)", "arista_eos", "", "4.30.4M", "http://10.50.1.30/images/", 912000015, True),
                ("nxos.9.3.10.bin", "Nexus 9000 9.3(10) (lab)", "cisco_nxos", "", "9.3(10)", "http://10.50.1.30/images/", 0, True),
                ("junos-arm-32-22.4R3-S2.11.tgz", "Junos EX2300 22.4R3-S2 (lab)", "juniper_junos", "^EX2300", "22.4R3-S2.11", "http://10.50.1.30/images/", 381000029, True),
                ("WC_16_11_0012.swi", "AOS-S 2930F WC.16.11.0012 (lab)", "aruba_aoss", "", "WC.16.11.0012", "tftp://10.50.1.30/", 0, False),
                ("S5735-L-V200R022C00SPC500.cc", "Huawei S5735 V200R022C00SPC500 (lab)", "huawei_vrp", "", "V200R022C00SPC500", "tftp://10.50.1.30/", 61866012, False),
                ("FS1E48-v7.4.3-build0845-FORTINET.out", "FortiSwitch 148F v7.4.3 (lab)", "fortiswitch", "", "v7.4.3", "tftp://10.50.1.30/", 0, False),
                ("ArubaOS-CX_6300_FL_10_13_1000.swi", "Aruba CX 6300 FL.10.13.1000 (lab)", "aruba_aoscx", "", "FL.10.13.1000", "http://10.50.1.30/images/", 0, False)):
            SoftwareImage.objects.get_or_create(filename=fn, defaults={
                "name": name, "platforms": plats, "model_match": model, "version": ver, "size_bytes": size, "transfer_url": url + fn,
                "md5": hashlib.md5(fn.encode()).hexdigest() if md5 else "", "notes": "Lab image: the mock switches pretend to download it."})
        AppSetting.put("upgrade_postcheck_delay_seconds", "50")
        AppSetting.put("upgrade_postcheck_retry_seconds", "20")
        AppSetting.put("poll_interval_minutes", "2")
        AppSetting.put("mac_scan_interval_minutes", "10")
        run = DiscoveryRun.objects.create(name="Mock lab", seeds=seed, platform="auto", ssh_credential=ssh, snmp_credential=snmp, site=site,
                                          max_depth=4, include="172.31.99.0/24", created_by="lab_setup")
        d, created = Device.objects.get_or_create(mgmt_ip=seed, defaults={"hostname": seed, "platform": "cisco_iosxe", "site": site,
                                                                          "ssh_credential": ssh, "snmp_credential": snmp, "discovery": run})
        if not created:
            d.discovery, d.discovery_depth = run, 0
            d.save()
        enqueue_collect(d, "lab_setup")
        for other in Device.objects.filter(mgmt_ip__startswith="172.31.99.", demo=False).exclude(pk=d.pk):
            other.discovery, other.discovery_depth = run, 0       # re-crawl from every known lab switch so new neighbours are found
            other.save(update_fields=["discovery", "discovery_depth"])
            enqueue_collect(other, "lab_setup")
        run.note("started from " + seed)
        self.stdout.write(f"Lab ready. Discovery #{run.pk} started from {seed}; open /devices/discovery/{run.pk}/")
