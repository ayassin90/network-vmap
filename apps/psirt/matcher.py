"""Match advisories to devices. Config-based exposure for built-in advisories; version matches come from sync.py."""
import re

from django.utils import timezone

from .models import Advisory, DeviceAdvisory
from .versions import fixed_status


def match_device(device):
    snap = device.latest_config
    text = snap.text if snap else ""
    os_type = device.os_type or device.driver.os_type
    seen = []
    for adv in Advisory.objects.exclude(condition=""):
        if os_type not in [o.strip() for o in adv.os_types.split(",")]:
            continue
        if not text:
            continue
        found = bool(re.search(adv.condition, text, re.M))
        exposed = (not found) if adv.condition_absent else found
        if not exposed:
            continue
        fixed = fixed_status(device.os_version, adv.fixed_in) if adv.fixed_in and device.os_version else None
        if fixed is True:
            continue
        detail = ("Feature enabled in config" if not adv.condition_absent else "Protective config line missing")
        detail += f"; {device.os_version} is before the fixed release" if fixed is False else "; confirm the fixed release for your version"
        seen.append(_hit(device, adv, "config", detail))
    # version matches are refreshed by sync; drop config matches that no longer apply
    DeviceAdvisory.objects.filter(device=device, match="config", status="open").exclude(pk__in=seen).update(status="resolved")
    return len(seen)


def _hit(device, adv, match, detail):
    obj, created = DeviceAdvisory.objects.get_or_create(device=device, advisory=adv, defaults={"match": match, "detail": detail[:300]})
    if not created:
        obj.detail, obj.last_seen = detail[:300], timezone.now()
        if obj.status == "resolved":
            obj.status = "open"
        if match == "version":
            obj.match = "version"
        obj.save()
    return obj.pk
