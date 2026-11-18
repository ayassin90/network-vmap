"""Lifecycle findings: end-of-sale / end-of-support hardware, software below the golden version, missing or expiring contracts."""
from datetime import date, timedelta

from apps.psirt.versions import at_or_after

from .models import Contract, HardwareLifecycle, SoftwareStandard, lifecycle_for


def device_pids(device):
    pids = []
    if device.model:
        pids.append(("chassis", device.model.split()[0]))
    for m in (device.facts or {}).get("modules", []) or []:
        if m.get("pid") and m["pid"].split()[0] != (device.model or "").split()[0]:
            pids.append((m.get("name") or "module", m["pid"]))
    for o in device.optics.all():
        if o.pid:
            pids.append((o.interface, o.pid))
    return pids


def device_serials(device):
    s = {device.serial.upper()} if device.serial else set()
    for m in (device.facts or {}).get("modules", []) or []:
        if m.get("serial"):
            s.add(m["serial"].upper())
    return s


def coverage(device, contracts=None):
    """(contract or None, end date) for the device's chassis serial."""
    contracts = contracts if contracts is not None else list(Contract.objects.all())
    if not device.serial:
        return None
    best = None
    for c in contracts:
        if device.serial.upper() in c.serial_set() and (not best or c.end > best.end):
            best = c
    return best


def run_lifecycle(device):
    from apps.checks.engine import _close, _upsert
    today = date.today()
    keep = []
    records = list(HardwareLifecycle.objects.all())
    for where, pid in device_pids(device):
        r = lifecycle_for(pid, records)
        if not r:
            continue
        key = f"{where}:{pid}"[:120]
        label = "This switch" if where == "chassis" else f"{pid} in {where}"
        if r.last_day_of_support and r.last_day_of_support <= today:
            keep.append(_upsert(device, "lifecycle", "LC-LDOS", key, "high" if where == "chassis" else "medium", f"{pid} is past its last day of support",
                                f"{label} reached end of support on {r.last_day_of_support:%d %b %Y}. No more fixes, security patches or TAC.",
                                f"Plan a replacement{f' (suggested: {r.replacement})' if r.replacement else ''}."))
        elif r.last_day_of_support and r.last_day_of_support <= today + timedelta(days=365):
            keep.append(_upsert(device, "lifecycle", "LC-LDOS", key, "medium", f"{pid} reaches end of support within a year",
                                f"{label}: last day of support {r.last_day_of_support:%d %b %Y}.",
                                f"Budget and plan the replacement now{f' (suggested: {r.replacement})' if r.replacement else ''}."))
        elif r.end_of_sale and r.end_of_sale <= today:
            keep.append(_upsert(device, "lifecycle", "LC-EOS", key, "low", f"{pid} is no longer sold",
                                f"{label}: end of sale {r.end_of_sale:%d %b %Y}"
                                + (f", supported until {r.last_day_of_support:%d %b %Y}." if r.last_day_of_support else "."),
                                "Spares will get harder to find. Add it to the refresh plan."))
    for std in SoftwareStandard.objects.all():
        if not std.fits(device) or not device.os_version:
            continue
        if std.minimum and not at_or_after(device.os_version, std.minimum):
            keep.append(_upsert(device, "lifecycle", "LC-SWMIN", "", "high", "Software older than the minimum you accept",
                                f"Running {device.os_version}; your minimum for this platform is {std.minimum} (recommended {std.recommended}).",
                                "Upgrade to the recommended version (Software upgrades page)."))
        elif device.os_version != std.recommended:
            keep.append(_upsert(device, "lifecycle", "LC-SWREC", "", "low", "Not on the recommended software version",
                                f"Running {device.os_version}; recommended is {std.recommended}.",
                                "Move to the recommended version in your next maintenance window."))
        break
    contracts = list(Contract.objects.all())
    if contracts and device.serial:
        c = coverage(device, contracts)
        if not c:
            keep.append(_upsert(device, "lifecycle", "LC-NOCONTRACT", "", "low", "No support contract covers this device",
                                f"Serial {device.serial} is not in any contract.", "Add it to a contract, or record why it is not covered."))
        elif c.end < today:
            keep.append(_upsert(device, "lifecycle", "LC-CONTRACTEXP", "", "medium", "Support contract has expired",
                                f"Contract {c.number} ended on {c.end:%d %b %Y}.", "Renew the contract or move the device to another one."))
        elif c.end <= today + timedelta(days=90):
            keep.append(_upsert(device, "lifecycle", "LC-CONTRACTSOON", "", "low", "Support contract ends within 90 days",
                                f"Contract {c.number} ends on {c.end:%d %b %Y}.", "Start the renewal now."))
    _close(device, ["lifecycle"], keep)
