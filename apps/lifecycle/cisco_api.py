"""Cisco Support APIs (same API-console app as openVuln, with the EoX and Serial Number to Information APIs enabled).
EoX:      https://apix.cisco.com/supporttools/eox/rest/5/EOXByProductID/1/{pid,pid}
Coverage: https://apix.cisco.com/sn2info/v2/coverage/summary/serial_numbers/{sn,sn}
Both need entitlement on the Cisco side; errors are reported, never fatal."""
from datetime import date

import requests

from apps.core.models import AppSetting
from apps.inventory.models import Device

from .models import Contract, HardwareLifecycle

API = "https://apix.cisco.com"


def _token():
    from apps.psirt.sync import _token as tok
    cid, secret = AppSetting.get("openvuln_client_id"), AppSetting.get("openvuln_client_secret")
    if not cid or not secret:
        raise RuntimeError("Cisco API credentials are not set (Settings).")
    return tok(cid, secret)


def _d(v):
    try:
        return date.fromisoformat((v or "")[:10]) if v else None
    except ValueError:
        return None


def sync_eox():
    from .engine import device_pids
    tok = _token()
    pids = sorted({pid for d in Device.objects.filter(vendor__iexact="cisco") for _w, pid in device_pids(d)})
    n = 0
    for i in range(0, len(pids), 20):
        chunk = ",".join(pids[i:i + 20])
        r = requests.get(f"{API}/supporttools/eox/rest/5/EOXByProductID/1/{chunk}", params={"responseencoding": "json"},
                         headers={"Authorization": f"Bearer {tok}"}, timeout=60)
        r.raise_for_status()
        for rec in r.json().get("EOXRecord", []):
            pid = rec.get("EOLProductID") or ""
            if not pid or rec.get("EOXError"):
                continue
            HardwareLifecycle.objects.update_or_create(pid=pid, prefix=False, defaults={
                "description": (rec.get("ProductIDDescription") or "")[:200],
                "end_of_sale": _d((rec.get("EndOfSaleDate") or {}).get("value")),
                "end_of_sw_maintenance": _d((rec.get("EndOfSWMaintenanceReleases") or {}).get("value")),
                "end_of_security": _d((rec.get("EndOfSecurityVulSupportDate") or {}).get("value")),
                "last_day_of_support": _d((rec.get("LastDateOfSupport") or {}).get("value")),
                "replacement": ((rec.get("EOXMigrationDetails") or {}).get("MigrationProductId") or "")[:120],
                "url": (rec.get("LinkToProductBulletinURL") or "")[:300], "source": "cisco_api"})
            n += 1
    return f"{len(pids)} product IDs checked, {n} end-of-life records"


def sync_coverage():
    tok = _token()
    serials = sorted({d.serial for d in Device.objects.filter(vendor__iexact="cisco").exclude(serial="")})
    n = 0
    for i in range(0, len(serials), 50):
        r = requests.get(f"{API}/sn2info/v2/coverage/summary/serial_numbers/{','.join(serials[i:i + 50])}",
                         headers={"Authorization": f"Bearer {tok}"}, timeout=60)
        r.raise_for_status()
        for s in r.json().get("serial_numbers", []):
            if (s.get("is_covered") or "").upper() != "YES" or not s.get("service_contract_number"):
                continue
            c, _ = Contract.objects.get_or_create(number=s["service_contract_number"], source="cisco_api",
                                                  defaults={"vendor": "Cisco", "end": _d(s.get("covered_product_line_end_date")) or date.today(), "serials": ""})
            c.serials = "\n".join(sorted(c.serial_set() | {s["sr_no"].upper()}))
            c.end = _d(s.get("covered_product_line_end_date")) or c.end
            c.level = (s.get("service_line_descr") or c.level)[:80]
            c.save()
            n += 1
    return f"{len(serials)} serial numbers checked, {n} covered"
