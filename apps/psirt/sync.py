"""Cisco PSIRT openVuln API: advisories for each (OS type, version) in the inventory.
Register an app at https://apiconsole.cisco.com (openVuln API, client credentials) and paste the ID and secret in Settings."""
import logging
from datetime import date

import requests
from django.utils import timezone

from apps.core.models import AppSetting
from apps.inventory.models import Device

from .matcher import _hit
from .models import Advisory, DeviceAdvisory

log = logging.getLogger("vmap.psirt")
TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API = "https://apix.cisco.com/security/advisories/v2"
OS_TYPES = {"ios": "ios", "iosxe": "iosxe", "nxos": "nxos"}


def _token(cid, secret):
    r = requests.post(TOKEN_URL, data={"grant_type": "client_credentials", "client_id": cid, "client_secret": secret}, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]


def sync_openvuln():
    cid, secret = AppSetting.get("openvuln_client_id"), AppSetting.get("openvuln_client_secret")
    if not cid or not secret:
        raise RuntimeError("Cisco openVuln API credentials are not set (Settings).")
    tok = _token(cid, secret)
    pairs = set(Device.objects.exclude(os_version="").exclude(os_type="").values_list("os_type", "os_version"))
    total = 0
    for os_type, version in pairs:
        ot = OS_TYPES.get(os_type)
        if not ot:
            continue
        r = requests.get(f"{API}/OSType/{ot}", params={"version": version}, headers={"Authorization": f"Bearer {tok}", "Accept": "application/json"}, timeout=60)
        if r.status_code == 404:
            continue
        r.raise_for_status()
        advs = r.json().get("advisories", []) or []
        ids = []
        for a in advs:
            adv, _ = Advisory.objects.update_or_create(advisory_id=a.get("advisoryId"), defaults={
                "title": (a.get("advisoryTitle") or "")[:300], "severity": (a.get("sir") or "medium").lower(),
                "cvss": _f(a.get("cvssBaseScore")), "cves": ",".join(a.get("cves") or [])[:500],
                "url": (a.get("publicationUrl") or "")[:400], "published": _d(a.get("firstPublished")),
                "summary": _strip(a.get("summary") or "")[:5000], "fixed_in": ",".join(a.get("firstFixed") or [])[:400],
                "os_types": ot, "source": "openvuln"})
            ids.append(adv.pk)
        for dev in Device.objects.filter(os_type=os_type, os_version=version):
            keep = [_hit(dev, Advisory.objects.get(pk=i), "version", f"{version} listed as affected by Cisco") for i in ids]
            DeviceAdvisory.objects.filter(device=dev, match="version", status="open").exclude(pk__in=keep).update(status="resolved")
        total += len(advs)
    AppSetting.put("openvuln_last_sync", timezone.now().isoformat())
    return f"{len(pairs)} software versions checked, {total} advisory matches"


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _d(v):
    try:
        return date.fromisoformat((v or "")[:10])
    except ValueError:
        return None


def _strip(html):
    import re
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()
