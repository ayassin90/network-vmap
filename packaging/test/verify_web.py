"""Run against an installed VMap (inside the app image, --network host): health, sign-in, ~60 pages, the version.
    python - BASE USER PASSWORD VERSION [HOST_HEADER]"""
import re
import sys

import requests
import urllib3

urllib3.disable_warnings()
base, user, pw, version = sys.argv[1:5]
host = sys.argv[5] if len(sys.argv) > 5 else ""
s = requests.Session()
s.verify = False
if host:
    s.headers["Host"] = host
origin = f"{base.split('://')[0]}://{host}" if host else base
assert s.get(base + "/healthz", timeout=20).text == "ok", "healthz"
r = s.get(base + "/accounts/login/", timeout=20)
assert r.status_code == 200, f"login page {r.status_code}"
tok = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', r.text).group(1)
r = s.post(base + "/accounts/login/", data={"username": user, "password": pw, "csrfmiddlewaretoken": tok},
           headers={"Referer": origin + "/accounts/login/", "Origin": origin}, timeout=30)
assert r.status_code == 200 and "/accounts/login" not in r.url, f"sign-in failed: {r.status_code} {r.url}"
assert f"Network VMap {version}" in r.text, "version not shown in the page"
pages = ['/', '/settings/', '/search/?q=acc', '/devices/', '/devices/add/', '/devices/add-many/', '/devices/interfaces/',
         '/devices/interfaces/?f=errors', '/devices/routes/', '/devices/discovery/', '/devices/setup/', '/devices/platforms/',
         '/devices/platforms/cisco_iosxe/', '/devices/platforms/aruba_aoscx/', '/devices/platforms/huawei_vrp/', '/checks/findings/',
         '/checks/standards/', '/checks/standards/new/', '/psirt/', '/upgrades/', '/upgrades/images/', '/upgrades/new/', '/alerts/',
         '/alerts/rules/', '/alerts/cases/', '/alerts/cases/new/', '/jobs/', '/jobs/collectors/', '/help/', '/accounts/users/',
         '/devices/endpoints/', '/devices/spanning-tree/', '/devices/vlans/', '/lifecycle/', '/lifecycle/?tab=contracts', '/changes/',
         '/changes/new/', '/changes/templates/', '/alerts/maintenance/', '/events/', '/events/rules/', '/topology/path/',
         '/reports/capacity/', '/reports/summary/', '/snapshots/', '/traffic/', '/reports/audit/', '/integrations/netbox/',
         '/devices/?export=csv', '/checks/findings/?export=csv', '/topology/l2/', '/topology/l3/']
bad = []
for p in pages:
    r = s.get(base + p, timeout=60, allow_redirects=False)
    if r.status_code != 200:
        bad.append(f"{p} {r.status_code}")
static = re.findall(r'(?:href|src)="(/static/[^"]+)"', s.get(base + "/", timeout=20).text)
for p in static[:20]:
    if s.get(base + p, timeout=20).status_code != 200:
        bad.append(f"{p} (static)")
print(f"web ok: signed in, version {version}, {len(pages) - len([b for b in bad if 'static' not in b])}/{len(pages)} pages, "
      f"{len(static[:20])} static files" + (f"; FAILED: {bad}" if bad else ""))
sys.exit(1 if bad else 0)
