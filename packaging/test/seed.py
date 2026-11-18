# Fed to `manage.py shell` in an installed VMap. ACTION=device: add the mock switch at MOCK_IP (optionally through the
# collector COLLECTOR) and collect it; ACTION=collector: create a collector, print its token; ACTION=state: summary.
import os
import time

from apps.inventory.models import Credential, Device, Site
from apps.jobs.models import Collector, Job

act = os.environ["ACTION"]
if act == "collector":
    c, _ = Collector.objects.get_or_create(name=os.environ.get("NAME", "branch-1"))
    tok = c.new_token()
    c.save()
    print("TOKEN=" + tok)
elif act == "device":
    from apps.jobs.services import enqueue_collect, enqueue_test
    site, _ = Site.objects.get_or_create(name="Install test")
    ssh, _ = Credential.objects.get_or_create(name="t-ssh", defaults={"kind": "ssh", "username": "vmap"})
    ssh.password = "vmap-lab"
    ssh.save()
    snmp, _ = Credential.objects.get_or_create(name="t-snmp", defaults={"kind": "snmp2"})
    snmp.community = "vmap-lab"
    snmp.save()
    col = Collector.objects.get(name=os.environ["COLLECTOR"]) if os.environ.get("COLLECTOR") else None
    d, _ = Device.objects.update_or_create(mgmt_ip=os.environ["MOCK_IP"], defaults=dict(
        hostname="pending", platform=os.environ.get("PLATFORM", "cisco_iosxe"), site=site, ssh_credential=ssh, snmp_credential=snmp, collector=col))
    t0 = time.time()
    for fn in (enqueue_test, enqueue_collect):
        fn(d)
    while time.time() - t0 < 240:
        if not Job.objects.filter(device=d, status__in=("queued", "running")).exists():
            break
        time.sleep(3)
    d.refresh_from_db()
    jobs = list(Job.objects.filter(device=d).order_by("pk").values_list("kind", "status", "summary"))
    ok = d.hostname != "pending" and d.model and all(j[1] == "done" for j in jobs)
    print(f"{'COLLECT_OK' if ok else 'COLLECT_FAIL'} via {'collector ' + col.name if col else 'server'} in {time.time() - t0:.0f}s: "
          f"{d.hostname} {d.model} {d.os_version} ifs={d.interfaces.count()} findings={d.findings.count()} jobs={[(k, s, (m or '')[:90]) for k, s, m in jobs]}")
elif act == "state":
    from apps.accounts.models import User
    c = Collector.objects.first()
    print(f"STATE devices={Device.objects.count()} users={User.objects.count()} collector_seen={bool(c and c.last_seen)} collector_ip={c.last_ip if c else ''}")
