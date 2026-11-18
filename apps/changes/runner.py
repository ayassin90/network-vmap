"""Run approved change requests: per device, save a rollback point, apply, optionally save; roll back automatically on error."""
import re

from django.utils import timezone

from apps.alerts.models import windows_for
from apps.jobs.models import Job
from apps.jobs.services import ssh_base

from .models import ChangeRequest, ChangeTarget


def frozen(device):
    return windows_for(device, freeze=True)


def tick():
    now = timezone.now()
    for ch in ChangeRequest.objects.filter(status="approved"):
        if not ch.scheduled_for or ch.scheduled_for <= now:
            ch.status = "running"
            ch.save(update_fields=["status"])
    for ch in ChangeRequest.objects.filter(status="running"):
        advance(ch)


def advance(ch):
    targets = ch.targets.select_related("device")
    active = targets.filter(status="running").count()
    for t in targets.filter(status="pending")[: max(0, ch.max_parallel - active)]:
        start(t)
    if not targets.filter(status__in=("pending", "running")).exists():
        ch.status = "failed" if targets.filter(status__in=("failed", "rolled_back")).exists() else "done"
        ch.finished_at = timezone.now()
        ch.save(update_fields=["status", "finished_at"])


def start(t):
    ch, d = t.change, t.device
    t.started_at = timezone.now()
    t.pre_snapshot = d.latest_config
    if frozen(d) and not ch.emergency:
        t.status = "skipped"
        t.note(f"skipped: change freeze '{frozen(d)[0].name}' is active")
        t.save()
        return
    if d.demo:
        t.status, t.finished_at = "done", timezone.now()
        t.note("demo device: nothing sent. Lines that would be applied:\n" + t.config)
        t.save()
        _demo_apply(t)
        return
    drv = d.driver
    base = ssh_base(d)
    if not base:
        t.status = "failed"
        t.note("no SSH credential")
        t.save()
        return
    t.backup_name = f"vmap-pre-{ch.pk}-{d.pk}.cfg"
    steps = []
    if ch.kind != "rollback":
        steps += drv.backup_steps(t.backup_name)
    steps.append({"label": "apply configuration", "cmd": t.config.strip(), "mode": "config", "fail_on": drv.config_fail, "timeout": 300})
    if t.config_after:
        steps += [{"label": "wait 5 seconds", "sleep": 5},
                  {"label": "apply second phase", "cmd": t.config_after.strip(), "mode": "config", "fail_on": drv.config_fail, "timeout": 300}]
    if ch.save_config:
        steps += drv.save_steps()
    spec = dict(base, steps=steps)
    if ch.rollback_on_failure and ch.kind != "rollback":
        spec["on_fail"] = drv.rollback_steps(t.backup_name)
    if not drv.backup_steps(t.backup_name):
        t.backup_name = ""
        t.note("this platform has no live configuration rollback: applying without a rollback point")
    t.status = "running"
    t.note(f"started by {ch.approved_by or ch.created_by}")
    t.save()
    Job.objects.create(kind="change", device=d, collector=d.collector, spec=spec, created_by=ch.created_by, ref=f"change:{t.pk}")


def on_job_finished(job):
    m = re.match(r"change:(\d+)", job.ref or "")
    if not m:
        return
    t = ChangeTarget.objects.select_related("change", "device").filter(pk=int(m.group(1))).first()
    if not t:
        return
    res = job.result or {}
    for st in res.get("steps") or []:
        t.note(f"{'ok  ' if st.get('ok') else 'FAIL'} {st.get('cmd')}")
        if not st.get("ok"):
            t.note((st.get("output") or "")[-1500:])
    failed = bool(res.get("error")) or any(not s.get("ok") for s in res.get("steps") or [])
    if res.get("error"):
        t.note(f"error: {res['error']}")
    if failed and res.get("rolled_back"):
        t.status = "rolled_back"
        t.note("rolled back to the saved configuration")
    else:
        t.status = "failed" if failed else "done"
    t.finished_at = timezone.now()
    t.save()
    from apps.jobs.services import enqueue_collect
    enqueue_collect(t.device, "change")          # refresh state, findings and the config history
    advance(t.change)


def _demo_apply(t):
    """Demo devices: reflect simple port changes in the stored data so the UI shows the effect."""
    from apps.inventory.models import Interface
    cur = None
    for line in (t.config + "\n" + t.config_after).splitlines():
        s = line.strip()
        if s.startswith("interface "):
            cur = Interface.objects.filter(device=t.device, name__iexact=s[10:]).first()
        elif cur:
            if s == "shutdown":
                cur.admin_up, cur.oper_up, cur.status = False, False, "disabled"
            elif s == "no shutdown":
                cur.admin_up, cur.status = True, "connected" if cur.speed else "notconnect"
                cur.oper_up = cur.status == "connected"
            elif s.startswith("switchport access vlan ") or s.startswith("vlan access "):
                cur.access_vlan, cur.mode = s.split()[-1], "access"
            elif s.startswith("description "):
                cur.description = s[12:]
            elif s in ("power inline never", "no power-over-ethernet"):
                cur.poe_admin, cur.poe_oper, cur.poe_watts = "off", "off", 0
            elif s in ("power inline auto", "power-over-ethernet"):
                cur.poe_admin = "auto"
            cur.save()
