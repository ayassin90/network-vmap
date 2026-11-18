"""Periodic work, run by the worker every 30 seconds: scheduled collections and polls, stuck jobs, upgrade plans,
discovery runs, data retention."""
import logging
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from apps.core.models import AppSetting
from apps.inventory.models import Device, DiscoveryRun, InterfaceSample

from .models import Job
from .services import enqueue_collect, enqueue_poll

log = logging.getLogger("vmap.scheduler")
_last = {}


def every(name, seconds):
    now = timezone.now()
    if name not in _last or (now - _last[name]).total_seconds() >= seconds:
        _last[name] = now
        return True
    return False


def tick():
    now = timezone.now()
    collect_min = AppSetting.get_int("collect_interval_minutes", 360)
    poll_min = AppSetting.get_int("poll_interval_minutes", 5)
    live = Device.objects.filter(enabled=True, demo=False)
    if collect_min > 0:
        for d in live.filter(Q(last_collected__lt=now - timedelta(minutes=collect_min)) | Q(last_collected=None)):
            if not Job.objects.filter(device=d, kind__in=("collect", "snmp_collect"), created_at__gt=now - timedelta(minutes=min(collect_min, 60))).exists():
                enqueue_collect(d)
    if poll_min > 0:
        for d in live.filter(Q(last_polled__lt=now - timedelta(minutes=poll_min)) | Q(last_polled=None)).exclude(last_collected=None):
            if d.status in ("up", "unknown") and not Job.objects.filter(device=d, kind__in=("snmp_poll", "command"), created_at__gt=now - timedelta(minutes=poll_min)).exists():
                enqueue_poll(d)
    mac_min = AppSetting.get_int("mac_scan_interval_minutes", 30)
    if mac_min > 0 and every("macscan", 60):
        from .services import enqueue_macscan
        for d in live.exclude(last_collected=None).exclude(status__in=("down", "auth_failed")):
            if not Job.objects.filter(device=d, kind__in=("macscan", "collect"), created_at__gt=now - timedelta(minutes=mac_min)).exists():
                enqueue_macscan(d)
    # stuck jobs: local ones running > 2h, collector ones never picked up for a day
    Job.objects.filter(status="running", started_at__lt=now - timedelta(hours=2)).update(
        status="failed", error="No result after 2 hours; the worker or collector probably restarted.", finished_at=now)
    Job.objects.filter(status="queued", collector__isnull=False, created_at__lt=now - timedelta(days=1)).update(
        status="cancelled", error="The collector did not pick this job up within a day.", finished_at=now)
    for run in DiscoveryRun.objects.filter(status="running"):
        busy = Job.objects.filter(device__discovery=run, status__in=("queued", "running")).exists()
        if not busy and (now - run.created_at).total_seconds() > 60:
            run.status = "done"
            run.save(update_fields=["status"])
            run.note(f"finished: {run.devices.count()} devices")
    from apps.upgrades.runner import tick as upgrade_tick
    upgrade_tick()
    from apps.changes.runner import tick as change_tick
    change_tick()
    from apps.alerts.engine import reconcile_topology
    reconcile_topology()
    if every("retention", 3600):
        days = AppSetting.get_int("sample_retention_days", 14)
        InterfaceSample.objects.filter(ts__lt=now - timedelta(days=days)).delete()
        from apps.events.models import Event
        from apps.inventory.models import DeviceSample
        DeviceSample.objects.filter(ts__lt=now - timedelta(days=days)).delete()
        Event.objects.filter(ts__lt=now - timedelta(days=AppSetting.get_int("event_retention_days", 14))).delete()
        from apps.flows.models import FlowStat
        FlowStat.objects.filter(ts__lt=now - timedelta(days=AppSetting.get_int("flow_retention_days", 7))).delete()
        Job.objects.filter(finished_at__lt=now - timedelta(days=AppSetting.get_int("job_retention_days", 30))).delete()
        # routine poll / MAC-scan jobs carry bulky raw output and are only useful briefly
        Job.objects.filter(Q(kind__in=("snmp_poll", "macscan")) | Q(kind="command", ref="poll"), status="done",
                           finished_at__lt=now - timedelta(days=2)).delete()
        from apps.flows.store import rollup
        try:
            rollup(24)
        except Exception as exc:  # noqa: BLE001
            log.warning("flow roll-up skipped: %s", exc)
    if every("snapshot", 900):
        from apps.snapshots.engine import maybe_take
        try:
            maybe_take()
        except Exception as exc:  # noqa: BLE001
            log.warning("snapshot skipped: %s", exc)
    nb_hours = AppSetting.get_int("netbox_sync_interval_hours", 0)
    if nb_hours > 0 and every("netbox", nb_hours * 3600) and AppSetting.get("netbox_url"):
        from apps.integrations.netbox import run as netbox_run
        try:
            netbox_run("push", user="schedule")
        except Exception as exc:  # noqa: BLE001
            log.warning("NetBox sync skipped: %s", exc)
    if every("report", 600):
        from apps.reports.data import maybe_send
        try:
            maybe_send()
        except Exception as exc:  # noqa: BLE001
            log.warning("weekly report not sent: %s", exc)
    if every("lifecycle", 86400):
        from apps.lifecycle.cisco_api import sync_coverage, sync_eox
        for fn in (sync_eox, sync_coverage):
            try:
                log.info(fn())
            except Exception as exc:  # noqa: BLE001
                log.warning("%s skipped: %s", fn.__name__, exc)
    if every("psirt", 86400):
        from apps.psirt.sync import sync_openvuln
        try:
            sync_openvuln()
        except Exception as exc:  # noqa: BLE001
            log.warning("PSIRT sync skipped: %s", exc)
