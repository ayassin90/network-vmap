"""Turn a finished job's raw result into data: parse, store, analyse, alert."""
import logging
import traceback

from django.utils import timezone

from apps.inventory import sync
from apps.inventory.models import Device

from .models import Job

log = logging.getLogger("vmap.ingest")
MAX_OUT = 300_000


def finish(job, result):
    job.finished_at = timezone.now()
    outputs = result.get("outputs") or {}
    job.result = dict(result, outputs={k: (v if len(v) < MAX_OUT else v[:MAX_OUT] + "\n…truncated") for k, v in outputs.items()})
    job.status = "failed" if result.get("error") else "done"
    job.error = result.get("error", "")
    try:
        job.summary = handle(job, result)[:300] if job.status == "done" or job.kind in ("upgrade", "change") else ""
    except Exception as exc:  # noqa: BLE001
        log.exception("ingest failed for job %s", job.pk)
        job.status = "failed"
        job.error = f"Could not process the result: {exc}\n{traceback.format_exc()[-2000:]}"
    if job.status == "failed" and job.device_id and job.kind in ("collect", "snmp_collect", "snmp_poll", "test", "command"):
        mark_failure(job.device, result)
    job.save()
    if job.device_id and job.kind in ("collect", "snmp_collect", "snmp_poll", "command", "test"):
        from apps.alerts.engine import evaluate_device
        try:
            evaluate_device(Device.objects.get(pk=job.device_id))
        except Exception:  # noqa: BLE001
            log.exception("alert evaluation failed")
    if job.kind == "upgrade":
        from apps.upgrades.runner import on_job_finished
        on_job_finished(job)
    if job.kind == "change":
        from apps.changes.runner import on_job_finished as change_done
        change_done(job)
    return job


def mark_failure(device, result):
    kind = result.get("error_kind", "error")
    device.status = {"auth": "auth_failed", "unreachable": "down"}.get(kind, "error")
    device.last_error = (result.get("error") or "")[:2000]
    device.save(update_fields=["status", "last_error"])


def handle(job, result):
    device = job.device
    if job.kind == "collect":
        out = result.get("outputs", {})
        if not out:
            raise RuntimeError("The device returned no output. " + "; ".join(f"{k}: {v}" for k, v in (result.get("errors") or {}).items())[:500])
        data = device.driver.parse(out)
        summary = sync.apply(device, data)
        errs = result.get("errors") or {}
        if "running" in errs:
            device.last_error = (f"Connected, but the configuration could not be read ({str(errs['running'])[:160].strip()}). "
                                 "The account needs full read rights (Cisco: privilege 15, or set the enable secret on the SSH credential; "
                                 "NX-OS: network-admin or a role that allows show running-config; Junos: a class with view-configuration). "
                                 "Security checks keep using the last configuration that was read.")
            device.save(update_fields=["last_error"])
            summary = f"{summary}; configuration not read" if summary else "configuration not read"
        analyse(device)
        from apps.inventory.discovery import crawl
        crawl(device)
        return summary
    if job.kind == "snmp_collect":
        data = device.driver.parse_snmp(result.get("snmp", {}))
        summary = sync.apply(device, data)
        analyse(device)
        from apps.inventory.discovery import crawl
        crawl(device)
        return summary
    if job.kind == "snmp_poll":
        summary = sync.apply_snmp_poll(device, result.get("snmp", {}))
        from apps.checks.engine import rescore, run_health_checks, run_interface_checks
        run_interface_checks(device)
        run_health_checks(device)
        rescore(device)
        return summary
    if job.kind == "command" and job.ref == "poll":
        rows = device.driver.parse_poll(result.get("outputs", {}))
        n = sync.sync_interfaces(device, rows)
        device.last_polled = timezone.now()
        device.status = "up"
        device.save(update_fields=["last_polled", "status"])
        from apps.checks.engine import run_interface_checks
        run_interface_checks(device)
        return f"{n} interfaces polled over SSH"
    if job.kind == "macscan":
        data = device.driver.parse_extras(result.get("outputs", {}))
        sync.apply_extras(device, data)
        return f"{len(data.get('macs') or [])} MAC entries, {len(data.get('arp') or [])} ARP entries"
    if job.kind == "change":
        steps = result.get("steps") or []
        return f"{sum(1 for s in steps if s.get('ok'))}/{len(steps)} steps ok" + (", rolled back" if result.get("rolled_back") else "")
    if job.kind == "command":
        return f"{len(result.get('outputs') or {})} commands run"
    if job.kind == "test":
        parts = []
        if "tcp" in result:
            parts.append("TCP port open" if result["tcp"] else "TCP port closed")
        if result.get("outputs"):
            parts.append("SSH login OK")
            errs = result.get("errors") or {}
            if "running" in (result.get("outputs") or {}):
                parts.append("configuration readable")
            elif "running" in errs:
                parts.append(f"configuration NOT readable ({str(errs['running'])[:120].strip()}): give the account full read rights or set the enable secret")
        elif (result.get("errors") or {}).get("prompt"):
            parts.append(f"SSH login OK but the first command failed: {str(result['errors']['prompt'])[:120]}")
        if (result.get("snmp") or {}).get("get"):
            parts.append(f"SNMP OK ({result['snmp']['get'].get('sysName')})")
        if result.get("outputs") or (result.get("snmp") or {}).get("get"):
            device.status = "up"
            device.last_error = ""
            device.save(update_fields=["status", "last_error"])
        return ", ".join(parts) or "No answer"
    if job.kind == "upgrade":
        return "dry run" if job.spec.get("dry_run") else f"{len(result.get('steps') or [])} steps"
    return ""


def analyse(device):
    from apps.checks.engine import run_all
    from apps.psirt.matcher import match_device
    run_all(device)
    match_device(device)


def run_local(job):
    """Execute a claimed job in this process (worker) and ingest it."""
    from collector.executor import execute
    if job.spec.get("dry_run"):
        result = dry_run(job.spec)
    else:
        result = execute(job.spec)
    return finish(Job.objects.get(pk=job.pk), result)


def dry_run(spec):
    lines = [c["cmd"] for c in spec.get("commands", [])] + [s.get("label") or s["cmd"] for s in spec.get("steps", [])]
    return {"outputs": {}, "steps": [{"cmd": l, "output": "(dry run: not sent)", "ok": True} for l in lines], "dry_run": True}
