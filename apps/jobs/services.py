"""Build job specs and queue them. Nothing here talks to a device; the worker or a collector does that."""
from django.conf import settings
from django.utils import timezone

from .models import Job

ACTIVE = ("queued", "running")


def ssh_base(device):
    c = device.ssh_credential
    if not c:
        return None
    return {"host": device.mgmt_ip, "port": c.port or 22, "device_type": device.driver.netmiko_type,
            "username": c.username, "password": c.password, "secret": c.enable, "timeout": settings.VMAP_SSH_TIMEOUT}


def snmp_base(device):
    c = device.snmp_credential
    return c.snmp_spec() if c else None


def _queue(device, kind, spec, user="", ref="", run_after=None, dedupe=True):
    if dedupe and Job.objects.filter(device=device, kind=kind, status__in=ACTIVE).exists():
        return None
    return Job.objects.create(kind=kind, device=device, collector=device.collector if device else None, spec=spec,
                              created_by=getattr(user, "username", user or "scheduler"), ref=ref,
                              run_after=run_after or timezone.now())


def enqueue_collect(device, user=""):
    if device.demo:
        from apps.core.demo import refresh_device
        refresh_device(device)
        return None
    drv = device.driver
    base = ssh_base(device)
    if base and drv.collect_commands():
        return _queue(device, "collect", dict(base, commands=drv.collect_commands()), user)
    snmp = snmp_base(device)
    if snmp:
        return _queue(device, "snmp_collect", {"host": device.mgmt_ip, "snmp": dict(snmp, **drv.snmp_collect_spec())}, user)
    return None


def enqueue_poll(device, user=""):
    if device.demo:
        return None
    drv = device.driver
    snmp = snmp_base(device)
    if snmp:
        return _queue(device, "snmp_poll", {"host": device.mgmt_ip, "snmp": dict(snmp, **drv.snmp_poll_spec())}, user)
    base = ssh_base(device)
    if base and drv.poll_commands():
        return _queue(device, "command", dict(base, commands=drv.poll_commands()), user, ref="poll")
    return None


def enqueue_test(device, user=""):
    spec = {"host": device.mgmt_ip, "tcp_check": True, "port": (device.ssh_credential.port if device.ssh_credential else 0) or 22, "timeout": 5}
    base = ssh_base(device)
    if base:
        cmds = device.driver.collect_commands()
        first = cmds[0]["cmd"] if cmds else "show version"
        running = next((c for c in cmds if c["key"] == "running"), None)
        tests = [{"key": "prompt", "cmd": first}]
        if running:
            tests.append({"key": "running", "cmd": running["cmd"], "timeout": running.get("timeout", 180)})
        spec.update(base, commands=tests)
    snmp = snmp_base(device)
    if snmp:
        spec["snmp"] = dict(snmp, get={"sysName": "1.3.6.1.2.1.1.5.0", "sysDescr": "1.3.6.1.2.1.1.1.0"})
    return _queue(device, "test", spec, user, dedupe=False)


SAFE_PREFIXES = ("show ", "dir", "verify ", "display ", "get ")


def enqueue_commands(device, commands, user=""):
    """Operator-run read-only commands. Anything that is not a show/display/dir command is refused."""
    base = ssh_base(device)
    if not base:
        raise ValueError("This device has no SSH credential.")
    cmds = [c.strip() for c in commands if c.strip()]
    bad = [c for c in cmds if not c.lower().startswith(SAFE_PREFIXES)]
    if bad:
        raise ValueError(f"Only read-only commands are allowed here (show, display, dir, verify): {bad[0]}")
    return _queue(device, "command", dict(base, commands=[{"key": f"c{i}", "cmd": c, "timeout": 120} for i, c in enumerate(cmds)]),
                  user, dedupe=False)


def enqueue_upgrade_stage(target, stage, run_after=None):
    device, image, plan = target.device, target.plan.image, target.plan
    ctx = dict(target.context or {}, allow_reload=plan.allow_reload)
    commands, steps = device.driver.upgrade_steps(stage, device, image, ctx)
    base = ssh_base(device)
    if plan.dry_run or device.demo:
        spec = {"dry_run": True, "commands": commands, "steps": steps, "host": device.mgmt_ip}
    else:
        spec = dict(base or {}, commands=commands, steps=steps)
    return _queue(device, "upgrade", spec, plan.created_by, ref=f"upgrade:{target.pk}:{stage}", run_after=run_after, dedupe=False)


def enqueue_macscan(device, user=""):
    if device.demo:
        return None
    base = ssh_base(device)
    cmds = device.driver.mac_commands()
    if base and cmds:
        return _queue(device, "macscan", dict(base, commands=cmds), user)
    return None
