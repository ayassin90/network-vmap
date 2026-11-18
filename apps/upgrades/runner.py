"""Moves upgrade targets through their stages. One job per stage; the result decides the next stage.

precheck  -> read version and free space; skip if already on the target version
transfer  -> copy the image (skipped if the file is already there)
verify    -> MD5 check against the image record
activate  -> boot variable / install add activate (reload only if the plan allows it)
postcheck -> after the reload, read the version again (retries while the switch boots)"""
import re
from datetime import timedelta

from django.utils import timezone

from apps.jobs.services import enqueue_upgrade_stage

from .models import UpgradePlan, UpgradeTarget

POSTCHECK_DELAY = timedelta(minutes=8)
POSTCHECK_RETRY = timedelta(minutes=3)
POSTCHECK_MAX = 10


def tick():
    now = timezone.now()
    for plan in UpgradePlan.objects.filter(status="approved", scheduled_for__lte=now) | UpgradePlan.objects.filter(status="approved", scheduled_for=None):
        plan.status = "running"
        plan.save(update_fields=["status"])
    for plan in UpgradePlan.objects.filter(status="running"):
        targets = plan.targets.select_related("device")
        failed = targets.filter(status="failed").count()
        if plan.stop_on_failures and failed >= plan.stop_on_failures:
            plan.status = "paused"
            plan.save(update_fields=["status"])
            continue
        active = targets.filter(status__in=("running", "waiting")).count()
        from apps.alerts.models import windows_for
        for t in targets.filter(status="pending")[: max(0, plan.max_parallel - active)]:
            fz = windows_for(t.device, freeze=True)
            if fz and not plan.dry_run:
                continue                    # wait until the change freeze ends
            start(t)
        if not targets.filter(status__in=("pending", "running", "waiting")).exists():
            plan.status = "failed" if targets.filter(status="failed").exists() else "done"
            plan.finished_at = now
            plan.save(update_fields=["status", "finished_at"])


def start(t):
    t.status, t.stage, t.started_at = "running", "precheck", timezone.now()
    t.from_version = t.device.os_version
    t.note(f"start: {t.device.hostname} {t.device.os_version} -> {t.plan.image.version}" + (" (dry run)" if t.plan.dry_run else ""))
    t.save()
    enqueue_upgrade_stage(t, "precheck")


def go(t, stage, delay=None, note=""):
    if note:
        t.note(note)
    t.stage = stage
    t.status = "waiting" if delay else "running"
    t.save()
    enqueue_upgrade_stage(t, stage, run_after=timezone.now() + delay if delay else None)


def done(t, status, note):
    t.status, t.finished_at = status, timezone.now()
    t.note(note)
    t.save()


def on_job_finished(job):
    m = re.match(r"upgrade:(\d+):(\w+)", job.ref or "")
    if not m:
        return
    t = UpgradeTarget.objects.select_related("plan", "plan__image", "device").filter(pk=int(m.group(1))).first()
    if not t or t.status not in ("running", "waiting"):
        return
    stage, plan, img = m.group(2), t.plan, t.plan.image
    res = job.result or {}
    dry = bool(res.get("dry_run"))
    for st in res.get("steps") or []:
        t.note(f"[{stage}] {'ok ' if st.get('ok') else 'FAIL'} {st.get('cmd')}")
    if res.get("error") and not (stage == "postcheck"):
        return done(t, "failed", f"[{stage}] error: {res['error']}")
    if any(not s.get("ok") for s in res.get("steps") or []):
        bad = next(s for s in res["steps"] if not s.get("ok"))
        return done(t, "failed", f"[{stage}] step failed: {bad.get('cmd')}\n{(bad.get('output') or '')[-1500:]}")
    out = res.get("outputs") or {}

    if stage == "precheck":
        if dry:
            t.context = {"install_mode": t.device.facts.get("install_mode", "bundle"), "filesystem": t.device.driver.flash}
            return go(t, "transfer", note="[precheck] dry run: assuming enough space")
        ver = out.get("version", "")
        if img.version and img.version in ver:
            return done(t, "skipped", f"[precheck] already running {img.version}")
        dirout = out.get("dir", "")
        drv = t.device.driver
        if hasattr(drv, "precheck"):
            free_b, has_file = drv.precheck(out, img)
            fs = None
        else:
            free = re.search(r"\((\d+) bytes free\)|(\d+) bytes free", dirout)
            free_b = int(free.group(1) or free.group(2)) if free else None
            has_file = img.filename in dirout
            fs = re.search(r"Directory of (\S+?):", dirout)
        ctx = {"install_mode": "install" if re.search(r"\bINSTALL\b", ver) else "bundle",
               "filesystem": f"{fs.group(1)}:" if fs else drv.flash, "has_file": has_file}
        t.context = ctx
        if not ctx["has_file"] and img.size_bytes and free_b is not None and free_b < img.size_bytes * 1.05:
            return done(t, "failed", f"[precheck] not enough space: {free_b:,} bytes free, image is {img.size_bytes:,}")
        t.note(f"[precheck] mode {ctx['install_mode']}, filesystem {ctx['filesystem']}, free {free_b if free_b is not None else '?'} bytes")
        if ctx["has_file"]:
            return go(t, "verify", note="[transfer] image already on flash, skipping copy")
        return go(t, "transfer")
    if stage == "transfer":
        return go(t, "verify", note="[transfer] copy finished")
    if stage == "verify":
        if not dry and hasattr(t.device.driver, "verify_ok"):
            ok, why = t.device.driver.verify_ok(out, img)
            if not ok:
                return done(t, "failed", f"[verify] {why}")
            t.note(f"[verify] {why}")
        if not dry and img.md5 and t.device.driver.md5_verify:
            got = re.search(r"=\s*([0-9a-fA-F]{32})", out.get("md5", ""))
            if not got or got.group(1).lower() != img.md5.lower():
                return done(t, "failed", f"[verify] MD5 mismatch: expected {img.md5}, got {got.group(1) if got else 'nothing'}")
            t.note("[verify] MD5 matches")
        if plan.mode == "stage":
            return done(t, "done", "staged: image copied and verified; activate in a later plan")
        return go(t, "activate")
    if stage == "activate":
        if not plan.allow_reload:
            return done(t, "done", "activated without reload: the new version runs after the next reload")
        if dry:
            return go(t, "postcheck", note="[activate] dry run: reload would happen here")
        from apps.core.models import AppSetting
        delay = timedelta(seconds=AppSetting.get_int("upgrade_postcheck_delay_seconds", int(POSTCHECK_DELAY.total_seconds())))
        return go(t, "postcheck", delay=delay, note="[activate] reload started; waiting for the switch to come back")
    if stage == "postcheck":
        ver = out.get("version", "")
        if dry:
            return done(t, "done", "dry run complete: no command was sent")
        if res.get("error") or not ver:
            t.postcheck_tries += 1
            if t.postcheck_tries >= POSTCHECK_MAX:
                return done(t, "failed", f"[postcheck] device not back after {POSTCHECK_MAX} tries: {res.get('error', '')}")
            from apps.core.models import AppSetting
            retry = timedelta(seconds=AppSetting.get_int("upgrade_postcheck_retry_seconds", int(POSTCHECK_RETRY.total_seconds())))
            return go(t, "postcheck", delay=retry, note=f"[postcheck] not reachable yet (try {t.postcheck_tries})")
        if img.version in ver:
            t.to_version = img.version
            from apps.jobs.services import enqueue_collect
            enqueue_collect(t.device)
            return done(t, "done", f"[postcheck] running {img.version}")
        return done(t, "failed", f"[postcheck] device is back but not on {img.version}")
