"""Alert rules evaluated after every collection or poll. An alert is raised once per condition (dedupe key),
counted while it persists, and resolved automatically when the condition clears."""
import json
import logging
import threading
from datetime import timedelta

import requests
from django.core.mail import send_mail
from django.utils import timezone

from apps.checks.models import SEV_RANK, Finding

from .models import Alert, AlertRule, NotificationChannel

log = logging.getLogger("vmap.alerts")

DEFAULT_RULES = [
    ("device_down", "Device unreachable or login failing", "high",
     "Raised when a device cannot be reached or rejects the login during collection or polling.", {}),
    ("security_finding", "Security finding", "high",
     "Raised for each open security or best-practice finding at or above the minimum severity.", {"min_severity": "high"}),
    ("interface_finding", "Interface problem", "high",
     "Raised for interface health findings (half duplex, CRC, mismatches, err-disabled, utilisation) at or above the minimum severity.",
     {"min_severity": "high"}),
    ("psirt", "Vulnerable software (PSIRT)", "critical",
     "Raised when a device matches a vendor security advisory at or above the minimum severity.", {"min_severity": "high"}),
    ("compliance", "Below config standard target", "medium",
     "Raised when a device's config-standard score falls below the target.", {"target": 80}),
    ("config_change", "Configuration changed", "info",
     "Raised when a new configuration version is saved. Acknowledge it once the change is reviewed.", {}),
    ("lifecycle", "Lifecycle risk", "medium",
     "Raised for end-of-support hardware, software below your minimum, and expired or missing contracts.", {"min_severity": "medium"}),
    ("endpoint", "Endpoint appeared or moved", "info",
     "Raised when a new MAC address shows up on an access port, or a known one moves to another port. Off by default: busy networks see many.", {}),
]


def ensure_rules():
    for key, name, sev, desc, params in DEFAULT_RULES:
        AlertRule.objects.get_or_create(key=key, defaults={"name": name, "severity": sev, "description": desc, "params": params,
                                                           "enabled": key != "endpoint", "notify": key != "endpoint"})


def _min(rule, default="high"):
    return SEV_RANK.get((rule.params or {}).get("min_severity", default), 3)


def evaluate_device(device):
    rules = {r.key: r for r in AlertRule.objects.filter(enabled=True)}
    want = {}

    def raise_(rule_key, key, severity, title, detail, link="", auto=True):
        if rule_key in rules:
            want[f"{rule_key}:{device.pk}:{key}"] = (rules[rule_key], severity, title, detail, link, auto)

    if device.status in ("down", "auth_failed"):
        raise_("device_down", "", rules["device_down"].severity if "device_down" in rules else "high",
               f"{device.hostname} is {device.get_status_display().lower()}", device.last_error[:500], f"/devices/{device.pk}/")
    for f in Finding.objects.filter(device=device, status="open").exclude(category="compliance"):
        rk = {"interface": "interface_finding", "stp": "interface_finding", "vlan": "interface_finding", "health": "interface_finding",
              "lifecycle": "lifecycle"}.get(f.category, "security_finding")
        if rk in rules and SEV_RANK[f.severity] >= _min(rules[rk]):
            raise_(rk, f"{f.check_id}:{f.key}" if f.category == "interface" else f.check_id, f.severity, f"{device.hostname}: {f.title}" + (f" on {f.key}" if f.category == "interface" else ""),
                   f.detail, f"/devices/{device.pk}/?tab=findings")
    for da in device.advisories.filter(status="open").select_related("advisory"):
        if "psirt" in rules and SEV_RANK.get(da.advisory.severity, 2) >= _min(rules["psirt"]):
            raise_("psirt", da.advisory.advisory_id, da.advisory.severity, f"{device.hostname}: {da.advisory.title[:150]}",
                   da.detail, f"/psirt/{da.advisory.pk}/")
    if "compliance" in rules and device.compliance_score is not None and device.compliance_score < (rules["compliance"].params or {}).get("target", 80):
        raise_("compliance", "", rules["compliance"].severity, f"{device.hostname} config standards at {device.compliance_score}%",
               "", f"/devices/{device.pk}/?tab=standards")
    snap = device.latest_config
    if "config_change" in rules and snap and (snap.added or snap.removed) and (timezone.now() - snap.collected_at).total_seconds() < 3600:
        raise_("config_change", f"cfg{snap.pk}", rules["config_change"].severity, f"{device.hostname} configuration changed",
               f"+{snap.added} / -{snap.removed} lines", f"/devices/{device.pk}/config/{snap.pk}/", auto=False)
    sync(device, want)


def sync(device, want):
    from apps.core.models import AppSetting

    from .models import windows_for
    now = timezone.now()
    cooldown = AppSetting.get_int("alert_cooldown_minutes", 30)
    mute = windows_for(device, now, mute=True)
    new = []
    for dedupe, (rule, sev, title, detail, link, auto) in want.items():
        a = Alert.objects.filter(dedupe=dedupe).exclude(status="resolved").first()
        if a:
            a.last_seen, a.count, a.severity, a.detail = now, a.count + 1, sev, detail
            a.save(update_fields=["last_seen", "count", "severity", "detail"])
            continue
        recent = Alert.objects.filter(dedupe=dedupe, status="resolved", resolved_at__gte=now - timedelta(minutes=cooldown)).first() if cooldown else None
        if recent:                       # came back within the cool-down: reopen instead of a new alert
            recent.status, recent.resolved_at, recent.last_seen = "open", None, now
            recent.count += 1
            recent.reopen_count += 1
            recent.flapping = recent.reopen_count >= 3
            recent.save()
            continue
        a = Alert(rule=rule, dedupe=dedupe, device=device, severity=sev, title=title[:250], detail=detail, link=link, auto_resolve=auto,
                  correlation=correlate(device, now))
        if mute:
            a.suppressed, a.suppressed_reason = True, f"Maintenance window: {mute[0].name}"
        a.save()
        if rule.notify and not a.suppressed:
            new.append(a)
    Alert.objects.filter(device=device, auto_resolve=True).exclude(status="resolved").exclude(dedupe__in=list(want)).update(
        status="resolved", resolved_at=now)
    if new:
        threading.Thread(target=notify, args=([a.pk for a in new],), daemon=True).start()


def correlate(device, now):
    """A config change or change request on this device shortly before the alert is the first thing to look at."""
    from apps.changes.models import ChangeTarget
    from apps.inventory.models import ConfigSnapshot
    since = now - timedelta(hours=2)
    ct = ChangeTarget.objects.filter(device=device, finished_at__gte=since).select_related("change").order_by("-finished_at").first()
    if ct:
        mins = int((now - ct.finished_at).total_seconds() // 60)
        return f"{ct.change.number} \"{ct.change.title[:80]}\" was applied to this device {mins} min before this alert."
    snap = ConfigSnapshot.objects.filter(device=device, collected_at__gte=since).exclude(added=0, removed=0).first()
    if snap:
        mins = int((now - snap.collected_at).total_seconds() // 60)
        return f"The configuration changed about {mins} min before this alert (+{snap.added}/-{snap.removed} lines)."
    return ""


def reconcile_topology():
    """Topology-aware suppression: when a switch is down, alerts for devices that can only be reached through it are
    marked as consequences of that switch's alert (suppressed, no notification)."""
    from collections import defaultdict, deque

    from apps.inventory.models import Device, Neighbor
    devs = {d.pk: d for d in Device.objects.filter(enabled=True)}
    adj = defaultdict(set)
    for a, b in Neighbor.objects.exclude(remote_device=None).values_list("device_id", "remote_device_id"):
        if a in devs and b in devs:
            adj[a].add(b)
            adj[b].add(a)
    down = {pk for pk, d in devs.items() if d.status in ("down", "auth_failed", "error")}
    anchors = [pk for pk, d in devs.items() if d.role in ("core", "router")] or sorted(adj, key=lambda k: -len(adj[k]))[:2]
    seen = set(a for a in anchors if a not in down)
    q = deque(seen)
    while q:
        cur = q.popleft()
        for nb in adj[cur]:
            if nb not in seen and nb not in down:
                seen.add(nb)
                q.append(nb)
    roots = {pk for pk in down if any(nb in seen for nb in adj[pk]) or pk in anchors}
    # every unreachable device (down or not-reached) hangs under the nearest root outage
    parent_of = {}
    for r in roots:
        q, visited = deque([r]), {r}
        while q:
            cur = q.popleft()
            for nb in adj[cur]:
                if nb in visited or nb in seen or nb in roots:
                    continue
                visited.add(nb)
                parent_of.setdefault(nb, r)
                q.append(nb)
    root_alert = {a.device_id: a for a in Alert.objects.filter(rule__key="device_down", device_id__in=roots).exclude(status="resolved")}
    for a in Alert.objects.filter(device_id__in=list(parent_of)).exclude(status="resolved").select_related("device"):
        ra = root_alert.get(parent_of[a.device_id])
        if ra and a.parent_id != ra.pk:
            a.parent, a.suppressed = ra, True
            a.suppressed_reason = f"Behind {devs[parent_of[a.device_id]].hostname}, which is down"
            a.save(update_fields=["parent", "suppressed", "suppressed_reason"])
    # release alerts whose root cause is gone
    for a in Alert.objects.filter(parent__isnull=False).exclude(status="resolved").select_related("parent"):
        if a.parent.status == "resolved" or a.device_id not in parent_of:
            a.parent, a.suppressed, a.suppressed_reason = None, False, ""
            a.save(update_fields=["parent", "suppressed", "suppressed_reason"])
    # maintenance windows that ended: release muted alerts
    from .models import windows_for
    for a in Alert.objects.filter(suppressed=True, parent__isnull=True, suppressed_reason__startswith="Maintenance").select_related("device"):
        if a.device and not windows_for(a.device, mute=True):
            a.suppressed, a.suppressed_reason = False, ""
            a.save(update_fields=["suppressed", "suppressed_reason"])


def endpoint_events(events):
    rule = AlertRule.objects.filter(key="endpoint", enabled=True).first()
    if not rule:
        return
    from apps.inventory.models import Device
    for e in events:
        if e.kind == "ip":
            continue
        ep = e.endpoint
        title = (f"New device {ep.mac_display} on {e.to_where}" if e.kind == "new" else f"{ep.mac_display} moved from {e.from_where} to {e.to_where}")
        Alert.objects.create(rule=rule, dedupe=f"endpoint:{ep.mac}:{e.pk}", device=ep.device if isinstance(ep.device, Device) else None,
                             severity=rule.severity, title=title[:250], detail=f"{ep.name or ep.vendor or ''} {ep.ip}".strip(),
                             link=f"/devices/endpoints/?q={ep.mac}", auto_resolve=False)


def notify(alert_ids):
    alerts = list(Alert.objects.filter(pk__in=alert_ids).select_related("device"))
    for ch in NotificationChannel.objects.filter(enabled=True):
        items = [a for a in alerts if ch.wants(a.severity)]
        if not items:
            continue
        try:
            send(ch, items)
            if ch.last_error:
                ch.last_error = ""
                ch.save(update_fields=["last_error"])
        except Exception as exc:  # noqa: BLE001
            ch.last_error = f"{timezone.now():%Y-%m-%d %H:%M} {exc}"[:1000]
            ch.save(update_fields=["last_error"])


def send(ch, items):
    from apps.core.models import AppSetting
    base = AppSetting.get("public_url", "").rstrip("/")
    lines = [f"[{a.severity.upper()}] {a.title}" + (f" - {base}{a.link}" if base and a.link else "") for a in items]
    text = "Network VMap alerts\n" + "\n".join(lines)
    if ch.kind == "email":
        send_mail(f"[VMap] {len(items)} new alert(s): {items[0].title[:80]}", text, None,
                  [x.strip() for x in ch.target.split(",") if x.strip()], fail_silently=False)
    elif ch.kind in ("slack", "teams"):
        requests.post(ch.target, json={"text": text}, timeout=8).raise_for_status()
    else:
        payload = [{"id": a.pk, "severity": a.severity, "title": a.title, "detail": a.detail, "device": a.device.hostname if a.device else None,
                    "first_seen": a.first_seen.isoformat(), "link": f"{base}{a.link}" if base else a.link} for a in items]
        requests.post(ch.target, data=json.dumps({"alerts": payload}), headers={"Content-Type": "application/json"}, timeout=8).raise_for_status()


def event_alert(device, ev, rule):
    """Syslog / trap rules: one alert per device and rule while it keeps happening (count goes up), cleared by hand."""
    from .models import AlertRule, windows_for
    ar, _ = AlertRule.objects.get_or_create(key="syslog", defaults={"name": "Syslog and trap rules", "severity": "medium",
                                                                     "description": "Raised by the event rules on the Event log page."})
    if not ar.enabled:
        return
    now = timezone.now()
    dedupe = f"event:{rule.pk}:{device.pk}"
    a = Alert.objects.filter(dedupe=dedupe).exclude(status="resolved").first()
    if a:
        a.count += 1
        a.last_seen = now
        a.detail = (ev.message[:400] + "\n" + a.detail)[:2000]
        a.save(update_fields=["count", "last_seen", "detail"])
        return
    mute = windows_for(device, now, mute=True)
    a = Alert.objects.create(rule=ar, dedupe=dedupe, device=device, severity=rule.alert_severity, title=f"{device.hostname}: {rule.name}"[:250],
                             detail=ev.message[:2000], link=f"/events/?device={device.pk}", auto_resolve=False,
                             correlation=correlate(device, now), suppressed=bool(mute),
                             suppressed_reason=f"Maintenance window: {mute[0].name}" if mute else "")
    if ar.notify and not a.suppressed:
        threading.Thread(target=notify, args=([a.pk],), daemon=True).start()
