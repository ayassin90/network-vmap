"""Open a ticket in Jira, ServiceNow or any webhook when a case is created, and note resolution. Configured in Settings."""
import logging
import threading

import requests

from apps.core.models import AppSetting

log = logging.getLogger("vmap.tickets")
PRIO_RANK = {"p1": 1, "p2": 2, "p3": 3, "p4": 4}
SEV_TO_PRIO = {"critical": 1, "high": 2, "medium": 3, "low": 4}


def enabled():
    return (AppSetting.get("ticket_system", "") or "").strip().lower() in ("jira", "servicenow", "webhook")


def _case_url(case):
    base = (AppSetting.get("public_url", "") or "").rstrip("/")
    return f"{base}/alerts/cases/{case.pk}/" if base else f"/alerts/cases/{case.pk}/"


def _body(case):
    devs = ", ".join(d.hostname for d in case.devices.all()[:20])
    return f"{case.description or case.title}\n\nDevices: {devs or '-'}\nPriority: {case.get_priority_display()}\nNetwork VMap case {case.number}: {_case_url(case)}"


def open_ticket(case, force=False):
    """Create the external ticket. Returns (ref, url) or raises."""
    system = (AppSetting.get("ticket_system", "") or "").strip().lower()
    if not system:
        raise ValueError("No ticketing system is configured (Settings → Ticketing).")
    if not force and PRIO_RANK.get(case.priority, 3) > SEV_TO_PRIO.get((AppSetting.get("ticket_min_severity", "high") or "high").lower(), 2):
        return None, None
    url, user, token, proj = (AppSetting.get("ticket_url", "") or "").rstrip("/"), AppSetting.get("ticket_user", ""), AppSetting.get("ticket_token", ""), AppSetting.get("ticket_project", "")
    summary = f"[VMap {case.number}] {case.title}"[:250]
    if system == "jira":
        prio = {"p1": "Highest", "p2": "High", "p3": "Medium", "p4": "Low"}.get(case.priority, "Medium")
        r = requests.post(f"{url}/rest/api/2/issue", auth=(user, token), timeout=15, json={"fields": {
            "project": {"key": proj}, "summary": summary, "description": _body(case), "issuetype": {"name": "Task"}, "priority": {"name": prio},
            "labels": ["network-vmap"]}})
        if r.status_code >= 400:
            raise RuntimeError(f"Jira said HTTP {r.status_code}: {r.text[:300]}")
        key = r.json()["key"]
        return key, f"{url}/browse/{key}"
    if system == "servicenow":
        r = requests.post(f"{url}/api/now/table/incident", auth=(user, token), timeout=15, headers={"Accept": "application/json"}, json={
            "short_description": summary, "description": _body(case), "urgency": {"p1": "1", "p2": "2"}.get(case.priority, "3"),
            "impact": {"p1": "1", "p2": "2"}.get(case.priority, "3"), "assignment_group": proj, "category": "network"})
        if r.status_code >= 400:
            raise RuntimeError(f"ServiceNow said HTTP {r.status_code}: {r.text[:300]}")
        res = r.json()["result"]
        return res.get("number"), f"{url}/nav_to.do?uri=incident.do?sys_id={res.get('sys_id')}"
    r = requests.post(url, timeout=15, headers={"Authorization": f"Bearer {token}"} if token else {}, json={
        "event": "case.created", "case": case.number, "title": case.title, "priority": case.priority, "description": _body(case),
        "devices": [d.hostname for d in case.devices.all()], "url": _case_url(case)})
    if r.status_code >= 400:
        raise RuntimeError(f"webhook said HTTP {r.status_code}: {r.text[:300]}")
    try:
        data = r.json()
    except ValueError:
        data = {}
    return str(data.get("id") or data.get("number") or "sent"), data.get("url", "")


def comment(case, text):
    system = (AppSetting.get("ticket_system", "") or "").strip().lower()
    if not case.ticket_ref or not system:
        return
    url, user, token = (AppSetting.get("ticket_url", "") or "").rstrip("/"), AppSetting.get("ticket_user", ""), AppSetting.get("ticket_token", "")
    if system == "jira":
        requests.post(f"{url}/rest/api/2/issue/{case.ticket_ref}/comment", auth=(user, token), timeout=15, json={"body": text})
    elif system == "servicenow":
        q = requests.get(f"{url}/api/now/table/incident", auth=(user, token), timeout=15, params={"sysparm_query": f"number={case.ticket_ref}", "sysparm_fields": "sys_id"})
        sid = (q.json().get("result") or [{}])[0].get("sys_id")
        if sid:
            requests.patch(f"{url}/api/now/table/incident/{sid}", auth=(user, token), timeout=15, json={"work_notes": text})
    else:
        requests.post(url, timeout=15, headers={"Authorization": f"Bearer {token}"} if token else {}, json={"event": "case.updated", "case": case.number, "ticket": case.ticket_ref, "text": text})


def in_background(fn, *a):
    def run():
        from django.db import close_old_connections
        close_old_connections()
        try:
            fn(*a)
        except Exception as exc:  # noqa: BLE001
            log.warning("ticketing: %s", exc)
        finally:
            close_old_connections()
    threading.Thread(target=run, daemon=True).start()


def create_for(case_id):
    from apps.alerts.models import Case
    case = Case.objects.get(pk=case_id)
    if case.ticket_ref:
        return
    try:
        ref, url = open_ticket(case)
    except Exception as exc:  # noqa: BLE001
        case.add_note("system", f"Could not open the external ticket: {exc}", kind="system")
        return
    if ref:
        Case.objects.filter(pk=case.pk).update(ticket_ref=ref[:60], ticket_url=(url or "")[:300])
        case.add_note("system", f"External ticket {ref} opened{f': {url}' if url else ''}", kind="system")
