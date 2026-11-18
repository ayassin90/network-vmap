from datetime import timedelta

from django.contrib import messages
from django.db.models import Avg, Count, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone

from apps.alerts.models import Alert, Case
from apps.checks.models import Finding
from apps.core.models import AppSetting, AuditLog
from apps.core.permissions import has_role
from apps.inventory.models import ConfigSnapshot, Device, Interface
from apps.jobs.models import Collector, Job
from apps.psirt.models import DeviceAdvisory


def healthz(request):
    return HttpResponse("ok")


def dashboard(request):
    devs = Device.objects.filter(enabled=True)
    by_status = dict(devs.values_list("status").annotate(n=Count("id")))
    scores = devs.aggregate(sec=Avg("security_score"), health=Avg("health_score"), comp=Avg("compliance_score"))
    open_f = Finding.objects.filter(status="open")
    sev = {s: Alert.objects.filter(status="open", severity=s, suppressed=False).count() for s in ("critical", "high", "medium", "low")}
    if_issues = open_f.filter(category="interface")
    by_check = list(if_issues.values("check_id", "title").annotate(n=Count("id")).order_by("-n")[:8])
    top_sec = list(open_f.filter(category__in=("security", "best_practice")).values("check_id", "title", "severity")
                   .annotate(n=Count("id")).order_by("-n")[:8])
    versions = list(devs.exclude(os_version="").values("os_type", "os_version").annotate(n=Count("id")).order_by("-n")[:8])
    psirt = DeviceAdvisory.objects.filter(status="open")
    busy = sorted(Interface.objects.filter(oper_up=True, device__enabled=True).exclude(speed_mbps=None).select_related("device")
                  .order_by("-in_rate_bps")[:200], key=lambda i: -(i.utilization or 0))[:6]
    since = timezone.now() - timedelta(days=7)
    return render(request, "core/dashboard.html", {
        "n_devices": devs.count(), "by_status": by_status, "n_unreach": sum(by_status.get(k, 0) for k in ("down", "auth_failed", "error")), "scores": scores, "sev": sev, "by_check": by_check, "top_sec": top_sec,
        "versions": versions, "busy": busy,
        "n_psirt_dev": psirt.values("device").distinct().count(),
        "n_psirt_crit": psirt.filter(advisory__severity="critical").values("device").distinct().count(),
        "n_if_issues": if_issues.count(),
        "n_half": Interface.objects.filter(duplex__icontains="half", oper_up=True).count(),
        "n_errdis": Interface.objects.filter(status="err-disabled").count(),
        "recent_alerts": Alert.objects.exclude(status="resolved").select_related("device").order_by("-last_seen")[:8],
        "changes": ConfigSnapshot.objects.filter(collected_at__gte=since).exclude(added=0, removed=0).select_related("device")[:8],
        "cases_open": Case.objects.exclude(status__in=("resolved", "closed")).count(),
        "cases_mine": Case.objects.filter(assignee=request.user).exclude(status__in=("resolved", "closed")).count(),
        "jobs_failed": Job.objects.filter(status="failed", finished_at__gte=timezone.now() - timedelta(days=1)).count(),
        "jobs_queued": Job.objects.filter(status__in=("queued", "running")).count(),
        "collectors": Collector.objects.all(),
        "worst": devs.exclude(security_score=None).order_by("security_score")[:6],
        "empty": not Device.objects.exists(),
        "n_endpoints": __import__("apps.inventory.models", fromlist=["Endpoint"]).Endpoint.objects.count(),
        "n_changes_pending": __import__("apps.changes.models", fromlist=["ChangeRequest"]).ChangeRequest.objects.filter(status="pending").count(),
        "n_lifecycle": open_f.filter(category="lifecycle", severity__in=("high", "medium")).values("device").distinct().count(),
        "n_stp": open_f.filter(category__in=("stp", "vlan")).count(),
        "n_suppressed": Alert.objects.filter(suppressed=True).exclude(status="resolved").count(),
        "n_health": open_f.filter(category="health").values("device").distinct().count(),
        "n_events": __import__("apps.events.models", fromlist=["Event"]).Event.objects.filter(ts__gte=timezone.now() - timedelta(hours=1)).count(),
        "n_events_bad": __import__("apps.events.models", fromlist=["Event"]).Event.objects.filter(ts__gte=timezone.now() - timedelta(hours=1), severity__lte=3).count(),
    })


SECTIONS = [
    ("Collection & retention", ["collect_interval_minutes", "poll_interval_minutes", "mac_scan_interval_minutes", "sample_retention_days",
                                "job_retention_days", "event_retention_days", "flow_retention_days", "snapshot_interval_hours", "snapshot_retention_days"]),
    ("Thresholds & alerts", ["if_error_threshold", "if_util_warn", "alert_cooldown_minutes", "public_url"]),
    ("Changes & upgrades", ["four_eyes", "upgrade_postcheck_delay_seconds", "upgrade_postcheck_retry_seconds"]),
    ("Reports", ["report_recipients", "report_weekday", "report_hour"]),
    ("Vendor data (Cisco APIs)", ["openvuln_client_id", "openvuln_client_secret"]),
    ("Directory login (LDAP / Active Directory)", ["ldap_enabled", "ldap_server", "ldap_start_tls", "ldap_verify_cert", "ldap_bind_dn", "ldap_bind_password",
                                                   "ldap_user_base", "ldap_user_filter", "ldap_group_base", "ldap_admin_groups", "ldap_operator_groups",
                                                   "ldap_viewer_groups", "ldap_default_role"]),
    ("Single sign-on (OIDC: Entra ID, Okta, Google, Keycloak…)", ["oidc_enabled", "oidc_button_label", "oidc_issuer", "oidc_client_id",
                                                                   "oidc_client_secret", "oidc_scopes", "oidc_username_claim", "oidc_groups_claim",
                                                                   "oidc_admin_groups", "oidc_operator_groups", "oidc_viewer_groups", "oidc_default_role"]),
    ("NetBox", ["netbox_url", "netbox_token", "netbox_verify_tls", "netbox_sync_interval_hours", "netbox_site_default"]),
    ("Ticketing (Jira / ServiceNow)", ["ticket_system", "ticket_url", "ticket_user", "ticket_token", "ticket_project", "ticket_min_severity"]),
]

SETTINGS = [
    ("collect_interval_minutes", "Full collection every (minutes)", "360", False,
     "How often each device is fully collected over SSH (config, neighbours, routes, interfaces). 0 turns scheduled collection off."),
    ("poll_interval_minutes", "Interface poll every (minutes)", "5", False,
     "How often throughput and error counters are polled (SNMP, or a light SSH poll when there is no SNMP credential)."),
    ("if_error_threshold", "Interface error threshold", "100", False, "Error counters at or above this raise an interface finding."),
    ("if_util_warn", "High utilisation (%)", "80", False, "Ports at or above this utilisation raise a finding."),
    ("sample_retention_days", "Keep throughput history (days)", "14", False, ""),
    ("job_retention_days", "Keep job history (days)", "30", False, ""),
    ("mac_scan_interval_minutes", "MAC / ARP scan every (minutes)", "30", False, "Keeps the endpoint finder fresh between full collections. 0 = only during collections."),
    ("alert_cooldown_minutes", "Alert cool-down (minutes)", "30", False, "An alert that clears and returns within this time reopens instead of creating a new one."),
    ("four_eyes", "Four-eyes change approval (1 = on)", "0", False, "When on, someone other than the requester must approve a configuration change."),
    ("upgrade_postcheck_delay_seconds", "Upgrade: wait after reload (seconds)", "480", False, "How long to wait before checking a reloaded switch."),
    ("upgrade_postcheck_retry_seconds", "Upgrade: retry every (seconds)", "180", False, "Retry interval while the switch boots."),
    ("report_recipients", "Weekly report recipients", "", False, "Email addresses, comma separated. Needs SMTP settings on the server."),
    ("report_weekday", "Weekly report day (0 = Monday)", "0", False, ""),
    ("report_hour", "Weekly report hour (server time)", "7", False, ""),
    ("event_retention_days", "Keep syslog / trap events (days)", "14", False, ""),
    ("flow_retention_days", "Keep NetFlow / IPFIX data (days)", "7", False, "Per-minute flow summaries take the most space; lower this on busy networks."),
    ("snapshot_interval_hours", "Network snapshot every (hours)", "24", False, "A full snapshot of the network for the time machine. 0 = only manual snapshots."),
    ("snapshot_retention_days", "Keep snapshots (days)", "90", False, ""),
    ("public_url", "Public URL of this server", "", False, "Used in alert notifications so links open the right page."),
    ("openvuln_client_id", "Cisco API client ID", "", False, "From apiconsole.cisco.com (client credentials). Used for openVuln (PSIRT), EoX and Serial Number to Information."),
    ("openvuln_client_secret", "Cisco API client secret", "", True, ""),

    ("ldap_enabled", "Enable LDAP / AD login (1 = on)", "0", False, "Local accounts with a password keep working (keep one admin as a break-glass account)."),
    ("ldap_server", "LDAP server URL", "", False, "ldaps://dc1.corp.local:636 or ldap://10.0.0.10:389"),
    ("ldap_start_tls", "Use StartTLS on ldap:// (1 = on)", "0", False, ""),
    ("ldap_verify_cert", "Verify the server certificate (1 = on)", "1", False, "Turn off only for testing."),
    ("ldap_bind_dn", "Service account DN", "", False, "CN=svc-vmap,OU=Service Accounts,DC=corp,DC=local (read-only)."),
    ("ldap_bind_password", "Service account password", "", True, ""),
    ("ldap_user_base", "Search base for users", "", False, "DC=corp,DC=local"),
    ("ldap_user_filter", "User filter", "(sAMAccountName={username})", False, "Active Directory: (sAMAccountName={username}). OpenLDAP: (uid={username})."),
    ("ldap_group_base", "Search base for groups (optional)", "", False, "Only used when the directory has no memberOf attribute (plain OpenLDAP)."),
    ("ldap_admin_groups", "Groups that get Administrator", "", False, "Group DNs or names (CN), one per line or comma separated."),
    ("ldap_operator_groups", "Groups that get Operator", "", False, ""),
    ("ldap_viewer_groups", "Groups that get Viewer", "", False, ""),
    ("ldap_default_role", "Role for users in none of those groups", "", False, "Empty = refuse the login. Or viewer / operator / admin."),
    ("oidc_enabled", "Enable single sign-on (1 = on)", "0", False, "Adds a sign-in button to the login page."),
    ("oidc_button_label", "Button label", "Sign in with single sign-on", False, "e.g. Sign in with Microsoft"),
    ("oidc_issuer", "Issuer URL", "", False, "Entra ID: https://login.microsoftonline.com/<tenant-id>/v2.0 · Okta: https://<org>.okta.com · Google: https://accounts.google.com"),
    ("oidc_client_id", "Client ID", "", False, "Register VMap as a web app; redirect URI: <public URL>/accounts/oidc/callback/"),
    ("oidc_client_secret", "Client secret", "", True, ""),
    ("oidc_scopes", "Scopes", "openid email profile", False, "Add groups (Okta, Keycloak) if your provider needs it for the groups claim."),
    ("oidc_username_claim", "Username claim", "preferred_username", False, ""),
    ("oidc_groups_claim", "Groups claim", "groups", False, "Entra ID sends group object IDs: list those IDs below."),
    ("oidc_admin_groups", "Groups that get Administrator", "", False, ""),
    ("oidc_operator_groups", "Groups that get Operator", "", False, ""),
    ("oidc_viewer_groups", "Groups that get Viewer", "", False, ""),
    ("oidc_default_role", "Role for users in none of those groups", "", False, "Empty = refuse the login."),
    ("netbox_url", "NetBox URL", "", False, "https://netbox.corp.local"),
    ("netbox_token", "NetBox API token", "", True, "A token with write access to DCIM and IPAM."),
    ("netbox_verify_tls", "Verify NetBox certificate (1 = on)", "1", False, ""),
    ("netbox_sync_interval_hours", "Push to NetBox every (hours)", "0", False, "0 = only when you press Sync on the NetBox page."),
    ("netbox_site_default", "NetBox site for devices without a site", "", False, "Slug or name. Empty = skip those devices."),
    ("ticket_system", "Ticketing system", "", False, "jira, servicenow or webhook. Empty = off."),
    ("ticket_url", "Ticketing URL", "", False, "Jira: https://<org>.atlassian.net · ServiceNow: https://<instance>.service-now.com · webhook: any URL"),
    ("ticket_user", "Ticketing user", "", False, "Jira: account email · ServiceNow: integration user"),
    ("ticket_token", "Ticketing API token / password", "", True, ""),
    ("ticket_project", "Jira project key / ServiceNow assignment group", "", False, "e.g. NET"),
    ("ticket_min_severity", "Open tickets for cases of at least", "high", False, "critical, high, medium or low. Tickets are opened when a case is created."),
]


def settings_page(request):
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators can change settings.")
            return redirect("core:settings")
        for key, _label, _d, secret, _h in SETTINGS:
            if key in request.POST:
                v = request.POST[key].strip()
                if secret and not v:
                    continue
                AppSetting.put(key, v, secret=secret)
        AuditLog.log(request, "settings.save")
        messages.success(request, "Settings saved.")
        if request.POST.get("test_ldap"):
            from apps.accounts.sso import ldap_authenticate, role_from_groups
            info, err = ldap_authenticate(request.POST.get("test_user", "").strip(), request.POST.get("test_password", ""))
            if info:
                role = role_from_groups(info["groups"], "ldap")
                messages.info(request, f"LDAP test OK: {info['dn']} · {len(info['groups'])} groups · VMap role: {role or 'none (login refused)'}")
            else:
                messages.error(request, f"LDAP test failed: {err}")
        return redirect("core:settings")
    rows = {k: {"key": k, "label": l, "value": "" if sec else AppSetting.get(k, d), "secret": sec, "is_set": bool(AppSetting.get(k)), "help": h}
            for k, l, d, sec, h in SETTINGS}
    sections = [(title, [rows[k] for k in keys if k in rows]) for title, keys in SECTIONS]
    listed = {k for _t, keys in SECTIONS for k in keys}
    other = [r for k, r in rows.items() if k not in listed]
    if other:
        sections.append(("Other", other))
    return render(request, "core/settings.html", {"sections": sections, "audit": AuditLog.objects.all()[:30]})


def search(request):
    q = request.GET.get("q", "").strip()
    out = []
    if len(q) >= 2:
        for d in Device.objects.filter(Q(hostname__icontains=q) | Q(mgmt_ip__icontains=q) | Q(serial__icontains=q) | Q(model__icontains=q))[:8]:
            out.append({"group": "Devices", "label": d.hostname, "sub": f"{d.mgmt_ip} · {d.model} · {d.os_version}", "url": f"/devices/{d.pk}/"})
        for i in Interface.objects.filter(Q(description__icontains=q) | Q(ip__startswith=q) | Q(mac__icontains=q)).select_related("device")[:8]:
            out.append({"group": "Interfaces", "label": f"{i.device.hostname} {i.short}", "sub": i.description or i.ip, "url": f"/devices/{i.device_id}/if/{i.pk}/"})
        for a in Alert.objects.filter(title__icontains=q).exclude(status="resolved")[:5]:
            out.append({"group": "Alerts", "label": a.title, "sub": a.severity, "url": f"/alerts/{a.pk}/"})
        for c in Case.objects.filter(title__icontains=q)[:5]:
            out.append({"group": "Cases", "label": f"{c.number} {c.title}", "sub": c.get_status_display(), "url": f"/alerts/cases/{c.pk}/"})
    groups = {}
    for r in out:
        groups.setdefault(r["group"], []).append(r)
    return JsonResponse({"groups": [{"title": g, "items": items} for g, items in groups.items()]})
