from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from apps.accounts.models import User
from apps.core.permissions import has_role, role_required
from apps.inventory.models import Device

from .models import Alert, AlertRule, Case, NotificationChannel


def alert_list(request):
    status = request.GET.get("status", "active")
    qs = Alert.objects.select_related("device", "case", "parent")
    show_sup = request.GET.get("suppressed") == "1"
    n_sup = Alert.objects.filter(suppressed=True).exclude(status="resolved").count()
    if not show_sup:
        qs = qs.filter(suppressed=False)
    if status == "active":
        qs = qs.exclude(status="resolved")
    elif status:
        qs = qs.filter(status=status)
    if request.GET.get("sev"):
        qs = qs.filter(severity=request.GET["sev"])
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(device__hostname__icontains=q))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items = sorted(qs[:2000], key=lambda a: (a.status != "open", rank.get(a.severity, 5), -a.last_seen.timestamp()))
    from apps.core.export import csv_response, wants_csv
    if wants_csv(request):
        return csv_response("alerts", ["device", "severity", "title", "status", "first_seen", "last_seen", "count", "suppressed", "case"],
                            ([a.device.hostname if a.device else "", a.severity, a.title, a.status, a.first_seen.isoformat() if getattr(a, "first_seen", None) else "",
                              a.last_seen.isoformat(), getattr(a, "count", ""), a.suppressed, a.case.number if a.case else ""] for a in items))
    page = Paginator(items, 100).get_page(request.GET.get("page"))
    stats = {s: Alert.objects.filter(status="open", severity=s, suppressed=False).count() for s in rank}
    return render(request, "alerts/list.html", {"page": page, "status": status, "stats": stats, "q": q, "show_sup": show_sup, "n_sup": n_sup,
                                               "cases": Case.objects.exclude(status__in=("resolved", "closed"))[:50]})


@role_required("operator")
@require_POST
def alert_bulk(request):
    ids = request.POST.getlist("ids") or [request.POST.get("id")]
    qs = Alert.objects.filter(pk__in=[i for i in ids if i])
    act = request.POST.get("action")
    if act == "ack":
        qs.filter(status="open").update(status="acknowledged", acknowledged_by=request.user.username)
    elif act == "resolve":
        qs.update(status="resolved", resolved_at=timezone.now())
    elif act == "reopen":
        qs.update(status="open", resolved_at=None)
    elif act in ("new_case", "add_case"):
        alerts = list(qs.select_related("device"))
        if not alerts:
            return redirect("alerts:list")
        if act == "new_case":
            worst = min(alerts, key=lambda a: ["critical", "high", "medium", "low", "info"].index(a.severity))
            case = Case.objects.create(title=worst.title[:200] + (f" (+{len(alerts) - 1} more)" if len(alerts) > 1 else ""),
                                       priority={"critical": "p1", "high": "p2", "medium": "p3"}.get(worst.severity, "p4"),
                                       created_by=request.user.username, assignee=request.user)
            case.add_note(request.user, "Case opened from alerts.", "system")
        else:
            case = get_object_or_404(Case, pk=request.POST.get("case"))
        for a in alerts:
            a.case = case
            a.save(update_fields=["case"])
            if a.device:
                case.devices.add(a.device)
            case.add_note(request.user, f"Linked alert: [{a.severity}] {a.title}", "system")
        return redirect("alerts:case", case.pk)
    return redirect(request.META.get("HTTP_REFERER") or "alerts:list")


def alert_detail(request, pk):
    a = get_object_or_404(Alert.objects.select_related("device", "rule", "case"), pk=pk)
    return render(request, "alerts/detail.html", {"a": a, "cases": Case.objects.exclude(status__in=("resolved", "closed"))[:50]})


def rules(request):
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators can change alert rules and channels.")
            return redirect("alerts:rules")
        act = request.POST.get("action")
        if act == "rule":
            r = get_object_or_404(AlertRule, pk=request.POST.get("id"))
            r.enabled = bool(request.POST.get("enabled"))
            r.notify = bool(request.POST.get("notify"))
            r.severity = request.POST.get("severity", r.severity)
            params = dict(r.params or {})
            if request.POST.get("min_severity"):
                params["min_severity"] = request.POST["min_severity"]
            if request.POST.get("target"):
                params["target"] = int(request.POST["target"])
            r.params = params
            r.save()
        elif act == "channel":
            NotificationChannel.objects.create(name=request.POST["name"], kind=request.POST["kind"], target=request.POST["target"],
                                               min_severity=request.POST.get("min_severity", "high"))
        elif act == "del_channel":
            NotificationChannel.objects.filter(pk=request.POST.get("id")).delete()
        elif act == "test_channel":
            from .engine import send
            ch = get_object_or_404(NotificationChannel, pk=request.POST.get("id"))
            fake = Alert(severity="info", title="Test notification from Network VMap", detail="If you can read this, the channel works.",
                         first_seen=timezone.now())
            try:
                send(ch, [fake])
                messages.success(request, f"Test sent to {ch.name}.")
            except Exception as exc:  # noqa: BLE001
                messages.error(request, f"Sending failed: {exc}")
        messages.success(request, "Saved.") if act != "test_channel" else None
        return redirect("alerts:rules")
    return render(request, "alerts/rules.html", {"rules": AlertRule.objects.all(), "channels": NotificationChannel.objects.all(),
                                                "kinds": NotificationChannel.KINDS, "sevs": ["critical", "high", "medium", "low", "info"]})


def cases(request):
    status = request.GET.get("status", "active")
    qs = Case.objects.select_related("assignee").annotate(n_alerts=Count("alerts", distinct=True), n_devices=Count("devices", distinct=True))
    if status == "active":
        qs = qs.exclude(status__in=("resolved", "closed"))
    elif status == "mine":
        qs = qs.filter(assignee=request.user).exclude(status="closed")
    elif status:
        qs = qs.filter(status=status)
    stats = {s: Case.objects.filter(status=s).count() for s, _ in Case.STATUS}
    return render(request, "alerts/cases.html", {"cases": qs, "status": status, "stats": stats})


@role_required("operator")
def case_new(request):
    if request.method == "POST":
        c = Case.objects.create(title=request.POST["title"][:200], description=request.POST.get("description", ""),
                                priority=request.POST.get("priority", "p3"), created_by=request.user.username,
                                assignee=User.objects.filter(pk=request.POST.get("assignee") or 0).first(),
                                due=request.POST.get("due") or None)
        c.devices.set(Device.objects.filter(pk__in=request.POST.getlist("devices")))
        c.add_note(request.user, "Case created.", "system")
        return redirect("alerts:case", c.pk)
    return render(request, "alerts/case_new.html", {"users": User.objects.all(), "devices": Device.objects.all(), "priorities": Case.PRIORITY,
                                                   "preset": Device.objects.filter(pk=request.GET.get("device") or 0).first()})


def case(request, pk):
    c = get_object_or_404(Case, pk=pk)
    if request.method == "POST":
        if not has_role(request.user, "operator"):
            messages.error(request, "You need the operator role.")
            return redirect("alerts:case", pk)
        act = request.POST.get("action")
        if act == "note" and request.POST.get("text", "").strip():
            c.add_note(request.user, request.POST["text"].strip())
            c.save()
        elif act == "ticket":
            from apps.integrations.tickets import open_ticket
            try:
                ref, url = open_ticket(c, force=True)
                c.ticket_ref, c.ticket_url = (ref or "")[:60], (url or "")[:300]
                c.save(update_fields=["ticket_ref", "ticket_url"])
                c.add_note(request.user, f"External ticket {ref} opened {url}", kind="system")
                messages.success(request, f"Ticket {ref} opened.")
            except Exception as exc:  # noqa: BLE001
                messages.error(request, f"Could not open a ticket: {exc}")
        elif act == "update":
            changes = []
            for f, label in (("status", "Status"), ("priority", "Priority")):
                v = request.POST.get(f)
                if v and v != getattr(c, f):
                    old = getattr(c, f"get_{f}_display")()
                    setattr(c, f, v)
                    changes.append(f"{label}: {old} → {getattr(c, f'get_{f}_display')()}")
            a = User.objects.filter(pk=request.POST.get("assignee") or 0).first()
            if a != c.assignee:
                changes.append(f"Assignee: {c.assignee or 'nobody'} → {a or 'nobody'}")
                c.assignee = a
            c.due = request.POST.get("due") or None
            if c.status in ("resolved", "closed") and not c.closed_at:
                c.closed_at = timezone.now()
                if request.POST.get("resolve_alerts"):
                    c.alerts.exclude(status="resolved").update(status="resolved", resolved_at=timezone.now())
            elif c.status not in ("resolved", "closed"):
                c.closed_at = None
            c.save()
            if changes:
                c.add_note(request.user, "; ".join(changes), "status")
        elif act == "devices":
            c.devices.set(Device.objects.filter(pk__in=request.POST.getlist("devices")))
            c.add_note(request.user, "Device list updated.", "system")
        elif act == "unlink":
            Alert.objects.filter(pk=request.POST.get("alert"), case=c).update(case=None)
        return redirect("alerts:case", pk)
    return render(request, "alerts/case.html", {"c": c, "ticketing": __import__("apps.integrations.tickets", fromlist=["enabled"]).enabled(), "users": User.objects.all(), "notes": c.notes.all(),
                                               "alerts": c.alerts.select_related("device"), "all_devices": Device.objects.all(),
                                               "statuses": Case.STATUS, "priorities": Case.PRIORITY})


def maintenance(request):
    from apps.inventory.models import Site

    from .models import MaintenanceWindow
    if request.method == "POST":
        if not has_role(request.user, "operator"):
            messages.error(request, "You need the operator role.")
            return redirect("alerts:maintenance")
        if request.POST.get("action") == "delete":
            MaintenanceWindow.objects.filter(pk=request.POST.get("id")).delete()
        elif request.POST.get("action") == "end":
            MaintenanceWindow.objects.filter(pk=request.POST.get("id")).update(ends=timezone.now())
        else:
            from django.utils.dateparse import parse_datetime
            starts, ends = parse_datetime(request.POST.get("starts") or ""), parse_datetime(request.POST.get("ends") or "")
            if not starts or not ends or ends <= starts:
                messages.error(request, "Give a start and an end after it.")
                return redirect("alerts:maintenance")
            if timezone.is_naive(starts):
                starts, ends = timezone.make_aware(starts), timezone.make_aware(ends)
            w = MaintenanceWindow.objects.create(name=request.POST.get("name") or "Maintenance", starts=starts, ends=ends,
                                                 all_devices=bool(request.POST.get("all_devices")), mute_alerts=bool(request.POST.get("mute")),
                                                 freeze=bool(request.POST.get("freeze")), note=request.POST.get("note", ""),
                                                 created_by=request.user.username)
            w.sites.set(Site.objects.filter(pk__in=request.POST.getlist("sites")))
            w.devices.set(Device.objects.filter(pk__in=request.POST.getlist("devices")))
            messages.success(request, "Window saved.")
        return redirect("alerts:maintenance")
    now = timezone.now()
    return render(request, "alerts/maintenance.html", {
        "active": MaintenanceWindow.objects.filter(starts__lte=now, ends__gte=now), "upcoming": MaintenanceWindow.objects.filter(starts__gt=now),
        "past": MaintenanceWindow.objects.filter(ends__lt=now)[:20], "sites": Site.objects.all(), "devices": Device.objects.all()})
