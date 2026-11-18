from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.shortcuts import redirect, render
from django.utils import timezone

from apps.core.permissions import has_role
from apps.inventory.models import Device

from .models import SEVERITY, Event, EventRule


def event_list(request):
    qs = Event.objects.select_related("device", "rule")
    f = request.GET
    if f.get("device"):
        qs = qs.filter(device_id=f["device"])
    if f.get("sev"):
        qs = qs.filter(severity__lte=int(f["sev"]))
    if f.get("kind"):
        qs = qs.filter(kind=f["kind"])
    if f.get("q"):
        qs = qs.filter(Q(message__icontains=f["q"]) | Q(mnemonic__icontains=f["q"]) | Q(source__startswith=f["q"]))
    if f.get("matched") == "1":
        qs = qs.exclude(rule=None)
    page = Paginator(qs, 200).get_page(f.get("page"))
    since = timezone.now() - timezone.timedelta(hours=24)
    top = Event.objects.filter(ts__gte=since).exclude(mnemonic="").values("mnemonic").annotate(n=Count("id")).order_by("-n")[:10]
    unknown = Event.objects.filter(ts__gte=since, device=None).values("source").annotate(n=Count("id")).order_by("-n")[:5]
    return render(request, "events/list.html", {"page": page, "devices": Device.objects.all(), "sevs": SEVERITY, "top": top, "unknown": unknown,
                                               "n24": Event.objects.filter(ts__gte=since).count(), "auto": f.get("live") == "1"})


def rules(request):
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators change event rules.")
            return redirect("events:rules")
        act = request.POST.get("action")
        if act == "delete":
            EventRule.objects.filter(pk=request.POST.get("id")).delete()
        else:
            import re
            try:
                re.compile(request.POST.get("pattern", ""))
            except re.error as exc:
                messages.error(request, f"Invalid pattern: {exc}")
                return redirect("events:rules")
            r = EventRule.objects.filter(pk=request.POST.get("id") or 0).first() or EventRule()
            r.name, r.pattern, r.action = request.POST["name"], request.POST["pattern"], request.POST.get("action_kind", "alert")
            r.max_severity, r.alert_severity = int(request.POST.get("max_severity", 7)), request.POST.get("alert_severity", "medium")
            r.enabled = bool(request.POST.get("enabled"))
            r.explanation = request.POST.get("explanation", r.explanation)
            r.order = int(request.POST.get("order") or r.order or 100)
            r.save()
            messages.success(request, "Rule saved.")
        return redirect("events:rules")
    since = timezone.now() - timezone.timedelta(days=1)
    hits = dict(Event.objects.filter(ts__gte=since).exclude(rule=None).values_list("rule").annotate(n=Count("id")))
    rs = list(EventRule.objects.all())
    for r in rs:
        r.hits = hits.get(r.pk, 0)
    return render(request, "events/rules.html", {"rules": rs, "sevs": SEVERITY, "actions": EventRule.ACTIONS})
