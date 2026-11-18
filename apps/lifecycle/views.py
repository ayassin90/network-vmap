import csv
import io
from datetime import date

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.dateparse import parse_date

from apps.checks.models import Finding
from apps.core.models import AuditLog
from apps.core.permissions import has_role
from apps.drivers.registry import drivers
from apps.inventory.models import Device, Transceiver

from .engine import coverage, device_pids
from .models import Contract, HardwareLifecycle, SoftwareStandard, lifecycle_for


def overview(request):
    tab = request.GET.get("tab", "hardware")
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators change lifecycle data.")
            return redirect(request.get_full_path())
        _post(request)
        return redirect(request.get_full_path())
    today = date.today()
    ctx = {"tab": tab, "today": today, "findings": Finding.objects.filter(category="lifecycle", status="open").count()}
    devs = list(Device.objects.filter(enabled=True).select_related("site"))
    if tab == "hardware":
        recs = list(HardwareLifecycle.objects.all())
        rows = []
        for d in devs:
            for where, pid in device_pids(d):
                r = lifecycle_for(pid, recs)
                if r or where == "chassis":
                    rows.append({"d": d, "where": where, "pid": pid, "r": r})
        rows.sort(key=lambda x: (x["r"] is None, (x["r"].last_day_of_support if x["r"] and x["r"].last_day_of_support else date.max)))
        ctx.update(rows=rows, records=recs)
    elif tab == "software":
        stds = list(SoftwareStandard.objects.all())
        rows = []
        for d in devs:
            std = next((s for s in stds if s.fits(d)), None)
            rows.append({"d": d, "std": std})
        ctx.update(rows=rows, stds=stds, platforms=sorted(drivers().values(), key=lambda x: x.label))
    elif tab == "contracts":
        contracts = list(Contract.objects.all())
        ctx.update(contracts=contracts, rows=[{"d": d, "c": coverage(d, contracts)} for d in devs])
    elif tab == "optics":
        ctx["optics"] = Transceiver.objects.select_related("device").order_by("device__hostname", "interface")
    return render(request, "lifecycle/overview.html", ctx)


def _post(request):
    act = request.POST.get("action")
    if act == "hw":
        HardwareLifecycle.objects.create(pid=request.POST["pid"].strip(), prefix=bool(request.POST.get("prefix")),
                                         description=request.POST.get("description", ""), end_of_sale=parse_date(request.POST.get("eos") or "") or None,
                                         last_day_of_support=parse_date(request.POST.get("ldos") or "") or None,
                                         replacement=request.POST.get("replacement", ""), source="manual")
    elif act == "hw_delete":
        HardwareLifecycle.objects.filter(pk=request.POST.get("id")).delete()
    elif act == "sw":
        SoftwareStandard.objects.create(platform=request.POST["platform"], model_match=request.POST.get("model_match", ""),
                                        recommended=request.POST["recommended"].strip(), minimum=request.POST.get("minimum", "").strip(),
                                        notes=request.POST.get("notes", ""))
    elif act == "sw_delete":
        SoftwareStandard.objects.filter(pk=request.POST.get("id")).delete()
    elif act == "contract":
        Contract.objects.create(number=request.POST["number"], vendor=request.POST.get("vendor", ""), level=request.POST.get("level", ""),
                                start=parse_date(request.POST.get("start") or "") or None, end=parse_date(request.POST["end"]),
                                serials=request.POST.get("serials", ""), notes=request.POST.get("notes", ""))
    elif act == "contract_delete":
        Contract.objects.filter(pk=request.POST.get("id")).delete()
    elif act == "import":
        f = request.FILES.get("file")
        kind = request.POST.get("kind")
        if not f:
            messages.error(request, "Choose a CSV file.")
            return
        rows = list(csv.DictReader(io.StringIO(f.read().decode("utf-8-sig"))))
        n = 0
        for r in rows:
            r = {k.strip().lower(): (v or "").strip() for k, v in r.items() if k}
            try:
                if kind == "hw" and r.get("pid"):
                    HardwareLifecycle.objects.update_or_create(pid=r["pid"], prefix=r.get("prefix", "").lower() in ("1", "yes", "true"), defaults={
                        "description": r.get("description", ""), "end_of_sale": parse_date(r.get("end_of_sale", "")) or None,
                        "end_of_sw_maintenance": parse_date(r.get("end_of_sw_maintenance", "")) or None,
                        "last_day_of_support": parse_date(r.get("last_day_of_support", "")) or None,
                        "replacement": r.get("replacement", ""), "source": "import"})
                    n += 1
                elif kind == "contracts" and r.get("number") and r.get("end"):
                    c, _ = Contract.objects.get_or_create(number=r["number"], defaults={"end": parse_date(r["end"]), "serials": ""})
                    c.end = parse_date(r["end"]) or c.end
                    c.vendor, c.level = r.get("vendor", c.vendor), r.get("level", c.level)
                    c.serials = "\n".join(sorted(c.serial_set() | {s for s in r.get("serial", r.get("serials", "")).replace(";", ",").split(",") if s}))
                    c.source = "import"
                    c.save()
                    n += 1
            except (ValueError, TypeError):
                continue
        messages.success(request, f"{n} rows imported.")
        AuditLog.log(request, "lifecycle.import", kind, f"{n} rows")
    elif act == "sync":
        from .cisco_api import sync_coverage, sync_eox
        for fn in (sync_eox, sync_coverage):
            try:
                messages.success(request, fn())
            except Exception as exc:  # noqa: BLE001
                messages.error(request, f"{fn.__name__}: {exc}")
    elif act == "recheck":
        from .engine import run_lifecycle
        for d in Device.objects.filter(enabled=True):
            run_lifecycle(d)
        messages.success(request, "Lifecycle checks re-run.")
