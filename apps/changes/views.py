import json

from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render
from django.template import TemplateSyntaxError
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.http import require_POST

from apps.core.models import AppSetting, AuditLog
from apps.core.permissions import has_role, role_required
from apps.inventory.models import Device, Interface, Site

from . import runner
from .models import ChangeRequest, ChangeTarget, ConfigTemplate
from .render import already_present, render as render_body

PORT_ACTIONS = {"shutdown": "Shut down", "no_shutdown": "Enable (no shutdown)", "bounce": "Bounce (shut, wait 5 s, enable)",
                "access_vlan": "Change access VLAN", "description": "Set description", "poe_off": "PoE off", "poe_on": "PoE on",
                "poe_cycle": "Cycle PoE (off, wait 5 s, on)"}


@role_required("operator")
@require_POST
def port_action(request, ipk):
    """One-port changes run straight away (operators), with a rollback point and an audit trail."""
    i = get_object_or_404(Interface.objects.select_related("device"), pk=ipk)
    action, value = request.POST.get("action"), request.POST.get("value", "").strip()
    if action not in PORT_ACTIONS:
        messages.error(request, "Unknown action.")
        return redirect("inventory:interface", i.device_id, i.pk)
    if action == "access_vlan" and not value.isdigit():
        messages.error(request, "Pick a VLAN number.")
        return redirect("inventory:interface", i.device_id, i.pk)
    try:
        first, after = i.device.driver.port_commands(action, i.name, value)
    except NotImplementedError as exc:
        messages.error(request, str(exc))
        return redirect("inventory:interface", i.device_id, i.pk)
    label = PORT_ACTIONS[action] + (f" {value}" if value else "")
    ch = ChangeRequest.objects.create(title=f"{i.device.hostname} {i.short}: {label}", kind="port", status="running",
                                      save_config=bool(request.POST.get("save")) and action not in ("bounce", "poe_cycle"),
                                      rollback_on_failure=True, emergency=bool(request.POST.get("emergency")) and has_role(request.user, "admin"),
                                      reason=request.POST.get("reason", ""), created_by=request.user.username,
                                      approved_by=request.user.username, approved_at=timezone.now())
    ChangeTarget.objects.create(change=ch, device=i.device, config="\n".join(first) + "\n", config_after="\n".join(after or []) + ("\n" if after else ""))
    AuditLog.log(request, "port." + action, f"{i.device.hostname} {i.short}", value)
    runner.advance(ch)
    messages.success(request, f"{ch.number}: {label} on {i.short} started.")
    return redirect("changes:detail", ch.pk)


def change_list(request):
    status = request.GET.get("status", "")
    qs = ChangeRequest.objects.all()
    if status:
        qs = qs.filter(status=status)
    pending = ChangeRequest.objects.filter(status="pending").count()
    return render(request, "changes/list.html", {"changes": qs[:300], "status": status, "pending": pending, "statuses": ChangeRequest.STATUS})


@role_required("operator")
def change_new(request):
    tpl = ConfigTemplate.objects.filter(pk=request.GET.get("template") or request.POST.get("template") or 0).first()
    devices = Device.objects.filter(enabled=True).select_related("site")
    if tpl:
        devices = devices.filter(platform__in=tpl.platform_list())
    devices = [d for d in devices if d.driver.changes_supported()]
    ctx = {"tpl": tpl, "templates": ConfigTemplate.objects.all(), "devices": devices, "sites": Site.objects.all()}
    if request.method == "POST":
        ids = request.POST.getlist("devices")
        body = tpl.body if tpl else request.POST.get("body", "")
        variables = {v["name"]: request.POST.get(f"var_{v['name']}", v.get("default", "")) for v in (tpl.variables if tpl else [])}
        ctx.update(sel=[int(x) for x in ids], body=body, variables=variables, form=request.POST)
        if not ids or not body.strip():
            messages.error(request, "Pick at least one device and give some configuration.")
            return render(request, "changes/new.html", ctx)
        try:
            previews = []
            for d in Device.objects.filter(pk__in=ids):
                cfg = render_body(body, d, variables)
                previews.append((d, cfg, already_present(cfg, d)))
        except TemplateSyntaxError as exc:
            messages.error(request, f"Template error: {exc}")
            return render(request, "changes/new.html", ctx)
        if request.POST.get("step") != "submit":
            ctx["previews"] = previews
            return render(request, "changes/new.html", ctx)
        ch = ChangeRequest.objects.create(
            title=request.POST.get("title") or (tpl.name if tpl else "Ad-hoc change"), kind="template" if tpl else "adhoc", template=tpl,
            variables=variables, body="" if tpl else body, status="pending", save_config=bool(request.POST.get("save_config")),
            rollback_on_failure=bool(request.POST.get("rollback")), max_parallel=int(request.POST.get("max_parallel") or 5),
            scheduled_for=parse_datetime(request.POST.get("scheduled_for") or "") or None, reason=request.POST.get("reason", ""),
            created_by=request.user.username)
        for d, cfg, present in previews:
            ChangeTarget.objects.create(change=ch, device=d, config=cfg, already_present=present)
        AuditLog.log(request, "change.submit", ch.number, ch.title)
        messages.success(request, f"{ch.number} submitted for approval.")
        return redirect("changes:detail", ch.pk)
    ctx.update(sel=[int(request.GET["device"])] if request.GET.get("device", "").isdigit() else [], body="", variables={v["name"]: v.get("default", "") for v in (tpl.variables if tpl else [])})
    return render(request, "changes/new.html", ctx)


def change_detail(request, pk):
    ch = get_object_or_404(ChangeRequest, pk=pk)
    if request.method == "POST":
        act = request.POST.get("action")
        if act in ("approve", "reject") and ch.status == "pending":
            if not has_role(request.user, "admin"):
                messages.error(request, "Only administrators approve changes.")
            elif AppSetting.get("four_eyes", "0") == "1" and request.user.username == ch.created_by:
                messages.error(request, "Four-eyes is on: someone else must approve your change.")
            else:
                ch.status = "approved" if act == "approve" else "rejected"
                ch.approved_by, ch.approved_at = request.user.username, timezone.now()
                ch.save()
                AuditLog.log(request, f"change.{act}", ch.number)
                if act == "approve" and not ch.scheduled_for:
                    ch.status = "running"
                    ch.save(update_fields=["status"])
                    runner.advance(ch)
                messages.success(request, f"{ch.number} {'approved' if act == 'approve' else 'rejected'}.")
        elif act == "cancel" and ch.status in ("draft", "pending", "approved") and has_role(request.user, "operator"):
            ch.status = "cancelled"
            ch.save(update_fields=["status"])
        elif act == "rollback" and has_role(request.user, "admin"):
            t = get_object_or_404(ChangeTarget, pk=request.POST.get("target"), change=ch)
            if not t.backup_name:
                messages.error(request, "No rollback point was saved for this device.")
            else:
                rb = ChangeRequest.objects.create(title=f"Roll back {ch.number} on {t.device.hostname}", kind="rollback", status="running",
                                                  save_config=True, rollback_on_failure=False, emergency=True, created_by=request.user.username,
                                                  approved_by=request.user.username, approved_at=timezone.now())
                lines = t.device.driver.rollback_steps(t.backup_name)
                rt = ChangeTarget.objects.create(change=rb, device=t.device, config="", backup_name=t.backup_name)
                _start_rollback(rt, lines)
                AuditLog.log(request, "change.rollback", ch.number, t.device.hostname)
                return redirect("changes:detail", rb.pk)
        return redirect("changes:detail", pk)
    targets = ch.targets.select_related("device", "pre_snapshot")
    return render(request, "changes/detail.html", {"ch": ch, "targets": targets, "counts": ch.counts(),
                                                  "auto": ch.status == "running"})


def _start_rollback(t, steps):
    from apps.jobs.models import Job
    from apps.jobs.services import ssh_base
    base = ssh_base(t.device)
    t.status, t.started_at = "running", timezone.now()
    if t.device.demo or not base:
        t.status, t.finished_at = "done", timezone.now()
        t.note("demo device: nothing sent")
        t.save()
        runner.advance(t.change)
        return
    t.note("restoring the configuration saved before the original change")
    t.save()
    Job.objects.create(kind="change", device=t.device, collector=t.device.collector, spec=dict(base, steps=steps + t.device.driver.save_steps()),
                       created_by=t.change.created_by, ref=f"change:{t.pk}")


def templates(request):
    return render(request, "changes/templates.html", {"templates": ConfigTemplate.objects.all()})


def template_edit(request, pk=None):
    t = get_object_or_404(ConfigTemplate, pk=pk) if pk else None
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators edit templates.")
            return redirect("changes:templates")
        if request.POST.get("action") == "delete" and t:
            t.delete()
            return redirect("changes:templates")
        try:
            variables = json.loads(request.POST.get("variables") or "[]")
            assert isinstance(variables, list)
        except (ValueError, AssertionError):
            messages.error(request, 'Variables must be a JSON list, e.g. [{"name": "ntp1", "label": "NTP server"}].')
            return render(request, "changes/template_edit.html", {"t": t, "form": request.POST})
        try:
            from .render import ENGINE
            ENGINE.from_string(request.POST.get("body", ""))
        except TemplateSyntaxError as exc:
            messages.error(request, f"Template error: {exc}")
            return render(request, "changes/template_edit.html", {"t": t, "form": request.POST})
        t = t or ConfigTemplate(created_by=request.user.username)
        t.name, t.description, t.platforms = request.POST["name"], request.POST.get("description", ""), request.POST.get("platforms", "")
        t.body, t.variables = request.POST.get("body", ""), variables
        t.save()
        messages.success(request, "Template saved.")
        return redirect("changes:templates")
    return render(request, "changes/template_edit.html", {"t": t, "form": None,
                                                          "vars_json": json.dumps(t.variables, indent=1) if t else "[]"})
