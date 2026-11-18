from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect, render

from apps.core.permissions import has_role
from apps.inventory.models import Credential, Site

from .models import SyncRun


def netbox(request):
    from . import netbox as nb
    if request.method == "POST":
        if not has_role(request.user, "admin"):
            messages.error(request, "Only administrators can sync with NetBox.")
            return redirect("integrations:netbox")
        act = request.POST.get("action")
        if act == "test":
            try:
                st = nb.NetBox().status()
                messages.success(request, f"Connected to NetBox {st.get('netbox-version', '?')}.")
            except Exception as exc:  # noqa: BLE001
                messages.error(request, f"NetBox is not reachable: {exc}")
            return redirect("integrations:netbox")
        if act in ("push", "dryrun"):
            sr = nb.run(kind=act, user=request.user.username)
        elif act == "import":
            sr = nb.run(kind="import", user=request.user.username, site_slug=request.POST.get("site", "").strip(),
                        role_slug=request.POST.get("role", "").strip(),
                        ssh_credential=Credential.objects.filter(pk=request.POST.get("ssh") or 0).first(),
                        snmp_credential=Credential.objects.filter(pk=request.POST.get("snmp") or 0).first(),
                        platform_default=request.POST.get("platform") or "cisco_iosxe")
        else:
            return redirect("integrations:netbox")
        (messages.success if sr.ok else messages.error)(request, f"NetBox {sr.kind}: {', '.join(f'{k} {v}' for k, v in sr.stats.items()) or 'nothing to do'}"
                                                                  + ("" if sr.ok else " (stopped, see the log)"))
        return redirect("integrations:run", sr.pk)
    from apps.core.models import AppSetting
    from apps.drivers.registry import choices
    return render(request, "integrations/netbox.html", {
        "configured": bool(AppSetting.get("netbox_url") and AppSetting.get("netbox_token")), "url": AppSetting.get("netbox_url", ""),
        "runs": SyncRun.objects.all()[:20], "creds": Credential.objects.all(), "sites": Site.objects.all(), "platforms": choices()})


def run(request, pk):
    return render(request, "integrations/run.html", {"r": get_object_or_404(SyncRun, pk=pk)})
