"""Shell context for every page: sidebar sections, the help topic for this page, notification counts."""
from django.conf import settings

from apps.core.permissions import has_role

NAV = [
    ("", [("Dashboard", "core:dashboard", "home", ("core:dashboard",))]),
    ("Network", [
        ("Devices", "inventory:list", "server", ("inventory:list", "inventory:detail", "inventory:add", "inventory:edit", "inventory:bulk_add")),
        ("L2 topology", "topology:l2", "layers", ("topology:l2",)),
        ("L3 topology", "topology:l3", "cloud", ("topology:l3",)),
        ("Path trace", "topology:path", "upgrade", ("topology:path",)),
        ("Routing tables", "inventory:routes", "code", ("inventory:routes",)),
        ("Interfaces", "inventory:interfaces", "dot", ("inventory:interfaces",)),
        ("Traffic (NetFlow)", "flows:traffic", "upgrade", ("flows:traffic",)),
        ("Find endpoint", "inventory:endpoints", "search", ("inventory:endpoints", "inventory:endpoint")),
        ("Spanning tree", "inventory:stp", "layers", ("inventory:stp",)),
        ("VLANs", "inventory:vlans", "tag", ("inventory:vlans",)),
        ("Snapshots", "snapshots:index", "clock", ("snapshots:index", "snapshots:detail", "snapshots:compare")),
        ("Discovery", "inventory:discovery", "sparkle", ("inventory:discovery", "inventory:discovery_detail")),
    ]),
    ("Assurance", [
        ("Security & practices", "checks:findings", "shield", ("checks:findings",)),
        ("Config standards", "checks:standards", "check", ("checks:standards", "checks:standard", "checks:compliance", "checks:standard_new")),
        ("PSIRT advisories", "psirt:list", "alert", ("psirt:list", "psirt:detail")),
        ("Lifecycle", "lifecycle:overview", "clock", ("lifecycle:overview",)),
        ("Capacity", "reports:capacity", "dot", ("reports:capacity",)),
        ("Weekly summary", "reports:summary", "check", ("reports:summary",)),
        ("Audit report", "reports:audit", "shield", ("reports:audit",)),
    ]),
    ("Operations", [
        ("Alerts", "alerts:list", "bell", ("alerts:list", "alerts:detail", "alerts:rules")),
        ("Event log", "events:list", "code", ("events:list", "events:rules")),
        ("Cases", "alerts:cases", "check", ("alerts:cases", "alerts:case", "alerts:case_new")),
        ("Changes", "changes:list", "code", ("changes:list", "changes:new", "changes:detail", "changes:templates", "changes:template", "changes:template_new")),
        ("Maintenance", "alerts:maintenance", "lock", ("alerts:maintenance",)),
        ("Software upgrades", "upgrades:list", "upgrade", ("upgrades:list", "upgrades:plan", "upgrades:new", "upgrades:images")),
        ("Jobs", "jobs:list", "clock", ("jobs:list", "jobs:detail")),
    ]),
    ("Setup", [
        ("Sites & credentials", "inventory:setup", "key", ("inventory:setup",)),
        ("Collectors", "jobs:collectors", "cloud", ("jobs:collectors", "jobs:collector")),
        ("Platform guide", "inventory:platforms", "sparkle", ("inventory:platforms", "inventory:platform")),
        ("NetBox", "integrations:netbox", "cloud", ("integrations:netbox", "integrations:run")),
        ("Settings", "core:settings", "gear", ("core:settings",)),
    ]),
]


def shell(request):
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {}
    match = getattr(request, "resolver_match", None)
    view = match.view_name if match else ""
    from apps.alerts.models import Alert
    from apps.help.topics import topic_for
    open_alerts = Alert.objects.filter(status="open", suppressed=False).count()
    from apps.changes.models import ChangeRequest
    pending_changes = ChangeRequest.objects.filter(status="pending").count()
    sections = {}
    for section, items in NAV:
        sections[section] = [{"label": l, "url_name": u, "icon": i, "active": view in act,
                              "count": open_alerts if u == "alerts:list" else (pending_changes if u == "changes:list" else 0)}
                             for l, u, i, act in items]
    recent = Alert.objects.filter(status="open", suppressed=False).select_related("device").order_by("-last_seen")[:8]
    return {
        "nav_sections": sections,
        "help_topic": topic_for(view) or "",
        "open_alert_count": open_alerts,
        "recent_alerts": recent,
        "vmap_version": settings.VMAP_VERSION,
        "is_admin": has_role(request.user, "admin"),
        "is_operator": has_role(request.user, "operator"),
    }
