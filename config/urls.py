from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path("", include("apps.core.urls")),
    path("accounts/", include("apps.accounts.urls")),
    path("devices/", include("apps.inventory.urls")),
    path("jobs/", include("apps.jobs.urls")),
    path("topology/", include("apps.topology.urls")),
    path("checks/", include("apps.checks.urls")),
    path("psirt/", include("apps.psirt.urls")),
    path("upgrades/", include("apps.upgrades.urls")),
    path("alerts/", include("apps.alerts.urls")),
    path("help/", include("apps.help.urls")),
    path("lifecycle/", include("apps.lifecycle.urls")),
    path("changes/", include("apps.changes.urls")),
    path("events/", include("apps.events.urls")),
    path("reports/", include("apps.reports.urls")),
    path("snapshots/", include("apps.snapshots.urls")),
    path("traffic/", include("apps.flows.urls")),
    path("integrations/", include("apps.integrations.urls")),
    path("api/collector/", include("apps.jobs.collector_urls")),
    path("api/v1/", include("apps.api.urls")),
    path("django-admin/", admin.site.urls),
]
