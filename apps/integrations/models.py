from django.db import models


class SyncRun(models.Model):
    """One NetBox push or import, with its log."""
    system = models.CharField(max_length=20, default="netbox")
    kind = models.CharField(max_length=10, default="push")      # push | import | dryrun
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    ok = models.BooleanField(default=False)
    stats = models.JSONField(default=dict)
    log = models.TextField(blank=True)
    created_by = models.CharField(max_length=150, blank=True)

    class Meta:
        ordering = ["-started_at"]
