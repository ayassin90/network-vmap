"""Configuration changes: one-port actions, templates rendered per device, approval, backup and rollback."""
from django.db import models
from django.utils import timezone


class ConfigTemplate(models.Model):
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    platforms = models.CharField(max_length=200, default="cisco_ios,cisco_iosxe")
    body = models.TextField(help_text="Configuration lines. Use {{ vars.name }} and {{ device.hostname }}; loops over {{ interfaces.access }} etc.")
    variables = models.JSONField(default=list, blank=True, help_text='[{"name": "ntp1", "label": "NTP server 1", "default": ""}]')
    created_by = models.CharField(max_length=150, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def platform_list(self):
        return [p.strip() for p in self.platforms.split(",") if p.strip()]


class ChangeRequest(models.Model):
    KINDS = [("port", "Port action"), ("template", "From template"), ("adhoc", "Ad-hoc lines"), ("rollback", "Rollback")]
    STATUS = [("draft", "Draft"), ("pending", "Waiting for approval"), ("approved", "Approved"), ("running", "Running"),
              ("done", "Done"), ("failed", "Finished with failures"), ("cancelled", "Cancelled"), ("rejected", "Rejected")]
    title = models.CharField(max_length=200)
    kind = models.CharField(max_length=10, choices=KINDS)
    template = models.ForeignKey(ConfigTemplate, null=True, blank=True, on_delete=models.SET_NULL)
    variables = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True)
    status = models.CharField(max_length=10, choices=STATUS, default="draft", db_index=True)
    save_config = models.BooleanField(default=True)
    rollback_on_failure = models.BooleanField(default=True)
    emergency = models.BooleanField(default=False, help_text="Run even during a change freeze")
    max_parallel = models.PositiveSmallIntegerField(default=5)
    scheduled_for = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True)
    created_by = models.CharField(max_length=150, blank=True)
    approved_by = models.CharField(max_length=150, blank=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    @property
    def number(self):
        return f"CHG-{self.pk:05d}"

    def counts(self):
        out = {}
        for s in self.targets.values_list("status", flat=True):
            out[s] = out.get(s, 0) + 1
        return out


class ChangeTarget(models.Model):
    STATUS = [("pending", "Pending"), ("running", "Running"), ("done", "Done"), ("failed", "Failed"), ("rolled_back", "Rolled back"),
              ("skipped", "Skipped")]
    change = models.ForeignKey(ChangeRequest, on_delete=models.CASCADE, related_name="targets")
    device = models.ForeignKey("inventory.Device", on_delete=models.CASCADE, related_name="change_targets")
    config = models.TextField()
    config_after = models.TextField(blank=True, help_text="Second phase (bounce, PoE cycle)")
    already_present = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=12, choices=STATUS, default="pending")
    backup_name = models.CharField(max_length=80, blank=True)
    pre_snapshot = models.ForeignKey("inventory.ConfigSnapshot", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")
    log = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["change", "device__hostname"]

    def note(self, line):
        self.log = (self.log + f"{timezone.now():%Y-%m-%d %H:%M:%S}  {line}\n")[-50000:]
