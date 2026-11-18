from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.checks.models import SEVERITIES, SEV_RANK


class AlertRule(models.Model):
    key = models.CharField(max_length=40, unique=True)
    name = models.CharField(max_length=160)
    description = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    severity = models.CharField(max_length=8, choices=SEVERITIES, default="high")
    params = models.JSONField(default=dict, blank=True)
    notify = models.BooleanField(default=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class NotificationChannel(models.Model):
    KINDS = [("email", "Email"), ("webhook", "Webhook (JSON POST)"), ("slack", "Slack incoming webhook"), ("teams", "Microsoft Teams webhook")]
    name = models.CharField(max_length=100)
    kind = models.CharField(max_length=8, choices=KINDS)
    target = models.CharField(max_length=500, help_text="Email addresses (comma separated) or webhook URL")
    min_severity = models.CharField(max_length=8, choices=SEVERITIES, default="high")
    enabled = models.BooleanField(default=True)
    last_error = models.TextField(blank=True)

    def wants(self, severity):
        return self.enabled and SEV_RANK.get(severity, 0) >= SEV_RANK.get(self.min_severity, 0)


class Case(models.Model):
    STATUS = [("new", "New"), ("in_progress", "In progress"), ("waiting", "Waiting"), ("resolved", "Resolved"), ("closed", "Closed")]
    PRIORITY = [("p1", "P1 critical"), ("p2", "P2 high"), ("p3", "P3 medium"), ("p4", "P4 low")]
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=12, choices=STATUS, default="new", db_index=True)
    priority = models.CharField(max_length=2, choices=PRIORITY, default="p3")
    assignee = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="cases")
    devices = models.ManyToManyField("inventory.Device", blank=True, related_name="cases")
    created_by = models.CharField(max_length=150, blank=True)
    due = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    ticket_ref = models.CharField(max_length=60, blank=True, help_text="Jira key / ServiceNow number of the linked ticket")
    ticket_url = models.CharField(max_length=300, blank=True)

    class Meta:
        ordering = ["-updated_at"]

    @property
    def number(self):
        return f"CASE-{self.pk:05d}"

    def __str__(self):
        return f"{self.number} {self.title}"

    def add_note(self, author, text, kind="note"):
        return CaseNote.objects.create(case=self, author=getattr(author, "username", author or "system"), text=text, kind=kind)


class CaseNote(models.Model):
    case = models.ForeignKey(Case, on_delete=models.CASCADE, related_name="notes")
    author = models.CharField(max_length=150, blank=True)
    kind = models.CharField(max_length=10, default="note")  # note | status | system
    text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]


class Alert(models.Model):
    STATUS = [("open", "Open"), ("acknowledged", "Acknowledged"), ("resolved", "Resolved")]
    rule = models.ForeignKey(AlertRule, null=True, blank=True, on_delete=models.SET_NULL)
    dedupe = models.CharField(max_length=200, db_index=True)
    device = models.ForeignKey("inventory.Device", null=True, blank=True, on_delete=models.CASCADE, related_name="alerts")
    severity = models.CharField(max_length=8, choices=SEVERITIES)
    title = models.CharField(max_length=250)
    detail = models.TextField(blank=True)
    link = models.CharField(max_length=300, blank=True)
    status = models.CharField(max_length=13, choices=STATUS, default="open", db_index=True)
    count = models.PositiveIntegerField(default=1)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    acknowledged_by = models.CharField(max_length=150, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    auto_resolve = models.BooleanField(default=True)
    case = models.ForeignKey(Case, null=True, blank=True, on_delete=models.SET_NULL, related_name="alerts")
    suppressed = models.BooleanField(default=False, db_index=True)
    suppressed_reason = models.CharField(max_length=200, blank=True)
    parent = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="children",
                               help_text="The root-cause alert this one is a consequence of")
    reopen_count = models.PositiveIntegerField(default=0)
    flapping = models.BooleanField(default=False)
    correlation = models.CharField(max_length=300, blank=True)

    class Meta:
        ordering = ["-last_seen"]


class MaintenanceWindow(models.Model):
    """A planned period for a scope: alerts muted, and/or a change freeze (no upgrades or config changes)."""
    name = models.CharField(max_length=120)
    starts = models.DateTimeField()
    ends = models.DateTimeField()
    all_devices = models.BooleanField(default=False)
    sites = models.ManyToManyField("inventory.Site", blank=True)
    devices = models.ManyToManyField("inventory.Device", blank=True)
    mute_alerts = models.BooleanField(default=True)
    freeze = models.BooleanField(default=False, help_text="Change freeze: block upgrades and configuration changes")
    note = models.TextField(blank=True)
    created_by = models.CharField(max_length=150, blank=True)

    class Meta:
        ordering = ["-starts"]

    def covers(self, device):
        return self.all_devices or self.devices.filter(pk=device.pk).exists() or (device.site_id and self.sites.filter(pk=device.site_id).exists())

    @property
    def active(self):
        now = timezone.now()
        return self.starts <= now <= self.ends


def windows_for(device, now=None, mute=None, freeze=None):
    now = now or timezone.now()
    qs = MaintenanceWindow.objects.filter(starts__lte=now, ends__gte=now)
    if mute is not None:
        qs = qs.filter(mute_alerts=mute)
    if freeze is not None:
        qs = qs.filter(freeze=freeze)
    return [w for w in qs if w.covers(device)]
