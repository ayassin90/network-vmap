import re

from django.db import models
from django.utils import timezone


class SoftwareImage(models.Model):
    name = models.CharField(max_length=120)
    platforms = models.CharField(max_length=200, default="cisco_iosxe", help_text="Driver keys, comma separated")
    model_match = models.CharField(max_length=120, blank=True, help_text="Optional regex on the device model, e.g. ^C9300")
    version = models.CharField(max_length=60)
    filename = models.CharField(max_length=200)
    md5 = models.CharField("MD5", max_length=32, blank=True)
    size_bytes = models.BigIntegerField(null=True, blank=True)
    transfer_url = models.CharField(max_length=400, help_text="Where the switch downloads it from: http://, https://, scp://user:pass@, ftp://, tftp://")
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.version})"

    @property
    def transfer_url_masked(self):
        return re.sub(r"//([^:/@]+):([^@]+)@", r"//\1:•••@", self.transfer_url)

    def fits(self, device):
        plats = [p.strip() for p in self.platforms.split(",")]
        return device.platform in plats and (not self.model_match or re.search(self.model_match, device.model or "", re.I))


class UpgradePlan(models.Model):
    STATUS = [("draft", "Draft"), ("approved", "Approved"), ("running", "Running"), ("paused", "Paused"), ("done", "Done"),
              ("failed", "Finished with failures"), ("cancelled", "Cancelled")]
    MODES = [("stage", "Copy and verify only"), ("activate", "Copy, verify and activate")]
    name = models.CharField(max_length=160)
    image = models.ForeignKey(SoftwareImage, on_delete=models.PROTECT, related_name="plans")
    mode = models.CharField(max_length=10, choices=MODES, default="stage")
    allow_reload = models.BooleanField(default=False)
    dry_run = models.BooleanField(default=True, help_text="Show every command without sending anything")
    max_parallel = models.PositiveSmallIntegerField(default=5)
    stop_on_failures = models.PositiveSmallIntegerField(default=1, help_text="Pause the plan after this many failed devices (0 = never)")
    scheduled_for = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS, default="draft")
    created_by = models.CharField(max_length=150, blank=True)
    approved_by = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def counts(self):
        out = {}
        for s in self.targets.values_list("status", flat=True):
            out[s] = out.get(s, 0) + 1
        return out


class UpgradeTarget(models.Model):
    STAGES = ["precheck", "transfer", "verify", "activate", "postcheck"]
    STATUS = [("pending", "Pending"), ("running", "Running"), ("waiting", "Waiting for reload"), ("done", "Done"),
              ("failed", "Failed"), ("skipped", "Skipped")]
    plan = models.ForeignKey(UpgradePlan, on_delete=models.CASCADE, related_name="targets")
    device = models.ForeignKey("inventory.Device", on_delete=models.CASCADE, related_name="upgrade_targets")
    stage = models.CharField(max_length=10, blank=True)
    status = models.CharField(max_length=10, choices=STATUS, default="pending")
    from_version = models.CharField(max_length=60, blank=True)
    to_version = models.CharField(max_length=60, blank=True)
    context = models.JSONField(default=dict, blank=True)
    log = models.TextField(blank=True)
    postcheck_tries = models.PositiveSmallIntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["plan", "device__hostname"]
        unique_together = [("plan", "device")]

    def note(self, line):
        self.log = (self.log + f"{timezone.now():%Y-%m-%d %H:%M:%S}  {line}\n")[-50000:]
