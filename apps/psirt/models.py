from django.db import models
from django.utils import timezone


class Advisory(models.Model):
    SOURCES = [("openvuln", "Cisco openVuln API"), ("builtin", "Built-in"), ("manual", "Added by a user")]
    advisory_id = models.CharField(max_length=120, unique=True)
    title = models.CharField(max_length=300)
    severity = models.CharField(max_length=10, default="medium")
    cvss = models.FloatField(null=True, blank=True)
    cves = models.CharField(max_length=500, blank=True)
    url = models.URLField(max_length=400, blank=True)
    published = models.DateField(null=True, blank=True)
    summary = models.TextField(blank=True)
    workaround = models.TextField(blank=True)
    os_types = models.CharField(max_length=100, blank=True, help_text="ios, iosxe, nxos … comma separated")
    condition = models.CharField(max_length=300, blank=True, help_text="Config regex that makes a device exposed")
    condition_absent = models.BooleanField(default=False, help_text="Exposed when the regex is NOT found")
    fixed_in = models.CharField(max_length=400, blank=True, help_text="First fixed releases per train, comma separated")
    source = models.CharField(max_length=10, choices=SOURCES, default="builtin")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-cvss", "-published"]

    def __str__(self):
        return self.advisory_id

    @property
    def cve_list(self):
        return [c.strip() for c in self.cves.split(",") if c.strip()]


class DeviceAdvisory(models.Model):
    MATCH = [("version", "Version match (vendor data)"), ("config", "Exposure by configuration")]
    STATUS = [("open", "Open"), ("mitigated", "Mitigated"), ("accepted", "Accepted risk"), ("resolved", "No longer affected")]
    device = models.ForeignKey("inventory.Device", on_delete=models.CASCADE, related_name="advisories")
    advisory = models.ForeignKey(Advisory, on_delete=models.CASCADE, related_name="hits")
    match = models.CharField(max_length=8, choices=MATCH)
    detail = models.CharField(max_length=300, blank=True)
    status = models.CharField(max_length=10, choices=STATUS, default="open")
    note = models.TextField(blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = [("device", "advisory")]
