"""Hardware end-of-life, golden software versions and support contracts."""
from django.db import models


class HardwareLifecycle(models.Model):
    SOURCES = [("cisco_api", "Cisco EoX API"), ("import", "CSV import"), ("manual", "Entered by hand"), ("demo", "Demo data")]
    pid = models.CharField("Product ID", max_length=80, db_index=True)
    prefix = models.BooleanField(default=False, help_text="Match every product ID that starts with this")
    description = models.CharField(max_length=200, blank=True)
    end_of_sale = models.DateField(null=True, blank=True)
    end_of_sw_maintenance = models.DateField(null=True, blank=True)
    end_of_security = models.DateField(null=True, blank=True)
    last_day_of_support = models.DateField(null=True, blank=True)
    replacement = models.CharField(max_length=120, blank=True)
    url = models.URLField(max_length=300, blank=True)
    source = models.CharField(max_length=10, choices=SOURCES, default="manual")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["pid"]

    def matches(self, pid):
        pid = (pid or "").strip().upper()
        me = self.pid.strip().upper()
        return pid.startswith(me) if self.prefix else pid == me


def lifecycle_for(pid, records=None):
    records = records if records is not None else list(HardwareLifecycle.objects.all())
    hits = [r for r in records if r.matches(pid)]
    return max(hits, key=lambda r: (not r.prefix, len(r.pid))) if hits else None


class SoftwareStandard(models.Model):
    """The version you want on a platform ("golden image") and the oldest you accept."""
    platform = models.CharField(max_length=40)
    model_match = models.CharField(max_length=120, blank=True, help_text="Regex on the device model, e.g. ^C9300. Empty = every model.")
    recommended = models.CharField(max_length=60)
    minimum = models.CharField(max_length=60, blank=True, help_text="Anything older is flagged as high risk")
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["platform", "model_match"]

    def fits(self, device):
        import re
        return device.platform == self.platform and (not self.model_match or re.search(self.model_match, device.model or "", re.I))


class Contract(models.Model):
    number = models.CharField(max_length=80)
    vendor = models.CharField(max_length=60, blank=True)
    level = models.CharField(max_length=80, blank=True, help_text="e.g. SNT 8x5xNBD")
    start = models.DateField(null=True, blank=True)
    end = models.DateField()
    serials = models.TextField(help_text="Covered serial numbers, one per line or comma separated")
    notes = models.TextField(blank=True)
    source = models.CharField(max_length=10, default="manual")

    class Meta:
        ordering = ["end"]

    def serial_set(self):
        import re
        return {s.strip().upper() for s in re.split(r"[\s,;]+", self.serials) if s.strip()}
