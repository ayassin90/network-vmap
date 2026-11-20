from django.db import models
from django.utils import timezone

SEVERITIES = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info")]
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Finding(models.Model):
    """One issue on one device (optionally one interface), kept open until the check stops seeing it."""
    CATEGORIES = [("security", "Security"), ("best_practice", "Best practice"), ("interface", "Interface health"),
                  ("compliance", "Config standard"), ("lifecycle", "Lifecycle"), ("stp", "Spanning tree"), ("vlan", "VLAN consistency"),
                  ("health", "Hardware & CPU")]
    STATUS = [("open", "Open"), ("resolved", "Resolved"), ("accepted", "Accepted risk")]
    device = models.ForeignKey("inventory.Device", on_delete=models.CASCADE, related_name="findings")
    category = models.CharField(max_length=14, choices=CATEGORIES)
    check_id = models.CharField(max_length=40, db_index=True)
    key = models.CharField(max_length=120, blank=True, help_text="Interface or object the finding is about, if any")
    severity = models.CharField(max_length=8, choices=SEVERITIES)
    title = models.CharField(max_length=200)
    detail = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    remediation = models.TextField(blank=True, help_text="Config that fixes it")
    status = models.CharField(max_length=10, choices=STATUS, default="open", db_index=True)
    accepted_by = models.CharField(max_length=150, blank=True)
    accepted_note = models.TextField(blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-last_seen"]
        unique_together = [("device", "check_id", "key")]

    @property
    def rank(self):
        return SEV_RANK.get(self.severity, 0)


class Standard(models.Model):
    """A named set of configuration rules ("our baseline") checked on every collection."""
    name = models.CharField(max_length=120, unique=True)
    description = models.TextField(blank=True)
    platforms = models.CharField(max_length=300, default="cisco_ios,cisco_iosxe",
                                 help_text="Driver keys this applies to, comma separated, or * for all")
    roles = models.CharField(max_length=200, blank=True, help_text="Only devices with these roles (comma separated). Empty = all.")
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def applies_to(self, device):
        plats = [p.strip() for p in self.platforms.split(",") if p.strip()]
        roles = [r.strip() for r in self.roles.split(",") if r.strip()]
        return ("*" in plats or device.platform in plats) and (not roles or device.role in roles)


class StandardRule(models.Model):
    KINDS = [("present", "Line must be present"), ("absent", "Line must NOT be present"),
             ("section", "Every matching section must contain"), ("section_absent", "No matching section may contain")]
    standard = models.ForeignKey(Standard, on_delete=models.CASCADE, related_name="rules")
    name = models.CharField(max_length=160)
    kind = models.CharField(max_length=16, choices=KINDS, default="present")
    pattern = models.CharField(max_length=300, help_text="Regular expression matched against each config line (trimmed)")
    section = models.CharField(max_length=200, blank=True, help_text="Section header regex, e.g. ^interface (Gi|Te)")
    applies_if = models.CharField(max_length=200, blank=True, help_text="Only sections that also contain a line matching this")
    severity = models.CharField(max_length=8, choices=SEVERITIES, default="medium")
    remediation = models.TextField(blank=True)
    explanation = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["standard", "order", "pk"]


class ComplianceResult(models.Model):
    device = models.ForeignKey("inventory.Device", on_delete=models.CASCADE, related_name="compliance")
    standard = models.ForeignKey(Standard, on_delete=models.CASCADE, related_name="results")
    ran_at = models.DateTimeField(default=timezone.now)
    passed = models.PositiveIntegerField(default=0)
    failed = models.PositiveIntegerField(default=0)
    details = models.JSONField(default=list)

    class Meta:
        unique_together = [("device", "standard")]

    @property
    def score(self):
        total = self.passed + self.failed
        return round(100 * self.passed / total) if total else 100


class PostureResult(models.Model):
    """The latest outcome of every built-in check on one device: {check_id: [status, detail]} with status pass/fail/na."""
    device = models.OneToOneField("inventory.Device", on_delete=models.CASCADE, related_name="posture")
    ran_at = models.DateTimeField(default=timezone.now)
    results = models.JSONField(default=dict)

    def counts(self):
        out = {"pass": 0, "fail": 0, "na": 0}
        for st, _d in self.results.values():
            out[st] = out.get(st, 0) + 1
        return out
