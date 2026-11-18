"""One queue for all device work. A job with no collector is run by this server's worker; a job with a collector
waits until that collector (an agent inside the customer network) picks it up over HTTPS."""
import secrets

from django.db import models
from django.utils import timezone

from apps.core.crypto import token_hash


class Collector(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.CharField(max_length=240, blank=True)
    token_hash = models.CharField(max_length=64, editable=False)
    token_prefix = models.CharField(max_length=12, editable=False)
    enabled = models.BooleanField(default=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    last_ip = models.CharField(max_length=60, blank=True)
    agent_version = models.CharField(max_length=40, blank=True)
    agent_host = models.CharField(max_length=120, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def new_token(self):
        token = "vmc_" + secrets.token_urlsafe(32)
        self.token_hash = token_hash(token)
        self.token_prefix = token[:10]
        return token

    @property
    def online(self):
        return bool(self.last_seen and (timezone.now() - self.last_seen).total_seconds() < 90)


class Job(models.Model):
    KINDS = [("collect", "Full collection (SSH)"), ("snmp_poll", "SNMP poll"), ("snmp_collect", "SNMP collection"),
             ("command", "Run commands"), ("upgrade", "Upgrade step"), ("test", "Connection test"),
             ("change", "Configuration change"), ("macscan", "MAC / ARP scan")]
    STATUS = [("queued", "Queued"), ("running", "Running"), ("done", "Done"), ("failed", "Failed"), ("cancelled", "Cancelled")]
    kind = models.CharField(max_length=14, choices=KINDS)
    device = models.ForeignKey("inventory.Device", null=True, blank=True, on_delete=models.CASCADE, related_name="jobs")
    collector = models.ForeignKey(Collector, null=True, blank=True, on_delete=models.SET_NULL, related_name="jobs")
    status = models.CharField(max_length=10, choices=STATUS, default="queued", db_index=True)
    spec = models.JSONField(default=dict)
    result = models.JSONField(default=dict, blank=True)
    summary = models.CharField(max_length=300, blank=True)
    error = models.TextField(blank=True)
    ref = models.CharField(max_length=60, blank=True, db_index=True, help_text="e.g. upgrade-target:12")
    created_by = models.CharField(max_length=150, blank=True)
    claimed_by = models.CharField(max_length=120, blank=True)
    run_after = models.DateTimeField(default=timezone.now, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"#{self.pk} {self.get_kind_display()} {self.device or ''}"

    @property
    def duration(self):
        if self.started_at and self.finished_at:
            return round((self.finished_at - self.started_at).total_seconds(), 1)
        return None

    def public_spec(self):
        """The spec with secrets masked, for the job page."""
        def mask(o):
            if isinstance(o, dict):
                return {k: ("•••" if k in ("password", "secret", "community", "auth_key", "priv_key") and v else mask(v)) for k, v in o.items()}
            if isinstance(o, list):
                return [mask(x) for x in o]
            return o
        return mask(self.spec)
