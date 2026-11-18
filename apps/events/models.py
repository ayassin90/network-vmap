"""Syslog messages and SNMP traps sent by devices, and the rules that turn some of them into alerts or actions."""
import re

from django.db import models
from django.utils import timezone

SEVERITY = [(0, "Emergency"), (1, "Alert"), (2, "Critical"), (3, "Error"), (4, "Warning"), (5, "Notice"), (6, "Info"), (7, "Debug")]


class Event(models.Model):
    device = models.ForeignKey("inventory.Device", null=True, blank=True, on_delete=models.CASCADE, related_name="events")
    source = models.CharField(max_length=45, db_index=True)
    ts = models.DateTimeField(default=timezone.now, db_index=True)
    kind = models.CharField(max_length=6, default="syslog")      # syslog | trap
    severity = models.PositiveSmallIntegerField(default=6, choices=SEVERITY, db_index=True)
    facility = models.PositiveSmallIntegerField(null=True, blank=True)
    mnemonic = models.CharField(max_length=80, blank=True, db_index=True)
    interface = models.CharField(max_length=60, blank=True)
    message = models.TextField()
    rule = models.ForeignKey("events.EventRule", null=True, blank=True, on_delete=models.SET_NULL)

    class Meta:
        ordering = ["-ts"]


class EventRule(models.Model):
    ACTIONS = [("alert", "Raise an alert"), ("collect", "Collect the device now (config change)"), ("flap", "Count as a link change"),
               ("ignore", "Ignore (keep in the log only)")]
    name = models.CharField(max_length=120)
    pattern = models.CharField(max_length=300, help_text="Regular expression on the message (mnemonic included), e.g. %PM-4-ERR_DISABLE")
    max_severity = models.PositiveSmallIntegerField(default=7, choices=SEVERITY, help_text="Only messages at this level or more severe")
    action = models.CharField(max_length=8, choices=ACTIONS, default="alert")
    alert_severity = models.CharField(max_length=8, default="medium")
    explanation = models.TextField(blank=True)
    enabled = models.BooleanField(default=True)
    order = models.PositiveIntegerField(default=100)

    class Meta:
        ordering = ["order", "pk"]

    def matches(self, ev):
        try:
            return self.enabled and ev.severity <= self.max_severity and re.search(self.pattern, ev.message, re.I)
        except re.error:
            return False
