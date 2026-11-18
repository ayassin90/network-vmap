import json
import zlib

from django.db import models


class Snapshot(models.Model):
    """The whole network at one moment: devices, software, ports, links, routes, endpoints and open findings.
    Stored compressed; compare any two (or one with now) to see what changed."""
    taken_at = models.DateTimeField(auto_now_add=True, db_index=True)
    label = models.CharField(max_length=120, blank=True)
    kind = models.CharField(max_length=10, default="auto", choices=[("auto", "Scheduled"), ("manual", "Manual"), ("change", "Before a change")])
    created_by = models.CharField(max_length=150, blank=True)
    summary = models.JSONField(default=dict)
    blob = models.BinaryField()

    class Meta:
        ordering = ["-taken_at"]

    def __str__(self):
        return self.label or self.taken_at.strftime("%Y-%m-%d %H:%M")

    @property
    def data(self):
        if not hasattr(self, "_data"):
            self._data = json.loads(zlib.decompress(bytes(self.blob)).decode())
        return self._data

    @data.setter
    def data(self, value):
        self._data = value
        self.blob = zlib.compress(json.dumps(value, separators=(",", ":")).encode(), 6)

    @property
    def size_kb(self):
        return round(len(bytes(self.blob)) / 1024, 1)
