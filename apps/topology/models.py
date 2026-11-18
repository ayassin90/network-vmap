from django.db import models


class Layout(models.Model):
    """A saved view of a topology: node positions, hidden nodes, custom labels and display options."""
    KINDS = [("l2", "Layer 2"), ("l3", "Layer 3")]
    name = models.CharField(max_length=120)
    kind = models.CharField(max_length=2, choices=KINDS)
    site = models.ForeignKey("inventory.Site", null=True, blank=True, on_delete=models.CASCADE)
    positions = models.JSONField(default=dict, blank=True)
    hidden = models.JSONField(default=list, blank=True)
    labels = models.JSONField(default=dict, blank=True)
    options = models.JSONField(default=dict, blank=True)
    updated_by = models.CharField(max_length=150, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["kind", "name"]
        unique_together = [("kind", "name")]
