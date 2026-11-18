from django.db import models


class FlowStat(models.Model):
    """Flow records from NetFlow v5/v9 or IPFIX, summed per minute, exporter and conversation. `port` is the service side
    of the conversation (the lower, well-known port), so client ephemeral ports do not explode the table."""
    ts = models.DateTimeField(db_index=True)
    device = models.ForeignKey("inventory.Device", null=True, blank=True, on_delete=models.CASCADE, related_name="flows")
    exporter = models.GenericIPAddressField()
    src = models.GenericIPAddressField()
    dst = models.GenericIPAddressField()
    proto = models.PositiveSmallIntegerField()
    port = models.PositiveIntegerField(default=0)
    in_if = models.PositiveIntegerField(default=0)
    out_if = models.PositiveIntegerField(default=0)
    bytes = models.BigIntegerField(default=0)
    packets = models.BigIntegerField(default=0)
    flows = models.PositiveIntegerField(default=0)
    res = models.PositiveSmallIntegerField(default=1, help_text="Minutes per row: 1 for fresh data, 60 after the hourly roll-up")

    class Meta:
        indexes = [models.Index(fields=["device", "ts"]), models.Index(fields=["src", "ts"]), models.Index(fields=["dst", "ts"])]
