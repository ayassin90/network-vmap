import secrets

from django.conf import settings
from django.db import models

from apps.core.crypto import token_hash


class ApiToken(models.Model):
    name = models.CharField(max_length=100)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="api_tokens")
    token_hash = models.CharField(max_length=64, unique=True, editable=False)
    prefix = models.CharField(max_length=12, editable=False)
    read_only = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def issue(self):
        t = "vmt_" + secrets.token_urlsafe(32)
        self.token_hash, self.prefix = token_hash(t), t[:10]
        return t
