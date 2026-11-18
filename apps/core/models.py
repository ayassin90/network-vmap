from django.db import models

from .crypto import decrypt, encrypt


class AppSetting(models.Model):
    """Key/value settings edited on the Settings page. Secret values are stored encrypted."""
    key = models.CharField(max_length=80, unique=True)
    value = models.TextField(blank=True)
    secret = models.BooleanField(default=False)

    @classmethod
    def get(cls, key, default=""):
        s = cls.objects.filter(key=key).first()
        if not s:
            return default
        return decrypt(s.value) if s.secret else s.value

    @classmethod
    def put(cls, key, value, secret=False):
        cls.objects.update_or_create(key=key, defaults={"value": encrypt(value) if secret else value, "secret": secret})

    @classmethod
    def get_int(cls, key, default):
        try:
            return int(cls.get(key, default))
        except (TypeError, ValueError):
            return default


class AuditLog(models.Model):
    at = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=80)
    target = models.CharField(max_length=200, blank=True)
    detail = models.TextField(blank=True)

    class Meta:
        ordering = ["-at"]

    @classmethod
    def log(cls, request_or_user, action, target="", detail=""):
        user = getattr(request_or_user, "user", request_or_user)
        cls.objects.create(user=getattr(user, "username", str(user or "system")), action=action, target=str(target)[:200], detail=detail)
