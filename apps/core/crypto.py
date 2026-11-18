"""Secrets at rest (device passwords, SNMP communities, API keys) are Fernet-encrypted.
The key comes from VMAP_FIELD_KEY or is derived from SECRET_KEY, so keep SECRET_KEY stable across upgrades."""
import base64
import hashlib
import os
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


@lru_cache(maxsize=1)
def _fernet():
    raw = os.environ.get("VMAP_FIELD_KEY") or settings.SECRET_KEY
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()))


def encrypt(value):
    if not value:
        return ""
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value):
    if not value:
        return ""
    try:
        return _fernet().decrypt(value.encode()).decode()
    except InvalidToken:
        return ""


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()
