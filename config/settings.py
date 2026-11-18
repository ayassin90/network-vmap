"""Network VMap settings. Everything deployment-specific comes from environment variables (see .env.example)."""
import os
from pathlib import Path

import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent
VAR_DIR = Path(os.environ.get("VMAP_VAR_DIR", BASE_DIR / "var"))
VAR_DIR.mkdir(parents=True, exist_ok=True)


def env_bool(name, default=False):
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")


def _secret_key():
    key = os.environ.get("DJANGO_SECRET_KEY")
    if key:
        return key
    f = VAR_DIR / "secret.key"          # generated once, kept in the data volume
    if not f.exists():
        from django.core.management.utils import get_random_secret_key
        f.write_text(get_random_secret_key())
        f.chmod(0o600)
    return f.read_text().strip()


SECRET_KEY = _secret_key()
# The release number: the VERSION file shipped in the image (a source checkout says "dev").
_vf = BASE_DIR / "VERSION"
VMAP_VERSION = _vf.read_text().strip() if _vf.is_file() else "dev"
DEBUG = env_bool("DJANGO_DEBUG", False)
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")
CSRF_TRUSTED_ORIGINS = [o for o in os.environ.get("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",") if o]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.humanize",
    "apps.core",
    "apps.accounts",
    "apps.inventory",
    "apps.jobs",
    "apps.topology",
    "apps.checks",
    "apps.psirt",
    "apps.upgrades",
    "apps.alerts",
    "apps.lifecycle",
    "apps.changes",
    "apps.events",
    "apps.reports",
    "apps.api",
    "apps.snapshots",
    "apps.flows",
    "apps.integrations",
    "apps.help",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "apps.core.middleware.LoginRequiredMiddleware",
]

ROOT_URLCONF = "config.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"builtins": ["apps.core.templatetags.ui", "django.contrib.humanize.templatetags.humanize"], "context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
        "apps.core.context.shell",
    ]},
}]
WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {"default": dj_database_url.config(
    default=f"sqlite:///{VAR_DIR / 'db.sqlite3'}", conn_max_age=60)}
if DATABASES["default"]["ENGINE"].endswith("sqlite3"):
    DATABASES["default"].setdefault("OPTIONS", {})
    DATABASES["default"]["OPTIONS"].update({"timeout": 30, "init_command": "PRAGMA journal_mode=WAL;"})

AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend", "apps.accounts.sso.LDAPBackend"]
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "core:dashboard"
AUTH_PASSWORD_VALIDATORS = [{"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"}]

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.environ.get("TZ", "UTC")
USE_I18N = False
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "whitenoise.storage.CompressedStaticFilesStorage"},
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
SESSION_COOKIE_AGE = 60 * 60 * 12
# Behind HTTPS (directly or via a reverse proxy that sets X-Forwarded-Proto): VMAP_HTTPS=1 secures cookies and redirects to HTTPS.
if env_bool("VMAP_HTTPS", False):
    SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = True
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = env_bool("VMAP_HTTPS_REDIRECT", True)
    # the container health check and an in-stack collector speak plain HTTP to web:8000 and must not be redirected
    SECURE_REDIRECT_EXEMPT = [r"^healthz$", r"^api/collector/"]
    SECURE_HSTS_SECONDS = int(os.environ.get("VMAP_HSTS_SECONDS", "0"))

# Set by install.sh when VMap sits behind its own nginx: the client address then comes from X-Real-IP (nginx overwrites
# it), so login throttling and the audit log see the real user, not the proxy.
VMAP_BEHIND_PROXY = env_bool("VMAP_BEHIND_PROXY", False)

EMAIL_HOST = os.environ.get("SMTP_HOST", "")
EMAIL_PORT = int(os.environ.get("SMTP_PORT", "587"))
EMAIL_HOST_USER = os.environ.get("SMTP_USER", "")
EMAIL_HOST_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
EMAIL_USE_TLS = env_bool("SMTP_TLS", True)
DEFAULT_FROM_EMAIL = os.environ.get("SMTP_FROM", "vmap@localhost")

# Worker
VMAP_WORKER_THREADS = int(os.environ.get("VMAP_WORKER_THREADS", "8"))
VMAP_SSH_TIMEOUT = int(os.environ.get("VMAP_SSH_TIMEOUT", "30"))

LOGGING = {
    "version": 1, "disable_existing_loggers": False,
    "formatters": {"plain": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": "INFO"},
    "loggers": {"paramiko": {"level": "WARNING"}, "netmiko": {"level": "WARNING"}},
}
