"""First-start defaults (idempotent): admin user from env, alert rules, baseline standard, built-in PSIRT advisories."""
import os
import secrets

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create defaults. Safe to run on every start."

    def handle(self, *args, **kw):
        from apps.accounts.models import User
        from apps.alerts.engine import ensure_rules
        from apps.checks.defaults import ensure_baseline
        from apps.psirt.builtin import load
        ensure_rules()
        ensure_baseline()
        load()
        from apps.changes.defaults import ensure_templates
        ensure_templates()
        from apps.events.defaults import ensure_rules as ensure_event_rules
        ensure_event_rules()
        if not User.objects.exists():
            name = os.environ.get("VMAP_ADMIN_USER", "admin")
            pw = os.environ.get("VMAP_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
            User.objects.create_superuser(name, os.environ.get("VMAP_ADMIN_EMAIL", ""), pw, role="admin")
            self.stdout.write(self.style.WARNING(f"Created administrator '{name}' with password: {pw}"))
        self.stdout.write("Defaults in place.")
