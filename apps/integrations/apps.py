from django.apps import AppConfig


class Config(AppConfig):
    name = "apps.integrations"
    label = "integrations"

    def ready(self):
        from . import signals  # noqa: F401
