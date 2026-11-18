from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Load (or with --clear remove) the sample campus network. Demo devices are never contacted."

    def add_arguments(self, parser):
        parser.add_argument("--clear", action="store_true")

    def handle(self, *args, clear=False, **kw):
        from apps.core.demo import load
        n = load(clear_only=clear)
        self.stdout.write("Demo data removed." if clear else f"Loaded {n} demo devices.")
