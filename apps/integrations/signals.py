from django.db import transaction
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver

from apps.alerts.models import Case

from . import tickets


@receiver(pre_save, sender=Case)
def remember_status(sender, instance, **kw):
    instance._old_status = Case.objects.filter(pk=instance.pk).values_list("status", flat=True).first() if instance.pk else None


@receiver(post_save, sender=Case)
def case_ticket(sender, instance, created, **kw):
    if not tickets.enabled():
        return
    if created:
        transaction.on_commit(lambda: tickets.in_background(tickets.create_for, instance.pk))
    elif instance.ticket_ref and getattr(instance, "_old_status", None) != instance.status and instance.status in ("resolved", "closed"):
        transaction.on_commit(lambda: tickets.in_background(tickets.comment, instance, f"Resolved in Network VMap ({instance.get_status_display()})."))
