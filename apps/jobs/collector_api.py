"""HTTPS API for collector agents. Authenticated with the collector's bearer token; CSRF does not apply."""
import json

from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from apps.core.crypto import token_hash
from apps.core.permissions import client_ip

from .ingest import finish
from .models import Collector, Job


def _collector(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Bearer "):
        return None
    return Collector.objects.filter(token_hash=token_hash(auth[7:].strip()), enabled=True).first()


@csrf_exempt
@require_POST
def poll(request):
    c = _collector(request)
    if not c:
        return JsonResponse({"error": "unauthorized"}, status=401)
    try:
        body = json.loads(request.body or b"{}")
    except ValueError:
        body = {}
    c.last_seen = timezone.now()
    c.last_ip = client_ip(request)
    c.agent_version = str(body.get("version", ""))[:40]
    c.agent_host = str(body.get("host", ""))[:120]
    c.save(update_fields=["last_seen", "last_ip", "agent_version", "agent_host"])
    free = max(0, min(int(body.get("free", 4) or 0), 32))
    jobs = []
    for job in Job.objects.filter(collector=c, status="queued", run_after__lte=timezone.now()).order_by("run_after", "pk")[:free]:
        if job.spec.get("dry_run"):
            continue
        if Job.objects.filter(pk=job.pk, status="queued").update(status="running", started_at=timezone.now(), claimed_by=c.name):
            jobs.append({"id": job.pk, "kind": job.kind, "spec": job.spec})
    return JsonResponse({"jobs": jobs, "server_time": timezone.now().isoformat()})


@csrf_exempt
@require_POST
def result(request, pk):
    c = _collector(request)
    if not c:
        return JsonResponse({"error": "unauthorized"}, status=401)
    job = Job.objects.filter(pk=pk, collector=c, status="running").first()
    if not job:
        return JsonResponse({"error": "unknown or finished job"}, status=404)
    try:
        res = json.loads(request.body)
    except ValueError:
        return JsonResponse({"error": "bad json"}, status=400)
    finish(job, res)
    return JsonResponse({"ok": True})
