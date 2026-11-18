"""The worker: runs jobs that have no collector, and the scheduler. Start one per deployment:  manage.py run_worker"""
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import close_old_connections
from django.utils import timezone

from apps.jobs.ingest import run_local
from apps.jobs.models import Job
from apps.jobs.scheduler import tick

log = logging.getLogger("vmap.worker")


class Command(BaseCommand):
    help = "Run queued jobs and the periodic scheduler."

    def add_arguments(self, parser):
        parser.add_argument("--threads", type=int, default=settings.VMAP_WORKER_THREADS)
        parser.add_argument("--no-scheduler", action="store_true")

    def handle(self, *args, threads, no_scheduler, **kw):
        name = f"worker@{socket.gethostname()}"
        pool = ThreadPoolExecutor(max_workers=threads)
        busy = set()
        last_tick = 0
        Job.objects.filter(status="running", collector=None).update(status="queued", started_at=None)   # restart recovery
        log.info("%s started with %d threads", name, threads)

        def run(job):
            try:
                close_old_connections()
                run_local(job)
            except Exception:  # noqa: BLE001
                log.exception("job %s crashed", job.pk)
                Job.objects.filter(pk=job.pk).update(status="failed", error="Worker crashed on this job; see worker log.", finished_at=timezone.now())
            finally:
                busy.discard(job.pk)
                close_old_connections()

        while True:
            try:
                close_old_connections()
                if not no_scheduler and time.time() - last_tick > 30:
                    last_tick = time.time()
                    tick()
                free = threads - len(busy)
                if free > 0:
                    for job in Job.objects.filter(status="queued", collector=None, run_after__lte=timezone.now()).order_by("run_after", "pk")[:free]:
                        if Job.objects.filter(pk=job.pk, status="queued").update(status="running", started_at=timezone.now(), claimed_by=name):
                            busy.add(job.pk)
                            pool.submit(run, job)
            except Exception:  # noqa: BLE001
                log.exception("worker loop error")
                time.sleep(5)
            time.sleep(1)
