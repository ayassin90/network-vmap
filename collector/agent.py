#!/usr/bin/env python3
"""Network VMap collector agent.

Run it inside the network you want to manage when the VMap server is hosted in the cloud (or anywhere that cannot
reach the switches directly). The agent only makes OUTBOUND HTTPS requests to the server: it asks for work,
runs SSH / SNMP against local devices, and sends the raw output back. No inbound firewall rule is needed.

    VMAP_URL=https://vmap.example.com VMAP_TOKEN=vmc_xxx python agent.py
    docker run -d --restart unless-stopped -e VMAP_URL=... -e VMAP_TOKEN=... vmap-collector

Environment: VMAP_URL, VMAP_TOKEN, VMAP_THREADS (default 8), VMAP_POLL (seconds, default 5),
             VMAP_VERIFY_TLS (default true; or a path to a CA bundle).
"""
import json
import logging
import os
import platform
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from executor import VERSION, execute  # noqa: E402

log = logging.getLogger("vmap-collector")


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    url = os.environ.get("VMAP_URL", "").rstrip("/")
    token = os.environ.get("VMAP_TOKEN", "")
    if not url or not token:
        sys.exit("Set VMAP_URL and VMAP_TOKEN (create the collector on the server's Collectors page).")
    threads = int(os.environ.get("VMAP_THREADS", "8"))
    poll = float(os.environ.get("VMAP_POLL", "5"))
    verify = os.environ.get("VMAP_VERIFY_TLS", "true")
    verify = False if verify.lower() in ("0", "false", "no") else (True if verify.lower() in ("1", "true", "yes") else verify)
    s = requests.Session()
    s.headers.update({"Authorization": f"Bearer {token}", "User-Agent": f"vmap-collector/{VERSION}"})
    s.verify = verify
    pool = ThreadPoolExecutor(max_workers=threads)
    busy = set()
    log.info("collector %s starting, server %s, %d threads", VERSION, url, threads)

    def run(job):
        try:
            res = execute(job["spec"])
        except Exception as exc:  # noqa: BLE001
            res = {"error": str(exc)}
        for attempt in range(5):
            try:
                r = s.post(f"{url}/api/collector/result/{job['id']}/", data=json.dumps(res), timeout=60,
                           headers={"Content-Type": "application/json"})
                r.raise_for_status()
                break
            except requests.RequestException as exc:
                log.warning("result upload for job %s failed (%s), retrying", job["id"], exc)
                time.sleep(3 * (attempt + 1))
        busy.discard(job["id"])

    while True:
        try:
            free = threads - len(busy)
            r = s.post(f"{url}/api/collector/poll/", timeout=30, json={
                "free": free, "version": VERSION, "host": socket.gethostname(), "os": platform.platform()})
            if r.status_code == 401:
                log.error("server rejected the token; check VMAP_TOKEN")
                time.sleep(30)
                continue
            r.raise_for_status()
            for job in r.json().get("jobs", []):
                busy.add(job["id"])
                log.info("job %s: %s %s", job["id"], job.get("kind"), job["spec"].get("host"))
                pool.submit(run, job)
        except requests.RequestException as exc:
            log.warning("cannot reach server: %s", exc)
            time.sleep(min(30, poll * 3))
        time.sleep(poll)


if __name__ == "__main__":
    main()
