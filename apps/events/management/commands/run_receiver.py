"""Syslog (UDP), SNMP trap and NetFlow/IPFIX receiver.  manage.py run_receiver
Ports from VMAP_SYSLOG_PORT (5514), VMAP_TRAP_PORT (1162) and VMAP_FLOW_PORT (2055)."""
import asyncio
import logging
import os
import threading
import time

from django.core.management.base import BaseCommand
from django.db import close_old_connections

from apps.events.processing import parse_syslog, parse_trap, process

log = logging.getLogger("vmap.receiver")


class Command(BaseCommand):
    help = "Receive syslog and SNMP traps."

    def handle(self, *a, **kw):
        sport, tport = int(os.environ.get("VMAP_SYSLOG_PORT", "5514")), int(os.environ.get("VMAP_TRAP_PORT", "1162"))
        fport = int(os.environ.get("VMAP_FLOW_PORT", "2055"))
        buf, lock = [], threading.Lock()
        stats = {"syslog": 0, "trap": 0, "flow_packets": 0, "flow_records": 0, "bad": 0}
        from apps.flows import decode, store

        class Syslog(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    ev = parse_syslog(data, addr[0])
                    stats["syslog"] += 1
                except Exception:  # noqa: BLE001
                    stats["bad"] += 1
                    return
                with lock:
                    buf.append(ev)

        class Trap(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    ev = parse_trap(data, addr[0])
                    stats["trap"] += 1
                except Exception:  # noqa: BLE001
                    stats["bad"] += 1
                    return
                with lock:
                    buf.append(ev)

        class Flow(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                try:
                    recs = decode.parse(data, addr[0])
                except Exception:  # noqa: BLE001
                    stats["bad"] += 1
                    return
                stats["flow_packets"] += 1
                stats["flow_records"] += len(recs)
                store.add(addr[0], recs)

        def flusher():
            last, last_flow = time.time(), time.time()
            while True:
                time.sleep(1)
                if time.time() - last_flow > 10:
                    last_flow = time.time()
                    try:
                        close_old_connections()
                        store.flush(older_than=5)
                    except Exception:  # noqa: BLE001
                        log.exception("could not store flows")
                with lock:
                    batch = buf[:5000]
                    del buf[:5000]
                if batch:
                    try:
                        close_old_connections()
                        process(batch)
                    except Exception:  # noqa: BLE001
                        log.exception("could not store events")
                if time.time() - last > 300:
                    last = time.time()
                    log.info("received so far: %s", stats)

        threading.Thread(target=flusher, daemon=True).start()
        loop = asyncio.new_event_loop()
        loop.run_until_complete(loop.create_datagram_endpoint(Syslog, local_addr=("0.0.0.0", sport)))
        loop.run_until_complete(loop.create_datagram_endpoint(Trap, local_addr=("0.0.0.0", tport)))
        loop.run_until_complete(loop.create_datagram_endpoint(Flow, local_addr=("0.0.0.0", fport)))
        log.info("listening: syslog udp/%s, traps udp/%s, netflow/ipfix udp/%s", sport, tport, fport)
        loop.run_forever()
