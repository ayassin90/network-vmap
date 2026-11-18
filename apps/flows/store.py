"""Per-minute aggregation of decoded flow records, flushed to the database by the receiver."""
import threading
import time
from datetime import datetime, timezone as dt_tz

from .decode import service_port

_lock = threading.Lock()
_agg = {}
_devices = {"at": 0, "map": {}}


def add(exporter, records, now=None):
    minute = int((now or time.time()) // 60 * 60)
    with _lock:
        for r in records:
            k = (minute, exporter, r["src"], r["dst"], r["proto"], service_port(r), r["in_if"], r["out_if"])
            v = _agg.get(k)
            if v:
                v[0] += r["bytes"]
                v[1] += r["packets"]
                v[2] += 1
            else:
                _agg[k] = [r["bytes"], r["packets"], 1]


def flush(older_than=0):
    """Write aggregated minutes to the database. older_than=0 writes everything (the open minute is merged later)."""
    from apps.inventory.models import Device
    from .models import FlowStat
    cutoff = time.time() - older_than
    with _lock:
        keys = [k for k in _agg if k[0] + 60 <= cutoff] if older_than else list(_agg)
        items = [(k, _agg.pop(k)) for k in keys]
    if not items:
        return 0
    if time.time() - _devices["at"] > 300:
        _devices["map"] = dict(Device.objects.values_list("mgmt_ip", "id"))
        _devices["at"] = time.time()
    rows = [FlowStat(ts=datetime.fromtimestamp(k[0], dt_tz.utc), device_id=_devices["map"].get(k[1]), exporter=k[1], src=k[2], dst=k[3],
                     proto=k[4], port=k[5], in_if=k[6], out_if=k[7], bytes=v[0], packets=v[1], flows=v[2]) for k, v in items]
    FlowStat.objects.bulk_create(rows, batch_size=2000)
    return len(rows)


def rollup(hours=24):
    """Merge per-minute rows older than `hours` into one row per hour and conversation (Postgres; other databases keep minutes)."""
    from django.db import connection, transaction
    if connection.vendor != "postgresql":
        return 0
    with transaction.atomic(), connection.cursor() as c:
        c.execute("""
            INSERT INTO flows_flowstat (ts, device_id, exporter, src, dst, proto, port, in_if, out_if, bytes, packets, flows, res)
            SELECT date_trunc('hour', ts), device_id, exporter, src, dst, proto, port, in_if, out_if, SUM(bytes), SUM(packets), SUM(flows), 60
            FROM flows_flowstat WHERE res = 1 AND ts < now() - make_interval(hours => %s)
            GROUP BY date_trunc('hour', ts), device_id, exporter, src, dst, proto, port, in_if, out_if""", [hours])
        merged = c.rowcount
        c.execute("DELETE FROM flows_flowstat WHERE res = 1 AND ts < now() - make_interval(hours => %s)", [hours])
        return merged, c.rowcount
