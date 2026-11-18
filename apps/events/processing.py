"""Parse syslog / trap datagrams, attach them to devices, apply event rules."""
import logging
import re
import time
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from .models import Event, EventRule

log = logging.getLogger("vmap.events")
MNEMONIC = re.compile(r"%([A-Z0-9_]+(?:-[A-Z0-9_]+)?-\d-[A-Z0-9_]+)")
IFACE = re.compile(r"(?:Interface|interface|port|Port)\s+([A-Za-z\-]*\d+(?:/\d+)*(?:\.\d+)?)")
_ipmap = {"at": 0, "map": {}}


def device_for(ip):
    from apps.inventory.models import Device, Interface
    if time.time() - _ipmap["at"] > 60:
        m = {d: pk for d, pk in Device.objects.values_list("mgmt_ip", "pk")}
        for ipcidr, dev in Interface.objects.exclude(ip="").values_list("ip", "device_id"):
            m.setdefault(ipcidr.split("/")[0], dev)
        _ipmap.update(at=time.time(), map=m)
    return _ipmap["map"].get(ip)


def parse_syslog(data, source):
    text = data.decode("utf-8", errors="replace").strip()
    sev, fac = 6, None
    m = re.match(r"^<(\d{1,3})>(.*)$", text, re.S)
    if m:
        pri = int(m.group(1))
        sev, fac, text = pri % 8, pri // 8, m.group(2)
    mn = MNEMONIC.search(text)
    if mn:
        lvl = re.search(r"-(\d)-", mn.group(1))
        if lvl:
            sev = int(lvl.group(1))
    iface = IFACE.search(text)
    return Event(source=source, kind="syslog", severity=sev, facility=fac, mnemonic=mn.group(1) if mn else "",
                 interface=iface.group(1) if iface else "", message=text[:4000])


TRAP_NAMES = {"1.3.6.1.6.3.1.1.5.1": ("coldStart", 5), "1.3.6.1.6.3.1.1.5.2": ("warmStart", 5), "1.3.6.1.6.3.1.1.5.3": ("linkDown", 4),
              "1.3.6.1.6.3.1.1.5.4": ("linkUp", 5), "1.3.6.1.6.3.1.1.5.5": ("authenticationFailure", 4)}


def parse_trap(data, source):
    from pyasn1.codec.ber import decoder
    from pysnmp.proto import api
    ver = int(api.decodeMessageVersion(data))
    pm = api.PROTOCOL_MODULES[ver]
    msg, _ = decoder.decode(data, asn1Spec=pm.Message())
    pdu = pm.apiMessage.get_pdu(msg)
    binds = [(str(o), v.prettyPrint()) for o, v in pm.apiPDU.get_varbinds(pdu)] if ver != api.SNMP_VERSION_1 else \
        [(str(o), v.prettyPrint()) for o, v in pm.apiTrapPDU.get_varbinds(pdu)]
    trap_oid = next((v for o, v in binds if o == "1.3.6.1.6.3.1.1.4.1.0"), "")
    if ver == api.SNMP_VERSION_1:
        generic = int(pm.apiTrapPDU.get_generic_trap(pdu))
        trap_oid = f"1.3.6.1.6.3.1.1.5.{generic + 1}" if generic < 6 else str(pm.apiTrapPDU.get_enterprise(pdu))
    name, sev = TRAP_NAMES.get(trap_oid, (trap_oid, 5))
    ifindex = next((v for o, v in binds if o.startswith("1.3.6.1.2.1.2.2.1.1.")), "")
    ifname = next((v for o, v in binds if o.startswith("1.3.6.1.2.1.31.1.1.1.1.") or o.startswith("1.3.6.1.2.1.2.2.1.2.")), "")
    rest = ", ".join(f"{o}={v}" for o, v in binds if not o.startswith(("1.3.6.1.2.1.1.3.0", "1.3.6.1.6.3.1.1.4.1.0")))[:1500]
    ev = Event(source=source, kind="trap", severity=sev, mnemonic=f"TRAP-{name}"[:80], interface=ifname,
               message=f"{name} {ifname or ('ifIndex ' + ifindex if ifindex else '')} {rest}".strip())
    ev._ifindex = ifindex
    return ev


def process(events):
    """Save a batch and run the rules. Called by the receiver about once a second."""
    from apps.inventory.models import Interface
    if not events:
        return
    rules = list(EventRule.objects.filter(enabled=True))
    for ev in events:
        ev.device_id = device_for(ev.source)
        if ev.kind == "trap" and getattr(ev, "_ifindex", "") and ev.device_id and not ev.interface:
            i = Interface.objects.filter(device_id=ev.device_id, if_index=int(ev._ifindex)).first()
            if i:
                ev.interface = i.short
                ev.message = ev.message.replace(f"ifIndex {ev._ifindex}", i.short)
        ev.rule = next((r for r in rules if r.matches(ev)), None)
    Event.objects.bulk_create(events)
    for ev in events:
        if not ev.rule or not ev.device_id:
            continue
        try:
            act(ev)
        except Exception:  # noqa: BLE001
            log.exception("event rule failed")


def act(ev):
    from apps.inventory.models import Device, Interface, short_ifname
    r = ev.rule
    dev = Device.objects.get(pk=ev.device_id)
    if r.action == "flap" and ev.interface:
        i = Interface.objects.filter(device=dev).filter(Q(short__iexact=short_ifname(ev.interface)) | Q(name__iexact=ev.interface)).first()
        if i and re.search(r"down|linkDown", ev.message):
            now = timezone.now()
            log = [t for t in (i.flap_log or []) if t > (now - timedelta(hours=24)).isoformat()]
            if not log or log[-1] < (now - timedelta(seconds=10)).isoformat():     # LINK, LINEPROTO and the trap are one flap
                i.flap_log = log + [now.isoformat()]
                i.save(update_fields=["flap_log"])
    elif r.action == "collect":
        from apps.jobs.models import Job
        from apps.jobs.services import enqueue_collect
        recent = Job.objects.filter(device=dev, kind="collect", created_at__gte=timezone.now() - timedelta(minutes=2)).exists()
        if not recent:
            enqueue_collect(dev, "syslog")
    elif r.action == "alert":
        from apps.alerts.engine import event_alert
        event_alert(dev, ev, r)
