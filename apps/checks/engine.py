"""Run every check for one device and keep Findings in step: new problems open, fixed ones resolve."""
import re
from dataclasses import dataclass, field
from datetime import timedelta

from django.utils import timezone

from apps.inventory.models import Interface

from .config import Config, child_has
from .controls import SEV_WEIGHT
from .models import ComplianceResult, Finding, PostureResult, Standard
from .rules import RULES
from .ruleset import evaluate

RULE_BY_ID = {r.id: r for r in RULES}

WEIGHT = {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}


@dataclass
class Ctx:
    device: object
    cfg: Config
    interfaces: list
    family: str
    is_switch: bool = False
    extra: dict = field(default_factory=dict)


def run_all(device):
    snap = device.latest_config
    ifs = list(device.interfaces.all())
    if snap:
        ctx = Ctx(device, Config(snap.text), ifs, device.driver.family, any(i.mode in ("access", "trunk") for i in ifs))
        run_rules(ctx)
        run_standards(device, ctx.cfg)
    run_interface_checks(device, ifs)
    run_stp_checks(device)
    run_vlan_checks(device)
    run_health_checks(device)
    from apps.lifecycle.engine import run_lifecycle
    run_lifecycle(device)
    rescore(device)


def _upsert(device, category, check_id, key, severity, title, detail, recommendation="", remediation=""):
    now = timezone.now()
    f, created = Finding.objects.get_or_create(device=device, check_id=check_id, key=key[:120], defaults=dict(
        category=category, severity=severity, title=title, detail=detail, recommendation=recommendation, remediation=remediation))
    if not created:
        f.severity, f.title, f.detail, f.last_seen = severity, title, detail, now
        f.recommendation, f.remediation, f.category = recommendation, remediation, category
        if f.status == "resolved":
            f.status, f.resolved_at, f.first_seen = "open", None, now
        f.save()
    return f.pk


def _close(device, categories, keep_ids):
    Finding.objects.filter(device=device, category__in=categories, status="open").exclude(pk__in=keep_ids).update(
        status="resolved", resolved_at=timezone.now())


def run_rules(ctx):
    """Evaluate every built-in check for the device's family. Failures become findings; every outcome (pass, fail,
    not applicable) is kept in PostureResult for the hardening posture pages."""
    keep, results = [], {}
    for r in RULES:
        if ctx.family not in r.families:
            continue
        try:
            st, hits = evaluate(r, ctx)
        except Exception as exc:  # noqa: BLE001 - one broken rule must not stop the others
            st, hits = "na", []
            print(f"rule {r.id} failed: {exc}")
        results[r.id] = [st, "; ".join(h.detail for h in hits)[:400]]
        for h in hits:
            keep.append(_upsert(ctx.device, r.category, r.id, h.key, r.severity, r.title, h.detail, r.why + "\n\n" + r.fix, r.snippet))
    _close(ctx.device, ["security", "best_practice"], keep)
    PostureResult.objects.update_or_create(device=ctx.device, defaults={"results": results, "ran_at": timezone.now()})


def run_standards(device, cfg):
    keep = []
    for std in Standard.objects.filter(enabled=True).prefetch_related("rules"):
        if not std.applies_to(device):
            ComplianceResult.objects.filter(device=device, standard=std).delete()
            continue
        passed = failed = 0
        details = []
        for rule in std.rules.all():
            ok, missing = evaluate_rule(rule, cfg)
            details.append({"rule": rule.pk, "name": rule.name, "ok": ok, "missing": missing[:200], "severity": rule.severity,
                            "remediation": rule.remediation})
            if ok:
                passed += 1
            else:
                failed += 1
                where = f" in {len(missing)} places: " + ", ".join(missing[:8]) + ("…" if len(missing) > 8 else "") if missing else ""
                keep.append(_upsert(device, "compliance", f"STD-{rule.pk}", std.name[:60], rule.severity,
                                    f"{std.name}: {rule.name}", f"Not met{where}", rule.explanation, rule.remediation))
        ComplianceResult.objects.update_or_create(device=device, standard=std, defaults={
            "passed": passed, "failed": failed, "details": details, "ran_at": timezone.now()})
    _close(device, ["compliance"], keep)


def evaluate_rule(rule, cfg):
    """(ok, [places that fail])"""
    import re
    try:
        rx = re.compile(rule.pattern)
    except re.error:
        return False, ["invalid regular expression"]
    if rule.kind == "present":
        return any(rx.search(l.strip()) for l in cfg.lines), []
    if rule.kind == "absent":
        bad = [l.strip() for l in cfg.lines if rx.search(l.strip())]
        return not bad, bad
    sections = cfg.blocks(rule.section or ".")
    if rule.applies_if:
        sections = [(h, ch) for h, ch in sections if child_has(ch, rule.applies_if)]
    if rule.kind == "section":
        bad = [h for h, ch in sections if not any(rx.search(c) for c in ch)]
    else:
        bad = [h for h, ch in sections if any(rx.search(c) for c in ch)]
    return not bad, bad


# ------------------------------------------------------------------ interface health
def run_interface_checks(device, ifs=None):
    from apps.core.models import AppSetting
    ifs = ifs if ifs is not None else list(device.interfaces.all())
    err_min = AppSetting.get_int("if_error_threshold", 100)
    util_warn = AppSetting.get_int("if_util_warn", 80)
    keep = []
    by_short = {}
    for i in Interface.objects.filter(device__in=device.neighbors.exclude(remote_device=None).values("remote_device")).select_related("device"):
        by_short[(i.device_id, i.short.lower())] = i
    nbr = {n.local_interface.lower(): n for n in device.neighbors.all()}

    def add(i, cid, sev, title, detail, rec, fix=""):
        keep.append(_upsert(device, "interface", cid, i.short, sev, title, detail, rec, fix))

    for i in ifs:
        if not i.is_physical and not i.name.lower().startswith("port-channel"):
            continue
        if i.status == "err-disabled":
            add(i, "IF-ERRDIS", "high", "Port is err-disabled",
                f"{i.short} ({i.description or 'no description'}) was shut by the switch for a protection reason.",
                "Find the cause with `show interfaces status err-disabled` and `show errdisable recovery`, fix it, then bounce the port.",
                f"interface {i.name}\n shutdown\n no shutdown")
        if not i.oper_up:
            continue
        if i.half_duplex:
            add(i, "IF-HALF", "high", "Port runs at half duplex",
                f"{i.short} is up at {i.speed or '?'} half duplex. Half duplex causes collisions and slow, unreliable traffic.",
                "Modern devices should be full duplex. Set both ends to auto/auto (or both to the same fixed speed and duplex). "
                "A half-duplex link usually means one side is hard-coded and the other is on auto.",
                f"interface {i.name}\n speed auto\n duplex auto")
        if i.late_collisions:
            add(i, "IF-LATECOLL", "high", "Late collisions (duplex mismatch symptom)",
                f"{i.short}: {i.late_collisions:,} late collisions.", "Late collisions almost always mean a duplex mismatch or a cable that is too long. Check both ends.")
        elif i.collisions and not i.half_duplex:
            add(i, "IF-COLL", "medium", "Collisions on a full-duplex port",
                f"{i.short}: {i.collisions:,} collisions.", "Full duplex links should never collide. Check the far-end settings.")
        if i.crc >= err_min or (i.crc and i.err_delta):
            growing = i.err_delta > 0
            add(i, "IF-CRC", "high" if growing else "medium", "CRC errors" + (" (still increasing)" if growing else ""),
                f"{i.short}: {i.crc:,} CRC errors" + (f", {i.err_delta:,} new since last poll." if growing else " (counter since last clear)."),
                "CRC errors point to a physical problem: a bad cable or patch lead, a dirty or failing optic, or electrical interference. "
                "Replace the cable or clean/swap the optic, then clear the counters (`clear counters " + i.short + "`) and watch.")
        elif i.in_errors >= err_min:
            add(i, "IF-INERR", "medium", "Input errors", f"{i.short}: {i.in_errors:,} input errors (runts {i.runts:,}, giants {i.giants:,}, frame {i.frame:,}, overrun {i.overrun:,}).",
                "Look at which counter is rising. Giants mean an MTU mismatch, runts a duplex problem, overruns a busy CPU or ASIC.")
        if i.out_errors >= err_min:
            add(i, "IF-OUTERR", "medium", "Output errors", f"{i.short}: {i.out_errors:,} output errors.",
                "Output errors are usually collisions or a failing transceiver on this side.")
        if i.out_drops >= max(1000, err_min * 10):
            add(i, "IF-DROPS", "medium", "Output drops (congestion)", f"{i.short}: {i.out_drops:,} packets dropped on output.",
                "The port had more traffic than it could send, often from a faster link feeding a slower one or microbursts. "
                "Consider more bandwidth (a port-channel or a faster link) or QoS to protect important traffic.")
        if i.giants >= err_min:
            add(i, "IF-GIANTS", "low", "Oversized frames (MTU mismatch)", f"{i.short}: {i.giants:,} giants.",
                "The far end sends frames larger than this port accepts. Make the MTU the same on both ends.")
        u = i.utilization
        if u is not None and u >= util_warn:
            add(i, "IF-UTIL", "high" if u >= 95 else "medium", f"High utilisation ({u}%)",
                f"{i.short} is at {u}% of {i.speed_mbps:,} Mb/s (in {i.in_rate_bps / 1e6:.1f} Mb/s, out {i.out_rate_bps / 1e6:.1f} Mb/s).",
                "Sustained high load causes drops and latency. Add capacity or move traffic.")
        n = nbr.get(i.short.lower())
        if n and i.speed_mbps and i.speed_mbps <= 100 and (n.kind in ("switch", "router") or i.mode == "trunk"):
            add(i, "IF-SLOWUPLINK", "medium", "Switch link running at low speed",
                f"{i.short} to {n.remote_name} {n.remote_port} is at {i.speed_mbps} Mb/s.",
                "A link between network devices at 100 Mb/s or less is usually a bad cable, a wrong optic or a hard-coded speed.")
        if n and n.remote_device_id:
            far = by_short.get((n.remote_device_id, n.remote_port.lower()))
            if far and far.oper_up:
                if i.speed_mbps and far.speed_mbps and i.speed_mbps != far.speed_mbps:
                    add(i, "IF-SPEEDMM", "high", "Speed mismatch with the neighbour",
                        f"{i.short} is {i.speed_mbps} Mb/s but {n.remote_name} {far.short} is {far.speed_mbps} Mb/s.",
                        "Both ends of a link must agree. Set both to auto, or both to the same fixed speed.")
                if i.duplex in ("half", "full") and far.duplex in ("half", "full") and i.duplex != far.duplex:
                    add(i, "IF-DUPLEXMM", "high", "Duplex mismatch with the neighbour",
                        f"{i.short} is {i.duplex} duplex but {n.remote_name} {far.short} is {far.duplex} duplex.",
                        "A duplex mismatch causes late collisions and very poor throughput. Set both ends the same (auto/auto preferred).")
                if i.mode == far.mode == "routed" and i.mtu and far.mtu and i.mtu != far.mtu:
                    add(i, "IF-MTUMM", "medium", "MTU mismatch on a routed link",
                        f"{i.short} has MTU {i.mtu}, {n.remote_name} {far.short} has MTU {far.mtu}.",
                        "OSPF and IS-IS neighbours stay stuck (OSPF in EXSTART/EXCHANGE) and large packets are dropped. Set the same IP MTU on both ends.")
                if {i.mode, far.mode} == {"trunk", "access"}:
                    add(i, "IF-MODEMM", "high", "Trunk on one side, access on the other",
                        f"{i.short} is {i.mode}, {n.remote_name} {far.short} is {far.mode}.",
                        "Only one VLAN will pass and spanning tree may block. Make both ends trunks (or both access).")
                elif i.mode == far.mode == "trunk" and i.native_vlan and far.native_vlan and i.native_vlan != far.native_vlan:
                    add(i, "IF-NATIVEMM", "high", "Native VLAN mismatch",
                        f"{i.short} native VLAN {i.native_vlan}, {n.remote_name} {far.short} native VLAN {far.native_vlan}.",
                        "Untagged traffic leaks between two VLANs. Set the same native VLAN on both ends.")
    # flapping, PoE and optics
    hour_ago = (timezone.now() - timedelta(hours=1)).isoformat()
    for i in ifs:
        recent = [t for t in (i.flap_log or []) if t > hour_ago]
        if len(recent) >= 3:
            add(i, "IF-FLAP", "high" if len(recent) >= 10 else "medium", f"Port is flapping ({len(recent)} changes in the last hour)",
                f"{i.short} ({i.description or 'no description'}) went up and down {len(recent)} times in the last hour.",
                "A flapping port is usually a failing cable, NIC or optic, a device that keeps rebooting, or a power-saving NIC. "
                "It also causes spanning-tree topology changes that flush MAC tables network-wide. Check the cable and the device; "
                "enable PortFast on edge ports so flaps do not trigger topology changes.")
        if i.poe_oper.lower() == "faulty":
            add(i, "IF-POEFAULT", "medium", "PoE fault on port", f"{i.short}: the switch detected a PoE fault and is not powering the device.",
                "Usually a damaged cable, a device that draws more than its class, or a non-standard powered device. Try another cable "
                "or port, then cycle PoE on the port.", f"interface {i.name}\n power inline never\n power inline auto")
    poe = (device.facts or {}).get("poe") or {}
    if poe.get("available") and poe.get("used") is not None and poe["used"] / poe["available"] >= 0.9:
        keep.append(_upsert(device, "interface", "IF-POEBUDGET", "poe", "medium", "PoE budget nearly used",
                            f"{poe['used']:.0f} W of {poe['available']:.0f} W in use ({100 * poe['used'] / poe['available']:.0f}%).",
                            "New phones or access points may not power up. Move some powered devices or add a power supply."))
    for o in device.optics.all():
        h = o.health
        if h in ("alarm", "warning"):
            what = ", ".join(f"{k} {v}" for k, v in (o.flags or {}).items()) or f"rx {o.rx} dBm"
            keep.append(_upsert(device, "interface", "IF-OPTIC", o.interface, "high" if h == "alarm" else "medium",
                                f"Optical power {'out of range' if h == 'alarm' else 'near its limit'}",
                                f"{o.interface} ({o.pid or 'optic'}): receive {o.rx} dBm, transmit {o.tx} dBm ({what}).",
                                "Low receive light means a dirty or damaged fibre or connector, a too-long run, or a failing optic at the far end. "
                                "Clean both ends, check patch panels, then swap the optic. Fix this before it turns into CRC errors or a dead link."))
    _close(device, ["interface"], keep)
    rescore(device)


def expand_vlans(text):
    t = re.sub(r"\s", "", (text or "")).upper()
    if t in ("", "ALL"):
        return set(range(1, 4095))
    if t == "NONE":
        return set()
    out = set()
    for part in t.split(","):
        b = part.split("-")
        try:
            if len(b) == 2:
                out.update(range(int(b[0]), int(b[1]) + 1))
            elif b[0]:
                out.add(int(b[0]))
        except ValueError:
            continue
    return out


def compact_vlans(vs):
    vs, out = sorted(vs), []
    i = 0
    while i < len(vs):
        j = i
        while j + 1 < len(vs) and vs[j + 1] == vs[j] + 1:
            j += 1
        out.append(str(vs[i]) if i == j else f"{vs[i]}-{vs[j]}")
        i = j + 1
    return ",".join(out)


BAD_ENV = ("fail", "faulty", "bad", "critical", "shutdown", "not functioning", "no input", "power loss", "abnormal")


def run_health_checks(device):
    keep = []
    if device.cpu is not None and device.cpu >= 80:
        keep.append(_upsert(device, "health", "HL-CPU", "", "high" if device.cpu >= 95 else "medium", f"High CPU ({device.cpu}%)",
                            f"The 5-minute CPU average is {device.cpu}%.",
                            "A busy control plane responds slowly to routing, STP and management, and drops can follow. Common causes: "
                            "a broadcast storm or loop, too much traffic punted to the CPU (ARP, IP options, logging to console), "
                            "a routing churn, or a bug. Run `show processes cpu sorted` to see what is busy."))
    if device.mem_pct is not None and device.mem_pct >= 90:
        keep.append(_upsert(device, "health", "HL-MEM", "", "high" if device.mem_pct >= 97 else "medium", f"Memory almost full ({device.mem_pct}%)",
                            f"{device.mem_pct}% of processor memory is in use.",
                            "Running out of memory can crash processes or stop new sessions. Look for a memory leak "
                            "(`show processes memory sorted`), large routing tables or many sessions; a reload frees memory but plan the fix."))
    env = device.env or {}
    for f in env.get("fans", []):
        if any(b in f["status"].lower() for b in BAD_ENV):
            keep.append(_upsert(device, "health", "HL-FAN", f["name"], "high", f"Fan failure: {f['name']}",
                                f"{f['name']} reports {f['status']}.", "Replace the fan (tray) soon: the switch may overheat and shut down.",))
    for p in env.get("psus", []):
        if any(b in p["status"].lower() for b in BAD_ENV):
            keep.append(_upsert(device, "health", "HL-PSU", p["name"], "high", f"Power supply problem: {p['name']}",
                                f"Power supply {p['name']} {p.get('pid', '')} reports {p['status']}.",
                                "The switch is running without power redundancy. Check the cable, the PDU and the circuit, then the supply itself."))
    ts = (env.get("temp_state") or "").upper()
    if ts in ("YELLOW", "RED", "WARNING", "CRITICAL"):
        keep.append(_upsert(device, "health", "HL-TEMP", "", "high" if ts in ("RED", "CRITICAL") else "medium",
                            f"Temperature {ts.lower()} ({device.temp_c} °C)",
                            f"The switch reports {device.temp_c} °C, state {ts}.",
                            "Check the room or cabinet cooling, blocked vents and fans. Hot switches shorten hardware life and may shut down."))
    _close(device, ["health"], keep)


def run_stp_checks(device):
    keep = []
    for s in device.stp.all():
        if s.is_root and device.role == "access":
            keep.append(_upsert(device, "stp", "STP-ROOTACC", f"vlan {s.vlan}", "high", f"Access switch is the root bridge for VLAN {s.vlan}",
                                f"{device.hostname} is root for VLAN {s.vlan} (priority {s.bridge_prio}). Traffic for this VLAN is pulled "
                                "through this switch, usually over slower links.",
                                "Make the core (or distribution) switches the primary and secondary root for every VLAN, and stop access "
                                "switches from winning the election.",
                                f"! on the core:\nspanning-tree vlan {s.vlan} root primary\n! on this switch:\nno spanning-tree vlan {s.vlan} priority"))
        elif s.is_root and s.bridge_prio == 32768 + s.vlan:
            keep.append(_upsert(device, "stp", "STP-ROOTDEF", f"vlan {s.vlan}", "medium", f"Root bridge for VLAN {s.vlan} was elected by default",
                                f"{device.hostname} is root for VLAN {s.vlan} only because it has the lowest MAC address; nobody set a priority.",
                                "Set the root explicitly so a new or replaced switch can never take over.", f"spanning-tree vlan {s.vlan} root primary"))
        secs = s.tc_seconds
        if s.tc_count and s.tc_count >= 100 and secs is not None and secs < 3600:
            keep.append(_upsert(device, "stp", "STP-TCN", f"vlan {s.vlan}", "medium", f"Frequent spanning-tree topology changes in VLAN {s.vlan}",
                                f"{s.tc_count} topology changes, the last one {s.tc_ago} ago" + (f", from {s.tc_from}" if s.tc_from else "") + ".",
                                "Every topology change flushes MAC tables and floods traffic. The usual cause is an edge port without PortFast "
                                "(each PC reboot counts) or a flapping link. Fix the port named above.",
                                f"interface {s.tc_from or '<port>'}\n spanning-tree portfast" if s.tc_from else ""))
    _close(device, ["stp"], keep)


def run_vlan_checks(device):
    from apps.inventory.models import Interface, Vlan
    keep = []
    ifs = {i.short.lower(): i for i in device.interfaces.all()}
    for n in device.neighbors.exclude(remote_device=None):
        mine = ifs.get(n.local_interface.lower())
        far = Interface.objects.filter(device_id=n.remote_device_id, short__iexact=n.remote_port).first()
        if not (mine and far and mine.mode == far.mode == "trunk" and mine.oper_up):
            continue
        a, b = expand_vlans(mine.trunk_vlans), expand_vlans(far.trunk_vlans)
        only_me, only_far = a - b, b - a
        if only_me or only_far:
            parts = []
            if only_me:
                parts.append(f"allowed here only: {compact_vlans(only_me)}")
            if only_far:
                parts.append(f"allowed on {n.remote_name.split('.')[0]} {far.short} only: {compact_vlans(only_far)}")
            keep.append(_upsert(device, "vlan", "VLAN-TRUNKMM", mine.short, "medium", "Allowed VLANs differ between the two ends of a trunk",
                                f"{mine.short} to {n.remote_name.split('.')[0]} {far.short}: " + "; ".join(parts) + ".",
                                "A VLAN allowed on only one end is silently dropped on that link. Make both allowed lists the same.",
                                f"interface {mine.name}\n switchport trunk allowed vlan {compact_vlans(a | b) if len(a | b) < 4094 else 'all'}"))
    defined = set(Vlan.objects.filter(device=device).values_list("vid", flat=True))
    if defined:
        missing = {}
        for i in ifs.values():
            if i.mode == "access" and i.access_vlan.isdigit() and int(i.access_vlan) not in defined and i.admin_up:
                missing.setdefault(int(i.access_vlan), []).append(i.short)
        for v, ports in missing.items():
            keep.append(_upsert(device, "vlan", "VLAN-UNDEF", f"vlan {v}", "high", f"Ports use VLAN {v}, which does not exist on this switch",
                                f"{', '.join(ports[:10])} are in VLAN {v}, but VLAN {v} is not defined, so these ports pass no traffic.",
                                "Create the VLAN (and allow it on the uplinks), or move the ports to the right VLAN.", f"vlan {v}\n name <name>"))
        names = {}
        for vid, name in Vlan.objects.exclude(name="").values_list("vid", "name"):
            names.setdefault(vid, {}).setdefault(name.upper(), 0)
            names[vid][name.upper()] += 1
        for v in Vlan.objects.filter(device=device).exclude(name=""):
            counts = names.get(v.vid, {})
            if len(counts) > 1 and v.vid not in (1,):
                common = max(counts, key=counts.get)
                if v.name.upper() != common and counts[v.name.upper()] < counts[common]:
                    keep.append(_upsert(device, "vlan", "VLAN-NAME", f"vlan {v.vid}", "low", f"VLAN {v.vid} has a different name here",
                                        f"Named {v.name} on {device.hostname}; most switches call it {common}.",
                                        "Consistent names avoid mistakes when someone picks a VLAN by name.", f"vlan {v.vid}\n name {common}"))
    _close(device, ["vlan"], keep)


def posture_score(results, open_ids):
    """Severity-weighted share of applicable checks that pass (an accepted risk counts as passing)."""
    total = got = 0
    for rid, (st, _d) in results.items():
        r = RULE_BY_ID.get(rid)
        w = SEV_WEIGHT.get(r.severity, 0) if r else 0
        if not w or st not in ("pass", "fail"):
            continue
        total += w
        if st == "pass" or rid not in open_ids:
            got += w
    return round(100 * got / total) if total else None


def rescore(device):
    open_f = list(Finding.objects.filter(device=device, status="open").values_list("category", "severity", "check_id"))
    health = sum(WEIGHT[s] for c, s, _i in open_f if c in ("interface", "stp", "vlan", "health"))
    results = list(ComplianceResult.objects.filter(device=device))
    posture = PostureResult.objects.filter(device=device).first()
    if posture and device.configs.exists():
        device.security_score = posture_score(posture.results, {i for c, _s, i in open_f if c in ("security", "best_practice")})
    else:
        sec = sum(WEIGHT[s] for c, s, _i in open_f if c in ("security", "best_practice"))
        device.security_score = max(0, 100 - sec) if device.configs.exists() else None
    device.health_score = max(0, 100 - health)
    device.compliance_score = round(sum(r.score for r in results) / len(results)) if results else None
    device.save(update_fields=["security_score", "health_score", "compliance_score"])
