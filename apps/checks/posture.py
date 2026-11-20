"""Hardening posture: roll the per-device check outcomes (PostureResult) up by domain, by framework and by control.

Status of one check on one device:
    pass       the device meets it
    fail       an open finding
    accepted   it fails, but an operator accepted the risk (counts as compliant, shown separately)
    na         does not apply to this device (no access ports, no BGP, …)
"""
from collections import defaultdict

from .controls import CONTROLS, DOMAINS, FRAMEWORKS, SEV_WEIGHT, TOPICS, control_title, sorted_controls
from .models import Finding
from .rules import RULES

RULE_BY_ID = {r.id: r for r in RULES}
FW_ORDER = ["cisv8", "nist", "iso", "pci", "csf", "cis"]


def pct(ok, bad):
    return round(100 * ok / (ok + bad)) if ok + bad else None


def _accepted(device_ids):
    return set(Finding.objects.filter(device_id__in=device_ids, status="accepted", category__in=("security", "best_practice"))
               .values_list("device_id", "check_id"))


def _status(st, dev_id, rid, accepted):
    return "accepted" if st == "fail" and (dev_id, rid) in accepted else st


def coverage():
    """How many checks map to each control of each framework (independent of any device)."""
    cov = {fw: defaultdict(list) for fw in FRAMEWORKS}
    for r in RULES:
        for fw, ids in r.controls.items():
            for cid in ids:
                cov[fw][cid].append(r.id)
    return cov


def device_view(device):
    pr = getattr(device, "posture", None)
    try:
        results = pr.results if pr else {}
    except Exception:  # noqa: BLE001 - RelatedObjectDoesNotExist
        results = {}
    accepted = _accepted([device.pk])
    rows = []
    for rid, (st, detail) in results.items():
        r = RULE_BY_ID.get(rid)
        if not r:
            continue
        rows.append({"r": r, "status": _status(st, device.pk, rid, accepted), "detail": detail})
    rank = {"fail": 0, "accepted": 1, "pass": 2, "na": 3}
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    rows.sort(key=lambda x: (list(DOMAINS).index(x["r"].domain) if x["r"].domain in DOMAINS else 99, rank[x["status"]], sev[x["r"].severity], x["r"].id))
    domains = []
    for key, label in DOMAINS.items():
        rs = [x for x in rows if x["r"].domain == key]
        if not rs:
            continue
        c = _count(rs)
        domains.append({"key": key, "label": label, "rows": rs, **c, "pct": pct(c["pass"] + c["accepted"], c["fail"])})
    frameworks = []
    for fw in FW_ORDER:
        rs = [x for x in rows if x["r"].controls.get(fw)]
        if not rs:
            continue
        c = _count(rs)
        failing = list({cid for x in rs if x["status"] == "fail" for cid in x["r"].controls[fw]})
        frameworks.append({"key": fw, "name": FRAMEWORKS[fw]["name"], "short": FRAMEWORKS[fw]["short"], **c,
                           "pct": pct(c["pass"] + c["accepted"], c["fail"]), "failing_controls": sorted_controls(fw, failing)})
    return {"posture_rows": rows, "posture_domains": domains, "posture_frameworks": frameworks, "posture_counts": _count(rows),
            "posture_ran": pr.ran_at if pr else None}


def _count(rows):
    c = {"pass": 0, "fail": 0, "accepted": 0, "na": 0}
    for x in rows:
        c[x["status"]] += 1
    c["applicable"] = c["pass"] + c["fail"] + c["accepted"]
    return c


def fleet(posture_results, fw):
    """Roll-up for a set of PostureResult rows (with .device), focused on one framework."""
    prs = list(posture_results)
    accepted = _accepted([p.device_id for p in prs])
    checks = {}
    fw_tot = {f: {"pass": 0, "fail": 0, "accepted": 0} for f in FW_ORDER}
    dom_tot = {d: {"pass": 0, "fail": 0, "accepted": 0} for d in DOMAINS}
    for p in prs:
        for rid, (st, _d) in p.results.items():
            r = RULE_BY_ID.get(rid)
            if not r:
                continue
            s = _status(st, p.device_id, rid, accepted)
            c = checks.setdefault(rid, {"r": r, "pass": 0, "fail": 0, "accepted": 0, "na": 0, "fail_devices": []})
            c[s] += 1
            if s == "fail":
                c["fail_devices"].append(p.device)
            if s == "na":
                continue
            for f in r.controls:
                if f in fw_tot:
                    fw_tot[f][s] += 1
            if r.domain in dom_tot:
                dom_tot[r.domain][s] += 1
    for c in checks.values():
        c["pct"] = pct(c["pass"] + c["accepted"], c["fail"])
    cov = coverage()[fw]
    controls = []
    for cid in sorted_controls(fw, list(cov)):
        rids = cov[cid]
        ok = sum(checks[i]["pass"] + checks[i]["accepted"] for i in rids if i in checks)
        bad = sum(checks[i]["fail"] for i in rids if i in checks)
        acc = sum(checks[i]["accepted"] for i in rids if i in checks)
        devs = {d.pk: d for i in rids if i in checks for d in checks[i]["fail_devices"]}
        rows = sorted((checks[i] for i in rids if i in checks), key=lambda c: (-c["fail"], c["r"].id))
        controls.append({"id": cid, "title": control_title(fw, cid), "checks": rids, "n_checks": len(rids), "ok": ok, "fail": bad, "accepted": acc,
                         "pct": pct(ok, bad), "fail_devices": sorted(devs.values(), key=lambda d: d.hostname), "rows": rows,
                         "evaluated": ok + bad > 0})
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    worst = sorted((c for c in checks.values() if c["fail"]), key=lambda c: (sev[c["r"].severity], -c["fail"]))[:15]
    frameworks = [{"key": f, "name": FRAMEWORKS[f]["name"], "short": FRAMEWORKS[f]["short"], "pct": pct(t["pass"] + t["accepted"], t["fail"]),
                   "n_controls": len(coverage()[f])} for f, t in fw_tot.items()]
    domains = [{"key": d, "label": DOMAINS[d], "pct": pct(t["pass"] + t["accepted"], t["fail"]), **t} for d, t in dom_tot.items() if sum(t.values())]
    devices = sorted(({"d": p.device, "score": p.device.security_score, "fail": sum(1 for rid, (st, _x) in p.results.items()
                                                                                     if st == "fail" and (p.device_id, rid) not in accepted)} for p in prs),
                     key=lambda x: (x["score"] if x["score"] is not None else 101))
    return {"fw": fw, "framework": FRAMEWORKS[fw], "frameworks": frameworks, "controls": controls, "domains": domains, "worst": worst,
            "devices": devices, "n_devices": len(prs),
            "n_failing_controls": sum(1 for c in controls if c["fail"]), "n_controls": len(controls),
            "n_evaluated": sum(1 for c in controls if c["evaluated"])}


def topic_rows():
    """Objectives with their control mappings, for the catalogue's 'how mapping works' table."""
    return [{"key": k, "label": v["label"], "maps": {fw: v.get(fw, []) for fw in FW_ORDER if fw != "cis"},
             "n": sum(1 for r in RULES if k in r.topics)} for k, v in TOPICS.items()]


__all__ = ["device_view", "fleet", "coverage", "topic_rows", "RULE_BY_ID", "FW_ORDER", "CONTROLS", "SEV_WEIGHT"]
