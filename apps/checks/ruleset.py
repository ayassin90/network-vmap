"""The rule framework shared by every built-in check.

A check function receives a Ctx (device, parsed config, interfaces, family) and returns:
    None          the check does not apply to this device (shown as N/A on the posture page)
    []            the device passes
    [Hit, ...]    the device fails; each Hit is one finding (key = the object it is about)

    @rule("IOS-AUX", "security", "medium", "AUX port allows logins", why, fix, snippet,
          families=("cisco_ios",), domain="access", topics=("mgmt-acl",), cis="1.2.3")
    def aux(ctx): ...

Most hardening checks are simple, so they are built from the helpers below:
    check(... , fn=need(r"^ip ssh version 2", "`ip ssh version 2` is missing"))
"""
import ipaddress
import re
from dataclasses import dataclass, field

from .config import child_has

RULES = []
NA = None


@dataclass
class Hit:
    key: str = ""
    detail: str = ""


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    families: tuple
    title: str
    why: str
    fix: str
    snippet: str
    fn: object
    switch_only: bool = False
    domain: str = "access"
    topics: tuple = ()
    cis: str = ""
    applies: object = None
    controls: dict = field(default_factory=dict)


def rule(id, category, severity, title, why, fix, snippet="", families=("cisco_ios",), switch_only=False, domain="access",
         topics=(), cis="", applies=None):
    def deco(fn):
        add(Rule(id, category, severity, tuple(families), title, why, fix, snippet, fn, switch_only, domain, tuple(topics), cis, applies))
        return fn
    return deco


def check(id, category, severity, title, why, fix, snippet="", families=("cisco_ios",), switch_only=False, domain="access",
          topics=(), cis="", applies=None, fn=None):
    add(Rule(id, category, severity, tuple(families), title, why, fix, snippet, fn, switch_only, domain, tuple(topics), cis, applies))


def add(r):
    from .controls import controls_for
    if any(x.id == r.id for x in RULES):
        raise ValueError(f"duplicate check id {r.id}")
    r.controls = controls_for(r.topics, r.cis)
    RULES.append(r)


def evaluate(r, ctx):
    """('pass'|'fail'|'na', [Hit])"""
    if ctx.family not in r.families:
        return "na", []
    if r.switch_only and not ctx.is_switch:
        return "na", []
    if r.applies is not None and not r.applies(ctx):
        return "na", []
    hits = r.fn(ctx)
    if hits is None:
        return "na", []
    return ("fail" if hits else "pass"), list(hits)


# ------------------------------------------------------------------ small text helpers
def ports(lst, limit=12):
    lst = list(lst)
    return ", ".join(lst[:limit]) + (f" and {len(lst) - limit} more" if len(lst) > limit else "")


def short(h):
    return h.split(" ", 1)[1] if " " in h else h


def num(text, default=None):
    m = re.search(r"\d+", text or "")
    return int(m.group()) if m else default


# ------------------------------------------------------------------ check builders
def need(rx, msg):
    """A top-level line matching rx must exist."""
    def f(ctx):
        return [] if ctx.cfg.has(rx) else [Hit("", msg)]
    return f


def need_any(rx, msg):
    """A line matching rx must exist anywhere (top level or inside a section)."""
    def f(ctx):
        return [] if ctx.cfg.all_lines(rx) else [Hit("", msg)]
    return f


def forbid(rx, msg=None):
    """No top-level line may match rx; one finding per offending line."""
    def f(ctx):
        return [Hit(l[:60], msg or f"`{l}`") for l in ctx.cfg.find(rx)]
    return f


def forbid_any(rx, msg=None, limit=20):
    """No line anywhere may match rx (one finding listing them)."""
    def f(ctx):
        bad = ctx.cfg.all_lines(rx)
        return [Hit("", (msg + ": " if msg else "") + "; ".join(f"`{b}`" for b in bad[:limit]) + (" …" if len(bad) > limit else ""))] if bad else []
    return f


def every(header_rx, need_rx, what="", when=None, unless=None, na_if_none=True):
    """Every section whose header matches (and that contains `when`, and not `unless`) must contain need_rx."""
    def f(ctx):
        secs = [(h, ch) for h, ch in ctx.cfg.blocks(header_rx) if (when is None or child_has(ch, when)) and (unless is None or not child_has(ch, unless))]
        if not secs:
            return NA if na_if_none else []
        bad = [h for h, ch in secs if not child_has(ch, need_rx)]
        return [Hit("sections", f"{len(bad)} of {len(secs)} {what or 'sections'}: {ports(bad, 8)}")] if bad else []
    return f


def none_has(header_rx, bad_rx, what="", when=None):
    """No section whose header matches may contain bad_rx."""
    def f(ctx):
        secs = [(h, ch) for h, ch in ctx.cfg.blocks(header_rx) if when is None or child_has(ch, when)]
        if not secs:
            return NA
        bad = [h for h, ch in secs if child_has(ch, bad_rx)]
        return [Hit("sections", f"{len(bad)} {what or 'sections'}: {ports(bad, 8)}")] if bad else []
    return f


def count_at_least(rx, n, msg):
    def f(ctx):
        found = len(ctx.cfg.find(rx))
        return [] if found >= n else [Hit("", msg.format(found=found))]
    return f


def max_value(rx, limit, msg, default_ok=True, zero_bad=False):
    """Lines matching rx (with a number captured in group 1) must not exceed limit."""
    def f(ctx):
        vals = [(l, int(m.group(1))) for l in ctx.cfg.all_lines(rx) for m in [re.search(rx, l)] if m]
        if not vals:
            return [] if default_ok else [Hit("", msg.format(v="not set"))]
        bad = [(l, v) for l, v in vals if v > limit or (zero_bad and v == 0)]
        return [Hit("", msg.format(v=", ".join(f"`{l}`" for l, _ in bad[:4])))] if bad else []
    return f


# ------------------------------------------------------------------ applicability helpers
def has(rx):
    return lambda ctx: ctx.cfg.has(rx)


def has_any(rx):
    return lambda ctx: bool(ctx.cfg.all_lines(rx))


def lacks(rx):
    return lambda ctx: not ctx.cfg.has(rx)


def role_in(*roles):
    return lambda ctx: ctx.device.role in roles


def role_not(*roles):
    return lambda ctx: ctx.device.role not in roles


def both(*preds):
    return lambda ctx: all(p(ctx) for p in preds)


def either(*preds):
    return lambda ctx: any(p(ctx) for p in preds)


def edge_switch(ctx):
    """An access-layer switch with user ports (where DHCP snooping, port security and 802.1X belong)."""
    return ctx.is_switch and ctx.device.role not in ("core", "router", "datacenter", "firewall") and any(i.mode == "access" for i in ctx.interfaces)


# ------------------------------------------------------------------ Cisco-style interface helpers
def ios_access(ctx):
    return [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^switchport mode access") and not child_has(ch, r"^shutdown$")]


def ios_trunks(ctx):
    return [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^switchport mode trunk")]


L3_SKIP = re.compile(r"^interface (Loopback|Null|Tunnel|NVE|nve|mgmt|Management|Embedded-Service|BDI|Virtual-Template)", re.I)
PUBLIC_DESC = re.compile(r"\b(isp|internet|inet|wan|transit|upstream|provider|dia|public|outside|untrust(ed)?)\b", re.I)


def ios_l3(ctx, include_skip=False):
    out = []
    for h, ch in ctx.cfg.blocks(r"^interface "):
        if child_has(ch, r"^shutdown$") or not child_has(ch, r"^ip(v4)? address \d"):
            continue
        if not include_skip and L3_SKIP.search(h):
            continue
        out.append((h, ch))
    return out


def is_public(addr):
    try:
        return ipaddress.ip_address(addr.split("/")[0]).is_global
    except ValueError:
        return False


def outside_ifaces(ctx):
    """Interfaces that face the Internet or a provider: a public address or a description like 'ISP', 'WAN', 'Internet'."""
    out = []
    for h, ch in ios_l3(ctx):
        desc = " ".join(c for c in ch if c.startswith("description "))
        ips = [m.group(1) for c in ch for m in [re.match(r"^ip(?:v4)? address (\d+\.\d+\.\d+\.\d+)", c)] if m]
        if PUBLIC_DESC.search(desc) or any(is_public(a) for a in ips):
            out.append((h, ch))
    return out


def has_outside(ctx):
    return bool(outside_ifaces(ctx))


# ------------------------------------------------------------------ FortiOS / FortiSwitchOS nested config
def fos(ctx):
    """Parse `config / edit / set / next / end` into nested dicts, cached on the context."""
    if "fos" in ctx.extra:
        return ctx.extra["fos"]
    root = {"kind": "config", "sets": {}, "configs": {}, "edits": {}}
    stack = [root]
    for raw in ctx.cfg.text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("config "):
            node = {"kind": "config", "sets": {}, "configs": {}, "edits": {}}
            stack[-1]["configs"][line[7:].strip()] = node
            stack.append(node)
        elif line.startswith("edit "):
            if stack[-1]["kind"] == "edit":
                stack.pop()
            node = {"kind": "edit", "sets": {}, "configs": {}, "edits": {}}
            stack[-1]["edits"][line[5:].strip().strip('"')] = node
            stack.append(node)
        elif line == "next":
            if stack[-1]["kind"] == "edit":
                stack.pop()
        elif line == "end":
            while len(stack) > 1 and stack[-1]["kind"] == "edit":
                stack.pop()
            if len(stack) > 1:
                stack.pop()
        elif line.startswith(("set ", "unset ")):
            parts = line.split(None, 2)
            if len(parts) >= 2:
                stack[-1]["sets"][parts[1]] = (parts[2] if len(parts) > 2 else "") if parts[0] == "set" else None
    ctx.extra["fos"] = root
    return root


def fos_node(ctx, path):
    """fos_node(ctx, "system global") -> the node, or None."""
    return fos(ctx)["configs"].get(path)


def fos_get(node, key, default=None):
    if not node:
        return default
    v = node["sets"].get(key, default)
    return v.strip('"') if isinstance(v, str) else v
