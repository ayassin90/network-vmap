"""Render a template (or ad-hoc lines) for one device, and mark lines the running configuration already has."""
from django.template import Context, Engine

ENGINE = Engine(autoescape=False, libraries={}, builtins=["django.template.defaulttags", "django.template.defaultfilters"])


def device_context(device, variables):
    ifs = list(device.interfaces.all())
    phys = [i for i in ifs if i.is_physical]
    return {
        "device": device, "vars": variables or {},
        "interfaces": {"all": phys, "access": [i for i in phys if i.mode == "access"], "trunk": [i for i in phys if i.mode == "trunk"],
                       "routed": [i for i in phys if i.mode == "routed"], "unused": [i for i in phys if i.status == "notconnect" and i.mode == "access"],
                       "svi": [i for i in ifs if i.name.lower().startswith("vlan")]},
        "vlans": list(device.vlans.all()),
    }


def render(body, device, variables):
    text = ENGINE.from_string(body).render(Context(device_context(device, variables)))
    lines = [l.rstrip() for l in text.splitlines()]
    return "\n".join(l for l in lines if l.strip()) + "\n"


def already_present(config, device):
    """Global and interface-level lines that the latest saved configuration already contains (no-ops)."""
    snap = device.latest_config
    if not snap:
        return []
    have_global = {l.strip() for l in snap.text.splitlines() if l and not l.startswith(" ")}
    sections, cur = {}, None
    for l in snap.text.splitlines():
        if l and not l.startswith(" "):
            cur = l.strip()
            sections.setdefault(cur, set())
        elif cur and l.strip():
            sections[cur].add(l.strip())
    out, ctx = [], None
    for line in config.splitlines():
        s = line.strip()
        if not s:
            continue
        if not line.startswith(" "):
            ctx = s if s.startswith(("interface ", "line ", "router ", "vlan ")) and s in sections else None
            if not ctx and s in have_global:
                out.append(s)
            continue
        if ctx and s in sections.get(ctx, set()):
            out.append(f"{ctx} / {s}")
    return out
