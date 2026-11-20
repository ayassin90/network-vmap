from django import template

from apps.checks.controls import FRAMEWORKS, control_title

register = template.Library()
ORDER = ["cisv8", "nist", "iso", "pci", "csf", "cis"]


@register.filter
def fw_short(fw):
    return FRAMEWORKS.get(fw, {}).get("short", fw)


@register.filter
def ordered_controls(controls, only=""):
    """[(fw, short name, [ids])] in a stable framework order; `only` limits to one framework."""
    return [(fw, FRAMEWORKS[fw]["short"], controls[fw]) for fw in ORDER if fw in controls and (not only or fw == only)]


@register.simple_tag
def ctl_title(fw, cid):
    return control_title(fw, cid)


@register.filter
def pct_tone(v):
    if v is None:
        return "muted"
    return "ok" if v >= 85 else ("warn" if v >= 60 else "bad")


@register.filter
def domain_label(key):
    from apps.checks.controls import DOMAINS
    return DOMAINS.get(key, key)
