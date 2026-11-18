"""Cisco version strings compared well enough for "is this at or past the first fixed release in its train"."""
import re


def vtuple(v):
    """'17.9.4a' -> (17, 9, 4, 'a'); '15.2(7)E8' -> (15, 2, 7, 'E', 8)"""
    parts = re.findall(r"\d+|[A-Za-z]+", v or "")
    return tuple(int(p) if p.isdigit() else p.lower() for p in parts)


def train(v):
    t = vtuple(v)
    if "(" in (v or ""):                 # classic IOS: 15.2(7)E8 -> train 15.2E
        letters = [p for p in t[3:] if isinstance(p, str)]
        return t[:2] + tuple(letters[:1])
    return t[:2]


def _cmp_key(t):
    return tuple((0, p) if isinstance(p, int) else (1, p) for p in t)


def at_or_after(version, fixed):
    return _cmp_key(vtuple(version)) >= _cmp_key(vtuple(fixed))


def fixed_status(version, fixed_list):
    """True = fixed, False = affected train and older, None = no data for this train."""
    for f in [x.strip() for x in fixed_list.split(",") if x.strip()]:
        if train(f) == train(version):
            return at_or_after(version, f)
    return None
