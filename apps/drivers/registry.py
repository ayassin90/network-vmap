from functools import lru_cache

from .base import FEATURES, LEVELS, Driver  # noqa: F401
from .catalog import OTHER, GenericSnmp
from .aoss import ArubaAOSS
from .arista import AristaEOS
from .aruba import ArubaCX
from .cisco import CiscoIOS, CiscoIOSXE, CiscoNXOS
from .fortiswitch import FortiSwitch
from .huawei import HuaweiVRP
from .juniper import JuniperJunos

NATIVE = [CiscoIOSXE, CiscoIOS, CiscoNXOS, ArubaCX, ArubaAOSS, HuaweiVRP, JuniperJunos, AristaEOS, FortiSwitch]
_ALL = [*NATIVE, *[d for d in OTHER if d.key not in {c.key for c in NATIVE}], GenericSnmp]


@lru_cache(maxsize=1)
def drivers():
    return {cls.key: cls() for cls in _ALL}


def get_driver(key):
    return drivers().get(key) or drivers()["generic_snmp"]


def choices():
    by_vendor = {}
    for d in drivers().values():
        tag = {"supported": "", "beta": " (beta)", "snmp": " (SNMP)", "planned": " (planned)"}[d.status]
        by_vendor.setdefault(d.vendor, []).append((d.key, d.label + tag))
    return list(by_vendor.items())


def detect_platform(sys_descr="", show_version=""):
    """Best guess from sysDescr or `show version` text, used by discovery."""
    t = (sys_descr + " " + show_version).lower()
    if "nx-os" in t or "nexus" in t:
        return "cisco_nxos"
    if "ios-xe" in t or "ios xe" in t or "cat9k" in t or "catalyst l3 switch software" in t:
        return "cisco_iosxe"
    if "ios xr" in t or "ios-xr" in t:
        return "cisco_iosxr"
    if "cisco ios" in t or "c2960" in t or "c3750" in t:
        return "cisco_ios"
    for hint, key in (("arubaos-cx", "aruba_aoscx"), ("aos-cx", "aruba_aoscx"), ("procurve", "aruba_aoss"), ("comware", "hp_comware"),
                      ("huawei", "huawei_vrp"), ("junos", "juniper_junos"), ("arista", "arista_eos"), ("os10", "dell_os10"),
                      ("extremexos", "extreme_exos"), ("switch engine", "extreme_exos"), ("voss", "extreme_voss"),
                      ("icx", "ruckus_icx"), ("fastiron", "ruckus_icx"), ("fortiswitch", "fortiswitch"), ("routeros", "mikrotik"),
                      ("edgeswitch", "ubiquiti"), ("netgear", "netgear"), ("alliedware", "allied"), ("omniswitch", "alcatel_aos"),
                      ("onyx", "nvidia_onyx"), ("cumulus", "nvidia_onyx"), ("zyxel", "zyxel"), ("jetstream", "tplink"),
                      ("d-link", "dlink"), ("ruijie", "ruijie"), ("zxr10", "zte")):
        if hint in t:
            return key
    return ""
