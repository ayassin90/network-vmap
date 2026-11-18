RULES = [
    ("Configuration changed", r"%SYS-5-CONFIG_I|%HPE_CONFIG|configuration changed", 7, "collect", "info",
     "Someone changed the configuration. VMap collects the device at once, so the change appears in the config history within a minute."),
    ("Link up / down", r"%LINK-3-UPDOWN|%LINEPROTO-5-UPDOWN|linkDown|linkUp|Link status changed", 7, "flap", "info",
     "Counted towards flap detection on the interface; not alerted one by one."),
    ("Port err-disabled", r"%PM-4-ERR_DISABLE|err-disable", 7, "alert", "high",
     "The switch shut a port to protect itself (BPDU Guard, port security, link flap, storm control). The message says why."),
    ("Spanning-tree protection triggered", r"%SPANTREE-2-|BLOCK_BPDUGUARD|LOOPGUARD|ROOTGUARD|%SPANTREE-7-RECV_1Q_NON", 7, "alert", "high",
     "A port received spanning-tree frames it should not (a switch or a loop on an edge port)."),
    ("Routing neighbour down", r"%OSPF-5-ADJCHG.*(Down|to INIT)|%DUAL-5-NBRCHANGE.*down|%BGP-5-ADJCHANGE.*Down|%BGP-3-NOTIFICATION", 7, "alert", "high",
     "A routing adjacency went down: traffic may be taking another path, or not flowing at all."),
    ("Power, fan or temperature", r"%PLATFORM_ENV|%ENVIRONMENT|%ENVMON|%PLATFORM-.*-(FAN|PEM|TEMP)|%POWER_SUPPLIES|%ILPOWER-3", 4, "alert", "high",
     "A hardware environment alarm (power supply, fan, temperature) or a PoE controller fault."),
    ("Memory or process problem", r"%SYS-2-MALLOCFAIL|%SYS-3-CPUHOG|%SYS-2-|Traceback", 3, "alert", "high",
     "The device reports a memory allocation failure, a CPU hog or a software traceback."),
    ("Failed logins", r"%SEC_LOGIN-4-LOGIN_FAILED|%SSH-5-SSH2_USERAUTH.*failed|authentication failed", 7, "alert", "medium",
     "Failed logins. Many in a row can be password guessing."),
    ("Duplicate address or MAC flapping", r"%IP-4-DUPADDR|%SW_MATM-4-MACFLAP_NOTIF|%ARP-4-DUPLICATE", 7, "alert", "medium",
     "Two devices claim the same IP, or a MAC moves between ports (often a loop)."),
    ("Device reloaded", r"%SYS-5-RESTART|%SYS-5-RELOAD|coldStart|warmStart", 7, "alert", "medium", "The device restarted or is about to."),
]


def ensure_rules():
    from .models import EventRule
    if EventRule.objects.exists():
        return
    for i, (name, pattern, sev, action, asev, why) in enumerate(RULES, start=1):
        EventRule.objects.create(name=name, pattern=pattern, max_severity=sev, action=action, alert_severity=asev, explanation=why, order=i * 10)
