"""The baseline standard created on first start. Edit it freely on the Config standards page."""
BASELINE = {
    "name": "Cisco campus baseline",
    "description": "A sensible starting point for Catalyst switches: management-plane hardening, logging, time, and edge-port protection. Adjust to your own policy.",
    "platforms": "cisco_ios,cisco_iosxe",
    "rules": [
        ("Password encryption on", "present", r"^service password-encryption$", "", "", "medium", "service password-encryption", "Hides passwords in the configuration and backups."),
        ("Log timestamps with milliseconds", "present", r"^service timestamps log datetime msec", "", "", "low", "service timestamps log datetime msec localtime show-timezone", "Makes logs from different devices line up."),
        ("SSH version 2", "present", r"^ip ssh version 2$", "", "", "medium", "ip ssh version 2", "SSH v1 is weak."),
        ("AAA enabled", "present", r"^aaa new-model$", "", "", "medium", "aaa new-model", "Central authentication and accounting."),
        ("HTTP server off", "absent", r"^ip http (secure-)?server$", "", "", "high", "no ip http server\nno ip http secure-server", "The web UI has been the target of critical attacks."),
        ("Syslog server", "present", r"^logging host \S+", "", "", "medium", "logging host <syslog-ip>", "Keeps logs off the box."),
        ("Two NTP servers", "present", r"^ntp server \S+", "", "", "medium", "ntp server <ntp-1>\nntp server <ntp-2>", "Correct time on every log line."),
        ("Login banner", "present", r"^banner (login|motd)", "", "", "low", "banner login ^Authorised access only.^", "Legal notice before login."),
        ("Rapid spanning tree", "present", r"^spanning-tree mode (rapid-pvst|mst)$", "", "", "medium", "spanning-tree mode rapid-pvst", "Fast convergence."),
        ("Smart Install off", "present", r"^no vstack$", "", "", "high", "no vstack", "Closes TCP 4786."),
        ("VTY: SSH only", "section", r"^transport input ssh$", r"^line vty", "", "high", "line vty 0 15\n transport input ssh", "No Telnet."),
        ("VTY: access-class", "section", r"^access-class \S+ in$", r"^line vty", "", "medium", "line vty 0 15\n access-class MGMT in", "Only management subnets may log in."),
        ("Access ports: PortFast", "section", r"^spanning-tree portfast", r"^interface ", r"^switchport mode access$", "low", "spanning-tree portfast", "Clients get a link immediately."),
        ("Access ports: BPDU Guard", "section", r"^spanning-tree bpduguard enable$", r"^interface ", r"^switchport mode access$", "medium", "spanning-tree bpduguard enable", "Stops loops from user ports."),
        ("Trunks: no DTP", "section", r"^switchport nonegotiate$", r"^interface ", r"^switchport mode trunk$", "low", "switchport nonegotiate", "Trunks do not negotiate."),
        ("Trunks: native VLAN not 1", "section", r"^switchport trunk native vlan (?!1$)\d+$", r"^interface ", r"^switchport mode trunk$", "medium", "switchport trunk native vlan 999", "Prevents VLAN hopping."),
    ],
}


def ensure_baseline():
    from .models import Standard, StandardRule
    if Standard.objects.exists():
        return
    b = BASELINE
    s = Standard.objects.create(name=b["name"], description=b["description"], platforms=b["platforms"])
    for i, (name, kind, pattern, section, applies, sev, fix, why) in enumerate(b["rules"], start=1):
        StandardRule.objects.create(standard=s, name=name, kind=kind, pattern=pattern, section=section, applies_if=applies, severity=sev,
                                    remediation=fix, explanation=why, order=i)
