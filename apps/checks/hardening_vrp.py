"""Huawei VRP hardening checks (S-series and CloudEngine)."""
import re

from .config import child_has
from .ruleset import Hit, both, check, count_at_least, edge_switch, every, forbid, forbid_any, has, need, role_in, rule

F = ("huawei_vrp",)
NTP = has(r"^ntp-service unicast-server ")


check("HW-SSH1", "security", "medium", "SSH version 1 is accepted (Huawei)",
      "`ssh server compatible-ssh1x enable` allows the obsolete SSH v1 protocol.", "Disable SSHv1 compatibility.",
      "undo ssh server compatible-ssh1x", families=F, domain="access", topics=("crypto-strength", "mgmt-crypto"),
      fn=forbid(r"^ssh server compatible-ssh1x enable"))

check("HW-SSHCIPHER", "security", "medium", "Weak SSH algorithms allowed (Huawei)",
      "CBC ciphers, DES/3DES, MD5/SHA1 MACs and DH group 1 have known weaknesses.", "Allow only modern algorithms.",
      "ssh server cipher aes256_ctr aes128_ctr\nssh server hmac sha2_256\nssh server key-exchange dh_group14_sha256",
      families=F, domain="access", topics=("crypto-strength",),
      fn=forbid(r"^ssh (server|client) (cipher|hmac|key-exchange) .*(cbc|des\b|3des|md5|sha1\b|dh_group1\b)"))

check("HW-VTYACL", "security", "medium", "Remote login is open to any address (Huawei)",
      "VTY lines without an inbound ACL accept SSH from anywhere that can reach the switch.", "Restrict the VTY lines.",
      "acl 2000\n rule permit source <mgmt-subnet> <wildcard>\nuser-interface vty 0 4\n acl 2000 inbound", families=F, domain="access",
      topics=("mgmt-acl",), fn=every(r"^user-interface vty", r"^acl (ipv6 )?\S+ inbound", "VTY lines", na_if_none=False))


@rule("HW-IDLE", "security", "medium", "Idle timeout disabled or longer than 10 minutes (Huawei)",
      "A forgotten session stays logged in. PCI DSS asks for re-authentication after 15 minutes; CIS asks for 10.",
      "Set idle-timeout to 10 minutes or less.", "user-interface vty 0 4\n idle-timeout 10 0\nuser-interface con 0\n idle-timeout 10 0",
      families=F, domain="access", topics=("session-timeout",))
def hw_idle(ctx):
    bad = []
    for h, ch in ctx.cfg.blocks(r"^user-interface (con|vty|console)"):
        for c in ch:
            m = re.match(r"^idle-timeout (\d+)(?: (\d+))?", c)
            if m and (int(m.group(1)) * 60 + int(m.group(2) or 0) > 600 or (m.group(1) == "0" and (m.group(2) or "0") == "0")):
                bad.append(f"{h} ({c})")
    return [Hit("lines", "; ".join(bad))] if bad else []


check("HW-NOAUTH", "security", "critical", "A login line needs no authentication (Huawei)",
      "`authentication-mode none` gives a shell to anyone who reaches that line.", "Use AAA authentication on every line.",
      "user-interface con 0\n authentication-mode aaa", families=F, domain="aaa", topics=("default-creds",),
      fn=lambda ctx: [Hit(h, h) for h, ch in ctx.cfg.blocks(r"^user-interface ") if child_has(ch, r"^authentication-mode none")])

check("HW-VTYPASSWORD", "security", "medium", "Remote logins use a shared line password (Huawei)",
      "`authentication-mode password` means everyone shares one password and nothing records who logged in.", "Use AAA on the VTY lines.",
      "user-interface vty 0 4\n authentication-mode aaa", families=F, domain="aaa", topics=("central-aaa", "accounting"),
      fn=lambda ctx: [Hit(h, h) for h, ch in ctx.cfg.blocks(r"^user-interface vty") if child_has(ch, r"^authentication-mode password")])

check("HW-LOCALPW", "security", "high", "Local account passwords use reversible storage (Huawei)",
      "`password simple` stores the password in clear text and `password cipher` can be reversed. `irreversible-cipher` uses a one-way hash.",
      "Re-enter the passwords with irreversible-cipher.", "aaa\n local-user <user> password irreversible-cipher <password>",
      families=F, domain="aaa", topics=("credential-storage",),
      fn=lambda ctx: [Hit(m.group(1), f"local-user {m.group(1)} password {m.group(2)}") for c in ctx.cfg.all_lines(r"^local-user \S+ password (simple|cipher) ")
                      for m in [re.match(r"^local-user (\S+) password (simple|cipher)", c)]])

check("HW-LOCALTELNET", "security", "medium", "Local accounts may log in over Telnet (Huawei)",
      "`service-type telnet` lets the account use clear-text Telnet even if SSH is available.", "Remove telnet from the service types.",
      "aaa\n undo local-user <user> service-type telnet\n local-user <user> service-type ssh terminal", families=F, domain="access",
      topics=("mgmt-crypto",),
      fn=lambda ctx: [Hit(c.split()[1], c) for c in ctx.cfg.all_lines(r"^local-user \S+ service-type .*\btelnet\b")])

check("HW-AAA", "security", "medium", "No central authentication (Huawei)",
      "Without an authentication scheme using HWTACACS or RADIUS, administrators share local accounts.", "Authenticate through HWTACACS or RADIUS.",
      "hwtacacs-server template TAC\n hwtacacs-server authentication <ip>\naaa\n authentication-scheme default\n  authentication-mode hwtacacs local",
      families=F, domain="aaa", topics=("central-aaa",),
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^authentication-mode (hwtacacs|radius)") else [Hit("", "no authentication scheme uses HWTACACS or RADIUS")])

check("HW-ACCT", "security", "medium", "Administrator commands are not recorded (Huawei)",
      "Command recording or accounting sends what each administrator did to the AAA server.", "Record commands through HWTACACS.",
      "aaa\n recording-scheme REC\n  recording-mode hwtacacs TAC\n cmd recording-scheme REC", families=F, domain="aaa", topics=("accounting",),
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^(cmd recording-scheme|recording-scheme|accounting-mode (hwtacacs|radius))") else [Hit("", "no command recording or accounting")])


@rule("HW-SNMPACL", "security", "medium", "SNMP communities are not limited to known managers (Huawei)",
      "A community without an ACL answers anyone who can reach the switch.", "Bind an ACL to each community.",
      "acl 2001\n rule permit source <nms-ip> 0\nsnmp-agent community read cipher <string> acl 2001", families=F, domain="snmp",
      topics=("snmp-community", "mgmt-acl"), applies=has(r"^snmp-agent community "))
def hw_snmpacl(ctx):
    return [Hit(f"#{i + 1}", "community without an ACL") for i, l in enumerate(ctx.cfg.find(r"^snmp-agent community ")) if " acl " not in f"{l} "]


check("HW-SNMPRW", "security", "high", "An SNMP community allows writes (Huawei)",
      "A write community lets anyone who knows it change the configuration over SNMP.", "Remove it.", "undo snmp-agent community write <string>",
      families=F, domain="snmp", topics=("snmp-community", "least-privilege"), fn=forbid(r"^snmp-agent community write ", "write community"))

check("HW-SNMPV3PRIV", "security", "medium", "SNMPv3 group without encryption (Huawei)",
      "SNMPv3 groups should use `privacy` (authentication and encryption).", "Use privacy for every v3 group.",
      "snmp-agent group v3 <group> privacy", families=F, domain="snmp", topics=("snmp-v3",),
      fn=forbid(r"^snmp-agent group v3 \S+ (authentication|noauthentication)\b"))

check("HW-HTTP", "security", "medium", "Plain HTTP web management is enabled (Huawei)",
      "The web interface over HTTP sends the login in clear text.", "Use HTTPS only, or turn the web server off.",
      "undo http server enable\nhttp secure-server enable", families=F, domain="access", topics=("mgmt-crypto",), fn=forbid(r"^http server enable"))

check("HW-FTP", "security", "medium", "FTP server is enabled (Huawei)",
      "FTP sends credentials and files in clear text.", "Disable FTP; use SFTP or SCP.", "undo ftp server enable\nsftp server enable",
      families=F, domain="services", topics=("least-functionality", "mgmt-crypto"), fn=forbid(r"^ftp (ipv6 )?server enable"))

check("HW-NTPAUTH", "security", "medium", "NTP is not authenticated (Huawei)",
      "A spoofed NTP server can move the clock, breaking logs and certificates.", "Authenticate NTP.",
      "ntp-service authentication enable\nntp-service authentication-keyid 1 authentication-mode hmac-sha256 cipher <key>\nntp-service reliable authentication-keyid 1\nntp-service unicast-server <ntp-1> authentication-keyid 1",
      families=F, domain="logging", topics=("time-auth",), applies=NTP, fn=need(r"^ntp-service authentication enable", "`ntp-service authentication enable` is missing"))

check("HW-NTP2", "best_practice", "low", "Only one NTP server (Huawei)", "One time source is a single point of failure.",
      "Configure at least two NTP servers.", "ntp-service unicast-server <ntp-2>", families=F, domain="logging", topics=("time-sync", "availability"),
      applies=NTP, fn=count_at_least(r"^ntp-service unicast-server ", 2, "{found} NTP server(s)"))

check("HW-LOGSRC", "best_practice", "low", "Syslog has no fixed source interface (Huawei)",
      "A fixed source keeps messages identifiable in the SIEM.", "Set the log host source interface.", "info-center loghost source Vlanif99",
      families=F, domain="logging", topics=("logging-central", "mgmt-plane"), applies=has(r"^info-center loghost \d"),
      fn=need(r"^info-center loghost source ", "no `info-center loghost source`"))

check("HW-BANNER", "security", "low", "No login banner (Huawei)",
      "A banner states that access is restricted; many legal and audit frameworks require one.", "Add a login header.",
      'header login information "Authorised access only. Activity is logged."', families=F, domain="access", topics=("banner",),
      fn=need(r"^header (login|shell) ", "no `header login`"))

check("HW-STPOFF", "best_practice", "high", "Spanning tree is disabled (Huawei)",
      "With spanning tree off, a single looped cable brings the network down.", "Enable spanning tree.", "stp enable",
      families=F, switch_only=True, domain="l2", topics=("availability", "l2-edge"), fn=forbid(r"^(stp disable|undo stp enable)$"))

check("HW-STPROOT", "best_practice", "medium", "Core switch does not set its spanning-tree priority (Huawei)",
      "If the core does not set a low priority any switch can win the root election.", "Make the core the root.",
      "stp root primary", families=F, switch_only=True, domain="l2", topics=("availability", "l2-edge"), applies=role_in("core", "distribution"),
      fn=need(r"^stp (root primary|priority |instance \d+ (root primary|priority))", "no spanning-tree priority set"))

check("HW-DHCPSNOOP", "security", "medium", "DHCP snooping is off (Huawei)",
      "Without DHCP snooping, any user port can run a rogue DHCP server.", "Enable DHCP snooping and trust the uplinks.",
      "dhcp enable\ndhcp snooping enable\nvlan <user-vlan>\n dhcp snooping enable\ninterface <uplink>\n dhcp snooping trusted",
      families=F, switch_only=True, domain="l2", topics=("l2-spoofing",), applies=edge_switch,
      fn=need(r"^dhcp snooping enable", "`dhcp snooping enable` is missing"))

check("HW-ARPCHECK", "security", "low", "ARP and IP spoofing checks are off (Huawei)",
      "With DHCP snooping on, `arp anti-attack check user-bind` and `ip source check user-bind` drop forged ARP and IP traffic.",
      "Enable the checks on user VLANs or ports.", "vlan <user-vlan>\n arp anti-attack check user-bind enable\n ip source check user-bind enable",
      families=F, switch_only=True, domain="l2", topics=("l2-spoofing", "anti-spoofing"), applies=both(edge_switch, has(r"^dhcp snooping enable")),
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^(arp anti-attack check user-bind enable|ip source check user-bind enable)") else [Hit("", "no user-bind checks")])

check("HW-LOOPDETECT", "best_practice", "low", "Loop detection is off (Huawei)",
      "Loopback detection catches loops spanning tree cannot see, such as an unmanaged switch looped on itself.", "Enable loop detection.",
      "loopback-detect enable", families=F, switch_only=True, domain="l2", topics=("l2-edge", "availability"), applies=edge_switch,
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^(loopback-detect enable|loop-detection enable)") else [Hit("", "loop detection is not enabled")])

check("HW-OSPFAUTH", "security", "medium", "OSPF neighbours are not authenticated (Huawei)",
      "Without authentication any device on a routed segment can inject routes.", "Authenticate OSPF areas or interfaces.",
      "ospf 1\n area 0\n  authentication-mode hmac-sha256 1 cipher <key>", families=F, domain="routing", topics=("routing-auth",),
      applies=has(r"^ospf \d"),
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^(ospf )?authentication-mode (md5|hmac-md5|hmac-sha256|keychain)") else [Hit("", "no OSPF authentication configured")])


@rule("HW-BGPAUTH", "security", "medium", "BGP peers without authentication (Huawei)",
      "An unauthenticated BGP session can be reset or hijacked.", "Add a password (or keychain) to each peer.",
      "bgp <as>\n peer <ip> password cipher <secret>", families=F, domain="routing", topics=("routing-auth",), applies=has(r"^bgp \d"))
def hw_bgp(ctx):
    bad = []
    for _h, ch in ctx.cfg.blocks(r"^bgp \d"):
        peers = sorted({c.split()[1] for c in ch if re.match(r"^peer \S+ as-number ", c)})
        bad += [p for p in peers if not child_has(ch, rf"^peer {re.escape(p)} (password|keychain|tcp-ao) ")]
    return [Hit(p, f"peer {p}") for p in bad]


check("HW-TELNETCLIENT", "best_practice", "info", "Telnet client allowed from the switch (Huawei)",
      "Administrators can open clear-text Telnet sessions from the switch to other devices.", "Disable the Telnet client.",
      "undo telnet client enable", families=F, domain="access", topics=("mgmt-crypto",),
      fn=forbid_any(r"^telnet client enable"))
