"""HPE Aruba hardening checks: AOS-CX and AOS-S (ProCurve)."""
import re

from .config import child_has
from .ruleset import NA, Hit, both, check, count_at_least, edge_switch, forbid, has, need, ports, role_in, rule, short

CX = ("aruba_aoscx",)
OS = ("aruba_aoss",)


# ================================================================== AOS-CX
def cx_access(ctx):
    return [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface \d+/\d+/\d+$") if child_has(ch, r"^vlan access ") and not child_has(ch, r"^shutdown$")]


check("CX-NOPASS", "security", "critical", "A local account has no password (AOS-CX)",
      "AOS-CX ships with an `admin` account and no password. An account line without a password means anyone can log in with that name.",
      "Set a password on every account.", "user admin group administrators password plaintext <password>",
      families=CX, domain="aaa", topics=("default-creds",), fn=forbid(r"^user \S+ group \S+$"))

check("CX-MGMTVRF", "security", "low", "Management services listen on the data VRF (AOS-CX)",
      "SSH, HTTPS and SNMP on the default VRF are reachable from every user VLAN with routing. Keep them on the management VRF.",
      "Run management services on the mgmt VRF only.", "no ssh server vrf default\nssh server vrf mgmt\nno https-server vrf default\nhttps-server vrf mgmt",
      families=CX, domain="access", topics=("mgmt-plane", "mgmt-acl"), fn=forbid(r"^(ssh server|https-server|snmp-server) vrf default$"))

check("CX-RESTRW", "security", "medium", "REST API allows configuration changes (AOS-CX)",
      "`https-server rest access-mode read-write` lets the REST API change the configuration. Allow it only for automation that needs it.",
      "Use read-only REST unless required.", "https-server rest access-mode read-only", families=CX, domain="access",
      topics=("least-functionality", "least-privilege"), fn=forbid(r"^https-server rest access-mode read-write"))

check("CX-SSHCIPHER", "security", "medium", "Weak SSH algorithms allowed (AOS-CX)",
      "CBC ciphers, 3DES and MD5/SHA1 MACs have known weaknesses.", "Allow only modern algorithms.",
      "ssh ciphers aes256-gcm@openssh.com aes256-ctr\nssh macs hmac-sha2-256 hmac-sha2-512", families=CX, domain="access",
      topics=("crypto-strength",), fn=forbid(r"^ssh (ciphers|macs|key-exchange-algorithms) .*(cbc|3des|md5|hmac-sha1\b|group1-sha1)"))

check("CX-AAAACCT", "security", "medium", "Administrator actions are not accounted (AOS-CX)",
      "Accounting sends every command and session to the AAA server: the audit trail of who changed what.", "Enable accounting.",
      "aaa accounting all-mgmt default start-stop group tacacs", families=CX, domain="aaa", topics=("accounting",),
      fn=need(r"^aaa accounting all-mgmt ", "no `aaa accounting all-mgmt`"))

check("CX-AAAAUTHZ", "security", "medium", "Commands are not authorised per user (AOS-CX)",
      "Command authorisation lets the TACACS+ server permit or deny each command by role.", "Authorise commands.",
      "aaa authorization commands default group tacacs none", families=CX, domain="aaa", topics=("authorization",),
      applies=has(r"^tacacs-server host "), fn=need(r"^aaa authorization commands ", "no `aaa authorization commands`"))


@rule("CX-AAASERVER", "security", "high", "AAA uses a server group with no servers (AOS-CX)",
      "Login authentication names TACACS+ or RADIUS, but no server of that type is defined.", "Define the servers or fix the method list.",
      "tacacs-server host <ip> key plaintext <key> vrf mgmt", families=CX, domain="aaa", topics=("central-aaa",),
      applies=has(r"^aaa authentication login default group"))
def cx_aaa_server(ctx):
    t = " ".join(ctx.cfg.find(r"^aaa authentication login "))
    out = []
    if re.search(r"\btacacs\b", t) and not ctx.cfg.has(r"^tacacs-server host "):
        out.append(Hit("tacacs", "TACACS+ used but no tacacs-server host"))
    if re.search(r"\bradius\b", t) and not ctx.cfg.has(r"^radius-server host "):
        out.append(Hit("radius", "RADIUS used but no radius-server host"))
    return out


check("CX-LOCKOUT", "security", "medium", "Accounts are not locked after failed logins (AOS-CX)",
      "Without a login-attempt limit an attacker can try passwords without limit.", "Lock out after repeated failures.",
      "aaa authentication limit-login-attempts 5 lockout-time 900", families=CX, domain="aaa", topics=("lockout",),
      fn=need(r"^aaa authentication limit-login-attempts ", "no `aaa authentication limit-login-attempts`"))


@rule("CX-SESSION", "security", "medium", "CLI sessions stay open for 30 minutes (AOS-CX)",
      "AOS-CX closes idle CLI sessions after 30 minutes by default. PCI DSS asks for 15 and CIS for 10.", "Set a shorter session timeout.",
      "session-timeout 10", families=CX, domain="access", topics=("session-timeout",))
def cx_session(ctx):
    vals = [int(m.group(1)) for l in ctx.cfg.find(r"^session-timeout \d+") for m in [re.match(r"^session-timeout (\d+)", l)]]
    return [] if vals and 0 < vals[0] <= 10 else [Hit("", f"session-timeout is {vals[0] if vals else '30 (default)'} minutes")]


check("CX-PWPOLICY", "security", "low", "No password complexity policy (AOS-CX)",
      "Without a complexity policy short local passwords are accepted.", "Enable password complexity with a 12-character minimum.",
      "password complexity\n    minimum-length 12\n    enable", families=CX, domain="aaa", topics=("password-policy",),
      fn=need(r"^password complexity", "no `password complexity` policy"))

check("CX-SNMPV3", "security", "low", "SNMP v2c is used without SNMPv3 (AOS-CX)",
      "Community strings travel in clear text. SNMPv3 adds authentication and encryption.", "Move monitoring to SNMPv3.",
      "snmpv3 user nms auth sha auth-pass plaintext <auth> priv aes priv-pass plaintext <priv>", families=CX, domain="snmp",
      topics=("snmp-v3",), applies=has(r"^snmp-server community "), fn=need(r"^snmpv3 user \S+ .*priv aes", "no SNMPv3 user with AES"))

check("CX-SNMPV3WEAK", "security", "medium", "SNMPv3 user without SHA and AES (AOS-CX)",
      "SNMPv3 users should authenticate with SHA and encrypt with AES; MD5 and DES are obsolete.", "Recreate the user with SHA and AES.",
      "snmpv3 user <user> auth sha auth-pass plaintext <auth> priv aes priv-pass plaintext <priv>", families=CX, domain="snmp",
      topics=("snmp-v3", "crypto-strength"), fn=lambda ctx: [Hit(l.split()[2], f"user {l.split()[2]}") for l in ctx.cfg.find(r"^snmpv3 user \S+")
                                                             if re.search(r"auth md5", l) or not re.search(r"priv aes", l)])

check("CX-NTPAUTH", "security", "medium", "NTP is not authenticated (AOS-CX)",
      "A spoofed NTP server can move the clock, breaking logs and certificates.", "Authenticate NTP.",
      "ntp authentication\nntp authentication-key 1 sha1 plaintext <key> trusted\nntp server <ntp-1> key 1 iburst",
      families=CX, domain="logging", topics=("time-auth",), applies=has(r"^ntp server "),
      fn=need(r"^ntp authentication$", "`ntp authentication` is not enabled"))

check("CX-NTP2", "best_practice", "low", "Only one NTP server (AOS-CX)", "One time source is a single point of failure.",
      "Configure at least two NTP servers.", "ntp server <ntp-2> iburst", families=CX, domain="logging", topics=("time-sync", "availability"),
      applies=has(r"^ntp server "), fn=count_at_least(r"^ntp server ", 2, "{found} NTP server(s)"))

check("CX-STP", "best_practice", "high", "Spanning tree is not enabled (AOS-CX)",
      "Spanning tree is off by default on AOS-CX. A single looped cable then brings the whole network down.", "Enable spanning tree.",
      "spanning-tree\nspanning-tree mode mstp", families=CX, switch_only=True, domain="l2", topics=("availability", "l2-edge"),
      fn=need(r"^spanning-tree$", "`spanning-tree` is not enabled"))

check("CX-STPROOT", "best_practice", "medium", "Core switch does not set its spanning-tree priority (AOS-CX)",
      "If the core does not set a low priority any switch can win the root election.", "Make the core the root.",
      "spanning-tree priority 0", families=CX, switch_only=True, domain="l2", topics=("availability", "l2-edge"),
      applies=role_in("core", "distribution"), fn=need(r"^spanning-tree (instance \d+ )?priority ", "no spanning-tree priority set"))

check("CX-DHCPSNOOP", "security", "medium", "DHCP snooping is off (AOS-CX)",
      "Without DHCP snooping, any user port can run a rogue DHCP server.", "Enable DHCPv4 snooping and trust the uplinks.",
      "dhcpv4-snooping\nvlan <user-vlans>\n    dhcpv4-snooping\ninterface <uplink>\n    dhcpv4-snooping trust",
      families=CX, switch_only=True, domain="l2", topics=("l2-spoofing",), applies=edge_switch,
      fn=need(r"^dhcpv4-snooping$", "`dhcpv4-snooping` is not enabled"))

check("CX-ARPINSPECT", "security", "low", "ARP inspection is off (AOS-CX)",
      "Dynamic ARP inspection drops forged ARP replies on user VLANs, stopping ARP spoofing.", "Enable ARP inspection on user VLANs.",
      "vlan <user-vlan>\n    arp inspection", families=CX, switch_only=True, domain="l2", topics=("l2-spoofing",),
      applies=both(edge_switch, has(r"^dhcpv4-snooping$")),
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^arp inspection$") else [Hit("", "no VLAN has `arp inspection`")])

check("CX-PORTACCESS", "security", "medium", "User ports accept any device (AOS-CX)",
      "Access ports without 802.1X, MAC authentication or port security let anyone plug in.", "Use port-access authentication (or port security).",
      "interface <port>\n    aaa authentication port-access dot1x authenticator\n        enable\n    aaa authentication port-access mac-auth\n        enable",
      families=CX, switch_only=True, domain="l2", topics=("nac", "l2-spoofing"), applies=edge_switch,
      fn=lambda ctx: (lambda secs, bad: NA if not secs else ([Hit("ports", f"{len(bad)} of {len(secs)} access ports: {ports(bad)}")] if bad else []))(
          cx_access(ctx), [short(h) for h, ch in cx_access(ctx) if not child_has(ch, r"^(aaa authentication port-access|port-access)")]))

check("CX-OSPFAUTH", "security", "medium", "OSPF neighbours are not authenticated (AOS-CX)",
      "Without authentication any device on a routed segment can inject routes.", "Authenticate OSPF.",
      "interface <if>\n    ip ospf authentication message-digest\n    ip ospf message-digest-key 1 md5 plaintext <key>",
      families=CX, domain="routing", topics=("routing-auth",), applies=has(r"^router ospf "),
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^(ip ospf authentication|area \S+ authentication)") else [Hit("", "no OSPF authentication configured")])

check("CX-BGPAUTH", "security", "medium", "BGP sessions without authentication (AOS-CX)",
      "An unauthenticated BGP session can be reset or hijacked.", "Add a password to each neighbour.",
      "router bgp <as>\n    neighbor <ip> password plaintext <secret>", families=CX, domain="routing", topics=("routing-auth",),
      applies=has(r"^router bgp "),
      fn=lambda ctx: [Hit(n, f"neighbour {n}") for _h, ch in ctx.cfg.blocks(r"^router bgp ")
                      for n in sorted({c.split()[1] for c in ch if re.match(r"^neighbor \S+ remote-as", c)})
                      if not child_has(ch, rf"^neighbor {re.escape(n)} password ")])


# ================================================================== AOS-S
check("AOSS-NOSSH", "security", "high", "SSH is disabled (AOS-S)",
      "With `no ip ssh` the switch can only be managed over Telnet or the web interface.", "Enable SSH.", "ip ssh",
      families=OS, domain="access", topics=("mgmt-crypto",), fn=forbid(r"^no ip ssh$"))

check("AOSS-SSHCIPHER", "security", "medium", "Weak SSH algorithms allowed (AOS-S)",
      "CBC ciphers, 3DES and MD5/SHA1 MACs have known weaknesses.", "Remove them.",
      "no ip ssh cipher aes128-cbc\nno ip ssh cipher 3des-cbc\nno ip ssh mac hmac-md5", families=OS, domain="access", topics=("crypto-strength",),
      fn=forbid(r"^ip ssh (cipher|mac) .*(cbc|3des|md5|hmac-sha1-96)"))

check("AOSS-AUTHMGR", "security", "medium", "Management access is open to any address (AOS-S)",
      "Without `ip authorized-managers`, SSH, web and SNMP management answer any host that can reach the switch.",
      "Restrict management to your management subnets.", "ip authorized-managers <mgmt-subnet> 255.255.255.0 access manager",
      families=OS, domain="access", topics=("mgmt-acl",), fn=need(r"^ip authorized-managers ", "no `ip authorized-managers`"))


@rule("AOSS-IDLE", "security", "medium", "Idle sessions never time out (AOS-S)",
      "AOS-S keeps idle console, SSH and Telnet sessions open forever by default.", "Close idle sessions after 10 minutes.",
      "console idle-timeout 600\nconsole idle-timeout serial-usb 600", families=OS, domain="access", topics=("session-timeout",))
def aoss_idle(ctx):
    vals = [int(m.group(1)) for l in ctx.cfg.find(r"^console idle-timeout \d+") for m in [re.match(r"^console idle-timeout (\d+)", l)]]
    return [] if vals and 0 < vals[0] <= 600 else [Hit("", f"console idle-timeout is {vals[0] if vals else '0 (never)'} seconds")]


check("AOSS-AAASSH", "security", "medium", "No central authentication for SSH (AOS-S)",
      "Without TACACS+ or RADIUS for SSH logins, administrators share the local manager password.", "Authenticate SSH through AAA.",
      "tacacs-server host <ip> key <key>\naaa authentication ssh login tacacs local\naaa authentication ssh enable tacacs local",
      families=OS, domain="aaa", topics=("central-aaa",), fn=need(r"^aaa authentication ssh login (tacacs|radius|peap-mschapv2)", "SSH logins use local passwords only"))

check("AOSS-ACCT", "security", "medium", "Administrator actions are not accounted (AOS-S)",
      "Command and exec accounting send what each administrator did to the AAA server.", "Enable accounting.",
      "aaa accounting commands stop-only tacacs\naaa accounting exec start-stop tacacs", families=OS, domain="aaa", topics=("accounting",),
      fn=need(r"^aaa accounting (commands|exec) ", "no `aaa accounting commands`"))


@rule("AOSS-PWLEN", "security", "medium", "No minimum password length (AOS-S)",
      "Without a minimum length short manager and operator passwords are accepted. PCI DSS asks for 12 characters.", "Set a 12-character minimum.",
      "password minimum-length 12", families=OS, domain="aaa", topics=("password-policy",))
def aoss_pwlen(ctx):
    vals = [int(m.group(1)) for l in ctx.cfg.find(r"^password minimum-length \d+") for m in [re.match(r"^password minimum-length (\d+)", l)]]
    return [] if vals and vals[0] >= 12 else [Hit("", f"minimum length is {vals[0] if vals else 'not set'}")]


check("AOSS-LOCKOUT", "security", "medium", "Accounts are not locked after failed logins (AOS-S)",
      "Without a lockout delay an attacker can keep trying passwords.", "Lock out after repeated failures.",
      "aaa authentication num-attempts 5\naaa authentication lockout-delay 900", families=OS, domain="aaa", topics=("lockout",),
      fn=lambda ctx: [] if ctx.cfg.has(r"^aaa authentication lockout-delay [1-9]") else [Hit("", "no `aaa authentication lockout-delay`")])

check("AOSS-INCLCRED", "security", "medium", "Credentials are stored in the configuration file (AOS-S)",
      "`include-credentials` writes passwords, SNMPv3 keys and RADIUS/TACACS keys into the configuration, so they appear in every backup.",
      "Turn it off unless you depend on it, and protect the backups.", "no include-credentials",
      families=OS, domain="aaa", topics=("credential-storage", "config-mgmt"), fn=forbid(r"^include-credentials"))

check("AOSS-SNMPV3", "security", "low", "SNMP v2c is used without SNMPv3 (AOS-S)",
      "Community strings travel in clear text. SNMPv3 adds authentication and encryption.", "Enable SNMPv3 and move monitoring to it.",
      "snmpv3 enable\nsnmpv3 user nms auth sha <auth> priv aes <priv>", families=OS, domain="snmp", topics=("snmp-v3",),
      applies=has(r"^snmp-server community "), fn=need(r"^snmpv3 enable", "SNMPv3 is not enabled"))

check("AOSS-NTPAUTH", "security", "medium", "NTP is not authenticated (AOS-S)",
      "A spoofed NTP server can move the clock, breaking logs and certificates.", "Authenticate NTP.",
      "ntp authentication key-id 1 authentication-mode sha1 key-value <key> trusted\nntp server <ntp-1> key 1",
      families=OS, domain="logging", topics=("time-auth",), applies=has(r"^ntp server "),
      fn=need(r"^ntp authentication key-id ", "no `ntp authentication key-id`"))

check("AOSS-NTP2", "best_practice", "low", "Only one NTP server (AOS-S)", "One time source is a single point of failure.",
      "Configure at least two NTP servers.", "ntp server <ntp-2> iburst", families=OS, domain="logging", topics=("time-sync", "availability"),
      applies=has(r"^ntp server "), fn=count_at_least(r"^ntp server ", 2, "{found} NTP server(s)"))

check("AOSS-TFTP", "security", "medium", "The switch is a TFTP server (AOS-S)",
      "TFTP has no authentication; anyone can read or write files on the switch.", "Disable the TFTP server; use SFTP/SCP.",
      "no tftp server\nip ssh filetransfer", families=OS, domain="services", topics=("least-functionality", "mgmt-crypto"),
      fn=forbid(r"^tftp server$"))

check("AOSS-BANNER", "security", "low", "No login banner (AOS-S)",
      "A banner states that access is restricted; many legal and audit frameworks require one.", "Add a banner.",
      'banner motd "Authorised access only. Activity is logged."', families=OS, domain="access", topics=("banner",),
      fn=need(r"^banner (motd|exec)", "no `banner motd`"))

check("AOSS-STP", "best_practice", "high", "Spanning tree is not enabled (AOS-S)",
      "Spanning tree is off by default on many AOS-S releases. A looped cable then brings the network down.", "Enable spanning tree.",
      "spanning-tree", families=OS, switch_only=True, domain="l2", topics=("availability", "l2-edge"),
      fn=need(r"^spanning-tree$", "`spanning-tree` is not enabled"))


@rule("AOSS-VLAN1", "security", "medium", "VLAN 1 has an IP address (AOS-S)",
      "AOS-S ships with `ip address dhcp-bootp` on VLAN 1, the default VLAN of every unconfigured port. Management there is reachable "
      "from any port.", "Manage the switch on a dedicated VLAN and remove the address from VLAN 1.", "vlan 1\n   no ip address",
      families=OS, domain="l2", topics=("segmentation", "mgmt-plane"))
def aoss_vlan1(ctx):
    for _h, ch in ctx.cfg.blocks(r"^vlan 1$"):
        if child_has(ch, r"^ip address (\d|dhcp-bootp)"):
            return [Hit("vlan 1", "VLAN 1 has an IP address")]
    return []


check("AOSS-DHCPSNOOP", "security", "medium", "DHCP snooping is off (AOS-S)",
      "Without DHCP snooping, any user port can run a rogue DHCP server.", "Enable DHCP snooping on user VLANs and trust the uplinks.",
      "dhcp-snooping\ndhcp-snooping vlan <user-vlans>\ndhcp-snooping trust <uplinks>", families=OS, switch_only=True, domain="l2",
      topics=("l2-spoofing",), applies=edge_switch, fn=need(r"^dhcp-snooping$", "`dhcp-snooping` is not enabled"))

check("AOSS-ARPPROTECT", "security", "low", "ARP protection is off (AOS-S)",
      "ARP protection drops forged ARP packets on user VLANs, stopping ARP spoofing.", "Enable ARP protection on user VLANs.",
      "arp-protect\narp-protect vlan <user-vlans>\narp-protect trust <uplinks>", families=OS, switch_only=True, domain="l2",
      topics=("l2-spoofing",), applies=both(edge_switch, has(r"^dhcp-snooping$")), fn=need(r"^arp-protect vlan ", "no `arp-protect vlan`"))

check("AOSS-LOOP", "best_practice", "low", "Loop protection off on edge ports (AOS-S)",
      "Loop protection catches loops spanning tree cannot see, such as an unmanaged switch looped on itself.", "Enable loop protection.",
      "loop-protect <access-ports>", families=OS, switch_only=True, domain="l2", topics=("l2-edge", "availability"), applies=edge_switch,
      fn=need(r"^loop-protect ", "no `loop-protect` ports"))

check("AOSS-PORTACCESS", "security", "medium", "User ports accept any device (AOS-S)",
      "Without 802.1X, MAC authentication or port security on access ports, anyone can plug in.", "Use port-access authentication (or port security).",
      "aaa port-access authenticator <ports>\naaa port-access authenticator active\naaa port-access mac-based <ports>",
      families=OS, switch_only=True, domain="l2", topics=("nac", "l2-spoofing"), applies=edge_switch,
      fn=need(r"^(aaa port-access |port-security )", "no port-access or port-security configured"))
