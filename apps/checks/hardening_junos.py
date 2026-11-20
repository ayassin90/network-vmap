"""Juniper Junos hardening checks (EX / QFX / MX / SRX management plane). The configuration is in `display set` form."""
import re

from .ruleset import NA, Hit, both, check, edge_switch, forbid, has, need, ports, rule

F = ("juniper_junos",)
NTP = has(r"^set system ntp server ")
SNMP_COMM = has(r"^set snmp community ")


check("JUN-SSHV1", "security", "high", "SSH version 1 is allowed (Junos)",
      "SSH v1 has known cryptographic weaknesses.", "Allow SSH version 2 only.", "delete system services ssh protocol-version v1",
      families=F, domain="access", topics=("crypto-strength", "mgmt-crypto"), fn=forbid(r"^set system services ssh protocol-version v1"))

check("JUN-SSHCIPHER", "security", "medium", "Weak SSH algorithms allowed (Junos)",
      "CBC ciphers, 3DES, MD5/SHA1 MACs and DH group 1 have known weaknesses.", "Allow only modern algorithms.",
      "set system services ssh ciphers aes256-gcm@openssh.com\nset system services ssh macs hmac-sha2-256\nset system services ssh key-exchange ecdh-sha2-nistp256",
      families=F, domain="access", topics=("crypto-strength",),
      fn=forbid(r"^set system services ssh (ciphers|macs|key-exchange) .*(cbc|3des|md5|hmac-sha1\b|group1-sha1)"))

check("JUN-SSHLIMIT", "security", "low", "No limit on SSH connections (Junos)",
      "Connection and rate limits stop a flood of SSH attempts from exhausting the routing engine.", "Limit SSH connections.",
      "set system services ssh connection-limit 10\nset system services ssh rate-limit 4", families=F, domain="access",
      topics=("cp-protection", "lockout"), fn=need(r"^set system services ssh (connection-limit|rate-limit) ", "no SSH connection-limit or rate-limit"))

check("JUN-INSECURE", "security", "medium", "Insecure management services are enabled (Junos)",
      "FTP, finger, rlogin, rsh, TFTP and clear-text Junoscript send credentials or data unencrypted.", "Remove them; use SSH, NETCONF over SSH and SCP.",
      "delete system services ftp\ndelete system services finger\ndelete system services xnm-clear-text", families=F, domain="services",
      topics=("least-functionality", "mgmt-crypto"), fn=forbid(r"^set system services (ftp|finger|rlogin|rsh|tftp-server|xnm-clear-text)\b"))

check("JUN-LOCKOUT", "security", "medium", "Accounts are not locked after failed logins (Junos)",
      "Without a lockout period an attacker can keep trying passwords.", "Lock out after repeated failures.",
      "set system login retry-options tries-before-disconnect 3\nset system login retry-options lockout-period 15",
      families=F, domain="aaa", topics=("lockout",), fn=need(r"^set system login retry-options lockout-period ", "no `retry-options lockout-period`"))

check("JUN-PWFORMAT", "security", "medium", "Passwords are stored with a weak hash (Junos)",
      "MD5 and DES password formats are easy to crack.", "Use SHA-512.", "set system login password format sha512",
      families=F, domain="aaa", topics=("credential-storage",), fn=forbid(r"^set system login password format (md5|des)"))


@rule("JUN-PWLEN", "security", "medium", "No 12-character minimum password length (Junos)",
      "Without a minimum length short local passwords are accepted. PCI DSS asks for 12 characters.", "Set a 12-character minimum.",
      "set system login password minimum-length 12", families=F, domain="aaa", topics=("password-policy",))
def jun_pwlen(ctx):
    v = [int(m.group(1)) for l in ctx.cfg.find(r"^set system login password minimum-length \d+") for m in [re.search(r"(\d+)$", l)]]
    return [] if v and v[0] >= 12 else [Hit("", f"minimum length is {v[0] if v else 'the default (6)'}")]


@rule("JUN-IDLE", "security", "medium", "Login classes without an idle timeout (Junos)",
      "Users in the predefined classes (super-user, operator…) are never logged out when idle. Use custom classes with idle-timeout.",
      "Put users in classes with an idle timeout of 10 minutes or less.",
      "set system login class ADMIN permissions all\nset system login class ADMIN idle-timeout 10\nset system login user <user> class ADMIN",
      families=F, domain="access", topics=("session-timeout",))
def jun_idle(ctx):
    timeouts = {m.group(1): int(m.group(2)) for l in ctx.cfg.find(r"^set system login class \S+ idle-timeout \d+")
                for m in [re.match(r"^set system login class (\S+) idle-timeout (\d+)", l)]}
    users = {m.group(1): m.group(2) for l in ctx.cfg.find(r"^set system login user \S+ class \S+")
             for m in [re.match(r"^set system login user (\S+) class (\S+)", l)]}
    if not users:
        return NA
    bad = [f"{u} ({c})" for u, c in users.items() if c not in timeouts or timeouts[c] == 0 or timeouts[c] > 10]
    return [Hit("users", ports(bad))] if bad else []


@rule("JUN-SUPERUSERS", "security", "low", "Several local super-user accounts (Junos)",
      "Local super-user accounts bypass central AAA. Keep one break-glass account and authenticate everyone else via TACACS+/RADIUS.",
      "Remove extra local administrators.", "delete system login user <user>", families=F, domain="aaa", topics=("least-privilege",))
def jun_super(ctx):
    names = sorted({l.split()[4] for l in ctx.cfg.find(r"^set system login user \S+ class super-user")})
    return [Hit("users", f"{len(names)} super-user accounts: {ports(names)}")] if len(names) > 1 else []


check("JUN-BANNER", "security", "low", "No login banner (Junos)",
      "A banner states that access is restricted; many legal and audit frameworks require one.", "Add a login message.",
      'set system login message "Authorised access only. Activity is logged."', families=F, domain="access", topics=("banner",),
      fn=need(r"^set system login (message|announcement) ", "no `system login message`"))

check("JUN-AAA", "security", "medium", "No central authentication (Junos)",
      "Without TACACS+ or RADIUS in the authentication order, administrators share local accounts.", "Authenticate through TACACS+ or RADIUS.",
      "set system tacplus-server <ip> secret <key>\nset system authentication-order [ tacplus password ]", families=F, domain="aaa",
      topics=("central-aaa",), fn=need(r"^set system authentication-order .*(tacplus|radius)", "no TACACS+/RADIUS in authentication-order"))

check("JUN-ACCT", "security", "medium", "Administrator actions are not accounted (Junos)",
      "Accounting sends logins and configuration changes to the AAA server.", "Enable accounting.",
      "set system accounting events [ login change-log interactive-commands ]\nset system accounting destination tacplus",
      families=F, domain="aaa", topics=("accounting",), fn=need(r"^set system accounting events ", "no `system accounting events`"))

check("JUN-CMDLOG", "security", "low", "Commands are not logged (Junos)",
      "Logging interactive-commands keeps a record of every command typed, even without TACACS+ accounting.", "Log interactive commands.",
      "set system syslog file interactive-commands interactive-commands any", families=F, domain="logging", topics=("accounting", "logging-content"),
      fn=need(r"^set system syslog (file|host) \S+ (interactive-commands|any) (any|info)", "interactive-commands are not logged at info"))

check("JUN-LOFILTER", "security", "medium", "The routing engine is not protected by a loopback filter (Junos)",
      "A firewall filter on lo0 is the Junos way of protecting the control plane: it decides who may reach SSH, SNMP, NTP, BGP and so on.",
      "Apply an input filter to lo0.", "set firewall family inet filter PROTECT-RE term ...\nset interfaces lo0 unit 0 family inet filter input PROTECT-RE",
      families=F, domain="control", topics=("cp-protection", "mgmt-acl"),
      fn=need(r"^set interfaces lo0 unit \d+ family inet filter input", "no input filter on lo0"))


@rule("JUN-SNMPCLIENTS", "security", "medium", "SNMP communities are not limited to known managers (Junos)",
      "A community without `clients` answers anyone who can reach the switch.", "Restrict each community to your monitoring hosts.",
      "set snmp community <string> clients <nms-ip>/32", families=F, domain="snmp", topics=("snmp-community", "mgmt-acl"), applies=SNMP_COMM)
def jun_snmp_clients(ctx):
    names = {l.split()[3] for l in ctx.cfg.find(r"^set snmp community \S+")}
    ok = {l.split()[3] for l in ctx.cfg.find(r"^set snmp community \S+ (clients|client-list-name) ")}
    return [Hit(n[:3] + "…", "community without clients") for n in sorted(names - ok)]


check("JUN-SNMPRW", "security", "high", "An SNMP community allows writes (Junos)",
      "A read-write community lets anyone who knows it change the configuration.", "Make it read-only or remove it.",
      "set snmp community <string> authorization read-only", families=F, domain="snmp", topics=("snmp-community", "least-privilege"),
      fn=lambda ctx: [Hit(l.split()[3][:3] + "…", "read-write community") for l in ctx.cfg.find(r"^set snmp community \S+ authorization read-write")])

check("JUN-SNMPV3", "security", "low", "SNMP v2c is used without SNMPv3 (Junos)",
      "Community strings travel in clear text. SNMPv3 adds authentication and encryption.", "Move monitoring to SNMPv3.",
      "set snmp v3 usm local-engine user nms authentication-sha authentication-password <auth>\nset snmp v3 usm local-engine user nms privacy-aes128 privacy-password <priv>",
      families=F, domain="snmp", topics=("snmp-v3",), applies=SNMP_COMM, fn=need(r"^set snmp v3 usm local-engine user \S+ privacy-aes", "no SNMPv3 user with AES"))

check("JUN-NTPAUTH", "security", "medium", "NTP is not authenticated (Junos)",
      "A spoofed NTP server can move the clock, breaking logs and certificates.", "Authenticate NTP.",
      "set system ntp authentication-key 1 type sha256 value <key>\nset system ntp trusted-key 1\nset system ntp server <ntp-1> key 1",
      families=F, domain="logging", topics=("time-auth",), applies=NTP, fn=need(r"^set system ntp trusted-key ", "no `system ntp trusted-key`"))

check("JUN-NTP2", "best_practice", "low", "Only one NTP server (Junos)", "One time source is a single point of failure.",
      "Configure at least two NTP servers.", "set system ntp server <ntp-2>", families=F, domain="logging", topics=("time-sync", "availability"),
      applies=NTP, fn=lambda ctx: [] if len({l.split()[4] for l in ctx.cfg.find(r"^set system ntp server \S+")}) >= 2 else [Hit("", "1 NTP server")])

check("JUN-NTPSRC", "best_practice", "low", "NTP has no fixed source address (Junos)",
      "A fixed source keeps server-side allow lists and authentication working.", "Set the NTP source address.",
      "set system ntp source-address <loopback-ip>", families=F, domain="logging", topics=("time-sync", "mgmt-plane"), applies=NTP,
      fn=need(r"^set system ntp source-address ", "no `system ntp source-address`"))

check("JUN-SYSLOGSRC", "best_practice", "low", "Syslog has no fixed source address (Junos)",
      "A fixed source keeps messages identifiable in the SIEM.", "Set the syslog source address.", "set system syslog source-address <loopback-ip>",
      families=F, domain="logging", topics=("logging-central", "mgmt-plane"), applies=has(r"^set system syslog host "),
      fn=need(r"^set system syslog (source-address|host \S+ source-address) ", "no syslog source-address"))

check("JUN-SYSLOGMS", "best_practice", "low", "Log timestamps lack milliseconds (Junos)",
      "Millisecond timestamps make it possible to line up events across devices.", "Use millisecond timestamps.",
      "set system syslog time-format millisecond", families=F, domain="logging", topics=("logging-content",),
      fn=need(r"^set system syslog time-format .*millisecond", "no `syslog time-format millisecond`"))

check("JUN-ARCHIVE", "best_practice", "low", "Configurations are not archived off the device (Junos)",
      "`transfer-on-commit` copies every committed configuration to an archive server: an independent change history and backup.",
      "Archive on commit.", "set system archival configuration transfer-on-commit\nset system archival configuration archive-sites \"scp://user@host/path\"",
      families=F, domain="ops", topics=("config-mgmt",), fn=need(r"^set system archival configuration (transfer-on-commit|transfer-interval)", "no configuration archival"))

check("JUN-AUTOINSTALL", "security", "medium", "Auto-installation is enabled (Junos)",
      "Auto-installation (ZTP) fetches a configuration from the network, which an attacker on the segment can supply.",
      "Remove auto-installation once the device is deployed.", "delete system autoinstallation", families=F, domain="services",
      topics=("config-mgmt", "least-functionality"), fn=forbid(r"^set system autoinstallation"))

check("JUN-REDIRECTS", "security", "low", "ICMP redirects are sent (Junos)",
      "Redirects can steer hosts' traffic and cost CPU.", "Disable them globally.", "set system no-redirects",
      families=F, domain="control", topics=("cp-protection",), fn=need(r"^set system no-redirects", "`system no-redirects` is missing"))

check("JUN-CONSOLE", "security", "low", "Console session stays open after disconnect (Junos)",
      "Without `log-out-on-disconnect`, the next person to plug into the console inherits the previous session.", "Log out on disconnect.",
      "set system ports console log-out-on-disconnect", families=F, domain="access", topics=("session-timeout",),
      fn=need(r"^set system ports console log-out-on-disconnect", "`console log-out-on-disconnect` is missing"))

check("JUN-DHCPSEC", "security", "medium", "DHCP snooping is off (Junos)",
      "Without DHCP security on user VLANs, any port can run a rogue DHCP server.", "Enable dhcp-security on user VLANs.",
      "set vlans <user-vlan> forwarding-options dhcp-security", families=F, switch_only=True, domain="l2", topics=("l2-spoofing",),
      applies=edge_switch, fn=lambda ctx: [] if ctx.cfg.find(r"(dhcp-security|examine-dhcp)") else [Hit("", "no dhcp-security on any VLAN")])

check("JUN-DAI", "security", "low", "ARP inspection is off (Junos)",
      "Dynamic ARP inspection drops forged ARP replies on user VLANs.", "Enable ARP inspection with dhcp-security.",
      "set vlans <user-vlan> forwarding-options dhcp-security arp-inspection", families=F, switch_only=True, domain="l2",
      topics=("l2-spoofing",), applies=both(edge_switch, lambda ctx: bool(ctx.cfg.find(r"dhcp-security"))),
      fn=lambda ctx: [] if ctx.cfg.find(r"(arp-inspection|examine-arp)") else [Hit("", "no arp-inspection")])

check("JUN-STORM", "best_practice", "low", "No storm control on access ports (Junos)",
      "Storm control caps broadcast and multicast from one port so a faulty NIC or loop cannot flood the VLAN.", "Apply a storm-control profile.",
      "set forwarding-options storm-control-profiles SC all bandwidth-percentage 5\nset interfaces <port> unit 0 family ethernet-switching storm-control SC",
      families=F, switch_only=True, domain="l2", topics=("l2-edge", "availability"), applies=edge_switch,
      fn=lambda ctx: [] if ctx.cfg.find(r"storm-control") else [Hit("", "no storm-control")])

check("JUN-OSPFAUTH", "security", "medium", "OSPF neighbours are not authenticated (Junos)",
      "Without authentication any device on a routed segment can inject routes.", "Authenticate OSPF interfaces.",
      "set protocols ospf area 0 interface <if> authentication md5 1 key <key>", families=F, domain="routing", topics=("routing-auth",),
      applies=has(r"^set protocols ospf3? "), fn=need(r"^set protocols ospf3? area \S+ interface \S+ authentication", "no OSPF interface authentication"))


@rule("JUN-BGPAUTH", "security", "medium", "BGP groups without authentication (Junos)",
      "An unauthenticated BGP session can be reset or hijacked.", "Add an authentication key to each group or neighbour.",
      "set protocols bgp group <group> authentication-key <secret>", families=F, domain="routing", topics=("routing-auth",),
      applies=has(r"^set protocols bgp group "))
def jun_bgp(ctx):
    groups = sorted({l.split()[4] for l in ctx.cfg.find(r"^set protocols bgp group \S+ neighbor ")})
    bad = [g for g in groups if not ctx.cfg.has(rf"^set protocols bgp (group {re.escape(g)} (neighbor \S+ )?)?authentication-(key|key-chain) ")]
    return [Hit(g, f"group {g}") for g in bad]
