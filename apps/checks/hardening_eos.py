"""Arista EOS hardening checks."""
import re

from .config import child_has
from .ruleset import NA, Hit, check, count_at_least, forbid, has, need, ports, role_in, rule, short

F = ("arista_eos",)
NTP = has(r"^ntp server ")


def _mgmt(ctx, name):
    return ctx.cfg.blocks(rf"^management {name}$")


check("EOS-NOPASS", "security", "critical", "A local account has no password (Arista)",
      "EOS ships with `username admin nopassword`. Anyone who can reach the switch can log in as admin.",
      "Set a secret on every account.", "username admin privilege 15 role network-admin secret sha512 <hash>",
      families=F, domain="aaa", topics=("default-creds",), fn=forbid(r"^username \S+ .*nopassword"))

check("EOS-ROOT", "security", "medium", "The Linux root account is enabled (Arista)",
      "`aaa root secret` enables root logins to the underlying Linux shell, outside AAA authorisation and accounting.",
      "Disable the root account.", "no aaa root", families=F, domain="aaa", topics=("least-privilege", "default-creds"),
      fn=forbid(r"^aaa root secret"))

check("EOS-WEAKHASH", "security", "low", "Account secrets use a weak hash (Arista)",
      "Secrets stored in clear text (0) or as MD5 (5) are easy to crack. EOS supports SHA-512.", "Re-enter the secrets with sha512.",
      "username <user> secret sha512 <hash>", families=F, domain="aaa", topics=("credential-storage",),
      fn=lambda ctx: [Hit(l.split()[1], f"account {l.split()[1]}") for l in ctx.cfg.find(r"^username \S+ .*secret (0|5) ")])

check("EOS-AAALOGIN", "security", "medium", "No central authentication (Arista)",
      "Without an AAA login method using TACACS+ or RADIUS, administrators share local accounts.", "Authenticate logins through AAA.",
      "tacacs-server host <ip> key <key>\naaa authentication login default group tacacs+ local", families=F, domain="aaa",
      topics=("central-aaa",), fn=need(r"^aaa authentication login default group ", "no `aaa authentication login default group`"))

check("EOS-AUTHZ", "security", "medium", "Commands are not authorised per user (Arista)",
      "Command authorisation lets the TACACS+ server permit or deny each command by role.", "Authorise exec and commands.",
      "aaa authorization exec default group tacacs+ local\naaa authorization commands all default group tacacs+ local",
      families=F, domain="aaa", topics=("authorization",), applies=has(r"^tacacs-server host "),
      fn=need(r"^aaa authorization commands all default ", "no `aaa authorization commands all default`"))

check("EOS-ACCT", "security", "medium", "Administrator actions are not accounted (Arista)",
      "Command accounting sends every command to the AAA server: the audit trail of who changed what.", "Account commands and sessions.",
      "aaa accounting exec default start-stop group tacacs+\naaa accounting commands all default start-stop group tacacs+",
      families=F, domain="aaa", topics=("accounting",), fn=need(r"^aaa accounting commands all default ", "no `aaa accounting commands all default`"))

check("EOS-LOCKOUT", "security", "medium", "Accounts are not locked after failed logins (Arista)",
      "Without a lockout policy an attacker can try passwords without limit.", "Lock accounts after repeated failures.",
      "aaa authentication policy lockout failure 5 duration 900", families=F, domain="aaa", topics=("lockout",),
      fn=need(r"^aaa authentication policy lockout failure ", "no `aaa authentication policy lockout`"))


@rule("EOS-PWLEN", "security", "low", "No minimum password length (Arista)",
      "Without a minimum length short local passwords are accepted. PCI DSS asks for 12 characters.", "Set a 12-character minimum.",
      "management security\n   password minimum length 12", families=F, domain="aaa", topics=("password-policy",))
def eos_pwlen(ctx):
    vals = [int(m.group(1)) for _h, ch in _mgmt(ctx, "security") for c in ch for m in [re.match(r"^password minimum length (\d+)", c)] if m]
    return [] if vals and vals[0] >= 12 else [Hit("", f"minimum length is {vals[0] if vals else 'not set'}")]


@rule("EOS-SSHACL", "security", "medium", "SSH is open to any address (Arista)",
      "Without an access group under `management ssh`, SSH answers anyone who can reach the switch.", "Restrict SSH to management subnets.",
      "ip access-list MGMT\n   permit ip <mgmt-subnet> any\nmanagement ssh\n   ip access-group MGMT in", families=F, domain="access", topics=("mgmt-acl",))
def eos_sshacl(ctx):
    secs = _mgmt(ctx, "ssh")
    return [] if any(child_has(ch, r"access-group \S+") for _h, ch in secs) else [Hit("", "no `ip access-group` under management ssh")]


@rule("EOS-IDLE", "security", "medium", "Idle sessions are not closed within 10 minutes (Arista)",
      "EOS does not time out SSH or console sessions by default.", "Set idle timeouts.",
      "management ssh\n   idle-timeout 10\nmanagement console\n   idle-timeout 10", families=F, domain="access", topics=("session-timeout",))
def eos_idle(ctx):
    bad = []
    for name in ("ssh", "console"):
        vals = [int(m.group(1)) for _h, ch in _mgmt(ctx, name) for c in ch for m in [re.match(r"^idle-timeout (\d+)", c)] if m]
        if not vals or vals[0] == 0 or vals[0] > 10:
            bad.append(f"management {name}: {('idle-timeout ' + str(vals[0])) if vals else 'no idle-timeout'}")
    return [Hit("", "; ".join(bad))] if bad else []


check("EOS-SSHCIPHER", "security", "medium", "Weak SSH ciphers or MACs allowed (Arista)",
      "CBC ciphers, 3DES and MD5/SHA1 MACs have known weaknesses.", "Allow only modern algorithms.",
      "management ssh\n   cipher aes256-gcm@openssh.com aes256-ctr\n   mac hmac-sha2-256 hmac-sha2-512", families=F, domain="access",
      topics=("crypto-strength",),
      fn=lambda ctx: [Hit("", f"`{c}`") for _h, ch in _mgmt(ctx, "ssh") for c in ch if re.match(r"^(cipher|mac|key-exchange) .*(cbc|3des|md5|hmac-sha1\b|group1-sha1)", c)])


@rule("EOS-EAPIACL", "security", "medium", "eAPI is enabled without an access list (Arista)",
      "The command API gives full control of the switch. If it is on, only automation hosts should reach it.", "Restrict eAPI.",
      "management api http-commands\n   vrf MGMT\n      ip access-group EAPI", families=F, domain="access", topics=("mgmt-acl", "least-functionality"))
def eos_eapiacl(ctx):
    for _h, ch in _mgmt(ctx, "api http-commands"):
        if child_has(ch, r"^no shutdown") and not child_has(ch, r"access-group"):
            return [Hit("eapi", "eAPI is enabled with no access group")]
        if child_has(ch, r"^no shutdown"):
            return []
    return NA


@rule("EOS-SNMPACL", "security", "medium", "SNMP communities are not limited to known managers (Arista)",
      "A community without an access list answers anyone who can reach the switch.", "Add an access list to each community.",
      "ip access-list standard SNMP-MANAGERS\n   permit host <nms-ip>\nsnmp-server community <string> ro SNMP-MANAGERS",
      families=F, domain="snmp", topics=("snmp-community", "mgmt-acl"), applies=has(r"^snmp-server community "))
def eos_snmpacl(ctx):
    bad = []
    for l in ctx.cfg.find(r"^snmp-server community "):
        p = l.split()
        rest, i = [], 3
        while i < len(p):
            if p[i] == "view":
                i += 2
                continue
            if p[i] not in ("ro", "rw", "ipv6"):
                rest.append(p[i])
            i += 1
        if not rest:
            bad.append(p[2][:3] + "…")
    return [Hit(b, "community without an access list") for b in bad]


check("EOS-SNMPRW", "security", "high", "An SNMP community allows writes (Arista)",
      "A read-write community lets anyone who knows it change the configuration.", "Make it read-only or remove it.",
      "snmp-server community <string> ro <acl>", families=F, domain="snmp", topics=("snmp-community", "least-privilege"),
      fn=lambda ctx: [Hit(l.split()[2][:3] + "…", "read-write community") for l in ctx.cfg.find(r"^snmp-server community \S+ .*\brw\b")])

check("EOS-SNMPV3", "security", "low", "SNMP v2c is used without SNMPv3 (Arista)",
      "Community strings travel in clear text. SNMPv3 with authPriv adds authentication and encryption.", "Move monitoring to SNMPv3.",
      "snmp-server group NMS v3 priv\nsnmp-server user nms NMS v3 auth sha <auth> priv aes <priv>", families=F, domain="snmp",
      topics=("snmp-v3",), applies=has(r"^snmp-server community "), fn=need(r"^snmp-server group \S+ v3 priv", "no SNMPv3 authPriv group"))

check("EOS-NTPAUTH", "security", "medium", "NTP is not authenticated (Arista)",
      "A spoofed NTP server can move the clock, breaking logs and certificates.", "Authenticate NTP.",
      "ntp authentication-key 1 sha1 <key>\nntp trusted-key 1\nntp authenticate\nntp server <ntp-1> key 1",
      families=F, domain="logging", topics=("time-auth",), applies=NTP, fn=need(r"^ntp authenticate", "`ntp authenticate` is missing"))

check("EOS-NTP2", "best_practice", "low", "Only one NTP server (Arista)", "One time source is a single point of failure.",
      "Configure at least two NTP servers.", "ntp server <ntp-2>", families=F, domain="logging", topics=("time-sync", "availability"),
      applies=NTP, fn=count_at_least(r"^ntp server ", 2, "{found} NTP server(s)"))

check("EOS-LOGSRC", "best_practice", "low", "Syslog has no fixed source interface (Arista)",
      "A fixed source keeps messages identifiable in the SIEM.", "Set the logging source interface.", "logging source-interface Management1",
      families=F, domain="logging", topics=("logging-central", "mgmt-plane"), applies=has(r"^logging (vrf \S+ )?host "),
      fn=need(r"^logging (vrf \S+ )?source-interface ", "no `logging source-interface`"))

check("EOS-LOGTS", "best_practice", "low", "Log timestamps are low resolution (Arista)",
      "High-resolution timestamps make it possible to line up events across devices.", "Use high-resolution timestamps.",
      "logging format timestamp high-resolution", families=F, domain="logging", topics=("logging-content",),
      fn=need(r"^logging format timestamp (high-resolution|traditional timezone year)", "`logging format timestamp high-resolution` is missing"))

check("EOS-LOOPGUARD", "best_practice", "low", "Loop guard is not enabled (Arista)",
      "Loop guard stops a port that loses BPDUs from forwarding and creating a loop.", "Enable loop guard by default.",
      "spanning-tree guard loop default", families=F, switch_only=True, domain="l2", topics=("l2-edge", "availability"),
      fn=need(r"^spanning-tree guard loop default", "`spanning-tree guard loop default` is missing"))

check("EOS-STPROOT", "best_practice", "medium", "Core switch does not set its spanning-tree priority (Arista)",
      "If the core does not set a low priority any switch can win the root election.", "Make the core the root.",
      "spanning-tree mst 0 priority 4096", families=F, switch_only=True, domain="l2", topics=("availability", "l2-edge"),
      applies=role_in("core", "distribution"), fn=need(r"^spanning-tree (mst|vlan(-id)?) \S+ priority", "no spanning-tree priority set"))

check("EOS-REDIRECTS", "security", "low", "ICMP redirects are not disabled (Arista)",
      "Redirects can steer hosts' traffic and cost CPU.", "Disable them globally.", "no ip icmp redirect", families=F, domain="control",
      topics=("cp-protection",), applies=has(r"^ip routing$"), fn=need(r"^no ip icmp redirect", "`no ip icmp redirect` is missing"))

check("EOS-PROXYARP", "security", "low", "Proxy ARP is enabled (Arista)",
      "Proxy ARP answers for other networks, hiding addressing mistakes and helping man-in-the-middle attacks.", "Disable it.",
      "interface <if>\n   no ip proxy-arp", families=F, domain="control", topics=("cp-protection",),
      fn=lambda ctx: [Hit(short(h), short(h)) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^ip proxy-arp")])

check("EOS-CPACL", "best_practice", "info", "Default control-plane access list (Arista)",
      "EOS protects the CPU with a default ACL that permits all management protocols from anywhere. A custom one limits them to your hosts.",
      "Apply a custom control-plane ACL.", "system control-plane\n   ip access-group CP-ACL in", families=F, domain="control",
      topics=("cp-protection", "mgmt-acl"),
      fn=lambda ctx: [] if any(child_has(ch, r"^ip access-group ") for _h, ch in ctx.cfg.blocks(r"^(system )?control-plane")) else [Hit("", "default control-plane ACL in use")])


@rule("EOS-OSPFAUTH", "security", "medium", "OSPF neighbours are not authenticated (Arista)",
      "Without authentication any device on a routed segment can inject routes.", "Authenticate OSPF.",
      "interface <if>\n   ip ospf authentication message-digest\n   ip ospf message-digest-key 1 sha256 <key>",
      families=F, domain="routing", topics=("routing-auth",), applies=has(r"^router ospf "))
def eos_ospf(ctx):
    if any(child_has(ch, r"^area \S+ authentication") for _h, ch in ctx.cfg.blocks(r"^router ospf ")):
        return []
    ifs = [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^ip ospf ")]
    bad = [short(h) for h, ch in ifs if not child_has(ch, r"^ip ospf (authentication|message-digest-key)")]
    return [Hit("ports", ports(bad) if ifs else "no OSPF authentication configured")] if bad or not ifs else []


@rule("EOS-BGPAUTH", "security", "medium", "BGP sessions without authentication (Arista)",
      "An unauthenticated BGP session can be reset or hijacked with spoofed TCP packets.", "Add a password to each neighbour or peer group.",
      "router bgp <as>\n   neighbor <ip> password <secret>", families=F, domain="routing", topics=("routing-auth",), applies=has(r"^router bgp "))
def eos_bgp(ctx):
    bad = []
    for _h, ch in ctx.cfg.blocks(r"^router bgp "):
        by = {}
        for c in ch:
            m = re.match(r"^neighbor (\S+) (.+)$", c)
            if m:
                by.setdefault(m.group(1), []).append(m.group(2))
        for n, opts in by.items():
            if any(o in ("peer group", "peer-group") for o in opts):
                continue
            merged = list(opts)
            for o in opts:
                m = re.match(r"^peer[ -]group (\S+)", o)
                if m:
                    merged += by.get(m.group(1), [])
            if any(o.startswith("remote-as") for o in merged) and not any(o.startswith("password") for o in merged):
                bad.append(n)
    return [Hit(n, f"neighbour {n}") for n in bad]
