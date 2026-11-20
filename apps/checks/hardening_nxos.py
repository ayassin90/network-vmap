"""Cisco NX-OS hardening checks (Nexus 3000/5000/7000/9000)."""
import re

from .config import child_has
from .ruleset import NA, Hit, check, count_at_least, every, forbid, has, need, ports, role_in, rule, short

F = ("cisco_nxos",)
NTP = has(r"^ntp server ")
SNMP = has(r"^snmp-server (community|user)")
SYSLOG = has(r"^logging server ")
AAA_GRP = has(r"^aaa group server ")


def _l3(ctx):
    out = []
    for h, ch in ctx.cfg.blocks(r"^interface "):
        if re.search(r"(?i)^interface (loopback|mgmt|nve|tunnel)", h) or child_has(ch, r"^shutdown$"):
            continue
        if child_has(ch, r"^ip address \d"):
            out.append((h, ch))
    return out


# ------------------------------------------------------------------ management access
check("NX-SSHOFF", "security", "high", "SSH is disabled (NX-OS)",
      "`no feature ssh` leaves only Telnet or the console for management.", "Enable SSH.", "feature ssh",
      families=F, domain="access", topics=("mgmt-crypto",), fn=forbid(r"^no feature ssh$"))

check("NX-SSHKEY", "security", "medium", "SSH host key is shorter than 2048 bits (NX-OS)",
      "RSA keys of 1024 bits or less are below current minimums.", "Regenerate a 2048-bit (or larger) key.",
      "no feature ssh\nssh key rsa 2048 force\nfeature ssh", families=F, domain="access", topics=("crypto-strength",),
      fn=forbid(r"^ssh key rsa (512|768|1024)\b"))

check("NX-SSHTRIES", "security", "low", "Too many SSH login attempts allowed (NX-OS)",
      "More attempts per connection make password guessing faster.", "Allow at most 3.", "ssh login-attempts 3",
      families=F, domain="access", topics=("lockout",), fn=forbid(r"^ssh login-attempts ([4-9]|\d{2,})$"))

check("NX-HTTPSRV", "security", "high", "Legacy HTTP server feature is on (NX-OS)",
      "`feature http-server` exposes an unencrypted web server on older NX-OS releases.", "Disable it.", "no feature http-server",
      families=F, domain="services", topics=("least-functionality", "mgmt-crypto"), fn=forbid(r"^feature http-server$"))

check("NX-NXAPIHTTP", "security", "medium", "NX-API answers over plain HTTP",
      "NX-API over HTTP sends credentials and commands unencrypted.", "Serve NX-API over HTTPS only.",
      "no nxapi http\nnxapi https port 443", families=F, domain="access", topics=("mgmt-crypto",), fn=forbid(r"^nxapi http port \d+"))

check("NX-BASH", "security", "medium", "The Bash shell feature is enabled (NX-OS)",
      "`feature bash-shell` gives administrators a Linux shell on the switch, outside AAA command authorisation and accounting.",
      "Disable it unless it is required.", "no feature bash-shell", families=F, domain="services", topics=("least-functionality", "authorization"),
      fn=forbid(r"^feature bash-shell$"))

check("NX-VTYACL", "security", "medium", "Remote login is open to any address (NX-OS)",
      "The VTY lines have no access-class, so SSH answers anyone who can reach the switch.", "Restrict the VTY lines to management subnets.",
      "ip access-list MGMT\n  permit ip <mgmt-subnet> any\nline vty\n  access-class MGMT in", families=F, domain="access", topics=("mgmt-acl",),
      fn=every(r"^line vty", r"^access-class \S+ in", "VTY lines", na_if_none=False))


@rule("NX-TIMEOUT", "security", "medium", "Idle sessions are not closed within 10 minutes (NX-OS)",
      "NX-OS does not time out VTY or console sessions by default. PCI DSS asks for re-authentication after 15 minutes; CIS asks for 10.",
      "Set exec-timeout on the console and VTY lines.", "line console\n  exec-timeout 10\nline vty\n  exec-timeout 10",
      families=F, domain="access", topics=("session-timeout",))
def nx_timeout(ctx):
    bad = []
    for name in ("console", "vty"):
        secs = ctx.cfg.blocks(rf"^line {name}")
        vals = [int(m.group(1)) for _h, ch in secs for c in ch for m in [re.match(r"^exec-timeout (\d+)", c)] if m]
        if not vals or vals[0] == 0 or vals[0] > 10:
            bad.append(f"line {name}: {('exec-timeout ' + str(vals[0])) if vals else 'no exec-timeout'}")
    return [Hit("lines", "; ".join(bad))] if bad else []


check("NX-SESSIONS", "best_practice", "low", "No limit on concurrent VTY sessions (NX-OS)",
      "A session limit keeps a few spare management sessions when something opens many connections.", "Set a session limit.",
      "line vty\n  session-limit 8", families=F, domain="access", topics=("availability",),
      fn=every(r"^line vty", r"^session-limit \d+", "VTY lines", na_if_none=False))

check("NX-LOGINBLOCK", "security", "low", "No protection against password guessing (NX-OS)",
      "Without `login block-for`, an attacker can try passwords as fast as the switch answers.", "Block logins after repeated failures.",
      "login block-for 120 attempts 5 within 60", families=F, domain="aaa", topics=("lockout",), fn=need(r"^login block-for ", "`login block-for` is missing"))

check("NX-PWSTRENGTH", "security", "medium", "Password strength checking is disabled (NX-OS)",
      "`no password strength-check` lets administrators set short, simple passwords.", "Turn strength checking back on.",
      "password strength-check", families=F, domain="aaa", topics=("password-policy",), fn=forbid(r"^no password strength-check$"))


@rule("NX-ADMINS", "security", "low", "Several local accounts have network-admin (NX-OS)",
      "Local network-admin accounts bypass central AAA. Keep one break-glass account and give everyone else access through TACACS+/RADIUS.",
      "Remove extra local administrators.", "no username <user>", families=F, domain="aaa", topics=("least-privilege",))
def nx_admins(ctx):
    users = ctx.cfg.find(r"^username \S+ .*role network-admin")
    names = sorted({l.split()[1] for l in users})
    return [Hit("users", f"{len(names)} local network-admin accounts: {ports(names)}")] if len(names) > 1 else []


check("NX-AAALOGIN", "security", "medium", "No central authentication (NX-OS)",
      "Without `aaa authentication login default group`, everyone logs in with local accounts and nothing is centrally controlled.",
      "Authenticate logins through TACACS+ or RADIUS.", "feature tacacs+\naaa group server tacacs+ TACACS\n  server <ip>\naaa authentication login default group TACACS",
      families=F, domain="aaa", topics=("central-aaa",), fn=need(r"^aaa authentication login default group ", "no `aaa authentication login default group`"))

check("NX-AAACONSOLE", "security", "low", "Console logins are not centrally authenticated (NX-OS)",
      "By default NX-OS authenticates the console locally even when VTY logins use AAA.", "Use the AAA group on the console too.",
      "aaa authentication login console group TACACS", families=F, domain="aaa", topics=("central-aaa",), applies=AAA_GRP,
      fn=need(r"^aaa authentication login console group ", "no `aaa authentication login console group`"))

check("NX-AAAACCT", "security", "medium", "Administrator actions are not accounted (NX-OS)",
      "Accounting sends every command and session to the AAA server: the audit trail of who changed what.", "Enable AAA accounting.",
      "aaa accounting default group TACACS", families=F, domain="aaa", topics=("accounting",),
      fn=need(r"^aaa accounting default group ", "no `aaa accounting default group`"))

check("NX-AAAAUTHZ", "security", "medium", "Commands are not authorised per user (NX-OS)",
      "Command authorisation lets the TACACS+ server permit or deny each command by role.", "Authorise configuration commands.",
      "aaa authorization config-commands default group TACACS local\naaa authorization commands default group TACACS local",
      families=F, domain="aaa", topics=("authorization",), applies=has(r"^feature tacacs\+"),
      fn=need(r"^aaa authorization (config-)?commands default group ", "no `aaa authorization commands`"))


# ------------------------------------------------------------------ SNMP
@rule("NX-SNMPACL", "security", "medium", "SNMP communities are not limited to known managers (NX-OS)",
      "A community without `use-ipv4acl` answers anyone who can reach the switch.", "Attach an access list to each community.",
      "ip access-list SNMP-MANAGERS\n  permit udp <nms-ip>/32 any eq snmp\nsnmp-server community <string> use-ipv4acl SNMP-MANAGERS",
      families=F, domain="snmp", topics=("snmp-community", "mgmt-acl"), applies=has(r"^snmp-server community "))
def nx_snmp_acl(ctx):
    names = {l.split()[2] for l in ctx.cfg.find(r"^snmp-server community \S+")}
    acl = {l.split()[2] for l in ctx.cfg.find(r"^snmp-server community \S+ use-(ipv4)?acl ")}
    return [Hit(n[:3] + "…", "community without an access list") for n in sorted(names - acl)]


check("NX-SNMPRW", "security", "high", "An SNMP community has write access (NX-OS)",
      "A community in the network-admin group can change the configuration over SNMP.", "Use network-operator (read-only) or remove it.",
      "snmp-server community <string> group network-operator", families=F, domain="snmp", topics=("snmp-community", "least-privilege"),
      fn=lambda ctx: [Hit(l.split()[2][:3] + "…", "community in group network-admin") for l in ctx.cfg.find(r"^snmp-server community \S+ group network-admin")])

check("NX-SNMPV3", "security", "medium", "SNMPv3 user without SHA and AES (NX-OS)",
      "SNMPv3 users should authenticate with SHA and encrypt with AES-128; MD5 and DES are obsolete.", "Recreate the user with SHA and AES.",
      "snmp-server user <user> network-operator auth sha <auth> priv aes-128 <priv>", families=F, domain="snmp", topics=("snmp-v3", "crypto-strength"),
      fn=lambda ctx: [Hit(l.split()[2], f"user {l.split()[2]}") for l in ctx.cfg.find(r"^snmp-server user \S+ .*\bauth\b")
                      if re.search(r"auth md5", l) or not re.search(r"priv aes-128", l)])

check("NX-SNMPONLYV2", "security", "low", "SNMP v2c is used without SNMPv3 (NX-OS)",
      "Community strings travel in clear text. SNMPv3 adds authentication and encryption.", "Move monitoring to SNMPv3.",
      "snmp-server user <user> network-operator auth sha <auth> priv aes-128 <priv>", families=F, domain="snmp", topics=("snmp-v3",),
      applies=has(r"^snmp-server community "), fn=need(r"^snmp-server user \S+ .*priv ", "only community-based SNMP"))


# ------------------------------------------------------------------ logging and time
check("NX-NTPAUTH", "security", "medium", "NTP is not authenticated (NX-OS)",
      "Without NTP authentication a spoofed server can move the clock, breaking logs and certificates.", "Authenticate NTP.",
      "ntp authentication-key 1 md5 <key> 7\nntp trusted-key 1\nntp authenticate\nntp server <ntp-1> key 1",
      families=F, domain="logging", topics=("time-auth",), applies=NTP, fn=need(r"^ntp authenticate$", "`ntp authenticate` is missing"))

check("NX-NTP2", "best_practice", "low", "Only one NTP server (NX-OS)", "One time source is a single point of failure.",
      "Configure at least two NTP servers.", "ntp server <ntp-2> use-vrf management", families=F, domain="logging",
      topics=("time-sync", "availability"), applies=NTP, fn=count_at_least(r"^ntp server ", 2, "{found} NTP server(s)"))

check("NX-NTPSRC", "best_practice", "low", "NTP has no fixed source (NX-OS)",
      "A fixed source keeps server-side allow lists and authentication working.", "Set the NTP source interface.",
      "ntp source-interface mgmt0", families=F, domain="logging", topics=("time-sync", "mgmt-plane"), applies=NTP,
      fn=need(r"^ntp source(-interface)? ", "no `ntp source-interface`"))


@rule("NX-LOGLEVEL", "best_practice", "low", "Syslog servers receive too little (NX-OS)",
      "NX-OS sends only notifications (level 5) to a syslog server unless told otherwise, so logins and many changes are missed.",
      "Send informational (6) messages.", "logging server <ip> 6 use-vrf management", families=F, domain="logging",
      topics=("logging-content", "logging-central"), applies=SYSLOG)
def nx_loglevel(ctx):
    bad = []
    for l in ctx.cfg.find(r"^logging server "):
        m = re.match(r"^logging server \S+(?: (\d))?", l)
        if not m.group(1) or int(m.group(1)) < 6:
            bad.append(l.split()[2])
    return [Hit("", f"servers below level 6: {ports(bad)}")] if bad else []


check("NX-LOGMSEC", "best_practice", "low", "Log timestamps lack milliseconds (NX-OS)",
      "Millisecond timestamps make it possible to line up events across devices.", "Use millisecond timestamps.",
      "logging timestamp milliseconds", families=F, domain="logging", topics=("logging-content",),
      fn=need(r"^logging timestamp milliseconds", "`logging timestamp milliseconds` is missing"))

check("NX-LOGSRC", "best_practice", "low", "Syslog has no fixed source interface (NX-OS)",
      "A fixed source keeps messages identifiable in the SIEM.", "Set the logging source interface.", "logging source-interface loopback0",
      families=F, domain="logging", topics=("logging-central", "mgmt-plane"), applies=SYSLOG,
      fn=need(r"^logging source-interface ", "no `logging source-interface`"))


# ------------------------------------------------------------------ control plane, L2, routing
check("NX-COPP", "security", "medium", "No control-plane policing profile (NX-OS)",
      "CoPP rate-limits traffic to the supervisor so a flood or a loop cannot starve routing and management.", "Apply a CoPP profile.",
      "copp profile strict", families=F, domain="control", topics=("cp-protection", "availability"),
      fn=need(r"^copp profile ", "no `copp profile`"))

check("NX-DOMLOOKUP", "best_practice", "info", "Mistyped commands trigger DNS lookups (NX-OS)",
      "With domain lookup on and no DNS server reachable, a typo hangs the CLI.", "Disable domain lookup unless the switch needs DNS.",
      "no ip domain-lookup", families=F, domain="ops", topics=("least-functionality",), fn=forbid(r"^ip domain-lookup$"))


@rule("NX-REDIRECTS", "security", "low", "ICMP redirects are sent from routed interfaces (NX-OS)",
      "Redirects can steer hosts' traffic and cost CPU; on vPC they are a known cause of drops.", "Disable redirects.",
      "interface <if>\n  no ip redirects", families=F, domain="control", topics=("cp-protection",))
def nx_redirects(ctx):
    l3 = _l3(ctx)
    if not l3:
        return NA
    bad = [short(h) for h, ch in l3 if not child_has(ch, r"^no ip redirects")]
    return [Hit("ports", f"{len(bad)} of {len(l3)} routed interfaces: {ports(bad)}")] if bad else []


check("NX-PROXYARP", "security", "low", "Proxy ARP is enabled (NX-OS)",
      "Proxy ARP answers for other networks, hiding addressing mistakes and helping man-in-the-middle attacks.", "Disable it.",
      "interface <if>\n  no ip proxy-arp", families=F, domain="control", topics=("cp-protection",),
      fn=lambda ctx: [Hit(short(h), short(h)) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^ip proxy-arp")])

check("NX-BPDUGUARD", "best_practice", "medium", "Edge ports are not protected with BPDU guard (NX-OS)",
      "BPDU guard err-disables an edge port that hears a switch, stopping loops and rogue root bridges.", "Enable BPDU guard on edge ports.",
      "spanning-tree port type edge bpduguard default", families=F, switch_only=True, domain="l2", topics=("l2-edge",),
      fn=lambda ctx: [] if ctx.cfg.has(r"^spanning-tree port type edge bpduguard default") or ctx.cfg.all_lines(r"^spanning-tree bpduguard enable")
      else [Hit("", "no BPDU guard default or per-port BPDU guard")])

check("NX-LOOPGUARD", "best_practice", "low", "Loop guard is not enabled (NX-OS)",
      "Loop guard stops a port that loses BPDUs (for example a unidirectional fibre) from forwarding and creating a loop.",
      "Enable loop guard globally.", "spanning-tree loopguard default", families=F, switch_only=True, domain="l2", topics=("l2-edge", "availability"),
      fn=need(r"^spanning-tree loopguard default", "`spanning-tree loopguard default` is missing"))

check("NX-STPROOT", "best_practice", "medium", "Core switch does not set its spanning-tree priority (NX-OS)",
      "If the core does not set a low priority, any switch can win the root election.", "Make the core the root.",
      "spanning-tree vlan 1-3967 priority 4096", families=F, switch_only=True, domain="l2", topics=("availability", "l2-edge"),
      applies=role_in("core", "distribution"), fn=need(r"^spanning-tree (vlan|mst) \S+ (priority|root)", "no spanning-tree priority set"))


@rule("NX-OSPFAUTH", "security", "medium", "OSPF neighbours are not authenticated (NX-OS)",
      "Without authentication, any device on a routed segment can inject routes.", "Authenticate OSPF.",
      "interface <if>\n  ip ospf authentication message-digest\n  ip ospf message-digest-key 1 md5 3 <key>",
      families=F, domain="routing", topics=("routing-auth",), applies=has(r"^router ospf "))
def nx_ospf(ctx):
    if any(child_has(ch, r"^area \S+ authentication") for _h, ch in ctx.cfg.blocks(r"^router ospf ")):
        return []
    ifs = [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^ip router ospf ")]
    bad = [short(h) for h, ch in ifs if not child_has(ch, r"^ip ospf authentication")]
    return [Hit("ports", ports(bad) if ifs else "no OSPF authentication configured")] if bad or not ifs else []


@rule("NX-BGPAUTH", "security", "medium", "BGP sessions without authentication (NX-OS)",
      "An unauthenticated BGP session can be reset or hijacked with spoofed TCP packets.", "Add a password to each neighbour.",
      "router bgp <as>\n  neighbor <ip>\n    password 3 <secret>", families=F, domain="routing", topics=("routing-auth",), applies=has(r"^router bgp "))
def nx_bgp(ctx):
    bad = []
    for _h, ch in ctx.cfg.blocks(r"^router bgp "):
        cur, pw = None, False
        for c in ch + ["neighbor END"]:
            if c.startswith("neighbor "):
                if cur and not pw:
                    bad.append(cur)
                cur, pw = c.split()[1], False
            elif c.startswith("password "):
                pw = True
        bad = [b for b in bad if b != "END"]
    return [Hit(n, f"neighbour {n}") for n in bad]


@rule("NX-HSRPAUTH", "security", "low", "HSRP groups without authentication (NX-OS)",
      "An unauthenticated HSRP group can be taken over by a host claiming higher priority.", "Authenticate HSRP with MD5.",
      "interface <if>\n  hsrp <grp>\n    authentication md5 key-string <key>", families=F, domain="routing", topics=("routing-auth",),
      applies=lambda ctx: bool(ctx.cfg.all_lines(r"^hsrp \d+")))
def nx_hsrp(ctx):
    bad = [short(h) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^hsrp \d+") and not child_has(ch, r"^authentication ")]
    return [Hit("ports", ports(bad))] if bad else []


check("NX-BOOT", "best_practice", "low", "The boot image is not pinned (NX-OS)",
      "Without a boot variable the switch may boot an unexpected image after a reload.", "Set the boot image.",
      "boot nxos bootflash:<image>", families=F, domain="ops", topics=("software-integrity", "config-mgmt"),
      fn=lambda ctx: [] if ctx.cfg.has(r"^boot (nxos|system|kickstart) ") or not ctx.cfg.has(r"^version ") else [Hit("", "no `boot nxos` variable in the configuration")])
