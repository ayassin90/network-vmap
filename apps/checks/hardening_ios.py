"""Cisco IOS / IOS-XE hardening checks. `cis=` is the CIS Cisco IOS XE Benchmark item; `topics=` maps to the other
frameworks through controls.py."""
import re

from .config import child_has
from .ruleset import (NA, Hit, both, check, count_at_least, edge_switch, every, forbid, has, has_any, has_outside, ios_access,
                      ios_l3, ios_trunks, need, outside_ifaces, ports, role_in, rule, short)

F = ("cisco_ios",)
AAA = has(r"^aaa new-model")
SNMP = has(r"^snmp-server (community|group|user|host)")
NTP = has(r"^ntp server ")
SNOOP = has(r"^ip dhcp snooping$")
SYSLOG = has(r"^logging (host )?\d")


def _lines(ctx):
    return ctx.cfg.blocks(r"^line (con|vty|aux)")


# ================================================================== management access
check("IOS-AUX", "security", "medium", "The AUX port accepts logins",
      "The auxiliary port is often wired to a modem or terminal server and forgotten. If it can start a session it is an "
      "unmonitored way in.", "Disable logins on the AUX port.", "line aux 0\n no exec\n transport input none\n transport output none",
      families=F, domain="access", topics=("mgmt-acl", "least-functionality"), cis="1.2.3,1.2.10",
      fn=every(r"^line aux", r"^(no exec$|transport input none$)", "AUX lines"))


@rule("IOS-EXECTIMEOUT", "security", "medium", "Idle timeout longer than 10 minutes",
      "A forgotten session stays logged in. PCI DSS requires re-authentication after 15 minutes of inactivity; CIS asks for 10.",
      "Set exec-timeout to 10 minutes or less on every line.", "line con 0\n exec-timeout 10 0\nline vty 0 15\n exec-timeout 10 0",
      families=F, domain="access", topics=("session-timeout",), cis="1.2.6,1.2.7,1.2.9")
def exec_timeout(ctx):
    bad = []
    for h, ch in _lines(ctx):
        for c in ch:
            m = re.match(r"^exec-timeout (\d+)(?: (\d+))?$", c)
            if m and (int(m.group(1)) * 60 + int(m.group(2) or 0)) > 600:
                bad.append(f"{h} ({c})")
    return [Hit("lines", "; ".join(bad))] if bad else []


check("IOS-VTYOUT", "security", "low", "Remote sessions can open Telnet onward",
      "`transport output telnet` (or all) on the VTY lines lets someone logged in jump to other devices in clear text.",
      "Allow only SSH (or nothing) as an outgoing transport.", "line vty 0 15\n transport output ssh",
      families=F, domain="access", topics=("mgmt-crypto",),
      fn=lambda ctx: [Hit(h, f"{h}: {c}") for h, ch in ctx.cfg.blocks(r"^line vty") for c in ch if re.match(r"^transport output .*\b(telnet|all)\b", c)])


check("IOS-VTY6ACL", "security", "medium", "Remote login over IPv6 is not restricted",
      "IPv6 is enabled, but the VTY lines have no `ipv6 access-class`, so SSH over IPv6 bypasses the IPv4 management list.",
      "Add an IPv6 access list to the VTY lines.", "ipv6 access-list MGMT6\n permit ipv6 <mgmt-prefix> any\nline vty 0 15\n ipv6 access-class MGMT6 in",
      families=F, domain="access", topics=("mgmt-acl",), applies=has_any(r"^(ipv6 address |ipv6 unicast-routing|ipv6 enable)"),
      fn=every(r"^line vty", r"^ipv6 access-class \S+ in", "VTY lines", unless=r"^transport input none"))


@rule("IOS-SSHTIMEOUT", "security", "low", "SSH login timeout is long",
      "The SSH negotiation timeout defaults to 120 seconds, which lets unauthenticated connections hold resources.",
      "Set the SSH timeout to 60 seconds or less.", "ip ssh time-out 60", families=F, domain="access",
      topics=("session-timeout", "cp-protection"), cis="2.1.1.1.4")
def ssh_timeout(ctx):
    m = [int(x) for l in ctx.cfg.find(r"^ip ssh time-out \d+") for x in re.findall(r"\d+", l)[:1]]
    return [] if m and m[0] <= 60 else [Hit("", f"ip ssh time-out is {m[0] if m else '120 (default)'} seconds")]


@rule("IOS-SSHRETRY", "security", "low", "Too many SSH password attempts per connection",
      "More attempts per connection make password guessing faster.", "Allow at most 3 attempts.", "ip ssh authentication-retries 3",
      families=F, domain="access", topics=("lockout",), cis="2.1.1.1.5")
def ssh_retry(ctx):
    m = [int(x) for l in ctx.cfg.find(r"^ip ssh authentication-retries \d+") for x in re.findall(r"\d+", l)[:1]]
    return [Hit("", f"ip ssh authentication-retries {m[0]}")] if m and m[0] > 3 else []


@rule("IOS-SSHALG", "security", "medium", "Weak SSH algorithms are allowed",
      "CBC ciphers, 3DES, MD5/SHA1-96 MACs, diffie-hellman-group1 and small DH groups have known weaknesses.",
      "Allow only modern algorithms.",
      "ip ssh server algorithm encryption aes256-gcm aes256-ctr aes128-ctr\nip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512\n"
      "ip ssh server algorithm kex ecdh-sha2-nistp256 diffie-hellman-group14-sha256\nip ssh dh min size 2048",
      families=F, domain="access", topics=("crypto-strength",))
def ssh_alg(ctx):
    bad = [l for l in ctx.cfg.find(r"^ip ssh (server|client) algorithm ") if re.search(r"cbc|3des|md5|sha1-96|group1-sha1|\bhmac-sha1\b", l)]
    bad += [l for l in ctx.cfg.find(r"^ip ssh dh min size (512|768|1024)$")]
    return [Hit("", "; ".join(f"`{b}`" for b in bad))] if bad else []


check("IOS-DOMAIN", "best_practice", "low", "No IP domain name",
      "A domain name is needed to generate the SSH key pair and makes the device's identity (FQDN) unambiguous.",
      "Set the domain name.", "ip domain name <example.com>", families=F, domain="access", topics=("mgmt-crypto", "inventory"), cis="2.1.1.1.2",
      fn=need(r"^ip domain[ -]name ", "no `ip domain name`"))

check("IOS-HOSTNAME", "best_practice", "low", "The device still has its factory host name",
      "A default name such as Switch or Router makes logs, alerts and audit trails ambiguous.", "Give the device a unique name.",
      "hostname <site>-<role>-<n>", families=F, domain="ops", topics=("inventory",), cis="2.1.1.1.1",
      fn=lambda ctx: [Hit("", "hostname is a factory default")] if not ctx.cfg.has(r"^hostname ") or ctx.cfg.has(r"^hostname (Switch|Router|switch|router|ios|IOS|cisco)$") else [])

check("IOS-HTTPTLS", "security", "low", "HTTPS server allows old TLS versions",
      "Without `ip http tls-version`, older releases accept TLS 1.0 and 1.1, which are deprecated.", "Allow TLS 1.2 or later only.",
      "ip http tls-version TLSv1.2", families=F, domain="access", topics=("crypto-strength",), applies=has(r"^ip http secure-server$"),
      fn=need(r"^ip http tls-version TLSv1\.[23]", "`ip http tls-version TLSv1.2` is missing"))

check("IOS-HTTPAUTH", "security", "medium", "Web server login does not use AAA or local accounts",
      "Without `ip http authentication aaa` (or `local`), the web server authenticates with the shared enable password.",
      "Authenticate web logins through AAA.", "ip http authentication aaa", families=F, domain="access", topics=("central-aaa",),
      applies=has(r"^ip http (secure-)?server$"), fn=need(r"^ip http authentication (aaa|local)", "web logins use the enable password"))

check("IOS-PROGAPI", "best_practice", "info", "Programmable interfaces are enabled",
      "RESTCONF, NETCONF and gNMI are powerful management APIs. Make sure they are needed and limited to management hosts.",
      "Turn off what you do not use; restrict the rest with access lists.", "no restconf\nno netconf-yang\nno gnxi",
      families=F, domain="services", topics=("least-functionality",), fn=forbid(r"^(restconf|netconf-yang|gnxi)$"))

check("IOS-FILESRV", "security", "medium", "The device is a TFTP or FTP server",
      "TFTP has no authentication at all and FTP sends credentials in clear text; both let others read files from flash.",
      "Remove the file server; copy files over SCP instead.", "no tftp-server <file>\nno ftp-server enable",
      families=F, domain="services", topics=("least-functionality", "mgmt-crypto"), fn=forbid(r"^(tftp-server |ftp-server enable)"))

check("IOS-RCMD", "security", "high", "Remote shell (rsh/rcp) is enabled",
      "rsh and rcp authenticate by host name only and send everything in clear text.", "Disable them.",
      "no ip rcmd rsh-enable\nno ip rcmd rcp-enable", families=F, domain="services", topics=("least-functionality", "mgmt-crypto"),
      fn=forbid(r"^ip rcmd (rsh|rcp)-enable"))

check("IOS-SCPAUTH", "best_practice", "info", "SCP server enabled without command authorisation",
      "`ip scp server enable` uses AAA authorisation to decide who may copy files. Without `aaa authorization exec` any account can.",
      "Configure exec authorisation, or disable SCP when not in use.", "aaa authorization exec default group tacacs+ local",
      families=F, domain="access", topics=("authorization",), applies=has(r"^ip scp server enable"),
      fn=need(r"^aaa authorization exec ", "no `aaa authorization exec`"))


# ================================================================== accounts and AAA
check("IOS-AAALOGIN", "security", "medium", "No AAA login method list",
      "AAA is on, but no `aaa authentication login` list says how logins are checked.", "Define the login method list.",
      "aaa authentication login default group tacacs+ local", families=F, domain="aaa", topics=("central-aaa",), cis="1.1.2",
      applies=AAA, fn=need(r"^aaa authentication login ", "no `aaa authentication login`"))

check("IOS-AAAENABLE", "security", "low", "Enable mode is not authenticated through AAA",
      "Without `aaa authentication enable`, privileged mode relies only on the shared enable secret.", "Authenticate enable through AAA.",
      "aaa authentication enable default group tacacs+ enable", families=F, domain="aaa", topics=("central-aaa",), cis="1.1.3",
      applies=AAA, fn=need(r"^aaa authentication enable default", "no `aaa authentication enable default`"))

check("IOS-AUTHZEXEC", "security", "medium", "No exec authorisation",
      "Without `aaa authorization exec`, the AAA server cannot decide which privilege level a user gets.", "Authorise exec sessions.",
      "aaa authorization exec default group tacacs+ local", families=F, domain="aaa", topics=("authorization",),
      applies=AAA, fn=need(r"^aaa authorization exec ", "no `aaa authorization exec`"))

check("IOS-AUTHZCMD", "security", "medium", "Privileged commands are not authorised per user",
      "Command authorisation lets the TACACS+ server allow or deny each configuration command by role.", "Authorise level-15 commands.",
      "aaa authorization commands 15 default group tacacs+ local", families=F, domain="aaa", topics=("authorization", "least-privilege"),
      applies=AAA, fn=need(r"^aaa authorization commands 15 ", "no `aaa authorization commands 15`"))

check("IOS-ACCTCMD", "security", "medium", "Configuration commands are not accounted",
      "Command accounting sends every privileged command, with the user name, to the AAA server: the audit trail of who changed what.",
      "Account level-15 commands.", "aaa accounting commands 15 default start-stop group tacacs+", families=F, domain="aaa",
      topics=("accounting",), cis="1.1.6", applies=AAA, fn=need(r"^aaa accounting commands 15 ", "no `aaa accounting commands 15`"))

check("IOS-ACCTCONN", "security", "low", "Outgoing connections are not accounted",
      "Connection accounting records sessions opened from the device to other hosts.", "Account connections.",
      "aaa accounting connection default start-stop group tacacs+", families=F, domain="aaa", topics=("accounting",), cis="1.1.7",
      applies=AAA, fn=need(r"^aaa accounting connection ", "no `aaa accounting connection`"))

check("IOS-ACCTEXEC", "security", "medium", "Login sessions are not accounted",
      "Exec accounting records who logged in, from where and for how long.", "Account exec sessions.",
      "aaa accounting exec default start-stop group tacacs+", families=F, domain="aaa", topics=("accounting",), cis="1.1.8",
      applies=AAA, fn=need(r"^aaa accounting exec ", "no `aaa accounting exec`"))

check("IOS-ACCTSYS", "security", "low", "System events are not accounted",
      "System accounting records reloads and accounting on/off events.", "Account system events.",
      "aaa accounting system default start-stop group tacacs+", families=F, domain="aaa", topics=("accounting",), cis="1.1.10",
      applies=AAA, fn=need(r"^aaa accounting system ", "no `aaa accounting system`"))


@rule("IOS-AAAFALLBACK", "best_practice", "low", "No local fallback if the AAA servers are unreachable",
      "If the login list names only server groups, nobody can log in when the servers or the path to them fail.",
      "End the login list with `local` and keep one break-glass account.", "aaa authentication login default group tacacs+ local",
      families=F, domain="aaa", topics=("central-aaa", "availability"), applies=has(r"^aaa authentication login default group"))
def aaa_fallback(ctx):
    return [Hit("", f"`{l}`") for l in ctx.cfg.find(r"^aaa authentication login default group") if not re.search(r"\b(local|local-case|enable|line)\b", l)]


@rule("IOS-AAASERVERS", "security", "high", "AAA uses a server group with no servers",
      "The method list names TACACS+ or RADIUS, but no server of that type is defined, so every login falls back (or fails).",
      "Define the servers, or fix the method list.", "tacacs server ISE-1\n address ipv4 <ip>\n key <key>",
      families=F, domain="aaa", topics=("central-aaa",), applies=AAA)
def aaa_servers(ctx):
    text = "\n".join(ctx.cfg.find(r"^aaa (authentication|authorization|accounting) "))
    out = []
    if re.search(r"group tacacs\+", text) and not ctx.cfg.has(r"^(tacacs server |tacacs-server host )"):
        out.append(Hit("tacacs", "`group tacacs+` used but no TACACS+ server defined"))
    if re.search(r"group radius\b", text) and not ctx.cfg.has(r"^(radius server |radius-server host )"):
        out.append(Hit("radius", "`group radius` used but no RADIUS server defined"))
    return out


check("IOS-AAASRC", "best_practice", "low", "AAA traffic has no fixed source interface",
      "Without a source interface the AAA request leaves from whichever interface is closest, so server-side allow lists break on failover.",
      "Source AAA from the loopback or management interface.", "ip tacacs source-interface Loopback0\nip radius source-interface Loopback0",
      families=F, domain="aaa", topics=("mgmt-plane", "central-aaa"), cis="2.4.2", applies=has(r"^(tacacs server |tacacs-server host |radius server |radius-server host )"),
      fn=need(r"^ip (tacacs|radius) source-interface ", "no `ip tacacs source-interface` / `ip radius source-interface`"))


@rule("IOS-KEY7", "security", "low", "AAA server keys use reversible encryption",
      "Type 7 (and plain) keys can be decoded instantly by anyone with the configuration. Type 6 uses AES with a master key.",
      "Turn on AES password encryption and re-enter the keys.", "key config-key password-encrypt <master-key>\npassword encryption aes",
      families=F, domain="aaa", topics=("credential-storage",), applies=has(r"^(tacacs server |tacacs-server |radius server |radius-server )"))
def key7(ctx):
    bad = [h for h, ch in ctx.cfg.blocks(r"^(tacacs|radius) server ") if any(re.match(r"^key (7 |0 |(?![0-9] )\S+$)", c) for c in ch)]
    bad += [l.split(" key")[0] for l in ctx.cfg.find(r"^(tacacs|radius)-server .*key (7 |0 )")]
    return [Hit("", ports(bad, 6))] if bad else []


check("IOS-NOENABLE", "security", "high", "No enable secret",
      "Without an enable secret, privileged mode is protected only by line passwords, or not at all from the console.",
      "Set a strong enable secret.", "enable algorithm-type scrypt secret <secret>", families=F, domain="aaa",
      topics=("default-creds", "credential-storage"), cis="1.4.1", fn=need(r"^enable (algorithm-type \S+ )?secret ", "no `enable secret`"))

check("IOS-NOPASS", "security", "critical", "A local account has no password",
      "`username ... nopassword` lets anyone log in with that name.", "Give the account a strong secret or remove it.",
      "no username <name>\nusername <name> algorithm-type scrypt secret <secret>", families=F, domain="aaa", topics=("default-creds",),
      fn=forbid(r"^username \S+ .*nopassword"))


@rule("IOS-PRIV15", "security", "low", "Local accounts have full privileges",
      "CIS asks that local accounts get privilege 1 and that administrators are elevated through AAA, so local accounts cannot "
      "change the configuration if their password leaks.", "Keep one privilege-15 break-glass account; use AAA for everyone else.",
      "username <user> privilege 1 algorithm-type scrypt secret <secret>", families=F, domain="aaa", topics=("least-privilege",), cis="1.2.1")
def priv15(ctx):
    users = ctx.cfg.find(r"^username \S+ ")
    if not users:
        return NA
    bad = [l.split()[1] for l in users if re.search(r"\bprivilege 15\b", l)]
    return [Hit("users", f"{len(bad)} privilege-15 local account(s): {ports(bad)}")] if len(bad) > 1 else []


@rule("IOS-MINLEN", "security", "medium", "No minimum password length",
      "Without a minimum length, short local passwords are accepted. PCI DSS asks for at least 12 characters.",
      "Enforce a 12-character minimum.", "security passwords min-length 12", families=F, domain="aaa", topics=("password-policy",))
def minlen(ctx):
    m = [int(x) for l in ctx.cfg.find(r"^security passwords min-length \d+") for x in re.findall(r"\d+", l)[:1]]
    if any(child_has(ch, r"^min-length (1[2-9]|[2-9]\d)") for _h, ch in ctx.cfg.blocks(r"^aaa common-criteria policy")):
        return []
    return [] if m and m[0] >= 12 else [Hit("", f"minimum length is {m[0] if m else 'not set'}")]


check("IOS-LOGINLOG", "security", "low", "Login failures and successes are not logged",
      "`login on-failure log` and `login on-success log` record every login attempt, which is how brute-force attempts are seen.",
      "Log logins.", "login on-failure log\nlogin on-success log", families=F, domain="aaa", topics=("accounting", "monitoring"),
      fn=lambda ctx: [Hit("", "missing: " + ", ".join(x for x, rx in (("login on-failure log", r"^login on-failure log"), ("login on-success log", r"^login on-success log")) if not ctx.cfg.has(rx)))]
      if not (ctx.cfg.has(r"^login on-failure log") and ctx.cfg.has(r"^login on-success log")) else [])

check("IOS-GENERICUSER", "security", "low", "Generic or default account names",
      "Accounts named admin, cisco, root or similar are shared by nature and are the first names attackers try.",
      "Use named personal accounts through AAA and one clearly owned break-glass account.", "no username admin",
      families=F, domain="aaa", topics=("default-creds", "least-privilege"),
      fn=lambda ctx: [Hit(l.split()[1], f"account `{l.split()[1]}`") for l in ctx.cfg.find(r"^username (admin|cisco|root|administrator|manager|user|test|guest) ")])

check("IOS-BANNEREXEC", "security", "low", "No exec banner",
      "The exec banner is shown after login; CIS asks for it alongside the login banner.", "Add an exec banner.",
      "banner exec ^\nAll activity is monitored and logged.\n^", families=F, domain="access", topics=("banner",), cis="1.3.1",
      fn=need(r"^banner exec", "no `banner exec`"))

check("IOS-BANNERMOTD", "security", "info", "No message-of-the-day banner",
      "The MOTD banner is shown before login on every connection.", "Add a MOTD banner.", "banner motd ^\nAuthorised access only.\n^",
      families=F, domain="access", topics=("banner",), cis="1.3.3", fn=need(r"^banner motd", "no `banner motd`"))


# ================================================================== SNMP
check("IOS-SNMPTRAPS", "best_practice", "low", "SNMP traps are not enabled",
      "Traps tell the monitoring system about link, power and security events as they happen.", "Enable SNMP traps.",
      "snmp-server enable traps", families=F, domain="snmp", topics=("monitoring",), cis="1.5.8", applies=SNMP,
      fn=need(r"^snmp-server enable traps", "no `snmp-server enable traps`"))

check("IOS-SNMPHOST", "best_practice", "low", "No SNMP trap receiver",
      "Traps are enabled but go nowhere without a receiver.", "Send traps to the monitoring server.",
      "snmp-server host <nms-ip> version 3 priv <user>", families=F, domain="snmp", topics=("monitoring",), cis="1.5.7", applies=SNMP,
      fn=need(r"^snmp-server host ", "no `snmp-server host`"))

check("IOS-SNMPV3PRIV", "security", "medium", "SNMPv3 group without encryption",
      "An SNMPv3 group with `noauth` or `auth` (no `priv`) sends data unencrypted, and `noauth` without any authentication.",
      "Use `priv` for every SNMPv3 group.", "snmp-server group <group> v3 priv", families=F, domain="snmp", topics=("snmp-v3",), cis="1.5.9",
      fn=forbid(r"^snmp-server group \S+ v3 (noauth|auth)\b"))

check("IOS-SNMPUSERAES", "security", "medium", "SNMPv3 user without AES encryption",
      "SNMPv3 users should authenticate with SHA and encrypt with AES; DES and 3DES are obsolete.", "Recreate the user with AES.",
      "snmp-server user <user> <group> v3 auth sha <auth> priv aes 128 <priv>", families=F, domain="snmp", topics=("snmp-v3", "crypto-strength"),
      cis="1.5.10", fn=lambda ctx: [Hit(l.split()[2], f"user {l.split()[2]}") for l in ctx.cfg.find(r"^snmp-server user \S+ \S+ v3")
                                    if not re.search(r"priv aes", l) or re.search(r"auth md5", l)])


@rule("IOS-SNMPACLDEF", "security", "medium", "SNMP refers to an access list that does not exist",
      "An undefined access list on a community permits everyone on many releases, so the restriction you think you have is not there.",
      "Create the access list or fix the name.", "ip access-list standard SNMP-MANAGERS\n permit <nms-ip>",
      families=F, domain="snmp", topics=("snmp-community", "mgmt-acl"), applies=has(r"^snmp-server community "))
def snmp_acl_def(ctx):
    defined = {m.group(2) for l in ctx.cfg.globals for m in [re.match(r"^(ip access-list (?:standard|extended)|access-list|ipv6 access-list) (\S+)", l)] if m}
    bad = []
    for l in ctx.cfg.find(r"^snmp-server community "):
        p = l.split()
        acl = p[-1] if len(p) >= 5 or (len(p) == 4 and p[3] not in ("RO", "RW", "ro", "rw")) else None
        if acl and acl not in defined and not acl.startswith("ipv6"):
            bad.append(acl)
    return [Hit(a, f"access list `{a}` is not defined") for a in sorted(set(bad))]


check("IOS-SNMPSHUT", "security", "medium", "SNMP is allowed to reload the device",
      "`snmp-server system-shutdown` lets an SNMP write request reload the device.", "Remove it.", "no snmp-server system-shutdown",
      families=F, domain="snmp", topics=("snmp-community", "least-functionality"), fn=forbid(r"^snmp-server system-shutdown"))

check("IOS-SNMPIFINDEX", "best_practice", "info", "Interface indexes may change after a reload",
      "Without `snmp-server ifindex persist`, graphs and thresholds in the monitoring system can attach to the wrong port after a reload.",
      "Keep interface indexes stable.", "snmp-server ifindex persist", families=F, domain="snmp", topics=("monitoring",), applies=SNMP,
      fn=need(r"^snmp-server ifindex persist", "no `snmp-server ifindex persist`"))


# ================================================================== logging and time
check("IOS-LOGON", "security", "medium", "Logging is switched off",
      "`no logging on` stops every log destination: console, buffer, syslog and traps.", "Turn logging back on.", "logging on",
      families=F, domain="logging", topics=("logging-central",), cis="2.2.1", fn=forbid(r"^no logging on$"))


@rule("IOS-LOGCONSOLE", "best_practice", "low", "Console logging is too verbose",
      "Logging every message to the console slows the CPU during an event storm, exactly when you need the device most.",
      "Limit console logging to critical messages (or turn it off).", "logging console critical",
      families=F, domain="logging", topics=("availability", "logging-content"), cis="2.2.3")
def log_console(ctx):
    if ctx.cfg.has(r"^no logging console$") or ctx.cfg.has(r"^logging console (critical|alerts|emergencies|[0-2])$"):
        return []
    lvl = ctx.cfg.find(r"^logging console")
    return [Hit("", f"`{lvl[0]}`" if lvl else "console logging at the default level (debugging)")]


check("IOS-LOGTRAP", "best_practice", "low", "Syslog level drops useful messages",
      "With the syslog level below informational, logins, configuration changes and interface events never reach the server.",
      "Send informational and above.", "logging trap informational", families=F, domain="logging", topics=("logging-content", "logging-central"),
      cis="2.2.5", applies=SYSLOG, fn=forbid(r"^logging trap (emergencies|alerts|critical|errors|warnings|[0-4])$"))

check("IOS-LOGSRC", "best_practice", "low", "Syslog has no fixed source interface",
      "Without a source interface, messages arrive from different addresses depending on the path, which breaks correlation in the SIEM.",
      "Source syslog from the loopback or management interface.", "logging source-interface Loopback0",
      families=F, domain="logging", topics=("logging-central", "mgmt-plane"), cis="2.2.7", applies=SYSLOG,
      fn=need(r"^logging source-interface ", "no `logging source-interface`"))

check("IOS-TSDEBUG", "best_practice", "low", "Debug messages lack timestamps",
      "Debug output without date and time cannot be lined up with other logs.", "Timestamp debug messages.",
      "service timestamps debug datetime msec localtime show-timezone", families=F, domain="logging", topics=("logging-content",), cis="2.2.6",
      fn=need(r"^service timestamps debug datetime", "`service timestamps debug datetime` is missing"))

check("IOS-LOG2", "best_practice", "low", "Only one syslog destination",
      "A single syslog server is a single point of failure for the audit trail.", "Send logs to two servers (or a load-balanced pair).",
      "logging host <syslog-1>\nlogging host <syslog-2>", families=F, domain="logging", topics=("logging-central", "availability"),
      applies=SYSLOG, fn=count_at_least(r"^logging (host )?\d", 2, "{found} syslog destination(s)"))

check("IOS-SEQNUM", "best_practice", "info", "Log messages are not numbered",
      "Sequence numbers show when log messages were lost or deleted.", "Number log messages.", "service sequence-numbers",
      families=F, domain="logging", topics=("logging-content",), fn=need(r"^service sequence-numbers", "`service sequence-numbers` is missing"))


@rule("IOS-LOGBUFSIZE", "best_practice", "low", "Local log buffer is small",
      "A buffer under 16 KB holds only a few minutes of events during an incident.", "Use at least 64 KB.", "logging buffered 64000 informational",
      families=F, domain="logging", topics=("logging-content",), cis="2.2.2", applies=has(r"^logging buffered"))
def log_buf(ctx):
    sizes = [int(x) for l in ctx.cfg.find(r"^logging buffered") for x in re.findall(r"\b(\d{3,})\b", l)]
    return [] if sizes and sizes[0] >= 16000 else [Hit("", f"buffer is {sizes[0] if sizes else 'the default (4096)'} bytes")]


@rule("IOS-HIDEKEYS", "security", "low", "The configuration change log can contain passwords",
      "`archive log config` without `hidekeys` writes the passwords and keys typed in configuration commands to the log.",
      "Add hidekeys.", "archive\n log config\n  hidekeys", families=F, domain="logging", topics=("credential-storage",),
      applies=lambda ctx: any("log config" in c for _h, ch in ctx.cfg.blocks(r"^archive$") for c in ch))
def hidekeys(ctx):
    return [] if any(c == "hidekeys" for _h, ch in ctx.cfg.blocks(r"^archive$") for c in ch) else [Hit("", "`hidekeys` is not set under archive log config")]


check("IOS-ARCHIVEPATH", "best_practice", "info", "No automatic configuration archive",
      "An archive path keeps copies of the configuration on each save, which allows `configure replace` to roll back.",
      "Archive the configuration on every write.", "archive\n path flash:archive/config\n write-memory\n maximum 10",
      families=F, domain="ops", topics=("config-mgmt",),
      fn=lambda ctx: [] if any(c.startswith("path ") for _h, ch in ctx.cfg.blocks(r"^archive$") for c in ch) else [Hit("", "no `archive / path`")])

check("IOS-NETFLOW", "best_practice", "low", "No flow export from a core or WAN device",
      "Flow records (NetFlow/IPFIX) show who talked to whom: essential for incident response and capacity planning.",
      "Export flows to your collector (VMap listens on UDP 2055).",
      "flow exporter VMAP\n destination <vmap-ip>\n transport udp 2055\nflow monitor VMAP\n exporter VMAP\n record netflow ipv4 original-input",
      families=F, domain="logging", topics=("monitoring",), applies=role_in("core", "router", "distribution", "wan"),
      fn=lambda ctx: [] if ctx.cfg.has(r"^(flow exporter |ip flow-export destination )") else [Hit("", "no flow exporter configured")])


@rule("IOS-NTPAUTH", "security", "medium", "NTP is not authenticated",
      "Without NTP authentication, anyone who can spoof the NTP server can shift the clock, breaking logs, certificates and time-based rules.",
      "Authenticate NTP with a key and mark it trusted.",
      "ntp authentication-key 1 hmac-sha2-256 <key>\nntp authenticate\nntp trusted-key 1\nntp server <ntp-1> key 1",
      families=F, domain="logging", topics=("time-auth",), cis="2.3.1.1,2.3.1.2,2.3.1.3,2.3.1.4", applies=NTP)
def ntp_auth(ctx):
    missing = [what for what, rx in (("ntp authenticate", r"^ntp authenticate$"), ("ntp authentication-key", r"^ntp authentication-key "),
                                     ("ntp trusted-key", r"^ntp trusted-key ")) if not ctx.cfg.has(rx)]
    nokey = [l.split()[2] for l in ctx.cfg.find(r"^ntp server ") if " key " not in l]
    if nokey:
        missing.append(f"servers without a key: {ports(nokey, 4)}")
    return [Hit("", "missing: " + "; ".join(missing))] if missing else []


check("IOS-NTP2", "best_practice", "low", "Only one NTP server",
      "With one source, a failed or wrong server goes unnoticed. Three or more sources let NTP reject a bad one.",
      "Configure at least two (ideally three) NTP servers.", "ntp server <ntp-1>\nntp server <ntp-2>\nntp server <ntp-3>",
      families=F, domain="logging", topics=("time-sync", "availability"), applies=NTP, fn=count_at_least(r"^ntp server ", 2, "{found} NTP server(s)"))

check("IOS-NTPSRC", "best_practice", "low", "NTP has no fixed source interface",
      "A fixed NTP source keeps server-side allow lists and authentication working when the path changes.",
      "Source NTP from the loopback or management interface.", "ntp source Loopback0", families=F, domain="logging",
      topics=("time-sync", "mgmt-plane"), cis="2.4.3", applies=NTP, fn=need(r"^ntp source ", "no `ntp source`"))

check("IOS-NTPACL", "security", "low", "The NTP service answers anyone",
      "Without `ntp access-group`, the device accepts NTP control and peer packets from any host, which allows time tampering and NTP amplification.",
      "Allow only your NTP servers to peer and serve.", "ip access-list standard NTP-SERVERS\n permit <ntp-1>\nntp access-group peer NTP-SERVERS",
      families=F, domain="logging", topics=("time-auth", "cp-protection"), applies=NTP, fn=need(r"^ntp access-group ", "no `ntp access-group`"))

check("IOS-NTPMASTER", "best_practice", "low", "The device is an authoritative NTP master",
      "`ntp master` serves the device's own unsynchronised clock as authoritative time, which can spread a wrong time across the network.",
      "Sync from a real reference instead.", "no ntp master", families=F, domain="logging", topics=("time-sync",), fn=forbid(r"^ntp master"))


# ================================================================== services
@rule("IOS-CDPEXT", "security", "medium", "Discovery protocols run on Internet-facing interfaces",
      "CDP and LLDP announce the model, software version and addresses to whoever is on the other side of the link.",
      "Turn CDP and LLDP off on provider and Internet links.", "interface <outside>\n no cdp enable\n no lldp transmit\n no lldp receive",
      families=F, domain="services", topics=("least-functionality", "boundary"), cis="2.1.2", applies=has_outside)
def cdp_ext(ctx):
    cdp_on = not ctx.cfg.has(r"^no cdp run$")
    lldp_on = ctx.cfg.has(r"^lldp run$")
    bad = []
    for h, ch in outside_ifaces(ctx):
        if (cdp_on and not child_has(ch, r"^no cdp enable")) or (lldp_on and not child_has(ch, r"^no lldp transmit")):
            bad.append(short(h))
    return [Hit("ports", ports(bad))] if bad else []


check("IOS-BOOTP", "security", "low", "BOOTP server not disabled",
      "The BOOTP service can hand out configuration and images to anyone who asks.", "Disable it.", "no ip bootp server",
      families=F, domain="services", topics=("least-functionality",), cis="2.1.3", fn=need(r"^no ip bootp server", "`no ip bootp server` is missing"))

check("IOS-DHCPSVC", "security", "low", "DHCP service runs without being used",
      "No DHCP pool, relay or snooping is configured, so the DHCP service is listening for nothing.", "Disable it.", "no service dhcp",
      families=F, domain="services", topics=("least-functionality",), cis="2.1.4",
      applies=lambda ctx: not ctx.cfg.all_lines(r"^(ip dhcp pool |ip helper-address |ip dhcp snooping|ip dhcp relay)"),
      fn=need(r"^no service dhcp", "`no service dhcp` is missing"))

check("IOS-IDENTD", "security", "low", "The identification (identd) service is on",
      "identd tells anyone who asks which user owns a TCP connection.", "Disable it.", "no ip identd",
      families=F, domain="services", topics=("least-functionality",), cis="2.1.5", fn=forbid(r"^ip identd$"))

check("IOS-KEEPIN", "best_practice", "low", "Dead incoming sessions are not cleaned up",
      "TCP keepalives detect sessions whose client vanished, freeing VTY lines that would otherwise stay busy.",
      "Enable incoming TCP keepalives.", "service tcp-keepalives-in", families=F, domain="services", topics=("session-timeout", "availability"),
      cis="2.1.6", fn=need(r"^service tcp-keepalives-in", "`service tcp-keepalives-in` is missing"))

check("IOS-KEEPOUT", "best_practice", "low", "Dead outgoing sessions are not cleaned up",
      "TCP keepalives on outgoing sessions close those whose peer disappeared.", "Enable outgoing TCP keepalives.",
      "service tcp-keepalives-out", families=F, domain="services", topics=("session-timeout", "availability"), cis="2.1.7",
      fn=need(r"^service tcp-keepalives-out", "`service tcp-keepalives-out` is missing"))

check("IOS-PAD", "security", "low", "The X.25 PAD service is not disabled",
      "PAD is a legacy X.25 service with no use on a modern network.", "Disable it.", "no service pad",
      families=F, domain="services", topics=("least-functionality",), cis="2.1.8", fn=need(r"^no service pad", "`no service pad` is missing"))

check("IOS-SVCCONFIG", "security", "low", "The device loads its configuration from the network at boot",
      "`service config` makes the device fetch configuration over TFTP at boot, which an attacker on the segment can answer.",
      "Disable network configuration loading.", "no service config", families=F, domain="services",
      topics=("config-mgmt", "software-integrity"), fn=forbid(r"^service config$"))

check("IOS-DNSSERVER", "security", "low", "The device is a DNS server",
      "`ip dns server` turns the device into a resolver that can be abused for amplification attacks.", "Disable it.", "no ip dns server",
      families=F, domain="services", topics=("least-functionality",), fn=forbid(r"^ip dns server$"))


# ================================================================== control and data plane
def _l3_without(ctx, rx, global_rx=None):
    if global_rx and ctx.cfg.has(global_rx):
        return []
    l3 = ios_l3(ctx)
    if not l3:
        return NA
    bad = [short(h) for h, ch in l3 if not child_has(ch, rx)]
    return [Hit("ports", f"{len(bad)} of {len(l3)} routed interfaces: {ports(bad)}")] if bad else []


check("IOS-PROXYARP", "security", "low", "Proxy ARP is on for routed interfaces",
      "Proxy ARP answers ARP requests for other networks, which hides addressing mistakes and helps man-in-the-middle attacks.",
      "Disable proxy ARP.", "ip arp proxy disable\n! or per interface:\ninterface <if>\n no ip proxy-arp", families=F, domain="control",
      topics=("cp-protection",), cis="3.1.2", fn=lambda ctx: _l3_without(ctx, r"^no ip proxy-arp", r"^ip arp proxy disable"))

check("IOS-REDIRECTS", "security", "low", "ICMP redirects are sent from routed interfaces",
      "ICMP redirects can be abused to steer hosts' traffic and cost CPU when traffic hairpins.", "Disable redirects.",
      "interface <if>\n no ip redirects", families=F, domain="control", topics=("cp-protection",),
      fn=lambda ctx: _l3_without(ctx, r"^no ip redirects"))

check("IOS-UNREACH", "security", "low", "ICMP unreachables are sent to the Internet",
      "Unreachable messages help scanners map the network and cost CPU under attack.", "Disable them on outside interfaces.",
      "interface <outside>\n no ip unreachables", families=F, domain="control", topics=("cp-protection", "boundary"), applies=has_outside,
      fn=lambda ctx: [Hit("ports", ports(short(h) for h, ch in outside_ifaces(ctx) if not child_has(ch, r"^no ip unreachables")))]
      if any(not child_has(ch, r"^no ip unreachables") for h, ch in outside_ifaces(ctx)) else [])

check("IOS-DIRBCAST", "security", "medium", "Directed broadcast is enabled",
      "`ip directed-broadcast` lets a single packet reach every host on a subnet: the basis of smurf amplification attacks.",
      "Disable it.", "interface <if>\n no ip directed-broadcast", families=F, domain="control", topics=("cp-protection", "anti-spoofing"),
      fn=lambda ctx: [Hit(short(h), f"{short(h)}: ip directed-broadcast") for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^ip directed-broadcast")])

check("IOS-URPF", "security", "medium", "No anti-spoofing (uRPF) on Internet-facing interfaces",
      "Unicast RPF drops packets whose source address could not have come from that interface, blocking spoofed traffic.",
      "Enable uRPF on outside interfaces (loose mode if you are multi-homed).", "interface <outside>\n ip verify unicast source reachable-via rx",
      families=F, domain="control", topics=("anti-spoofing",), cis="3.1.4", applies=has_outside,
      fn=lambda ctx: [Hit("ports", ports(short(h) for h, ch in outside_ifaces(ctx) if not child_has(ch, r"^ip verify unicast")))]
      if any(not child_has(ch, r"^ip verify unicast") for h, ch in outside_ifaces(ctx)) else [])

check("IOS-BORDERACL", "security", "high", "Internet-facing interface without an inbound filter",
      "An outside interface with no inbound access list accepts anything, including traffic to the device itself and spoofed private addresses.",
      "Apply an inbound access list that drops bogons and protects the device.",
      "ip access-list extended OUTSIDE-IN\n deny ip 10.0.0.0 0.255.255.255 any\n deny ip 172.16.0.0 0.15.255.255 any\n deny ip 192.168.0.0 0.0.255.255 any\n permit ip any any\ninterface <outside>\n ip access-group OUTSIDE-IN in",
      families=F, domain="control", topics=("boundary", "anti-spoofing"), cis="3.2.1,3.2.2", applies=has_outside,
      fn=lambda ctx: [Hit("ports", ports(short(h) for h, ch in outside_ifaces(ctx) if not child_has(ch, r"^ip access-group \S+ in")))]
      if any(not child_has(ch, r"^ip access-group \S+ in") for h, ch in outside_ifaces(ctx)) else [])


@rule("IOS-TUNNELENC", "security", "medium", "Tunnel without encryption",
      "A GRE tunnel without `tunnel protection` carries traffic in clear text across whatever network it crosses.",
      "Protect the tunnel with IPsec.", "interface Tunnel<n>\n tunnel protection ipsec profile <profile>",
      families=F, domain="control", topics=("data-crypto",), cis="3.1.3", applies=has(r"^interface Tunnel"))
def tunnel_enc(ctx):
    bad = [short(h) for h, ch in ctx.cfg.blocks(r"^interface Tunnel") if not child_has(ch, r"^shutdown$")
           and not child_has(ch, r"^tunnel protection ") and not child_has(ch, r"^tunnel mode ipsec")]
    return [Hit("ports", ports(bad))] if bad else []


@rule("IOS-COPP", "security", "medium", "No control-plane policing",
      "Control-plane policing rate-limits traffic to the CPU so a flood (or a loop) cannot starve routing, spanning tree and management.",
      "Apply a CoPP policy to the control plane.", "control-plane\n service-policy input <copp-policy>",
      families=F, domain="control", topics=("cp-protection", "availability"))
def copp(ctx):
    return [] if any(child_has(ch, r"^service-policy input ") for _h, ch in ctx.cfg.blocks(r"^control-plane")) else [Hit("", "no service-policy under control-plane")]


check("IOS-IPOPTIONS", "security", "low", "Packets with IP options are processed",
      "IP options are punted to the CPU; dropping them at the edge removes a cheap way to load the control plane.",
      "Drop packets with IP options.", "ip options drop", families=F, domain="control", topics=("cp-protection",), applies=has_outside,
      fn=need(r"^ip options (drop|ignore)", "`ip options drop` is missing"))


# ================================================================== routing protocols
@rule("IOS-OSPFAUTH", "security", "medium", "OSPF neighbours are not authenticated",
      "Without authentication, any device on a routed segment can form an adjacency and inject routes.",
      "Authenticate OSPF with SHA (key chain) or at least MD5.",
      "key chain OSPF\n key 1\n  key-string <key>\n  cryptographic-algorithm hmac-sha-256\ninterface <if>\n ip ospf authentication key-chain OSPF",
      families=F, domain="routing", topics=("routing-auth",), cis="3.3.2.1,3.3.2.2", applies=has(r"^router ospf "))
def ospf_auth(ctx):
    if any(child_has(ch, r"^area \S+ authentication") for _h, ch in ctx.cfg.blocks(r"^router ospf ")):
        return []
    ospf_ifs = [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^ip ospf ") and not child_has(ch, r"^shutdown$")]
    bad = [short(h) for h, ch in ospf_ifs if not child_has(ch, r"^ip ospf (authentication|message-digest-key)")]
    if not ospf_ifs:
        return [Hit("", "no OSPF authentication configured")]
    return [Hit("ports", f"interfaces without authentication: {ports(bad)}")] if bad else []


check("IOS-EIGRPAUTH", "security", "medium", "EIGRP neighbours are not authenticated",
      "Without authentication, any device on a segment can peer with EIGRP and inject routes.", "Authenticate EIGRP with a key chain.",
      "router eigrp NAMED\n address-family ipv4 unicast autonomous-system <as>\n  af-interface default\n   authentication mode hmac-sha-256 <key>",
      families=F, domain="routing", topics=("routing-auth",), cis="3.3.1.1,3.3.1.2", applies=has(r"^router eigrp "),
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^(ip authentication mode eigrp|authentication mode )") else [Hit("", "no EIGRP authentication configured")])


@rule("IOS-RIP", "security", "medium", "RIP without authentication",
      "RIP accepts routes from anyone on the segment unless authenticated; RIP version 1 cannot authenticate at all.",
      "Use RIPv2 with MD5 authentication, or move to OSPF.", "router rip\n version 2\ninterface <if>\n ip rip authentication mode md5\n ip rip authentication key-chain RIP",
      families=F, domain="routing", topics=("routing-auth",), cis="3.3.3.1,3.3.3.2", applies=has(r"^router rip"))
def rip(ctx):
    out = []
    if not any(child_has(ch, r"^version 2") for _h, ch in ctx.cfg.blocks(r"^router rip")):
        out.append(Hit("version", "RIP version 2 is not set"))
    if not ctx.cfg.all_lines(r"^ip rip authentication mode md5"):
        out.append(Hit("auth", "no RIP MD5 authentication"))
    return out


def _bgp(ctx):
    """[(neighbour, settings text)] with peer-group settings merged, and whether each is eBGP."""
    out = []
    for h, ch in ctx.cfg.blocks(r"^router bgp \d+"):
        local_as = h.split()[2]
        by = {}
        for c in ch:
            m = re.match(r"^neighbor (\S+) (.+)$", c)
            if m:
                by.setdefault(m.group(1), []).append(m.group(2))
        for n, opts in by.items():
            if "peer-group" in opts:
                continue                                   # a peer-group definition, not a neighbour
            merged = list(opts)
            for o in opts:
                if o.startswith("peer-group "):
                    merged += by.get(o.split()[1], [])
            ras = [o.split()[1] for o in merged if o.startswith("remote-as ")]
            if ras:
                out.append((n, " | ".join(merged), ras[0] != local_as))
    return out


check("IOS-BGPAUTH", "security", "medium", "BGP sessions without authentication",
      "An unauthenticated BGP session can be reset or hijacked with spoofed TCP packets.", "Add a TCP MD5 password (or TCP-AO) to each neighbour.",
      "router bgp <as>\n neighbor <ip> password <secret>", families=F, domain="routing", topics=("routing-auth",), cis="3.3.4.1",
      applies=has(r"^router bgp "),
      fn=lambda ctx: [Hit(n, f"neighbour {n}") for n, opts, _e in _bgp(ctx) if not re.search(r"(^| \| )(password|ao) ", opts)])

check("IOS-BGPMAXPFX", "best_practice", "low", "eBGP neighbours without a prefix limit",
      "A maximum-prefix limit protects the router if a peer suddenly sends a full table or leaks routes.", "Set maximum-prefix on eBGP sessions.",
      "router bgp <as>\n address-family ipv4\n  neighbor <ip> maximum-prefix <n> 90", families=F, domain="routing", topics=("routing-policy", "availability"),
      applies=has(r"^router bgp "),
      fn=lambda ctx: [Hit(n, f"neighbour {n}") for n, opts, ebgp in _bgp(ctx) if ebgp and "maximum-prefix" not in opts])

check("IOS-BGPFILTER", "security", "medium", "eBGP neighbours without an inbound filter",
      "Without an inbound prefix-list or route-map, the router accepts any route the peer announces, including your own prefixes and bogons.",
      "Filter what each eBGP peer may announce.", "router bgp <as>\n address-family ipv4\n  neighbor <ip> prefix-list FROM-PEER in",
      families=F, domain="routing", topics=("routing-policy", "boundary"), applies=has(r"^router bgp "),
      fn=lambda ctx: [Hit(n, f"neighbour {n}") for n, opts, ebgp in _bgp(ctx) if ebgp and not re.search(r"(prefix-list|route-map|filter-list|distribute-list) \S+ in", opts)])

check("IOS-BGPTTL", "best_practice", "info", "eBGP sessions without TTL security",
      "TTL security (GTSM) drops BGP packets that did not come from a directly connected peer, protecting against remote session attacks.",
      "Enable ttl-security on single-hop eBGP sessions.", "router bgp <as>\n neighbor <ip> ttl-security hops 1",
      families=F, domain="routing", topics=("routing-auth", "cp-protection"), applies=has(r"^router bgp "),
      fn=lambda ctx: [Hit(n, f"neighbour {n}") for n, opts, ebgp in _bgp(ctx) if ebgp and "ttl-security" not in opts and "ebgp-multihop" not in opts])

check("IOS-BGPLOG", "best_practice", "low", "BGP neighbour changes are not logged",
      "Logging neighbour up and down events is how session flaps and attacks are noticed.", "Log neighbour changes.",
      "router bgp <as>\n bgp log-neighbor-changes", families=F, domain="routing", topics=("monitoring",), applies=has(r"^router bgp "),
      fn=every(r"^router bgp ", r"^bgp log-neighbor-changes", "BGP processes"))

check("IOS-OSPFPASSIVE", "best_practice", "low", "OSPF is not passive by default",
      "Without `passive-interface default`, OSPF sends hellos on every matching interface, including user VLANs where anyone can answer.",
      "Make interfaces passive by default and enable only the transit links.",
      "router ospf <id>\n passive-interface default\n no passive-interface <transit-if>", families=F, domain="routing",
      topics=("routing-policy", "routing-auth"), applies=has(r"^router ospf "),
      fn=every(r"^router ospf ", r"^passive-interface default", "OSPF processes"))


@rule("IOS-FHRPAUTH", "security", "low", "HSRP or VRRP groups without authentication",
      "An unauthenticated first-hop redundancy group can be taken over by a host claiming a higher priority, becoming everyone's gateway.",
      "Authenticate HSRP/VRRP with MD5.", "interface <if>\n standby <grp> authentication md5 key-string <key>",
      families=F, domain="routing", topics=("routing-auth",), applies=has_any(r"^(standby|vrrp) \d+ ip"))
def fhrp(ctx):
    bad = []
    for h, ch in ctx.cfg.blocks(r"^interface "):
        for proto in ("standby", "vrrp"):
            for g in {m.group(1) for c in ch for m in [re.match(rf"^{proto} (\d+) ip", c)] if m}:
                if not child_has(ch, rf"^{proto} {g} authentication"):
                    bad.append(f"{short(h)} {proto} {g}")
    return [Hit("groups", ports(bad))] if bad else []


# ================================================================== layer 2 and edge
check("IOS-DAI", "security", "medium", "Dynamic ARP Inspection is off",
      "DAI drops ARP replies that do not match the DHCP snooping table, stopping ARP spoofing (man-in-the-middle) on user VLANs.",
      "Enable DAI on the user VLANs and trust the uplinks.", "ip arp inspection vlan <user-vlans>\ninterface <uplink>\n ip arp inspection trust",
      families=F, switch_only=True, domain="l2", topics=("l2-spoofing",), applies=both(edge_switch, SNOOP),
      fn=need(r"^ip arp inspection vlan ", "DHCP snooping is on but `ip arp inspection vlan` is not"))

check("IOS-DHCPTRUST", "best_practice", "medium", "DHCP snooping has no trusted port",
      "With snooping on and no trusted port, DHCP offers from the real server are dropped (unless the switch itself relays).",
      "Trust the uplinks towards the DHCP server.", "interface <uplink>\n ip dhcp snooping trust",
      families=F, switch_only=True, domain="l2", topics=("l2-spoofing", "availability"), applies=SNOOP,
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"^ip dhcp snooping trust") else [Hit("", "no interface has `ip dhcp snooping trust`")])

check("IOS-DHCPRATE", "security", "low", "DHCP requests from user ports are not rate-limited",
      "A host flooding DHCP requests can exhaust the scope and the switch CPU. A rate limit err-disables the port instead.",
      "Rate-limit DHCP on access ports.", "interface range <access-ports>\n ip dhcp snooping limit rate 15",
      families=F, switch_only=True, domain="l2", topics=("l2-spoofing", "cp-protection"), applies=both(edge_switch, SNOOP),
      fn=lambda ctx: (lambda bad: [Hit("ports", f"{len(bad)} access ports: {ports(bad)}")] if bad else [])(
          [short(h) for h, ch in ios_access(ctx) if not child_has(ch, r"^ip dhcp snooping limit rate")]))

check("IOS-IPSG", "security", "low", "IP Source Guard is off on user ports",
      "IP Source Guard drops traffic from addresses that DHCP did not give to that port, stopping IP spoofing from users.",
      "Enable IP Source Guard on access ports.", "interface range <access-ports>\n ip verify source",
      families=F, switch_only=True, domain="l2", topics=("l2-spoofing", "anti-spoofing"), applies=both(edge_switch, SNOOP),
      fn=lambda ctx: (lambda bad: [Hit("ports", f"{len(bad)} access ports: {ports(bad)}")] if bad else [])(
          [short(h) for h, ch in ios_access(ctx) if not child_has(ch, r"^ip verify source")]))

check("IOS-EDGEAUTH", "security", "medium", "User ports accept any device",
      "Access ports without 802.1X, MAB or port security let anyone plug in a laptop, a rogue access point or a small switch.",
      "Use 802.1X/MAB (preferred) or at least port security.",
      "interface <port>\n authentication port-control auto\n mab\n dot1x pae authenticator\n! or:\n switchport port-security\n switchport port-security maximum 2",
      families=F, switch_only=True, domain="l2", topics=("nac", "l2-spoofing"), applies=edge_switch,
      fn=lambda ctx: (lambda secs, bad: NA if not secs else ([Hit("ports", f"{len(bad)} of {len(secs)} access ports: {ports(bad)}")] if bad else []))(
          ios_access(ctx), [short(h) for h, ch in ios_access(ctx)
                            if not child_has(ch, r"^(switchport port-security$|switchport port-security maximum|authentication port-control|access-session port-control|dot1x pae authenticator|mab$)")]))

check("IOS-DOT1XGLOBAL", "security", "high", "802.1X is configured on ports but not enabled globally",
      "Ports carry 802.1X settings, but without `dot1x system-auth-control` nothing is enforced and every port is open.",
      "Enable 802.1X globally.", "dot1x system-auth-control", families=F, switch_only=True, domain="l2", topics=("nac",),
      applies=has_any(r"^(dot1x pae authenticator|authentication port-control|access-session port-control)"),
      fn=need(r"^dot1x system-auth-control", "`dot1x system-auth-control` is missing"))

check("IOS-LOOPGUARD", "best_practice", "low", "Loop Guard is not enabled",
      "Loop Guard stops a port that stops receiving BPDUs (for example a unidirectional fibre) from going forwarding and causing a loop.",
      "Enable Loop Guard globally.", "spanning-tree loopguard default", families=F, switch_only=True, domain="l2", topics=("l2-edge", "availability"),
      fn=need(r"^spanning-tree loopguard default", "`spanning-tree loopguard default` is missing"))

check("IOS-STPROOT", "best_practice", "medium", "Core switch does not set its spanning-tree priority",
      "If core and distribution switches do not set a low priority, any switch (even a new access switch) can become root.",
      "Make the core the primary root for every VLAN.", "spanning-tree vlan 1-4094 root primary",
      families=F, switch_only=True, domain="l2", topics=("availability", "l2-edge"), applies=role_in("core", "distribution"),
      fn=lambda ctx: [] if ctx.cfg.has(r"^spanning-tree (vlan \S+ (priority|root)|mst \S+ (priority|root))") else [Hit("", "no spanning-tree priority set")])

check("IOS-VTP", "security", "medium", "VTP can overwrite the VLAN database",
      "In VTP server or client mode, a switch plugged in with a higher revision number can replace or delete every VLAN on the network.",
      "Use VTP transparent or off (or VTPv3 with a primary server and a password).", "vtp mode transparent",
      families=F, switch_only=True, domain="l2", topics=("config-mgmt", "availability"),
      fn=lambda ctx: [] if ctx.cfg.has(r"^vtp (mode (transparent|off)|version 3)") else [Hit("", "VTP mode is server or client (not transparent/off)")])

check("IOS-NATIVETAG", "security", "low", "Native VLAN traffic is not tagged",
      "`vlan dot1q tag native` tags native VLAN traffic on trunks, which defeats double-tagging VLAN-hopping attacks.",
      "Tag the native VLAN.", "vlan dot1q tag native", families=F, switch_only=True, domain="l2", topics=("segmentation",),
      applies=lambda ctx: bool(ios_trunks(ctx)), fn=need(r"^vlan dot1q tag native", "`vlan dot1q tag native` is missing"))

check("IOS-SVI1", "security", "medium", "VLAN 1 has an IP address",
      "Management on VLAN 1 shares the default VLAN with every unconfigured port and with control protocols.",
      "Move management to a dedicated VLAN and shut interface Vlan1.", "interface Vlan1\n no ip address\n shutdown",
      families=F, domain="l2", topics=("segmentation", "mgmt-plane"),
      fn=lambda ctx: [Hit("Vlan1", "interface Vlan1 has an address and is up") for h, ch in ctx.cfg.blocks(r"^interface Vlan1$")
                      if child_has(ch, r"^ip address \d") and not child_has(ch, r"^shutdown$")])


@rule("IOS-PARKING", "best_practice", "low", "Shut ports are still in a production VLAN",
      "When a shut port is re-enabled by mistake it lands straight in a user VLAN. Park unused ports in a VLAN with no routing.",
      "Move shut ports to a parking VLAN.", "interface range <shut-ports>\n switchport access vlan <parking-vlan>",
      families=F, switch_only=True, domain="l2", topics=("segmentation",))
def parking(ctx):
    def vlan(ch):
        m = [c.split()[-1] for c in ch if c.startswith("switchport access vlan ")]
        return m[0] if m else "1"
    acc = [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^switchport mode access")]
    shut = [(h, ch) for h, ch in acc if child_has(ch, r"^shutdown$")]
    if not shut:
        return NA
    live = {vlan(ch) for h, ch in acc if not child_has(ch, r"^shutdown$")}
    bad = [short(h) for h, ch in shut if vlan(ch) in live or vlan(ch) == "1"]
    return [Hit("ports", f"{len(bad)} shut ports in active VLANs: {ports(bad)}")] if bad else []


check("IOS-RAGUARD", "security", "low", "No IPv6 RA Guard on user ports",
      "Even on an IPv4-only network, hosts accept IPv6 router advertisements. A rogue RA makes the attacker every host's IPv6 gateway.",
      "Attach an RA Guard policy to access ports (or VLANs).", "ipv6 nd raguard policy HOSTS\n device-role host\ninterface range <access-ports>\n ipv6 nd raguard attach-policy HOSTS",
      families=F, switch_only=True, domain="l2", topics=("l2-spoofing",), applies=edge_switch,
      fn=lambda ctx: [] if ctx.cfg.all_lines(r"ipv6 nd raguard") else [Hit("", "no `ipv6 nd raguard` policy attached")])


# ================================================================== operations
check("IOS-BOOTSYS", "best_practice", "low", "The boot image is not pinned",
      "Without `boot system`, the device boots the first image it finds in flash, which may be an old or untested one.",
      "Point boot system at the approved image.", "boot system flash:<image-or-packages.conf>",
      families=F, domain="ops", topics=("software-integrity", "config-mgmt"), fn=need(r"^boot system ", "no `boot system`"))

check("IOS-MEMRESERVE", "best_practice", "info", "No memory reserved for management",
      "Reserving memory for critical processes keeps the console and SSH usable when the device runs out of memory.",
      "Reserve memory for critical operations.", "memory reserve critical 1000\nmemory free low-watermark processor 20000",
      families=F, domain="ops", topics=("availability",), applies=lambda ctx: ctx.device.platform == "cisco_ios",
      fn=need(r"^memory (reserve critical|free low-watermark)", "no `memory reserve critical`"))


@rule("IOS-L3DESC", "best_practice", "low", "Routed interfaces without a description",
      "A description on each routed link says what is on the other side: a circuit ID, a neighbour, a VRF.",
      "Describe each routed interface.", "interface <if>\n description <neighbour or circuit>",
      families=F, domain="ops", topics=("inventory",))
def l3_desc(ctx):
    l3 = ios_l3(ctx)
    if not l3:
        return NA
    bad = [short(h) for h, ch in l3 if not child_has(ch, r"^description ")]
    return [Hit("ports", ports(bad))] if bad else []
