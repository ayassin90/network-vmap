"""Built-in security and best-practice rules. Each rule reads the saved configuration (and collected interface data)
and returns the problems it sees. Plain-English text here is what users read on the Findings page.

    @rule("SEC-TELNET", "security", "high", families=("cisco_ios",), title=..., why=..., fix=..., snippet=...)
    def telnet(ctx): return [Hit(key, detail)]
"""
import re
from dataclasses import dataclass

from .config import child_has

RULES = []


@dataclass
class Hit:
    key: str = ""
    detail: str = ""


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    families: tuple
    title: str
    why: str
    fix: str
    snippet: str
    fn: object
    switch_only: bool = False


def rule(id, category, severity, title, why, fix, snippet="", families=("cisco_ios",), switch_only=False):
    def deco(fn):
        RULES.append(Rule(id, category, severity, families, title, why, fix, snippet, fn, switch_only))
        return fn
    return deco


def _ports(lst, limit=12):
    lst = list(lst)
    return ", ".join(lst[:limit]) + (f" and {len(lst) - limit} more" if len(lst) > limit else "")


def access_sections(ctx):
    return [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^switchport mode access") and not child_has(ch, r"^shutdown$")]


def trunk_sections(ctx):
    return [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface ") if child_has(ch, r"^switchport mode trunk")]


# ------------------------------------------------------------------ security
@rule("SEC-TELNET", "security", "high", "Telnet is allowed on remote login lines",
      "Telnet sends usernames, passwords and every command in clear text. Anyone on the path can read them.",
      "Allow only SSH on the VTY lines.", "line vty 0 15\n transport input ssh", families=("cisco_ios", "cisco_nxos"))
def telnet(ctx):
    if ctx.family == "cisco_nxos":
        return [Hit("feature telnet", "feature telnet is enabled")] if ctx.cfg.has(r"^feature telnet") else []
    out = []
    for h, ch in ctx.cfg.blocks(r"^line vty"):
        t = [c for c in ch if c.startswith("transport input")]
        if any(re.search(r"\b(telnet|all)\b", c) for c in t):
            out.append(Hit(h, f"{h}: {t[0]}"))
    return out


@rule("SEC-SSHV2", "security", "medium", "SSH version 2 is not enforced",
      "SSH version 1 has known cryptographic weaknesses. Without `ip ssh version 2` the switch may accept it.",
      "Force SSH version 2.", "ip ssh version 2")
def sshv2(ctx):
    return [] if ctx.cfg.has(r"^ip ssh version 2") else [Hit("", "`ip ssh version 2` is missing")]


@rule("SEC-HTTP", "security", "high", "The web management server is enabled",
      "The HTTP/HTTPS server (Web UI) has been the entry point for critical attacks, for example CVE-2023-20198 on IOS-XE. "
      "Unless you use the Web UI, it should be off; if you need it, restrict who can reach it.",
      "Disable the web server, or restrict it with an access list.", "no ip http server\nno ip http secure-server")
def http(ctx):
    out = []
    if ctx.cfg.has(r"^ip http server$"):
        out.append(Hit("ip http server", "`ip http server` is on (plain HTTP)"))
    if ctx.cfg.has(r"^ip http secure-server$") and not ctx.cfg.has(r"^ip http access-class"):
        out.append(Hit("ip http secure-server", "`ip http secure-server` is on with no access-class"))
    return out


@rule("SEC-SMI", "security", "high", "Smart Install may be enabled",
      "Smart Install (vstack) lets anyone who can reach TCP 4786 replace the configuration or image without a password "
      "(CVE-2018-0171 and others). It is on by default on many Catalyst switches.",
      "Turn Smart Install off. Check with `show vstack config`.", "no vstack", switch_only=True)
def smi(ctx):
    if ctx.device.platform not in ("cisco_ios", "cisco_iosxe"):
        return []
    return [] if ctx.cfg.has(r"^no vstack") else [Hit("", "No `no vstack` line in the configuration")]


@rule("SEC-PWENC", "security", "medium", "Passwords are stored in clear text",
      "Without `service password-encryption`, line and local passwords appear readable in the configuration and in backups.",
      "Turn on password encryption (and prefer `secret` over `password`).", "service password-encryption")
def pwenc(ctx):
    return [] if ctx.cfg.has(r"^service password-encryption") else [Hit("", "`service password-encryption` is missing")]


@rule("SEC-ENABLEPW", "security", "high", "Enable password uses weak or no hashing",
      "`enable password` is stored in clear text or with reversible type 7 encoding. It can be recovered in seconds.",
      "Remove it and use an `enable secret` with a strong hash (type 9, scrypt).",
      "no enable password\nenable algorithm-type scrypt secret <new-secret>")
def enable_pw(ctx):
    return [Hit("enable password", "`enable password` is configured")] if ctx.cfg.has(r"^enable password") else []


@rule("SEC-USERPW", "security", "high", "Local users have weak password storage",
      "Local accounts configured with `password` (type 0 or 7) can be decoded by anyone who sees the configuration.",
      "Recreate those users with `secret` and a strong hash (type 9, scrypt).",
      "username <name> privilege 15 algorithm-type scrypt secret <new-secret>")
def user_pw(ctx):
    return [Hit(l.split()[1], l.split(" password")[0] + " password …") for l in ctx.cfg.find(r"^username \S+ .*password [07]? ?\S")]


@rule("SEC-MD5SECRET", "security", "low", "Secrets use the old MD5 hash (type 5)",
      "Type 5 secrets use MD5, which can be brute-forced quickly with modern hardware.",
      "Re-enter the secrets with type 9 (scrypt) or type 8 (PBKDF2).", "enable algorithm-type scrypt secret <new-secret>")
def md5(ctx):
    return [Hit(l.split()[0] + " " + l.split()[1], "type 5 secret") for l in ctx.cfg.find(r"^(enable|username \S+.*) secret 5 ")]


@rule("SEC-AAA", "security", "medium", "AAA is not enabled",
      "Without `aaa new-model` the switch cannot use central authentication (TACACS+/RADIUS), per-command authorisation or accounting.",
      "Enable AAA and point it at your TACACS+ or RADIUS servers, with local fallback.",
      "aaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local\naaa accounting commands 15 default start-stop group tacacs+")
def aaa(ctx):
    return [] if ctx.cfg.has(r"^aaa new-model") else [Hit("", "`aaa new-model` is missing")]


@rule("SEC-SNMPDEF", "security", "critical", "SNMP uses a default community string",
      "`public` and `private` are the first strings every scanner tries. With them an attacker can read (or change) the device.",
      "Remove the default communities. Use SNMPv3 with authentication and encryption.",
      "no snmp-server community public\nno snmp-server community private", families=("cisco_ios", "cisco_nxos", "aruba_aoscx", "arista_eos"))
def snmp_default(ctx):
    return [Hit(m.group(1), f"community `{m.group(1)}`") for l in ctx.cfg.find(r"^snmp-server community (public|private)\b")
            for m in [re.match(r"^snmp-server community (\S+)", l)]]


@rule("SEC-SNMPRW", "security", "high", "An SNMP community allows writes",
      "A read-write community lets anyone who knows it change the configuration over SNMP, which is rarely needed.",
      "Change it to read-only, or remove it.", "snmp-server community <string> RO <acl>", families=("cisco_ios", "cisco_nxos"))
def snmp_rw(ctx):
    return [Hit(l.split()[2][:3] + "…", "read-write community") for l in ctx.cfg.find(r"^snmp-server community \S+ .*\b(RW|rw)\b")]


@rule("SEC-SNMPACL", "security", "medium", "SNMP communities are not limited to known managers",
      "A community without an access list answers anyone who can reach the switch.",
      "Add an access list with your monitoring servers to each community.",
      "ip access-list standard SNMP-MANAGERS\n permit <nms-ip>\nsnmp-server community <string> RO SNMP-MANAGERS")
def snmp_acl(ctx):
    out = []
    for l in ctx.cfg.find(r"^snmp-server community "):
        parts = l.split()
        if len(parts) <= 4 and not (len(parts) == 4 and parts[3] not in ("RO", "RW", "ro", "rw")):
            out.append(Hit(parts[2][:3] + "…", "community without an access list"))
    return out


@rule("SEC-SNMPV3", "security", "low", "SNMP v1/v2c is used without SNMPv3",
      "SNMP v1 and v2c send the community string in clear text. SNMPv3 adds authentication and encryption.",
      "Configure an SNMPv3 group and user with authPriv, then remove the v2c communities.",
      "snmp-server group NMS v3 priv\nsnmp-server user nms NMS v3 auth sha <auth-pass> priv aes 128 <priv-pass>")
def snmp_v3(ctx):
    return [Hit("", "only community-based SNMP configured")] if ctx.cfg.has(r"^snmp-server community") and not ctx.cfg.has(r"^snmp-server group \S+ v3") else []


@rule("SEC-VTYACL", "security", "medium", "Remote login is open to any address",
      "VTY lines without an `access-class` accept SSH from anywhere that can reach the switch.",
      "Limit remote login to your management subnets.",
      "ip access-list standard MGMT\n permit <mgmt-subnet> <wildcard>\nline vty 0 15\n access-class MGMT in")
def vty_acl(ctx):
    return [Hit(h, f"{h} has no access-class") for h, ch in ctx.cfg.blocks(r"^line vty") if not child_has(ch, r"^access-class \S+ in")
            and not child_has(ch, r"^transport input none")]


@rule("SEC-TIMEOUT", "security", "medium", "Idle sessions never time out",
      "`exec-timeout 0 0` keeps an abandoned session logged in forever, for anyone who walks up to it.",
      "Set an idle timeout of 10 minutes or less.", "line con 0\n exec-timeout 10 0\nline vty 0 15\n exec-timeout 10 0")
def timeout(ctx):
    return [Hit(h, f"{h}: exec-timeout 0 0") for h, ch in ctx.cfg.blocks(r"^line (con|vty)") if child_has(ch, r"^exec-timeout 0( 0)?$")]


@rule("SEC-BANNER", "security", "low", "No login warning banner",
      "A login banner states that access is restricted. Many legal and audit frameworks require one.",
      "Add a login banner.", "banner login ^\nAuthorised access only. Activity is logged.\n^", families=("cisco_ios", "cisco_nxos", "aruba_aoscx", "arista_eos"))
def banner(ctx):
    return [] if ctx.cfg.has(r"^banner (login|motd)") else [Hit("", "no banner login or banner motd")]


@rule("SEC-SMALLSRV", "security", "medium", "Legacy small services are on",
      "TCP/UDP small servers, finger and bootp are old services with no modern use that widen the attack surface.",
      "Turn them off.", "no service tcp-small-servers\nno service udp-small-servers\nno ip finger\nno ip bootp server")
def small(ctx):
    return [Hit(l, l) for l in ctx.cfg.find(r"^(service (tcp|udp)-small-servers|ip finger|service finger)$")]


@rule("SEC-SRCROUTE", "security", "low", "IP source routing is not disabled",
      "Source-routed packets let a sender choose the path through your network, which can bypass filters.",
      "Disable IP source routing.", "no ip source-route")
def srcroute(ctx):
    return [] if ctx.cfg.has(r"^no ip source-route") else [Hit("", "`no ip source-route` is missing")]


@rule("SEC-LOGINBLOCK", "security", "low", "No protection against password guessing",
      "Without `login block-for`, an attacker can try passwords as fast as the switch answers.",
      "Block logins for a while after repeated failures.", "login block-for 120 attempts 5 within 60")
def loginblock(ctx):
    return [] if ctx.cfg.has(r"^login block-for") else [Hit("", "`login block-for` is missing")]


@rule("SEC-DHCPSNOOP", "security", "medium", "DHCP snooping is off",
      "Without DHCP snooping, any user port can run a rogue DHCP server and redirect traffic. It is also needed for "
      "Dynamic ARP Inspection and IP Source Guard.",
      "Enable DHCP snooping on user VLANs and trust only uplinks.",
      "ip dhcp snooping\nip dhcp snooping vlan <user-vlans>\ninterface <uplink>\n ip dhcp snooping trust", switch_only=True)
def dhcp_snoop(ctx):
    if ctx.device.role in ("core", "router", "datacenter") or not access_sections(ctx):
        return []
    return [] if ctx.cfg.has(r"^ip dhcp snooping$") else [Hit("", "access ports exist but `ip dhcp snooping` is off")]


@rule("SEC-NXFEATURES", "security", "low", "Unneeded management features enabled",
      "Every enabled feature is code that can be attacked. Turn off what you do not use.",
      "Disable unused features.", "no feature telnet\nno feature nxapi", families=("cisco_nxos",))
def nx_feat(ctx):
    return [Hit(l, l) for l in ctx.cfg.find(r"^feature (nxapi|telnet|scp-server)$")]


# ------------------------------------------------------------------ best practice
@rule("BP-NTP", "best_practice", "medium", "No NTP server configured",
      "Without NTP, log timestamps drift and cannot be correlated across devices during an incident. Certificates may also fail.",
      "Point the switch at two or more NTP servers.", "ntp server <ntp-1>\nntp server <ntp-2>", families=("cisco_ios", "cisco_nxos", "aruba_aoscx", "arista_eos"))
def ntp(ctx):
    return [] if ctx.cfg.has(r"^ntp server ") else [Hit("", "no `ntp server` line")]


@rule("BP-SYSLOG", "best_practice", "medium", "Logs are not sent to a syslog server",
      "Logs that only live on the switch are lost on reload and are hard to search. Send them to a central server or SIEM.",
      "Send logs to your syslog server.", "logging host <syslog-ip>\nlogging trap informational", families=("cisco_ios", "cisco_nxos", "aruba_aoscx", "arista_eos"))
def syslog(ctx):
    return [] if ctx.cfg.has(r"^logging (host |server |\d+\.\d+)") else [Hit("", "no `logging host` line")]


@rule("BP-LOGBUF", "best_practice", "low", "Local log buffer not sized",
      "A larger local buffer keeps recent events for troubleshooting when the syslog server is unreachable.",
      "Set a local log buffer.", "logging buffered 64000 informational")
def logbuf(ctx):
    return [] if ctx.cfg.has(r"^logging buffered") else [Hit("", "`logging buffered` is not set")]


@rule("BP-TIMESTAMPS", "best_practice", "low", "Log messages lack precise timestamps",
      "Millisecond timestamps with the date make it possible to line up events across devices.",
      "Add date and millisecond timestamps.", "service timestamps log datetime msec localtime show-timezone\nservice timestamps debug datetime msec localtime show-timezone")
def timestamps(ctx):
    return [] if ctx.cfg.has(r"^service timestamps log datetime msec") else [Hit("", "`service timestamps log datetime msec` is missing")]


@rule("BP-STPMODE", "best_practice", "medium", "Spanning tree runs the legacy PVST mode",
      "Classic PVST+ takes 30 to 50 seconds to recover from a failure. Rapid PVST+ or MST converge in about a second.",
      "Move to Rapid PVST+ (plan a short window; it is safe with other Cisco switches).", "spanning-tree mode rapid-pvst", switch_only=True)
def stp_mode(ctx):
    if ctx.cfg.has(r"^spanning-tree mode (rapid-pvst|mst)"):
        return []
    return [Hit("", "spanning-tree mode is pvst (default)")]


@rule("BP-PORTFAST", "best_practice", "low", "Access ports without PortFast",
      "Without PortFast, a PC or phone waits 30 seconds for the port to forward, which breaks DHCP and PXE boot on some clients.",
      "Enable PortFast on access ports (or globally for all access ports).", "spanning-tree portfast default", switch_only=True)
def portfast(ctx):
    if ctx.cfg.has(r"^spanning-tree portfast (edge )?default"):
        return []
    bad = [h.split(" ", 1)[1] for h, ch in access_sections(ctx) if not child_has(ch, r"^spanning-tree portfast")]
    return [Hit("ports", f"{len(bad)} access ports: {_ports(bad)}")] if bad else []


@rule("BP-BPDUGUARD", "best_practice", "medium", "Access ports without BPDU Guard",
      "BPDU Guard shuts an access port that suddenly hears a switch. It stops a user from creating a loop or taking over the root bridge.",
      "Enable BPDU Guard on all PortFast ports.", "spanning-tree portfast bpduguard default", switch_only=True)
def bpduguard(ctx):
    if ctx.cfg.has(r"^spanning-tree portfast (edge )?bpduguard default"):
        return []
    bad = [h.split(" ", 1)[1] for h, ch in access_sections(ctx) if not child_has(ch, r"^spanning-tree bpduguard enable")]
    return [Hit("ports", f"{len(bad)} access ports: {_ports(bad)}")] if bad else []


@rule("BP-STORM", "best_practice", "low", "Access ports without storm control",
      "Storm control caps broadcast traffic from one port so a faulty NIC or a loop cannot flood the VLAN.",
      "Add broadcast storm control to access ports.", "interface range <access-ports>\n storm-control broadcast level 1.00\n storm-control action trap", switch_only=True)
def storm(ctx):
    bad = [h.split(" ", 1)[1] for h, ch in access_sections(ctx) if not child_has(ch, r"^storm-control broadcast")]
    return [Hit("ports", f"{len(bad)} access ports: {_ports(bad)}")] if bad else []


@rule("BP-UNUSED", "best_practice", "low", "Unused ports are left enabled",
      "Ports with nothing connected but still enabled let anyone plug in. Shut them and move them to an unused 'parking' VLAN.",
      "Shut unused ports and park them.", "interface range <unused-ports>\n switchport access vlan <parking-vlan>\n shutdown", switch_only=True)
def unused(ctx):
    bad = [i.short for i in ctx.interfaces if i.is_physical and i.admin_up and i.status == "notconnect" and i.mode == "access"]
    return [Hit("ports", f"{len(bad)} ports not connected but enabled: {_ports(bad)}")] if len(bad) >= 1 else []


@rule("BP-NATIVE1", "best_practice", "medium", "Trunks use VLAN 1 as the native VLAN",
      "Untagged traffic on VLAN 1 enables VLAN-hopping (double tagging) attacks and mixes control traffic with user traffic.",
      "Use an unused VLAN as native on every trunk (the same on both ends).", "interface <trunk>\n switchport trunk native vlan <unused-vlan>", switch_only=True)
def native1(ctx):
    bad = [i.short for i in ctx.interfaces if i.mode == "trunk" and i.native_vlan in ("1", "") and i.oper_up]
    return [Hit("ports", f"trunks: {_ports(bad)}")] if bad else []


@rule("BP-TRUNKALL", "best_practice", "low", "Trunks carry every VLAN",
      "A trunk that allows all VLANs extends every broadcast domain everywhere. Allow only the VLANs that are needed.",
      "Prune the allowed VLAN list.", "interface <trunk>\n switchport trunk allowed vlan <needed-vlans>", switch_only=True)
def trunk_all(ctx):
    bad = [i.short for i in ctx.interfaces if i.mode == "trunk" and i.oper_up and re.sub(r"\s", "", i.trunk_vlans).upper() in ("1-4094", "ALL", "1-4093", "")]
    return [Hit("ports", f"trunks: {_ports(bad)}")] if bad else []


@rule("BP-DTP", "best_practice", "medium", "Ports negotiate trunking automatically (DTP)",
      "Ports without an explicit `switchport mode` can be turned into a trunk by whatever is plugged in, giving access to every VLAN.",
      "Set every port explicitly to access or trunk, and turn off negotiation on trunks.",
      "interface <port>\n switchport mode access\n! trunks:\n switchport mode trunk\n switchport nonegotiate", switch_only=True)
def dtp(ctx):
    bad = []
    for h, ch in ctx.cfg.blocks(r"^interface (Gi|Te|Fa|Tw|Fi|Twe|Fo|Hu|GigabitEthernet|TenGigabitEthernet|FastEthernet|TwoGigabitEthernet|FiveGigabitEthernet|TwentyFiveGigE|FortyGigabitEthernet|HundredGigE)\S*\d$"):
        if not child_has(ch, r"^(switchport mode|no switchport|shutdown$|channel-group)"):
            bad.append(h.split(" ", 1)[1])
    trunks_neg = [h.split(" ", 1)[1] for h, ch in trunk_sections(ctx) if not child_has(ch, r"^switchport nonegotiate")]
    out = []
    if bad:
        out.append(Hit("dynamic", f"{len(bad)} ports without switchport mode: {_ports(bad)}"))
    if trunks_neg and len(trunks_neg) > 0:
        out.append(Hit("nonegotiate", f"{len(trunks_neg)} trunks still send DTP: {_ports(trunks_neg)}"))
    return out


@rule("BP-VLAN1", "best_practice", "medium", "User ports are in VLAN 1",
      "VLAN 1 is the default for everything (including control protocols). Putting users there mixes them with infrastructure traffic.",
      "Move users to a dedicated VLAN.", "interface <port>\n switchport access vlan <user-vlan>", switch_only=True)
def vlan1(ctx):
    bad = [i.short for i in ctx.interfaces if i.mode == "access" and i.access_vlan == "1" and i.oper_up and i.is_physical]
    return [Hit("ports", f"{len(bad)} active ports in VLAN 1: {_ports(bad)}")] if bad else []


@rule("BP-DNSLOOKUP", "best_practice", "info", "Mistyped commands trigger DNS lookups",
      "With domain lookup on, a typo at the CLI hangs while the switch tries to resolve it as a hostname.",
      "Turn off domain lookup (unless the switch needs DNS).", "no ip domain lookup")
def dnslookup(ctx):
    return [] if ctx.cfg.has(r"^no ip domain[- ]lookup") else [Hit("", "`no ip domain lookup` is missing")]


@rule("BP-ARCHIVE", "best_practice", "low", "Configuration changes are not logged",
      "`archive log config` records who changed what. It makes changes traceable without waiting for the next backup.",
      "Turn on configuration change logging.", "archive\n log config\n  logging enable\n  notify syslog contenttype plaintext\n  hidekeys")
def archive(ctx):
    return [] if ctx.cfg.blocks(r"^archive$") and "log config" in "\n".join(ch for _h, chs in ctx.cfg.blocks(r"^archive$") for ch in chs) else [Hit("", "no `archive / log config`")]


@rule("BP-ERRREC", "best_practice", "info", "Err-disabled ports never recover by themselves",
      "Ports shut by BPDU Guard, storm control or link flap stay down until someone resets them. Automatic recovery after a delay helps users.",
      "Enable automatic recovery for common causes.", "errdisable recovery cause bpduguard\nerrdisable recovery cause link-flap\nerrdisable recovery interval 300", switch_only=True)
def errrec(ctx):
    return [] if ctx.cfg.has(r"^errdisable recovery cause") else [Hit("", "no `errdisable recovery cause`")]


@rule("BP-UPLINKDESC", "best_practice", "low", "Uplinks and trunks without a description",
      "Descriptions on uplinks tell the next engineer what is on the other end. VMap can suggest them from CDP/LLDP.",
      "Describe each trunk with the neighbour name and port.", "interface <trunk>\n description <neighbour>:<port>")
def uplinkdesc(ctx):
    bad = [i.short for i in ctx.interfaces if i.mode == "trunk" and i.oper_up and not i.description and not i.port_channel]
    return [Hit("ports", f"{_ports(bad)}")] if bad else []


# ------------------------------------------------------------------ Aruba AOS-CX
def cx_access(ctx):
    return [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface \d+/\d+/\d+$") if child_has(ch, r"^vlan access ") and not child_has(ch, r"^shutdown$")]


@rule("CX-BPDU", "best_practice", "medium", "Access ports without BPDU guard (AOS-CX)",
      "BPDU guard disables an edge port that suddenly hears a switch, stopping loops and rogue root bridges.",
      "Enable BPDU guard and admin-edge on access ports.", "interface <port>\n    spanning-tree bpdu-guard\n    spanning-tree port-type admin-edge",
      families=("aruba_aoscx",), switch_only=True)
def cx_bpdu(ctx):
    bad = [h.split(" ", 1)[1] for h, ch in cx_access(ctx) if not child_has(ch, r"^spanning-tree bpdu-guard")]
    return [Hit("ports", f"{len(bad)} access ports: {_ports(bad)}")] if bad else []


@rule("CX-LOOP", "best_practice", "low", "Loop protection off on access ports (AOS-CX)",
      "Loop-protect catches loops that spanning tree cannot see, such as a small unmanaged switch looped back on itself.",
      "Enable loop protection on access ports.", "interface <port>\n    loop-protect", families=("aruba_aoscx",), switch_only=True)
def cx_loop(ctx):
    bad = [h.split(" ", 1)[1] for h, ch in cx_access(ctx) if not child_has(ch, r"^loop-protect")]
    return [Hit("ports", f"{len(bad)} access ports: {_ports(bad)}")] if bad else []


@rule("CX-AAA", "security", "medium", "No central authentication (AOS-CX)",
      "Without AAA, every admin shares local accounts and nothing is accounted for centrally.",
      "Point login authentication at TACACS+ or RADIUS with local fallback.",
      "aaa authentication login default group tacacs local", families=("aruba_aoscx",))
def cx_aaa(ctx):
    return [] if ctx.cfg.has(r"^aaa authentication login default") else [Hit("", "no `aaa authentication login default`")]


# ------------------------------------------------------------------ Huawei VRP
def hw_access(ctx):
    return [(h, ch) for h, ch in ctx.cfg.blocks(r"^interface (X?GigabitEthernet|MultiGE)") if child_has(ch, r"^port link-type access") and not child_has(ch, r"^shutdown$")]


@rule("HW-TELNET", "security", "high", "Telnet is enabled (Huawei)",
      "Telnet sends passwords and commands in clear text.", "Turn the Telnet server off and allow only SSH (STelnet) on the VTY lines.",
      "undo telnet server enable\nuser-interface vty 0 4\n protocol inbound ssh", families=("huawei_vrp",))
def hw_telnet(ctx):
    hits = []
    if ctx.cfg.has(r"^telnet server enable"):
        hits.append(Hit("server", "`telnet server enable`"))
    for h, ch in ctx.cfg.blocks(r"^user-interface vty"):
        if child_has(ch, r"^protocol inbound (all|telnet)"):
            hits.append(Hit(h, f"{h}: protocol inbound allows Telnet"))
    return hits


@rule("HW-NTP", "best_practice", "medium", "No NTP server configured (Huawei)", "Without NTP, log times drift and cannot be correlated.",
      "Add your NTP servers.", "ntp-service unicast-server <ntp-1>", families=("huawei_vrp",))
def hw_ntp(ctx):
    return [] if ctx.cfg.has(r"^ntp-service unicast-server") else [Hit("", "no `ntp-service unicast-server`")]


@rule("HW-SYSLOG", "best_practice", "medium", "Logs are not sent to a syslog server (Huawei)", "Keep logs off the box.",
      "Send logs to your syslog server.", "info-center loghost <syslog-ip>", families=("huawei_vrp",))
def hw_syslog(ctx):
    return [] if ctx.cfg.has(r"^info-center loghost") else [Hit("", "no `info-center loghost`")]


@rule("HW-SNMPV2", "security", "low", "SNMP v1/v2c enabled without v3 (Huawei)",
      "Community strings travel in clear text. SNMPv3 adds authentication and encryption.",
      "Move monitoring to SNMPv3 and disable v1/v2c.", "snmp-agent sys-info version v3", families=("huawei_vrp",))
def hw_snmp(ctx):
    return [Hit("", "community-based SNMP enabled")] if ctx.cfg.has(r"^snmp-agent sys-info version (v2c|v1|all)") and not ctx.cfg.has(r"^snmp-agent usm-user v3") else []


@rule("HW-EDGE", "best_practice", "medium", "Access ports are not edge ports (Huawei)",
      "Edge ports skip the spanning-tree listening delay and, with BPDU protection, shut if a switch is plugged in.",
      "Make access ports edge ports and enable BPDU protection.", "stp bpdu-protection\ninterface <port>\n stp edged-port enable",
      families=("huawei_vrp",), switch_only=True)
def hw_edge(ctx):
    out = []
    if not ctx.cfg.has(r"^stp edged-port default"):
        bad = [h.split(" ", 1)[1] for h, ch in hw_access(ctx) if not child_has(ch, r"^stp edged-port enable")]
        if bad:
            out.append(Hit("ports", f"{len(bad)} access ports: {_ports(bad)}"))
    if hw_access(ctx) and not ctx.cfg.has(r"^stp bpdu-protection"):
        out.append(Hit("bpdu", "`stp bpdu-protection` is not enabled"))
    return out


# ------------------------------------------------------------------ Arista EOS
@rule("EOS-TELNET", "security", "high", "Telnet management is enabled (Arista)",
      "Telnet sends passwords and commands in clear text.", "Shut the Telnet management service; SSH is on by default.",
      "management telnet\n   shutdown", families=("arista_eos",))
def eos_telnet(ctx):
    return [Hit("telnet", "`management telnet` is not shut down") for h, ch in ctx.cfg.blocks(r"^management telnet") if child_has(ch, r"^no shutdown")]


@rule("EOS-EAPI-HTTP", "security", "medium", "eAPI answers over plain HTTP (Arista)",
      "The command API over HTTP sends credentials unencrypted. Use HTTPS only, and limit it to the management VRF.",
      "Allow eAPI over HTTPS only.", "management api http-commands\n   no protocol http\n   protocol https", families=("arista_eos",))
def eos_eapi(ctx):
    return [Hit("eapi", "`protocol http` is enabled under eAPI") for h, ch in ctx.cfg.blocks(r"^management api http-commands")
            if child_has(ch, r"^protocol http$")]


@rule("EOS-BPDU", "best_practice", "medium", "Edge ports without BPDU guard (Arista)",
      "BPDU guard shuts an edge port that suddenly hears a switch, stopping loops and rogue root bridges.",
      "Enable BPDU guard on edge ports (or globally for all portfast ports).",
      "spanning-tree edge-port bpduguard default", families=("arista_eos",), switch_only=True)
def eos_bpdu(ctx):
    if ctx.cfg.has(r"^spanning-tree edge-port bpduguard default"):
        return []
    bad = [h.split(" ", 1)[1] for h, ch in ctx.cfg.blocks(r"^interface Ethernet") if child_has(ch, r"^spanning-tree portfast")
           and not child_has(ch, r"^spanning-tree bpduguard enable")]
    return [Hit("ports", f"{len(bad)} edge ports: {_ports(bad)}")] if bad else []


# ------------------------------------------------------------------ Juniper Junos (configuration in `display set` form)
@rule("JUN-TELNET", "security", "high", "Telnet service is enabled (Junos)",
      "Telnet sends passwords and commands in clear text.", "Remove the Telnet service; use SSH.", "delete system services telnet",
      families=("juniper_junos",))
def jun_telnet(ctx):
    return [Hit("telnet", "`set system services telnet`")] if ctx.cfg.has(r"^set system services telnet") else []


@rule("JUN-HTTP", "security", "medium", "J-Web over plain HTTP (Junos)",
      "J-Web over HTTP sends the login in clear text.", "Disable HTTP for J-Web; use HTTPS or turn J-Web off.",
      "delete system services web-management http", families=("juniper_junos",))
def jun_http(ctx):
    return [Hit("http", "`web-management http` is enabled")] if ctx.cfg.has(r"^set system services web-management http\b") else []


@rule("JUN-ROOTSSH", "security", "high", "Root can log in over SSH (Junos)",
      "Direct root login removes accountability and is the first account attackers try.",
      "Deny root login over SSH; use named accounts.", "set system services ssh root-login deny", families=("juniper_junos",))
def jun_rootssh(ctx):
    return [] if ctx.cfg.has(r"^set system services ssh root-login deny") else [Hit("root", "`ssh root-login deny` is not set")]


@rule("JUN-SNMP", "security", "high", "Default SNMP community (Junos)", "`public` and `private` are the first strings every scanner tries.",
      "Remove the default community; prefer SNMPv3.", "delete snmp community public", families=("juniper_junos",))
def jun_snmp(ctx):
    return [Hit(m, f"community `{m}`") for m in re.findall(r"^set snmp community (public|private)\b", "\n".join(ctx.cfg.globals), re.M)]


@rule("JUN-NTP", "best_practice", "medium", "No NTP server configured (Junos)", "Without NTP, log times drift and cannot be correlated.",
      "Add your NTP servers.", "set system ntp server <ntp-1>", families=("juniper_junos",))
def jun_ntp(ctx):
    return [] if ctx.cfg.has(r"^set system ntp server ") else [Hit("", "no `system ntp server`")]


@rule("JUN-SYSLOG", "best_practice", "medium", "Logs are not sent to a syslog server (Junos)", "Keep logs off the box.",
      "Send logs to your syslog server.", "set system syslog host <syslog-ip> any notice", families=("juniper_junos",))
def jun_syslog(ctx):
    return [] if ctx.cfg.has(r"^set system syslog host ") else [Hit("", "no `system syslog host`")]


@rule("JUN-BPDU", "best_practice", "medium", "Edge ports are not protected against BPDUs (Junos)",
      "With bpdu-block-on-edge an edge port that hears a switch is disabled, stopping loops and rogue root bridges.",
      "Mark access ports as edge and block BPDUs on edge ports.", "set protocols rstp interface <port> edge\nset protocols rstp bpdu-block-on-edge",
      families=("juniper_junos",), switch_only=True)
def jun_bpdu(ctx):
    return [] if ctx.cfg.has(r"^set protocols (rstp|mstp|vstp) bpdu-block-on-edge") else [Hit("", "`bpdu-block-on-edge` is not set")]


# ------------------------------------------------------------------ Aruba AOS-S / ProCurve
@rule("AOSS-TELNET", "security", "high", "Telnet server is enabled (AOS-S)",
      "Telnet sends passwords and commands in clear text. AOS-S enables it by default.", "Turn the Telnet server off; SSH stays on.",
      "no telnet-server", families=("aruba_aoss",))
def aoss_telnet(ctx):
    return [] if ctx.cfg.has(r"^no telnet-server") else [Hit("telnet", "`no telnet-server` is missing (Telnet is on by default)")]


@rule("AOSS-WEB", "security", "medium", "Web management over plain HTTP (AOS-S)",
      "The web interface over HTTP sends the login in clear text.", "Use HTTPS only (`web-management ssl`) or turn the web interface off.",
      "no web-management\n; or: web-management ssl\n;     no web-management plaintext", families=("aruba_aoss",))
def aoss_web(ctx):
    if ctx.cfg.has(r"^no web-management$") or ctx.cfg.has(r"^no web-management plaintext"):
        return []
    return [Hit("web", "plain-text web management is enabled (the default)")]


@rule("AOSS-SNMP", "security", "high", "Default SNMP community (AOS-S)", "`public` is the first string every scanner tries, and AOS-S ships with it.",
      "Remove the default community; prefer SNMPv3.", 'no snmp-server community "public"', families=("aruba_aoss",))
def aoss_snmp(ctx):
    hits = [Hit(m.group(1), f"community `{m.group(1)}`") for l in ctx.cfg.find(r'^snmp-server community "?(public|private)"?')
            for m in [re.match(r'^snmp-server community "?([^"\s]+)', l)]]
    hits += [Hit("unrestricted", f"community `{m.group(1)}` is read-write (unrestricted)") for l in ctx.cfg.find(r"^snmp-server community .* unrestricted")
             for m in [re.match(r'^snmp-server community "?([^"\s]+)', l)] if m.group(1) not in ("public", "private")]
    return hits


@rule("AOSS-PASSWORD", "security", "high", "No manager password (AOS-S)",
      "Without a manager password anyone who reaches the console or a session gets full control.",
      "Set operator and manager passwords (and preferably RADIUS/TACACS+).", "password manager user-name admin plaintext <password>", families=("aruba_aoss",))
def aoss_password(ctx):
    return [] if ctx.cfg.has(r"^password manager") else [Hit("", "no `password manager`")]


@rule("AOSS-NTP", "best_practice", "medium", "No NTP server configured (AOS-S)", "Without NTP, log times drift and cannot be correlated.",
      "Add NTP servers and enable time sync.", "timesync ntp\nntp unicast\nntp server <ntp-1> iburst\nntp enable", families=("aruba_aoss",))
def aoss_ntp(ctx):
    return [] if ctx.cfg.has(r"^(ntp server|sntp server)") else [Hit("", "no `ntp server`")]


@rule("AOSS-SYSLOG", "best_practice", "medium", "Logs are not sent to a syslog server (AOS-S)", "Keep logs off the box.",
      "Send logs to your syslog server.", "logging <syslog-ip>", families=("aruba_aoss",))
def aoss_syslog(ctx):
    return [] if ctx.cfg.has(r"^logging \d+\.\d+") else [Hit("", "no `logging <ip>`")]


@rule("AOSS-BPDU", "best_practice", "medium", "Edge ports without BPDU protection (AOS-S)",
      "BPDU protection disables an edge port that hears a switch, stopping loops and rogue root bridges.",
      "Enable BPDU protection on the admin-edge ports.", "spanning-tree <ports> bpdu-protection", families=("aruba_aoss",), switch_only=True)
def aoss_bpdu(ctx):
    if ctx.cfg.has(r"^spanning-tree \S+ admin-edge-port") and not ctx.cfg.has(r"^spanning-tree \S+ bpdu-protection"):
        return [Hit("", "admin-edge ports have no `bpdu-protection`")]
    return []


# ------------------------------------------------------------------ FortiSwitch
def fs_allowaccess(ctx):
    return [l for h, ch in ctx.cfg.blocks(r"^config system interface") for l in ch if l.startswith("set allowaccess")]


@rule("FSW-TELNET", "security", "high", "Telnet allowed on a management interface (FortiSwitch)",
      "Telnet sends passwords and commands in clear text.", "Remove telnet from allowaccess.",
      'config system interface\n    edit "mgmt"\n        set allowaccess ping https ssh snmp\n    next\nend', families=("fortiswitch",))
def fsw_telnet(ctx):
    return [Hit("telnet", l) for l in fs_allowaccess(ctx) if re.search(r"\btelnet\b", l)][:1]


@rule("FSW-HTTP", "security", "medium", "HTTP allowed on a management interface (FortiSwitch)",
      "The GUI over HTTP sends the login in clear text.", "Remove http from allowaccess; keep https.",
      'config system interface\n    edit "mgmt"\n        set allowaccess ping https ssh snmp\n    next\nend', families=("fortiswitch",))
def fsw_http(ctx):
    return [Hit("http", l) for l in fs_allowaccess(ctx) if re.search(r"\bhttp\b", l)][:1]


@rule("FSW-SNMP", "security", "high", "Default SNMP community (FortiSwitch)", "`public` is the first string every scanner tries.",
      "Rename or delete the community; prefer SNMPv3 users.", "config system snmp community\n    delete <id>\nend", families=("fortiswitch",))
def fsw_snmp(ctx):
    return [Hit(m, f"community `{m}`") for m in re.findall(r'set name "(public|private)"', ctx.cfg.text)]


@rule("FSW-NTP", "best_practice", "medium", "No NTP server configured (FortiSwitch)", "Without NTP, log times drift and cannot be correlated.",
      "Enable NTP sync with your servers.", 'config system ntp\n    set ntpsync enable\nend', families=("fortiswitch",))
def fsw_ntp(ctx):
    return [] if re.search(r"set ntpsync enable", ctx.cfg.text) else [Hit("", "NTP sync is not enabled")]


@rule("FSW-SYSLOG", "best_practice", "medium", "Logs are not sent to a syslog server (FortiSwitch)", "Keep logs off the box.",
      "Enable remote syslog.", 'config log syslogd setting\n    set status enable\n    set server "<syslog-ip>"\nend', families=("fortiswitch",))
def fsw_syslog(ctx):
    return [] if re.search(r"config log syslogd setting\n\s+set status enable", ctx.cfg.text) else [Hit("", "remote syslog is not enabled")]
