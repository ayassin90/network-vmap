"""FortiSwitch (standalone FortiSwitchOS) hardening checks. The configuration is nested `config / edit / set` blocks."""
from .ruleset import NA, Hit, both, check, edge_switch, fos_get, fos_node, num, ports, rule

F = ("fortiswitch",)


def _glob(ctx):
    return fos_node(ctx, "system global")


def _edits(ctx, path):
    n = fos_node(ctx, path)
    return n["edits"] if n else {}


def _set(ctx, path, key, default=None):
    return fos_get(fos_node(ctx, path), key, default)


@rule("FSW-ADMINTIMEOUT", "security", "medium", "Admin sessions stay open longer than 10 minutes (FortiSwitch)",
      "A forgotten GUI or CLI session stays logged in. PCI DSS asks for 15 minutes and CIS for 10.", "Set a short admin timeout.",
      "config system global\n    set admintimeout 10\nend", families=F, domain="access", topics=("session-timeout",))
def fsw_timeout(ctx):
    v = num(_set(ctx, "system global", "admintimeout", "5"), 5)
    return [Hit("", f"admintimeout {v} minutes")] if v > 10 else []


@rule("FSW-LOCKOUT", "security", "medium", "Failed logins lock the account for only a minute (FortiSwitch)",
      "The default lockout is 60 seconds after 3 failures, which barely slows password guessing. PCI DSS asks for 30 minutes.",
      "Lengthen the lockout.", "config system global\n    set admin-lockout-threshold 3\n    set admin-lockout-duration 1800\nend",
      families=F, domain="aaa", topics=("lockout",))
def fsw_lockout(ctx):
    thr = num(_set(ctx, "system global", "admin-lockout-threshold", "3"), 3)
    dur = num(_set(ctx, "system global", "admin-lockout-duration", "60"), 60)
    bad = []
    if thr > 5:
        bad.append(f"threshold {thr} attempts")
    if dur < 300:
        bad.append(f"duration {dur} seconds")
    return [Hit("", ", ".join(bad))] if bad else []


check("FSW-SSHV1", "security", "high", "SSH version 1 is allowed (FortiSwitch)",
      "SSH v1 has known cryptographic weaknesses.", "Disable SSH v1.", "config system global\n    set admin-ssh-v1 disable\nend",
      families=F, domain="access", topics=("crypto-strength", "mgmt-crypto"),
      fn=lambda ctx: [Hit("", "admin-ssh-v1 enable")] if _set(ctx, "system global", "admin-ssh-v1") == "enable" else [])

check("FSW-STRONGCRYPTO", "security", "medium", "Strong cryptography is disabled (FortiSwitch)",
      "With strong-crypto disabled, HTTPS and SSH accept weak ciphers and protocols.", "Enable strong cryptography.",
      "config system global\n    set strong-crypto enable\nend", families=F, domain="access", topics=("crypto-strength",),
      fn=lambda ctx: [Hit("", "strong-crypto disable")] if _set(ctx, "system global", "strong-crypto") == "disable" else [])

check("FSW-HTTPSREDIRECT", "security", "low", "HTTP is not redirected to HTTPS (FortiSwitch)",
      "Without the redirect, a user who types http:// logs in over clear text.", "Redirect HTTP to HTTPS.",
      "config system global\n    set admin-https-redirect enable\nend", families=F, domain="access", topics=("mgmt-crypto",),
      fn=lambda ctx: [Hit("", "admin-https-redirect disable")] if _set(ctx, "system global", "admin-https-redirect") == "disable" else [])

check("FSW-BANNER", "security", "low", "No pre-login banner (FortiSwitch)",
      "A banner states that access is restricted; many legal and audit frameworks require one.", "Enable the pre-login banner.",
      "config system global\n    set pre-login-banner enable\nend", families=F, domain="access", topics=("banner",),
      fn=lambda ctx: [] if _set(ctx, "system global", "pre-login-banner") == "enable" else [Hit("", "pre-login-banner is not enabled")])


@rule("FSW-TRUSTHOST", "security", "medium", "Admin accounts can log in from anywhere (FortiSwitch)",
      "Trusted hosts limit where each administrator may log in from. Without them, any address that reaches the switch can try.",
      "Set trusted hosts on every admin account.", 'config system admin\n    edit "admin"\n        set trusthost1 <mgmt-subnet> <mask>\n    next\nend',
      families=F, domain="access", topics=("mgmt-acl",))
def fsw_trusthost(ctx):
    admins = _edits(ctx, "system admin")
    if not admins:
        return [Hit("", "no admin account restricts trusted hosts (default admin)")]
    bad = [n for n, node in admins.items() if not any(k.startswith("trusthost") for k in node["sets"])]
    return [Hit("admins", ports(bad))] if bad else []


check("FSW-ADMINNAME", "security", "low", "The default `admin` account is in use (FortiSwitch)",
      "`admin` is the first name every attacker tries. Use named accounts and keep one renamed break-glass account.",
      "Create named administrators, then remove or rename admin.", families=F, domain="aaa", topics=("default-creds", "least-privilege"),
      fn=lambda ctx: [Hit("admin", "account `admin` exists")] if "admin" in _edits(ctx, "system admin") else [])


@rule("FSW-PWPOLICY", "security", "medium", "No password policy (FortiSwitch)",
      "Without a password policy short administrator passwords are accepted. PCI DSS asks for at least 12 characters.",
      "Enable a password policy with a 12-character minimum.", "config system password-policy\n    set status enable\n    set min-length 12\nend",
      families=F, domain="aaa", topics=("password-policy",))
def fsw_pwpolicy(ctx):
    n = fos_node(ctx, "system password-policy")
    if not n or fos_get(n, "status") != "enable":
        return [Hit("", "password policy is not enabled")]
    ln = num(fos_get(n, "min-length", "8"), 8)
    return [Hit("", f"min-length {ln}")] if ln < 12 else []


check("FSW-AAA", "security", "medium", "No central authentication (FortiSwitch)",
      "Without a TACACS+ or RADIUS server for administrators, everyone shares local accounts.", "Authenticate admins through TACACS+ or RADIUS.",
      'config user tacacs+\n    edit "TAC"\n        set server <ip>\n        set key <key>\n    next\nend\nconfig system admin\n    edit "remote"\n        set remote-auth enable\n        set wildcard enable\n        set remote-group "TAC-GROUP"\n    next\nend',
      families=F, domain="aaa", topics=("central-aaa",),
      fn=lambda ctx: [] if _edits(ctx, "user tacacs+") or _edits(ctx, "user radius") else [Hit("", "no TACACS+ or RADIUS server")])


@rule("FSW-SNMPHOSTS", "security", "medium", "SNMP communities are not limited to known managers (FortiSwitch)",
      "A community without hosts answers anyone who can reach the switch.", "Add your monitoring hosts to each community.",
      'config system snmp community\n    edit 1\n        config hosts\n            edit 1\n                set ip <nms-ip> 255.255.255.255\n            next\n        end\n    next\nend',
      families=F, domain="snmp", topics=("snmp-community", "mgmt-acl"))
def fsw_snmp_hosts(ctx):
    comms = _edits(ctx, "system snmp community")
    if not comms:
        return NA
    bad = [fos_get(c, "name", i) for i, c in comms.items() if not (c["configs"].get("hosts") or {}).get("edits")]
    return [Hit(str(b)[:3] + "…", "community without hosts") for b in bad]


check("FSW-SNMPV3", "security", "low", "SNMP v2c is used without SNMPv3 (FortiSwitch)",
      "Community strings travel in clear text. SNMPv3 adds authentication and encryption.", "Move monitoring to SNMPv3.",
      'config system snmp user\n    edit "nms"\n        set security-level auth-priv\n        set auth-proto sha256\n        set priv-proto aes256\n    next\nend',
      families=F, domain="snmp", topics=("snmp-v3",), applies=lambda ctx: bool(_edits(ctx, "system snmp community")),
      fn=lambda ctx: [] if any(fos_get(u, "security-level") == "auth-priv" for u in _edits(ctx, "system snmp user").values()) else [Hit("", "no SNMPv3 auth-priv user")])

check("FSW-SNMPV3WEAK", "security", "medium", "SNMPv3 user without strong authentication and encryption (FortiSwitch)",
      "SNMPv3 users should use auth-priv with SHA and AES.", "Use auth-priv, SHA-256 and AES.",
      'config system snmp user\n    edit "<user>"\n        set security-level auth-priv\n        set auth-proto sha256\n        set priv-proto aes256\n    next\nend',
      families=F, domain="snmp", topics=("snmp-v3", "crypto-strength"),
      fn=lambda ctx: [Hit(n, f"user {n}") for n, u in _edits(ctx, "system snmp user").items()
                      if fos_get(u, "security-level", "no-auth-no-priv") != "auth-priv" or fos_get(u, "auth-proto", "") == "md5" or fos_get(u, "priv-proto", "") == "des"])


def _ntp_auth(ctx):
    n = fos_node(ctx, "system ntp")
    if not n:
        return False
    if fos_get(n, "authentication") == "enable":
        return True
    return any(fos_get(s, "authentication") == "enable" for s in (n["configs"].get("ntpserver") or {}).get("edits", {}).values())


check("FSW-NTPAUTH", "security", "medium", "NTP is not authenticated (FortiSwitch)",
      "A spoofed NTP server can move the clock, breaking logs and certificates.", "Authenticate NTP.",
      'config system ntp\n    config ntpserver\n        edit 1\n            set authentication enable\n            set key <key>\n            set key-id 1\n        next\n    end\nend',
      families=F, domain="logging", topics=("time-auth",), applies=lambda ctx: _set(ctx, "system ntp", "ntpsync") == "enable",
      fn=lambda ctx: [] if _ntp_auth(ctx) else [Hit("", "NTP authentication is not enabled")])

check("FSW-NTP2", "best_practice", "low", "Only one NTP server (FortiSwitch)", "One time source is a single point of failure.",
      "Configure at least two NTP servers.", 'config system ntp\n    config ntpserver\n        edit 2\n            set server "<ntp-2>"\n        next\n    end\nend',
      families=F, domain="logging", topics=("time-sync", "availability"), applies=lambda ctx: _set(ctx, "system ntp", "ntpsync") == "enable",
      fn=lambda ctx: [] if len(((fos_node(ctx, "system ntp") or {}).get("configs", {}).get("ntpserver") or {}).get("edits", {})) >= 2 else [Hit("", "fewer than 2 NTP servers")])


def _edge_ports(ctx):
    return {n: p for n, p in _edits(ctx, "switch interface").items() if fos_get(p, "edge-port") in ("enabled", "enable")}


@rule("FSW-BPDU", "best_practice", "medium", "Edge ports without BPDU guard (FortiSwitch)",
      "BPDU guard shuts an edge port that suddenly hears a switch, stopping loops and rogue root bridges.", "Enable BPDU guard on edge ports.",
      'config switch interface\n    edit "port1"\n        set stp-bpdu-guard enabled\n    next\nend', families=F, switch_only=True, domain="l2", topics=("l2-edge",))
def fsw_bpdu(ctx):
    edge = _edge_ports(ctx)
    if not edge:
        return NA
    bad = [n for n, p in edge.items() if fos_get(p, "stp-bpdu-guard") not in ("enabled", "enable")]
    return [Hit("ports", f"{len(bad)} edge ports: {ports(bad)}")] if bad else []


@rule("FSW-LOOPGUARD", "best_practice", "low", "Loop guard off on edge ports (FortiSwitch)",
      "Loop guard catches loops spanning tree cannot see, such as an unmanaged switch looped on itself.", "Enable loop guard on edge ports.",
      'config switch interface\n    edit "port1"\n        set loop-guard enabled\n    next\nend', families=F, switch_only=True, domain="l2",
      topics=("l2-edge", "availability"))
def fsw_loop(ctx):
    edge = _edge_ports(ctx)
    if not edge:
        return NA
    bad = [n for n, p in edge.items() if fos_get(p, "loop-guard") not in ("enabled", "enable")]
    return [Hit("ports", f"{len(bad)} edge ports: {ports(bad)}")] if bad else []


def _vlan_has(ctx, key):
    return any(fos_get(v, key) in ("enable", "enabled") for v in _edits(ctx, "switch vlan").values())


check("FSW-DHCPSNOOP", "security", "medium", "DHCP snooping is off (FortiSwitch)",
      "Without DHCP snooping, any user port can run a rogue DHCP server.", "Enable DHCP snooping on user VLANs and trust the uplinks.",
      'config switch vlan\n    edit <user-vlan>\n        set dhcp-snooping enable\n    next\nend', families=F, switch_only=True, domain="l2",
      topics=("l2-spoofing",), applies=edge_switch, fn=lambda ctx: [] if _vlan_has(ctx, "dhcp-snooping") else [Hit("", "no VLAN has dhcp-snooping enabled")])

check("FSW-ARP", "security", "low", "ARP inspection is off (FortiSwitch)",
      "Dynamic ARP inspection drops forged ARP replies on user VLANs.", "Enable ARP inspection on user VLANs.",
      'config switch vlan\n    edit <user-vlan>\n        set arp-inspection enable\n    next\nend', families=F, switch_only=True, domain="l2",
      topics=("l2-spoofing",), applies=both(edge_switch, lambda ctx: _vlan_has(ctx, "dhcp-snooping")),
      fn=lambda ctx: [] if _vlan_has(ctx, "arp-inspection") else [Hit("", "no VLAN has arp-inspection enabled")])

check("FSW-MGMTDATA", "security", "low", "Management is allowed on data interfaces (FortiSwitch)",
      "Allowing HTTPS/SSH/SNMP on in-band interfaces makes the management plane reachable from user VLANs. Keep it on the mgmt port.",
      "Remove allowaccess from in-band interfaces.", 'config system interface\n    edit "internal"\n        unset allowaccess\n    next\nend',
      families=F, domain="access", topics=("mgmt-plane", "mgmt-acl"),
      fn=lambda ctx: [Hit(n, f"{n}: allowaccess {fos_get(i, 'allowaccess')}") for n, i in _edits(ctx, "system interface").items()
                      if n != "mgmt" and fos_get(i, "allowaccess") and set((fos_get(i, "allowaccess") or "").split()) - {"ping"}])

check("FSW-STORM", "best_practice", "low", "Storm control is not enabled (FortiSwitch)",
      "Storm control caps broadcast and unknown traffic so a faulty NIC or loop cannot flood a VLAN.", "Enable storm control.",
      "config switch storm-control\n    set broadcast enable\n    set unknown-multicast enable\n    set unknown-unicast enable\n    set rate 500\nend",
      families=F, switch_only=True, domain="l2", topics=("l2-edge", "availability"), applies=edge_switch,
      fn=lambda ctx: [] if _set(ctx, "switch storm-control", "broadcast") == "enable" else [Hit("", "broadcast storm control is not enabled")])

