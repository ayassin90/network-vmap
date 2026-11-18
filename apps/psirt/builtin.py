"""A few high-impact Cisco advisories that VMap can flag from the configuration alone, even without API access.
These are exposure checks: the risky feature is on. Always confirm with the advisory or the Cisco Software Checker."""
BUILTIN = [
    {"advisory_id": "cisco-sa-iosxe-webui-privesc-j22SaA4z", "severity": "critical", "cvss": 10.0,
     "title": "Cisco IOS XE Software Web UI Privilege Escalation Vulnerabilities",
     "cves": "CVE-2023-20198,CVE-2023-20273", "published": "2023-10-16",
     "url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-webui-privesc-j22SaA4z",
     "summary": "An unauthenticated remote attacker can create a privilege-15 account through the Web UI and then run commands as root. "
                "Actively exploited in October 2023. Exposure requires the HTTP or HTTPS server to be enabled.",
     "workaround": "Disable the HTTP server on all internet-facing systems: `no ip http server` and `no ip http secure-server`, then save. "
                   "Look for unknown local users and implants.",
     "os_types": "iosxe", "condition": r"^ip http (secure-)?server\s*$", "fixed_in": "17.9.4a,17.6.6a,17.3.8a,16.12.10a"},
    {"advisory_id": "cisco-sa-20180328-smi2", "severity": "critical", "cvss": 9.8,
     "title": "Cisco IOS and IOS XE Software Smart Install Remote Code Execution Vulnerability",
     "cves": "CVE-2018-0171", "published": "2018-03-28",
     "url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-smi2",
     "summary": "A buffer overflow in Smart Install lets an unauthenticated attacker reload the switch or run code on it over TCP port 4786. "
                "Smart Install client is enabled by default on many Catalyst switches unless `no vstack` is configured.",
     "workaround": "Disable Smart Install with `no vstack` where it is not used.",
     "os_types": "ios,iosxe", "condition": r"^no vstack", "condition_absent": True},
    {"advisory_id": "cisco-sa-20170317-cmp", "severity": "critical", "cvss": 9.8,
     "title": "Cisco IOS and IOS XE Software Cluster Management Protocol Remote Code Execution Vulnerability",
     "cves": "CVE-2017-3881", "published": "2017-03-17",
     "url": "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp",
     "summary": "Cluster Management Protocol handling of Telnet options lets an unauthenticated attacker run code with full privileges. "
                "Exposure requires Telnet to be accepted by the switch.",
     "workaround": "Allow only SSH on VTY lines: `line vty 0 15` / `transport input ssh`.",
     "os_types": "ios,iosxe", "condition": r"^\s*transport input .*\b(telnet|all)\b"},
]


def load():
    from datetime import date

    from .models import Advisory
    for a in BUILTIN:
        a = dict(a)
        a["published"] = date.fromisoformat(a["published"])
        Advisory.objects.update_or_create(advisory_id=a.pop("advisory_id"), defaults=dict(a, source="builtin"))
