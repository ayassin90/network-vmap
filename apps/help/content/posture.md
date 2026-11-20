# Hardening posture
pages: checks:posture checks:catalog
group: Assurance
order: 19
VMap checks every collected configuration against a catalogue of hardening checks for Cisco IOS / IOS-XE, NX-OS, Arista EOS, Aruba AOS-CX and AOS-S, Huawei VRP, Juniper Junos and FortiSwitch. Each check is mapped to the controls it supports in **CIS Controls v8**, **NIST SP 800-53 Rev. 5**, **ISO/IEC 27001:2022**, **PCI DSS v4.0.1** and the **NIST Cybersecurity Framework 2.0**. Cisco IOS checks also carry their **CIS Benchmark** item number.

## frameworks: Frameworks and controls
Pick a framework at the top. The page lists each of its controls that VMap can evaluate, with the share of passing checks across the selected devices. Open a control to see the checks behind it and which devices fail each one.
- A control is only as good as the checks mapped to it. VMap evaluates the device configuration; it does not see policies, processes or other systems that an auditor will also look at.
- Use the result as evidence and as a to-do list, not as a certification.

## status: Pass, fail, accepted, not applicable
- **Pass**: the configuration meets the check.
- **Fail**: an open finding. It also appears on the Security & practices page.
- **Accepted**: the check fails, but an operator accepted the risk with a reason. It counts as compliant and is listed separately in the audit report.
- **Not applicable**: the check does not apply to this device. For example DHCP snooping on a core switch, BGP checks on a switch without BGP, or 802.1X on a switch without user ports.

## score: The hardening score
The device score is the share of applicable checks that pass, weighted by severity (critical 10, high 6, medium 3, low 1; informational checks do not count). Accepted risks count as passing. The same score appears as the Security score on the dashboard and the device list.

## domains: Domains
Checks are grouped by what they protect: management access, accounts and AAA, SNMP, logging and time, services, the control and data plane, routing protocols, layer 2 and edge ports, and operations.

## catalogue: Check catalogue
The catalogue lists every built-in check with its severity, the platforms it runs on, why it matters, how to fix it, example configuration, and its control mappings. Filter by platform, domain, severity or a specific control (for example NIST `AC-17(2)` or PCI `8.3.4`). **Export CSV** gives the whole mapping, which is handy for an audit workbook.

## mapping: How mapping works
Each check supports one or more control objectives, such as "management traffic is encrypted" or "repeated login failures are blocked". Each objective names the controls it helps meet in every framework. Every check that enforces the same objective therefore maps to the same controls, whatever the vendor. The table at the bottom of the catalogue shows all objectives and their mappings.

## rerun: Re-run checks
Checks run automatically after every collection. **Re-run checks** evaluates them again on the configurations already collected, without logging in to the devices.
