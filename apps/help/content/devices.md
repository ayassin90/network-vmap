# Devices
pages: inventory:list inventory:detail inventory:add inventory:edit inventory:bulk_add inventory:config inventory:interface
group: Network
order: 10
Every switch and router VMap manages. Open a device to see everything collected from it: ports, neighbours, routes, VLANs, saved configurations, findings and advisories.

## add: Adding a device
- **Management IP / host** is the address VMap logs in to. It must be unique.
- **Platform** decides which commands are run. For any Catalyst, picking Cisco IOS is fine: VMap reads `show version` and switches to IOS-XE automatically if needed.
- **SSH credential** is needed for configuration, neighbours, routes and checks. Use an account with privilege 15, or fill in the enable secret on the credential.
- **SNMP credential** (optional) gives throughput and error counters every few minutes without logging in. Without it, VMap does a light SSH poll instead.
- **Collector** is only needed when this server cannot reach the device directly (see Collectors).
- **Role** (core, distribution, access…) is used to place the device on the maps and to apply standards to the right devices. VMap guesses a tier if you leave it unset.

## bulk: Adding many devices
Paste one device per line. A line can be just an address (`10.0.0.5`) or an address and a display name (`10.0.0.5,ACC-2F-01`). Every device gets the same platform, role, site and credentials; you can change them later one by one or with the bulk actions on the device list. Addresses that already exist are skipped.

## actions: Test, Poll and Collect now
- **Test** checks that the SSH port is open, that the login works, and that SNMP answers. Use it first when a device shows "Login failed" or "Unreachable".
- **Poll** refreshes counters and throughput right now.
- **Collect now** reads everything again: configuration, neighbours, routing table, VLANs and interface details. Findings, scores and alerts update as soon as it finishes.
VMap also does this by itself on a schedule (see Settings).

## scores: Scores on a device
Security, Health and Standards are explained on the dashboard help. Open the **Findings** tab to see exactly which problems took points off, and the **Standards** tab for each rule of your standards.

## config: Configuration history
Each collection saves the running configuration. A new version is kept only when something changed, so the list is a change history. Click a version to see what was added (green) and removed (red) compared with the one before, or compare any two versions. VMap ignores lines that change on their own (like "Last configuration change at"), so you only see real changes.

## commands: Run commands
Operators can run read-only commands (`show`, `display`, `dir`, `verify`) on one device and read the output in the job page. Configuration commands are refused here on purpose.

## interfaces-tab: The Interfaces tab
One row per port: status, access/trunk/routed mode, VLAN, speed and duplex, current traffic and utilisation, error counters and the CDP/LLDP neighbour. Problems found on a port appear in red under the neighbour. Click a port for its throughput chart.

## health: Hardware health
CPU (5-minute average), memory, temperature, fans and power supplies. Read on every collection over SSH and, with an SNMP credential, on every poll (Cisco process, memory-pool and environment MIBs; the standard host-resources MIB for other vendors). VMap raises a finding for CPU at 80% or more, memory at 90% or more, a failed fan or power supply, and a temperature warning. "Not present" power supplies are not a problem by themselves.
