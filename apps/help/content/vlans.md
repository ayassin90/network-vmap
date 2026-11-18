# VLANs
pages: inventory:vlans
group: Network
order: 17
Every VLAN across all switches: names, where it is defined, how many access ports use it and how many trunks carry it.

## checks: What VMap checks
- **Allowed VLANs differ between the two ends of a trunk**: a VLAN allowed on only one end is silently dropped on that link.
- **Ports in a VLAN that does not exist on the switch**: those ports pass no traffic at all.
- **Same VLAN, different names** on different switches: harmless for traffic, but it leads to mistakes.
- Trunk native VLAN and trunk/access mismatches are under Interfaces.
