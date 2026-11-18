# Platform guide
pages: inventory:platforms inventory:platform
group: Setup
order: 31
What VMap can do on each switch and router family, one column per function.

## levels: What the levels mean
- **Supported**: built and tested for this platform.
- **Partial**: works, with limits that are explained on the platform's page (for example stacked switches during upgrades).
- **Via SNMP**: available today through standard SNMP MIBs. Add an SNMP credential to the device. Quality depends on what the vendor implements.
- **Manual**: the vendor offers no reliable remote way. VMap still tracks versions and exposure; you do the change by hand.
- **Planned**: on the roadmap.

## order: Vendors with an SSH driver
Cisco (IOS, IOS-XE, NX-OS), Aruba (AOS-CX and AOS-S), Huawei VRP, Juniper Junos, Arista EOS and FortiSwitch have full SSH drivers: inventory, interfaces and errors, neighbours, VLANs, routes, MAC/ARP, health, configuration backup, security checks, standards, port actions and remote upgrades. Everything else works through generic SNMP. Drivers other than Cisco IOS/IOS-XE are marked **beta**: they were built from public sample output and tested against the lab, not yet against every real model and release.

## aruba: Aruba AOS-CX
The second vendor with a full SSH driver (beta): inventory, interfaces and errors, LLDP neighbours, VLANs, routes, MAC/ARP for the endpoint finder, configuration backup, standards, port actions with checkpoint rollback, and upgrades to the secondary partition. Spanning-tree and optics views are Cisco-only for now.

## huawei: Huawei VRP
Third vendor with an SSH driver (beta), for S-series campus switches and CloudEngine: inventory, power supplies and fans, interfaces and errors, LLDP, VLANs and port modes, routes, MAC/ARP, CPU and memory, configuration backup, standards and port actions. VRP cannot roll back a configuration live from the CLI, so changes on Huawei run without an automatic rollback point (VMap says so in the change log). Upgrades download the .cc file over TFTP or SFTP, check it on flash, set it with `startup system-software` and reboot.

## nxos: Cisco NX-OS
Nexus 3000/5000/7000/9000 in NX-OS mode: everything the IOS driver reads (including MAC/ARP and CPU, memory, fans, power and temperature). Changes save a rollback **checkpoint** first and use `rollback running-config checkpoint` if a line fails. Upgrades use `install all`; on vPC pairs upgrade one peer at a time.

## arista: Arista EOS
7000-series and campus 720XP/750: version and serial, interfaces with rates and errors, switchport modes, LLDP, routes in every VRF, MAC/ARP, CPU, memory, power, fans and temperature. Changes save `flash:<name>` first and roll back with `configure replace`. Upgrades copy the .swi, verify MD5, set `boot system` and reload.

## junos: Juniper Junos
EX and QFX with the ELS CLI. The configuration is stored in `display set` form, so standards and searches work line by line. Every change ends with a **commit**; a copy of the configuration is saved to /var/tmp first and restored with `load override` if anything fails. Upgrades copy the package to /var/tmp, check its MD5 and run `request system software add` (with reboot when allowed).

## aoss: Aruba AOS-S / ProCurve
2530, 2540, 2930F/M, 3810M, 5400R. Port VLANs come from the configuration's `vlan` blocks (untagged = access or native VLAN, tagged = trunk). AOS-S has no configuration rollback from the CLI, so changes run without a rollback point. Upgrades copy the image to the secondary flash over TFTP or SFTP and boot from it.

## fortiswitch: FortiSwitch (standalone)
Standalone FortiSwitchOS: status, ports, errors, native and allowed VLANs, LLDP, routes, MAC/ARP, CPU and memory, configuration and security checks. FortiLink-managed FortiSwitches are configured from the FortiGate: collect them, but make changes on the FortiGate. Upgrades run `execute restore image tftp`, which installs and reboots in one step.

## generic: Any vendor (generic SNMP)
Choose this platform for anything that has no driver yet. With an SNMP credential you get interfaces, errors, throughput, LLDP neighbours (so it appears on the map) and the routing table.
