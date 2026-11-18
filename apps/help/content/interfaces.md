# Interface health
pages: inventory:interfaces
group: Network
order: 12
This page looks across every port of every device for physical and configuration problems, and shows where the traffic is.

## problems: What counts as a problem
- **Half duplex**: the port negotiated half duplex. Modern devices should always be full duplex; half duplex usually means one end is hard-coded and the other is on auto.
- **Duplex or speed mismatch**: both ends of a link are managed by VMap and they disagree. This causes late collisions, CRC errors and very slow transfers.
- **Trunk on one side, access on the other** and **native VLAN mismatch**: the two ends of a link are configured differently, so VLANs leak or do not pass.
- **CRC errors**: frames arrived damaged. Almost always a cable, patch lead or optic problem. "Still increasing" means new errors appeared since the last poll.
- **Late collisions / collisions on full duplex**: the classic sign of a duplex mismatch.
- **Output drops**: the port had more to send than it could, usually congestion or microbursts.
- **Giants**: frames larger than the port accepts, which points to an MTU mismatch.
- **Err-disabled**: the switch shut the port to protect itself (BPDU Guard, port security, link flap, storm control…).
- **High utilisation**: the port is at or above the threshold in Settings (80% by default).
- **Flapping**: the port went up and down three or more times in the last hour (seen between polls, or counted by the switch).
- **Optical power**: the transceiver's receive or transmit light is near or past its limits (dirty or damaged fibre, failing optic).
- **PoE fault / PoE budget**: the switch stopped powering a device, or the switch's power budget is nearly used.
- **Switch link at low speed**: a link to another switch or router running at 100 Mb/s or less.

## throughput: Throughput and error charts
With an SNMP credential, VMap reads the interface counters every few minutes and works out bits per second and new errors between two polls. Without SNMP it uses the 5-minute rate the switch itself reports in `show interfaces`. Charts keep 14 days by default (Settings).

## filters: Filters
**Problems** shows ports with an open interface finding. **Errors** sorts by CRC count. **Busy** lists ports at 50% or more. **Top talkers** sorts by total traffic.
