# Discovery
pages: inventory:discovery inventory:discovery_detail
group: Network
order: 14
Discovery finds your network for you, starting from one or more seed switches.

## how: How it works
1. VMap logs in to each seed with the credential you choose and collects it like any device.
2. It reads the seed's CDP and LLDP neighbours. Every neighbour that is a switch or router (not a phone, access point or PC) and that has a management address becomes a new device.
3. Each new device is collected the same way, and its neighbours are followed in turn, until **Max depth** is reached.
Phones and access points still appear on the map as neighbours; they are just not logged in to.

## seeds: Seeds
One address per line. A core or distribution switch is the best seed: it sees the most neighbours.

## include: Only follow neighbours inside these subnets
A safety net. List your management ranges (for example `10.0.0.0/8, 172.16.10.0/24`). Neighbours with addresses outside them are not added, so discovery does not wander into a partner network or the internet edge.

## platforms: Other vendors
Neighbours are recognised from their CDP/LLDP platform string. Cisco IOS, IOS-XE and NX-OS are collected over SSH. For other vendors VMap needs an SNMP credential on the discovery; without one they are skipped and listed in the log.
