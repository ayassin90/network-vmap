# Find an endpoint
pages: inventory:endpoints inventory:endpoint
group: Network
order: 15
Answers the everyday question "where is this thing plugged in?". VMap reads the MAC address table of every switch (and the ARP table of routers and layer 3 switches, to learn IP addresses) and works out the **edge port**: the access port with no other switch behind it.

## search: Searching
Type any of:
- a MAC address in any format (`00:50:56:aa:bb:cc`, `0050.56aa.bbcc`, `005056aabbcc`, or just part of it),
- an IP address (from the ARP tables),
- a name announced over CDP/LLDP (phones and access points announce themselves),
- a switch name or a port name.

## edge: Why one port and not many
A MAC address appears on many switches: the edge port where the device is, plus every uplink and trunk on the way to the core. VMap ignores trunks and ports with a switch behind them, so the port it shows is the one with the cable to the device.

## history: Moves and new devices
When a known MAC shows up on a different edge port, VMap records a **move**. When an unknown MAC appears, it records **first seen**. Turn on the alert rule "Endpoint appeared or moved" (off by default, because busy networks see many) to be told about it.

## vendor: Vendor hints
VMap marks virtual machines (VMware, Hyper-V, KVM, VirtualBox), Raspberry Pis, and **private / randomised** MAC addresses (phones and laptops that change their MAC for privacy, so they may appear as several "devices" over time).

## freshness: How fresh is it
MAC and ARP tables are read on every full collection and by a lighter MAC scan every 30 minutes (Settings). A device that was unplugged a while ago keeps its last known place, with its last-seen time.
