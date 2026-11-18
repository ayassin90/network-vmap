# Routing tables
pages: inventory:routes
group: Network
order: 13
The routing table of every layer 3 device in one place.

## lookup: Looking up an address
Type an IP address and VMap shows, for every device and VRF, the route it would use to reach it: the most specific prefix that contains the address (longest prefix match), its protocol, next hop and outgoing interface. If a device shows nothing, it has no route at all, not even a default route.

## codes: Protocol codes
C connected, L local (the device's own address), S static, O OSPF, D EIGRP, B BGP, R RIP, i IS-IS. An asterisk (*) marks a candidate default route.
