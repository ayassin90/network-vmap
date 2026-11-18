# Topology maps
pages: topology:l2 topology:l3
group: Network
order: 11
Two live maps built from what the devices report. They redraw with the latest state every minute, keeping your layout.

## l2: Layer 2 map
Built from CDP and LLDP neighbours. Each line is a cable between two ports.
- **Thick blue**: trunk (carries many VLANs, 802.1Q tagged). An extra-thick line is a member of a port-channel.
- **Thin grey**: access port (one VLAN).
- **Purple dashed**: routed port (no VLANs; an IP link).
- **Dotted / faded**: the link is down.
- **Red dot on a line**: one end has an interface problem (errors, half duplex, mismatch…).
Devices VMap does not manage (phones, access points, other switches) appear with a dashed outline. Tick **Phones, APs & hosts** to show endpoints too.

## ports: Port details on hover
The small dots near each end of a line are the ports. Hover one to see its name, description, status, speed and duplex, VLANs (access VLAN, or native and allowed VLANs on a trunk), current traffic and utilisation, error counters and any problem found. Hover the line itself for a summary of both ends.

## l3: Layer 3 map
Built from interface IP addresses, routing tables and OSPF neighbours.
- A **purple dashed line** joins two routers that share a small point-to-point subnet (/29 to /31); the subnet is written on the line.
- A **teal box** is a larger subnet or VLAN with several devices in it; every member device is connected to it.
- An **amber line** is an OSPF adjacency.
Hover a router for its route counts per protocol, loopbacks and default route.

## customise: Arranging and saving
- Drag devices to move them; drag the background to pan; use the mouse wheel to zoom.
- **Tiered layout** places core devices at the top and access below, using each device's role (or a guess from the links).
- **Organic layout** spreads the map by its connections.
- Right-click a device to rename it on this map, pin it, hide it, or show only it and its neighbours. Hidden devices can be brought back with "show all".
- **Highlight VLAN** dims every link that does not carry that VLAN, so you can follow a VLAN across the network.
- Changes save automatically to the current layout ("Default" the first time). **Save as…** keeps a separate named layout, for example one per building.
- **Export** downloads the current view as an SVG image.

## groups: Grouping, colours and your own drawings
- **Group by** site, role or vendor draws a dashed box around the devices that share it.
- **Colour** outlines each device by status, vendor, security score or interface health (green good, amber needs attention, red poor).
- Right-click the empty background to add a **note**, or a device VMap cannot see: the internet or an ISP, a firewall, a cloud or WAN, a server, an unmanaged switch.
- Right-click any device and choose **Draw a link from here…**, then click the other end. Hand-drawn links are dotted and can carry a note, such as a circuit ID. Right-click one to edit or delete it.
- **Change icon…** on a device's menu picks another symbol (firewall, server, cloud…).
- All of this is saved with the layout, so different saved layouts can tell different stories.
