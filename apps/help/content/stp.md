# Spanning tree
pages: inventory:stp
group: Network
order: 16
Spanning tree (STP) keeps loops out of the layer 2 network by blocking redundant links. It works best when you decide which switch is the **root bridge** for each VLAN, normally your core or distribution pair.

## root: Root bridge
The root is the switch with the lowest bridge priority (ties go to the lowest MAC address). VMap shows the root of each VLAN and raises a finding when:
- an **access switch is root**: traffic for the VLAN is pulled through it, usually over slower links;
- the root was **elected by default** (nobody set a priority), so a new or replaced switch could take over at any time;
- different switches disagree on the root of a VLAN ("more than one root"), which means the VLAN is split.

## blocking: Blocked ports
On each switch, ports in **blocking** (alternate) state are the redundant paths STP keeps ready. On the L2 map they are shown with an amber dot; highlight a VLAN to see which links are blocked for it.

## tcn: Topology changes
Every topology change flushes MAC tables and briefly floods traffic. VMap flags VLANs with many recent changes and names the port that caused the last one. The usual cause is an access port without PortFast (every PC reboot counts) or a flapping link.
