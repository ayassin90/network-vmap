# Network snapshots
pages: snapshots:index snapshots:detail snapshots:compare
group: Network
order: 19
A snapshot records the whole network at one moment: every device with its software, configuration fingerprint and scores; every port's status, mode, VLANs, speed and description; the links between devices; routing tables; where each endpoint was plugged in; and the open findings. It is the "time machine": what did the network look like last Tuesday, and what changed since?

## taking: Taking snapshots
- One is taken automatically every day (Settings → Network snapshot every; 0 turns it off). Snapshots are kept for 90 days by default.
- **Take snapshot now** before a maintenance window or a big change, with a label such as "before core upgrade".
- Snapshots are compressed: a few hundred kilobytes for a site of a few dozen switches.

## browsing: Looking at a snapshot
The device list shows the network as it was. Click a device to see its ports, routes and open findings at that time.

## compare: What changed
Pick two snapshots, or one and **Now**, to list every difference:
- devices added or removed, and changes to software, configuration, status, role or scores;
- ports that went up or down or changed mode, VLAN, speed, duplex or description;
- links that appeared or disappeared;
- routes added or removed per device;
- endpoints that are new, gone or moved to another port;
- findings that are new or fixed.
