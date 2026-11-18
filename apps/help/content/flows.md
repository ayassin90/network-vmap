# Traffic (NetFlow / IPFIX)
pages: flows:traffic
group: Network
order: 14
Who is talking to whom, with which applications, from flow records your routers and switches export. VMap accepts **NetFlow v5, NetFlow v9 and IPFIX** on **UDP 2055** (the `receiver` container).

## setup: Sending flows to VMap
Configure an exporter on the devices that see the traffic you care about (WAN routers, core switches, data centre uplinks) towards this server, UDP 2055. The page shows configuration examples for IOS-XE, NX-OS, Junos and Huawei when no data has arrived yet. sFlow (Arista, Aruba, FortiSwitch) is not decoded yet.

## reading: Reading the page
- **Top talkers** and **top destinations**: the addresses that sent and received the most bytes, with the endpoint name or switch port VMap knows for them.
- **Applications**: traffic by protocol and service port (HTTPS, SMB, RDP, DNS…). The service port is the well-known side of the conversation.
- **Top conversations**: source, destination and application, with average rate over the window.
- **Exporters** and, when you filter on one device, its **input interfaces**.
- Click an address or an application to filter on it. The window (15 minutes to 7 days) is at the top.

## storage: Storage
Records are summed per minute and conversation as they arrive. Keep them for 7 days by default (Settings → Keep NetFlow / IPFIX data); on busy networks lower it.
