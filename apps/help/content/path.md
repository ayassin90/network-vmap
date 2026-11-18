# Path trace
pages: topology:path
group: Network
order: 12
Shows how traffic from one IP address gets to another, using only what VMap has collected. Use it to answer "which switches and links does this traffic cross?" before a change, or to find where traffic stops.

## how: How the trace is built
1. **Where is the source?** A device address, or an endpoint found in the MAC/ARP tables (Find endpoint).
2. **To its gateway (layer 2)**: the shortest path through switch links that carry the source VLAN and are not blocked by spanning tree.
3. **Across routers (layer 3)**: on each router, the most specific matching route; its next hop tells VMap which device comes next.
4. **To the destination (layer 2)**: from the last router to the switch port where the destination is plugged in.
If the destination is outside the managed network (the internet, a partner), the trace ends where traffic leaves.

## stops: When the trace stops early
- "No route": a router has no route (not even a default) to the destination; traffic is dropped there.
- "No forwarding layer 2 path": the VLAN is missing on a trunk, or every path is blocked or down.
- "Routing loop": two routers point at each other.

## issues: Problems on this path
Every open interface problem (errors, half duplex, mismatches, high load, flapping) on a port the path uses is listed next to the result, so a slow application can be tied to a bad link quickly.

## limits: Limits
The trace uses the last collected tables, not live packets. Policy routing, ACLs, NAT, firewalls and load-balancers are not taken into account, and equal-cost routes show the first path (with a note).
