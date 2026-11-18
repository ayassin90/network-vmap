# Network VMap

Visibility and assurance for campus and data centre switches and routers, over SSH and SNMP.

- **Inventory & discovery**: add devices, paste a list, or crawl CDP/LLDP from a seed switch.
- **Topology**: live layer 2 (trunk / access / routed / port-channel, hover any port for details) and layer 3 (subnets, point-to-point links, OSPF) maps, with saved custom layouts, grouping by site/role/vendor, colouring by status/vendor/score, notes, hand-drawn links and custom nodes (ISP, firewall, cloud…).
- **Assurance**: built-in security and best-practice checks, your own config standards with remediation, interface health (errors, CRC, half duplex, speed/duplex/trunk/native mismatches, err-disabled, utilisation, throughput history), PSIRT matching (Cisco openVuln API + built-in config exposure checks).
- **Operations**: alerts with auto-resolve and notifications (email, webhook, Slack, Teams), case management, mass software upgrades in waves (dry run, approval, pre/post checks).
- **Cloud-ready**: remote collectors connect out over HTTPS, so a cloud-hosted server can manage private networks.
- **Find any endpoint**: MAC/IP/name → switch and edge port, with move history (MAC + ARP tables).
- **Spanning tree & VLANs**: root bridge per VLAN, blocked ports (also on the map), topology-change sources, trunk VLAN mismatches, undefined VLANs.
- **Lifecycle**: end-of-sale/support per chassis, module and optic (Cisco EoX API or CSV), golden software versions, contract coverage, optics light levels.
- **Less alert noise**: topology-aware root-cause suppression, maintenance windows, change freezes, cool-down/flap detection, change correlation.
- **Changes**: port actions (shut, bounce, VLAN, description, PoE cycle), config templates rendered per device with preview, approval (optional four-eyes), rollback point on the device, automatic rollback on error.
- **Hardware health**: CPU, memory, temperature, fans and power supplies (SSH and SNMP), with history.
- **Syslog & SNMP traps**: receiver on udp/514 and udp/162, event rules (alert, collect-on-config-change, flap counting), live event log.
- **Path trace**: hop-by-hop L2/L3 path between two IPs from MAC/ARP, STP and routing tables, with the problems on the way.
- **Traffic**: NetFlow v5/v9 and IPFIX collector on udp/2055: top talkers, destinations, applications, conversations, per exporter and interface.
- **Snapshots ("time machine")**: daily and on-demand snapshots of devices, software, ports, links, routes, endpoints and findings; compare any two, or one with now.
- **Reports**: capacity (p95 uplink load, free / never-used ports, PoE), a weekly email summary, a printable audit report (save as PDF), CSV export of every main list.
- **Sign-in**: local accounts, LDAP / Active Directory (group → role), and OIDC single sign-on (Entra ID, Okta, Google, Keycloak…).
- **Integrations**: REST API (`/api/v1/`), NetBox push (devices, interfaces, IPs, cables) and import, Jira / ServiceNow / webhook tickets for cases.
- **Platforms** (SSH drivers): Cisco IOS / IOS-XE / NX-OS, Aruba AOS-CX and AOS-S, Huawei VRP, Juniper Junos, Arista EOS, FortiSwitch, with remote upgrades on all of them; 19 other vendor families via SNMP (see the Platform guide page). Drivers other than Cisco IOS/IOS-XE are beta: tested against the mock lab, not yet on real hardware.

## Run with Docker

```bash
cp .env.example .env      # set the secrets
docker compose up -d --build
# open http://<host>:8090  (user/password from .env: VMAP_ADMIN_USER / VMAP_ADMIN_PASSWORD)
```

Services: `web` (Django + gunicorn), `worker` (jobs + scheduler), `receiver` (syslog udp/514, traps udp/162, NetFlow/IPFIX udp/2055), `db` (PostgreSQL 16). Data lives in the `vmap-data` and `vmap-db` volumes.

Sample data: `VMAP_LOAD_DEMO=1` loads a demo campus on first start; remove it with
`docker compose exec web python manage.py load_demo --clear`.

## Mock switch lab (test without real hardware)

Fifteen pretend switches on 172.31.99.0/24 that speak SSH and SNMP, keep state, accept config changes and rollbacks, "upgrade" and reload,
and send syslog, traps and NetFlow (v9, IPFIX, v5): Catalyst 9500 cores, 9300 and 2960-X access, an ISR WAN router, Aruba CX 6300 and
2930F (AOS-S), Huawei S5735, Juniper EX2300, FortiSwitch 148F, and an Arista 7050SX3 + Nexus 93180 data-centre pair. Problems are planted
on purpose (half duplex, CRC errors, failed fan and PSU, MTU and VLAN mismatches, Telnet, default SNMP…) so every check has something to find.
SSH `vmap` / `vmap-lab`, SNMP community `vmap-lab`.

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d --build
docker compose exec web python manage.py lab_setup --clear-demo     # credentials, sample lifecycle data, discovery from 172.31.99.1
```

## Remote collector

Create a collector on the **Collectors** page, then inside the remote network:

```bash
docker build -t vmap-collector ./collector
docker run -d --restart unless-stopped -e VMAP_URL=https://vmap.example.com -e VMAP_TOKEN=vmc_... vmap-collector
```

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python manage.py migrate && .venv/bin/python manage.py bootstrap && .venv/bin/python manage.py load_demo
.venv/bin/python manage.py runserver 0.0.0.0:8090     # and in another shell:
.venv/bin/python manage.py run_worker
```

## Layout

| Path | What |
|---|---|
| `apps/drivers/` | Platform drivers (commands, parsing, upgrade steps) and the feature matrix. Add a vendor here. |
| `collector/` | Standalone executor (SSH/SNMP) shared by the worker and the remote agent. |
| `apps/jobs/` | Job queue, worker, scheduler, collector API, result ingest. |
| `apps/checks/` | Security / best-practice rules, interface health, config standards. |
| `apps/topology/` | L2/L3 graph builders and saved layouts (`apps/core/static/core/topology.js` draws them). |
| `apps/psirt/`, `apps/upgrades/`, `apps/alerts/` | Advisories, upgrade plans, alerts and cases. |
| `apps/flows/` | NetFlow v5/v9/IPFIX decoder, per-minute aggregation, traffic page. |
| `apps/snapshots/` | Network snapshots and diffs. |
| `apps/integrations/` | NetBox sync and ticketing (Jira, ServiceNow, webhook). |
| `apps/accounts/sso.py` | LDAP / Active Directory backend and OIDC sign-on. |
| `labnet/`, `tools/mocklab/` | The lab network model, per-vendor CLI output, and the mock switch (SSH, SNMP, syslog, traps, NetFlow). |
| `apps/help/content/` | Right-panel help, one Markdown file per page. |
