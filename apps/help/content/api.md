# REST API
pages: api:tokens
group: Setup
order: 34
VMap has a JSON API for integrations: ticketing (ServiceNow, Jira), dashboards (Grafana), inventory sync scripts, chat bots.

## auth: Tokens
Create a token on this page and send it in the `Authorization: Token <token>` header. A **read-only** token can read everything; a **read and write** token can also add devices, start collections and acknowledge alerts. Tokens act as the administrator who created them; revoke a token as soon as it is no longer needed.

## endpoints: What is available
- `GET /api/v1/devices/` (filters: q, site, status, platform, role), `POST /api/v1/devices/` (mgmt_ip, hostname, platform, site, ssh_credential, snmp_credential by name)
- `GET /api/v1/devices/<id>/`, `/interfaces/`, `/config/`; `POST /api/v1/devices/<id>/collect/`
- `GET /api/v1/endpoints/?q=<mac, ip or name>`: where something is plugged in
- `GET /api/v1/findings/`, `GET /api/v1/alerts/`, `POST /api/v1/alerts/<id>/ack/`
- `GET /api/v1/routes/lookup/?ip=` and `GET /api/v1/path/?src=&dst=`
Lists are paged with `limit` and `offset`.
