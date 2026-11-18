# Collectors
pages: jobs:collectors jobs:collector
group: Setup
order: 32
A collector lets a VMap server that runs elsewhere (for example in the cloud) manage switches in a private network.

## how: How it works
The collector is a small agent you run inside the private network. Every few seconds it connects **out** to VMap over HTTPS and asks for work. VMap answers with the jobs for the devices assigned to it. The agent runs SSH and SNMP against those devices locally and posts the raw output back; all parsing and analysis happen on the server.
- No inbound firewall rule or VPN is needed, only HTTPS out from the collector to VMap.
- Credentials travel only inside the HTTPS connection, only for the jobs that need them.
- One collector handles hundreds of switches. Add more for more sites.

## install: Installing the agent
Create the collector here to get its token (shown once). Then on any small Linux machine in that network, run the Docker command shown on the collector's page, or run `agent.py` with Python. The collector appears **Online** within seconds. Finally, set the collector on each device (or on a discovery) so its jobs go there.

## token: Tokens
The token identifies the collector. Keep it secret. **New token** replaces it immediately: the running agent stops until you give it the new one. **Disable** stops a collector from receiving jobs without deleting it.
