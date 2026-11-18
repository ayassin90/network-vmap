# Event log (syslog and traps)
pages: events:list events:rules
group: Operations
order: 46
VMap receives syslog messages (UDP 514) and SNMP traps (UDP 162) from your devices, keeps them for 14 days, and acts on the important ones.

## setup: Sending events to VMap
On a Cisco switch:
- `logging host <vmap-ip>` and `logging trap informational`
- `snmp-server host <vmap-ip> version 2c <community>` and `snmp-server enable traps snmp linkdown linkup coldstart`
Messages are matched to devices by source IP (management or any interface address). Senders VMap does not know are listed apart.

## rules: Rules
Each message is checked against the rules in order; the first match decides:
- **Raise an alert**: one alert per device and rule while it keeps happening (the count goes up). Examples: err-disabled ports, BPDU Guard, routing neighbour down, power/fan/temperature alarms, failed logins, duplicate IPs.
- **Collect the device now**: used for "configuration changed" messages, so a change shows up in the config history within a minute, with a diff and a config-change alert.
- **Count as a link change**: link up/down messages and traps feed the flapping detection on that port.
- **Ignore**: keep it in the log only.
Rules are regular expressions on the message text, including the Cisco mnemonic such as `%LINK-3-UPDOWN`.

## live: Live view
"Live" refreshes the page every 10 seconds: handy during a change window.
