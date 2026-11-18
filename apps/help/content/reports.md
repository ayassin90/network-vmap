# Reports
pages: reports:capacity reports:summary reports:audit
group: Assurance
order: 25
## capacity: Capacity
- **Uplinks and routed links**: the 95th-percentile load over the chosen period (95% of the samples were below it, so short spikes do not dominate), the peak and the average, the utilisation against the link speed, and the change against the previous period of the same length. Plan an upgrade (another link in the port-channel, or a faster one) when the p95 stays above about 70%.
- **Access ports per switch**: how many are in use and free, and how many were **never used** in the last 30 days (down, with no traffic and no endpoint seen). Reuse those before buying more switches. PoE shows the power budget in use.
Data comes from interface polls (every few minutes with SNMP), so it fills in over time.

## summary: Weekly summary
A one-page summary of the network: devices down, open alerts, new serious findings, findings fixed, PSIRT exposure, lifecycle risks, changes waiting for approval, failed jobs and the busiest uplinks. Set the recipients, day and hour in Settings; it needs SMTP settings on the server (SMTP_HOST and friends in the environment). **Send now** sends it straight away.

## audit: Audit report
One page for auditors: average security and standards scores, every open security and best-practice finding grouped by check with the devices it affects, configuration-standard compliance, vendor advisories (PSIRT) affecting devices, lifecycle risks, risks someone accepted (with their reason) and the devices with the lowest scores. **Print / save as PDF** produces a clean document without the menus.

## export: CSV exports
The device list, interfaces, routes, endpoints, findings and alerts pages have **Export CSV**: it downloads the list with the filters you have on screen, ready for Excel.
