# PSIRT advisories
pages: psirt:list psirt:detail
group: Assurance
order: 22
Vendor security advisories (PSIRT) that affect the software your devices run.

## sources: Where matches come from
- **Version match (vendor data)**: with a Cisco openVuln API key in Settings, VMap asks Cisco every day which advisories affect each exact software version you run. This is the authoritative list.
- **Exposure by configuration**: without the API, VMap still flags a small set of critical, widely exploited advisories when the vulnerable feature is turned on in the configuration (for example the IOS-XE web UI, Smart Install, Telnet with cluster management). These are exposure warnings: confirm the fixed release for your version with the advisory.

## api: Getting a Cisco openVuln API key
1. Sign in at apiconsole.cisco.com with a Cisco account.
2. Register an application with the "Cisco PSIRT openVuln API" and the client credentials grant.
3. Paste the client ID and secret into Settings. The first check runs within a day; use **Check with Cisco now** to run it straight away.

## status: Marking an advisory
For each device you can set **Mitigated** (for example the feature is disabled or an ACL protects it), **Accepted risk**, or leave it **Open**. Upgrading the device to a fixed release clears the match on the next check.
