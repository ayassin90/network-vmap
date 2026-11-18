# Sites & credentials
pages: inventory:setup
group: Setup
order: 30
## credentials: Credentials
A credential is a reusable login. Many devices can share one.
- **SSH**: username and password. If the account does not land at privilege 15, fill in the **enable secret** too. Read access to `show running-config` is required for security checks and standards.
- **SNMP v2c**: a read-only community string. Prefer an access list on the switch that only allows VMap or the collector.
- **SNMP v3**: username, authentication protocol and password, privacy protocol and password. Use SHA and AES where the device supports them.
- **Port** 0 means the default (22 for SSH, 161 for SNMP).
Passwords are encrypted in the database and never shown again. When you edit a credential, leave a password field empty to keep the current value.
> VMap only ever runs read-only commands during collection. The only time it changes anything is a software upgrade plan you create and approve.

## sites: Sites
Sites group devices: they filter the device list and the maps, and a discovery can assign all the devices it finds to a site.
