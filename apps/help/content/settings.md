# Settings
pages: core:settings accounts:users
group: Setup
order: 33
## schedule: Schedules
- **Full collection** reads everything from each device over SSH. Every 6 hours is a good default; lower it for faster change detection, raise it on very large networks.
- **Interface poll** refreshes counters and throughput. Every 5 minutes with SNMP is light for the devices.

## thresholds: Thresholds
**Interface error threshold** is the counter value at which errors become a finding (any new CRC errors since the last poll always count). **High utilisation** is the percentage at which a port is reported as busy.

## more: Other settings
- **MAC scan**: how often MAC and ARP tables are read for the endpoint finder (between full collections).
- **Alert cool-down**: an alert that comes back within this many minutes reopens instead of creating a new one.
- **Four-eyes approval**: when on, a configuration change must be approved by someone other than the person who asked for it.
- **Upgrade reload wait / retry**: how long to wait for a switch to come back after the reload, and how often to retry.

## sso: Directory login and single sign-on
- **LDAP / Active Directory**: VMap binds with a read-only service account, finds the user with the filter (`(sAMAccountName={username})` for AD, `(uid={username})` for OpenLDAP), then checks their password by binding as them. Their groups (`memberOf`) decide the role: list group DNs or names for Administrator, Operator and Viewer. People in none of them are refused unless you set a default role. Use **Save and test LDAP** with a real account to check it.
- **Single sign-on (OIDC)**: works with Entra ID (Azure AD), Okta, Google, Keycloak, Authentik and others. Register VMap as a web application with the redirect URI `<public URL>/accounts/oidc/callback/`, paste the issuer, client ID and secret, and map the groups claim to roles. A button appears on the login page.
- Local accounts that have a password keep signing in locally, so keep one administrator as a break-glass account. Directory and SSO users get a local account without a password; their role is refreshed at every sign-in.

## integrations: NetBox and ticketing
- **NetBox**: URL and an API token. See the [NetBox page](/integrations/netbox/) to push the inventory or import devices. Leave the interval at 0 to push only by hand.
- **Ticketing**: `jira`, `servicenow` or `webhook`. When a case of at least the chosen priority is created, VMap opens a ticket and links it on the case page; resolving the case adds a comment to the ticket. A case page also has **Open external ticket** for any priority.

## users: Users and roles
- **Viewer**: sees everything, changes nothing.
- **Operator**: runs collections, polls, tests and commands, works alerts and cases, arranges maps, creates upgrade plans (dry run) and accepts findings.
- **Administrator**: everything, including credentials, collectors, standards, settings, users and approving live upgrades.
