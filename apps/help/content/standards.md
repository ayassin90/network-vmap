# Config standards
pages: checks:standards checks:standard checks:standard_new checks:compliance
group: Assurance
order: 21
A config standard is your own list of what every configuration must or must not contain. VMap checks every device against it on each collection and reports what is missing, with the configuration to add.
A starting standard, "Cisco campus baseline", is created for you. Edit it to match your policy.

## rules: Writing rules
Each rule is a regular expression matched against each configuration line (leading spaces removed).
- **Line must be present**: at least one line matches. Example: `^ntp server \S+`.
- **Line must NOT be present**: no line matches. Example: `^ip http server$`.
- **Every matching section must contain**: for each section whose header matches **Section header** (for example `^interface ` or `^line vty`), one of its lines must match the pattern. Add **Only sections that contain** to narrow it, for example only access ports: `^switchport mode access$`.
- **No matching section may contain**: the opposite, for example no trunk may allow all VLANs.
Fill in **Fix** with the configuration that satisfies the rule; it is shown in the report for every device that fails.
> Tip: `^` means start of line and `$` end of line. `\S+` means "some word". `(?!1$)\d+` means "a number other than 1".

## scope: Which devices a standard applies to
**Platforms** lists driver keys (for example `cisco_ios,cisco_iosxe`), or `*` for all. **Roles** limits it further (for example `access` only). Devices outside the scope are not scored.

## report: The device report
Open a device under a standard to see every rule, met or not, where it fails (for section rules: which interfaces or lines), and the fix. Use **Print report** for an audit.
