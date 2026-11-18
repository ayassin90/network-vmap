# Lifecycle
pages: lifecycle:overview
group: Assurance
order: 23
Keeps track of how long your hardware is supported, whether each device runs the software you chose, and which devices a support contract covers.

## hardware: Hardware end of life
Vendors announce **end of sale** (no more orders), then **last day of support** (no fixes, no security patches, no support cases). VMap matches every chassis, module and optic it collects against these dates and raises findings when support has ended or ends within a year.
Where the data comes from:
- **Fetch from Cisco** uses the Cisco EoX API (enable it for the same API-console app as openVuln, keys in Settings).
- **Import CSV** for any vendor, or add records by hand. Tick "match every product ID starting with this" to cover a family with one line.

## software: Software versions ("golden images")
For each platform (and optionally each model), set the **recommended** version and the **minimum** you accept. Devices below the minimum get a high finding; devices not on the recommended version get a low one. The upgrade planner uses the same versions.

## contracts: Support contracts
Add contracts with their end date and the serial numbers they cover (or import a CSV, or fetch coverage from Cisco's Serial Number to Information API). VMap reports devices that are not covered, contracts that have ended, and contracts ending within 90 days.

## optics: Optics inventory
Every transceiver with its product ID, serial and, where the switch reports it (DOM), receive and transmit light, temperature and thresholds. "Alarm" means the switch itself flags the value as out of range; act on those before they become CRC errors or a dead link.
