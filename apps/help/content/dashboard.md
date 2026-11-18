# Dashboard
pages: core:dashboard
group: Start here
order: 1
The dashboard is the morning view of your network: what is down, what is risky, and what changed. Every tile is a link to the page with the details.

## tiles: The four tiles at the top
- **Devices** counts every enabled switch and router, and how many could not be reached on the last try.
- **Open alerts** are problems that still exist right now. They close by themselves when the problem goes away.
- **PSIRT exposure** is the number of devices running software with a known vendor security advisory.
- **Interface problems** counts ports with errors, half duplex, speed or duplex mismatches, err-disabled state or very high load.

## scores: Scores (Security, Interface health, Config standards)
Each device gets three scores from 0 to 100. 100 means nothing was found.
- **Security** starts at 100 and loses points for every open security or best-practice finding: 25 for critical, 12 for high, 5 for medium, 2 for low.
- **Interface health** works the same way, using only interface problems.
- **Config standards** is the share of your standard's rules the configuration meets.
The dashboard shows the average over all devices. A device that has never been collected has no score yet (shown as –).
> A score is a way to sort and compare, not a grade. A single critical finding on an internet-facing device matters more than ten low findings elsewhere.

## empty: Starting from nothing
1. Add an SSH credential (and an SNMP one if you can) under **Sites & credentials**.
2. Either add devices one at a time, paste a list, or start a **Discovery** from one core switch.
3. Within a minute or two the maps, findings and scores fill in.
