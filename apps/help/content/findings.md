# Security & best practices
pages: checks:findings
group: Assurance
order: 20
After each collection VMap reads the configuration and checks it against built-in security and best-practice rules. Each problem becomes a **finding** on that device.

## reading: Reading a finding
- **What we saw** is the exact thing found on the device (for example, which VTY lines allow Telnet, or which ports lack BPDU Guard).
- The text below explains **why it matters** and **what to do**, in plain words.
- **Suggested configuration** is a starting point you can adapt and paste. VMap does not push it for you.

## lifecycle: Open, resolved, accepted
A finding stays **open** while the check still sees the problem, and **resolves itself** on the next collection after you fix it. If a finding is acceptable in your environment (for example HTTP is needed for a specific tool), an operator can **Accept risk** with a reason; it then stops counting against the score and stops alerting.

## security-vs-practice: Security versus best practice
**Security** findings are about who can get in or what an attacker could abuse. **Best practice** findings are about stability and operations: spanning tree, logging, time, port hygiene. Both count towards the Security score.

## rerun: Re-run checks
Re-evaluates every rule on the data already collected, without logging in to the devices. Useful after you edit a config standard or change thresholds.
