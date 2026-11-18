# Alerts
pages: alerts:list alerts:detail alerts:rules
group: Operations
order: 40
Alerts tell you when something needs attention. They are raised automatically after each collection or poll.

## lifecycle: How an alert lives
- **Open**: the problem exists and nobody has acknowledged it.
- **Acknowledged**: someone is on it. It stays visible but does not look new.
- **Resolved**: the problem went away (VMap checks again on every collection) or someone resolved it by hand.
The same problem never creates two alerts: while it persists, the existing alert's counter and "last seen" time go up.
Configuration-change alerts are the exception: they stay until someone acknowledges or resolves them, so every change gets reviewed.

## rules: Rules
- **Device unreachable or login failing**: the last collection or poll could not reach the device or the login was refused.
- **Security finding** and **Interface problem**: raised for findings at or above the chosen minimum severity.
- **Vulnerable software (PSIRT)**: a device matches an advisory at or above the minimum severity.
- **Below config standard target**: a device's standards score drops under the target percentage.
- **Configuration changed**: a new configuration version was saved.
Untick **Notify** to keep a rule on the Alerts page without sending messages.

## noise: Less noise
VMap works to send you fewer, better alerts:
- **Root cause first**: when a switch is down, devices that can only be reached through it are also unreachable. Their alerts are linked to the switch's alert as *consequences* and are not sent. The alert list hides them by default ("Show suppressed").
- **Cool-down**: an alert that clears and comes back within 30 minutes (Settings) reopens the same alert instead of creating a new one. If it keeps coming back it is marked **flapping** and stops notifying.
- **Maintenance windows** mute alerts during planned work.
- **Change correlation**: if the device's configuration changed, or a VMap change ran on it, shortly before the alert, the alert says so. That is the first thing to check.

## channels: Notification channels
New alerts are sent to every channel whose minimum severity they meet. Email needs SMTP settings in the server environment. Slack and Teams take an incoming-webhook URL. "Webhook" posts JSON to any URL (for a ticketing system or SOAR). Use **Send test** to check a channel. Set the public URL in Settings so links in messages open the right page.

## cases: Alerts and cases
Select alerts and choose **Open a case** to start tracking them together, or **Add to case** to attach them to an existing one.
