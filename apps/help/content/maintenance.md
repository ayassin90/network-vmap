# Maintenance windows and change freezes
pages: alerts:maintenance
group: Operations
order: 45
## mute: Maintenance window (mute alerts)
For planned work. Alerts for the covered devices are still recorded (so you can see what happened), but marked suppressed and **not sent** to email, Slack, Teams or webhooks. When the window ends they are released.

## freeze: Change freeze
For busy periods (year end, events). Configuration changes and live upgrades for the covered devices wait until the freeze ends. Dry-run upgrades still run. Administrators can force an emergency port change.

## scope: Scope
A window can cover every device, whole sites, or picked devices.
