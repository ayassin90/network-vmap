# Configuration changes
pages: changes:list changes:new changes:detail changes:templates changes:template changes:template_new
group: Operations
order: 44
VMap can change device configuration safely: every change is recorded, a rollback point is saved on the device first, and a change that the device rejects is rolled back automatically.

## port: Changing one port
On a port's page (Devices → device → Interfaces → port), operators can shut or enable the port, **bounce** it (shut, wait 5 seconds, enable), change its access VLAN, set its description, and turn PoE off, on or **cycle** it (a quick way to reboot a phone or access point). These run straight away, without approval. Tick "save the configuration" to make the change survive a reload.

## templates: Templates
A template is a reusable change with blanks to fill in. It is rendered separately for each device, so it can use the device's own name, site and port lists, for example "add BPDU Guard to every access port on this switch". Starter templates are included; administrators can add and edit them.

## flow: Request, preview, approve
1. Pick a template (or type lines), pick devices, and click **Preview**: you see exactly what each device will receive, and which lines it already has.
2. **Submit** sends it for approval. An administrator approves or rejects it (with four-eyes on in Settings, it must be someone else).
3. It runs on a few devices at a time. Each device: save a rollback point (`copy running-config flash:…` on Cisco, a checkpoint on Aruba CX), apply, optionally save.

## rollback: Rollback
- **Automatic**: if the device rejects a line, VMap restores the saved configuration on that device (`configure replace` on Cisco, checkpoint restore on Aruba CX) and marks it "Rolled back".
- **By hand**: on a finished change, administrators can **Roll back** any device to the configuration saved before the change.
After every change VMap collects the device again, so findings, the config history and the **Config diff** button show the result.

## freeze: Change freezes
During a change freeze (Maintenance page) changes and upgrades wait. Administrators can tick **Emergency** on a port action to run it anyway; it is marked as such in the history.
