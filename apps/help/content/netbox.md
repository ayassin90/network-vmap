# NetBox
pages: integrations:netbox integrations:run
group: Setup
order: 34
Keep NetBox, your source of truth for documentation, in step with what VMap actually sees, or use NetBox to tell VMap what to manage.

## push: Push to NetBox
For every enabled device VMap creates or updates, in NetBox: the site (by name), manufacturer, device type (model), device role, platform, the device itself (serial, status, comments), all its interfaces (type, description, enabled, MTU), management IP addresses (set as the primary IPv4) and **cables** between devices that see each other over CDP or LLDP. Nothing is deleted in NetBox. **Dry run** lists what would change without writing anything. Devices without a VMap site use the default NetBox site from Settings, or are skipped.

## import: Import from NetBox
Active NetBox devices that have a primary IP become VMap devices with the credentials you pick. The NetBox platform slug selects the driver when it matches one of VMap's (for example `cisco_iosxe`, `juniper_junos`, `arista_eos`), otherwise the manufacturer is used to guess, then the default you choose. Devices whose IP is already in VMap are skipped. Imported devices are tagged `netbox`.

## schedule: Scheduled push
Set "Push to NetBox every (hours)" in Settings to keep NetBox up to date automatically.
