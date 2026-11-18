# Software upgrades
pages: upgrades:list upgrades:plan upgrades:new upgrades:images
group: Operations
order: 42
Upgrade many devices in a controlled way: one image, a list of devices, a few at a time, with checks before and after.

## images: Images
VMap does not store image files. Put the file on a server your switches can reach (HTTP, HTTPS, SCP, FTP or TFTP) and give VMap its URL. Each switch downloads it directly. Always fill in the **MD5** from the vendor download page: the plan stops on a device if the copied file does not match. **Size** lets VMap check free flash space before copying.

## stages: What happens on each device
1. **Pre-check**: reads the version and free space. Devices already on the target version are skipped. Install or bundle mode is detected on IOS-XE.
2. **Transfer**: copies the image to flash (skipped if the file is already there).
3. **Verify**: checks the MD5 of the copied file.
4. **Activate**: IOS-XE in install mode runs `install add file … activate commit`; bundle mode and classic IOS set the boot variable and save; NX-OS runs `install all`.
5. **Post-check**: after the reload, VMap waits for the device to come back and confirms the new version. It retries for about half an hour.

## modes: Copy only, or activate
"Copy and verify only" stages the image during the day without any impact; create a second plan later to activate in a change window.

## reload: Allow reload
Activation on most platforms means a reload, which interrupts traffic through that switch. If you do not allow the reload, IOS-XE install mode only adds the package and classic IOS only sets the boot variable; the new version runs after the next reload.

## safety: Safety
- New plans start as a **dry run**: every command is listed in the log and nothing is sent. Run one first.
- Live plans need an administrator's approval.
- **Devices at a time** limits the blast radius. **Pause after failures** stops the rollout when something goes wrong, so you can look before continuing.
- Stacks, vPC pairs and redundant cores: put the two members of a pair in different plans, or use 1 device at a time.
- Platforms that cannot be upgraded remotely are marked "Manual" in the platform guide.
