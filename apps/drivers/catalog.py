"""Every platform VMap knows about. Cisco is implemented first; the others are listed with their connection type and
what is already possible through generic SNMP, so the Platform guide shows exactly where each vendor stands.
To implement a vendor, subclass Driver (see cisco.py), set its features to "full" and register it in registry.py."""
from .base import Driver

SNMP_ONLY = {"ssh_collect": "planned", "snmp": "full", "neighbors": "snmp", "vlans": "snmp", "routes": "snmp",
             "interfaces": "snmp", "config": "planned", "security": "planned", "standards": "planned", "psirt": "planned",
             "upgrade": "planned"}


class SnmpDriver(Driver):
    """Base for platforms that, for now, are collected over SNMP only."""
    status = "snmp"
    features = SNMP_ONLY


def _p(key, vendor, label, netmiko, models, notes="", upgrade="planned", upgrade_notes="", psirt="planned", **extra):
    attrs = {"key": key, "vendor": vendor, "label": label, "netmiko_type": netmiko, "ntc_platform": netmiko, "models": models,
             "notes": notes or "SNMP gives neighbours, interfaces, errors, throughput and routes today. The SSH driver "
                               "(configuration backup, security checks, standards) is planned.",
             "features": dict(SNMP_ONLY, upgrade=upgrade, psirt=psirt, **extra), "upgrade_notes": upgrade_notes}
    return type(f"Driver_{key}", (SnmpDriver,), attrs)


OTHER = [
    _p("cisco_sbs", "Cisco", "Cisco Business / Small Business (CBS, SG)", "cisco_s300", "CBS220/250/350, SG300/350/500, Catalyst 1200/1300",
       upgrade="manual", upgrade_notes="Firmware is usually loaded through the web UI or TFTP with a reboot; treat as manual."),
    _p("cisco_iosxr", "Cisco", "Cisco IOS-XR", "cisco_xr", "ASR 9000, NCS 5500, 8000", upgrade="manual",
       upgrade_notes="IOS-XR uses install packages and SMUs; plan these with the Cisco tooling for now."),
    _p("aruba_aoscx", "HPE Aruba", "Aruba AOS-CX", "aruba_aoscx", "CX 4100i, 6000, 6100, 6200, 6300, 6400, 8100, 8320, 8325, 8360, 9300",
       upgrade="planned", upgrade_notes="AOS-CX supports remote upgrade (copy to the secondary partition, boot system secondary). Driver planned."),
    _p("aruba_aoss", "HPE Aruba", "Aruba AOS-S / ProCurve", "hp_procurve", "2530, 2540, 2930F/M, 3810M, 5400R",
       upgrade="planned", upgrade_notes="Remote upgrade over TFTP/SFTP to the secondary flash, then `boot system flash secondary`. Driver planned."),
    _p("hp_comware", "HPE", "HPE Comware / H3C", "hp_comware", "HPE 5130, 5140, 5510, 5710, 5940, 5945, H3C S5000/S6000"),
    _p("huawei_vrp", "Huawei", "Huawei VRP (CloudEngine / S-series)", "huawei", "S5700, S6700, S7700, S12700, CE6800, CE12800",
       upgrade="planned", upgrade_notes="Remote upgrade is possible (`startup system-software`), but stacks (iStack/CSS) need care. Driver planned."),
    _p("juniper_junos", "Juniper", "Juniper Junos (EX / QFX)", "juniper_junos", "EX2300, EX3400, EX4300, EX4400, EX4650, QFX5100/5120/5200",
       upgrade="planned", upgrade_notes="`request system software add` with validation, then reboot. Virtual Chassis needs NSSU for hitless upgrades."),
    _p("arista_eos", "Arista", "Arista EOS", "arista_eos", "7010, 7020, 7050X, 7060X, 7280R, 720XP, 750",
       upgrade="planned", upgrade_notes="Copy the .swi, set `boot system flash:`, reload. Smart System Upgrade (SSU) on supported models."),
    _p("dell_os10", "Dell", "Dell Enterprise SONiC / OS10", "dell_os10", "S4100, S5200, Z9100, Z9200 series"),
    _p("dell_os6", "Dell", "Dell OS6 (N-series)", "dell_os6", "N1100, N1500, N2000, N3000, N4000", upgrade="manual"),
    _p("extreme_exos", "Extreme", "Extreme EXOS / Switch Engine", "extreme_exos", "X440-G2, X460-G2, X465, X590, X620, X690, 5320, 5420, 5520"),
    _p("extreme_voss", "Extreme", "Extreme VOSS / Fabric Engine", "extreme_vsp", "VSP 4900, VSP 7400, 5520 (Fabric Engine)"),
    _p("ruckus_icx", "Ruckus (CommScope)", "Ruckus ICX / FastIron", "ruckus_fastiron", "ICX 7150, 7250, 7450, 7550, 7650, 7850",
       upgrade="planned", upgrade_notes="Copy image via TFTP/SCP to primary or secondary flash, then reload. Driver planned."),
    _p("fortiswitch", "Fortinet", "FortiSwitch (standalone)", "fortinet", "FortiSwitch 100 / 200 / 400 / 500 / 1000 / 3000 series",
       upgrade="manual", upgrade_notes="FortiLink-managed FortiSwitches are upgraded from the FortiGate; standalone units through `execute restore image`.",
       psirt="planned"),
    _p("mikrotik", "MikroTik", "MikroTik RouterOS / SwOS", "mikrotik_routeros", "CRS3xx, CRS5xx, CSS series", upgrade="manual"),
    _p("ubiquiti", "Ubiquiti", "Ubiquiti EdgeSwitch / UniFi", "ubiquiti_edgeswitch", "EdgeSwitch, UniFi switches (UniFi are controller-managed)",
       upgrade="none", upgrade_notes="UniFi switches are upgraded from the UniFi controller only."),
    _p("netgear", "Netgear", "Netgear ProSAFE / M4x00", "netgear_prosafe", "M4250, M4300, M4350, GS7xx", upgrade="manual"),
    _p("allied", "Allied Telesis", "Allied Telesis AlliedWare Plus", "allied_telesis_awplus", "x230, x330, x530, x930, SBx908"),
    _p("alcatel_aos", "Alcatel-Lucent", "Alcatel-Lucent OmniSwitch (AOS)", "alcatel_aos", "OS2260, OS2360, OS6360, OS6560, OS6860, OS6900"),
    _p("nvidia_onyx", "NVIDIA", "NVIDIA / Mellanox Onyx & Cumulus", "mellanox_mlnxos", "SN2000, SN3000, SN4000 series"),
    _p("zyxel", "Zyxel", "Zyxel switches", "zyxel_os", "XGS / XS / GS series", upgrade="manual"),
    _p("tplink", "TP-Link", "TP-Link JetStream / Omada", "tplink_jetstream", "T1600G, T2600G, T3700G, SG3428", upgrade="manual"),
    _p("dlink", "D-Link", "D-Link managed switches", "dlink_ds", "DGS-1210, DGS-3000, DXS series", upgrade="manual"),
    _p("ruijie", "Ruijie", "Ruijie RGOS", "ruijie_os", "S2900, S5300, S5750, S6000 series"),
    _p("zte", "ZTE", "ZTE ZXR10", "zte_zxros", "ZXR10 5900, 5960, 9900 series"),
]


class GenericSnmp(SnmpDriver):
    key = "generic_snmp"
    vendor = "Any"
    label = "Any vendor (generic SNMP)"
    netmiko_type = "generic"
    models = "Anything that answers standard MIBs (IF-MIB, LLDP-MIB, IP-MIB, BRIDGE-MIB)"
    notes = "Use this for vendors without a driver yet. You get neighbours, interfaces, errors, throughput and routes."
