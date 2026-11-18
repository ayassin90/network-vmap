"""Starter templates, created once. Edit or delete them freely."""
TEMPLATES = [
    ("Time and logging servers", "Point the device at your NTP and syslog servers.", "cisco_ios,cisco_iosxe",
     "ntp server {{ vars.ntp1 }}\n{% if vars.ntp2 %}ntp server {{ vars.ntp2 }}\n{% endif %}logging host {{ vars.syslog }}\nlogging trap informational\n"
     "service timestamps log datetime msec localtime show-timezone\n",
     [{"name": "ntp1", "label": "NTP server 1"}, {"name": "ntp2", "label": "NTP server 2 (optional)"}, {"name": "syslog", "label": "Syslog server"}]),
    ("Harden access ports", "PortFast, BPDU Guard and broadcast storm control on every access port of the device.", "cisco_ios,cisco_iosxe",
     "{% for i in interfaces.access %}interface {{ i.name }}\n spanning-tree portfast\n spanning-tree bpduguard enable\n"
     " storm-control broadcast level {{ vars.storm_level|default:'1.00' }}\n{% endfor %}",
     [{"name": "storm_level", "label": "Broadcast storm level (%)", "default": "1.00"}]),
    ("Disable web management", "Turn off the HTTP and HTTPS servers (CVE-2023-20198 exposure).", "cisco_ios,cisco_iosxe",
     "no ip http server\nno ip http secure-server\n", []),
    ("Park unused ports", "Shut every access port that has nothing connected and move it to a parking VLAN.", "cisco_ios,cisco_iosxe",
     "{% for i in interfaces.unused %}interface {{ i.name }}\n description UNUSED\n switchport access vlan {{ vars.parking_vlan }}\n shutdown\n{% endfor %}",
     [{"name": "parking_vlan", "label": "Parking VLAN", "default": "999"}]),
    ("Aruba CX: edge port protection", "BPDU guard, admin-edge and loop-protect on every access port.", "aruba_aoscx",
     "{% for i in interfaces.access %}interface {{ i.name }}\n    spanning-tree bpdu-guard\n    spanning-tree port-type admin-edge\n    loop-protect\n{% endfor %}", []),
]


def ensure_templates():
    from .models import ConfigTemplate
    if ConfigTemplate.objects.exists():
        return
    for name, desc, plats, body, variables in TEMPLATES:
        ConfigTemplate.objects.create(name=name, description=desc, platforms=plats, body=body, variables=variables, created_by="system")
