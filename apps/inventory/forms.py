from django import forms

from apps.drivers.registry import choices as platform_choices

from .models import Credential, Device, DiscoveryRun, Site


class DeviceForm(forms.ModelForm):
    class Meta:
        model = Device
        fields = ["hostname", "mgmt_ip", "platform", "role", "site", "ssh_credential", "snmp_credential", "collector", "tags", "enabled", "notes"]
        widgets = {"notes": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.fields["platform"] = forms.ChoiceField(choices=platform_choices(), initial="cisco_iosxe")
        self.fields["ssh_credential"].queryset = Credential.objects.filter(kind="ssh")
        self.fields["snmp_credential"].queryset = Credential.objects.exclude(kind="ssh")
        self.fields["ssh_credential"].required = False
        self.fields["hostname"].help_text = "Replaced by the device's own hostname after the first collection."
        self.fields["collector"].empty_label = "This server (direct)"


class BulkAddForm(forms.Form):
    lines = forms.CharField(widget=forms.Textarea(attrs={"rows": 10, "placeholder": "10.10.0.1\n10.10.0.2,access-sw-02\ncore-1.example.net"}),
                            help_text="One device per line: an IP or hostname, optionally followed by a comma and a display name.")
    platform = forms.ChoiceField(choices=[])
    role = forms.ChoiceField(choices=Device.ROLES, initial="unknown")
    site = forms.ModelChoiceField(Site.objects.all(), required=False)
    ssh_credential = forms.ModelChoiceField(Credential.objects.filter(kind="ssh"), required=False)
    snmp_credential = forms.ModelChoiceField(Credential.objects.exclude(kind="ssh"), required=False)
    collector = forms.ModelChoiceField(None, required=False, empty_label="This server (direct)")
    collect_now = forms.BooleanField(required=False, initial=True, label="Collect right away")

    def __init__(self, *a, **kw):
        from apps.jobs.models import Collector
        super().__init__(*a, **kw)
        self.fields["platform"].choices = platform_choices()
        self.fields["collector"].queryset = Collector.objects.all()


class SiteForm(forms.ModelForm):
    class Meta:
        model = Site
        fields = ["name", "location", "description"]
        widgets = {"description": forms.Textarea(attrs={"rows": 2})}


class CredentialForm(forms.ModelForm):
    password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False), help_text="SSH password. Leave empty to keep the current one.")
    enable = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False), label="Enable secret", help_text="Only if the account does not log in at privilege 15.")
    community = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False), label="SNMP community", help_text="SNMP v2c only.")
    auth_key = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False), label="SNMPv3 auth password")
    priv_key = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False), label="SNMPv3 privacy password")

    class Meta:
        model = Credential
        fields = ["name", "kind", "username", "port", "auth_proto", "priv_proto"]

    def save(self, commit=True):
        obj = super().save(commit=False)
        for f in ("password", "enable", "community", "auth_key", "priv_key"):
            v = self.cleaned_data.get(f)
            if v:
                setattr(obj, f, v)
        if commit:
            obj.save()
        return obj


class DiscoveryForm(forms.ModelForm):
    class Meta:
        model = DiscoveryRun
        fields = ["name", "seeds", "platform", "ssh_credential", "snmp_credential", "site", "collector", "max_depth", "include"]
        widgets = {"seeds": forms.Textarea(attrs={"rows": 4, "placeholder": "10.0.0.1\n10.0.0.2"})}

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.fields["platform"] = forms.ChoiceField(choices=[("auto", "Detect (Cisco IOS / IOS-XE / NX-OS)")] + platform_choices(), initial="auto",
                                                    help_text="Seeds use this platform. Neighbours are detected from their CDP/LLDP platform.")
        self.fields["ssh_credential"].queryset = Credential.objects.filter(kind="ssh")
        self.fields["snmp_credential"].queryset = Credential.objects.exclude(kind="ssh")
        self.fields["collector"].empty_label = "This server (direct)"
