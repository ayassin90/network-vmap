"""Directory and single sign-on logins. Everything is configured in Settings (AppSetting), so no restart is needed.

LDAP / Active Directory: bind with a service account, find the user, bind as the user to check the password, map group
membership to a VMap role. OIDC (Entra ID / Azure AD, Okta, Google, Keycloak, Authentik, dex…): authorization code flow with
PKCE, ID token signature checked against the provider's JWKS, groups claim mapped to a role.

Users who sign in this way get a local account (no usable password) whose role is refreshed on every sign-in."""
import base64
import hashlib
import logging
import secrets
import time

import requests
from django.contrib.auth.backends import BaseBackend

from apps.core.models import AppSetting

from .models import User

log = logging.getLogger("vmap.sso")
RANK = {"viewer": 1, "operator": 2, "admin": 3}


def _list(key):
    """One group per line (or ;). Plain names may also be comma separated; DNs keep their commas."""
    out = []
    for part in (AppSetting.get(key, "") or "").replace(";", "\n").splitlines():
        part = part.strip()
        if not part:
            continue
        out += [part.lower()] if "=" in part else [x.strip().lower() for x in part.split(",") if x.strip()]
    return out


def role_from_groups(groups, prefix):
    """Highest role whose configured groups intersect the user's groups. Group names match on the full DN or the CN."""
    have = set()
    for g in groups or []:
        g = str(g).strip().lower()
        have.add(g)
        if g.startswith("cn="):
            have.add(g.split(",", 1)[0][3:])
    for role in ("admin", "operator", "viewer"):
        if have & set(_list(f"{prefix}_{role}_groups")):
            return role
    return (AppSetting.get(f"{prefix}_default_role", "") or "").strip() or None


def upsert_user(username, role, email="", first="", last="", source=""):
    u = User.objects.filter(username__iexact=username).first()
    if not u:
        u = User(username=username)
        u.set_unusable_password()
    u.role, u.email = role, email or u.email
    u.first_name, u.last_name = (first or u.first_name)[:150], (last or u.last_name)[:150]
    u.is_active = True
    u.save()
    from apps.core.models import AuditLog
    AuditLog.log(u, "login", detail=f"{source} role={role}")
    return u


# ------------------------------------------------------------------ LDAP / AD
def ldap_settings():
    return {"enabled": AppSetting.get("ldap_enabled", "0") == "1", "server": AppSetting.get("ldap_server", ""),
            "bind_dn": AppSetting.get("ldap_bind_dn", ""), "bind_password": AppSetting.get("ldap_bind_password", ""),
            "base": AppSetting.get("ldap_user_base", ""), "filter": AppSetting.get("ldap_user_filter", "") or "(sAMAccountName={username})",
            "start_tls": AppSetting.get("ldap_start_tls", "0") == "1", "verify": AppSetting.get("ldap_verify_cert", "1") == "1",
            "group_base": AppSetting.get("ldap_group_base", "")}


def ldap_authenticate(username, password, conf=None):
    """(user dict, error). The dict has dn, username, email, first, last, groups."""
    from ldap3 import ALL_ATTRIBUTES, SUBTREE, Connection, Server, Tls
    from ldap3.utils.conv import escape_filter_chars
    import ssl
    c = conf or ldap_settings()
    if not (c["server"] and c["base"] and username and password):
        return None, "LDAP is not fully configured"
    tls = Tls(validate=ssl.CERT_REQUIRED if c["verify"] else ssl.CERT_NONE)
    server = Server(c["server"], use_ssl=c["server"].startswith("ldaps://"), tls=tls, connect_timeout=6, get_info=None)
    try:
        svc = Connection(server, user=c["bind_dn"] or None, password=c["bind_password"] or None, receive_timeout=10, raise_exceptions=True)
        if c["start_tls"]:
            svc.open()
            svc.start_tls()
        svc.bind()
        flt = c["filter"].replace("{username}", escape_filter_chars(username))
        svc.search(c["base"], flt, SUBTREE, attributes=[ALL_ATTRIBUTES, "memberOf"], size_limit=2)
        if len(svc.entries) != 1:
            return None, "user not found" if not svc.entries else "more than one user matches"
        e = svc.entries[0]
        dn = e.entry_dn
        attrs = e.entry_attributes_as_dict
        groups = [str(g) for g in attrs.get("memberOf", [])]
        if not groups:          # no memberOf overlay (plain OpenLDAP): look the groups up
            gbase = c["group_base"] or ",".join(p for p in c["base"].split(",") if p.strip().lower().startswith("dc="))
            uid = (attrs.get("uid") or attrs.get("sAMAccountName") or [username])[0]
            svc.search(gbase, f"(|(member={escape_filter_chars(dn)})(uniqueMember={escape_filter_chars(dn)})(memberUid={escape_filter_chars(str(uid))}))",
                       SUBTREE, attributes=["cn"])
            groups = [g.entry_dn for g in svc.entries]
        svc.unbind()
        user = Connection(server, user=dn, password=password, receive_timeout=10, raise_exceptions=True)
        if c["start_tls"]:
            user.open()
            user.start_tls()
        user.bind()
        user.unbind()
    except Exception as exc:  # noqa: BLE001
        msg = str(exc)
        return None, "wrong password" if "invalidCredentials" in msg or "49" in msg.split(" ")[:3] else msg[:200]

    def first(k):
        v = attrs.get(k) or []
        return str(v[0]) if v else ""
    return {"dn": dn, "username": first("sAMAccountName") or first("uid") or username, "email": first("mail"),
            "first": first("givenName"), "last": first("sn"), "groups": groups}, None


class LDAPBackend(BaseBackend):
    def authenticate(self, request, username=None, password=None, **kw):
        c = ldap_settings()
        if not c["enabled"] or not username or not password:
            return None
        local = User.objects.filter(username__iexact=username).first()
        if local and local.has_usable_password():
            return None                   # local accounts keep signing in locally (break-glass admin)
        info, err = ldap_authenticate(username, password, c)
        if not info:
            log.info("LDAP login for %s failed: %s", username, err)
            return None
        role = role_from_groups(info["groups"], "ldap")
        if not role:
            log.info("LDAP login for %s refused: no group maps to a VMap role", username)
            return None
        return upsert_user(info["username"], role, info["email"], info["first"], info["last"], source="ldap")

    def get_user(self, user_id):
        return User.objects.filter(pk=user_id).first()


# ------------------------------------------------------------------ OIDC
_disc = {}


def oidc_settings():
    return {"enabled": AppSetting.get("oidc_enabled", "0") == "1", "issuer": (AppSetting.get("oidc_issuer", "") or "").rstrip("/"),
            "client_id": AppSetting.get("oidc_client_id", ""), "client_secret": AppSetting.get("oidc_client_secret", ""),
            "scopes": AppSetting.get("oidc_scopes", "") or "openid email profile", "username_claim": AppSetting.get("oidc_username_claim", "") or "preferred_username",
            "groups_claim": AppSetting.get("oidc_groups_claim", "") or "groups", "label": AppSetting.get("oidc_button_label", "") or "Sign in with single sign-on"}


def discovery(issuer):
    hit = _disc.get(issuer)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    r = requests.get(issuer + "/.well-known/openid-configuration", timeout=8)
    r.raise_for_status()
    _disc[issuer] = (time.time(), r.json())
    return _disc[issuer][1]


def oidc_start(request, redirect_uri):
    c = oidc_settings()
    d = discovery(c["issuer"])
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    request.session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier, "redirect_uri": redirect_uri,
                               "next": request.GET.get("next") or "/"}
    from urllib.parse import urlencode
    q = {"response_type": "code", "client_id": c["client_id"], "redirect_uri": redirect_uri, "scope": c["scopes"], "state": state,
         "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"}
    return d["authorization_endpoint"] + ("&" if "?" in d["authorization_endpoint"] else "?") + urlencode(q)


def oidc_finish(request):
    """Returns (user, next_url, error)."""
    import jwt
    c = oidc_settings()
    sess = request.session.pop("oidc", None)
    if not sess or request.GET.get("state") != sess["state"]:
        return None, "/", "The sign-in session expired or did not match. Try again."
    if request.GET.get("error"):
        return None, "/", f"The identity provider said: {request.GET.get('error_description') or request.GET['error']}"
    d = discovery(c["issuer"])
    r = requests.post(d["token_endpoint"], timeout=10, data={
        "grant_type": "authorization_code", "code": request.GET.get("code", ""), "redirect_uri": sess["redirect_uri"],
        "client_id": c["client_id"], "client_secret": c["client_secret"], "code_verifier": sess["verifier"]})
    if r.status_code != 200:
        return None, "/", f"Token exchange failed ({r.status_code}): {r.text[:200]}"
    tok = r.json()
    idt = tok.get("id_token")
    if not idt:
        return None, "/", "The identity provider returned no ID token."
    try:
        key = jwt.PyJWKClient(d["jwks_uri"], timeout=8).get_signing_key_from_jwt(idt)
        claims = jwt.decode(idt, key.key, algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "PS256"], audience=c["client_id"],
                            issuer=d.get("issuer", c["issuer"]), leeway=60)
    except Exception as exc:  # noqa: BLE001
        return None, "/", f"The ID token is not valid: {exc}"
    if claims.get("nonce") != sess["nonce"]:
        return None, "/", "The ID token nonce does not match."
    if c["groups_claim"] not in claims and d.get("userinfo_endpoint") and tok.get("access_token"):
        try:
            ui = requests.get(d["userinfo_endpoint"], headers={"Authorization": f"Bearer {tok['access_token']}"}, timeout=8).json()
            claims = {**ui, **claims}
        except Exception:  # noqa: BLE001
            pass
    username = claims.get(c["username_claim"]) or claims.get("email") or claims.get("sub")
    groups = claims.get(c["groups_claim"]) or []
    if isinstance(groups, str):
        groups = [groups]
    role = role_from_groups(groups, "oidc")
    if not role:
        return None, "/", f"{username} signed in, but none of their groups is mapped to a VMap role. Ask an administrator."
    user = upsert_user(str(username)[:150], role, claims.get("email", ""), claims.get("given_name", ""), claims.get("family_name", ""), source="oidc")
    return user, sess.get("next") or "/", None
