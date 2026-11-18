import time

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.core.cache import cache
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from apps.core.models import AuditLog
from apps.core.permissions import role_required

from .models import User

MAX_FAILS, WINDOW = 8, 300


def login_view(request):
    nxt = request.GET.get("next") or request.POST.get("next") or "/"
    if not url_has_allowed_host_and_scheme(nxt, {request.get_host()}):
        nxt = "/"
    error = ""
    if request.method == "POST":
        from apps.core.permissions import client_ip
        ip = client_ip(request)
        key = f"login-fail:{ip}"
        fails = cache.get(key, 0)
        if fails >= MAX_FAILS:
            error = "Too many attempts. Wait five minutes and try again."
        else:
            user = authenticate(request, username=request.POST.get("username", ""), password=request.POST.get("password", ""))
            if user:
                cache.delete(key)
                login(request, user)
                AuditLog.log(user, "login", detail=ip)
                return redirect(nxt)
            cache.set(key, fails + 1, WINDOW)
            time.sleep(0.4)
            error = "That username and password do not match."
    from .sso import ldap_settings, oidc_settings
    oidc = oidc_settings()
    return render(request, "accounts/login.html", {"next": nxt, "error": error or request.session.pop("sso_error", ""),
                                                   "oidc": oidc if oidc["enabled"] and oidc["issuer"] else None,
                                                   "ldap": ldap_settings()["enabled"]})


def oidc_login(request):
    from .sso import oidc_settings, oidc_start
    if not oidc_settings()["enabled"]:
        return redirect("accounts:login")
    try:
        return redirect(oidc_start(request, request.build_absolute_uri("/accounts/oidc/callback/")))
    except Exception as exc:  # noqa: BLE001
        request.session["sso_error"] = f"Single sign-on is not reachable: {exc}"
        return redirect("accounts:login")


def oidc_callback(request):
    from .sso import oidc_finish
    try:
        user, nxt, err = oidc_finish(request)
    except Exception as exc:  # noqa: BLE001
        user, nxt, err = None, "/", f"Single sign-on failed: {exc}"
    if not user:
        request.session["sso_error"] = err
        return redirect("accounts:login")
    login(request, user, backend="django.contrib.auth.backends.ModelBackend")
    if not url_has_allowed_host_and_scheme(nxt, {request.get_host()}):
        nxt = "/"
    return redirect(nxt)


@require_POST
def logout_view(request):
    logout(request)
    return redirect("accounts:login")


@role_required("admin")
def users(request):
    if request.method == "POST":
        act = request.POST.get("action")
        if act == "create":
            u = request.POST.get("username", "").strip()
            pw = request.POST.get("password", "")
            if not u or len(pw) < 8:
                messages.error(request, "Give a username and a password of at least 8 characters.")
            elif User.objects.filter(username=u).exists():
                messages.error(request, "That username is taken.")
            else:
                User.objects.create_user(u, password=pw, role=request.POST.get("role", "viewer"), email=request.POST.get("email", ""))
                AuditLog.log(request, "user.create", u)
                messages.success(request, f"User {u} created.")
        elif act == "role":
            User.objects.filter(pk=request.POST.get("id")).exclude(pk=request.user.pk).update(role=request.POST.get("role"))
        elif act == "delete":
            User.objects.filter(pk=request.POST.get("id")).exclude(pk=request.user.pk).delete()
        return redirect("accounts:users")
    return render(request, "accounts/users.html", {"users": User.objects.order_by("username"), "roles": User.ROLES})
