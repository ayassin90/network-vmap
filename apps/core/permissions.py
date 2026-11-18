"""Three roles: viewer (read only), operator (run jobs, work alerts and cases), admin (everything, including settings and users)."""
from functools import wraps

from django.contrib import messages
from django.shortcuts import redirect

RANK = {"viewer": 0, "operator": 1, "admin": 2}


def has_role(user, role):
    if not user.is_authenticated:
        return False
    if user.is_superuser:
        return True
    return RANK.get(getattr(user, "role", "viewer"), 0) >= RANK[role]


def role_required(role):
    def deco(view):
        @wraps(view)
        def wrapper(request, *a, **kw):
            if not has_role(request.user, role):
                messages.error(request, f"You need the {role} role to do that.")
                return redirect(request.META.get("HTTP_REFERER") or "core:dashboard")
            return view(request, *a, **kw)
        return wrapper
    return deco


def client_ip(request):
    """The user's address: X-Real-IP from VMap's own nginx when VMAP_BEHIND_PROXY is set, else the socket peer."""
    from django.conf import settings
    if settings.VMAP_BEHIND_PROXY:
        real = request.META.get("HTTP_X_REAL_IP", "").strip()
        if real:
            return real[:60]
    return request.META.get("REMOTE_ADDR", "")[:60]
