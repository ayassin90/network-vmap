from django.shortcuts import redirect

OPEN = ("/accounts/login", "/accounts/oidc/", "/static/", "/api/collector/", "/healthz", "/django-admin/login")
API = "/api/v1/"


class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith(API) and request.path != "/api/v1/tokens/":
            return self.get_response(request)          # token auth inside the API views
        if not request.user.is_authenticated and not request.path.startswith(OPEN):
            return redirect(f"/accounts/login/?next={request.path}")
        return self.get_response(request)
