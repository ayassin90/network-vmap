from django.urls import path

from . import views

app_name = "checks"
urlpatterns = [
    path("findings/", views.findings, name="findings"),
    path("findings/<int:pk>/", views.finding_action, name="finding_action"),
    path("rerun/", views.rerun, name="rerun"),
    path("standards/", views.standards, name="standards"),
    path("standards/new/", views.standard_new, name="standard_new"),
    path("standards/<int:pk>/", views.standard, name="standard"),
    path("standards/<int:pk>/device/<int:device>/", views.compliance, name="compliance"),
]
