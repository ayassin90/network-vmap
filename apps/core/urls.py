from django.urls import path

from . import views

app_name = "core"
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("settings/", views.settings_page, name="settings"),
    path("search/", views.search, name="search"),
    path("healthz", views.healthz, name="healthz"),
]
