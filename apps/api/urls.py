from django.urls import path

from . import views

app_name = "api"
urlpatterns = [
    path("", views.index), path("devices/", views.devices), path("devices/<int:pk>/", views.device),
    path("devices/<int:pk>/interfaces/", views.device_interfaces), path("devices/<int:pk>/config/", views.device_config),
    path("devices/<int:pk>/collect/", views.device_collect), path("endpoints/", views.endpoints), path("findings/", views.findings),
    path("alerts/", views.alerts), path("alerts/<int:pk>/ack/", views.alert_ack), path("routes/lookup/", views.route_lookup),
    path("path/", views.path), path("tokens/", views.tokens, name="tokens"),
]
