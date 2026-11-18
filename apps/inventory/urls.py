from django.urls import path

from . import views

app_name = "inventory"
urlpatterns = [
    path("", views.device_list, name="list"),
    path("add/", views.device_add, name="add"),
    path("add-many/", views.bulk_add, name="bulk_add"),
    path("bulk/", views.bulk, name="bulk"),
    path("interfaces/", views.interfaces, name="interfaces"),
    path("routes/", views.routes, name="routes"),
    path("discovery/", views.discovery, name="discovery"),
    path("discovery/<int:pk>/", views.discovery_detail, name="discovery_detail"),
    path("setup/", views.setup, name="setup"),
    path("endpoints/", views.endpoints, name="endpoints"),
    path("endpoints/<int:pk>/", views.endpoint, name="endpoint"),
    path("spanning-tree/", views.stp, name="stp"),
    path("vlans/", views.vlans, name="vlans"),
    path("platforms/", views.platforms, name="platforms"),
    path("platforms/<str:key>/", views.platform, name="platform"),
    path("<int:pk>/", views.device_detail, name="detail"),
    path("<int:pk>/edit/", views.device_edit, name="edit"),
    path("<int:pk>/action/", views.device_action, name="action"),
    path("<int:pk>/config/<int:snap>/", views.config_view, name="config"),
    path("<int:pk>/if/<int:ipk>/", views.interface_detail, name="interface"),
]
