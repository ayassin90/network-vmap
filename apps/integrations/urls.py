from django.urls import path

from . import views

app_name = "integrations"
urlpatterns = [path("netbox/", views.netbox, name="netbox"), path("runs/<int:pk>/", views.run, name="run")]
