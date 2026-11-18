from django.urls import path

from . import views

app_name = "lifecycle"
urlpatterns = [path("", views.overview, name="overview")]
