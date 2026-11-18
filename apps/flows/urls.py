from django.urls import path

from . import views

app_name = "flows"
urlpatterns = [path("", views.traffic, name="traffic")]
