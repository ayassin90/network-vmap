from django.urls import path

from . import views

app_name = "help"
urlpatterns = [
    path("", views.index, name="index"),
    path("<slug:slug>/", views.topic, name="topic"),
    path("<slug:slug>/panel/", views.panel, name="panel"),
]
