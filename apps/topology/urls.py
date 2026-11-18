from django.urls import path

from . import views

app_name = "topology"
urlpatterns = [
    path("l2/", views.l2, name="l2"),
    path("l3/", views.l3, name="l3"),
    path("path/", views.path_view, name="path"),
    path("data/<str:kind>/", views.data, name="data"),
    path("layout/save/", views.save, name="save"),
    path("layout/<int:pk>/delete/", views.delete, name="delete"),
]
