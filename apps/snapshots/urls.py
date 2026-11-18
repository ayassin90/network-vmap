from django.urls import path

from . import views

app_name = "snapshots"
urlpatterns = [path("", views.index, name="index"), path("compare/", views.compare, name="compare"), path("<int:pk>/", views.detail, name="detail")]
