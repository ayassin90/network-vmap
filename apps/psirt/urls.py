from django.urls import path

from . import views

app_name = "psirt"
urlpatterns = [
    path("", views.advisory_list, name="list"),
    path("sync/", views.sync, name="sync"),
    path("<int:pk>/", views.advisory_detail, name="detail"),
    path("hit/<int:pk>/", views.hit_action, name="hit"),
]
