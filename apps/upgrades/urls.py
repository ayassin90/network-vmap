from django.urls import path

from . import views

app_name = "upgrades"
urlpatterns = [
    path("", views.plan_list, name="list"),
    path("images/", views.images, name="images"),
    path("new/", views.plan_new, name="new"),
    path("<int:pk>/", views.plan, name="plan"),
]
