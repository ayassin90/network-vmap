from django.urls import path

from . import views

app_name = "jobs"
urlpatterns = [
    path("", views.job_list, name="list"),
    path("<int:pk>/", views.job_detail, name="detail"),
    path("<int:pk>/cancel/", views.job_cancel, name="cancel"),
    path("collectors/", views.collectors, name="collectors"),
    path("collectors/<int:pk>/", views.collector, name="collector"),
]
