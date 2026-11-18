from django.urls import path

from . import views

app_name = "reports"
urlpatterns = [path("capacity/", views.capacity, name="capacity"), path("summary/", views.summary, name="summary"),
               path("audit/", views.audit, name="audit")]
