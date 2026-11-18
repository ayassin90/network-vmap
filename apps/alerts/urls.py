from django.urls import path

from . import views

app_name = "alerts"
urlpatterns = [
    path("", views.alert_list, name="list"),
    path("bulk/", views.alert_bulk, name="bulk"),
    path("rules/", views.rules, name="rules"),
    path("maintenance/", views.maintenance, name="maintenance"),
    path("<int:pk>/", views.alert_detail, name="detail"),
    path("cases/", views.cases, name="cases"),
    path("cases/new/", views.case_new, name="case_new"),
    path("cases/<int:pk>/", views.case, name="case"),
]
