from django.urls import path

from . import views

app_name = "changes"
urlpatterns = [
    path("", views.change_list, name="list"),
    path("new/", views.change_new, name="new"),
    path("<int:pk>/", views.change_detail, name="detail"),
    path("port/<int:ipk>/", views.port_action, name="port"),
    path("templates/", views.templates, name="templates"),
    path("templates/new/", views.template_edit, name="template_new"),
    path("templates/<int:pk>/", views.template_edit, name="template"),
]
