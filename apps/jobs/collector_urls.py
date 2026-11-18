from django.urls import path

from . import collector_api

urlpatterns = [
    path("poll/", collector_api.poll),
    path("result/<int:pk>/", collector_api.result),
]
