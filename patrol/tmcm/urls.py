# coding: utf-8
"""URL mappings for tmcm patrol."""

from django.urls import path

from .views import get_scan_detail


urlpatterns = [
    path('v1/scandetail/', get_scan_detail),
]
