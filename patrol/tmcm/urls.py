# coding: utf-8
"""URL mappings for tmcm patrol."""

from django.urls import path

from .views import get_scan_detail, get_basic_info


urlpatterns = [
    path('v1/scandetail/', get_scan_detail),
    path('v1/basicinfo/', get_basic_info),
]
