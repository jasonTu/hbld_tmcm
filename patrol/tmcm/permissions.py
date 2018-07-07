"""APIKey permissions."""
import hashlib

from django.conf import settings
from rest_framework import permissions


class APIKeyPermission(permissions.BasePermission):
    """API key permission."""

    def has_permission(self, request, view):
        must_key = ['app_key', 'sign', 'timestamp']
        for key in must_key:
            if key not in request.query_params:
                return False
        keys = list(request.query_params.keys())
        keys.remove('sign')
        keys.sort()
        concact_values = settings.G_CONF['apikey']['sign_key']
        for key in keys:
            concact_values += key + request.query_params[key]
        print(concact_values)
        print(request.query_params['sign'])
        print(hashlib.sha1(concact_values.encode()).hexdigest())
        return hashlib.sha1(concact_values.encode()).hexdigest() == request.query_params['sign']
