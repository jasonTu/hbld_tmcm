"Tmcm patrol views"
from django.conf import settings

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes

from .helper import do_get_basic_info, do_get_scan_detail
from .permissions import APIKeyPermission


@api_view(['GET'])
@permission_classes((APIKeyPermission, ))
def get_scan_detail(request):
    """Get scanned detail info of specific osce agent by time range."""
    data = do_get_scan_detail(settings.G_CONF['mssql'])
    return Response(data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes((APIKeyPermission, ))
def get_basic_info(request):
    """Get osce agent basic info."""
    data = do_get_basic_info(settings.G_CONF['mssql'])
    return Response(data, status=status.HTTP_200_OK)
