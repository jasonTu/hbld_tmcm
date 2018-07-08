"Tmcm patrol views"
from django.conf import settings

from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes

from .helper import (
    do_get_basic_info, do_get_scan_detail, check_scan_detail_params
)
from .permissions import APIKeyPermission


@api_view(['GET'])
@permission_classes((APIKeyPermission, ))
def get_scan_detail(request):
    """Get scanned detail info of specific osce agent by time range."""
    if not check_scan_detail_params(request.query_params):
        return Response(
            {'reason': 'query parameters valid fail, please check carefully!'},
            status=status.HTTP_400_BAD_REQUEST
        )
    print(request.query_params)
    data = do_get_scan_detail(
        settings.G_CONF['mssql'], request.query_params['agent'],
        request.query_params['begin'], request.query_params['end']
    )
    return Response(data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes((APIKeyPermission, ))
def get_basic_info(request):
    """Get osce agent basic info."""
    data = do_get_basic_info(settings.G_CONF['mssql'])
    return Response(data, status=status.HTTP_200_OK)
