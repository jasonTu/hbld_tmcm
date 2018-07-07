from django.conf import settings

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, permission_classes

from .helper import MssqlUtil


@api_view(['GET'])
@permission_classes((AllowAny, ))
def get_scan_detail(request):
    """Get scanned detail info of specific osce agent by time range."""
    with MssqlUtil('192.168.1.192', 'sa', 'puyacn#1..', 'db_ControlManager') as db:
        data = db.exc_query('select * from tb_EntityInfo')
        print(data)
    return Response(status=status.HTTP_200_OK)
