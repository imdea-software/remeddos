from django.shortcuts import get_object_or_404
from django.conf import settings
from rest_framework.exceptions import PermissionDenied

from rest_framework import viewsets
from flowspec.models import (
    Route, MatchPort, ThenAction, FragmentType, MatchProtocol,
    MatchDscp)

from flowspec.serializers import (
    RouteSerializer,
    PortSerializer,
    ThenActionSerializer,
    FragmentTypeSerializer,
    MatchProtocolSerializer,
    MatchDscpSerializer)

from flowspec.validators import check_if_rule_exists
from rest_framework.response import Response



class PortViewSet(viewsets.ModelViewSet):
    queryset = MatchPort.objects.all()
    serializer_class = PortSerializer


class ThenActionViewSet(viewsets.ModelViewSet):
    queryset = ThenAction.objects.all()
    serializer_class = ThenActionSerializer


class FragmentTypeViewSet(viewsets.ModelViewSet):
    queryset = FragmentType.objects.all()
    serializer_class = FragmentTypeSerializer


class MatchProtocolViewSet(viewsets.ModelViewSet):
    queryset = MatchProtocol.objects.all()
    serializer_class = MatchProtocolSerializer


class MatchDscpViewSet(viewsets.ModelViewSet):
    queryset = MatchDscp.objects.all()
    serializer_class = MatchDscpSerializer
