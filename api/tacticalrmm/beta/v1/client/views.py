from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from clients.models import Client
from clients.permissions import ClientsPerms
from beta.v1.pagination import StandardResultsSetPagination
from ..serializers import ClientSerializer


class ClientViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated, ClientsPerms]
    queryset = Client.objects.all()
    pagination_class = StandardResultsSetPagination
    serializer_class = ClientSerializer
    http_method_names = ["get", "put"]
