from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from .models import AuditLog, DebugLog, PendingAction


class AuditLogSerializer(serializers.ModelSerializer):
    entry_time = serializers.ReadOnlyField()
    ip_address = serializers.CharField(source="debug_info.ip", read_only=True)
    site = serializers.SerializerMethodField()

    @extend_schema_field(OpenApiTypes.OBJECT)
    def get_site(self, obj):
        from agents.models import Agent
        from clients.serializers import SiteMinimumSerializer

        if obj.agent_id and Agent.objects.filter(agent_id=obj.agent_id).exists():
            return SiteMinimumSerializer(
                Agent.objects.get(agent_id=obj.agent_id).site
            ).data

        return None

    class Meta:
        model = AuditLog
        fields = "__all__"


class PendingActionSerializer(serializers.ModelSerializer):
    hostname = serializers.ReadOnlyField(source="agent.hostname")
    client = serializers.CharField(source="agent.client.name", read_only=True)
    site = serializers.ReadOnlyField(source="agent.site.name")
    due = serializers.ReadOnlyField()
    description = serializers.ReadOnlyField()

    class Meta:
        model = PendingAction
        fields = "__all__"


class DebugLogSerializer(serializers.ModelSerializer):
    agent = serializers.ReadOnlyField(source="agent.hostname")
    entry_time = serializers.ReadOnlyField()

    class Meta:
        model = DebugLog
        fields = "__all__"
