from datetime import datetime as dt

from django.db.models import Q
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    inline_serializer,
)
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from tacticalrmm.helpers import notify_error

from .models import Alert, AlertTemplate
from .permissions import AlertPerms, AlertTemplatePerms
from .serializers import (
    AlertSerializer,
    AlertTemplateRelationSerializer,
    AlertTemplateSerializer,
)
from .tasks import cache_agents_alert_template


class GetAddAlerts(APIView):
    permission_classes = [IsAuthenticated, AlertPerms]

    @extend_schema(
        tags=["alerts"],
        summary="List/filter alerts",
        description="Returns alerts the user is allowed to view. Behavior depends on the "
        "request body: supply `top` for the dashboard's top-N unresolved/unsnoozed alerts "
        "(with a total count), supply any of the filter keys to filter, or send an empty "
        "body to list all alerts.",
        request=inline_serializer(
            name="AlertsListFilterRequest",
            fields={
                "top": serializers.IntegerField(
                    required=False,
                    help_text="Return the top N unresolved/unsnoozed/unhidden alerts "
                    "plus a total count.",
                ),
                "timeFilter": serializers.IntegerField(
                    required=False, help_text="Number of days back to include."
                ),
                "clientFilter": serializers.ListField(
                    child=serializers.IntegerField(),
                    required=False,
                    help_text="List of client ids to filter by.",
                ),
                "severityFilter": serializers.ListField(
                    child=serializers.CharField(),
                    required=False,
                    help_text="List of severities to filter by.",
                ),
                "resolvedFilter": serializers.BooleanField(required=False),
                "snoozedFilter": serializers.BooleanField(required=False),
            },
        ),
        responses={
            200: OpenApiResponse(
                response=AlertSerializer(many=True),
                description="A list of alerts, or (when `top` is supplied) an object "
                "with `alerts_count` and `alerts`.",
            )
        },
        examples=[
            OpenApiExample(
                "Top 10 for dashboard",
                value={"top": 10},
                request_only=True,
            ),
            OpenApiExample(
                "Filter by client and severity",
                value={"clientFilter": [1, 2], "severityFilter": ["error"]},
                request_only=True,
            ),
        ],
    )
    def patch(self, request):
        # top 10 alerts for dashboard icon
        if "top" in request.data.keys():
            alerts = (
                Alert.objects.filter_by_role(request.user)  # type: ignore
                .filter(resolved=False, snoozed=False, hidden=False)
                .order_by("alert_time")[: int(request.data["top"])]
            )
            count = (
                Alert.objects.filter_by_role(request.user)  # type: ignore
                .filter(resolved=False, snoozed=False, hidden=False)
                .count()
            )
            return Response(
                {
                    "alerts_count": count,
                    "alerts": AlertSerializer(alerts, many=True).data,
                }
            )

        elif any(
            key
            in (
                "timeFilter",
                "clientFilter",
                "severityFilter",
                "resolvedFilter",
                "snoozedFilter",
            )
            for key in request.data.keys()
        ):
            clientFilter = Q()
            severityFilter = Q()
            timeFilter = Q()
            resolvedFilter = Q()
            snoozedFilter = Q()

            if (
                "snoozedFilter" in request.data.keys()
                and not request.data["snoozedFilter"]
            ):
                snoozedFilter = Q(snoozed=request.data["snoozedFilter"])

            if (
                "resolvedFilter" in request.data.keys()
                and not request.data["resolvedFilter"]
            ):
                resolvedFilter = Q(resolved=request.data["resolvedFilter"])

            if "clientFilter" in request.data.keys():
                from agents.models import Agent
                from clients.models import Client

                clients = Client.objects.filter(
                    pk__in=request.data["clientFilter"]
                ).values_list("id")
                agents = Agent.objects.filter(site__client_id__in=clients).values_list(
                    "id"
                )

                clientFilter = Q(agent__in=agents)

            if "severityFilter" in request.data.keys():
                severityFilter = Q(severity__in=request.data["severityFilter"])

            if "timeFilter" in request.data.keys():
                timeFilter = Q(
                    alert_time__lte=djangotime.make_aware(dt.today()),
                    alert_time__gt=djangotime.make_aware(dt.today())
                    - djangotime.timedelta(days=int(request.data["timeFilter"])),
                )

            alerts = (
                Alert.objects.filter_by_role(request.user)  # type: ignore
                .filter(clientFilter)
                .filter(severityFilter)
                .filter(resolvedFilter)
                .filter(snoozedFilter)
                .filter(timeFilter)
            )
            return Response(AlertSerializer(alerts, many=True).data)

        else:
            alerts = Alert.objects.filter_by_role(request.user)  # type: ignore
            return Response(AlertSerializer(alerts, many=True).data)

    @extend_schema(
        tags=["alerts"],
        summary="Create an alert",
        request=AlertSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request):
        serializer = AlertSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")


@extend_schema(
    tags=["alerts"],
    parameters=[
        OpenApiParameter("pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                         description="Alert primary key.")
    ],
)
class GetUpdateDeleteAlert(APIView):
    permission_classes = [IsAuthenticated, AlertPerms]

    @extend_schema(summary="Get a single alert", responses=AlertSerializer)
    def get(self, request, pk):
        alert = get_object_or_404(Alert, pk=pk)
        return Response(AlertSerializer(alert).data)

    @extend_schema(
        summary="Update an alert",
        description="Updates an alert. When `type` is supplied, performs a shortcut "
        "action: `resolve`, `snooze` (requires `snooze_days`), or `unsnooze`. Otherwise "
        "the request body is treated as a partial alert update.",
        request=inline_serializer(
            name="AlertsUpdateAlertRequest",
            fields={
                "type": serializers.ChoiceField(
                    choices=["resolve", "snooze", "unsnooze"], required=False
                ),
                "snooze_days": serializers.IntegerField(
                    required=False,
                    help_text="Number of days to snooze for. Required when type=snooze.",
                ),
            },
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
        examples=[
            OpenApiExample(
                "Snooze for 7 days",
                value={"type": "snooze", "snooze_days": 7},
                request_only=True,
            ),
        ],
    )
    def put(self, request, pk):
        alert = get_object_or_404(Alert, pk=pk)

        data = request.data

        if "type" in data.keys():
            if data["type"] == "resolve":
                data = {
                    "resolved": True,
                    "resolved_on": djangotime.now(),
                    "snoozed": False,
                }

                # unable to set snooze_until to none in serialzier
                alert.snooze_until = None
                alert.save()
            elif data["type"] == "snooze":
                if "snooze_days" in data.keys():
                    data = {
                        "snoozed": True,
                        "snooze_until": djangotime.now()
                        + djangotime.timedelta(days=int(data["snooze_days"])),
                    }
                else:
                    return notify_error(
                        "Missing 'snoozed_days' when trying to snooze alert"
                    )
            elif data["type"] == "unsnooze":
                data = {"snoozed": False}

                # unable to set snooze_until to none in serialzier
                alert.snooze_until = None
                alert.save()
            else:
                return notify_error("There was an error in the request data")

        serializer = AlertSerializer(instance=alert, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")

    @extend_schema(
        summary="Delete an alert",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        Alert.objects.get(pk=pk).delete()

        return Response("ok")


class BulkAlerts(APIView):
    permission_classes = [IsAuthenticated, AlertPerms]

    @extend_schema(
        tags=["alerts"],
        summary="Bulk alert action",
        description="Performs a bulk action on the given alert ids. `bulk_action` may be "
        "`resolve` or `snooze` (which requires `snooze_days`).",
        request=inline_serializer(
            name="AlertsBulkActionRequest",
            fields={
                "bulk_action": serializers.ChoiceField(choices=["resolve", "snooze"]),
                "alerts": serializers.ListField(
                    child=serializers.IntegerField(),
                    help_text="List of alert ids to act on.",
                ),
                "snooze_days": serializers.IntegerField(
                    required=False,
                    help_text="Number of days to snooze for. Required when "
                    "bulk_action=snooze.",
                ),
            },
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
        examples=[
            OpenApiExample(
                "Resolve several alerts",
                value={"bulk_action": "resolve", "alerts": [1, 2, 3]},
                request_only=True,
            ),
        ],
    )
    def post(self, request):
        if request.data["bulk_action"] == "resolve":
            Alert.objects.filter_by_role(request.user).filter(
                id__in=request.data["alerts"]
            ).update(
                resolved=True,
                resolved_on=djangotime.now(),
                snoozed=False,
                snooze_until=None,
            )
            return Response("ok")
        elif request.data["bulk_action"] == "snooze":
            if "snooze_days" in request.data.keys():
                Alert.objects.filter_by_role(request.user).filter(
                    id__in=request.data["alerts"]
                ).update(
                    snoozed=True,
                    snooze_until=djangotime.now()
                    + djangotime.timedelta(days=int(request.data["snooze_days"])),
                )
                return Response("ok")

        return notify_error("The request was invalid")


class GetAddAlertTemplates(APIView):
    permission_classes = [IsAuthenticated, AlertTemplatePerms]

    @extend_schema(
        tags=["alerts"],
        summary="List alert templates",
        responses=AlertTemplateSerializer(many=True),
    )
    def get(self, request):
        alert_templates = AlertTemplate.objects.all()
        return Response(AlertTemplateSerializer(alert_templates, many=True).data)

    @extend_schema(
        tags=["alerts"],
        summary="Create an alert template",
        request=AlertTemplateSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request):
        serializer = AlertTemplateSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # cache alert_template value on agents
        cache_agents_alert_template.delay()

        return Response("ok")


@extend_schema(
    tags=["alerts"],
    parameters=[
        OpenApiParameter("pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                         description="Alert template primary key.")
    ],
)
class GetUpdateDeleteAlertTemplate(APIView):
    permission_classes = [IsAuthenticated, AlertTemplatePerms]

    @extend_schema(summary="Get a single alert template", responses=AlertTemplateSerializer)
    def get(self, request, pk):
        alert_template = get_object_or_404(AlertTemplate, pk=pk)

        return Response(AlertTemplateSerializer(alert_template).data)

    @extend_schema(
        summary="Update an alert template",
        request=AlertTemplateSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request, pk):
        alert_template = get_object_or_404(AlertTemplate, pk=pk)

        serializer = AlertTemplateSerializer(
            instance=alert_template, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        # cache alert_template value on agents
        cache_agents_alert_template.delay()

        return Response("ok")

    @extend_schema(
        summary="Delete an alert template",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        get_object_or_404(AlertTemplate, pk=pk).delete()

        # cache alert_template value on agents
        cache_agents_alert_template.delay()

        return Response("ok")


@extend_schema(
    tags=["alerts"],
    parameters=[
        OpenApiParameter("pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                         description="Alert template primary key.")
    ],
)
class RelatedAlertTemplate(APIView):
    permission_classes = [IsAuthenticated, AlertTemplatePerms]

    @extend_schema(
        summary="Get alert template relations",
        description="Returns the alert template with its related policies, clients and "
        "sites expanded.",
        responses=AlertTemplateRelationSerializer,
    )
    def get(self, request, pk):
        alert_template = get_object_or_404(AlertTemplate, pk=pk)
        return Response(AlertTemplateRelationSerializer(alert_template).data)
