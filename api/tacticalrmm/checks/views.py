import asyncio
from datetime import datetime as dt

from django.db.models import Prefetch, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone as djangotime
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    inline_serializer,
)
from rest_framework import serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from alerts.models import Alert
from automation.models import Policy
from tacticalrmm.constants import AGENT_DEFER, CheckStatus, CheckType
from tacticalrmm.exceptions import NatsDown
from tacticalrmm.helpers import notify_error
from tacticalrmm.nats_utils import abulk_nats_command
from tacticalrmm.permissions import _has_perm_on_agent

from .models import Check, CheckHistory, CheckResult
from .permissions import BulkRunChecksPerms, ChecksPerms, RunChecksPerms
from .serializers import CheckHistorySerializer, CheckSerializer


class GetAddChecks(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    @extend_schema(
        tags=["checks"],
        summary="List checks",
        description="Returns checks the authenticated user is allowed to view. When an "
        "agent_id or policy id is supplied via the URL, returns the checks for that agent "
        "(including policy-inherited checks) or policy respectively.",
        parameters=[
            OpenApiParameter(
                "agent_id", OpenApiTypes.STR, OpenApiParameter.PATH,
                required=False, description="Agent id to list checks for."
            ),
            OpenApiParameter(
                "policy", OpenApiTypes.INT, OpenApiParameter.PATH,
                required=False, description="Policy id to list checks for."
            ),
        ],
        responses=CheckSerializer(many=True),
    )
    def get(self, request, agent_id=None, policy=None):
        if agent_id:
            agent = get_object_or_404(Agent, agent_id=agent_id)
            checks = agent.get_checks_with_policies()
        elif policy:
            policy = get_object_or_404(Policy, id=policy)
            checks = Check.objects.filter(policy=policy)
        else:
            checks = Check.objects.filter_by_role(request.user)  # type: ignore
        return Response(CheckSerializer(checks, many=True).data)

    @extend_schema(
        tags=["checks"],
        summary="Add a check",
        description="Creates a check on an agent or policy. Pass `agent` as an agent id "
        "(resolved to the agent's pk server-side) to attach the check to an agent.",
        request=CheckSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request):
        data = request.data.copy()
        # Determine if adding check to Agent and replace agent_id with pk
        if "agent" in data.keys():
            agent = get_object_or_404(Agent, agent_id=data["agent"])
            if not _has_perm_on_agent(request.user, agent.agent_id):
                raise PermissionDenied()

            data["agent"] = agent.pk

        # set event id to 0 if wildcard because it needs to be an integer field for db
        # will be ignored anyway by the agent when doing wildcard check
        if data["check_type"] == CheckType.EVENT_LOG and data["event_id_is_wildcard"]:
            data["event_id"] = 0

        serializer = CheckSerializer(data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        new_check = serializer.save()

        return Response(f"{new_check.readable_desc} was added!")


@extend_schema(tags=["checks"], parameters=[
    OpenApiParameter("pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                     description="Check primary key.")
])
class GetUpdateDeleteCheck(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    @extend_schema(
        summary="Get a single check",
        responses=CheckSerializer,
    )
    def get(self, request, pk):
        check = get_object_or_404(Check, pk=pk)
        if check.agent and not _has_perm_on_agent(request.user, check.agent.agent_id):
            raise PermissionDenied()

        return Response(CheckSerializer(check).data)

    @extend_schema(
        summary="Update a check",
        description="Edits a check. Non-editable fields are ignored if supplied.",
        request=CheckSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request, pk):
        check = get_object_or_404(Check, pk=pk)

        data = request.data.copy()

        if check.agent and not _has_perm_on_agent(request.user, check.agent.agent_id):
            raise PermissionDenied()

        # remove fields that should not be changed when editing a check from the frontend
        [data.pop(i) for i in Check.non_editable_fields() if i in data.keys()]

        # set event id to 0 if wildcard because it needs to be an integer field for db
        # will be ignored anyway by the agent when doing wildcard check
        if check.check_type == CheckType.EVENT_LOG:
            try:
                data["event_id_is_wildcard"]
            except KeyError:
                pass
            else:
                if data["event_id_is_wildcard"]:
                    data["event_id"] = 0

        serializer = CheckSerializer(instance=check, data=data, partial=True)
        serializer.is_valid(raise_exception=True)
        check = serializer.save()

        return Response(f"{check.readable_desc} was edited!")

    @extend_schema(
        summary="Delete a check",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        check = get_object_or_404(Check, pk=pk)

        if check.agent and not _has_perm_on_agent(request.user, check.agent.agent_id):
            raise PermissionDenied()

        check.delete()

        return Response(f"{check.readable_desc} was deleted!")


class ResetCheck(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    @extend_schema(
        tags=["checks"],
        summary="Reset a check result status",
        description="Resets the status of a single check result to passing and resolves "
        "any open alert for it.",
        parameters=[
            OpenApiParameter("pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                             description="CheckResult primary key.")
        ],
        request=None,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request, pk):
        result = get_object_or_404(CheckResult, pk=pk)

        if result.agent and not _has_perm_on_agent(request.user, result.agent.agent_id):
            raise PermissionDenied()

        result.status = CheckStatus.PASSING
        result.save()

        # resolve any alerts that are open
        if alert := Alert.create_or_return_check_alert(
            result.assigned_check, agent=result.agent, skip_create=True
        ):
            alert.resolve()

        return Response("The check status was reset")


class ResetAllChecksStatus(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    @extend_schema(
        tags=["checks"],
        summary="Reset all check statuses for an agent",
        description="Resets every check result for the given agent to passing and "
        "resolves any open alerts.",
        parameters=[
            OpenApiParameter("agent_id", OpenApiTypes.STR, OpenApiParameter.PATH,
                             description="Agent id.")
        ],
        request=None,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request, agent_id):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER)
            .select_related(
                "policy",
                "policy__alert_template",
                "alert_template",
            )
            .prefetch_related(
                Prefetch(
                    "checkresults",
                    queryset=CheckResult.objects.select_related("assigned_check"),
                ),
                "agentchecks",
            ),
            agent_id=agent_id,
        )

        if not _has_perm_on_agent(request.user, agent.agent_id):
            raise PermissionDenied()

        for check in agent.get_checks_with_policies():
            try:
                result = check.check_result
                result.status = CheckStatus.PASSING
                result.save()
                if alert := Alert.create_or_return_check_alert(
                    result.assigned_check, agent=agent, skip_create=True
                ):
                    alert.resolve()
            except:
                # check hasn't run yet, no check result entry
                continue

        return Response("All checks status were reset")


class GetCheckHistory(APIView):
    permission_classes = [IsAuthenticated, ChecksPerms]

    @extend_schema(
        tags=["checks"],
        summary="Get check history",
        description="Returns historical check result data points for a check result, "
        "optionally restricted to the last N days via `timeFilter` (0 = all history).",
        parameters=[
            OpenApiParameter("pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                             description="CheckResult primary key.")
        ],
        request=inline_serializer(
            name="ChecksGetCheckHistoryRequest",
            fields={
                "timeFilter": serializers.IntegerField(
                    required=False,
                    help_text="Number of days of history to return; 0 returns all.",
                ),
            },
        ),
        responses=CheckHistorySerializer(many=True),
    )
    def patch(self, request, pk):
        result = get_object_or_404(CheckResult, pk=pk)

        if result.agent and not _has_perm_on_agent(request.user, result.agent.agent_id):
            raise PermissionDenied()

        timeFilter = Q()

        if "timeFilter" in request.data:
            if request.data["timeFilter"] != 0:
                timeFilter = Q(
                    x__lte=djangotime.make_aware(dt.today()),
                    x__gt=djangotime.make_aware(dt.today())
                    - djangotime.timedelta(days=request.data["timeFilter"]),
                )

        check_history = (
            CheckHistory.objects.filter(
                check_id=result.assigned_check.id, agent_id=result.agent.agent_id
            )
            .filter(timeFilter)
            .order_by("-x")
        )

        return Response(CheckHistorySerializer(check_history, many=True).data)


@extend_schema(
    tags=["checks"],
    summary="Run checks on an agent",
    description="Triggers all checks to run immediately on the specified agent via NATS.",
    parameters=[
        OpenApiParameter("agent_id", OpenApiTypes.STR, OpenApiParameter.PATH,
                         description="Agent id.")
    ],
    request=None,
    responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated, RunChecksPerms])
def run_checks(request, agent_id):
    agent = get_object_or_404(Agent, agent_id=agent_id)

    r = asyncio.run(agent.nats_cmd({"func": "runchecks"}, timeout=15))
    if r == "busy":
        return notify_error(f"Checks are already running on {agent.hostname}")
    elif r == "ok":
        return Response(f"Checks will now be run on {agent.hostname}")

    return notify_error("Unable to contact the agent")


@extend_schema(
    tags=["checks"],
    summary="Bulk run checks for a client or site",
    description="Triggers all checks to run on every agent under the given client or "
    "site via NATS.",
    parameters=[
        OpenApiParameter(
            "target", OpenApiTypes.STR, OpenApiParameter.PATH,
            enum=["client", "site"],
            description="Whether `pk` refers to a client or a site.",
        ),
        OpenApiParameter("pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                         description="Client or site primary key."),
    ],
    request=None,
    responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
)
@api_view(["POST"])
@permission_classes([IsAuthenticated, BulkRunChecksPerms])
def bulk_run_checks(request, target, pk):
    q = Q()
    match target:
        case "client":
            q = Q(site__client__id=pk)
        case "site":
            q = Q(site__id=pk)

    agent_ids = list(
        Agent.objects.only("agent_id", "site")
        .filter(q)
        .values_list("agent_id", flat=True)
    )

    if not agent_ids:
        return notify_error("No agents matched query")

    payload = {"func": "runchecks"}
    items = [(agent_id, payload) for agent_id in agent_ids]

    try:
        asyncio.run(abulk_nats_command(items=items))
    except NatsDown as e:
        return notify_error(str(e))

    ret = f"Checks will now be run on {len(agent_ids)} agents"
    return Response(ret)
