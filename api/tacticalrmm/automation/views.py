from django.shortcuts import get_object_or_404
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    OpenApiExample,
    OpenApiParameter,
    OpenApiResponse,
    extend_schema,
    inline_serializer,
)
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from autotasks.models import TaskResult
from checks.models import CheckResult
from clients.models import Client, Site
from tacticalrmm.permissions import _has_perm_on_client, _has_perm_on_site
from winupdate.models import WinUpdatePolicy
from winupdate.serializers import WinUpdatePolicySerializer
from django.db.models import Prefetch

from .models import Policy
from .permissions import AutomationPolicyPerms
from .serializers import (
    PolicyCheckStatusSerializer,
    PolicyOverviewSerializer,
    PolicyRelatedSerializer,
    PolicySerializer,
    PolicyTableSerializer,
    PolicyTaskStatusSerializer,
)


class GetAddPolicies(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    @extend_schema(
        tags=["automation"],
        summary="List all automation policies",
        description="Returns every automation policy with its excluded agents/sites/"
        "clients, related win update policies and agent counts.",
        responses=PolicyTableSerializer(many=True),
    )
    def get(self, request):
        policies = Policy.objects.select_related("alert_template").prefetch_related(
            "excluded_agents", "excluded_sites", "excluded_clients"
        )

        return Response(
            PolicyTableSerializer(
                policies, context={"user": request.user}, many=True
            ).data
        )

    @extend_schema(
        tags=["automation"],
        summary="Add a policy",
        description="Creates a new automation policy. Optionally supply `copyId` to "
        "clone the checks and tasks from an existing policy.",
        request=inline_serializer(
            name="AutomationAddPolicyRequest",
            fields={
                "name": serializers.CharField(),
                "desc": serializers.CharField(required=False),
                "active": serializers.BooleanField(required=False),
                "enforced": serializers.BooleanField(required=False),
                "copyId": serializers.IntegerField(
                    required=False,
                    help_text="Id of an existing policy to copy checks and tasks from.",
                ),
            },
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request):
        serializer = PolicySerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        policy = serializer.save()

        # copy checks and tasks from specified policy
        if "copyId" in request.data:
            copyPolicy = Policy.objects.get(pk=request.data["copyId"])

            checks = copyPolicy.policychecks.all()
            for check in checks:
                check.create_policy_check(policy=policy)

            tasks = copyPolicy.autotasks.all()
            for task in tasks:
                if not task.assigned_check:
                    task.create_policy_task(policy=policy)

        return Response("ok")


@extend_schema(
    tags=["automation"],
    parameters=[
        OpenApiParameter(
            "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
            description="Policy primary key.",
        )
    ],
)
class GetUpdateDeletePolicy(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    @extend_schema(
        summary="Get a single policy",
        responses=PolicySerializer,
    )
    def get(self, request, pk):
        policy = get_object_or_404(Policy, pk=pk)

        return Response(PolicySerializer(policy).data)

    @extend_schema(
        summary="Update a policy",
        request=PolicySerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request, pk):
        policy = get_object_or_404(Policy, pk=pk)

        serializer = PolicySerializer(instance=policy, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")

    @extend_schema(
        summary="Delete a policy",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        get_object_or_404(Policy, pk=pk).delete()

        return Response("ok")


@extend_schema(
    tags=["automation"],
    parameters=[
        OpenApiParameter(
            "task", OpenApiTypes.INT, OpenApiParameter.PATH,
            description="Policy automated task id.",
        )
    ],
)
class PolicyAutoTask(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    # get status of all tasks
    @extend_schema(
        summary="Get status of a policy task",
        description="Returns the task results for the given policy automated task "
        "across all affected agents.",
        responses=PolicyTaskStatusSerializer(many=True),
    )
    def get(self, request, task):
        tasks = TaskResult.objects.filter(task=task)
        return Response(PolicyTaskStatusSerializer(tasks, many=True).data)

    # bulk run win tasks associated with policy
    @extend_schema(
        summary="Run a policy task",
        description="Bulk runs the windows tasks associated with the policy on all "
        "affected agents.",
        request=None,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request, task):
        from .tasks import run_win_policy_autotasks_task

        run_win_policy_autotasks_task.delay(task=task)
        return Response("Affected agent tasks will run shortly")


@extend_schema(
    tags=["automation"],
    parameters=[
        OpenApiParameter(
            "check", OpenApiTypes.INT, OpenApiParameter.PATH,
            description="Policy check id.",
        )
    ],
)
class PolicyCheck(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    @extend_schema(
        summary="Get status of a policy check",
        description="Returns the check results for the given policy check across all "
        "affected agents.",
        responses=PolicyCheckStatusSerializer(many=True),
    )
    def get(self, request, check):
        checks = CheckResult.objects.filter(assigned_check=check)
        return Response(PolicyCheckStatusSerializer(checks, many=True).data)


class OverviewPolicy(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    @extend_schema(
        tags=["automation"],
        summary="Policy overview",
        description="Returns clients with their sites and the workstation/server "
        "policies assigned at each level.",
        responses=PolicyOverviewSerializer(many=True),
    )
    def get(self, request):
        clients = (
            Client.objects.filter_by_role(request.user)
            .select_related("workstation_policy", "server_policy")
            .prefetch_related(
                Prefetch(
                    "sites",
                    queryset=Site.objects.select_related(
                        "workstation_policy", "server_policy"
                    ),
                    to_attr="filtered_sites",
                )
            )
        )
        return Response(PolicyOverviewSerializer(clients, many=True).data)


class GetRelated(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    @extend_schema(
        tags=["automation"],
        summary="Get policy related objects",
        description="Returns the clients, sites and agents related to a policy "
        "(both workstation and server assignments).",
        parameters=[
            OpenApiParameter(
                "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                description="Policy primary key.",
            )
        ],
        responses=PolicyRelatedSerializer,
    )
    def get(self, request, pk):
        policy = (
            Policy.objects.filter(pk=pk)
            .prefetch_related(
                "workstation_clients",
                "workstation_sites",
                "server_clients",
                "server_sites",
            )
            .first()
        )

        return Response(
            PolicyRelatedSerializer(policy, context={"user": request.user}).data
        )


class UpdatePatchPolicy(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    # create new patch policy
    @extend_schema(
        tags=["automation"],
        summary="Create a patch policy",
        description="Creates a windows update (patch) policy attached to the policy "
        "referenced by `policy`.",
        request=inline_serializer(
            name="AutomationCreatePatchPolicyRequest",
            fields={
                "policy": serializers.IntegerField(
                    help_text="Id of the policy to attach the patch policy to."
                ),
            },
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
        examples=[
            OpenApiExample(
                "Create patch policy",
                value={"policy": 1, "critical": "approve", "important": "approve"},
                request_only=True,
            )
        ],
    )
    def post(self, request):
        policy = get_object_or_404(Policy, pk=request.data["policy"])

        serializer = WinUpdatePolicySerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.policy = policy
        serializer.save()

        return Response("ok")

    # update patch policy
    @extend_schema(
        tags=["automation"],
        summary="Update a patch policy",
        parameters=[
            OpenApiParameter(
                "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                description="WinUpdatePolicy primary key.",
            )
        ],
        request=WinUpdatePolicySerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request, pk):
        policy = get_object_or_404(WinUpdatePolicy, pk=pk)

        serializer = WinUpdatePolicySerializer(
            instance=policy, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("ok")

    # delete patch policy
    @extend_schema(
        tags=["automation"],
        summary="Delete a patch policy",
        parameters=[
            OpenApiParameter(
                "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                description="WinUpdatePolicy primary key.",
            )
        ],
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        get_object_or_404(WinUpdatePolicy, pk=pk).delete()

        return Response("ok")


class ResetPatchPolicy(APIView):
    permission_classes = [IsAuthenticated, AutomationPolicyPerms]

    # bulk reset agent patch policy
    @extend_schema(
        tags=["automation"],
        summary="Reset agent patch policies",
        description="Bulk resets the windows update policy on agents back to 'inherit'. "
        "Scope to a client or site by supplying `client` or `site`; if neither is "
        "given, all agents the user can access are reset.",
        request=inline_serializer(
            name="AutomationResetPatchPolicyRequest",
            fields={
                "client": serializers.IntegerField(
                    required=False, help_text="Client id to scope the reset to."
                ),
                "site": serializers.IntegerField(
                    required=False, help_text="Site id to scope the reset to."
                ),
            },
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request):
        if "client" in request.data:
            if not _has_perm_on_client(request.user, request.data["client"]):
                raise PermissionDenied()

            agents = (
                Agent.objects.filter_by_role(request.user)  # type: ignore
                .prefetch_related("winupdatepolicy")
                .filter(site__client_id=request.data["client"])
            )
        elif "site" in request.data:
            if not _has_perm_on_site(request.user, request.data["site"]):
                raise PermissionDenied()

            agents = (
                Agent.objects.filter_by_role(request.user)  # type: ignore
                .prefetch_related("winupdatepolicy")
                .filter(site_id=request.data["site"])
            )
        else:
            agents = (
                Agent.objects.filter_by_role(request.user)  # type: ignore
                .prefetch_related("winupdatepolicy")
                .only("pk")
            )

        for agent in agents:
            winupdatepolicy = agent.winupdatepolicy.get()
            winupdatepolicy.critical = "inherit"
            winupdatepolicy.important = "inherit"
            winupdatepolicy.moderate = "inherit"
            winupdatepolicy.low = "inherit"
            winupdatepolicy.other = "inherit"
            winupdatepolicy.run_time_frequency = "inherit"
            winupdatepolicy.reboot_after_install = "inherit"
            winupdatepolicy.reprocess_failed_inherit = True
            winupdatepolicy.save(
                update_fields=[
                    "critical",
                    "important",
                    "moderate",
                    "low",
                    "other",
                    "run_time_frequency",
                    "reboot_after_install",
                    "reprocess_failed_inherit",
                ]
            )

        return Response("The patch policy on the affected agents has been reset.")
