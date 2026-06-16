import asyncio
from typing import Any

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
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent, AgentHistory
from logs.models import AuditLog, PendingAction
from tacticalrmm.constants import AgentHistoryType, PAAction
from tacticalrmm.helpers import notify_error

from .models import ChocoSoftware, InstalledSoftware
from .permissions import SoftwarePerms, UninstallSoftwarePerms
from .serializers import InstalledSoftwareSerializer


@extend_schema(
    tags=["software"],
    summary="List available Chocolatey packages",
    description="Returns the most recently cached Chocolatey software catalog as a "
    "mapping of package name to package metadata. Returns an empty object if no "
    "catalog has been cached yet.",
    request=None,
    responses={
        200: OpenApiResponse(
            OpenApiTypes.OBJECT,
            description="Chocolatey package catalog keyed by package name.",
        )
    },
)
@api_view(["GET"])
def chocos(request):
    chocos = ChocoSoftware.objects.last()
    if not chocos:
        return Response({})

    return Response(chocos.chocos)


class GetSoftware(APIView):
    permission_classes = [IsAuthenticated, SoftwarePerms]

    # get software list
    @extend_schema(
        tags=["software"],
        summary="List installed software",
        description="If `agent_id` is supplied, returns the installed software record "
        "for that agent (or an empty list if none has been collected). Without "
        "`agent_id`, returns installed software for every agent the user can view.",
        parameters=[
            OpenApiParameter(
                "agent_id",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id. Omit to list software across all viewable agents.",
            )
        ],
        request=None,
        responses=InstalledSoftwareSerializer(many=True),
    )
    def get(self, request, agent_id=None):
        if agent_id:
            agent = get_object_or_404(Agent, agent_id=agent_id)

            try:
                software = InstalledSoftware.objects.filter(agent=agent).get()
                return Response(InstalledSoftwareSerializer(software).data)
            except Exception:
                return Response([])
        else:
            software = InstalledSoftware.objects.filter_by_role(request.user)  # type: ignore
            return Response(InstalledSoftwareSerializer(software, many=True).data)

    # software install
    @extend_schema(
        tags=["software"],
        summary="Install software via Chocolatey",
        description="Queues a Chocolatey install of the named package on the agent and "
        "dispatches the command over NATS. Not available for POSIX agents.",
        parameters=[
            OpenApiParameter(
                "agent_id",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id.",
            )
        ],
        request=inline_serializer(
            name="SoftwareInstallRequest",
            fields={
                "name": serializers.CharField(
                    help_text="Chocolatey package name to install."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(
                OpenApiTypes.STR, description="Confirmation message"
            )
        },
        examples=[
            OpenApiExample(
                "Install 7zip",
                value={"name": "7zip"},
                request_only=True,
            )
        ],
    )
    def post(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if agent.is_posix:
            return notify_error(f"Not available for {agent.plat}")

        name = request.data["name"]

        action = PendingAction.objects.create(
            agent=agent,
            action_type=PAAction.CHOCO_INSTALL,
            details={"name": name, "output": None, "installed": False},
        )

        nats_data = {
            "func": "installwithchoco",
            "choco_prog_name": name,
            "pending_action_pk": action.pk,
        }

        r = asyncio.run(agent.nats_cmd(nats_data, timeout=2))
        if r != "ok":
            action.delete()
            return notify_error("Unable to contact the agent")

        return Response(
            f"{name} will be installed shortly on {agent.hostname}. Check the Pending Actions menu to see the status/output"
        )

    # refresh software list
    @extend_schema(
        tags=["software"],
        summary="Refresh installed software list",
        description="Requests the current software inventory from the agent over NATS "
        "and stores it. Not available for POSIX agents.",
        parameters=[
            OpenApiParameter(
                "agent_id",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id.",
            )
        ],
        request=None,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")
        },
    )
    def put(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if agent.is_posix:
            return notify_error(f"Not available for {agent.plat}")

        r: Any = asyncio.run(agent.nats_cmd({"func": "softwarelist"}, timeout=15))
        if r in ("timeout", "natsdown"):
            return notify_error("Unable to contact the agent")

        if not InstalledSoftware.objects.filter(agent=agent).exists():
            InstalledSoftware(agent=agent, software=r).save()
        else:
            s = agent.installedsoftware_set.first()  # type: ignore
            s.software = r
            s.save(update_fields=["software"])

        return Response("ok")


@extend_schema(
    tags=["software"],
    parameters=[
        OpenApiParameter(
            "agent_id",
            OpenApiTypes.STR,
            OpenApiParameter.PATH,
            description="Agent id.",
        )
    ],
)
class UninstallSoftware(APIView):
    permission_classes = [IsAuthenticated, UninstallSoftwarePerms]

    @extend_schema(
        summary="Uninstall software",
        description="Runs the supplied uninstall command on the agent over NATS. The "
        "Tactical RMM agent itself cannot be uninstalled through this endpoint. Not "
        "available for POSIX agents.",
        request=inline_serializer(
            name="SoftwareUninstallRequest",
            fields={
                "name": serializers.CharField(
                    help_text="Display name of the software being uninstalled."
                ),
                "command": serializers.CharField(
                    help_text="Raw uninstall command to execute (run via cmd shell)."
                ),
                "timeout": serializers.IntegerField(
                    help_text="Command timeout in seconds."
                ),
                "run_as_user": serializers.BooleanField(
                    help_text="Whether to run the command as the logged-in user."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")
        },
        examples=[
            OpenApiExample(
                "Uninstall example",
                value={
                    "name": "7zip",
                    "command": "C:\\Program Files\\7-Zip\\Uninstall.exe /S",
                    "timeout": 300,
                    "run_as_user": False,
                },
                request_only=True,
            )
        ],
    )
    def post(self, request, agent_id):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if agent.is_posix:
            return notify_error(f"Not available for {agent.plat}")

        name = request.data["name"]
        uninstall_cmd = request.data["command"]

        if all(i in uninstall_cmd.lower() for i in ("tacticalagent", "unins")):
            return notify_error(
                "The Tactical RMM Agent cannot be uninstalled from here."
            )

        data = {
            "func": "rawcmd",
            "timeout": request.data["timeout"],
            "payload": {
                "command": uninstall_cmd,
                "shell": "cmd",
            },
            "run_as_user": request.data["run_as_user"],
        }

        hist = AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.CMD_RUN,
            command=uninstall_cmd,
            username=request.user.username[:50],
        )
        data["id"] = hist.pk

        AuditLog.audit_raw_command(
            username=request.user.username,
            agent=agent,
            cmd=uninstall_cmd,
            shell="cmd",
            debug_info={"ip": request._client_ip},
        )

        asyncio.run(agent.nats_cmd(data, wait=False))

        return Response(f"{name} will now be uninstalled on {agent.hostname}.")
