import asyncio
from typing import Dict, Tuple, Union

from django.conf import settings
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
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from tacticalrmm.helpers import notify_error

from .permissions import WinSvcsPerms


def process_nats_response(data: Union[str, Dict]) -> Tuple[bool, bool, str]:
    natserror = isinstance(data, str)
    success = (
        data["success"]
        if isinstance(data, dict) and isinstance(data["success"], bool)
        else False
    )
    errormsg = (
        data["errormsg"]
        if isinstance(data, dict) and isinstance(data["errormsg"], str)
        else "timeout"
    )

    return success, natserror, errormsg


@extend_schema(
    tags=["services"],
    parameters=[
        OpenApiParameter(
            "agent_id",
            OpenApiTypes.STR,
            OpenApiParameter.PATH,
            description="The agent_id of the agent.",
        )
    ],
)
class GetServices(APIView):
    permission_classes = [IsAuthenticated, WinSvcsPerms]

    @extend_schema(
        summary="List agent Windows services",
        description="Queries the agent over NATS for its current list of Windows "
        "services, stores the result on the agent and returns it. Returns an error "
        "if the agent cannot be contacted.",
        request=None,
        responses={
            200: OpenApiResponse(
                OpenApiTypes.OBJECT,
                description="List of Windows services reported by the agent.",
            ),
            400: OpenApiResponse(
                OpenApiTypes.STR, description="Unable to contact the agent."
            ),
        },
    )
    def get(self, request, agent_id):
        if getattr(settings, "DEMO", False):
            from tacticalrmm.demo_views import demo_get_services

            return demo_get_services()

        agent = get_object_or_404(Agent, agent_id=agent_id)
        r = asyncio.run(agent.nats_cmd(data={"func": "winservices"}, timeout=10))

        if r in ("timeout", "natsdown"):
            return notify_error("Unable to contact the agent")

        agent.services = r
        agent.save(update_fields=["services"])
        return Response(agent.services)


@extend_schema(
    tags=["services"],
    parameters=[
        OpenApiParameter(
            "agent_id",
            OpenApiTypes.STR,
            OpenApiParameter.PATH,
            description="The agent_id of the agent.",
        ),
        OpenApiParameter(
            "svcname",
            OpenApiTypes.STR,
            OpenApiParameter.PATH,
            description="The name of the Windows service.",
        ),
    ],
)
class GetEditActionService(APIView):
    permission_classes = [IsAuthenticated, WinSvcsPerms]

    # get agent service details
    @extend_schema(
        summary="Get Windows service details",
        description="Queries the agent over NATS for the details of a single Windows "
        "service by name.",
        request=None,
        responses={
            200: OpenApiResponse(
                OpenApiTypes.OBJECT,
                description="Details of the requested Windows service.",
            ),
            400: OpenApiResponse(
                OpenApiTypes.STR, description="Unable to contact the agent."
            ),
        },
    )
    def get(self, request, agent_id, svcname):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        data = {"func": "winsvcdetail", "payload": {"name": svcname}}
        r = asyncio.run(agent.nats_cmd(data, timeout=10))
        if r == "timeout":
            return notify_error("Unable to contact the agent")

        return Response(r)

    # win service action
    @extend_schema(
        summary="Perform a Windows service action",
        description="Performs a start, stop or restart action on the given Windows "
        "service via the agent over NATS. Not available on POSIX agents.",
        request=inline_serializer(
            name="ServicesServiceActionRequest",
            fields={
                "sv_action": serializers.ChoiceField(
                    choices=["start", "stop", "restart"]
                ),
            },
        ),
        responses={
            200: OpenApiResponse(
                OpenApiTypes.STR, description="The service action succeeded."
            ),
            400: OpenApiResponse(
                OpenApiTypes.STR,
                description="The action failed or the agent could not be contacted.",
            ),
        },
        examples=[
            OpenApiExample(
                "Restart a service",
                value={"sv_action": "restart"},
                request_only=True,
            )
        ],
    )
    def post(self, request, agent_id, svcname):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        if agent.is_posix:
            return notify_error("Please use 'Recover Connection' instead.")
        action = request.data["sv_action"]
        data = {
            "func": "winsvcaction",
            "payload": {
                "name": svcname,
            },
        }
        # response struct from agent: {success: bool, errormsg: string}
        if action == "restart":
            data["payload"]["action"] = "stop"
            r = asyncio.run(agent.nats_cmd(data, timeout=32))
            success, natserror, errormsg = process_nats_response(r)

            if errormsg == "timeout" or natserror:
                return notify_error("Unable to contact the agent")
            elif not success and errormsg:
                return notify_error(errormsg)
            elif success:
                data["payload"]["action"] = "start"
                r = asyncio.run(agent.nats_cmd(data, timeout=32))
                success, natserror, errormsg = process_nats_response(r)

                if errormsg == "timeout" or natserror:
                    return notify_error("Unable to contact the agent")
                elif not success and errormsg:
                    return notify_error(errormsg)
                elif success:
                    return Response("The service was restarted successfully")
        else:
            data["payload"]["action"] = action
            r = asyncio.run(agent.nats_cmd(data, timeout=32))
            success, natserror, errormsg = process_nats_response(r)

            if errormsg == "timeout" or natserror:
                return notify_error("Unable to contact the agent")
            elif not success and errormsg:
                return notify_error(errormsg)
            elif success:
                return Response(
                    f"The service was {'started' if action == 'start' else 'stopped'} successfully"
                )

        return notify_error("Something went wrong")

    # edit win service
    @extend_schema(
        summary="Edit a Windows service start type",
        description="Updates the start type of the given Windows service via the "
        "agent over NATS.",
        request=inline_serializer(
            name="ServicesEditServiceRequest",
            fields={
                "startType": serializers.CharField(
                    help_text="The new start type, e.g. auto, manual, disabled."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(
                OpenApiTypes.STR,
                description="The service start type was updated successfully.",
            ),
            400: OpenApiResponse(
                OpenApiTypes.STR,
                description="The update failed or the agent could not be contacted.",
            ),
        },
    )
    def put(self, request, agent_id, svcname):
        agent = get_object_or_404(Agent, agent_id=agent_id)
        data = {
            "func": "editwinsvc",
            "payload": {
                "name": svcname,
                "startType": request.data["startType"],
            },
        }

        r = asyncio.run(agent.nats_cmd(data, timeout=10))
        success, natserror, errormsg = process_nats_response(r)
        # response struct from agent: {success: bool, errormsg: string}
        if r == "timeout" or natserror:
            return notify_error("Unable to contact the agent")
        elif not success and errormsg:
            return notify_error(errormsg)
        elif success:
            return Response("The service start type was updated successfully")

        return notify_error("Something went wrong")
