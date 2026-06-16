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
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from logs.models import PendingAction
from tacticalrmm.constants import AGENT_DEFER, PAStatus


@extend_schema(
    tags=["apiv4"],
    parameters=[
        OpenApiParameter(
            "agentid",
            OpenApiTypes.STR,
            OpenApiParameter.PATH,
            description="Agent ID of the calling agent.",
        ),
        OpenApiParameter(
            "pk",
            OpenApiTypes.INT,
            OpenApiParameter.PATH,
            description="Primary key of the chocolatey install pending action.",
        ),
    ],
)
class ChocoResultV4(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Submit chocolatey install result (internal agent endpoint)",
        description="Internal agent callback endpoint. The agent posts the raw output "
        "of a chocolatey software install attempt; the matching pending action is "
        "parsed for success/duplicate markers, marked completed and its output stored.",
        request=inline_serializer(
            name="ApiV4ChocoResultRequest",
            fields={
                "results": serializers.CharField(
                    help_text="Raw chocolatey command output."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(
                OpenApiTypes.STR, description="Result recorded ('ok')."
            )
        },
        examples=[
            OpenApiExample(
                "Choco install output",
                value={
                    "results": "The install of googlechrome was successful. ... installed"
                },
                request_only=True,
            )
        ],
    )
    def patch(self, request, agentid, pk):
        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), user=request.user)
        action = get_object_or_404(PendingAction, agent=agent, pk=pk)

        results: str = request.data["results"]

        software_name = action.details["name"].lower()
        success = [
            "install",
            "of",
            software_name,
            "was",
            "successful",
            "installed",
        ]
        duplicate = [software_name, "already", "installed", "--force", "reinstall"]
        installed = False

        if all(x in results.lower() for x in success):
            installed = True
        elif all(x in results.lower() for x in duplicate):
            installed = True

        action.details["output"] = results
        action.details["installed"] = installed
        action.status = PAStatus.COMPLETED
        action.save(update_fields=["details", "status"])
        return Response("ok")
