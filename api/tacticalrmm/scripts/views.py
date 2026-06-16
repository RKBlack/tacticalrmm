import asyncio

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
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.permissions import RunScriptPerms
from core.utils import clear_entire_cache
from logs.models import AuditLog
from tacticalrmm.constants import ScriptShell, ScriptType
from tacticalrmm.helpers import notify_error

from .models import Script, ScriptSnippet
from .permissions import ScriptsPerms
from .serializers import (
    ScriptSerializer,
    ScriptSnippetSerializer,
    ScriptTableSerializer,
)


class GetAddScripts(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    @extend_schema(
        tags=["scripts"],
        summary="List all scripts",
        description="Returns all scripts for the scripts table. By default community "
        "(built-in) scripts are included and hidden scripts are excluded; control this "
        "with the showCommunityScripts and showHiddenScripts query parameters.",
        parameters=[
            OpenApiParameter(
                "showCommunityScripts",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                required=False,
                description="Include community/built-in scripts. Defaults to true. "
                "Set to 'false' to return only user-defined scripts.",
            ),
            OpenApiParameter(
                "showHiddenScripts",
                OpenApiTypes.BOOL,
                OpenApiParameter.QUERY,
                required=False,
                description="Include hidden scripts. Defaults to false. "
                "Set to 'true' to include hidden scripts.",
            ),
        ],
        responses=ScriptTableSerializer(many=True),
    )
    def get(self, request):
        showCommunityScripts = request.GET.get("showCommunityScripts", True)
        showHiddenScripts = request.GET.get("showHiddenScripts", False)

        if not showCommunityScripts or showCommunityScripts == "false":
            scripts = Script.objects.filter(script_type=ScriptType.USER_DEFINED)
        else:
            scripts = Script.objects.all()

        if not showHiddenScripts or showHiddenScripts != "true":
            scripts = scripts.filter(hidden=False)

        return Response(
            ScriptTableSerializer(scripts.order_by("category"), many=True).data
        )

    @extend_schema(
        tags=["scripts"],
        summary="Add a script",
        request=ScriptSerializer,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")
        },
    )
    def post(self, request):
        serializer = ScriptSerializer(data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        obj = serializer.save()

        # obj.hash_script_body()

        return Response(f"{obj.name} was added!")


@extend_schema(
    tags=["scripts"],
    parameters=[
        OpenApiParameter(
            "pk",
            OpenApiTypes.INT,
            OpenApiParameter.PATH,
            description="Script primary key.",
        )
    ],
)
class GetUpdateDeleteScript(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    @extend_schema(
        summary="Get a single script",
        responses=ScriptSerializer,
    )
    def get(self, request, pk):
        script = get_object_or_404(Script, pk=pk)
        return Response(ScriptSerializer(script).data)

    @extend_schema(
        summary="Update a script",
        description="Updates a script. Built-in/community scripts can only have their "
        "'favorite' or 'hidden' flags changed; any other edit is rejected.",
        request=ScriptSerializer,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")
        },
    )
    def put(self, request, pk):
        script = get_object_or_404(Script.objects.prefetch_related("script"), pk=pk)

        data = request.data

        if script.script_type == ScriptType.BUILT_IN:
            # allow only favoriting builtin scripts
            if "favorite" in data:
                # overwrite request data
                data = {"favorite": data["favorite"]}
            elif "hidden" in data:
                data = {"hidden": data["hidden"]}
            else:
                return notify_error("Community scripts cannot be edited.")

        serializer = ScriptSerializer(data=data, instance=script, partial=True)
        serializer.is_valid(raise_exception=True)
        obj = serializer.save()

        # TODO rename the related field from 'script' to 'scriptchecks' so it's not so confusing
        if script.script.exists():
            for script_check in script.script.all():
                if script_check.policy:
                    clear_entire_cache()
                    break

        return Response(f"{obj.name} was edited!")

    @extend_schema(
        summary="Delete a script",
        description="Deletes a user-defined script. Built-in/community scripts cannot "
        "be deleted.",
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")
        },
    )
    def delete(self, request, pk):
        script = get_object_or_404(Script, pk=pk)

        # this will never trigger but check anyway
        if script.script_type == ScriptType.BUILT_IN:
            return notify_error("Community scripts cannot be deleted")

        script.delete()
        return Response(f"{script.name} was deleted!")


class GetAddScriptSnippets(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    @extend_schema(
        tags=["scripts"],
        summary="List all script snippets",
        responses=ScriptSnippetSerializer(many=True),
    )
    def get(self, request):
        snippets = ScriptSnippet.objects.all()
        return Response(ScriptSnippetSerializer(snippets, many=True).data)

    @extend_schema(
        tags=["scripts"],
        summary="Add a script snippet",
        request=ScriptSnippetSerializer,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")
        },
    )
    def post(self, request):
        serializer = ScriptSnippetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("Script snippet was saved successfully")


@extend_schema(
    tags=["scripts"],
    parameters=[
        OpenApiParameter(
            "pk",
            OpenApiTypes.INT,
            OpenApiParameter.PATH,
            description="Script snippet primary key.",
        )
    ],
)
class GetUpdateDeleteScriptSnippet(APIView):
    permission_classes = [IsAuthenticated, ScriptsPerms]

    @extend_schema(
        summary="Get a single script snippet",
        responses=ScriptSnippetSerializer,
    )
    def get(self, request, pk):
        snippet = get_object_or_404(ScriptSnippet, pk=pk)
        return Response(ScriptSnippetSerializer(snippet).data)

    @extend_schema(
        summary="Update a script snippet",
        request=ScriptSnippetSerializer,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")
        },
    )
    def put(self, request, pk):
        snippet = get_object_or_404(ScriptSnippet, pk=pk)

        serializer = ScriptSnippetSerializer(
            instance=snippet, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("Script snippet was saved successfully")

    @extend_schema(
        summary="Delete a script snippet",
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")
        },
    )
    def delete(self, request, pk):
        snippet = get_object_or_404(ScriptSnippet, pk=pk)
        snippet.delete()

        return Response("Script snippet was deleted successfully")


class TestScript(APIView):
    permission_classes = [IsAuthenticated, RunScriptPerms]

    @extend_schema(
        tags=["scripts"],
        summary="Test run a script on an agent",
        description="Runs an ad-hoc script (code + shell + args/env) against the given "
        "agent over NATS and returns the raw command output. The run is recorded in the "
        "audit log.",
        parameters=[
            OpenApiParameter(
                "agent_id",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent identifier (agent_id).",
            )
        ],
        request=inline_serializer(
            name="ScriptsTestScriptRequest",
            fields={
                "code": serializers.CharField(help_text="Script body to execute."),
                "shell": serializers.CharField(help_text="Script shell/interpreter."),
                "args": serializers.ListField(
                    child=serializers.CharField(), help_text="Script arguments."
                ),
                "env_vars": serializers.ListField(
                    child=serializers.CharField(), help_text="Environment variables."
                ),
                "timeout": serializers.IntegerField(
                    help_text="Execution timeout in seconds."
                ),
                "run_as_user": serializers.BooleanField(
                    help_text="Run the script in the logged-on user's context."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(
                OpenApiTypes.STR, description="Raw script execution output"
            )
        },
        examples=[
            OpenApiExample(
                "Test a PowerShell script",
                value={
                    "code": "Write-Output 'hello'",
                    "shell": "powershell",
                    "args": [],
                    "env_vars": [],
                    "timeout": 90,
                    "run_as_user": False,
                },
                request_only=True,
            )
        ],
    )
    def post(self, request, agent_id):
        from agents.models import Agent

        from .models import Script

        agent = get_object_or_404(Agent, agent_id=agent_id)

        parsed_args = Script.parse_script_args(
            agent, request.data["shell"], request.data["args"]
        )
        parsed_env_vars = Script.parse_script_env_vars(
            agent, request.data["shell"], request.data["env_vars"]
        )

        script_body = Script.replace_with_snippets(request.data["code"])

        data = {
            "func": "runscriptfull",
            "timeout": request.data["timeout"],
            "script_args": parsed_args,
            "payload": {
                "code": script_body,
                "shell": request.data["shell"],
            },
            "run_as_user": request.data["run_as_user"],
            "env_vars": parsed_env_vars,
            "nushell_enable_config": settings.NUSHELL_ENABLE_CONFIG,
            "deno_default_permissions": settings.DENO_DEFAULT_PERMISSIONS,
        }

        r = asyncio.run(
            agent.nats_cmd(data, timeout=request.data["timeout"], wait=True)
        )

        AuditLog.audit_test_script_run(
            username=request.user.username,
            agent=agent,
            before_value=data,
            after_value=r,
            debug_info={"ip": request._client_ip},
        )

        return Response(r)


@extend_schema(
    tags=["scripts"],
    summary="Download a script's code",
    description="Returns the script filename (with shell-appropriate extension) and its "
    "code. By default referenced snippets are expanded into the code; pass "
    "with_snippets=false to return the raw code without snippet expansion.",
    parameters=[
        OpenApiParameter(
            "pk",
            OpenApiTypes.INT,
            OpenApiParameter.PATH,
            description="Script primary key.",
        ),
        OpenApiParameter(
            "with_snippets",
            OpenApiTypes.BOOL,
            OpenApiParameter.QUERY,
            required=False,
            description="Expand snippets into the returned code. Defaults to true. "
            "Set to 'false' to return code without snippet expansion.",
        ),
    ],
    responses={
        200: inline_serializer(
            name="ScriptsDownloadResponse",
            fields={
                "filename": serializers.CharField(),
                "code": serializers.CharField(),
            },
        )
    },
)
@api_view(["GET"])
@permission_classes([IsAuthenticated, ScriptsPerms])
def download(request, pk):
    script = get_object_or_404(Script, pk=pk)

    with_snippets = request.GET.get("with_snippets", True)

    if with_snippets == "false":
        with_snippets = False

    match script.shell:
        case ScriptShell.POWERSHELL:
            ext = ".ps1"
        case ScriptShell.CMD:
            ext = ".bat"
        case ScriptShell.PYTHON:
            ext = ".py"
        case ScriptShell.SHELL:
            ext = ".sh"
        case ScriptShell.NUSHELL:
            ext = ".nu"
        case ScriptShell.DENO:
            ext = ".ts"
        case _:
            ext = ""

    return Response(
        {
            "filename": f"{script.name}{ext}",
            "code": script.code if with_snippets else script.code_no_snippets,
        }
    )
