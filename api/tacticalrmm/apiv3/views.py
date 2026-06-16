import asyncio
import os

from django.conf import settings
from django.db import transaction
from django.db.models import Prefetch
from django.db.utils import IntegrityError
from django.http import FileResponse
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
from packaging import version as pyver
from rest_framework import serializers
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.models import User
from agents.models import Agent, AgentHistory, Note
from agents.serializers import AgentHistorySerializer
from alerts.tasks import cache_agents_alert_template
from apiv3.utils import get_agent_config
from autotasks.models import AutomatedTask, TaskResult
from autotasks.serializers import TaskGOGetSerializer, TaskResultSerializer
from checks.constants import CHECK_DEFER, CHECK_RESULT_DEFER
from checks.models import Check, CheckResult
from checks.serializers import CheckRunnerGetSerializer
from core.tasks import sync_mesh_perms_task
from core.utils import (
    download_mesh_agent,
    get_core_settings,
    get_mesh_device_id,
    get_mesh_installer,
    get_mesh_ws_url,
    get_meshagent_url,
)
from logs.models import DebugLog
from software.models import InstalledSoftware
from tacticalrmm.constants import (
    AGENT_DEFER,
    TRMM_MAX_REQUEST_SIZE,
    AgentHistoryType,
    AgentMonType,
    AgentPlat,
    AuditActionType,
    AuditObjType,
    CheckStatus,
    CustomFieldModel,
    DebugLogType,
    GoArch,
    MeshAgentIdent,
    TaskRunStatus,
)
from tacticalrmm.helpers import make_random_password, notify_error
from tacticalrmm.utils import reload_nats
from winupdate.models import WinUpdate, WinUpdatePolicy


class CheckIn(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    # called once during tacticalagent windows service startup
    @extend_schema(
        tags=["apiv3"],
        summary="Agent startup check-in",
        description="Internal agent endpoint. Called once during the tacticalagent "
        "service startup. Triggers chocolatey install (if needed) and a Windows "
        "updates scan over NATS. The agent is identified by its auth token.",
        request=None,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def post(self, request):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER),
            user=request.user,
        )
        if not agent.choco_installed:
            asyncio.run(agent.nats_cmd({"func": "installchoco"}, wait=False))

        asyncio.run(agent.nats_cmd({"func": "getwinupdates"}, wait=False))
        return Response("ok")


class SyncMeshNodeID(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Sync MeshCentral node id",
        description="Internal agent endpoint. The agent reports its MeshCentral node "
        "id so it can be persisted on the Agent record. Optionally triggers a mesh "
        "permissions sync task.",
        request=inline_serializer(
            name="ApiV3SyncMeshNodeIDRequest",
            fields={
                "nodeid": serializers.CharField(help_text="MeshCentral node id."),
                "run_sync_task": serializers.BooleanField(
                    required=False,
                    help_text="If truthy, queues the mesh permissions sync task.",
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def post(self, request):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER),
            user=request.user,
        )
        if agent.mesh_node_id != request.data["nodeid"]:
            agent.mesh_node_id = request.data["nodeid"]
            agent.save(update_fields=["mesh_node_id"])

        if request.data.get("run_sync_task"):
            sync_mesh_perms_task.delay()

        return Response("ok")


class Choco(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Report chocolatey install status",
        description="Internal agent endpoint. The agent reports whether chocolatey "
        "has been installed so the flag can be persisted on the Agent record.",
        request=inline_serializer(
            name="ApiV3ChocoRequest",
            fields={
                "installed": serializers.BooleanField(
                    help_text="Whether chocolatey is installed on the agent."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def post(self, request):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER),
            user=request.user,
        )
        agent.choco_installed = request.data["installed"]
        agent.save(update_fields=["choco_installed"])
        return Response("ok")


class WinUpdates(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Report reboot-needed state after updates",
        description="Internal agent endpoint. The agent reports whether a reboot is "
        "required after installing Windows updates. Honors the patch policy to "
        "optionally trigger an immediate reboot over NATS.",
        request=inline_serializer(
            name="ApiV3WinUpdatesNeedsRebootRequest",
            fields={
                "needs_reboot": serializers.BooleanField(
                    help_text="Whether the agent requires a reboot."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def put(self, request):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER),
            user=request.user,
        )

        needs_reboot: bool = request.data["needs_reboot"]
        agent.needs_reboot = needs_reboot
        agent.save(update_fields=["needs_reboot"])

        reboot_policy: str = agent.get_patch_policy().reboot_after_install
        reboot = False

        if reboot_policy == "always":
            reboot = True
        elif needs_reboot and reboot_policy == "required":
            reboot = True

        if reboot:
            asyncio.run(agent.nats_cmd({"func": "rebootnow"}, wait=False))
            DebugLog.info(
                agent=agent,
                log_type=DebugLogType.WIN_UPDATES,
                message=f"{agent.hostname} is rebooting after updates were installed.",
            )

        agent.delete_superseded_updates()
        return Response("ok")

    @extend_schema(
        tags=["apiv3"],
        summary="Report a single update install result",
        description="Internal agent endpoint. The agent reports the success/failure "
        "result for a specific Windows update identified by its GUID.",
        request=inline_serializer(
            name="ApiV3WinUpdatesResultRequest",
            fields={
                "guid": serializers.CharField(help_text="Windows update GUID."),
                "success": serializers.BooleanField(
                    help_text="Whether the update installed successfully."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def patch(self, request):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER),
            user=request.user,
        )
        u = agent.winupdates.filter(guid=request.data["guid"]).last()  # type: ignore
        if not u:
            raise WinUpdate.DoesNotExist

        success: bool = request.data["success"]
        if success:
            u.result = "success"
            u.downloaded = True
            u.installed = True
            u.date_installed = djangotime.now()
            u.save(
                update_fields=[
                    "result",
                    "downloaded",
                    "installed",
                    "date_installed",
                ]
            )
        else:
            u.result = "failed"
            u.save(update_fields=["result"])

        agent.delete_superseded_updates()
        return Response("ok")

    @extend_schema(
        tags=["apiv3"],
        summary="Submit the Windows update inventory",
        description="Internal agent endpoint. The agent submits the list of Windows "
        "updates discovered by the Windows Update Agent (WUA). Existing updates are "
        "updated and new ones created.",
        request=inline_serializer(
            name="ApiV3WinUpdatesInventoryRequest",
            fields={
                "wua_updates": serializers.ListField(
                    child=inline_serializer(
                        name="ApiV3WinUpdateItem",
                        fields={
                            "guid": serializers.CharField(),
                            "title": serializers.CharField(),
                            "installed": serializers.BooleanField(),
                            "downloaded": serializers.BooleanField(),
                            "description": serializers.CharField(),
                            "severity": serializers.CharField(),
                            "categories": serializers.ListField(
                                child=serializers.CharField()
                            ),
                            "category_ids": serializers.ListField(
                                child=serializers.CharField()
                            ),
                            "kb_article_ids": serializers.ListField(
                                child=serializers.CharField()
                            ),
                            "more_info_urls": serializers.ListField(
                                child=serializers.CharField()
                            ),
                            "support_url": serializers.CharField(),
                            "revision_number": serializers.IntegerField(),
                        },
                    ),
                    help_text="List of Windows updates reported by the agent.",
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'."),
            400: OpenApiResponse(description="Empty payload."),
        },
    )
    def post(self, request):
        updates = request.data["wua_updates"]
        if not updates:
            return notify_error("Empty payload")

        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER),
            user=request.user,
        )

        for update in updates:
            if agent.winupdates.filter(guid=update["guid"]).exists():  # type: ignore
                u = agent.winupdates.filter(guid=update["guid"]).last()  # type: ignore
                u.downloaded = update["downloaded"]
                u.installed = update["installed"]
                u.save(update_fields=["downloaded", "installed"])
            else:
                try:
                    kb = "KB" + update["kb_article_ids"][0]
                except:
                    continue

                WinUpdate(
                    agent=agent,
                    guid=update["guid"],
                    kb=kb,
                    title=update["title"],
                    installed=update["installed"],
                    downloaded=update["downloaded"],
                    description=update["description"],
                    severity=update["severity"],
                    categories=update["categories"],
                    category_ids=update["category_ids"],
                    kb_article_ids=update["kb_article_ids"],
                    more_info_urls=update["more_info_urls"],
                    support_url=update["support_url"],
                    revision_number=update["revision_number"],
                ).save()

        agent.delete_superseded_updates()
        return Response("ok")


class SupersededWinUpdate(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Delete a superseded Windows update",
        description="Internal agent endpoint. The agent reports a superseded update "
        "by GUID; all matching WinUpdate records are deleted.",
        request=inline_serializer(
            name="ApiV3SupersededWinUpdateRequest",
            fields={
                "guid": serializers.CharField(
                    help_text="GUID of the superseded Windows update."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def post(self, request):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER),
            user=request.user,
        )
        updates = agent.winupdates.filter(guid=request.data["guid"])  # type: ignore
        for u in updates:
            u.delete()

        return Response("ok")


class RunChecks(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Get all checks to run",
        description="Internal agent endpoint. Returns the full set of checks "
        "(including policy checks) the agent should run, along with the agent pk "
        "and check interval.",
        parameters=[
            OpenApiParameter(
                "agentid",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id (the agent is also resolved via its auth token).",
            )
        ],
        responses={
            200: inline_serializer(
                name="ApiV3RunChecksResponse",
                fields={
                    "agent": serializers.IntegerField(help_text="Agent primary key."),
                    "check_interval": serializers.IntegerField(),
                    "checks": CheckRunnerGetSerializer(many=True),
                },
            )
        },
    )
    def get(self, request, agentid):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER).prefetch_related(
                Prefetch("agentchecks", queryset=Check.objects.select_related("script"))
            ),
            user=request.user,
        )
        checks = agent.get_checks_with_policies(exclude_overridden=True)
        ret = {
            "agent": agent.pk,
            "check_interval": agent.check_interval,
            "checks": CheckRunnerGetSerializer(
                checks, context={"agent": agent}, many=True
            ).data,
        }
        return Response(ret)


class CheckRunner(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Get checks that are due to run",
        description="Internal agent endpoint. Returns only the checks whose run "
        "interval has elapsed (or that have never run), along with the agent pk and "
        "check interval.",
        parameters=[
            OpenApiParameter(
                "agentid",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id (the agent is also resolved via its auth token).",
            )
        ],
        responses={
            200: inline_serializer(
                name="ApiV3CheckRunnerGetResponse",
                fields={
                    "agent": serializers.IntegerField(help_text="Agent primary key."),
                    "check_interval": serializers.IntegerField(),
                    "checks": CheckRunnerGetSerializer(many=True),
                },
            )
        },
    )
    def get(self, request, agentid):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER).prefetch_related(
                Prefetch("agentchecks", queryset=Check.objects.select_related("script"))
            ),
            user=request.user,
        )
        checks = agent.get_checks_with_policies(exclude_overridden=True)

        run_list = [
            check
            for check in checks
            # always run if check hasn't run yet
            if not isinstance(check.check_result, CheckResult)
            or not check.check_result.last_run
            # see if the correct amount of seconds have passed
            or (
                check.check_result.last_run
                < djangotime.now()
                - djangotime.timedelta(
                    seconds=check.run_interval or agent.check_interval
                )
            )
        ]

        ret = {
            "agent": agent.pk,
            "check_interval": agent.check_run_interval(),
            "checks": CheckRunnerGetSerializer(
                run_list, context={"agent": agent}, many=True
            ).data,
        }
        return Response(ret)

    @extend_schema(
        tags=["apiv3"],
        summary="Submit a check result",
        description="Internal agent endpoint. The agent submits the result of a "
        "single check run. Persists the result, evaluates pass/fail, and runs any "
        "assigned tasks on failure. The exact accepted fields depend on the check "
        "type.",
        request=inline_serializer(
            name="ApiV3CheckRunnerResultRequest",
            fields={
                "id": serializers.IntegerField(help_text="Check primary key."),
                "agent_id": serializers.CharField(
                    help_text="Agent id; required (older agents are rejected)."
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'."),
            400: OpenApiResponse(description="Agent upgrade required."),
        },
    )
    def patch(self, request):
        if "agent_id" not in request.data.keys():
            return notify_error("Agent upgrade required")

        check = get_object_or_404(
            Check.objects.defer(*CHECK_DEFER),
            pk=request.data["id"],
        )
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER),
            user=request.user,
        )

        # get check result or create if doesn't exist
        check_result, created = CheckResult.objects.defer(
            *CHECK_RESULT_DEFER
        ).get_or_create(
            assigned_check=check,
            agent=agent,
        )

        if created:
            check_result.save()

        status = check_result.handle_check(request.data, check, agent)
        if status == CheckStatus.FAILING and check.assignedtasks.exists():
            for task in check.assignedtasks.all():
                if task.enabled:
                    if task.policy:
                        task.run_win_task(agent)
                    else:
                        task.run_win_task()

        return Response("ok")


class CheckRunnerInterval(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Get the check run interval",
        description="Internal agent endpoint. Returns the agent pk and the effective "
        "check run interval in seconds.",
        parameters=[
            OpenApiParameter(
                "agentid",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id (the agent is also resolved via its auth token).",
            )
        ],
        responses={
            200: inline_serializer(
                name="ApiV3CheckRunnerIntervalResponse",
                fields={
                    "agent": serializers.IntegerField(help_text="Agent primary key."),
                    "check_interval": serializers.IntegerField(),
                },
            )
        },
    )
    def get(self, request, agentid):
        agent = get_object_or_404(
            Agent.objects.defer(*AGENT_DEFER).prefetch_related("agentchecks"),
            user=request.user,
        )

        return Response(
            {"agent": agent.pk, "check_interval": agent.check_run_interval()}
        )


@extend_schema(
    tags=["apiv3"],
    parameters=[
        OpenApiParameter(
            "pk",
            OpenApiTypes.INT,
            OpenApiParameter.PATH,
            description="AutomatedTask primary key.",
        ),
        OpenApiParameter(
            "agentid",
            OpenApiTypes.STR,
            OpenApiParameter.PATH,
            description="Agent id (the agent is also resolved via its auth token).",
        ),
    ],
)
class TaskRunner(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get a task definition to run",
        description="Internal agent endpoint. Returns the automated task definition "
        "(script, args, etc.) for the agent to execute.",
        responses={200: TaskGOGetSerializer},
    )
    def get(self, request, pk, agentid):
        agent = get_object_or_404(
            Agent.objects.select_related("policy", "site").defer(*AGENT_DEFER),
            user=request.user,
        )
        task = get_object_or_404(
            AutomatedTask.objects.select_related("agent", "policy"), pk=pk
        )

        if task.agent:
            if task.agent.agent_id != agent.agent_id:
                return notify_error("")
        elif task.policy:
            if pk not in [t.pk for t in agent.get_tasks_with_policies()]:
                return notify_error("")

        return Response(TaskGOGetSerializer(task, context={"agent": agent}).data)

    @extend_schema(
        summary="Submit a task run result",
        description="Internal agent endpoint. The agent submits the result of an "
        "automated task run (stdout/stderr/retcode/etc.). Persists the TaskResult, "
        "records agent history, updates collector custom fields, and handles alerts.",
        request=TaskResultSerializer,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def patch(self, request, pk, agentid):
        from alerts.models import Alert

        agent = get_object_or_404(Agent.objects.defer(*AGENT_DEFER), user=request.user)
        task = get_object_or_404(
            AutomatedTask.objects.select_related("custom_field"), pk=pk
        )

        content_length = request.META.get("CONTENT_LENGTH")
        if content_length and int(content_length) > TRMM_MAX_REQUEST_SIZE:
            request.data["stdout"] = ""
            request.data["stderr"] = "Content truncated due to excessive request size."
            request.data["retcode"] = 1

        # get task result or create if doesn't exist
        try:
            task_result = (
                TaskResult.objects.select_related("agent")
                .defer("agent__services", "agent__wmi_detail")
                .get(task=task, agent=agent)
            )
            serializer = TaskResultSerializer(
                data=request.data, instance=task_result, partial=True
            )
        except TaskResult.DoesNotExist:
            serializer = TaskResultSerializer(data=request.data, partial=True)

        serializer.is_valid(raise_exception=True)
        task_result = serializer.save(
            last_run=djangotime.now(), run_status=TaskRunStatus.COMPLETED
        )

        AgentHistory.objects.create(
            agent=agent,
            type=AgentHistoryType.TASK_RUN,
            command=task.name,
            script_results=request.data,
        )

        # check if task is a collector and update the custom field
        if task.custom_field:
            if not task_result.stderr:
                task_result.save_collector_results()

                status = CheckStatus.PASSING
            else:
                status = CheckStatus.FAILING
        else:
            status = (
                CheckStatus.FAILING if task_result.retcode != 0 else CheckStatus.PASSING
            )

        task_result.status = status
        task_result.save(update_fields=["status"])

        if status == CheckStatus.PASSING:
            if Alert.create_or_return_task_alert(task, agent=agent, skip_create=True):
                Alert.handle_alert_resolve(task_result)
        else:
            Alert.handle_alert_failure(task_result)

        return Response("ok")


class MeshExe(APIView):
    """Sends the mesh exe to the installer"""

    @extend_schema(
        tags=["apiv3"],
        summary="Download the MeshCentral agent",
        description="Internal agent endpoint. Used by the installer to download the "
        "appropriate MeshCentral agent binary for the requested architecture and "
        "platform.",
        request=inline_serializer(
            name="ApiV3MeshExeRequest",
            fields={
                "goarch": serializers.CharField(
                    help_text="Target architecture, e.g. amd64, 386, arm64."
                ),
                "plat": serializers.CharField(
                    help_text="Target platform, e.g. windows, darwin."
                ),
            },
        ),
        responses={
            (200, "application/octet-stream"): OpenApiTypes.BINARY,
            400: OpenApiResponse(
                description="Unsupported arch or unable to reach mesh."
            ),
        },
    )
    def post(self, request):
        match request.data:
            case {"goarch": GoArch.AMD64, "plat": AgentPlat.WINDOWS}:
                ident = MeshAgentIdent.WIN64
            case {"goarch": GoArch.i386, "plat": AgentPlat.WINDOWS}:
                ident = MeshAgentIdent.WIN32
            case {"goarch": GoArch.AMD64, "plat": AgentPlat.DARWIN} | {
                "goarch": GoArch.ARM64,
                "plat": AgentPlat.DARWIN,
            }:
                ident = MeshAgentIdent.DARWIN_UNIVERSAL
            case _:
                return notify_error("Arch not supported")

        core = get_core_settings()

        try:
            uri = get_mesh_ws_url()
            mesh_device_id: str = asyncio.run(
                get_mesh_device_id(uri, core.mesh_device_group)
            )
        except:
            return notify_error("Unable to connect to mesh to get group id information")

        dl_url = get_meshagent_url(
            ident=ident,
            plat=request.data["plat"],
            mesh_site=core.mesh_site,
            mesh_device_id=mesh_device_id,
        )

        try:
            return download_mesh_agent(dl_url)
        except Exception as e:
            return notify_error(f"Unable to download mesh agent: {e}")


class MeshReinstall(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Download MeshCentral reinstall installer",
        description="Internal agent endpoint. Streams a MeshCentral agent installer "
        "for reinstalling the mesh agent on this agent (Windows only for now).",
        parameters=[
            OpenApiParameter(
                "agentid",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id (the agent is also resolved via its auth token).",
            )
        ],
        request=None,
        responses={
            (200, "application/octet-stream"): OpenApiTypes.BINARY,
            400: OpenApiResponse(
                description="Unable to reach mesh or build the installer."
            ),
        },
    )
    def get(self, request, agentid):

        agent = get_object_or_404(
            Agent.objects.only("plat", "goarch"), user=request.user
        )
        core = get_core_settings()

        try:
            uri = get_mesh_ws_url()
            mesh_device_id: str = asyncio.run(
                get_mesh_device_id(uri, core.mesh_device_group)
            )
        except:
            return notify_error("Unable to connect to mesh to get group id information")

        # windows only for now
        ident = (
            MeshAgentIdent.WIN64
            if agent.goarch == GoArch.AMD64
            else MeshAgentIdent.WIN32
        )
        dl_url = get_meshagent_url(
            ident=ident,
            plat=agent.plat,
            mesh_site=core.mesh_site,  # type: ignore
            mesh_device_id=mesh_device_id,
        )

        try:
            mesh_installer = get_mesh_installer(agent.goarch, dl_url, agent.plat)
        except Exception as e:
            return notify_error(str(e))

        response = FileResponse(
            open(mesh_installer, "rb"),
            as_attachment=True,
            filename=os.path.basename(mesh_installer),
        )
        return response


class NewAgent(APIView):
    @extend_schema(
        tags=["apiv3"],
        summary="Register a new agent",
        description="Internal agent endpoint. Called during agent installation to "
        "create the Agent record, its service user/auth token, and a default Windows "
        "update policy. Returns the new agent pk and auth token.",
        request=inline_serializer(
            name="ApiV3NewAgentRequest",
            fields={
                "agent_id": serializers.CharField(),
                "hostname": serializers.CharField(),
                "site": serializers.IntegerField(help_text="Site primary key."),
                "monitoring_type": serializers.ChoiceField(
                    choices=["server", "workstation"]
                ),
                "description": serializers.CharField(),
                "mesh_node_id": serializers.CharField(),
                "goarch": serializers.CharField(help_text="Architecture, e.g. amd64."),
                "plat": serializers.CharField(help_text="Platform, e.g. windows."),
            },
        ),
        responses={
            200: inline_serializer(
                name="ApiV3NewAgentResponse",
                fields={
                    "pk": serializers.IntegerField(help_text="New agent primary key."),
                    "token": serializers.CharField(help_text="Agent auth token."),
                },
            ),
            400: OpenApiResponse(description="Agent already exists."),
        },
    )
    def post(self, request):
        from logs.models import AuditLog

        """ Creates the agent """

        try:
            with transaction.atomic():
                agent = Agent(
                    agent_id=request.data["agent_id"],
                    hostname=request.data["hostname"],
                    site_id=int(request.data["site"]),
                    monitoring_type=request.data["monitoring_type"],
                    description=request.data["description"],
                    mesh_node_id=request.data["mesh_node_id"],
                    goarch=request.data["goarch"],
                    plat=request.data["plat"],
                    last_seen=djangotime.now(),
                )
                agent.save()

                user = User.objects.create_user(  # type: ignore
                    username=request.data["agent_id"],
                    agent=agent,
                    password=make_random_password(len=60),
                )

                token = Token.objects.create(user=user)

                if agent.monitoring_type == AgentMonType.WORKSTATION:
                    WinUpdatePolicy(agent=agent, run_time_days=[5, 6]).save()
                else:
                    WinUpdatePolicy(agent=agent).save()

                # create agent install audit record
                AuditLog.objects.create(
                    username=request.user,
                    agent=agent.hostname,
                    object_type=AuditObjType.AGENT,
                    action=AuditActionType.AGENT_INSTALL,
                    message=f"{request.user} installed new agent {agent.hostname}",
                    after_value=Agent.serialize(agent),
                    debug_info={"ip": request._client_ip},
                )
        except IntegrityError:
            return notify_error(
                "Agent already exists. Remove old agent first if trying to re-install"
            )

        reload_nats()
        ret = {"pk": agent.pk, "token": token.key}

        if agent.plat == AgentPlat.WINDOWS:
            sync_mesh_perms_task.delay()

        cache_agents_alert_template.delay()
        return Response(ret)


class Software(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Submit installed software inventory",
        description="Internal agent endpoint. The agent submits its installed "
        "software list, which is stored/updated on the agent's InstalledSoftware "
        "record.",
        request=inline_serializer(
            name="ApiV3SoftwareRequest",
            fields={
                "software": serializers.ListField(
                    child=serializers.DictField(),
                    help_text="List of installed software entries.",
                ),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def post(self, request):
        agent = get_object_or_404(Agent, user=request.user)
        sw = request.data["software"]
        if not InstalledSoftware.objects.filter(agent=agent).exists():
            InstalledSoftware(agent=agent, software=sw).save()
        else:
            s = agent.installedsoftware_set.first()  # type: ignore
            s.software = sw
            s.save(update_fields=["software"])

        return Response("ok")


class Installer(APIView):
    @extend_schema(
        tags=["apiv3"],
        summary="Validate installer token",
        description="Internal agent endpoint. Used by the installer to verify its "
        "auth token is valid; returns 401 if not.",
        request=None,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'."),
            401: OpenApiResponse(description="Invalid token."),
        },
    )
    def get(self, request):
        # used to check if token is valid. will return 401 if not
        return Response("ok")

    @extend_schema(
        tags=["apiv3"],
        summary="Validate installer version",
        description="Internal agent endpoint. Checks the supplied installer version "
        "against the latest supported agent version and rejects outdated installers.",
        request=inline_serializer(
            name="ApiV3InstallerVersionRequest",
            fields={
                "version": serializers.CharField(help_text="Installer/agent version."),
            },
        ),
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'."),
            400: OpenApiResponse(description="Invalid data or outdated installer."),
        },
    )
    def post(self, request):
        if "version" not in request.data:
            return notify_error("Invalid data")

        ver = request.data["version"]
        if (
            pyver.parse(ver) < pyver.parse(settings.LATEST_AGENT_VER)
            and "-dev" not in settings.LATEST_AGENT_VER
        ):
            return notify_error(
                f"Old installer detected (version {ver} ). Latest version is {settings.LATEST_AGENT_VER} Please generate a new installer from the RMM"
            )

        return Response("ok")


class AgentHistoryResult(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Submit script run history result",
        description="Internal agent endpoint. The agent submits the result of a "
        "script run associated with an AgentHistory record. Updates collector custom "
        "fields and optionally saves an agent note.",
        parameters=[
            OpenApiParameter(
                "agentid",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id (the agent is also resolved via its auth token).",
            ),
            OpenApiParameter(
                "pk",
                OpenApiTypes.INT,
                OpenApiParameter.PATH,
                description="AgentHistory primary key.",
            ),
        ],
        request=AgentHistorySerializer,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Returns 'ok'.")
        },
    )
    def patch(self, request, agentid, pk):
        content_length = request.META.get("CONTENT_LENGTH")
        if content_length and int(content_length) > TRMM_MAX_REQUEST_SIZE:

            request.data["script_results"]["stdout"] = ""
            request.data["script_results"][
                "stderr"
            ] = "Content truncated due to excessive request size."
            request.data["script_results"]["retcode"] = 1

        hist = get_object_or_404(
            AgentHistory.objects.select_related("custom_field").filter(
                agent__user=request.user,
            ),
            pk=pk,
        )
        s = AgentHistorySerializer(instance=hist, data=request.data, partial=True)
        s.is_valid(raise_exception=True)
        s.save()

        if hist.custom_field:
            if hist.custom_field.model == CustomFieldModel.AGENT:
                field = hist.custom_field.get_or_create_field_value(hist.agent)
            elif hist.custom_field.model == CustomFieldModel.CLIENT:
                field = hist.custom_field.get_or_create_field_value(hist.agent.client)
            elif hist.custom_field.model == CustomFieldModel.SITE:
                field = hist.custom_field.get_or_create_field_value(hist.agent.site)

            r = request.data["script_results"]["stdout"]
            value = (
                r.strip()
                if hist.collector_all_output
                else r.strip().split("\n")[-1].strip()
            )

            field.save_to_field(value)

        if hist.save_to_agent_note:
            Note.objects.create(
                agent=hist.agent,
                user=request.user,
                note=request.data["script_results"]["stdout"],
            )

        return Response("ok")


class AgentConfig(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    @extend_schema(
        tags=["apiv3"],
        summary="Get agent configuration",
        description="Internal agent endpoint. Returns the agent configuration object "
        "(server-side settings the agent applies locally).",
        parameters=[
            OpenApiParameter(
                "agentid",
                OpenApiTypes.STR,
                OpenApiParameter.PATH,
                description="Agent id (the agent is also resolved via its auth token).",
            )
        ],
        responses={
            200: OpenApiResponse(
                OpenApiTypes.OBJECT, description="Agent configuration key/value object."
            )
        },
    )
    def get(self, request, agentid):
        ret = get_agent_config()
        return Response(ret._to_dict())
