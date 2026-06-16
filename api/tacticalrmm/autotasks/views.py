from django.shortcuts import get_object_or_404
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
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from agents.models import Agent
from automation.models import Policy
from tacticalrmm.constants import TaskType
from tacticalrmm.helpers import notify_error
from tacticalrmm.permissions import _has_perm_on_agent

from .models import AutomatedTask
from .permissions import AutoTaskPerms, RunAutoTaskPerms
from .serializers import TaskSerializer
from .tasks import remove_orphaned_win_tasks


class GetAddAutoTasks(APIView):
    permission_classes = [IsAuthenticated, AutoTaskPerms]

    @extend_schema(
        tags=["autotasks"],
        summary="List automated tasks",
        description="Lists automated tasks. With no path parameter, returns all tasks the "
        "user may view. When an agent_id is supplied, returns that agent's tasks "
        "(including policy-inherited tasks). When a policy id is supplied, returns the "
        "tasks defined on that policy.",
        parameters=[
            OpenApiParameter(
                "agent_id", OpenApiTypes.STR, OpenApiParameter.PATH,
                description="Agent id to list tasks for.",
            ),
            OpenApiParameter(
                "policy", OpenApiTypes.INT, OpenApiParameter.PATH,
                description="Policy id to list tasks for.",
            ),
        ],
        responses=TaskSerializer(many=True),
    )
    def get(self, request, agent_id=None, policy=None):
        if agent_id:
            agent = get_object_or_404(Agent, agent_id=agent_id)
            tasks = agent.get_tasks_with_policies()
        elif policy:
            policy = get_object_or_404(Policy, id=policy)
            tasks = AutomatedTask.objects.filter(policy=policy)
        else:
            tasks = AutomatedTask.objects.filter_by_role(request.user)  # type: ignore
        return Response(TaskSerializer(tasks, many=True).data)

    @extend_schema(
        tags=["autotasks"],
        summary="Add an automated task",
        description="Creates an automated task. When an `agent` (agent_id string) is "
        "supplied, the task is attached to that agent and scheduled on it; otherwise "
        "the task is created against a policy. Onboarding tasks require agent >= 2.6.0.",
        request=TaskSerializer,
        responses={
            200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message"),
            400: OpenApiResponse(description="Validation or agent version error"),
        },
        examples=[
            OpenApiExample(
                "Add task to an agent",
                value={
                    "agent": "abc123-agent-id",
                    "name": "Nightly cleanup",
                    "task_type": "daily",
                },
                request_only=True,
            )
        ],
    )
    def post(self, request):
        from autotasks.tasks import create_win_task_schedule

        data = request.data.copy()

        # Determine if adding to an agent and replace agent_id with pk
        if "agent" in data.keys():
            agent = get_object_or_404(Agent, agent_id=data["agent"])

            if not _has_perm_on_agent(request.user, agent.agent_id):
                raise PermissionDenied()

            if data["task_type"] == TaskType.ONBOARDING and pyver.parse(
                agent.version
            ) < pyver.parse("2.6.0"):
                return notify_error("Onboarding tasks require agent >= 2.6.0")

            data["agent"] = agent.pk

        serializer = TaskSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        task = serializer.save()

        if task.agent:
            create_win_task_schedule.delay(pk=task.pk)

        return Response(
            "The task has been created. It will show up on the agent on next checkin"
        )


@extend_schema(
    tags=["autotasks"],
    parameters=[
        OpenApiParameter(
            "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
            description="Automated task primary key.",
        )
    ],
)
class GetEditDeleteAutoTask(APIView):
    permission_classes = [IsAuthenticated, AutoTaskPerms]

    @extend_schema(
        summary="Get an automated task",
        responses=TaskSerializer,
    )
    def get(self, request, pk):
        task = get_object_or_404(AutomatedTask, pk=pk)

        if task.agent and not _has_perm_on_agent(request.user, task.agent.agent_id):
            raise PermissionDenied()

        return Response(TaskSerializer(task).data)

    @extend_schema(
        summary="Update an automated task",
        request=TaskSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request, pk):
        task = get_object_or_404(AutomatedTask, pk=pk)

        if task.agent and not _has_perm_on_agent(request.user, task.agent.agent_id):
            raise PermissionDenied()

        serializer = TaskSerializer(instance=task, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response("The task was updated")

    @extend_schema(
        summary="Delete an automated task",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        from autotasks.tasks import delete_win_task_schedule

        task = get_object_or_404(AutomatedTask, pk=pk)

        if task.agent and not _has_perm_on_agent(request.user, task.agent.agent_id):
            raise PermissionDenied()

        if task.agent:
            delete_win_task_schedule.delay(pk=task.pk)
        else:
            task.delete()
            remove_orphaned_win_tasks.delay()

        return Response(f"{task.name} will be deleted shortly")


class RunAutoTask(APIView):
    permission_classes = [IsAuthenticated, RunAutoTaskPerms]

    @extend_schema(
        tags=["autotasks"],
        summary="Run an automated task",
        description="Queues an automated task to run now. If `agent_id` is provided in the "
        "body, runs the (policy) task against that specific agent; otherwise runs the task "
        "against its own agent.",
        parameters=[
            OpenApiParameter(
                "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
                description="Automated task primary key.",
            )
        ],
        request=inline_serializer(
            name="AutoTasksRunTaskRequest",
            fields={
                "agent_id": serializers.CharField(
                    required=False,
                    help_text="Agent id to run a policy task against.",
                ),
            },
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request, pk):
        from autotasks.tasks import run_win_task

        task = get_object_or_404(AutomatedTask, pk=pk)

        if task.agent and not _has_perm_on_agent(request.user, task.agent.agent_id):
            raise PermissionDenied()

        # run policy task on agent
        if "agent_id" in request.data.keys():
            if not _has_perm_on_agent(request.user, request.data["agent_id"]):
                raise PermissionDenied()

            run_win_task.delay(pk=pk, agent_id=request.data["agent_id"])

        # run normal task on agent
        else:
            run_win_task.delay(pk=pk)
        return Response(f"{task.name} will now be run.")
