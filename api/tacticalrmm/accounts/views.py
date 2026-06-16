import datetime

import pyotp
from allauth.socialaccount.models import SocialAccount, SocialApp
from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError
from django.db import IntegrityError
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
from knox.models import AuthToken
from knox.views import LoginView as KnoxLoginView
from python_ipware import IpWare
from rest_framework import serializers
from rest_framework.authtoken.serializers import AuthTokenSerializer
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.serializers import (
    ModelSerializer,
    ReadOnlyField,
    SerializerMethodField,
)
from rest_framework.views import APIView

from accounts.utils import is_root_user
from core.tasks import sync_mesh_perms_task
from logs.models import AuditLog
from tacticalrmm.helpers import notify_error
from tacticalrmm.mixins import GenericPermsViewMixin
from tacticalrmm.throttles import (
    CheckCredsDayThrottle,
    CheckCredsMinThrottle,
    LoginDayThrottle,
    LoginMinThrottle,
)
from tacticalrmm.utils import get_core_settings

from .models import APIKey, Role, User
from .permissions import (
    AccountsPerms,
    APIKeyPerms,
    LocalUserPerms,
    RolesPerms,
    SelfResetSSOPerms,
)
from .serializers import (
    APIKeySerializer,
    RoleSerializer,
    TOTPSetupSerializer,
    UserSerializer,
    UserUISerializer,
)


class CheckCredsV2(KnoxLoginView):
    permission_classes = (AllowAny,)
    throttle_classes = [CheckCredsMinThrottle, CheckCredsDayThrottle]

    # restrict time on tokens issued by this view to 3 min
    def get_token_ttl(self):
        return datetime.timedelta(seconds=180)

    @extend_schema(
        tags=["accounts"],
        summary="Check user credentials (step 1 of login)",
        description="Validates username/password and issues a short-lived (3 minute) "
        "token. If the user has no TOTP key set, the user is logged in and a login "
        "token is returned with `totp: false`; otherwise only `totp: true` is returned "
        "to prompt for two-factor entry.",
        request=inline_serializer(
            name="AccountsCheckCredsRequest",
            fields={
                "username": serializers.CharField(),
                "password": serializers.CharField(),
            },
        ),
        responses={
            200: inline_serializer(
                name="AccountsCheckCredsResponse",
                fields={
                    "totp": serializers.BooleanField(),
                    "token": serializers.CharField(required=False),
                    "expiry": serializers.DateTimeField(required=False),
                },
            ),
            400: OpenApiResponse(OpenApiTypes.STR, description="Bad credentials"),
        },
    )
    def post(self, request, format=None):
        # check credentials
        serializer = AuthTokenSerializer(data=request.data)
        if not serializer.is_valid():
            AuditLog.audit_user_failed_login(
                request.data["username"], debug_info={"ip": request._client_ip}
            )
            return notify_error("Bad credentials")

        user = serializer.validated_data["user"]

        if user.block_dashboard_login or user.is_sso_user:
            return notify_error("Bad credentials")

        # block local logon if configured
        core_settings = get_core_settings()
        if not user.is_superuser and core_settings.block_local_user_logon:
            return notify_error("Bad credentials")

        # if totp token not set modify response to notify frontend
        if not user.totp_key:
            login(request, user)
            response = super().post(request, format=None)
            response.data["totp"] = False
            return response

        return Response({"totp": True})


class LoginViewV2(KnoxLoginView):
    permission_classes = (AllowAny,)
    throttle_classes = [LoginMinThrottle, LoginDayThrottle]

    @extend_schema(
        tags=["accounts"],
        summary="Complete login with two-factor token (step 2 of login)",
        description="Validates the username/password plus the TOTP two-factor token and, "
        "on success, returns a login token along with the username.",
        request=inline_serializer(
            name="AccountsLoginRequest",
            fields={
                "username": serializers.CharField(),
                "password": serializers.CharField(),
                "twofactor": serializers.CharField(help_text="TOTP two-factor code."),
            },
        ),
        responses={
            200: inline_serializer(
                name="AccountsLoginResponse",
                fields={
                    "token": serializers.CharField(),
                    "expiry": serializers.DateTimeField(),
                    "username": serializers.CharField(),
                    "name": serializers.CharField(allow_null=True),
                },
            ),
            400: OpenApiResponse(OpenApiTypes.STR, description="Bad credentials"),
        },
        examples=[
            OpenApiExample(
                "Login with 2FA",
                value={
                    "username": "jsmith",
                    "password": "hunter2",
                    "twofactor": "123456",
                },
                request_only=True,
            )
        ],
    )
    def post(self, request, format=None):
        valid = False

        serializer = AuthTokenSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        if user.block_dashboard_login:
            return notify_error("Bad credentials")

        # block local logon if configured
        core_settings = get_core_settings()
        if not user.is_superuser and core_settings.block_local_user_logon:
            return notify_error("Bad credentials")

        if user.is_sso_user:
            return notify_error("Bad credentials")

        token = request.data["twofactor"]
        totp = pyotp.TOTP(user.totp_key)

        if settings.DEBUG and token == "sekret":
            valid = True
        elif getattr(settings, "DEMO", False):
            valid = True
        elif totp.verify(token, valid_window=10):
            valid = True

        if valid:
            login(request, user)

            # save ip information
            ipw = IpWare()
            client_ip, _ = ipw.get_client_ip(request.META)
            if client_ip:
                user.last_login_ip = str(client_ip)
                user.save()

            AuditLog.audit_user_login_successful(
                request.data["username"], debug_info={"ip": request._client_ip}
            )
            response = super().post(request, format=None)
            response.data["username"] = request.user.username
            response.data["name"] = None

            return Response(response.data)
        else:
            AuditLog.audit_user_failed_twofactor(
                request.data["username"], debug_info={"ip": request._client_ip}
            )
            return notify_error("Bad credentials")


@extend_schema(
    tags=["accounts"],
    parameters=[
        OpenApiParameter(
            "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
            description="User primary key.",
        )
    ],
)
class GetDeleteActiveLoginSessionsPerUser(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    class TokenSerializer(ModelSerializer):
        user = ReadOnlyField(source="user.username")

        class Meta:
            model = AuthToken
            fields = (
                "digest",
                "user",
                "created",
                "expiry",
            )

    @extend_schema(
        summary="List a user's active login sessions",
        description="Returns the non-expired auth tokens (active login sessions) for "
        "the specified user.",
        responses=inline_serializer(
            name="AccountsActiveLoginSessionResponse",
            fields={
                "digest": serializers.CharField(),
                "user": serializers.CharField(),
                "created": serializers.DateTimeField(),
                "expiry": serializers.DateTimeField(),
            },
            many=True,
        ),
    )
    def get(self, request, pk):
        tokens = get_object_or_404(User, pk=pk).auth_token_set.filter(
            expiry__gt=djangotime.now()
        )

        return Response(self.TokenSerializer(tokens, many=True).data)

    @extend_schema(
        summary="Delete all of a user's active login sessions",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        tokens = get_object_or_404(User, pk=pk).auth_token_set.filter(
            expiry__gt=djangotime.now()
        )

        tokens.delete()
        return Response("ok")


@extend_schema(
    tags=["accounts"],
    parameters=[
        OpenApiParameter(
            "pk", OpenApiTypes.STR, OpenApiParameter.PATH,
            description="Auth token digest of the session to delete.",
        )
    ],
)
class DeleteActiveLoginSession(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    @extend_schema(
        summary="Delete a single active login session",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        token = get_object_or_404(AuthToken, digest=pk)

        token.delete()

        return Response("ok")


class GetAddUsers(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    class UserSerializerSSO(ModelSerializer):
        social_accounts = SerializerMethodField()

        def get_social_accounts(self, obj):
            accounts = SocialAccount.objects.filter(user_id=obj.pk)

            if accounts:
                social_accounts = []
                for account in accounts:
                    try:
                        provider_account = account.get_provider_account()
                        display = provider_account.to_str()
                    except SocialApp.DoesNotExist:
                        display = "Orphaned Provider"
                    except Exception:
                        display = "Unknown"

                    social_accounts.append(
                        {
                            "uid": account.uid,
                            "provider": account.provider,
                            "display": display,
                            "last_login": account.last_login,
                            "date_joined": account.date_joined,
                            "extra_data": account.extra_data,
                        }
                    )

                return social_accounts

            return []

        class Meta:
            model = User
            fields = [
                "id",
                "username",
                "first_name",
                "last_name",
                "email",
                "is_active",
                "last_login",
                "last_login_ip",
                "role",
                "block_dashboard_login",
                "date_format",
                "social_accounts",
            ]

    @extend_schema(
        tags=["accounts"],
        summary="List users",
        description="Returns all dashboard users (excluding agent and installer users), "
        "optionally filtered by username via the `search` query parameter. Each user "
        "includes any linked SSO social accounts.",
        parameters=[
            OpenApiParameter(
                "search", OpenApiTypes.STR, OpenApiParameter.QUERY, required=False,
                description="Case-insensitive username substring filter.",
            )
        ],
        responses=inline_serializer(
            name="AccountsUserWithSSOResponse",
            fields={
                "id": serializers.IntegerField(),
                "username": serializers.CharField(),
                "first_name": serializers.CharField(),
                "last_name": serializers.CharField(),
                "email": serializers.CharField(),
                "is_active": serializers.BooleanField(),
                "last_login": serializers.DateTimeField(allow_null=True),
                "last_login_ip": serializers.CharField(allow_null=True),
                "role": serializers.IntegerField(allow_null=True),
                "block_dashboard_login": serializers.BooleanField(),
                "date_format": serializers.CharField(allow_null=True),
                "social_accounts": serializers.ListField(
                    child=serializers.DictField()
                ),
            },
            many=True,
        ),
    )
    def get(self, request):
        search = request.GET.get("search", None)

        if search:
            users = User.objects.filter(agent=None, is_installer_user=False).filter(
                username__icontains=search
            )
        else:
            users = User.objects.filter(agent=None, is_installer_user=False)

        return Response(self.UserSerializerSSO(users, many=True).data)

    @extend_schema(
        tags=["accounts"],
        summary="Add a user",
        request=inline_serializer(
            name="AccountsAddUserRequest",
            fields={
                "username": serializers.CharField(),
                "email": serializers.CharField(),
                "password": serializers.CharField(),
                "first_name": serializers.CharField(required=False),
                "last_name": serializers.CharField(required=False),
                "role": serializers.IntegerField(required=False),
            },
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Username of the created user")},
    )
    def post(self, request):
        # add new user
        validate_username = UnicodeUsernameValidator()
        try:
            validate_username(request.data["username"])
        except ValidationError as e:
            return notify_error(str(e))

        try:
            user = User.objects.create_user(  # type: ignore
                request.data["username"],
                request.data["email"],
                request.data["password"],
            )
        except IntegrityError:
            return notify_error(
                f"ERROR: User {request.data['username']} already exists!"
            )

        if "first_name" in request.data.keys():
            user.first_name = request.data["first_name"]
        if "last_name" in request.data.keys():
            user.last_name = request.data["last_name"]
        if "role" in request.data.keys() and isinstance(request.data["role"], int):
            role = get_object_or_404(Role, pk=request.data["role"])
            user.role = role

        user.save()
        sync_mesh_perms_task.delay()
        return Response(user.username)


@extend_schema(
    tags=["accounts"],
    parameters=[
        OpenApiParameter(
            "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
            description="User primary key.",
        )
    ],
)
class GetUpdateDeleteUser(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms]

    @extend_schema(summary="Get a single user", responses=UserSerializer)
    def get(self, request, pk):
        user = get_object_or_404(User, pk=pk)

        return Response(UserSerializer(user).data)

    @extend_schema(
        summary="Update a user",
        description="Partially updates a user. The root user cannot be modified.",
        request=UserSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request, pk):
        user = get_object_or_404(User, pk=pk)

        if is_root_user(request=request, user=user):
            return notify_error("The root user cannot be modified from the UI")

        serializer = UserSerializer(instance=user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        sync_mesh_perms_task.delay()

        return Response("ok")

    @extend_schema(
        summary="Delete a user",
        description="Deletes a user. The root user cannot be deleted.",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        if is_root_user(request=request, user=user):
            return notify_error("The root user cannot be deleted from the UI")

        user.delete()
        sync_mesh_perms_task.delay()
        return Response("ok")


class UserActions(APIView):
    permission_classes = [IsAuthenticated, AccountsPerms, LocalUserPerms]

    # reset password
    @extend_schema(
        tags=["accounts"],
        summary="Reset a user's password",
        description="Sets a new password for the specified user. The root user cannot "
        "be modified.",
        request=inline_serializer(
            name="AccountsResetPasswordRequest",
            fields={
                "id": serializers.IntegerField(help_text="User primary key."),
                "password": serializers.CharField(),
            },
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request):
        user = get_object_or_404(User, pk=request.data["id"])
        if is_root_user(request=request, user=user):
            return notify_error("The root user cannot be modified from the UI")

        user.set_password(request.data["password"])
        user.save()

        return Response("ok")

    # reset two factor token
    @extend_schema(
        tags=["accounts"],
        summary="Reset a user's two-factor token",
        description="Clears the TOTP two-factor key for the specified user so they can "
        "set it up again on next sign in. The root user cannot be modified.",
        request=inline_serializer(
            name="AccountsResetTotpRequest",
            fields={"id": serializers.IntegerField(help_text="User primary key.")},
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request):
        user = get_object_or_404(User, pk=request.data["id"])
        if is_root_user(request=request, user=user):
            return notify_error("The root user cannot be modified from the UI")

        user.totp_key = ""
        user.save()

        return Response(
            f"{user.username}'s Two-Factor key was reset. Have them sign in again to setup"
        )


class TOTPSetup(GenericPermsViewMixin, APIView):
    # totp setup
    @extend_schema(
        tags=["accounts"],
        summary="Set up two-factor authentication for the current user",
        description="Generates and stores a new TOTP key for the authenticated user if "
        "one is not already set, returning the key and provisioning QR URL. Returns "
        "`false` if a key already exists.",
        request=None,
        responses={
            200: TOTPSetupSerializer,
        },
    )
    def post(self, request):
        user = request.user
        if not user.totp_key:
            code = pyotp.random_base32()
            user.totp_key = code
            user.save(update_fields=["totp_key"])
            return Response(TOTPSetupSerializer(user).data)

        return Response(False)


class UserUI(GenericPermsViewMixin, APIView):
    @extend_schema(
        tags=["accounts"],
        summary="Update the current user's UI preferences",
        request=UserUISerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def patch(self, request):
        serializer = UserUISerializer(
            instance=request.user, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response("ok")


class GetAddRoles(APIView):
    permission_classes = [IsAuthenticated, RolesPerms]

    @extend_schema(
        tags=["accounts"],
        summary="List roles",
        responses=RoleSerializer(many=True),
    )
    def get(self, request):
        roles = Role.objects.all()
        return Response(RoleSerializer(roles, many=True).data)

    @extend_schema(
        tags=["accounts"],
        summary="Add a role",
        request=RoleSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response("Role was added")


@extend_schema(
    tags=["accounts"],
    parameters=[
        OpenApiParameter(
            "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
            description="Role primary key.",
        )
    ],
)
class GetUpdateDeleteRole(APIView):
    permission_classes = [IsAuthenticated, RolesPerms]

    @extend_schema(summary="Get a single role", responses=RoleSerializer)
    def get(self, request, pk):
        role = get_object_or_404(Role, pk=pk)
        return Response(RoleSerializer(role).data)

    @extend_schema(
        summary="Update a role",
        request=RoleSerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request, pk):
        role = get_object_or_404(Role, pk=pk)
        serializer = RoleSerializer(instance=role, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        sync_mesh_perms_task.delay()
        return Response("Role was edited")

    @extend_schema(
        summary="Delete a role",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        role = get_object_or_404(Role, pk=pk)
        role.delete()
        sync_mesh_perms_task.delay()
        return Response("Role was removed")


class GetAddAPIKeys(APIView):
    permission_classes = [IsAuthenticated, APIKeyPerms]

    @extend_schema(
        tags=["accounts"],
        summary="List API keys",
        responses=APIKeySerializer(many=True),
    )
    def get(self, request):
        apikeys = APIKey.objects.all()
        return Response(APIKeySerializer(apikeys, many=True).data)

    @extend_schema(
        tags=["accounts"],
        summary="Add an API key",
        description="Creates a new API key. The key value itself is generated "
        "server-side and any supplied `key` is ignored.",
        request=APIKeySerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def post(self, request):
        # generate a random API Key
        from django.utils.crypto import get_random_string

        request.data["key"] = get_random_string(length=32).upper()
        serializer = APIKeySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response("The API Key was added")


@extend_schema(
    tags=["accounts"],
    parameters=[
        OpenApiParameter(
            "pk", OpenApiTypes.INT, OpenApiParameter.PATH,
            description="API key primary key.",
        )
    ],
)
class GetUpdateDeleteAPIKey(APIView):
    permission_classes = [IsAuthenticated, APIKeyPerms]

    @extend_schema(
        summary="Update an API key",
        description="Updates an API key. The `key` value cannot be changed and is "
        "ignored if supplied.",
        request=APIKeySerializer,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request, pk):
        apikey = get_object_or_404(APIKey, pk=pk)

        # remove API key is present in request data
        if "key" in request.data.keys():
            request.data.pop("key")

        serializer = APIKeySerializer(instance=apikey, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response("The API Key was edited")

    @extend_schema(
        summary="Delete an API key",
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def delete(self, request, pk):
        apikey = get_object_or_404(APIKey, pk=pk)
        apikey.delete()
        return Response("The API Key was deleted")


class ResetPass(APIView):
    permission_classes = [IsAuthenticated, SelfResetSSOPerms]

    @extend_schema(
        tags=["accounts"],
        summary="Reset the current user's password",
        request=inline_serializer(
            name="AccountsSelfResetPasswordRequest",
            fields={"password": serializers.CharField()},
        ),
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request):
        user = request.user
        user.set_password(request.data["password"])
        user.save()
        return Response("Password was reset.")


class Reset2FA(APIView):
    permission_classes = [IsAuthenticated, SelfResetSSOPerms]

    @extend_schema(
        tags=["accounts"],
        summary="Reset the current user's two-factor token",
        request=None,
        responses={200: OpenApiResponse(OpenApiTypes.STR, description="Confirmation message")},
    )
    def put(self, request):
        user = request.user
        user.totp_key = ""
        user.save()
        return Response("2FA was reset. Log out and back in to setup.")
