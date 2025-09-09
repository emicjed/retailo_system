from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt

from .controllers.Administration import AdministrationController
from .controllers.Authorization import AuthorizationController
from .controllers.PasswordReset import AdministrationResetPasswordController
import jwt as pyjwt
from decouple import config
from functools import wraps
from .addons.http import json_err as _err
from .addons.http import json_ok as _ok


def _authenticate_request(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    parts = auth.split()
    if len(parts) == 2 and parts[0] == "Bearer":
        token = parts[1]
    elif len(parts) == 1 and parts[0]:
        token = parts[0]
    else:
        return False, _err("Authentication credentials were not provided.", 401)
    try:
        payload = pyjwt.decode(
            token,
            config("JWT_SECRET_KEY"),
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
        if not payload.get("sub"):
            return False, _err("Invalid token (missing sub).", 401)
        request.jwt = payload
        return True, None
    except pyjwt.ExpiredSignatureError:
        return False, _err("Token expired.", 401)
    except pyjwt.InvalidTokenError:
        return False, _err("Invalid token.", 401)

def jwt_required(method):
    @wraps(method)
    def _wrapper(self, request, *args, **kwargs):
        ok, resp = _authenticate_request(request)
        if not ok:
            return resp
        return method(self, request, *args, **kwargs)
    return _wrapper


@method_decorator(csrf_exempt, name="dispatch")
class LoginStep1View(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AuthorizationController()
    def post(self, request, *args, **kwargs):
        return self.ctrl.login_step1(request)

@method_decorator(csrf_exempt, name="dispatch")
class LoginStep2View(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AuthorizationController()
    def post(self, request, *args, **kwargs):
        return self.ctrl.login_step2(request)

@method_decorator(csrf_exempt, name="dispatch")
class ForcePasswordChangeView(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AuthorizationController()
    def post(self, request, *args, **kwargs):
        return self.ctrl.force_password_change(request)

@method_decorator(csrf_exempt, name="dispatch")
class PasswordChangeStartView(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AuthorizationController()
    @jwt_required
    def post(self, request, *args, **kwargs):
        return self.ctrl.password_change_start(request)

@method_decorator(csrf_exempt, name="dispatch")
class PasswordChangeConfirmView(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AuthorizationController()
    @jwt_required
    def post(self, request, *args, **kwargs):
        return self.ctrl.password_change_confirm(request)

@method_decorator(csrf_exempt, name="dispatch")
class AdministrationResetPassword(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AdministrationResetPasswordController()

    def get(self, request, *args, **kwargs):
        return self.ctrl.activate(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.ctrl.reset_password(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.ctrl.set_password(request, *args, **kwargs)

@method_decorator(csrf_exempt, name="dispatch")
class AdministrationGroups(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AdministrationController()

    def post(self, request, *args, **kwargs):
        return self.ctrl.create_group(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if "uuid" in kwargs and kwargs["uuid"]:
            return self.ctrl.get_group(request, str(kwargs["uuid"]))
        return self.ctrl.list_groups(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        if "uuid" not in kwargs or not kwargs["uuid"]:
            return _err("Group UUID is required in path.", status=400)
        k = dict(kwargs)
        uuid_val = str(k.pop("uuid"))
        return self.ctrl.update_group(request, uuid=uuid_val, **k)

@method_decorator(csrf_exempt, name="dispatch")
class AdministrationAccessMetadata(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AdministrationController()

    def get(self, request, *args, **kwargs):
        return self.ctrl.access_metadata(request, *args, **kwargs)

class AdministrationUsers(View):
    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.ctrl = AdministrationController()

    def post(self, request, *args, **kwargs):
        return self.ctrl.create_user(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        uuid_val = kwargs.get("uuid")
        if not uuid_val:
            return _err("Missing 'uuid' in path.", status=400)
        return self.ctrl.update_user(request, uuid=str(uuid_val))

    def get(self, request, *args, **kwargs):
        if "uuid" in kwargs and kwargs["uuid"]:
            return self.ctrl.get_user(request, uuid=str(kwargs["uuid"]))
        privilege = (request.GET.get("privilege") or "ADMIN").strip().upper()
        if privilege == "ADMIN":
            return self.ctrl.list_admins(request, *args, **kwargs)
        if privilege == "MANAGER":
            # future: return self.ctrl.list_managers(request, *args, **kwargs)
            return _err("Not implemented: managers list.", status=501)
        if privilege == "WORKER":
            # future: return self.ctrl.list_workers(request, *args, **kwargs)
            return _err("Not implemented: workers list.", status=501)
        return _err("Invalid 'privilege'. Allowed: ADMIN, MANAGER, WORKER.", status=400)

    def delete(self, request, *args, **kwargs):
        uuid_val = kwargs.get("uuid")
        if not uuid_val:
            return _err("Missing 'uuid' in path.", status=400)
        action = (request.GET.get("action") or "").strip().lower()
        if action == "block":
            return self.ctrl.block_user(request, uuid=str(uuid_val))
        if action == "unblock":
            return self.ctrl.unblock_user(request, uuid=str(uuid_val))
        return _err("Invalid 'action'. Allowed: block, unblock.", status=400)