from django.views import View
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .controllers.Authorization import AuthorizationController
from .controllers.PasswordReset import AdministrationResetPasswordController
import jwt as pyjwt
from decouple import config
from functools import wraps

def _json_ok(data: dict, status: int = 200):
    return JsonResponse(data, status=status, json_dumps_params={"ensure_ascii": False})

def _json_err(detail: str, status: int = 400, extra: dict | None = None):
    payload = {"detail": detail}
    if extra: payload.update(extra)
    return JsonResponse(payload, status=status, json_dumps_params={"ensure_ascii": False})

def _authenticate_request(request):
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    parts = auth.split()
    if len(parts) == 2 and parts[0] == "Bearer":
        token = parts[1]
    elif len(parts) == 1 and parts[0]:
        token = parts[0]
    else:
        return False, _json_err("Authentication credentials were not provided.", 401)
    try:
        payload = pyjwt.decode(
            token,
            config("JWT_SECRET_KEY"),
            algorithms=["HS256"],
            options={"verify_aud": False},
        )
        if not payload.get("sub"):
            return False, _json_err("Invalid token (missing sub).", 401)
        request.jwt = payload
        return True, None
    except pyjwt.ExpiredSignatureError:
        return False, _json_err("Token expired.", 401)
    except pyjwt.InvalidTokenError:
        return False, _json_err("Invalid token.", 401)

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
