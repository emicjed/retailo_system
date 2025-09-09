# api/controllers/Authorization.py
from datetime import timedelta

from decouple import config
from django.utils import timezone
from django.contrib.auth.hashers import check_password as dj_check

from ..addons.http import json_ok as _ok, json_err as _err, with_json_body, require_fields
from ..addons.authentication import generate_jwt, get_jwt_payload, decode_jwt
from ..models import Administration, Authorization, EmailOTP, Access, UserIdentifier
from ..addons.utils import create_email_otp, hash_otp, validate_password_policy

PASSWORD_MAX_AGE_DAYS = int(config("PASSWORD_MAX_AGE_DAYS", default=45, cast=int))
LOCK_ATTEMPTS = int(config("LOCK_ATTEMPTS", default=3, cast=int))
LOCK_MINUTES = int(config("LOCK_MINUTES", default=15, cast=int))


def _mask_email(email: str) -> str:
    if not email or "@" not in email:
        return "—"
    local, _, domain = email.partition("@")
    masked_local = local[0] + "***" + (local[-1] if len(local) > 1 else "")
    parts = domain.split(".")
    parts[0] = parts[0][0] + "***"
    return masked_local + "@" + ".".join(parts)


def _password_needs_change(admin: Administration, auth: Authorization) -> tuple[bool, str | None]:

    if admin.last_login_at is None:
        return True, "first_login"
    if timezone.now() - auth.updated_at >= timedelta(days=PASSWORD_MAX_AGE_DAYS):
        return True, "expired"
    return False, None


def _issue_change_token(user_token: str) -> str:
    return generate_jwt({"sub": user_token, "token_type": "pwd_change"}, exp_hours=1)


def _verify_change_token(token: str) -> str | None:
    try:
        payload = decode_jwt(token)
        if payload.get("token_type") != "pwd_change":
            return None
        return payload.get("sub")
    except Exception:
        return None


def _role_name(user: UserIdentifier) -> str:
    return (getattr(getattr(user, "user_privilege", None), "name", "") or "").upper()


def _is_allowed_role(user: UserIdentifier) -> bool:
    return _role_name(user) in ("ADMIN", "MANAGER")


def _clear_initial_password_if_present(user: UserIdentifier) -> None:
    try:
        auth = Authorization.objects.get(user=user)
    except Authorization.DoesNotExist:
        return
    if getattr(auth, "initial_password_encrypted", None):
        auth.initial_password_encrypted = None
        auth.save(update_fields=["initial_password_encrypted", "updated_at"])


class AuthorizationController:
    @with_json_body
    @require_fields(["username_or_email", "password"])
    def login_step1(self, request, body=None):
        username_or_email = body["username_or_email"].strip()
        password = body["password"]
        qs = Administration.objects.select_related("user")
        admin = (
            qs.filter(email_address__iexact=username_or_email).first()
            if "@" in username_or_email
            else qs.filter(login__iexact=username_or_email).first()
        )

        if not admin or not admin.is_active:
            return _err("Invalid credentials")

        user = admin.user
        if user.user_status != user.Status.ACTIVE:
            return _err("Account disabled", 403)

        if not _is_allowed_role(user):
            return _err("Role not permitted to log in", 403)

        try:
            auth = Authorization.objects.get(user=user)
        except Authorization.DoesNotExist:
            return _err("Invalid credentials")

        now = timezone.now()
        if auth.locked_until and now < auth.locked_until:
            return _err("Account locked", 429, {"locked_until": auth.locked_until.isoformat()})

        if not auth.check_password(password, attempt_limit=LOCK_ATTEMPTS, lock_minutes=LOCK_MINUTES):
            return _err("Invalid credentials")

        need_change, reason = _password_needs_change(admin, auth)
        if need_change:
            change_token = _issue_change_token(user.user_token)
            return _ok({"require_password_change": True, "reason": reason, "change_token": change_token}, 403)

        try:
            _, otp = create_email_otp(
                user=user,
                purpose=EmailOTP.Purpose.LOGIN,
                request_ip=request.META.get("REMOTE_ADDR"),
            )
        except Exception:
            return _err("Unable to send OTP", 500)

        return _ok(
            {
                "challenge_id": str(otp.id),
                "expires_at": otp.expires_at.isoformat(),
                "email_masked": _mask_email(admin.email_address or ""),
                "detail": "OTP sent",
            }
        )

    @with_json_body
    @require_fields(["challenge_id", "code"])
    def login_step2(self, request, body=None):

        challenge_id = body["challenge_id"]
        code = body["code"].strip()

        try:
            otp = EmailOTP.objects.select_related("user").get(id=challenge_id, purpose=EmailOTP.Purpose.LOGIN)
        except EmailOTP.DoesNotExist:
            return _err("Invalid challenge")

        now = timezone.now()
        if otp.used_at is not None or otp.is_expired():
            return _err("Code expired or already used")
        if otp.attempts >= otp.max_attempts:
            return _err("Too many attempts", 429)
        if hash_otp(code) != otp.code_hash:
            otp.attempts += 1
            otp.save(update_fields=["attempts"])
            return _err("Invalid code")
        otp.mark_used()
        user = otp.user
        if not _is_allowed_role(user):
            return _err("Role not permitted to log in", 403)

        admin = getattr(user, "administration_profile", None)
        if admin:
            admin.last_login_at = now
            admin.save(update_fields=["last_login_at"])
        _clear_initial_password_if_present(user)

        modules = list(
            Access.objects.filter(user=user, level__gt=Access.Level.NO_ACCESS).values_list("module", flat=True)
        )

        user_token = user.user_token
        payload = {
            "sub": user_token,
            "uid": user_token,
            "user_id": str(user.id),
            "token_type": "access",
            "role": user.user_privilege.name,
            "modules": modules,
            "login": getattr(admin, "login", None),
            "email": getattr(admin, "email_address", None),
        }
        jwt_token = generate_jwt(payload)

        return _ok(
            {
                "access_token": jwt_token,
                "token_type": "Bearer",
                "user": {
                    "id": str(user.id),
                    "user_token": user_token,
                    "login": getattr(admin, "login", None),
                    "email": getattr(admin, "email_address", None),
                    "privilege": user.user_privilege.name,
                },
            }
        )

    @with_json_body
    @require_fields(["change_token", "new_password", "new_password_confirm"])
    def force_password_change(self, request, body=None):
        change_token = body["change_token"].strip()
        new_password = body["new_password"]
        new_password_confirm = body["new_password_confirm"]

        if new_password != new_password_confirm:
            return _err("Passwords do not match")

        try:
            validate_password_policy(new_password)
        except ValueError as e:
            return _err(str(e))

        user_token = _verify_change_token(change_token)
        if not user_token:
            return _err("Invalid change token")

        try:
            user = UserIdentifier.objects.get(user_token=user_token)
        except UserIdentifier.DoesNotExist:
            return _err("Account not found")
        if not _is_allowed_role(user):
            return _err("Role not permitted to log in", 403)
        try:
            auth = Authorization.objects.get(user=user)
        except Authorization.DoesNotExist:
            return _err("Authorization record missing")

        if auth.password_used_before(new_password):
            return _err("Password was used before")

        auth.set_password(new_password)
        try:
            _, otp = create_email_otp(
                user=user,
                purpose=EmailOTP.Purpose.LOGIN,
                request_ip=request.META.get("REMOTE_ADDR"),
            )
        except Exception:
            return _err("Unable to send OTP", 500)

        admin = getattr(user, "administration_profile", None)
        return _ok(
            {
                "challenge_id": str(otp.id),
                "expires_at": otp.expires_at.isoformat(),
                "email_masked": _mask_email(getattr(admin, "email_address", "") or ""),
                "detail": "Password changed. OTP sent.",
            }
        )

    @with_json_body
    @require_fields(["old_password", "new_password", "new_password_confirm"])
    def password_change_start(self, request, body=None):
        try:
            payload = get_jwt_payload(request)
        except (ValueError, PermissionError) as e:
            return _err(str(e), 401)

        old_password = body["old_password"]
        new_password = body["new_password"]
        new_password_confirm = body["new_password_confirm"]

        if new_password != new_password_confirm:
            return _err("Passwords do not match")
        if new_password == old_password:
            return _err("New password must differ from old password")

        try:
            validate_password_policy(new_password)
        except ValueError as e:
            return _err(str(e))

        user_token = payload["sub"]
        try:
            user = UserIdentifier.objects.get(user_token=user_token)
        except UserIdentifier.DoesNotExist:
            return _err("Invalid token user", 401)

        if not _is_allowed_role(user):
            return _err("Role not permitted", 403)
        try:
            auth = Authorization.objects.get(user=user)
        except Authorization.DoesNotExist:
            return _err("Authorization record missing")

        if not dj_check(old_password, auth.password_hash):
            return _err("Invalid old password")

        if auth.password_used_before(new_password):
            return _err("Password was used before")

        try:
            _, otp = create_email_otp(
                user=user,
                purpose=EmailOTP.Purpose.PASSWORD_CHANGE,
                request_ip=request.META.get("REMOTE_ADDR"),
            )
        except Exception:
            return _err("Unable to send OTP", 500)

        admin = getattr(user, "administration_profile", None)
        return _ok(
            {
                "challenge_id": str(otp.id),
                "expires_at": otp.expires_at.isoformat(),
                "email_masked": _mask_email(getattr(admin, "email_address", "") or ""),
                "detail": "OTP sent. Confirm to change password.",
            }
        )

    @with_json_body
    @require_fields(["challenge_id", "code", "new_password", "new_password_confirm"])
    def password_change_confirm(self, request, body=None):
        try:
            payload = get_jwt_payload(request)
        except (ValueError, PermissionError) as e:
            return _err(str(e), 401)

        challenge_id = body["challenge_id"]
        code = body["code"].strip()
        new_password = body["new_password"]
        new_password_confirm = body["new_password_confirm"]

        if new_password != new_password_confirm:
            return _err("Passwords do not match")
        try:
            validate_password_policy(new_password)
        except ValueError as e:
            return _err(str(e))

        user_token = payload["sub"]
        try:
            user = UserIdentifier.objects.get(user_token=user_token)
        except UserIdentifier.DoesNotExist:
            return _err("Invalid token user", 401)

        if not _is_allowed_role(user):
            return _err("Role not permitted", 403)
        try:
            otp = EmailOTP.objects.select_related("user").get(
                id=challenge_id, user=user, purpose=EmailOTP.Purpose.PASSWORD_CHANGE
            )
        except EmailOTP.DoesNotExist:
            return _err("Invalid challenge")

        now = timezone.now()
        if otp.used_at is not None or otp.is_expired():
            return _err("Code expired or already used")
        if otp.attempts >= otp.max_attempts:
            return _err("Too many attempts", 429)
        if hash_otp(code) != otp.code_hash:
            otp.attempts += 1
            otp.save(update_fields=["attempts"])
            return _err("Invalid code")

        try:
            auth = Authorization.objects.get(user=user)
        except Authorization.DoesNotExist:
            return _err("Authorization record missing")

        if auth.password_used_before(new_password):
            return _err("Password was used before")

        auth.set_password(new_password)
        otp.mark_used()

        return _ok({"detail": "Password changed successfully."})
