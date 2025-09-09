# api/controllers/PasswordResetController.py
import logging
from django.utils import timezone

from ..addons.http import json_ok as _ok, json_err as _err, with_json_body, require_fields
from ..addons.authentication import generate_jwt, decode_jwt
from ..addons.utils import create_email_otp, hash_otp, validate_password_policy
from ..models import Administration, Authorization, EmailOTP, UserIdentifier


def _mask_email(email: str) -> str:
    if not email or "@" not in email:
        return "—"
    local, _, domain = email.partition("@")
    if not local:
        local_mask = "***"
    else:
        local_mask = local[0] + "***" + (local[-1] if len(local) > 1 else "")
    if not domain:
        domain_mask = "***"
    else:
        parts = domain.split(".")
        if parts and parts[0]:
            parts[0] = parts[0][0] + "***"
        domain_mask = ".".join(parts) if parts else "***"
    return f"{local_mask}@{domain_mask}"

def _role_name(user: UserIdentifier) -> str:
    return (getattr(getattr(user, "user_privilege", None), "name", "") or "").upper()

def _issue_reset_token(user_token: str) -> str:
    return generate_jwt({"sub": user_token, "token_type": "pwd_reset"}, exp_hours=1)


def _verify_reset_token(token: str) -> str | None:
    try:
        payload = decode_jwt(token)
        if payload.get("token_type") != "pwd_reset":
            return None
        return payload.get("sub")
    except Exception:
        return None


class AdministrationResetPasswordController:
    def activate(self, request, *args, **kwargs):
        token = (request.GET.get("token") or "").strip()
        user_token = _verify_reset_token(token)
        if not user_token:
            return _err("Invalid or expired token", 400)
        return _ok({"token_valid": True})

    @with_json_body
    def reset_password(self, request, *args, **kwargs):
        body = request.json
        if missing := require_fields(body, ["username_or_email"]):
            return _err(f"Missing fields: {', '.join(missing)}")

        username_or_email = body["username_or_email"].strip()
        qs = Administration.objects.select_related("user")
        admin = (
            qs.filter(email_address__iexact=username_or_email).first()
            if "@" in username_or_email
            else qs.filter(login__iexact=username_or_email).first()
        )

        generic_ok = {"detail": "If the account exists, instructions were sent."}

        if not admin or not admin.is_active or admin.user.user_status != admin.user.Status.ACTIVE\
                or _role_name(admin.user) not in ("ADMIN,MANAGER"):
            return _ok(generic_ok)

        reset_token = _issue_reset_token(admin.user.user_token)
        try:
            _, otp = create_email_otp(
                user=admin.user,
                purpose=EmailOTP.Purpose.RESET,
                request_ip=request.META.get("REMOTE_ADDR"),
            )
            return _ok({
                **generic_ok,
                "reset_token": reset_token,
                "challenge_id": str(otp.id),
                "expires_at": otp.expires_at.isoformat(),
                "email_masked": _mask_email(admin.email_address or ""),
            })
        except Exception:
            logging.exception("OTP send failed during password reset")
            return _ok(generic_ok)

    @with_json_body
    def set_password(self, request, *args, **kwargs):
        body = request.json
        if missing := require_fields(body, ["reset_token", "challenge_id", "code", "new_password", "new_password_confirm"]):
            return _err(f"Missing fields: {', '.join(missing)}")

        token = body["reset_token"].strip()
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

        user_token = _verify_reset_token(token)
        if not user_token:
            return _err("Invalid or expired token", 400)

        try:
            user = UserIdentifier.objects.get(user_token=user_token)
        except UserIdentifier.DoesNotExist:
            return _err("Invalid token user", 400)

        try:
            otp = EmailOTP.objects.select_related("user").get(
                id=challenge_id,
                user=user,
                purpose=EmailOTP.Purpose.RESET,
            )
        except EmailOTP.DoesNotExist:
            return _err("Invalid challenge", 400)

        if otp.used_at is not None or otp.is_expired():
            return _err("Code expired or already used", 400)
        if otp.attempts >= otp.max_attempts:
            return _err("Too many attempts", 429)
        if hash_otp(code) != otp.code_hash:
            otp.attempts += 1
            otp.save(update_fields=["attempts"])
            return _err("Invalid code", 400)

        try:
            auth = Authorization.objects.get(user=user)
        except Authorization.DoesNotExist:
            return _err("Authorization record missing", 400)

        if auth.password_used_before(new_password):
            return _err("Password was used before")

        auth.set_password(new_password)
        otp.mark_used()

        return _ok({"detail": "Password reset successfully."})
