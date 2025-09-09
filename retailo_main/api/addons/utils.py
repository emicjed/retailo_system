import re

import random
import string

from secrets import token_urlsafe

from decouple import config
from django.core.validators import EmailValidator
from django.core.exceptions import ValidationError

from django.db.models import Model
from .mailsender import send_otp_email
import json
from django.http import JsonResponse

from typing import Iterable, Mapping, Tuple, List

import logging
logger = logging.getLogger(__name__)

def json_body(request):
    try:
        return json.loads(request.body or b"{}")
    except Exception:
        return None

def require_fields(data: dict, fields: list[str]):
    missing = [f for f in fields if not (str(data.get(f) or "").strip())]
    if missing:
        return JsonResponse({"detail": f"Missing fields: {', '.join(missing)}"}, status=400)
    return None

def validate_email_strict(email: str) -> None:
    if not email:
        raise ValidationError("Email is required")
    EmailValidator()(email.strip())


def normalize_email(email: str | None) -> str | None:
    return None if email is None else email.strip().lower()


PL_TO_ASCII = str.maketrans({
    "ą":"a","ć":"c","ę":"e","ł":"l","ń":"n","ó":"o","ś":"s","ź":"z","ż":"z",
    "Ą":"A","Ć":"C","Ę":"E","Ł":"L","Ń":"N","Ó":"O","Ś":"S","Ź":"Z","Ż":"Z",
})

def _strip_pl(text: str) -> str:
    return (text or "").translate(PL_TO_ASCII)

def _compact_login(text: str) -> str:
    ascii_txt = _strip_pl(text).lower()
    return re.sub(r"[^a-z0-9]+", "", ascii_txt)

def make_admin_login(first_name: str, last_name: str) -> str:
    base = f"{_compact_login(first_name)}.{_compact_login(last_name)}".strip(".")
    base = re.sub(r"\.+", ".", base)
    return base or "admin"


def ensure_unique_login(model: type[Model], base_login: str, field_name: str = "login") -> str:
    if not base_login:
        base_login = "admin"
    candidate = base_login
    n = 0
    lookup = {f"{field_name}__iexact": candidate}
    while model.objects.filter(**lookup).exists():
        n += 1
        candidate = f"{base_login}{n}"
        lookup = {f"{field_name}__iexact": candidate}
        if n > 9999:
            raise RuntimeError("Unable to generate unique login")
    return candidate


def generate_user_token(prefix: str = "usr", entropy_bytes: int = 16) -> str:
    core = token_urlsafe(entropy_bytes)
    return f"{prefix}_{core}" if prefix else core


def ensure_unique_user_token(
    model: type[Model],
    field_name: str = "user_token",
    prefix: str = "usr",
    entropy_bytes: int = 16,
    max_tries: int = 20,
) -> str:
    for _ in range(max_tries):
        token = generate_user_token(prefix=prefix, entropy_bytes=entropy_bytes)
        if not model.objects.filter(**{field_name: token}).exists():
            return token
    raise RuntimeError("Failed to generate a unique user_token (max tries exceeded)")


def generate_numeric_code(length: int | None = None) -> str:
    n = length or int(config("OTP_CODE_LENGTH", default=6, cast=int))
    return "".join(random.choices(string.digits, k=n))


def hash_otp(code: str) -> str:
    import hashlib
    pepper = config("OTP_PEPPER", default="change-me")
    return hashlib.sha256((code + pepper).encode("utf-8")).hexdigest()


def create_email_otp(user, purpose: str = "LOGIN", request_ip: str | None = None):
    from django.utils import timezone
    from ..models import EmailOTP

    ttl = int(config("OTP_TTL_MINUTES", default=10, cast=int))
    code = generate_numeric_code()
    otp = EmailOTP.objects.create(
        user=user,
        purpose=purpose,
        code_hash=hash_otp(code),
        expires_at=timezone.now() + timezone.timedelta(minutes=ttl),
        max_attempts=int(config("OTP_MAX_ATTEMPTS", default=5, cast=int)),
        request_ip=request_ip,
    )
    email = getattr(getattr(user, "administration_profile", None), "email_address", None)
    if not email:
        otp.delete()
        raise ValueError("User has no email address associated (administration_profile.email_address is missing)")

    try:
        send_otp_email(email, code, purpose)
    except Exception:
        logger.exception("send_otp_email failed (user=%s, email=%s, purpose=%s)", user.id, email, purpose)
        try:
            otp.delete()
        except Exception: logger.warning("Failed to delete OTP after send error", exc_info=True)
        raise

    return code, otp

def validate_password_policy(p: str, min_len: int = 8, max_len: int = 100) -> None:
    if p is None:
        raise ValueError("Hasło jest wymagane.")
    L = len(p)
    if L < min_len or L > max_len:
        raise ValueError(f"Hasło musi mieć {min_len}-{max_len} znaków.")
    if not re.search(r"[A-ZĄĆĘŁŃÓŚŹŻ]", p):
        raise ValueError("Hasło musi zawierać minimum 1 wielką literę.")
    if not re.search(r"[^\w\s]", p, flags=re.UNICODE):
        raise ValueError("Hasło musi zawierać minimum 1 znak specjalny.")


def update_instance_fields(
    instance,
    values: Mapping[str, object],
    allowed: Iterable[str] | None = None,
    save: bool = True,
    touch_updated_at: bool = True,
) -> Tuple[bool, List[str]]:
    allowed_set = set(allowed) if allowed is not None else None
    to_set: dict[str, object] = {}

    for field, new_val in values.items():
        if allowed_set is not None and field not in allowed_set:
            continue
        if not hasattr(instance, field):
            continue
        if getattr(instance, field) != new_val:
            to_set[field] = new_val

    if not to_set:
        return False, []

    for field, new_val in to_set.items():
        setattr(instance, field, new_val)

    changed_fields = list(to_set.keys())

    if touch_updated_at and hasattr(instance, "updated_at"):
        if "updated_at" not in changed_fields:
            changed_fields.append("updated_at")

    if save:
        instance.save(update_fields=changed_fields)

    return True, changed_fields



