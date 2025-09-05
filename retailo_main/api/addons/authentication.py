# api/addons/authentication.py
from __future__ import annotations
import jwt as pyjwt
from datetime import datetime, timedelta, timezone
from decouple import config

def generate_jwt(payload: dict, exp_hours: int | None = None) -> str:
    """Tworzy JWT (HS256) z iat/exp oraz opcjonalnym iss/aud z .env."""
    if not isinstance(payload, dict) or not payload:
        raise ValueError("payload must be a non-empty dict")
    secret = config("JWT_SECRET_KEY")
    hours = int(exp_hours or config("TOKEN_EXPIRATION", default=8, cast=int))
    now_utc = datetime.now(timezone.utc)
    body = {
        **payload,
        "iat": int(now_utc.timestamp()),
        "exp": int((now_utc + timedelta(hours=hours)).timestamp()),
    }
    issuer = config("JWT_ISSUER", default=None)
    audience = config("JWT_AUDIENCE", default=None)
    if issuer:
        body["iss"] = issuer
    if audience:
        body["aud"] = audience
    token = pyjwt.encode(body, secret, algorithm="HS256")
    return token if isinstance(token, str) else token.decode("utf-8")

def extract_bearer_token(request) -> str | None:
    """Zwraca token z nagłówka Authorization (obsługuje 'Bearer <tok>' oraz sam token)."""
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    parts = auth.split()
    if len(parts) == 2 and parts[0] == "Bearer":
        return parts[1]
    if len(parts) == 1 and parts[0]:
        return parts[0]
    return None

def decode_jwt(token: str) -> dict:
    """Dekoduje i weryfikuje JWT wg .env (HS256, iss/aud gdy ustawione)."""
    secret = config("JWT_SECRET_KEY")
    issuer = config("JWT_ISSUER", default=None)
    audience = config("JWT_AUDIENCE", default=None)
    options = {"verify_aud": bool(audience)}
    return pyjwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer=issuer or None,
        audience=audience or None,
        options=options,
    )

def get_jwt_payload(request) -> dict:
    """Pobiera payload z requestu; rzuca:
       - ValueError, gdy brak tokenu
       - PermissionError, gdy token wygasł/niepoprawny
    """
    token = extract_bearer_token(request)
    if not token:
        raise ValueError("Authentication credentials were not provided.")
    try:
        return decode_jwt(token)
    except pyjwt.ExpiredSignatureError as e:
        raise PermissionError("Token expired.") from e
    except pyjwt.InvalidTokenError as e:
        raise PermissionError("Invalid token.") from e
