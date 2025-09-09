# api/addons/http.py
from __future__ import annotations

import inspect
import json
from functools import wraps
from typing import Callable, Any
from pathlib import Path

from django.http import JsonResponse
from django.conf import settings
from django.utils import timezone

_SENSITIVE_KEYS = ("password", "code", "secret")

def _logs_dir() -> Path:
    base = Path(getattr(settings, "BASE_DIR", Path(__file__).resolve().parents[3]))
    d = base / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _redact_shallow(d: dict | None) -> dict:
    if not isinstance(d, dict):
        return {}
    out = {}
    for k, v in d.items():
        if any(s in k.lower() for s in _SENSITIVE_KEYS):
            out[k] = "***"
        else:
            out[k] = v if isinstance(v, (int, float, bool)) else str(v)[:500]
    return out

def _log_http(request, status: int, kind: str, detail: str | None = None, extra: dict | None = None) -> None:
    try:
        fname = _logs_dir() / f"http_{timezone.localdate().strftime('%Y%m%d')}.log"
        ts = timezone.localtime().strftime("%Y-%m-%d %H:%M:%S%z")
        method = getattr(request, "method", "-")
        path = getattr(request, "path", "-")
        ip = getattr(request, "META", {}).get("REMOTE_ADDR", "-") if request else "-"
        user_token = "-"
        payload = getattr(request, "jwt", None)
        if isinstance(payload, dict):
            user_token = str(payload.get("sub") or payload.get("uid") or "-")

        parts = [ts, method, path, str(status), user_token, kind]
        line = " - ".join(parts)

        if detail:
            line += f" - {detail}"
        if extra:
            try:
                line += f" - {json.dumps(_redact_shallow(extra), ensure_ascii=False)}"
            except Exception:
                line += f" - {str(_redact_shallow(extra))}"

        with open(fname, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def json_ok(data: dict, status: int = 200, *, request=None, event: str = "OK") -> JsonResponse:
    _log_http(request, status, event, extra=data)
    return JsonResponse(data, status=status, json_dumps_params={"ensure_ascii": False})

def json_err(detail: str, status: int = 400, extra: dict | None = None, *, request=None, event: str = "ERR") -> JsonResponse:
    payload = {"detail": detail}
    if extra:
        payload.update(extra)
    _log_http(request, status, event, detail=detail, extra=payload)
    return JsonResponse(payload, status=status, json_dumps_params={"ensure_ascii": False})


def with_json_body(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        request = None
        if len(args) >= 2 and hasattr(args[1], "META"):
            request = args[1]
        elif len(args) >= 1 and hasattr(args[0], "META"):
            request = args[0]

        if request is None:
            from .http import json_err
            return json_err("with_json_body: request not found.", status=500)
        raw = getattr(request, "body", b"") or b""
        if raw:
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                from .http import json_err
                return json_err("Malformed JSON body.", status=400)
        else:
            body = {}
        kwargs["body"] = body
        return func(*args, **kwargs)
    return wrapper


def require_fields(required_fields):
    from functools import wraps
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            body = kwargs.get("body")
            if not isinstance(body, dict):
                from .http import json_err
                return json_err("Invalid or missing JSON body.", status=400)
            missing = [f for f in required_fields if f not in body]
            if missing:
                from .http import json_err
                return json_err(f"Missing required fields: {', '.join(missing)}", status=400)
            return func(*args, **kwargs)
        return wrapper
    return decorator