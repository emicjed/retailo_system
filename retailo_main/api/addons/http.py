# api/addons/http.py
from __future__ import annotations
import json
from functools import wraps
from typing import Callable, Any
from django.http import JsonResponse

def json_ok(data: dict, status: int = 200) -> JsonResponse:
    return JsonResponse(data, status=status, json_dumps_params={"ensure_ascii": False})

def json_err(detail: str, status: int = 400, extra: dict | None = None) -> JsonResponse:
    payload = {"detail": detail}
    if extra:
        payload.update(extra)
    return JsonResponse(payload, status=status, json_dumps_params={"ensure_ascii": False})

def with_json_body(func: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(func)
    def wrapper(self, request, *args, **kwargs):
        try:
            request.json = json.loads(request.body or b"{}")
        except Exception:
            return json_err("Invalid JSON", 400)
        return func(self, request, *args, **kwargs)
    return wrapper

def require_fields(data: dict, fields: list[str]) -> list[str]:
    missing = []
    for f in fields:
        v = data.get(f)
        if isinstance(v, str):
            v = v.strip()
        if not v:
            missing.append(f)
    return missing
