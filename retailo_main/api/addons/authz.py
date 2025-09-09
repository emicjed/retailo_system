# api/addons/authz.py
from __future__ import annotations
from functools import wraps
from typing import Any, Optional

from .http import json_err
from .authentication import get_jwt_payload

def _extract_request(args: tuple, kwargs: dict) -> Optional[Any]:
    if "request" in kwargs and hasattr(kwargs["request"], "META"):
        return kwargs["request"]
    if len(args) >= 2 and hasattr(args[1], "META"):
        return args[1]
    if len(args) >= 1 and hasattr(args[0], "META"):
        return args[0]
    return None

def with_jwt_payload(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        request = _extract_request(args, kwargs)
        if request is None:
            return json_err("with_jwt_payload: request not found.", status=500)

        try:
            payload = get_jwt_payload(request)
        except ValueError:
            return json_err("Authentication credentials were not provided.", status=401)
        except PermissionError as e:
            return json_err(str(e), status=401)

        kwargs["jwt_payload"] = payload
        return func(*args, **kwargs)
    return wrapper


def require_module_level(module_code: str, min_level: int):
    from ..models import Access

    target = (str(module_code) or "").strip().lower()

    def _has_module_level(jwt_payload: dict) -> bool:
        modules = jwt_payload.get("modules")
        if not modules:
            return False

        def to_int(x):
            try:
                return int(x)
            except Exception:
                return None

        if isinstance(modules, dict):
            for k, v in modules.items():
                if str(k).strip().lower() == target:
                    lvl = to_int(v)
                    return lvl is not None and lvl >= int(min_level)
            return False
        if isinstance(modules, list) and any(isinstance(it, dict) for it in modules):
            for it in modules:
                if isinstance(it, dict):
                    m = (it.get("module") or it.get("code") or it.get("name") or "").strip().lower()
                    if m == target:
                        lvl = to_int(it.get("level"))
                        return lvl is not None and lvl >= int(min_level)
            return False
        if isinstance(modules, list) and all(isinstance(it, str) for it in modules):
            if any((m or "").strip().lower() == target for m in modules):
                user_id = jwt_payload.get("user_id")
                if not user_id:
                    return False
                lvl = (
                    Access.objects
                    .filter(user_id=user_id, module=module_code)
                    .values_list("level", flat=True)
                    .first()
                )
                return lvl is not None and int(lvl) >= int(min_level)
            return False

        return False

    @wraps(require_module_level)
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            payload = kwargs.get("jwt_payload")

            if payload is None:
                request = _extract_request(args, kwargs)
                if request is None:
                    return json_err("require_module_level: request not found.", status=500)
                try:
                    payload = get_jwt_payload(request)
                except ValueError:
                    return json_err("Authentication credentials were not provided.", status=401)
                except PermissionError as e:
                    return json_err(str(e), status=401)

            if not _has_module_level(payload):
                return json_err("Forbidden: FULL access to administration module required.", status=403)

            return func(*args, **kwargs)
        return wrapper
    return decorator
