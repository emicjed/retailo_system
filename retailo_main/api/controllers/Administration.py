# api/controllers/Administration.py
from __future__ import annotations

import logging
import re
import secrets
import string

from django.utils import timezone
from django.db import transaction, IntegrityError
from django.db.models import Q
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from decouple import config

from ..addons.authz import require_module_level, with_jwt_payload
from ..addons.http import json_ok as _ok, json_err as _err, with_json_body, require_fields
from ..addons.pagination import get_pagination_params, paginate_queryset
from ..addons.utils import update_instance_fields, ensure_unique_login, make_admin_login
from ..models import Group, Access, UserIdentifier, UserPrivileges, Administration, Authorization

logger = logging.getLogger(__name__)

MIN_ACCESS_BY_PRIVILEGE = {
    "ADMIN": {Access.ModuleCode.ADMINISTRATION: Access.Level.READ_ONLY},
    "MANAGER": {},
    "WORKER": {},
}


# ----------------------------- Helpers (module-level) -----------------------------

def _to_bool(val) -> bool:
    if val is None:
        return False
    s = str(val).strip().lower()
    return s in {"1", "true", "t", "yes", "y"}


def _decrypt_initial(cipher: bytes) -> str | None:
    if not cipher:
        return None
    try:
        from cryptography.fernet import Fernet  # import lokalny (brak zależności -> brak 500)
    except Exception:
        logger.warning("[INITPWD] cryptography not installed; cannot decrypt initial password.")
        return None
    key = config("INITIAL_PWD_KEY", default="")
    if not key:
        logger.warning("[INITPWD] INITIAL_PWD_KEY missing; cannot decrypt initial password.")
        return None
    try:
        f = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
        return f.decrypt(cipher).decode("utf-8")
    except Exception as e:
        logger.warning(f"[INITPWD] decrypt failed: {e}")
        return None





def _resolve_target(target_uuid: str):
    try:
        adm = (Administration.objects
               .select_related("user", "user__user_privilege")
               .get(id=target_uuid))
        user = adm.user
        return user, user.user_privilege.name.upper(), adm
    except Administration.DoesNotExist:
        pass

    try:
        user = UserIdentifier.objects.select_related("user_privilege").get(id=target_uuid)
        return user, user.user_privilege.name.upper(), None
    except UserIdentifier.DoesNotExist:
        return None, None, None


def _serialize_manager_minimal(user: UserIdentifier) -> dict:
    access_list = [{"module": a.module, "level": int(a.level)} for a in user.accesses.all()]
    return {
        "user": {
            "id": str(user.id),
            "user_token": user.user_token,
            "status": user.user_status,
            "privilege": user.user_privilege.name,  # 'MANAGER'
        },
        "access": access_list,
        # "manager": { ... }  # do uzupełnienia później
    }


# --------------------------------- Controller ------------------------------------

class AdministrationController:

    # ------------------------ Utils / validators / serializers ------------------------

    @staticmethod
    def _enforce_min_access(access_norm: list[dict], privilege: str, autofix: bool = False):
        req = MIN_ACCESS_BY_PRIVILEGE.get((privilege or "").upper(), {})
        if not req:
            return True, access_norm, None

        current = {a["module"]: int(a["level"]) for a in access_norm}
        changed = False

        for mod, min_lvl in req.items():
            cur = current.get(mod)
            if cur is None or cur < int(min_lvl):
                if not autofix:
                    return False, None, f"{privilege} requires {mod} with level >= {int(min_lvl)}"
                current[mod] = int(min_lvl)
                changed = True

        if changed:
            normalized = [{"module": m, "level": l} for m, l in current.items()]
            return True, normalized, None
        return True, access_norm, None

    @staticmethod
    def _gen_group_token(prefix: str = "grp", entropy_bytes: int = 16) -> str:
        core = secrets.token_urlsafe(entropy_bytes)
        return f"{prefix}_{core}" if prefix else core

    @staticmethod
    def _compile_regex_or_error(pattern: str, field_name: str):
        try:
            re.compile(pattern)
        except re.error:
            raise ValueError(f"Invalid {field_name}")

    @staticmethod
    def _has_module_level(jwt_payload: dict, module_code: str, min_level: int) -> bool:
        modules = jwt_payload.get("modules")
        if not modules:
            return False

        target = (module_code or "").lower()

        if isinstance(modules, dict):
            for k, v in modules.items():
                if str(k).lower() == target:
                    try:
                        return int(v) >= int(min_level)
                    except (TypeError, ValueError):
                        return False
            return False

        if isinstance(modules, list) and all(isinstance(it, dict) for it in modules):
            for it in modules:
                m = (it.get("module") or "").lower()
                if m == target:
                    try:
                        return int(it.get("level")) >= int(min_level)
                    except (TypeError, ValueError):
                        return False
            return False

        if isinstance(modules, list) and all(isinstance(it, str) for it in modules):
            if any(m.lower() == target for m in modules):
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

    @staticmethod
    def _generate_initial_password(length: int = 28) -> str:
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def _normalize_email(email: str) -> str:
        return (email or "").strip().lower()

    @staticmethod
    def _validate_access_payload(access_list):
        if not isinstance(access_list, list) or not access_list:
            return False, None, "Field 'access' must be a non-empty list."

        normalized = []
        seen_modules = set()
        valid_modules = {c for c, _ in Access.ModuleCode.choices}

        for item in access_list:
            if not isinstance(item, dict):
                return False, None, "Each access entry must be an object {module, level}."
            module = str(item.get("module", "")).strip().lower()
            try:
                level = int(item.get("level"))
            except (TypeError, ValueError):
                return False, None, "Access 'level' must be an integer."

            if module not in valid_modules:
                return False, None, f"Unknown module '{module}'."
            if level not in [Access.Level.NO_ACCESS, Access.Level.READ_ONLY, Access.Level.READ_WRITE, Access.Level.FULL]:
                return False, None, f"Invalid level {level} for module '{module}'."
            if module in seen_modules:
                return False, None, f"Duplicate module '{module}' in access list."
            seen_modules.add(module)

            normalized.append({"module": module, "level": level})

        return True, normalized, None

    @staticmethod
    def _serialize_admin(adm: Administration) -> dict:
        user = adm.user
        access_list = [{"module": a.module, "level": int(a.level)} for a in user.accesses.all()]
        return {
            "user": {
                "id": str(user.id),
                "user_token": user.user_token,
                "status": user.user_status,
                "privilege": user.user_privilege.name,
            },
            "administration": {
                "id": str(adm.id),
                "login": adm.login,
                "first_name": adm.first_name,
                "last_name": adm.last_name,
                "email_address": adm.email_address,
                "is_active": adm.is_active,
                "last_login_at": adm.last_login_at.isoformat().replace("+00:00", "Z") if adm.last_login_at else None,
                "created_at": adm.created_at.isoformat().replace("+00:00", "Z"),
                "updated_at": adm.updated_at.isoformat().replace("+00:00", "Z"),
            },
            "access": access_list,
        }

    @staticmethod
    def _can_reader_fetch_target(reader_priv: str, target_priv: str) -> bool:
        r = (reader_priv or "").upper()
        t = (target_priv or "").upper()
        if r == "ADMIN" and t in {"ADMIN", "MANAGER", "WORKER"}:
            return True
        return False

    # ------------------------------- Access metadata -------------------------------

    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.FULL)
    def access_metadata(self, request, *args, **kwargs):
        modules = [{"code": code, "label": label} for code, label in Access.ModuleCode.choices]
        levels = [{"value": int(value), "label": label} for value, label in Access.Level.choices]
        return _ok({"modules": modules, "levels": levels})

    # --------------------------------- Groups CRUD ---------------------------------

    @transaction.atomic
    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.FULL)
    @with_json_body
    @require_fields(["name", "country", "postal_code_regex", "phone_regex"])
    def create_group(self, request, body, *args, **kwargs):
        name = str(body.get("name", "")).strip()
        country = str(body.get("country", "")).strip().upper()
        postal_code_regex = str(body.get("postal_code_regex", "")).strip()
        phone_regex = str(body.get("phone_regex", "")).strip()

        if not name:
            return _err("Field 'name' is required.", status=400)
        if len(country) != 2:
            return _err("Field 'country' must be exactly 2 characters (ISO alpha-2).", status=400)
        if not postal_code_regex or not phone_regex:
            return _err("postal_code_regex and phone_regex are required.", status=400)

        if len(name) > 255 or len(postal_code_regex) > 255 or len(phone_regex) > 255:
            return _err("Fields must not exceed 255 characters.", status=400)

        try:
            self._compile_regex_or_error(postal_code_regex, "postal_code_regex")
            self._compile_regex_or_error(phone_regex, "phone_regex")
        except ValueError as ve:
            return _err(str(ve), status=400)

        if Group.objects.filter(country=country, name__iexact=name).exists():
            return _err("Group with the same name and country already exists.", status=409)

        token = self._gen_group_token("grp", 16)
        for _ in range(5):
            if not Group.objects.filter(token=token).exists():
                break
            token = self._gen_group_token("grp", 16)
        else:
            return _err("Could not generate a unique group token. Please retry.", status=409)

        grp = Group.objects.create(
            token=token,
            name=name,
            country=country,
            postal_code_regex=postal_code_regex,
            phone_regex=phone_regex,
        )
        data = {
            "uuid": str(grp.uuid),
            "token": grp.token,
            "name": grp.name,
            "country": grp.country,
            "postal_code_regex": grp.postal_code_regex,
            "phone_regex": grp.phone_regex,
            "created_at": grp.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": grp.updated_at.isoformat().replace("+00:00", "Z"),
        }
        return _ok(data, status=201)

    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.READ_ONLY)
    def list_groups(self, request, *args, **kwargs):
        qs_params = request.GET
        name = (qs_params.get("name") or "").strip()
        country = (qs_params.get("country") or "").strip().upper()

        q = Q()
        if name:
            q &= Q(name__icontains=name)
        if country:
            q &= Q(country__iexact=country)

        base_qs = Group.objects.filter(q).order_by("-created_at")

        page, page_size = get_pagination_params(qs_params)
        items, meta = paginate_queryset(base_qs, page, page_size)

        results = [{
            "uuid": str(g.uuid),
            "token": g.token,
            "name": g.name,
            "country": g.country,
            "postal_code_regex": g.postal_code_regex,
            "phone_regex": g.phone_regex,
            "created_at": g.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": g.updated_at.isoformat().replace("+00:00", "Z"),
        } for g in items]

        return _ok({**meta, "results": results})

    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.READ_ONLY)
    def get_group(self, request, uuid: str, *args, **kwargs):
        grp = Group.objects.filter(uuid=uuid).first()
        if not grp:
            return _err("Group not found.", status=404)

        return _ok({
            "uuid": str(grp.uuid),
            "token": grp.token,
            "name": grp.name,
            "country": grp.country,
            "postal_code_regex": grp.postal_code_regex,
            "phone_regex": grp.phone_regex,
            "created_at": grp.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": grp.updated_at.isoformat().replace("+00:00", "Z"),
        })

    @transaction.atomic
    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.READ_WRITE)
    @with_json_body
    def update_group(self, request, uuid: str, body=None, *args, **kwargs):
        grp = Group.objects.filter(uuid=uuid).first()
        if not grp:
            return _err("Group not found.", status=404)

        if not isinstance(body, dict):
            return _err("Invalid or missing JSON body.", status=400)

        allowed_keys = {"name", "country", "postal_code_regex", "phone_regex"}
        payload_keys = set(body.keys()) & allowed_keys
        if not payload_keys:
            return _err("No updatable fields provided.", status=400)

        new_name = grp.name
        new_country = grp.country
        new_postal = grp.postal_code_regex
        new_phone = grp.phone_regex

        if "name" in payload_keys:
            val = str(body.get("name", "")).strip()
            if not val:
                return _err("Field 'name' cannot be empty.", status=400)
            if len(val) > 255:
                return _err("Field 'name' must not exceed 255 characters.", status=400)
            new_name = val

        if "country" in payload_keys:
            val = str(body.get("country", "")).strip().upper()
            if len(val) != 2:
                return _err("Field 'country' must be exactly 2 characters (ISO alpha-2).", status=400)
            new_country = val

        if "postal_code_regex" in payload_keys:
            val = str(body.get("postal_code_regex", "")).strip()
            if not val:
                return _err("Field 'postal_code_regex' cannot be empty.", status=400)
            if len(val) > 255:
                return _err("Field 'postal_code_regex' must not exceed 255 characters.", status=400)
            try:
                re.compile(val)
            except re.error:
                return _err("Invalid postal_code_regex", status=400)
            new_postal = val

        if "phone_regex" in payload_keys:
            val = str(body.get("phone_regex", "")).strip()
            if not val:
                return _err("Field 'phone_regex' cannot be empty.", status=400)
            if len(val) > 255:
                return _err("Field 'phone_regex' must not exceed 255 characters.", status=400)
            try:
                re.compile(val)
            except re.error:
                return _err("Invalid phone_regex", status=400)
            new_phone = val

        if Group.objects.filter(country=new_country, name__iexact=new_name).exclude(pk=grp.pk).exists():
            return _err("Group with the same name and country already exists.", status=409)

        updates = {
            "name": new_name,
            "country": new_country,
            "postal_code_regex": new_postal,
            "phone_regex": new_phone,
        }
        changed, changed_fields = update_instance_fields(
            grp,
            updates,
            allowed={"name", "country", "postal_code_regex", "phone_regex"},
            save=True,
            touch_updated_at=True,
        )

        data = {
            "uuid": str(grp.uuid),
            "token": grp.token,
            "name": grp.name,
            "country": grp.country,
            "postal_code_regex": grp.postal_code_regex,
            "phone_regex": grp.phone_regex,
            "created_at": grp.created_at.isoformat().replace("+00:00", "Z"),
            "updated_at": grp.updated_at.isoformat().replace("+00:00", "Z"),
        }
        return _ok(data)

    # -------------------------------- Users (create/list/get) -------------------------------

    @transaction.atomic
    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.READ_WRITE)
    @with_json_body
    @require_fields(["privilege"])
    def create_user(self, request, body=None, jwt_payload=None, *args, **kwargs):
        privilege = str(body.get("privilege", "")).strip().upper()
        if privilege == "ADMIN":
            return self._create_admin(request, body=body)
        elif privilege == "MANAGER":
            return _err("MANAGER creation is not implemented yet.", status=501)
        elif privilege == "WORKER":
            return _err("WORKER creation is not implemented yet.", status=501)
        return _err("Invalid 'privilege'. Allowed: ADMIN, MANAGER, WORKER.", status=400)

    @transaction.atomic
    @require_fields(["first_name", "last_name", "email_address", "access"])
    def _create_admin(self, request, body=None):
        first_name = str(body.get("first_name", "")).strip()
        last_name = str(body.get("last_name", "")).strip()
        email_address = self._normalize_email(body.get("email_address", ""))  # lower + strip

        if not first_name:
            return _err("Field 'first_name' is required.", status=400)
        if not last_name:
            return _err("Field 'last_name' is required.", status=400)
        if not email_address:
            return _err("Field 'email_address' is required.", status=400)
        try:
            validate_email(email_address)
        except ValidationError:
            return _err("Field 'email_address' must be a valid email.", status=400)

        login_input = body.get("login")
        base_login = login_input.strip() if login_input else make_admin_login(first_name, last_name)
        final_login = ensure_unique_login(Administration, base_login)

        if Administration.objects.filter(login__iexact=final_login).exists():
            return _err("Login already exists.", status=409)
        if Administration.objects.filter(email_address__iexact=email_address).exists():
            return _err("Email already exists.", status=409)

        access_payload = body.get("access")
        ok, access_norm, err = self._validate_access_payload(access_payload)
        if not ok:
            return _err(err, status=400)

        ok, access_norm, err = self._enforce_min_access(access_norm, "ADMIN", autofix=False)
        if not ok:
            return _err(err, status=400)

        priv, _ = UserPrivileges.objects.get_or_create(name="ADMIN")
        try:
            user = UserIdentifier(
                user_privilege=priv,
                user_status=UserIdentifier.Status.ACTIVE,
            )
            user.save()
            admin = Administration.objects.create(
                user=user,
                login=final_login,
                first_name=first_name,
                last_name=last_name,
                email_address=email_address,
                is_active=True,
            )

            auth = Authorization.objects.create(user=user, password_hash="", initial_password_encrypted=None)
            initial_password = self._generate_initial_password(28)
            auth.set_password(initial_password)

            try:
                from cryptography.fernet import Fernet
                key = config("INITIAL_PWD_KEY")
                f = Fernet(key.encode("utf-8") if isinstance(key, str) else key)
                auth.initial_password_encrypted = f.encrypt(initial_password.encode("utf-8"))
                auth.save(update_fields=["initial_password_encrypted"])
            except Exception as e:
                logger.warning(f"[INITPWD] Unable to encrypt initial password: {e}")

            access_objects = [Access(user=user, module=a["module"], level=int(a["level"])) for a in access_norm]
            Access.objects.bulk_create(access_objects)

        except IntegrityError:
            return _err("Login or email already exists.", status=409)

        access_resp = [{"module": a["module"], "level": int(a["level"])} for a in access_norm]
        data = {
            "user": {
                "id": str(user.id),
                "user_token": user.user_token,
                "status": user.user_status,
                "privilege": priv.name,
            },
            "administration": {
                "id": str(admin.id),
                "login": admin.login,
                "first_name": admin.first_name,
                "last_name": admin.last_name,
                "email_address": admin.email_address,
                "is_active": admin.is_active,
                "created_at": admin.created_at.isoformat().replace("+00:00", "Z"),
                "updated_at": admin.updated_at.isoformat().replace("+00:00", "Z"),
            },
            "access": access_resp,
        }
        return _ok(data, status=201)

    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.READ_ONLY)
    def list_admins(self, request, *args, **kwargs):
        qs = (Administration.objects
              .select_related("user")
              .prefetch_related("user__accesses")
              .filter(user__user_privilege__name="ADMIN"))

        qp = request.GET


        q_text = (qp.get("q") or "").strip()
        if q_text:
            qs = qs.filter(
                Q(login__icontains=q_text) |
                Q(first_name__icontains=q_text) |
                Q(last_name__icontains=q_text) |
                Q(email_address__icontains=q_text) |
                Q(user__user_token__icontains=q_text)
            )

        status = (qp.get("status") or "").strip().upper()
        if status:
            allowed_status = {v for v, _ in UserIdentifier.Status.choices}
            if status in allowed_status:
                qs = qs.filter(user__user_status=status)

        def to_bool(val):
            if val is None:
                return None
            s = str(val).strip().lower()
            if s in {"1", "true", "t", "yes", "y"}:
                return True
            if s in {"0", "false", "f", "no", "n"}:
                return False
            return None

        is_active = to_bool(qp.get("is_active"))
        if is_active is not None:
            qs = qs.filter(is_active=is_active)

        qs = qs.order_by("-created_at")

        page, page_size = get_pagination_params(qp)
        items, meta = paginate_queryset(qs, page, page_size)

        results = []
        for adm in items:
            user = adm.user
            access_list = [{"module": a.module, "level": int(a.level)} for a in user.accesses.all()]
            results.append({
                "user": {
                    "id": str(user.id),
                    "user_token": user.user_token,
                    "status": user.user_status,
                    "privilege": user.user_privilege.name,
                },
                "administration": {
                    "id": str(adm.id),
                    "login": adm.login,
                    "first_name": adm.first_name,
                    "last_name": adm.last_name,
                    "email_address": adm.email_address,
                    "is_active": adm.is_active,
                    "last_login_at": adm.last_login_at.isoformat().replace("+00:00", "Z") if adm.last_login_at else None,
                    "created_at": adm.created_at.isoformat().replace("+00:00", "Z"),
                    "updated_at": adm.updated_at.isoformat().replace("+00:00", "Z"),
                },
                "access": access_list,
            })

        return _ok({**meta, "results": results})

    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.READ_ONLY)
    def get_user(self, request, *args, **kwargs):
        target_uuid = kwargs.get("uuid")
        if not target_uuid:
            return _err("Missing 'uuid' in path.", status=400)

        include_pwd = _to_bool(request.GET.get("include_initial_password"))
        user, privilege, adm_obj = _resolve_target(target_uuid)
        if not user:
            logger.info(f"[404] get_user uuid={target_uuid} not found")
            return _err("NOT_FOUND", status=404)

        privilege = (privilege or "").upper()
        if privilege not in {"ADMIN", "MANAGER"}:
            logger.info(f"[501] get_user uuid={target_uuid}({privilege}) unsupported privilege")
            return _err("Not implemented for this privilege.", status=501)

        if privilege == "ADMIN":
            adm = adm_obj
            if not adm:
                try:
                    adm = (Administration.objects
                           .select_related("user")
                           .prefetch_related("user__accesses")
                           .get(user__id=user.id))
                except Administration.DoesNotExist:
                    logger.info(f"[404] get_user uuid={target_uuid}(ADMIN) detail=admin_profile_missing")
                    return _err("NOT_FOUND", status=404)
            data = self._serialize_admin(adm)
        else:
            user = (UserIdentifier.objects
                    .select_related("user_privilege")
                    .prefetch_related("accesses")
                    .get(id=user.id))
            data = _serialize_manager_minimal(user)

        credentials = {"initial_password_available": False}
        if include_pwd:
            payload = kwargs.get("jwt_payload") or {}
            requester_id = payload.get("user_id")
            if not requester_id:
                logger.info(f"[DENY] get_user+pwd uuid={target_uuid} reason=no payload user_id")
                return _err("FORBIDDEN", status=403)

            has_reveal_rights = Access.objects.filter(
                user_id=requester_id,
                module__iexact="administration",
                level__gte=Access.Level.READ_WRITE
            ).exists()
            if not has_reveal_rights:
                logger.info(f"[DENY] get_user+pwd uuid={target_uuid} reason=no READ_WRITE")
                return _err("FORBIDDEN", status=403)
            try:
                auth = Authorization.objects.get(user_id=user.id)
            except Authorization.DoesNotExist:
                auth = None
            can_show = False
            if auth and getattr(auth, "initial_password_encrypted", None):
                if privilege == "ADMIN":
                    never_logged = (getattr(adm, "last_login_at", None) is None)
                    can_show = never_logged
                else:
                    can_show = True

            if can_show:
                plaintext = _decrypt_initial(auth.initial_password_encrypted) if auth else None
                if plaintext:
                    credentials = {
                        "initial_password_available": True,
                        "initial_password": plaintext
                    }
                else:
                    credentials = {"initial_password_available": False}
            else:
                credentials = {"initial_password_available": False}
        data["credentials"] = credentials
        resp = _ok(data)
        if credentials.get("initial_password_available") and credentials.get("initial_password"):
            try:
                resp["Cache-Control"] = "no-store"
            except Exception:
                pass
        logger.info(
            f"[OK] get_user uuid={target_uuid} priv={privilege} reveal={credentials.get('initial_password_available')}"
        )
        return resp

    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.FULL)
    @with_json_body
    def block_user(self, request, body=None, *args, **kwargs):
        target_uuid = kwargs.get("uuid")
        if not target_uuid:
            return _err("Missing 'uuid' in path.", status=400)

        user, privilege, adm_obj = _resolve_target(target_uuid)
        if not user:
            return _err("NOT_FOUND", status=404)

        privilege = (privilege or "").upper()
        if privilege not in {"ADMIN", "MANAGER"}:
            return _err("Not implemented for this privilege.", status=501)

        payload = kwargs.get("jwt_payload") or {}
        requester_id = str(payload.get("user_id") or "")
        if requester_id and requester_id == str(user.id):
            return _err("FORBIDDEN: cannot block yourself.", status=403)

        blocker_label = None
        try:
            req_adm = Administration.objects.get(user_id=requester_id)
            blocker_label = req_adm.login or req_adm.email_address or requester_id
        except Administration.DoesNotExist:
            blocker_label = payload.get("sub") or payload.get("uid") or requester_id

        now = timezone.now()
        updates = []
        if user.user_status != UserIdentifier.Status.BLOCKED:
            user.user_status = UserIdentifier.Status.BLOCKED
            updates.append("user_status")
        user.blocked_at = now
        user.blocked_by = (blocker_label or "")[:128]
        updates.extend(["blocked_at", "blocked_by", "updated_at"])
        user.save(update_fields=list(dict.fromkeys(updates)))  # dedupe

        if privilege == "ADMIN" and adm_obj and adm_obj.is_active:
            adm_obj.is_active = False
            adm_obj.save(update_fields=["is_active", "updated_at"])

        reason = (body or {}).get("reason")
        logger.info(f"[BLOCK] by={blocker_label} target={user.id} priv={privilege} reason={reason!r}")

        if privilege == "ADMIN":
            adm = adm_obj or Administration.objects.select_related("user").prefetch_related("user__accesses").get(
                user__id=user.id)
            data = self._serialize_admin(adm)
        else:
            user = (UserIdentifier.objects
                    .select_related("user_privilege")
                    .prefetch_related("accesses")
                    .get(id=user.id))
            data = _serialize_manager_minimal(user)

        data["lock"] = {
            "is_blocked": True,
            "blocked_at": (user.blocked_at.isoformat().replace("+00:00", "Z") if user.blocked_at else None),
            "blocked_by": user.blocked_by,
        }
        return _ok(data)

    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.FULL)
    def unblock_user(self, request, *args, **kwargs):
        target_uuid = kwargs.get("uuid")
        if not target_uuid:
            return _err("Missing 'uuid' in path.", status=400)

        user, privilege, adm_obj = _resolve_target(target_uuid)
        if not user:
            return _err("NOT_FOUND", status=404)

        privilege = (privilege or "").upper()
        if privilege not in {"ADMIN", "MANAGER"}:
            return _err("Not implemented for this privilege.", status=501)

        updates = []
        if user.user_status != UserIdentifier.Status.ACTIVE:
            user.user_status = UserIdentifier.Status.ACTIVE
            updates.append("user_status")
        if user.blocked_at is not None:
            user.blocked_at = None
            updates.append("blocked_at")
        if user.blocked_by:
            user.blocked_by = None
            updates.append("blocked_by")
        if updates:
            updates.append("updated_at")
            user.save(update_fields=list(dict.fromkeys(updates)))

        if privilege == "ADMIN" and adm_obj and not adm_obj.is_active:
            adm_obj.is_active = True
            adm_obj.save(update_fields=["is_active", "updated_at"])

        logger.info(f"[UNBLOCK] by={kwargs.get('jwt_payload', {}).get('user_id')} target={user.id} priv={privilege}")

        if privilege == "ADMIN":
            adm = adm_obj or Administration.objects.select_related("user").prefetch_related("user__accesses").get(
                user__id=user.id)
            data = self._serialize_admin(adm)
        else:
            user = (UserIdentifier.objects
                    .select_related("user_privilege")
                    .prefetch_related("accesses")
                    .get(id=user.id))
            data = _serialize_manager_minimal(user)

        data["lock"] = {
            "is_blocked": user.user_status == UserIdentifier.Status.BLOCKED,
            "blocked_at": (user.blocked_at.isoformat().replace("+00:00", "Z") if user.blocked_at else None),
            "blocked_by": user.blocked_by,
        }
        return _ok(data)

    @with_jwt_payload
    @require_module_level(Access.ModuleCode.ADMINISTRATION, Access.Level.READ_WRITE)
    @with_json_body
    @transaction.atomic
    def update_user(self, request, uuid: str, body=None, *args, **kwargs):
        if not isinstance(body, dict):
            return _err("Invalid or missing JSON body.", status=400)

        allowed = {"first_name", "last_name", "email_address", "access"}
        keys = {k for k in body.keys() if k in allowed}
        if not keys:
            return _err(
                "No updatable fields provided. Allowed: first_name, last_name, email_address, access.",
                status=400
            )
        user, privilege, adm_obj = _resolve_target(uuid)
        if not user:
            return _err("NOT_FOUND", status=404)

        privilege = (privilege or "").upper()

        if privilege == "ADMIN":
            adm = adm_obj
            if not adm:
                try:
                    adm = (Administration.objects
                           .select_related("user")
                           .prefetch_related("user__accesses")
                           .get(user__id=user.id))
                except Administration.DoesNotExist:
                    return _err("NOT_FOUND", status=404)

            updates = {}

            if "first_name" in keys:
                val = str(body.get("first_name", "")).strip()
                if not val:
                    return _err("Field 'first_name' cannot be empty.", status=400)
                updates["first_name"] = val

            if "last_name" in keys:
                val = str(body.get("last_name", "")).strip()
                if not val:
                    return _err("Field 'last_name' cannot be empty.", status=400)
                updates["last_name"] = val

            if "email_address" in keys:
                email = self._normalize_email(body.get("email_address", ""))
                if not email:
                    return _err("Field 'email_address' cannot be empty.", status=400)
                try:
                    validate_email(email)
                except ValidationError:
                    return _err("Field 'email_address' must be a valid email.", status=400)
                if Administration.objects.filter(email_address__iexact=email).exclude(pk=adm.pk).exists():
                    return _err("Email already exists.", status=409)
                updates["email_address"] = email

            will_change_first = ("first_name" in updates and updates["first_name"] != adm.first_name)
            will_change_last = ("last_name" in updates and updates["last_name"] != adm.last_name)
            if will_change_first or will_change_last:
                new_first = updates.get("first_name", adm.first_name)
                new_last = updates.get("last_name", adm.last_name)
                base_login = make_admin_login(new_first, new_last)

                if base_login.strip().lower() != (adm.login or "").strip().lower():
                    candidate = base_login
                    i = 1
                    while Administration.objects.filter(login__iexact=candidate).exclude(pk=adm.pk).exists():
                        i += 1
                        candidate = f"{base_login}.{i}"
                    updates["login"] = candidate

            changed, changed_fields = update_instance_fields(
                adm,
                updates,
                allowed={"first_name", "last_name", "email_address", "login"},
                save=True,
                touch_updated_at=True,
            )

            access_changed = False
            if "access" in keys:
                access_payload = body.get("access")

                ok, access_norm, err = self._validate_access_payload(access_payload)
                if not ok:
                    return _err(err, status=400)

                ok, access_norm, err = self._enforce_min_access(access_norm, privilege, autofix=False)
                if not ok:
                    return _err(err, status=400)

                desired = {a["module"]: int(a["level"]) for a in access_norm}

                requester_id = str((kwargs.get("jwt_payload") or {}).get("user_id") or "")
                if requester_id and requester_id == str(user.id):
                    desired_admin_level = int(desired.get(Access.ModuleCode.ADMINISTRATION, Access.Level.NO_ACCESS))
                    if desired_admin_level < int(Access.Level.READ_WRITE):
                        logger.info(
                            f"[DENY] update_user SELF-UPDATE guard: admin level {desired_admin_level} < READ_WRITE")
                        return _err("FORBIDDEN: cannot reduce your own 'administration' access below READ_WRITE.",
                                    status=403)

                existing_qs = Access.objects.filter(user=user)
                existing = {a.module: int(a.level) for a in existing_qs}

                to_create = []
                for mod, lvl in desired.items():
                    cur = existing.get(mod)
                    if cur is None:
                        to_create.append(Access(user=user, module=mod, level=lvl))
                    elif cur != lvl:
                        Access.objects.filter(user=user, module=mod).update(level=lvl)
                        access_changed = True
                if to_create:
                    Access.objects.bulk_create(to_create)
                    access_changed = True

                to_delete = [m for m in existing.keys() if m not in desired]
                if to_delete:
                    if requester_id and requester_id == str(user.id):
                        safe_to_delete = [m for m in to_delete if m != Access.ModuleCode.ADMINISTRATION]
                    else:
                        safe_to_delete = to_delete

                    if safe_to_delete:
                        Access.objects.filter(user=user, module__in=safe_to_delete).delete()
                        access_changed = True

                    if requester_id and requester_id == str(user.id) and Access.ModuleCode.ADMINISTRATION in to_delete:
                        logger.info("[DENY] update_user SELF-UPDATE guard: attempted to remove 'administration' module")
                        return _err("FORBIDDEN: cannot remove your own 'administration' access.", status=403)

            adm_refreshed = (Administration.objects
                             .select_related("user")
                             .prefetch_related("user__accesses")
                             .get(pk=adm.pk))
            logger.info(
                f"[OK] update_user ADMIN uuid={uuid} "
                f"changed_fields={changed_fields if changed else []} "
                f"access_updated={access_changed}"
            )
            return _ok(self._serialize_admin(adm_refreshed))

        if privilege == "MANAGER":
            logger.info(f"[501] update_user uuid={uuid}(MANAGER) detail=manager_logic_missing")
            return _err("Not implemented: manager update.", status=501)

        if privilege == "WORKER":
            logger.info(f"[501] update_user uuid={uuid}(WORKER) detail=worker_logic_missing")
            return _err("Not implemented: worker update.", status=501)

        return _err("Not implemented for this privilege.", status=501)