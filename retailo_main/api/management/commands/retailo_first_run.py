import getpass
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from api.models import (
    UserPrivileges,
    UserIdentifier,
    Administration,
    Authorization,
    Access,
)
from api.addons import (
    validate_email_strict,
    normalize_email,
    make_admin_login,
    ensure_unique_login,
)


class Command(BaseCommand):
    help = (
        "Inicjalizacja systemu: tworzy role (ADMIN, MANAGER, WORKER) "
        "oraz pierwszego administratora z pełnymi dostępami."
    )

    def prompt(self, label: str, required: bool = True, default: str | None = None, validator=None) -> str:
        while True:
            suffix = f" [{default}]" if default else ""
            val = input(f"{label}{suffix}: ").strip()
            if not val and default is not None:
                val = default
            if required and not val:
                self.stdout.write(self.style.ERROR("To pole jest wymagane."))
                continue
            if validator and val:
                try:
                    validator(val)
                except Exception as e:
                    self.stdout.write(self.style.ERROR(str(e)))
                    continue
            return val

    def prompt_password(self) -> str:
        while True:
            pwd1 = getpass.getpass("Hasło administratora: ")
            if not pwd1:
                self.stdout.write(self.style.ERROR("Hasło nie może być puste."))
                continue
            if len(pwd1) < 8:
                self.stdout.write(self.style.ERROR("Hasło musi mieć co najmniej 8 znaków."))
                continue
            pwd2 = getpass.getpass("Powtórz hasło: ")
            if pwd1 != pwd2:
                self.stdout.write(self.style.ERROR("Hasła nie są takie same."))
                continue
            return pwd1

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("== Retailo: pierwsze uruchomienie =="))

        first_name = self.prompt("Imię", default="Super")
        last_name = self.prompt("Nazwisko", default="Admin")
        login_input = self.prompt("Login (puste = z imienia+nazwiska)", required=False, default="")
        email_input = self.prompt(
            "Adres e-mail (opcjonalnie)",
            required=False,
            default="admin@example.com",
            validator=validate_email_strict,
        )
        email_norm = normalize_email(email_input) if email_input else None
        password = self.prompt_password()
        base_login = login_input.strip() if login_input else make_admin_login(first_name, last_name)

        try:
            with transaction.atomic():
                roles = {}
                for name in ["ADMIN", "MANAGER", "WORKER"]:
                    obj, created = UserPrivileges.objects.get_or_create(name=name)
                    roles[name] = obj
                    self.stdout.write(f"• Uprawnienie {name}: {'utworzono' if created else 'istniało'}")

                user_identifier = UserIdentifier(
                    user_status=UserIdentifier.Status.ACTIVE,
                    user_privilege=roles["ADMIN"],
                )
                user_identifier.save()
                self.stdout.write(f"• UserIdentifier: utworzono ({user_identifier.id})")

                final_login = ensure_unique_login(Administration, base_login)
                admin_defaults = {
                    "login": final_login,
                    "first_name": first_name.strip(),
                    "last_name": last_name.strip(),
                    "email_address": email_norm,
                    "is_active": True,
                }
                admin_profile, created_admin = Administration.objects.get_or_create(
                    user=user_identifier,
                    defaults=admin_defaults,
                )
                if not created_admin:
                    for k, v in admin_defaults.items():
                        setattr(admin_profile, k, v)
                    admin_profile.save()
                    self.stdout.write("• Administration: zaktualizowano")
                else:
                    self.stdout.write("• Administration: utworzono")

                auth_obj, created_auth = Authorization.objects.get_or_create(
                    user=user_identifier,
                    defaults={"password_hash": ""},
                )
                auth_obj.set_password(password)
                self.stdout.write(f"• Authorization: {'utworzono' if created_auth else 'zaktualizowano'} (hasło ustawione)")

                created_accesses = 0
                updated_accesses = 0
                for module_code, _label in Access.ModuleCode.choices:
                    access, created_acc = Access.objects.get_or_create(
                        user=user_identifier,
                        module=module_code,
                        defaults={"level": Access.Level.FULL},
                    )
                    if created_acc:
                        created_accesses += 1
                    else:
                        if access.level != Access.Level.FULL:
                            access.level = Access.Level.FULL
                            access.save(update_fields=["level", "updated_at"])
                            updated_accesses += 1
                self.stdout.write(f"• Dostępy: dodano {created_accesses}, zaktualizowano {updated_accesses} (FULL)")

        except Exception as exc:
            raise CommandError(f"Błąd inicjalizacji: {exc}") from exc

        self.stdout.write(self.style.SUCCESS("✅ Pierwsza konfiguracja zakończona."))
        self.stdout.write("")
        self.stdout.write("Dane administracyjne:")
        self.stdout.write(f"  • user_token: {user_identifier.user_token}")
        self.stdout.write(f"  • login: {admin_profile.login}")
        self.stdout.write(f"  • email: {admin_profile.email_address or '-'}")
        self.stdout.write(f"  • rola: ADMIN")
