import uuid, hashlib
from django.db import models
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from .addons import ensure_unique_user_token
from .addons.utils import validate_password_policy


class UserPrivileges(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name


class UserIdentifier(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "ACTIVE", "Active"
        INACTIVE = "INACTIVE", "Inactive"
        BLOCKED = "BLOCKED", "Blocked"
        REMOVED = "REMOVED", "Removed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user_token = models.CharField(max_length=256, unique=True, db_index=True)
    user_status = models.CharField(max_length=20, choices=Status.choices, default=Status.INACTIVE)
    user_privilege = models.ForeignKey("api.UserPrivileges", on_delete=models.PROTECT, related_name="users")
    blocked_by = models.CharField(max_length=128, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    blocked_at = models.DateTimeField(null=True, blank=True)
    removed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user_token"]),
            models.Index(fields=["user_status"]),
        ]

    def save(self, *args, **kwargs):
        if not self.user_token:
            self.user_token = ensure_unique_user_token(UserIdentifier)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.user_token} ({self.user_status})"

class Administration(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        UserIdentifier,
        on_delete=models.PROTECT,
        related_name="administration_profile",
    )
    login = models.CharField(max_length=100, unique=True, db_index=True, null=True, blank=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email_address = models.EmailField(max_length=256, unique=True, db_index=True, null=True, blank=True)
    is_active = models.BooleanField(default=True)
    last_login_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.login or self.email_address or str(self.id)


class Access(models.Model):
    class ModuleCode(models.TextChoices):
        ADMINISTRATION = "administration", "Panel administracyjny"
        ORDERS = "orders", "Zamówienia"
        PRODUCTS = "products", "Produkty"
        CUSTOMERS = "customers", "Klienci"

    class Level(models.IntegerChoices):
        NO_ACCESS = 0, "Brak dostępu"
        READ_ONLY = 1, "Tylko odczyt"
        READ_WRITE = 2, "Odczyt i modyfikacja"
        FULL = 3, "Pełny dostęp (łącznie z blokowaniem)"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        UserIdentifier,
        on_delete=models.CASCADE,
        related_name="accesses",
    )
    module = models.CharField(max_length=32, choices=ModuleCode.choices, db_index=True)
    level = models.IntegerField(choices=Level.choices, default=Level.NO_ACCESS)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "module")

    def __str__(self):
        return f"{self.user.user_token} → {self.get_module_display()}: {self.get_level_display()}"


class Authorization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(
        UserIdentifier,
        on_delete=models.CASCADE,
        related_name="authorization",
    )
    password_hash = models.CharField(max_length=256)
    password_history = models.JSONField(default=list, blank=True)
    user_attempts = models.IntegerField(default=0)
    last_attempt = models.DateTimeField(null=True, blank=True)
    locked_until = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["locked_until"]),
        ]

    def __str__(self):
        return f"Authorization<{self.user_id}>"

    def set_password(self, raw_password: str, keep_history: int = 5) -> None:
        validate_password_policy(raw_password)
        new_hash = make_password(raw_password)
        history = list(self.password_history or [])
        if self.password_hash:
            history = [self.password_hash] + history
        self.password_hash = new_hash
        if keep_history > 0:
            self.password_history = history[:keep_history]
        else:
            self.password_history = []
        self.user_attempts = 0
        self.locked_until = None
        self.save(update_fields=["password_hash", "password_history", "user_attempts", "locked_until", "updated_at"])

    def check_password(self, raw_password: str, attempt_limit: int = 5, lock_minutes: int = 15) -> bool:
        now = timezone.now()
        self.last_attempt = now

        if self.locked_until and now < self.locked_until:
            self.save(update_fields=["last_attempt"])
            return False

        ok = check_password(raw_password, self.password_hash)

        if ok:
            self.user_attempts = 0
            self.locked_until = None
            self.save(update_fields=["user_attempts", "last_attempt", "locked_until"])
            return True

        self.user_attempts = (self.user_attempts or 0) + 1
        if attempt_limit and self.user_attempts >= attempt_limit:
            self.locked_until = now + timezone.timedelta(minutes=lock_minutes)
            self.user_attempts = 0

        self.save(update_fields=["user_attempts", "last_attempt", "locked_until"])  # bez updated_at
        return False

    def password_used_before(self, raw_password: str) -> bool:
        for old_hash in self.password_history or []:
            if check_password(raw_password, old_hash):
                return True
        return False

class EmailOTP(models.Model):
    class Purpose(models.TextChoices):
        LOGIN = "LOGIN", "Login 2FA"
        RESET = "RESET", "Password reset"
        PASSWORD_CHANGE = "PWD_CHANGE", "Password change"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey("api.UserIdentifier", on_delete=models.CASCADE, related_name="email_otps")
    purpose = models.CharField(max_length=50, choices=Purpose.choices, default=Purpose.LOGIN)
    code_hash = models.CharField(max_length=128)
    expires_at = models.DateTimeField()
    sent_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=5)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    request_ip = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "purpose"]),
            models.Index(fields=["expires_at"]),
            models.Index(fields=["created_at"]),
        ]

    @staticmethod
    def hash_code(raw_code: str, pepper: str) -> str:
        return hashlib.sha256((raw_code + pepper).encode("utf-8")).hexdigest()

    def is_expired(self) -> bool:
        return timezone.now() >= self.expires_at

    def mark_used(self):
        self.used_at = timezone.now()
        self.save(update_fields=["used_at"])