from django.urls import path
from .views import (
    LoginStep1View,
    LoginStep2View,
    ForcePasswordChangeView,
    PasswordChangeStartView,
    PasswordChangeConfirmView,
    AdministrationResetPassword,
)

urlpatterns = [
    # Logowanie (2 kroki)
    path("auth/login/step1/", LoginStep1View.as_view(), name="auth-login-step1"),
    path("auth/login/step2/", LoginStep2View.as_view(), name="auth-login-step2"),

    # Wymuszona zmiana hasła po pierwszym logowaniu / po wygaśnięciu
    path("auth/password/force-change/", ForcePasswordChangeView.as_view(), name="auth-password-force-change"),

    # Zmiana hasła dla zalogowanego (2 kroki, wymaga JWT)
    path("auth/password/change/start/", PasswordChangeStartView.as_view(), name="auth-password-change-start"),
    path("auth/password/change/confirm/", PasswordChangeConfirmView.as_view(), name="auth-password-change-confirm"),

    # Reset hasła "zapomniałem" (jeden endpoint dla GET/POST/PUT)
    path("auth/password/reset/", AdministrationResetPassword.as_view(), name="auth-password-reset"),
]
