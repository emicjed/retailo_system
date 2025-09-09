from django.urls import path
from .views import (
    LoginStep1View,
    LoginStep2View,
    ForcePasswordChangeView,
    PasswordChangeStartView,
    PasswordChangeConfirmView,
    AdministrationResetPassword, AdministrationGroups, AdministrationUsers, AdministrationAccessMetadata,
)

urlpatterns = [
    path("auth/login/step1/", LoginStep1View.as_view(), name="auth-login-step1"),
    path("auth/login/step2/", LoginStep2View.as_view(), name="auth-login-step2"),

    path("auth/password/force-change/", ForcePasswordChangeView.as_view(), name="auth-password-force-change"),

    path("auth/password/change/start/", PasswordChangeStartView.as_view(), name="auth-password-change-start"),
    path("auth/password/change/confirm/", PasswordChangeConfirmView.as_view(), name="auth-password-change-confirm"),

    path("auth/password/reset/", AdministrationResetPassword.as_view(), name="auth-password-reset"),

    path("administration/groups", AdministrationGroups.as_view(), name="administration-groups"),
    path("administration/groups/<uuid:uuid>", AdministrationGroups.as_view(), name="administration-group-detail"),

    path("administration/access-metadata", AdministrationAccessMetadata.as_view(),
         name="administration-access-metadata"),

    path("administration/users", AdministrationUsers.as_view(), name="administration-users"),
    path("administration/users/<uuid:uuid>", AdministrationUsers.as_view(), name="administration-user-detail"),
]
