from pathlib import Path
from decouple import config, Csv
from corsheaders.defaults import default_headers

BASE_DIR = Path(__file__).resolve().parent.parent

# ========================
# Podstawowe ustawienia
# ========================
SECRET_KEY = config("SECRET_KEY", default="change-me")

DEBUG = config("DEBUG", default=True, cast=bool)

ALLOWED_HOSTS = config("ALLOWED_HOSTS", default="*", cast=Csv())

# ========================
# Aplikacje
# ========================
INSTALLED_APPS = [
    # core
    "django.contrib.contenttypes",
    "django.contrib.staticfiles",
    # 3rd party
    "rest_framework",
    "corsheaders",
    "drf_spectacular",
    # local
    "api",
]

# ========================
# Middleware
# ========================
# MIDDLEWARE = [
#     "corsheaders.middleware.CorsMiddleware",
#     "django.middleware.security.SecurityMiddleware",
#     "django.contrib.sessions.middleware.SessionMiddleware",
#     "django.middleware.common.CommonMiddleware",
#     "django.middleware.csrf.CsrfViewMiddleware",
#     "django.contrib.auth.middleware.AuthenticationMiddleware",
#     "django.contrib.messages.middleware.MessageMiddleware",
#     "django.middleware.clickjacking.XFrameOptionsMiddleware",
# ]
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "retailo_main.urls"

# ========================
# Templates
# ========================
# TEMPLATES = [
#     {
#         "BACKEND": "django.template.backends.django.DjangoTemplates",
#         "DIRS": [],
#         "APP_DIRS": True,
#         "OPTIONS": {
#             "context_processors": [
#                 "django.template.context_processors.request",
#                # "django.contrib.auth.context_processors.auth",
#                 #"django.contrib.messages.context_processors.messages",
#             ],
#         },
#     },
# ]
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    },
]

WSGI_APPLICATION = "retailo_main.wsgi.application"
ASGI_APPLICATION = "retailo_main.asgi.application"

# ========================
# Baza danych
# ========================
DATABASES = {
    "default": {
        "ENGINE": config("DB_ENGINE", default="django.db.backends.sqlite3"),
        "NAME": config("DB_NAME", default=BASE_DIR / "db.sqlite3"),
        "USER": config("DB_USER", default=""),
        "PASSWORD": config("DB_PASSWORD", default=""),
        "HOST": config("DB_HOST", default=""),
        "PORT": config("DB_PORT", default=""),
    }
}

# ========================
# Walidacja haseł
# ========================
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

# ========================
# Lokalizacja i czas
# ========================
LANGUAGE_CODE = "en"
USE_I18N = True
USE_TZ = True
TIME_ZONE = "UTC"

# ========================
# Statyczne pliki
# ========================
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ========================
# Django REST Framework
# ========================
# REST_FRAMEWORK = {
#     "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
#     "DATETIME_FORMAT": None,   # ISO 8601 w UTC, np. "2025-09-04T12:34:56Z"
#     "DATE_FORMAT": None,
#     "TIME_FORMAT": None,
# }
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [],      # żadnych Session/Basic
    "UNAUTHENTICATED_USER": None,              # nie twórz AnonymousUser (wymaga auth)
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Retailo System API",
    "VERSION": "1.0.0",
    "DESCRIPTION": "Backend API dla Retailo System",
}

# ========================
# CORS
# ========================
CORS_ALLOW_ALL_ORIGINS = config("CORS_ALLOW_ALL_ORIGINS", default=True, cast=bool)

CORS_ALLOW_HEADERS = list(default_headers) + [
    "Pragma",
    "X-Requested-With",
    "Content-Type",
    "Authorization",
]

CORS_EXPOSE_HEADERS = [
    "X-Auth-Token",
]

CSRF_COOKIE_SECURE = config("CSRF_COOKIE_SECURE", default=False, cast=bool)
SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=False, cast=bool)
