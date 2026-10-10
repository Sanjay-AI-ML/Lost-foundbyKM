"""
Django settings for lost_found_project.
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Load server-only integration settings before reading any environment options.
_env_file = BASE_DIR / '.env'
if _env_file.exists():
    for _line in _env_file.read_text(encoding='utf-8-sig').splitlines():
        _line = _line.strip()
        if _line and not _line.startswith('#') and '=' in _line:
            _key, _value = _line.split('=', 1)
            os.environ.setdefault(_key.strip(), _value.strip().strip('\"\''))

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-lost-found-secret-key-change-in-production')

DEBUG = os.environ.get('DJANGO_DEBUG', 'true').lower() in ('true', '1', 'yes')

ALLOWED_HOSTS = ['*']

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Custom Apps
    'accounts.apps.AccountsConfig',
    'items.apps.ItemsConfig',
    'claims.apps.ClaimsConfig',
    'notifications.apps.NotificationsConfig',
    'audit.apps.AuditConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'lost_found_project.cyberaccess.CyberAccessSecurityMiddleware',
]

ROOT_URLCONF = 'lost_found_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'notifications.views.unread_notifications_count',
            ],
        },
    },
]

WSGI_APPLICATION = 'lost_found_project.wsgi.application'
ASGI_APPLICATION = 'lost_found_project.asgi.application'

# Database
# Using database/db.sqlite3 inside the project root
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.environ.get('DJANGO_DATABASE_PATH', str(BASE_DIR / 'database' / 'db.sqlite3')),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Media files (User uploads)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Auth redirects
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'items:home'
LOGOUT_REDIRECT_URL = 'accounts:login'

# CyberAccess BOLA Defense Engine Configuration (OWASP API1:2023)
CYBERACCESS_API_KEY = os.environ.get('CYBERACCESS_API_KEY', '')
CYBERACCESS_ENABLED = os.environ.get('CYBERACCESS_ENABLED', str(bool(CYBERACCESS_API_KEY))).lower() in ('true', '1', 'yes')
CYBERACCESS_API_URL = os.environ.get('CYBERACCESS_API_URL', 'http://127.0.0.1:8000')
CYBERACCESS_FAIL_OPEN = os.environ.get('CYBERACCESS_FAIL_OPEN', 'false').lower() in ('true', '1', 'yes')
CYBERACCESS_TIMEOUT = float(os.environ.get('CYBERACCESS_TIMEOUT', '2.0'))
CYBERACCESS_CANARIES = [value for value in os.environ.get('CYBERACCESS_CANARIES', '').split(',') if value]
CYBERACCESS_DEMO_ENABLED = os.environ.get('CYBERACCESS_DEMO_ENABLED', 'false').lower() in ('true', '1', 'yes')
CYBERACCESS_LEGACY_DEMO_ENABLED = os.environ.get('CYBERACCESS_LEGACY_DEMO_ENABLED', 'false').lower() in ('true', '1', 'yes')
CYBERACCESS_CONSOLE_URL = os.environ.get('CYBERACCESS_CONSOLE_URL', 'http://127.0.0.1:5177')
CYBERACCESS_NOTIFICATIONS_ENABLED = os.environ.get('CYBERACCESS_NOTIFICATIONS_ENABLED', 'true').lower() in ('true', '1', 'yes')
CYBERACCESS_NOTIFICATION_COOLDOWN_SECONDS = max(1, int(os.environ.get('CYBERACCESS_NOTIFICATION_COOLDOWN_SECONDS', '60')))
CYBERACCESS_LOG_ALLOWED = os.environ.get('CYBERACCESS_LOG_ALLOWED', 'false').lower() in ('true', '1', 'yes')

# Safe decision metadata goes to server stdout. An optional rotating local file aids demos.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {'cyberaccess_console': {'class': 'logging.StreamHandler'}},
    'loggers': {'cyberaccess': {'handlers': ['cyberaccess_console'], 'level': 'INFO', 'propagate': False}},
}
_security_log_file = os.environ.get('CYBERACCESS_SECURITY_LOG_FILE', '')
if _security_log_file:
    Path(_security_log_file).parent.mkdir(parents=True, exist_ok=True)
    LOGGING['handlers']['cyberaccess_file'] = {
        'class': 'logging.handlers.RotatingFileHandler', 'filename': _security_log_file,
        'maxBytes': 2 * 1024 * 1024, 'backupCount': 3, 'encoding': 'utf-8',
    }
    LOGGING['loggers']['cyberaccess']['handlers'].append('cyberaccess_file')

# URL Safety Defense Configuration
URL_SAFETY_ENABLED = os.environ.get('URL_SAFETY_ENABLED', 'true').lower() in ('true', '1', 'yes')
