"""
Django settings for lost_found_project.
"""

from pathlib import Path
import os

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-lost-found-secret-key-change-in-production')

DEBUG = True

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
        'NAME': BASE_DIR / 'database' / 'db.sqlite3',
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

# Auto-load .env if present
_env_file = BASE_DIR / '.env'
if _env_file.exists():
    for _l in _env_file.read_text(encoding='utf-8').splitlines():
        _l = _l.strip()
        if _l and not _l.startswith('#') and '=' in _l:
            _k, _v = _l.split('=', 1)
            os.environ.setdefault(_k.strip(), _v.strip())

# CyberAccess BOLA Defense Engine Configuration (OWASP API1:2023)
CYBERACCESS_ENABLED = os.environ.get('CYBERACCESS_ENABLED', 'true').lower() in ('true', '1', 'yes')
CYBERACCESS_API_URL = os.environ.get('CYBERACCESS_API_URL', 'http://127.0.0.1:8000')
CYBERACCESS_API_KEY = os.environ.get('CYBERACCESS_API_KEY', 'dev_test_key')
CYBERACCESS_FAIL_OPEN = os.environ.get('CYBERACCESS_FAIL_OPEN', 'true').lower() in ('true', '1', 'yes')
CYBERACCESS_TIMEOUT = float(os.environ.get('CYBERACCESS_TIMEOUT', '2.0'))
CYBERACCESS_CANARIES = os.environ.get('CYBERACCESS_CANARIES', '0,999999,canary_admin_vault').split(',')

# URL Safety Defense Configuration
URL_SAFETY_ENABLED = os.environ.get('URL_SAFETY_ENABLED', 'true').lower() in ('true', '1', 'yes')
