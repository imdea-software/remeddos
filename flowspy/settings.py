import uuid
uuid._uuid_generate_random = None
try:
    from uuid import _uuid_generate_random
except ImportError:
    _uuid_generate_random = None

import os
from celery.schedules import crontab
from dotenv import load_dotenv, find_dotenv

import mimetypes
mimetypes.add_type("text/css", ".css", True)

load_dotenv(find_dotenv())

#===Important variables

DATABASE_NAME=os.environ.get('DATABASE_NAME')
DATABASE_USER=os.environ.get('DATABASE_USER')
DATABASE_PWD=os.environ.get('DATABASE_PWD')

ZABBIX_USER = os.environ.get('ZABBIX_USER')
ZABBIX_PWD =  os.environ.get('ZABBIX_PWD')
ZABBIX_SOURCE =  os.environ.get('ZABBIX_SOURCE')

GOLEM_USER = os.environ.get('GOLEM_USER')
GOLEM_PWD = os.environ.get('GOLEM_PWD')

NETCONF_DEVICE=os.environ.get('NETCONF_DEVICE')
NETCONF_USER=os.environ.get('NETCONF_USER')
NETCONF_PASS=os.environ.get('NETCONF_PASS')
NETCONF_PORT=os.environ.get('NETCONF_PORT')

NETCONF_DEVICE_B=os.environ.get('NETCONF_DEVICE_B')
NETCONF_USER_B=os.environ.get('NETCONF_USER_B')
NETCONF_PASS_B=os.environ.get('NETCONF_PASS_B')
NETCONF_PORT_B=os.environ.get('NETCONF_PORT_B')

STAFF_MAIL = os.environ.get('STAFF_MAIL')

DIR_GOLEM = os.environ.get('DIR_GOLEM')

DEBUG = False
DEBUG_PROPAGATE_EXCEPTIONS = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    ('Remadmin', STAFF_MAIL),
)
MANAGERS = ADMINS
here = lambda x: os.path.join(os.path.abspath(os.path.dirname(__file__)), x)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Hosts/domain names that are valid for this site; required if DEBUG is False
ALLOWED_HOSTS = ['remedios.redimadrid.es','localhost','193.145.15.172','10.10.4.90','db','logs.redimadrid.es']
SITE_ID = 1

# Place a sequence of random chars here
SECRET_KEY = os.environ.get('SECRET_KEY')

USE_TZ = True
TIME_ZONE = 'Europe/Madrid'

# Set up database

DATABASES = {
   'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASS'),
        'HOST':'db',
        'PORT':'5432',
    }, 
}
DBBACKUP_CONNECTORS = {'connector':'dbbackup.db.postgresql.PgDumpBinaryConnector'}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
#TIME_ZONE = 'Europe/Athens'
TIME_ZONE = 'Europe/Madrid'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
_ = lambda s: s

LANGUAGES = (
    ('en', _('English')),
)

LOCALE_PATHS = (
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'locale'),
)

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    "whitenoise.middleware.WhiteNoiseMiddleware",
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'simple_history.middleware.HistoryRequestMiddleware',
    "django.middleware.security.SecurityMiddleware",
    
]

# Templates


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates/'),
            ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                "context.global_vars.settings_vars",
            ],
        },
    },
]

ROOT_URLCONF = 'flowspy.urls'
WSGI_APPLICATION = 'flowspy.wsgi.application'

AUTHENTICATION_BACKENDS = (
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
    'django_python3_ldap.auth.LDAPBackend',
)

INSTALLED_APPS = (
    'whitenoise.runserver_nostatic',
    'longerusername',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.admin',
    'django.contrib.flatpages',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.postgres',
    'rest_framework',
    'rest_framework.authtoken',
    'flowspec',
    'poller',
    'peers',
    'accounts',
    'tinymce',
    'widget_tweaks',
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'dbbackup',
    'django_sass',
    'django_celery_results',
    'simple_history',
    'golem',
)

#---DBBACKUP 
DBBACKUP_STORAGE = 'django.core.files.storage.FileSystemStorage'
BACK_UP_DIR = os.path.join(BASE_DIR,'_backup/')

#---STATIC 

STATIC_ROOT = os.path.join(BASE_DIR, "staticfiles")
STATIC_URL = "static/"
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, "media")



#----MEDIA
MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')
MEDIA_URL = '/media/'

#GRAPHS_API_URL = 'graphs'
GRAPHS_API_URL = 'http://127.0.0.1:8080/api/routes/'

CORS_ALLOW_CREDENTIALS = True
CORS_ORIGIN_WHITELIST = (
    'redidock.redimadrid.es:8000',
    '127.0.0.1:8000'
)

DEFAULT_AUTO_FIELD='django.db.models.AutoField'

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
    }
}

#==Django-Allauth Settings

LOGIN_REDIRECT_URL = 'dashboard'
ACCOUNT_LOGOUT_REDIRECT_URL ='/accounts/login/'
DEFAULT_FROM_EMAIL = "remeddos@software.imdea.org"

ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS =1

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
    }
}

AUTH_PROFILE_MODULE = 'accounts.UserProfile'

# Netconf Device credentials
# The following variables should contain the address of the device with
# flowspec, the username and password of the appliers account and the netconf
# port.
NETCONF_DEVICE = NETCONF_DEVICE

NETCONF_USER = NETCONF_USER
NETCONF_PASS = NETCONF_PASS
NETCONF_PORT = NETCONF_PORT

# The filter applied in the device in order to find the flowspec routes
ROUTES_FILTER = "<configuration><routing-options><flow/></routing-options></configuration>"
ROUTE_FILTER = "<configuration><routing-options><flow><route><name>%s</name></route></flow></routing-options></configuration>"
COMMIT_CONFIRMED_TIMEOUT = "120"

# Change the following values only if you know what you are doing!!!
# To integrate FoD with tables (Peer, Networks, Contacts)
# from your CRM platform, set the following values to False and create the views that are
# exact matches of the tables in peers/models.py
PEER_MANAGED_TABLE = True
PEER_RANGE_MANAGED_TABLE = True
PEER_TECHC_MANAGED_TABLE = True

# Actually apply the rules
COMMIT = True

# Flowspy configuration
#EXPIRATION_DAYS_OFFSET = 7
EXPIRATION_DAYS_OFFSET = 30

USE_X_FORWARDED_HOST = True

# List of modules to import when celery starts.
imports = ("flowspec.tasks",)

# broker configuration for celery
POLLS_TUBE = 'polls'
BROKER_URL = "redis://redis:6379"
CELERY_RESULT_BACKEND = "redis://redis:6379"
POLL_SESSION_UPDATE = 60.0
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TASK_SERIALIZER ='json'
CELERY_TIMEZONE = 'Europe/Madrid'



#ENABLE_SETUP_VIEW = True

# Notifications
EMAIL_HOST = os.environ.get('EMAIL_HOST')
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = True
EMAIL_PORT = 587

DISABLE_EMAIL_NOTIFICATION = False
SERVER_EMAIL = os.environ.get('EMAIL_HOST_USER')
EMAIL_SUBJECT_PREFIX = "[REMeDDoS] "
EXPIRATION_NOTIFY_DAYS = 4
PREFIX_LENGTH = 29
POLL_SESSION_UPDATE = 60.0

#==Slack Notifications
SLACK_TOKEN=os.environ.get('SLACK_TOKEN')
SLACK_CHANNEL=os.environ.get('CHANNEL')
REM_SLACK_TOKEN = os.environ.get('REM_SLACK_TOKEN')

#==Telegram Bot
API_KEY_T=os.getenv('API_KEY_TG')

# BCC mail addresses
NOTIFY_ADMIN_MAILS = [STAFF_MAIL]

# Then actions in the ui (dropdown)
UI_USER_THEN_ACTIONS = ['discard', 'rate-limit','accept']
UI_USER_PROTOCOLS = ['icmp', 'tcp', 'udp']
UI_USER_TCPFLAG = ["ack","rst","fin","push","urgent","syn"]
ACCOUNT_ACTIVATION_DAYS = 7

# Define subnets that should not have any rules applied whatsoever
PROTECTED_SUBNETS = ['10.10.0.0/16']
# max number of days into the future that is allowed to pick in rule expiration datepicker
MAX_RULE_EXPIRE_DAYS = 30

# Add two whois servers in order to be able to get all the subnets for an AS.
PRIMARY_WHOIS = 'whois.remedios.redimadrid.es'
ALTERNATE_WHOIS = 'whois.remedios.redimadrid.com'

TINYMCE_JS_URL = STATIC_URL +'js/tinymce/tiny_mce.js'

TINYMCE_DEFAULT_CONFIG = {
    'extended_valid_elements': 'iframe[src|width|height|name|align]',
    'plugins': "table,spellchecker,paste,searchreplace",
    'theme': "advanced",
}

import _version
SW_VERSION = _version.VERSION

LOG_FILE_LOCATION = "/var/log/fod"


BRANDING = {
    'name': 'REM-E-DDOS',
    'url': 'https://remeddos.com',
    'footer_iframe': 'https://remeddos.com/iframe',
    'facebook': '//facebook.com/',
    'twitter': '//twitter.com/',
    'phone': '800-example-com',
    'email': STAFF_MAIL,
    'logo': 'logo.png',
    'favicon': 'favicon.ico',
}


# Django Rest Framework configuration.
# You should leave this intact.
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.TokenAuthentication',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    ),
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.DjangoModelPermissions',
        'rest_framework.permissions.IsAuthenticated'
    ]
}

# Limit of ports in 'ports' / 'SrcPorts' / 'DstPorts' of a rule:
#PORTRANGE_LIMIT = 100
PORTRANGE_LIMIT = 65535

# Statistics polled via SNMP:
# Default community string
SNMP_COMMUNITY = "abcd"

# list of IP addresses, each IP is a dict with "ip", "port" (optional, default
# is 161), "community" (optional, default is SNMP_COMMUNITY) keys
SNMP_IP = [
    {"ip": "192.168.0.1", "port": 1000},
    {"ip": "192.168.0.2", "port": 1001, "community": "abcdef"},
    {"ip": "192.168.0.3", "port": 1002},
    {"ip": "192.168.0.4", "port": 1002}
]

# or simpler way of IP list:
# SNMP_IP = ["10.0.0.1", "10.0.0.2"]

# OID of bytes counter (currently unused)
SNMP_CNTBYTES =     "1.3.6.1.4.1.2636.3.5.2.1.5"
# OID of packet counter
SNMP_CNTPACKETS =   "1.3.6.1.4.1.2636.3.5.2.1.4"

# get only statistics of specified tables
SNMP_RULESFILTER = ["__flowspec_default_inet__", "__flowspec_IAS_inet__"]
# load new data into cache if it is older that a specified number of seconds
SNMP_POLL_INTERVAL = 8 #seconds
# cache file for data
SNMP_TEMP_FILE = "/tmp/snmp_temp_data"
SNMP_POLL_LOCK = "/var/run/fod/snmppoll.lock"

# Number of historical values to store for a route.
# Polling interval must be set for "snmp-stats-poll" celery task in beat_schedule.
# By default, it is 5 min interval, so SNMP_MAX_SAMPLECOUNT=12 means we have about
# one hour history.
SNMP_MAX_SAMPLECOUNT = 12

# Age of inactive routes that can be already removed (in seconds)
SNMP_REMOVE_RULES_AFTER = 3600

##############################################################################
##############################################################################

# REST API config (v1.6 only)

DISABLE_RULE_OVERLAP_CHECK = False

ALLOW_DELETE_FULL_FOR_NONADMIN = False

MAIL_NOTIFICATION_TO_ALL_MATCHING_PEERS = True

# statistics calc

STATISTICS_PER_MATCHACTION_ADD_FINAL_ZERO = False # not necessary if STATISTICS_PER_RULE==True
STATISTICS_PER_RULE = True

STATISTICS_PER_RULE__ADD_INITIAL_ZERO = True


DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

# HTTPS settings  
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# HSTS settings
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_PRELOAD = True
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

""" LDAP SERVER CONFIG  """

# The URL of the LDAP server(s).  List multiple servers for high availability ServerPool connection.
LDAP_AUTH_URL = ["ldaps://ldap.software.imdea.org"]

# Specify which TLS version to use (Python 3.10 requires TLSv1 or higher)
import ssl
LDAP_AUTH_TLS_VERSION = ssl.PROTOCOL_TLSv1_2


AUTH_LDAP_SERVER_URI = "ldaps://ldap.software.imdea.org" 
LDAP_AUTH_SEARCH_BASE = "ou=People,dc=software,dc=imdea,dc=org"

LDAP_ALWAYS_SEARCH_BIND = True

AUTH_LDAP_START_TLS = True