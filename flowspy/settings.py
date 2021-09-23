# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab
# Django settings for flowspy project.
# Copyright © 2011-2015 Greek Research and Technology Network (GRNET S.A.)
# Copyright © 2011-2014 Leonidas Poulopoulos (@leopoul)
# Copyright © 2014-2015 Stavros Kroustouris (@kroustou)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# _uuid_generate_random was deprecated and removed in newer python
import uuid
uuid._uuid_generate_random = None
try:
    from uuid import _uuid_generate_random
except ImportError:
    _uuid_generate_random = None

import os
from celery.schedules import crontab
from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

#===Important variables

DATABASE_NAME=os.environ.get('DATABASE_NAME')
DATABASE_USER=os.environ.get('DATABASE_USER')
DATABASE_PWD=os.environ.get('DATABASE_PWD')

ZABBIX_USER = os.environ.get('ZABBIX_USER')
ZABBIX_PWD =  os.environ.get('ZABBIX_PWD')
ZABBIX_SOURCE =  os.environ.get('ZABBIX_SOURCE')

NETCONF_DEVICE=os.environ.get('NETCONF_DEVICE')
NETCONF_USER=os.environ.get('NETCONF_USER')
NETCONF_PASS=os.environ.get('NETCONF_PASS')
NETCONF_PORT=os.environ.get('NETCONF_PORT')

EMAIL_HOST_USER=os.environ.get('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD=os.environ.get('EMAIL_HOST_PASSWORD')



DEBUG = True
TEMPLATE_DEBUG = DEBUG

ADMINS = (
    ('AdminName', 'admin@example.com'),
)
MANAGERS = ADMINS
here = lambda x: os.path.join(os.path.abspath(os.path.dirname(__file__)), x)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# Hosts/domain names that are valid for this site; required if DEBUG is False
ALLOWED_HOSTS = ['redifod.redimadrid.es','127.0.0.1','localhost','193.145.15.172','10.10.4.90','db']
SITE_ID = 1

# Place a sequence of random chars here
SECRET_KEY = '@sa@5234#$%345345^@#$%*()123^@12!&!()$JMNDF#$@(@#8FRNJWX_'

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
#DBBACKUP_CONNECTORS = {'connector':'dbbackup.db.postgresql.PgDumpBinaryConnector'}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
#TIME_ZONE = 'Europe/Athens'
TIME_ZONE = 'Europe/London'

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
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# Templates

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [            
            os.path.join(BASE_DIR, 'templates'),
        ],
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
                "context.global_vars.settings_vars",
                'django.template.context_processors.request',
            ],
            'loaders': [
                'django.template.loaders.filesystem.Loader',
                'django.template.loaders.app_directories.Loader',
            ]
        },
    },
]


ROOT_URLCONF = 'flowspy.urls'
WSGI_APPLICATION = 'flowspy.wsgi.application'

AUTHENTICATION_BACKENDS = (
    'djangobackends.shibauthBackend.shibauthBackend',
    'django.contrib.auth.backends.ModelBackend',
        'allauth.account.auth_backends.AuthenticationBackend',
)

INSTALLED_APPS = (
    'longerusername',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.admin',
    'django.contrib.flatpages',
    'django.contrib.messages',
    'django.contrib.staticfiles',
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
)

#---DBBACKUP 
DBBACKUP_STORAGE = 'django.core.files.storage.FileSystemStorage'
BACK_UP_DIR = os.path.join(BASE_DIR,'_backup/')
DBBACKUP_STORAGE_OPTIONS = {'location': BACK_UP_DIR}
DBBACKUP_FILE_NAME_TEMPLATE='redifod-{databasename}-{datetime}.sql'

#---STATIC 
STATIC_ROOT = os.path.join(BASE_DIR, 'static/')
STATIC_URL = "/static/"

#----MEDIA
MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')
MEDIA_URL = '/media/'

#GRAPHS_API_URL = 'graphs'
GRAPHS_API_URL = 'http://127.0.0.1:8080/api/routes/'

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


ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS =1




# CACHES = {
#     'default': {
#         'BACKEND': 'django.core.cache.backends.memcached.MemcachedCache',
#         'LOCATION': '127.0.0.1:11211',
#     }
# }
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

# broker configuration for celery
POLLS_TUBE = 'polls'
CELERY_BROKER_URL = "redis://redis:6379"
RESULT_BACKEND = "redis://redis:6379"
CELERY_CONCURRENCY = 1
POLL_SESSION_UPDATE = 60.0
##
accept_content = ['application/json']
result_serializer = 'json'
task_serializer='json'




# List of modules to import when celery starts.
imports = ("flowspec.tasks",)

#ENABLE_SETUP_VIEW = True

# Notifications
EMAIL_HOST='smtp.gmail.com'
EMAIL_HOST_USER=EMAIL_HOST_USER
EMAIL_HOST_PASSWORD=EMAIL_HOST_PASSWORD
EMAIL_USE_TLS=True
EMAIL_PORT=587

DISABLE_EMAIL_NOTIFICATION = False
SERVER_EMAIL = "RediMadrid FoD Service (TEST) <redimadridalicia@gmail.com>"
EMAIL_SUBJECT_PREFIX = "[FoD] "
EXPIRATION_NOTIFY_DAYS = 4
PREFIX_LENGTH = 29
POLL_SESSION_UPDATE = 60.0

#==Slack Notifications
SLACK_TOKEN=os.environ.get('SLACK_TOKEN')
SLACK_CHANNEL=os.environ.get('CHANNEL')

# BCC mail addresses
NOTIFY_ADMIN_MAILS = ["admin@example.com"]

# Then actions in the ui (dropdown)
UI_USER_THEN_ACTIONS = ['discard', 'rate-limit']
UI_USER_PROTOCOLS = ['icmp', 'tcp', 'udp']
ACCOUNT_ACTIVATION_DAYS = 7

# Define subnets that should not have any rules applied whatsoever
PROTECTED_SUBNETS = ['10.10.0.0/16']
# max number of days into the future that is allowed to pick in rule expiration datepicker
MAX_RULE_EXPIRE_DAYS = 30

# Add two whois servers in order to be able to get all the subnets for an AS.
PRIMARY_WHOIS = 'whois.redimadrid.redifod.com'
ALTERNATE_WHOIS = 'whois.example.net'

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
    'name': 'Redifod',
    'url': 'https://example.com',
    'footer_iframe': 'https://example.com/iframe',
    'facebook': '//facebook.com/',
    'twitter': '//twitter.com/',
    'phone': '800-example-com',
    'email': 'helpdesk@example.com',
    'logo': 'fodlogo2.png',
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
##############################################################################
##############################################################################

#MYSETTING1="default"
#from settings_local import *
#from flowspy.settings_local import *

#print "MYSETTING1="+MYSETTING1
#print("MYSETTING1="+MYSETTING1, file=sys.stderr)
#print "debug settings.NOTIFY_ADMIN_MAILS="+str(NOTIFY_ADMIN_MAILS)

##############################################################################
##############################################################################

