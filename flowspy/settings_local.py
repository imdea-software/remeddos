# -*- coding: utf-8 -*-

##############################################################################
##############################################################################
import os
import sys
print ("loaded settings_local.py")
import socket
from celery.schedules import crontab
try:
    FODHOSTNAME = socket.gethostname()
except:
    FODHOSTNAME = 'localhost'

MYSETTING1 = "testsettings1"

#sys.exit

##############################################################################
##############################################################################

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())

#=====Important variables

DATABASE_NAME=os.environ.get('DATABASE_NAME')
DATABASE_USER=os.environ.get('DATABASE_USER')
DATABASE_PWD=os.environ.get('DATABASE_PWD')


NETCONF_DEVICE=os.environ.get('NETCONF_DEVICE')
NETCONF_USER=os.environ.get('NETCONF_USER')
NETCONF_PASS=os.environ.get('NETCONF_PASS')
NETCONF_PORT=os.environ.get('NETCONF_PORT')

EMAIL_HOST_USER=os.environ.get('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD=os.environ.get('EMAIL_HOST_PASSWORD')



DEBUG = True
TEMPLATE_DEBUG = DEBUG

BASE_DIR = os.path.dirname(os.path.dirname(__file__))




ADMINS = (
    ('AdminName', 'alicia.cardenosa@imdea.org'),
)

MANAGERS = ADMINS

ALLOWED_HOSTS = ['*']
SITE_ID = 1

SECRET_KEY = 'XXXXXX'

DATABASES = {
   'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': DATABASE_NAME,
        'USER': DATABASE_USER,
        'PASSWORD': DATABASE_PWD,
        'HOST':'127.0.0.1',
        'PORT':'5432',
    }, 
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'Europe/Athens'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
_ = lambda s: s

LANGUAGES = (
    ('el', _('Greek')),
    ('en', _('English')),
)



ROOT_URLCONF = 'flowspy.urls'
WSGI_APPLICATION = 'flowspy.wsgi.application'

# Netconf Device credentials
# The following variables should contain the address of the device with
# flowspec, the username and password of the appliers account and the netconf
# port.
NETCONF_DEVICE = NETCONF_DEVICE

NETCONF_USER = NETCONF_USER
NETCONF_PASS = NETCONF_PASS
NETCONF_PORT = NETCONF_PORT


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

#Shibboleth attribute map
SHIB_AUTH_ENTITLEMENT = ''
SHIB_ADMIN_DOMAIN = 'grnet.gr'
SHIB_LOGOUT_URL = 'https://' + FODHOSTNAME + '/Shibboleth.sso/Logout'

# BCC mail addresses
NOTIFY_ADMIN_MAILS = ["alicia.cardenosa@imdea.org"]

# Then actions in the ui (dropdown)
UI_USER_THEN_ACTIONS = ['discard', 'rate-limit']
UI_USER_PROTOCOLS = ['icmp', 'tcp', 'udp']
ACCOUNT_ACTIVATION_DAYS = 7

# Define subnets that should not have any rules applied whatsoever
#PROTECTED_SUBNETS = ['10.10.0.0/16']
PROTECTED_SUBNETS = []
# max number of days into the future that is allowed to pick in rule expiration datepicker
#MAX_RULE_EXPIRE_DAYS = 10
MAX_RULE_EXPIRE_DAYS = 30

# Add two whois servers in order to be able to get all the subnets for an AS.
PRIMARY_WHOIS = 'whois.ripe.net'
ALTERNATE_WHOIS = 'whois.ripe.net'
# results in exceptions:
#ALTERNATE_WHOIS = 'whois.example.net'

LOG_FILE_LOCATION = "/var/log/fod"

BRANDING = {
    'name': 'RediFod',
    'url': 'https://www.redimadrid.es/',
    'footer_iframe': 'https://example.com/iframe',
    'facebook': '//facebook.com/',
    'twitter': '//twitter.com/',
    'phone': '+34 911 012 202',
    'email': 'noc@redimadrid.es',
    'logo': 'fodlogo2.png',
    'favicon': 'favicon.ico',
}

# Limit of ports in 'ports' / 'SrcPorts' / 'DstPorts' of a rule:
#PORTRANGE_LIMIT = 100
PORTRANGE_LIMIT = 65535

SNMP_COMMUNITY = "XXXXXXXXXXXXXX"
SNMP_IP = ["172.16.113.10",
            #"172.16.113.12",
            "172.16.113.14",
            "172.16.113.16"]


# currently unused
SNMP_CNTBYTES =     "1.3.6.1.4.1.2636.3.5.2.1.5"
SNMP_CNTPACKETS =   "1.3.6.1.4.1.2636.3.5.2.1.4"

# get only statistics of specified tables
SNMP_RULESFILTER = ["__flowspec_default_inet__", "__flowspec_IAS_inet__"]
# load new data into cache if it is older that a specified number of seconds
SNMP_POLL_INTERVAL = 8 #seconds
# cache file for data
SNMP_TEMP_FILE = "/tmp/snmp_temp_data"
SNMP_POLL_LOCK = "/var/run/fod/snmppoll.lock"

# Number of historical values to store for a route.
# Polling interval must be set for "snmp-stats-poll" celery task in CELERYBEAT_SCHEDULE.
# By default, it is 5 min interval, so SNMP_MAX_SAMPLECOUNT=12 means we have about
# one hour history.
#SNMP_MAX_SAMPLECOUNT = 12
SNMP_MAX_SAMPLECOUNT = 2016

# Age of inactive routes that can be already removed (in seconds)
#SNMP_REMOVE_RULES_AFTER = 3600
SNMP_REMOVE_RULES_AFTER = 604800

#

DISABLE_RULE_OVERLAP_CHECK = True

ENABLE_SETUP_VIEW = False

##############################################################################
##############################################################################
