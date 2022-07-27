from __future__ import absolute_import, unicode_literals

import os

from django.conf import settings
from celery import Celery

from celery.schedules import crontab


os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'flowspy.settings')

#using celerys broker or redis
app = Celery('flowspy')
app.config_from_object('django.conf:settings')
app.conf.timezone = 'UTC'
app.conf.redbeat_redis_url = 'redis://redis:6379'
app.autodiscover_tasks()
app.conf.beat_schedule = {
    "every-day-route-sync": {
        "task": "flowspec.tasks.routes_sync",
        "schedule": crontab(minute=0, hour=0),
        "args": (),
    },
    "every-day-sync": {
        "task": "flowspec.tasks.check_sync",
        "schedule": crontab(minute=0, hour=0),
        "args": (),
    },
    "notify-expired": {
        "task": "flowspec.tasks.notify_expired",
        "schedule": crontab(minute=0, hour=0),
        "args": (),
    },
    "every-day-sync-codes": {
        "task": "flowspec.tasks.expired_val_codes",
        "schedule": crontab(minute=0, hour=0), 
        "args": (),
    },
    "daily-back-up": {
        "task": "flowspec.tasks.daily_backup",
        "schedule": crontab(minute=0, hour=0), 
        "args": (),
    },
    "every-day-del-golem-events": {
        "task": "flowspec.tasks.delete_expired_events",
        "schedule": crontab(minute=0, hour=0), 
        "args": (),
    },
    "every-day-del-proposed-routes": {
        "task": "flowspec.tasks.delete_expired_proposed_routes",
        "schedule": crontab(minute=0, hour=0), 
        "args": (),
    },
    "every-day-sync-router-with-db":{
        "task":"flowspec.tasks.sync_router_with_db",
        "schedule":crontab(minute=0,hour=0),
        "args":(),
    },
}

