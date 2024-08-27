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
        "schedule": crontab(minute='*/5', hour='*'),
        "args": (),
    },
}

