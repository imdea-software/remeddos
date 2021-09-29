from __future__ import absolute_import, unicode_literals


from celery import shared_task
from celery import subtask
import logging
from django.conf import settings
import os
from ipaddr import *
import os
from os import fork,_exit
from sys import exit
import time
import slack

LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')

#slack channel 
client = slack.WebClient(token=settings.SLACK_TOKEN)

# FORMAT = '%(asctime)s %(levelname)s: %(message)s'
# logging.basicConfig(format=FORMAT)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME)
handler.setFormatter(formatter)
logger.addHandler(handler)


@shared_task(ignore_result=True, serializer='json')
def add(route, callback=None):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply()
        if commit:            
            status = "ACTIVE"
        else:
            status = "ERROR"
        route.status = status
        route.response = response
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except Exception as e:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except TransactionManagementError: 
        route.status = "ERROR"
        route.response = "Transaction Management Error"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)

@shared_task(ignore_result=True)
def edit(route, callback=None):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply(operation="replace")
        if commit:
            status = "ACTIVE"
        else:
            status = "ERROR"
        route.status = status
        route.response = response
        route.save()
        message = (f"[{route.applier_username_nice}] Rule edit:  {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule edit:  {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule edit:  {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except Exception:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule edit:  {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)


@shared_task(ignore_result=True)
def delete(route, **kwargs):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply(operation="delete")
        reason_text = ''
        if commit:
            status = "INACTIVE"
            if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                status = 'EXPIRED'
                reason_text = " Reason: %s " % status
        else:
            status = "ERROR"
        route.status = status
        route.response = response
        route.save()
        message = (f"[{route.applier_username_nice}] Suspending rule:  {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Suspending rule:  {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Suspending rule:  {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    except Exception as e:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier_username_nice}] Suspending rule:  {route.name} - Result: {response}")
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)


# May not work in the first place... proxy is not aware of Route models
@shared_task(serializer='json')
def batch_delete(routes, **kwargs):
    from utils import proxy as PR
    import datetime

    if routes:
        for route in routes:
            route.status = 'PENDING';route.save()
        applier = PR.Applier(route_objects=routes)
        conf = applier.delete_routes()
        commit, response = applier.apply(configuration=conf)
        reason_text = ''
        if commit:
            status = "INACTIVE"
            if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                status = 'EXPIRED'
                reason_text = " Reason: %s " % status
            elif "reason" in kwargs and kwargs['reason'] != 'EXPIRED':
                status = kwargs['reason']
                reason_text = " Reason: %s " % status
        else:
            status = "ERROR"
        for route in routes:
            route.status = status
            route.response = response
            route.expires = datetime.date.today()
            route.save()
            message = (f"[{route.applier_username_nice}] Rule removal: %s%s- Result %s" % (route.name, reason_text, response), route.applier)
            client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    else:
        return False

@shared_task
def check_sync(route_name=None, selected_routes=[]):
    from flowspec.models import Route, MatchPort, MatchDscp, ThenAction
    if not selected_routes:
        routes = Route.objects.all()
    else:
        routes = selected_routes
    if route_name:
        routes = routes.filter(name=route_name)
    for route in routes:
        if route.has_expired() and (route.status != 'EXPIRED' and route.status != 'ADMININACTIVE' and route.status != 'INACTIVE'):
            if route.status != 'ERROR':
                message = ('Expiring %s route %s' %(route.status, route.name)) 
                client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
                route.status='EXPIRED'
                delete(route)
            if route.status == 'ERROR':
                message = ('Deleting %s route with error %s' %(route.status, route.name)) 
                client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
                route.status='EXPIRED'
                delete(route)
        else:
            if route.status != 'EXPIRED':
                route.check_sync()
@shared_task(ignore_result=True)
def notify_expired():
    from flowspec.models import Route
    import datetime
    from django.contrib.sites.models import Site
    from django.core.mail import send_mail
    from django.template.loader import render_to_string

    message = ('Initializing expiration notification')
    client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    routes = Route.objects.all()
    today = datetime.date.today()
    for route in routes:
        if route.expires != None:
            if route.status not in ['EXPIRED', 'ADMININACTIVE', 'INACTIVE', 'ERROR']:
                expiration_days = (route.expires - today).days
                if expiration_days < settings.EXPIRATION_NOTIFY_DAYS and expiration_days > 0:
                    try:
                        fqdn = Site.objects.get_current().domain
                        admin_url = "https://%s%s" % \
                        (fqdn,
                        "/edit/%s"%route.name)
                        mail_body = render_to_string("rule_action.txt", {"route": route, 'expiration_days':expiration_days, 'action':'expires', 'url':admin_url})
                        days_num = ' days'
                        expiration_days_text = "%s %s" %('in',expiration_days)
                        if expiration_days == 0:
                            days_num = ' today'
                            expiration_days_text = ''
                        if expiration_days == 1:
                            days_num = ' day'
                        message = ('Route %s expires %s%s. Notifying %s (%s)' %(route.name, expiration_days_text, days_num, route.applier.username, route.applier.email))
                        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
                        send_mail(settings.EMAIL_SUBJECT_PREFIX + "Rule %s expires %s%s" %
                                (route.name,expiration_days_text, days_num),
                                mail_body, settings.SERVER_EMAIL,
                                [route.applier.email])
                    except Exception as e:
                        message = ("Exception: %s"%e)
                        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
        else:
            message = ("Route: %s, won't expire." %route.name)
            client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
    messagae = ('Expiration notification process finished')
    client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)

@shared_task
def expired_val_codes():
    from flowspec.models import Validation
    valid_codes = Validation.objects.all()
    for code in valid_codes:
        code.is_outdated()


@shared_task
def routes_sync():
    from flowspec.models import Route
    from utils.proxy import Retriever
    from xml.etree import ElementTree as ET
    options =  [];flow = [];route = []
    retriever = Retriever()
    router_config = retriever.fetch_config_str()
    routes = Route.objects.all()
    tree = ET.fromstring(router_config)
    data = [d for d in tree]
    config = [c for c in data]   
    for config_nodes in config:
        options = config_nodes
    for option_nodes in options:
        flow = option_nodes 
    for flow_nodes in flow:
        route = flow_nodes      
    names = []
    for children in route:
        for child in children:
            if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                names.append(child.text)
            else:
                pass  
    routenames = [x.name for x in routes]
    diff = set(routenames).difference(names)
    notsynced_routes = list(diff)
    if notsynced_routes:
        for route in notsynced_routes:
            route = Route.objects.get(name=route)
            if (route.has_expired()==False) and (route.status == 'ACTIVE' or route.status == 'OUTOFSYNC'):
                route.commit_add()
                message = ('status: %s route out of sync: %s, saving route.' %(route.status, route.name))
                client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
            else:
                if (route.has_expired()==True) or (route.status == 'EXPIRED' or route.status != 'ADMININACTIVE' or route.status != 'INACTIVE'):
                    message = ('Route: %s route status: %s'%(route.status, route.name))
                    client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
                    route.check_sync()             
    else:
        message = ('There are no routes out of sync')
        client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
 
