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
from flowspec.helpers import *
from django.http import HttpResponse
from flowspec.models import *

LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')

#slack channel 

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
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message)
    except Exception as e:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message)
    except TransactionManagementError: 
        route.status = "ERROR"
        route.response = "Transaction Management Error"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message)

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
        message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
        send_message(message)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
        send_message(message)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
        send_message(message)
    except Exception:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
        send_message(message)


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
        message = (f"Suspending rule:  {route.name}")
        send_message(message)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {response}")
        send_message(message)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {response}")
        send_message(message)
    except Exception as e:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {response}")
        send_message(message)


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
            send_message(message)
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
                send_message(message)
                route.status='EXPIRED'
                route.save()
                delete(route)
            if route.status == 'ERROR' and route.has_expired():
                message = ('Deleting %s route with error %s' %(route.status, route.name)) 
                send_message(message)
                route.status='EXPIRED'
                print(' this is route, ',route.status)
                route.save()
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
    send_message(message)
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
                        message = ('Route %s expires %s%s. Notifying %s (%s)' %(route.name, expiration_days_text, days_num, route.applier, route.applier.email))
                        send_message(message)
                        send_mail(settings.EMAIL_SUBJECT_PREFIX + "Rule %s expires %s%s" %
                                (route.name,expiration_days_text, days_num),
                                mail_body, settings.SERVER_EMAIL,
                                [route.applier.email])
                    except Exception as e:
                        message = ("Exception: %s"%e)
                        send_message(message)
        else:
            message = ("Route: %s, won't expire." % route.name)
            send_message(message)
    messagae = ('Expiration notification process finished')
    send_message(message)

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
                send_message(message)
            else:
                if (route.has_expired()==True) or (route.status == 'EXPIRED' or route.status != 'ADMININACTIVE' or route.status != 'INACTIVE'):
                    message = ('Route: %s route status: %s'%(route.status, route.name))
                    send_message(message)
                    route.check_sync()             
    else:
        message = ('There are no routes out of sync')
        send_message(message)
 
@shared_task
def back_up():
    from flowspec.models import Backup_signal
    from django.core.management import call_command
    import datetime

    now = datetime.datetime.now()
    current_time = now.strftime("%H:%M")
    current_date = now.strftime("%d-%B-%Y")
    signal_object = Backup_signal.objects.latest('pk')
    if signal_object.boolean: 
        try:
            call_command('dbbackup', output_filename=(f"redifod-{current_date}-{current_time}.psql"))
            message = 'Back up succesfully created.'
            signal_object.boolean = False
            signal_object.save()
            print('it worked ', signal_object)
            send_message(message) 
        except Exception as e:
            message = ('An error came up and the database was not created. %s'%e)
            send_message(message)
        pass
    else:
        print('There are no changes in the database')


@shared_task
def post(request,anomaly_ticket, anomaly_info, id_event, *args, **kwargs):
    import time
    import subprocess 
    from flowspec.models import AttackEvent    
    print('New webhook message, event status: ', anomaly_info['status'], ' ', anomaly_info['severity'],' ', id_event)
    if not anomaly_info['institution_name'] == 'Non-Home':
        if anomaly_info['status'] == 'Open' or anomaly_info == 'Ongoing':
            print('something happened , id: ', id_event)
            time.sleep(90)
            event_ticket, event_info = petition_geni(id_event)
            event_data, event, traffic_event = event_ticket['response']['result']['data'],  event_ticket['response']['result']['data'][0]['event'], event_ticket['response']['result']['data'][0]['traffic_characteristics']
            net_event = event_ticket['response']['result']['data'][0]['network_elements'] if event_ticket['response']['result']['data'][0]['network_elements'] else ''
            mv, tv = float(event_info['max_value']), float(event_info['threshold_value'])
            if ((mv/tv)*100) > 100 and not event_info['status'] == 'Recovered' and not event_info['status']=='Burst':
                print('traffic_event', traffic_event)
                print('##########')
                print('_event_data', event_data)
                print('##########')
                print('trace 0')
                # first rule proposition and send email to user
                id_attack, status, severity_type, max_value, th_value, attack_name, institution_name, initial_date, ip_attacked = event_info['id'], event_info['status'], event_info['severity'], event_info['max_value'], event_info['threshold_value'] , event_info['attack_name'], event_info['institution_name'], event_info['initial_date'], event_info['ip_attacked']
                print('ip attacked: ', ip_attacked)
                ip = get_ip_address(ip_attacked)
                send_message(f"Nuevo ataque a la institución '{institution_name}' de tipo '{attack_name}' contra el recurso '{ip}'. La regla para poder mitigar este ataque que te proponemos desde RediMadrid es [ ... ]. Más información sobre el ataque : Id: {id_attack}, Status: {status}, Max Value: {max_value}, Threshold value: {th_value}.")  
                recovered = False
                geni_attack = AttackEvent(id_attack=id_attack,institution_name=institution_name,name_attack=attack_name,status=status,max_value=max_value,threshold_value=th_value,ip_attacked=ip_attacked,severity=severity_type)                    
                geni_attack.save()
                time.sleep(210)
                # dest ip protrocolo de origen y el puerto y el tcp-flag si es udp debe ser descartado porque siempre va a ser 0
                print('trace 1')
                event_data, info = petition_geni(id_event)
                print('trace 2 after geni petition')
                mv, tv = float(info['max_value']), float(info['threshold_value'])
                if ((mv/tv)*100) > 200 and not info['status'] == 'Recovered' and not info['status']=='Burst':
                    print('trace 3 inside second condition after waiting 210 second')
                    id_att, status, max_v, th_value, name, institution_name, initial_date, ip_att = info['id'], info['status'],  info['max_value'], info['threshold_value'] , info['attack_name'], info['institution_name'], info['initial_date'], info['ip_attacked']                  
                    attack = AttackEvent.objects.get(id_attack=id_event)
                    attack.status, attack.max_value, attack.threshold_value = info['status'], info['max_value'], info['threshold_value']
                    attack.save()
                    send_message(f'El ataque registrado anteriormente a la institucion {institution_name} con id {id_att} persiste y hemos obtenido nuevos datos del {name}, la regla de firewall que te proponemos desde RediMadrid es [ ... ]. Más información sobre el ataque : id: {id_event}, status: {status},  max_value: {max_v}, threshold value: {th_value}')
                    # second rule proposition
                    # preguntar si no es recover un bucle hasta que devuelva recovery cada 5 min
                    # check multi threading in case there are multiple attacks going on 
                    while recovered:
                        print('inside while loop')
                        time.sleep(300)
                        attack_data, attack_info = petition_geni(id_event)
                        mv, thv = float(attack_info['max_value']), float(attack_info['threshold_value'])
                        if ((mv/thv)*100) > 200 and not attack_info['status'] == 'Recovered' and not attack_info == 'Burst':
                            # again send rule proposition
                            #GeniEvents.objects.create(event=event_info,traffic_characteristics=traffic_event,network_characteristics=net_event)
                            id_attack, status, severity_type, max_value, th_value, attack_name, institution_name, initial_date, ip_attacked = attack_info['id'], attack_info['status'], attack_info['severity'], attack_info['max_value'], attack_info['threshold_value'] , attack_info['attack_name'], attack_info['institution_name'], attack_info['initial_date'], attack_info['ip_attacked']
                            attack = AttackEvent.objects.get(id_attack=id_event)
                            attack.status, attack.max_value, attack.threshold_value = attack_info['status'], attack_info['max_value'], attack_info['threshold_value']
                            attack.save()
                            send_message(f"El ataque registrado anteriormente a la institución {institution_name} persiste {name} y hemos obtenido nuevos datos, la regla de firewall que te proponemos desde RediMadrid es [ ... ]. Más información sobre el ataque : Id: {id_attack}, Status: {status}, Max Value: {max_value}, Threshold value: {th_value}.")
                            recovered = False
                        else: 
                            if attack_info['status'] == 'Recovered' or attack_info['status'] == 'Burst':
                            # si es recovered coger los datos de inicio y fin del ataque, informar
                                id_attack, status, severity_type, max_value, th_value, attack_name, institution_name, initial_date, ip_attacked = attack_info['id'], attack_info['status'], attack_info['severity'], attack_info['max_value'], attack_info['threshold_value'] , attack_info['attack_name'], attack_info['institution_name'], attack_info['initial_date'], attack_info['ip_attacked']
                                attack = AttackEvent.objects.get(id_attack=id_event)
                                attack.status, attack.max_value, attack.threshold_value = attack_info['status'], attack_info['max_value'], attack_info['threshold_value']
                                attack.save()
                                send_message(f"El ataque registrado anteriormente a la institución {institution_name} con nombre {name} e id {id_attack} ha terminado. Más información sobre el ataque : Id: {id_attack}, Status: {status}, Max Value: {max_value}, Threshold value: {th_value}.")
                                recovered = True
                else:
                    if info['status'] == 'Recovered' or info['status']=='Burst':
                        attack = AttackEvent.objects.get(id_attack=id_event)
                        id_att, status, max_v, th_value, name, institution_name, initial_date, ip_att = info['id'], info['status'],  info['max_value'], info['threshold_value'] , info['attack_name'], info['institution_name'], info['initial_date'], info['ip_attacked']
                        send_message(f"El ataque registrado anteriormente a la institución {institution_name} con nombre {name} y estado {status} ha terminado. Más información sobre el ataque : Id: {id_attack}, Max Value: {max_value}, Threshold value: {th_value}.")                  
                # send message to slack saying the attack has finished
                # wait 4 min 
                # rule proposition and send email to user
                # repeat process every 5 min until status equals 'recovered'
                #GeniEvents.objects.create(event=event_info,traffic_characteristics=traffic_event,network_characteristics=net_event)
        elif anomaly_info['status'] =='Burst':
            print('evento descartado, estado burst') 
            pass
        else: 
            # check if it's recovered and already in database to inform the attack is over
            pass     
    else:
        pass
        