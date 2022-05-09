from __future__ import absolute_import, unicode_literals
from socket import IP_TOS
from tabnanny import check


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
from golem.helpers import *

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
    peers = ['CV', 'CIB', 'CSIC', 'CEU', 'CUNEF', 'IMDEA_NET', 'IMDEA', 'UAM', 'UC3M', 'UCM', 'UAH', 'UEM', 'UNED', 'UPM', 'URJC']
    for peer in peers:
        if not selected_routes:
            routes = find_routes(applier=None,peer=peer)
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
                elif route.status == 'OUTOFSYN':
                    route.check_sync()
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
    peers = ['CV', 'CIB', 'CSIC', 'CEU', 'CUNEF', 'IMDEA_NET', 'IMDEA', 'UAM', 'UC3M', 'UCM', 'UAH', 'UEM', 'UNED', 'UPM', 'URJC']
    message = ('Initializing expiration notification')
    #send_message(message)
    print(message)
    for peer in peers:
        routes = find_routes(applier=None, peer=peer)
        today = datetime.date.today()
        for route in routes:
            print('routes: ', route)
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
                print(message)
                pass
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
    from flowspec.helpers import find_all_routes
    from utils.proxy import Retriever
    from xml.etree import ElementTree as ET
    options =  [];flow = [];route = []
    retriever = Retriever()
    router_config = retriever.fetch_config_str()
    routes = find_all_routes()
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
    routenames = []
    for x in routes:
        for route in x:
            if route.applier != None:
                print(route.name)
                routenames.append(route.name)
    diff = set(routenames).difference(names)
    notsynced_routes = list(diff)
    if notsynced_routes:
        for route in notsynced_routes:
            pt = route.find('_')
            peer_tag = route[pt+1::]
            route = get_specific_route(applier=None,peer=peer_tag,route_slug=route)
            try:
                if (route.status == 'PENDING' or route.status == 'DEACTIVATED' or route.status == 'OUTOFSYNC') and route.applier == None:
                    print(route)
                    route.status = 'PENDING'
                    route.save()
                    
                if (route.has_expired()==False) and (route.status == 'ACTIVE' or route.status == 'OUTOFSYNC'):
                    route.commit_add()
                    message = ('status: %s route out of sync: %s, saving route.' %(route.status, route.name))
                    send_message(message)
                else:
                    if (route.has_expired()==True) or (route.status == 'EXPIRED' or route.status != 'ADMININACTIVE' or route.status != 'INACTIVE'):
                        message = ('Route: %s route status: %s'%(route.status, route.name))
                        send_message(message)
                        route.check_sync()  
            except Exception as e:
                print('There was an exception when trying to sync the routes, route: ',route,' error: ', e)           
    else:
        message = ('There are no routes out of sync')
        send_message(message)


@shared_task
def create_route(golem_id,route_dic,peer):
    from flowspec.helpers import get_route,find_routes
    from golem.models import GolemAttack
    from peers.models import Peer
    #ip origen, ip destino, protocolo, puerto (que mas trafico tenga), la tcp flag q mas trafico que tenga, 
    #el tcp-flag si el protocolo es udp debe ser descartado porque siempre va a ser 0
    peers = Peer.objects.get(peer_tag=peer)
    golem_routes = []
    try:
        routes = find_routes(applier=None, peer=peer)
        route = get_route(applier=None,peer=peer)
        for r in routes:
            name = r.name
            fd = name.find('_')
            if golem_id==name[:fd]:
                golem_routes.append(r)
                #busqueda de todas las reglas, ver si alguna tiene el nombre del ataque
                #cuantas hay, dependiendo de cuantas crear 1,2,3
        if len(golem_routes)==0:
            try: 
                route.name = route_dic['name']+'_1'
                route.peer = peers
                route.status = 'PENDING'
                tcpflag = golem_translate_tcpflag(route_dic['tcpflag'])
                route.source,route.destination,route.port,route.tcpflag = route_dic['ipsrc'],route_dic['ipdest'],route_dic['port'], tcpflag
                route.save() 
                print(route)
                route.protocol.add(route_dic['protocol'])
                g = GolemAttack.objects.get(id_name=golem_id)
                g.set_route(route)
                g.save()
                return route
            except Exception as e:
                print('An exception happened: ',e)
        else:
            golem_routes.sort()
            last_element = golem_routes[-1]
            n = last_element.name[-1]
            num = (int(n)+1)
            dicname = route_dic['name']
            name = str(f"{dicname}_{num}")
            print('name: ',name,' tipo: ',type(name))
            route.name = name
            route.peer = peers
            route.status = 'PENDING'
            tcpflag = golem_translate_tcpflag(route_dic['tcpflag'])
            route.source,route.destination,route.port,route.tcpflag = route_dic['ipsrc'],route_dic['ipdest'],route_dic['port'], tcpflag
            route.save()
            route.protocol.add(route_dic['protocol'])
            g = GolemAttack.objects.get(id_name=golem_id)
            g.set_route(route)
            g.save()
            return route
    except MultipleObjectsReturned:
        print('Route has already being commited to the router')
        return None


@shared_task
def post(anomaly_info, id_event):
    from flowspec.models import MatchProtocol
    from golem.models import GolemAttack
    from golem.helpers import petition_geni
    import time
    
    print('New webhook message, event status: ', anomaly_info['status'], ' ', anomaly_info['severity'],' ', id_event)
    if not anomaly_info['institution_name'] == 'Non-Home':
        if anomaly_info['status'] == 'Open' or anomaly_info == 'Ongoing':
            time.sleep(90)
            event_ticket, event_info = petition_geni(id_event)
            traffic_event = event_ticket['response']['result']['data'][0]['traffic_characteristics']
            dic_regla = assemble_dic(traffic_event,event_info)
            if not event_info['status'] == 'Recovered' and not event_info['status']=='Burst':
                prt = traffic_event[4]['data'][0][0]; protocol = get_protocol(prt)
                ip = get_ip_address(event_info['ip_attacked'])
                link = get_link(dic_regla['id_attack'])
                send_message(f"Nuevo ataque a la institución '{dic_regla['institution_name']}' de tipo '{dic_regla['attack_name']}' contra el recurso '{ip}'. Algunos datos sobre el ataque son: Id: {dic_regla['id_attack']}, Status: {dic_regla['status']}, Max Value: {dic_regla['max_value']} Threshold value: {dic_regla['th_value']}. Para más información sobre el ataque consulte el siguiente link: {link}.")  
                peer = find_peer(dic_regla['institution_name'])
                route_dic = {'name':dic_regla['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla['ip_dest'],'ipsrc':dic_regla['ip_src'],'protocol':protocol.pk,'tcpflag':dic_regla['tcp_flag'],'port':dic_regla['port']}
                if peer:
                    geni_attack = GolemAttack(id_name=dic_regla['id_attack'], peer=peer, ip_src = dic_regla['ip_src'], port=dic_regla['port'], tcpflag=dic_regla['tcp_flag'], status = dic_regla['status'], max_value=dic_regla['max_value'],threshold_value=dic_regla['th_value'], typeof_attack=dic_regla['typeofattack'],typeof_value=dic_regla['typeofvalue'])
                    geni_attack.save()
                    create_route(dic_regla['id_attack'],route_dic, peer.peer_tag)
                    if isinstance(protocol,(list)):
                        for p in protocol:
                            fs = p.find('(')
                            prot, created = MatchProtocol.objects.get_or_create(protocol=p[:fs].lower())
                            geni_attack.protocol.add(prot.pk)
                        geni_attack.save()
                    else:
                        p=get_protocol(protocol)
                        geni_attack.protocol.add(p.pk)
                        geni_attack.save()
                    time.sleep(210)
                    event_data, info = petition_geni(id_event)
                    if info['status'] != 'Recovered' and info['status'] !='Burst':
                        tf_char = event_data['response']['result']['data'][0]['traffic_characteristics']
                        dic_regla2 = assemble_dic(tf_char,info)
                        attack = GolemAttack.objects.get(id_name=id_event)
                        attack.status, attack.max_value, attack.threshold_value = dic_regla2['status'], dic_regla2['max_value'], dic_regla2['th_value']
                        attack.save()
                        p1 = tf_char[4]['data'][0][0]
                        m_protocol = check_protocol(p1)
                        dic2 = {'name':dic_regla2['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla2['ip_dest'],'ipsrc':dic_regla2['ip_src'],'protocol':m_protocol.pk,'tcpflag':dic_regla2['tcp_flag'],'port':dic_regla2['port']}
                        create_route(id_event,dic2,peer.peer_tag)
                        link1 = get_link(id_event)
                        send_message(f"El ataque registrado anteriormente a la institucion {dic_regla2['institution_name']} con id {dic_regla2['id_attack']} persiste y hemos obtenido nuevos datos del {dic_regla2['attack_name']} id: {dic_regla2['id_attack']}, status: {dic_regla2['status']},  max_value: {dic_regla2['max_value']}, threshold value: {dic_regla2['th_value']}. Para más información sobre el ataque siga el siguiente link: {link1}. Consulte nuestra web para ver las reglas que le hemos propuesto.")
                        recovered = False 
                        while recovered:
                            time.sleep(300)
                            attack_data, attack_info = petition_geni(id_event)
                            if attack_info['status'] != 'Recovered' and attack_info != 'Burst':
                                 # "THIRD RULE PROPOSITION"
                                traffic_data = attack_data['response']['result']['data'][0]['traffic_characteristics']
                                dic_regla3 = assemble_dic(traffic_data,attack_info)
                                attack = GolemAttack.objects.get(id_name=id_event)
                                attack.status, attack.max_value, attack.threshold_value = dic_regla3['status'], dic_regla3['max_value'], dic_regla3['th_value']
                                attack.save()
                                dic3 = {'name':dic_regla3['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla3['ip_dest'],'ipsrc':dic_regla3['ip_src'],'port':dic_regla3['port'],'protocol':m_protocol.pk,'tcpflag':dic_regla3['tcp_flag']}
                                create_route(id_event,dic3,peer.peer_tag)
                                link2 = get_link(id_event)
                                send_message(f"El ataque registrado anteriormente a la institución {dic_regla3['institution_name']} persiste {dic_regla3['attack_name']} y hemos obtenido nuevos datos: Id: {dic_regla3['id_attack']}, Status: {dic_regla3['status']}, Max Value: {dic_regla3['max_value']}, Threshold value: {dic_regla3['th_value']}. Si desea más información sobre el ataque visite el siguiente link: {link2}.")
                                recovered = False
                            elif attack_info['status'] == 'Recovered' or attack_info['status'] == 'Burst':
                                    id_attack, status, severity_type, max_value, th_value, attack_name, institution_name, initial_date, ip_attacked = attack_info['id'], attack_info['status'], attack_info['severity'], attack_info['max_value'], attack_info['threshold_value'] , attack_info['attack_name'], attack_info['institution_name'], attack_info['initial_date'], attack_info['ip_attacked']
                                    attack = GolemAttack.objects.get(id_name=id_event)
                                    attack.status, attack.max_value, attack.threshold_value = status, max_value, th_value
                                    attack.save()
                                    send_message(f"El ataque registrado anteriormente a la institución {institution_name} con nombre {name} e id {id_attack} ha terminado. Más información sobre el ataque : Id: {id_attack}, Status: {status}, Max Value: {max_value}, Threshold value: {th_value}.")
                                    recovered = True
                    else:
                        if info['status'] == 'Recovered' or info['status']=='Burst':
                            attack = GolemAttack.objects.get(id_name=id_event)
                            id_att, status, max_value, th_value, name, institution_name, initial_date, ip_att = info['id'], info['status'],  info['max_value'], info['threshold_value'] , info['attack_name'], info['institution_name'], info['initial_date'], info['ip_attacked']
                            send_message(f"El ataque registrado anteriormente a la institución {institution_name} con nombre {name} y estado {status} ha terminado. Más información sobre el ataque : Id: {id_event}, Max Value: {max_value}, Threshold value: {th_value}.")                  
                    # send message to slack saying the attack has finished
                    # wait 4 min 
                    # rule proposition and send email to user
                    # repeat process every 5 min until status equals 'recovered'
                    # GeniEvents.objects.create(event=event_info,traffic_characteristics=traffic_event,network_characteristics=net_event)
                else:
                    print('The peer that has suffered the attack is not connected to REM-e-DDoS.')
        elif anomaly_info['status']=='Burst':
            try:
                attack = GolemAttack.objects.get(id_name=id_event)
                event, info = petition_geni(id_event)
                id_att, status, max_value, th_value, name, institution_name, initial_date, ip_att = info['id'], info['status'],  info['max_value'], info['threshold_value'] , info['attack_name'], info['institution_name'], info['initial_date'], info['ip_attacked']
                attack.status = status
                attack.max_value = max_value
                attack.threshold_value = th_value
                attack.save()
                send_message(f"El ataque registrado anteriormente a la institución {institution_name} con nombre {name} y estado {status} ha terminado. Más información sobre el ataque : Id: {id_att}, Max Value: {max_value}, Threshold value: {th_value}.")
                    # check if it's recovered and already in database to inform the attack is over
            except ObjectDoesNotExist:
                print(f'There was an attack with id: {id_event}.')            
        elif anomaly_info['status'] == 'Recovered': 
            try:
                attack = GolemAttack.objects.get(id_name=id_event)
                event, info = petition_geni(id_event)
                id_att, status, max_value, th_value, name, institution_name, initial_date, ip_att = info['id'], info['status'],  info['max_value'], info['threshold_value'] , info['attack_name'], info['institution_name'], info['initial_date'], info['ip_attacked']
                attack.status = status
                attack.max_value = max_value
                attack.threshold_value = th_value
                attack.save()      
                send_message(f"El ataque registrado anteriormente a la institución {institution_name} con nombre {name} y estado {status} ha terminado. Más información sobre el ataque : Id: {id_att}, Max Value: {max_value}, Threshold value: {th_value}.")
                # check if it's recovered and already in database to inform the attack is over
            except ObjectDoesNotExist:
                print(f'There was an attack with id: {id_event}.')
                pass     
    else:
        pass