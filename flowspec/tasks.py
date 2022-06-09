from flowspy.celery import app
#from __future__ import absolute_import, unicode_literals
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


#add helper for finding a peer based on a route name

@shared_task(ignore_result=True, serializer='json')
def add(route, callback=None):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR

    peer = get_peer_with_name(route.name)

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
        send_message(message,peer,superuser=False)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message,peer,superuser=False)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message,peer,superuser=False)
    except Exception as e:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message,peer,superuser=False)
    except TransactionManagementError: 
        route.status = "ERROR"
        route.response = "Transaction Management Error"
        route.save()
        message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
        send_message(message,peer,superuser=False)

@shared_task(ignore_result=True)
def edit(route, callback=None):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR

    peer = get_peer_with_name(route.name)
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
        send_message(message,peer,superuser=False)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
        send_message(message,peer,superuser=False)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
        send_message(message,peer,superuser=False)
    except Exception:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
        send_message(message,peer,superuser=False)


@shared_task(ignore_result=True)
def delete(route, **kwargs):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR

    peer = get_peer_with_name(route.name)
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
        send_message(message,peer,superuser=False)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {response}")
        send_message(message,peer,superuser=False)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        route.save()
        message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {response}")
        send_message(message,peer,superuser=False)
    except Exception as e:
        route.status = "ERROR"
        route.response = "Error"
        route.save()
        message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {response}")
        send_message(message,peer,superuser=False)


# May not work in the first place... proxy is not aware of Route models
@shared_task(serializer='json')
def batch_delete(routes, **kwargs):
    from utils import proxy as PR
    import datetime

    peer = get_peer_with_name(route.name)
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
            send_message(message,peer,superuser=False)
    else:
        return False

@shared_task
def check_sync(route_name=None, selected_routes=[]):
    peers = Peer.objects.all()
    for peer in peers:
        if not selected_routes:
            routes = find_routes(applier=None,peer=peer.peer_tag)
        else:
            routes = selected_routes
        if route_name:
            routes = routes.filter(name=route_name)
        for route in routes:
            if route.has_expired() and route.status == 'INACTIVE':
                route.status == 'EXPIRED'
                route.save()
            if route.has_expired() and (route.status != 'EXPIRED' and route.status != 'ADMININACTIVE' and route.status != 'INACTIVE'):
                if route.status != 'ERROR':
                    message = ('Expiring %s route %s' %(route.status, route.name)) 
                    send_message(message,peer.peer_tag,superuser=False)
                    route.status='EXPIRED'
                    route.save()
                    delete(route)
                if route.status == 'ERROR' and route.has_expired():
                    message = ('Deleting %s route with error %s' %(route.status, route.name)) 
                    send_message(message,peer.peer_tag,superuser=False)
                    route.status='EXPIRED'
                    route.save()
                elif route.status == 'OUTOFSYN':
                    route.check_sync()
            else:
                if route.status != 'EXPIRED':
                    route.check_sync()

                
@shared_task(ignore_result=True)
def notify_expired():
    import datetime
    from django.contrib.sites.models import Site
    from django.core.mail import send_mail
    from django.template.loader import render_to_string

    peers = Peer.objects.all()
    for peer in peers:
        routes = find_routes(applier=None, peer=peer.peer_tag)
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
                            send_message(message=message,peer=peer.peer_tag,superuser=False)
                            send_mail(settings.EMAIL_SUBJECT_PREFIX + "Rule %s expires %s%s" %
                                    (route.name,expiration_days_text, days_num),
                                    mail_body, settings.SERVER_EMAIL,
                                    [route.applier.email])
                        except Exception as e:
                            logger.info("Exception: %s"%e)
                            #send_message(message=message,peer=peer.peer_tag)
            else:
                message = ("Route: %s, won't expire." % route.name)
                logger.info(message,peer)
                pass

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
    
    
    options =  []
    flow = []
    route = []
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
            if route.status == 'ACTIVE' or route.applier != None:
                routenames.append(route.name)
    diff = set(routenames).difference(names)
    notsynced_routes = list(diff)
    if notsynced_routes:
        for route in notsynced_routes:
            peer_tag = get_peer_with_name(route)
            route = get_specific_route(applier=None,peer=peer_tag,route_slug=route)
            try:
                if (route.status == 'PENDING' or route.status == 'DEACTIVATED' or route.status == 'OUTOFSYNC' or route.status == 'ERROR' or route.status == None) and route.applier == None:
                    route.status = 'PENDING'
                    route.save()
                if (route.has_expired()==False) and (route.status == 'ACTIVE' or route.status == 'OUTOFSYNC'):
                    route.commit_add()
                    message = ('status: %s route out of sync: %s, saving route.' %(route.status, route.name))
                    send_message(message,peer_tag,superuser=False)
                else:
                    if (route.has_expired()==True) or (route.status == 'EXPIRED' or route.status != 'ADMININACTIVE' or route.status != 'INACTIVE'):
                        message = ('Route: %s route status: %s'%(route.status, route.name))
                        send_message(message,peer_tag,superuser=False)
                        route.check_sync()                  
            except Exception as e:
                print('There was an exception when trying to sync the routes route: ', e)           
    else:
        message = ('There are no routes out of sync')
        send_message(message, peer_tag,superuser=False)


@shared_task
def check_golem_events():
    from golem.models import GolemAttack
    from golem.helpers import petition_geni

    golem_events = GolemAttack.objects.all()
    for golem in golem_events:
        if golem.status == 'Ongoing' :
            event_ticket, attack_info = petition_geni(id_event=golem.id_name)
            post(attack_info,golem.id_name)
        else:
            pass


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
            if golem_id == name[:fd] :
                golem_routes.append(r)
                #busqueda de todas las reglas, ver si alguna tiene el nombre del ataque
                #cuantas hay, dependiendo de cuantas crear 1,2,3
        if len(golem_routes)==0:
            try: 
                route.name = route_dic['name']+'_1'
                route.peer = peers
                route.status = 'PENDING'
                if route_dic['protocol'] == 'tcp':
                    tcpflag = golem_translate_tcpflag(route_dic['tcpflag'])
                    route.source,route.destination,route.port,route.tcpflag = route_dic['ipsrc'],route_dic['ipdest'],route_dic['port'], tcpflag
                    route.save()
                else: 
                    route.source,route.destination,route.port = route_dic['ipsrc'],route_dic['ipdest'],route_dic['port']
                    route.save()
                route.protocol.add(route_dic['protocol'])
                g = GolemAttack.objects.get(id_name=golem_id)
                g.set_route(route)
                g.save()
                return route
            except Exception as e:
                print('An exception happened: ',e)
        else:
            sorted_routes = [route.name for route in golem_routes]
            last_element = sorted_routes[-1]
            n = last_element[-1]
            num = (int(n)+1)
            dicname = route_dic['name']
            name = str(f"{dicname}_{num}")
            route.name = name
            route.peer = peers
            route.status = 'PENDING'
            if route_dic['protocol'] == 'tcp':
                tcpflag = golem_translate_tcpflag(route_dic['tcpflag'])
                route.source,route.destination,route.port,route.tcpflag = route_dic['ipsrc'],route_dic['ipdest'],route_dic['port'], tcpflag
                route.save()
            else:
                route.source,route.destination,route.port = route_dic['ipsrc'],route_dic['ipdest'],route_dic['port']
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

    logger.info('Inside post task')
        # first we filter out the attack, it could belong to a registered peer or not, also there will be false positives (bursts attacks)
    if not anomaly_info['institution_name'] == 'Non-Home':
        if anomaly_info['status'] == 'Open' or anomaly_info == 'Ongoing':
            # wait 90 sec for a get request, information won't be ready until a 1.30 min has passed
            time.sleep(90)
            event_ticket, event_info = petition_geni(id_event)
            traffic_event = event_ticket['response']['result']['data'][0]['traffic_characteristics']
            dic_regla = assemble_dic(traffic_event,event_info)
            if not event_info['status'] == 'Recovered' and not event_info['status']=='Burst':
                 # get together all the relevant information into one dictionary in order to create the proposed route
                 # also registered the attack and the proposed route to the DB
                peer = find_peer(dic_regla['institution_name'])
                prt = traffic_event[4]['data'][0][0]
                protocol = get_protocol(prt)
                ip = get_ip_address(event_info['ip_attacked'])
                link = get_link(dic_regla['id_attack'])
                send_message(message = (f"Nuevo ataque DDoS contra el recurso '{ip}' con id {dic_regla['id_attack']}.. Consulte nuestra <https://remedios.redimadrid.es/|*web*> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información sobre el ataque visite el siguiente link: {link}."), peer=peer.peer_tag,superuser=False)  

                route_dic = {'name':dic_regla['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla['ip_dest'],'ipsrc':dic_regla['ip_src'],'protocol':protocol.pk,'tcpflag':dic_regla['tcp_flag'],'port':dic_regla['port']}
                if peer:
                    geni_attack = GolemAttack(id_name=dic_regla['id_attack'], peer=peer, ip_src = dic_regla['ip_src'], port=dic_regla['port'], tcpflag=dic_regla['tcp_flag'], status = dic_regla['status'], max_value=dic_regla['max_value'],threshold_value=dic_regla['th_value'], typeof_attack=dic_regla['typeofattack'],typeof_value=dic_regla['typeofvalue'],link=link)
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
                    # wait a bit more to check if the attack is still going, if it is, the program will proposed another route
                    time.sleep(210)
                    event_data, info = petition_geni(id_event)
                    if info['status'] != 'Recovered' and info['status'] !='Burst':
                        tf_char = event_data['response']['result']['data'][0]['traffic_characteristics']
                        dic_regla2 = assemble_dic(tf_char,info)
                        link1 = get_link(id_event)
                        attack = GolemAttack.objects.get(id_name=id_event)
                        attack.status, attack.max_value, attack.threshold_value,attack.link = dic_regla2['status'], dic_regla2['max_value'], dic_regla2['th_value'], link1
                        attack.save()
                        p1 = tf_char[4]['data'][0][0]
                        m_protocol = check_protocol(p1)
                        dic2 = {'name':dic_regla2['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla2['ip_dest'],'ipsrc':dic_regla2['ip_src'],'protocol':m_protocol.pk,'tcpflag':dic_regla2['tcp_flag'],'port':dic_regla2['port']}
                        create_route(id_event,dic2,peer.peer_tag)
                        send_message(f"El ataque DDoS con id {dic_regla2['id_attack']}  a la institución {dic_regla2['institution_name']} persiste y hemos actualizado los datos del ataque. Consulte nuestra <https://remedios.redimadrid.es/|web> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información sobre el ataque visite el siguiente link: {link1}.", peer=peer.peer_tag,superuser=False)

                        

                        recovered = True 
                        while recovered:
                            time.sleep(300)
                            attack_data, attack_info = petition_geni(id_event)
                            if attack_info['status'] != 'Recovered' and attack_info != 'Burst':
                                 # wait 4 min 
                                # rule proposition and send email to user
                                # repeat process every 5 min until status equals 'recovered'
                                traffic_data = attack_data['response']['result']['data'][0]['traffic_characteristics']
                                dic_regla3 = assemble_dic(traffic_data,attack_info)
                                link2 = get_link(id_event)                                
                                attack = GolemAttack.objects.get(id_name=id_event)
                                attack.status, attack.max_value, attack.threshold_value,attack.link = dic_regla3['status'], dic_regla3['max_value'], dic_regla3['th_value'], link2
                                attack.save()
                                dic3 = {'name':dic_regla3['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla3['ip_dest'],'ipsrc':dic_regla3['ip_src'],'port':dic_regla3['port'],'protocol':m_protocol.pk,'tcpflag':dic_regla3['tcp_flag']}
                                create_route(id_event,dic3,peer.peer_tag)
                                send_message(message=(f"El ataque DDoS con id {dic_regla3['id_attack']} a la institución {institution_name} persiste y hemos actualizado los datos del ataque. Consulte nuestra <https://remedios.redimadrid.es/|web> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información siga el siguiente link: {link2}."),peer=peer.peer_tag,superuser=False)
                                recovered = True
                            elif attack_info['status'] == 'Recovered' or attack_info['status'] == 'Burst':
                                id_attack, status, severity_type, max_value, th_value, attack_name, institution_name, initial_date, ip_attacked = attack_info['id'], attack_info['status'], attack_info['severity'], attack_info['max_value'], attack_info['threshold_value'] , attack_info['attack_name'], attack_info['institution_name'], attack_info['initial_date'], attack_info['ip_attacked']
                                attack = GolemAttack.objects.get(id_name=id_event)
                                attack.status, attack.max_value, attack.threshold_value = status, max_value, th_value
                                attack.save()
                                send_message(message=(f"El ataque DDoS con id {id_attack} a la institución {institution_name} ha terminado. Más información en <https://remedios.redimadrid.es/|REMeDDoS> o REM-GOLEM."),peer=peer.peer_tag,superuser=False)
                                recovered = False
                                break
                    else:
                        if info['status'] == 'Recovered' or info['status']=='Burst':
                            # send message to slack saying the attack has finished
                            attack = GolemAttack.objects.get(id_name=id_event)
                            id_att, status, max_value, th_value, name, institution_name, initial_date, ip_att = info['id'], info['status'],  info['max_value'], info['threshold_value'] , info['attack_name'], info['institution_name'], info['initial_date'], info['ip_attacked']
                            peer = find_peer(institution_name)                           
                            send_message(message=(f"El ataque DDoS con id {id_att} a la institución {institution_name} ha terminado. Más información en <https://remedios.redimadrid.es/|REMeDDoS> o REM-GOLEM."),peer=peer.peer_tag,superuser=False)                  
                else:
                    #The peer that has suffered the attack is not connected to REM-e-DDoS
                    pass
        elif anomaly_info['status']=='Burst':
            try:
                # check if it's recovered and already in database to inform the attack is over
                attack = GolemAttack.objects.get(id_name=id_event)
                event, info = petition_geni(id_event)
                id_att, status, max_value, th_value, name, institution_name, initial_date, ip_att = info['id'], info['status'],  info['max_value'], info['threshold_value'] , info['attack_name'], info['institution_name'], info['initial_date'], info['ip_attacked']
                peer = find_peer(institution_name)
                attack.status = status
                attack.max_value = max_value
                attack.threshold_value = th_value
                attack.save()
                send_message(message=(f"El ataque DDoS con {info['id']} a la institución {institution_name} ha terminado. Más información en <https://remedios.redimadrid.es/|*REMeDDoS*> o REM-GOLEM."),peer=peer.peer_tag,superuser=False)
            except ObjectDoesNotExist: pass           
        elif anomaly_info['status'] == 'Recovered': 
            # check if it's recovered and already in database to inform the attack is over
            try:
                attack = GolemAttack.objects.get(id_name=id_event)
                event, info = petition_geni(id_event)
                id_att, status, max_value, th_value, name, institution_name, initial_date, ip_att = info['id'], info['status'],  info['max_value'], info['threshold_value'] , info['attack_name'], info['institution_name'], info['initial_date'], info['ip_attacked']
                peer = find_peer(institution_name)
                attack.status = status
                attack.max_value = max_value
                attack.threshold_value = th_value
                attack.save()      
                send_message(message=(f"El ataque DDoS con id {id_att} a la institución {institution_name} ha terminado. Más información en <https://remedios.redimadrid.es/|*REMeDDoS*> o REM-GOLEM."),peer=peer.peer_tag,superuser=False)
            except ObjectDoesNotExist:
                # the attack was not important to be saved inside the DB
                pass     
   

   ## check that the routes that are configured on the router are found on the db
@shared_task
def sync_router():
    from peers.models import Peer
    from flowspec.models import MatchProtocol,ThenAction
    from flowspec.helpers import get_routes_router, get_route
    from accounts.models import UserProfile

    peers = Peer.objects.all()
    users = UserProfile.objects.all()
    for peer in peers:
        """ if not user.user.is_superuser:
            username = user.user.username """
            # find what peer organisation does the user belong to
        """peers = user.peers.all()
            peer = [peer for peer in peers]
            peer = peer[0]
            applier = user.user;
            """
            # first initialize all the needed vars    
        routes = get_routes_router() ; fw_rules = []; message = ''
            # for getting the route parameters is needed to run through the xml 
        for children in routes:
            then = '' ; then_action = '' ; protocol = [] ; destination = [] ; source = '' ; src_port =  '' ; dest_port = '' ; tcpflags = '' ; icmpcode = ''; icmptype = ''; packetlength = ''; prot = '';  name_fw = ''
            for child in children:
                if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                    name_fw = child.text
                    if (peer.peer_name in name_fw):
                            fw_rules.append(child.text)                              
                    # if the user peer organisation is found on the router the program will collect all the info
                if (peer.peer_name in name_fw):  
                    for child in children:
                        if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}then':
                            for thenaction in child:                    
                                th = thenaction.tag ; start = th.find('}') ; then = th[start+1::]
                                then_action = thenaction.text
                        if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}match':
                            for c in child:
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}protocol': protocol = c.text
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}destination-port':dest_port = c.text
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}source-port':src_port = c.text
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}destination':destination = c.text
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}tcp-flags': tcpflags = c.text 
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}icmp-code': icmpcode = c.text 
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}icmp-type': icmptype = c.text 
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}packet-length' and c.text != '': packetlength = c.text
                                if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}source': source = c.text
                if (peer.peer_name in name_fw):
                    try: 
                        route = get_route(applier=None,peer=peer.peer_tag)
                        route.name = name_fw
                            #route.applier = applier
                        route.source = source
                        route.sourceport = src_port
                        route.destination = destination
                        route.destinationport = dest_port
                        route.icmpcode = icmpcode
                        route.icmptype = icmptype
                        route.packetlength = packetlength
                        route.tcpflag = tcpflags
                        route.status = 'ACTIVE'
                        route.save()
                        if isinstance(protocol,(list)):
                            for p in protocol:
                                prot, created = MatchProtocol.objects.get_or_create(protocol=p)
                                route.protocol.add(prot.pk)
                        else:
                            prot, created = MatchProtocol.objects.get_or_create(protocol=protocol)
                            route.protocol.add(prot)
                        th_act, created = ThenAction.objects.get_or_create(action=then,action_value=then_action)
                        route.then.add(th_act.pk)
                        message ='Routes are syncronised with the database.' 
                                # check if the route is already in our DB
                    except Exception as e:                    
                            #message = 'Routes have already been syncronised.'
                            
                            pass
                else:
                        # means that the route does not belong to the user's peer
                    pass
        print(f'Database syncronised {peer.peer_name}')
    

#task for deleting attacks and routes that are a week old and not relevant
@shared_task
def delete_expired_events():
    from golem.models import GolemAttack
    from django.utils import timezone
    import datetime

    today = timezone.now() 
    golem_events = GolemAttack.objects.all()
    for event in golem_events:
        expired_date = event.received_at  + datetime.timedelta(days=5)
        if today > expired_date:
            print('Event: ', event.id_name,' deleted.')
            event.delete()


         
@shared_task
def delete_expired_proposed_routes():
    from django.utils import timezone
    from flowspec.helpers import find_all_routes
    import datetime

    today = timezone.now()
    routes = find_all_routes()
    for x in routes:
        for route in x:
            if route.status == 'OUTOFSYNC' and route.applier == None:
                expired_date = route.filed + datetime.timedelta(days=5)
                if today > expired_date:
                    logger.info('Route: ', route.name,' is about to expired')
                    route.delete()
                    pass

