from urllib3.exceptions import InsecureRequestWarning
from django.core.exceptions import MultipleObjectsReturned
from flowspec.helpers import *
from flowspy import settings
import requests


def assemble_dic(traffic_event,event_info):
    # organise all info collected from rem_golem, also we assemble here the route based on the attack
    # for example which port to use depending on the traffic
    try:
        ip_dest = traffic_event[1]['data'][0][0]; 
        ip_src = traffic_event[0]['data'][0][0] 
        source_port = traffic_event[2]['data'][0][0]; fd = source_port.find(':') ; src_port = source_port[fd+1::] 
        destination_port = traffic_event[3]['data'][0][0]; fn = destination_port.find(':'); dest_port = destination_port[fn+1::]
        p = traffic_event[4]['data'][0][0]; tcp_flag = traffic_event[5]['data'][0][0]
        spt = traffic_event[2]['data'][0][1]; sport = traffic_event[2]['data'][0][0] ; fs = sport.find(':'); srcport = sport[fs+1:]
        dpt = traffic_event[3]['data'][0][1]; dport = traffic_event[3]['data'][0][0] ; fd = dport.find(':'); destport = dport[fd+1:]
        ft = tcp_flag.find('(')
        tcpflag = tcp_flag[:ft]
        if spt > dpt : 
            dic = {'id_attack':event_info['id'],'status':event_info['status'],'typeofattack':event_info['typeof_attack'],'max_value':event_info['max_value'],'th_value':event_info['threshold_value'],
            'attack_name':event_info['attack_name'],'institution_name':event_info['institution_name'],'typeofvalue':event_info['typeof_value'],
            'ip_dest':ip_dest,'ip_src':ip_src,'source_port':src_port,'dest_port':dest_port,'tcp_flag':tcpflag,'port':srcport,'protocol':get_protocol(p)}
        else:
            dic = {'id_attack':event_info['id'],'status':event_info['status'],'typeofattack':event_info['typeof_attack'],'max_value':event_info['max_value'],'th_value':event_info['threshold_value'],
            'attack_name':event_info['attack_name'],'institution_name':event_info['institution_name'],'typeofvalue':event_info['typeof_value'],'protocol':get_protocol(p), 'ip_dest':ip_dest,'ip_src':ip_src,'source_port':src_port,'dest_port':dest_port,'tcp_flag':tcpflag,'port':destport}
        return dic
    except IndexError as e:
        logger.info('There was an exception when trying to assemble the dictionary for a proposed route. Error: ', e)

def get_event_name(route_slug):
    p = route_slug.find('_')
    event_name = route_slug[:p]
    return event_name

def petition_geni(id_event):
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    session = requests.Session()
    session.verify = False
    data = {'request': '{"display_data":"yes"}'}
    response = ''
    try:
        # this is the petition that needs to go through:  curl --user Alicia:ali54* --insecure --data 'request={"display_data":"yes"}' https://193.145.15.26/api/anomalyevent/application/A376135
        response = requests.get(f'https://193.145.15.26/api/anomalyevent/application/{id_event}', data=data, verify=False, auth=(settings.GOLEM_USER, settings.GOLEM_PWD))
        json_event = response.json()
        event_data = {
           'id':json_event['response']['result']['data'][0]['event']['id'],'status':json_event['response']['result']['data'][0]['event']['status'],'severity':json_event['response']['result']['data'][0]['event']['severity']['type'],
            'threshold_value':json_event['response']['result']['data'][0]['event']['severity']['threshold_value'],'max_value':json_event['response']['result']['data'][0]['event']['severity']['max_value'],
            'institution_name': json_event['response']['result']['data'][0]['event']['resource']['name'][0], 'attack_name' : json_event['response']['result']['data'][0]['event']['attack']['name'],
            'initial_date' : json_event['response']['result']['data'][0]['event']['datetime']['start_time'], 'attack_duration' : json_event['response']['result']['data'][0]['event']['datetime']['duration'], 'ip_attacked' : json_event['response']['result']['data'][0]['event']['resource']['ip'],
            'typeof_attack':json_event['response']['result']['data'][0]['event']['attack']['type'],'typeof_value':json_event['response']['result']['data'][0]['event']['attack']['counter']}
    except requests.exceptions.ConnectionError:
        logger.info(f"Error cuando se realizaba la petición a REM-Golem. Error: {response.status_code}")
    return (response.json(),event_data)


def check_golem_conexion(anomaly_info):
    if anomaly_info['ip_attacked'] == '146.88.240.4' :
        message = (f"Conexion between REM-GOLEM and REM-e-DDOS works. ID: {anomaly_info['id']}")
        send_message(message,peer=None,superuser=True)


def open_event(id_event):
    import time
    from golem.models import GolemAttack
    from flowspec.models import MatchProtocol


    time.sleep(90)
    event_ticket, event_info = petition_geni(id_event) 
    traffic_event = event_ticket['response']['result']['data'][0]['traffic_characteristics']
    dic_regla = assemble_dic(traffic_event,event_info)
    peer = find_peer(dic_regla['institution_name'])
    if event_info['status'] == 'Open' or event_info['status'] == 'Ongoing' :
        # get together all the relevant information into one dictionary in order to create the proposed route
        # also registered the attack and the proposed route to the DB
        prt = traffic_event[4]['data'][0][0]
        protocol = get_protocol(prt)
        ip = get_ip_address(event_info['ip_attacked'])
        link = get_link(dic_regla['id_attack'])
        if peer:
            geni_attack,created = GolemAttack.objects.get_or_create(id_name=dic_regla['id_attack'],peer=peer, ip_src = dic_regla['ip_src'],ip_dest=dic_regla['ip_dest'],port=dic_regla['port'],tcpflag = dic_regla['tcp_flag'], status = dic_regla['status'], max_value = dic_regla['max_value'], threshold_value = dic_regla['th_value'], nameof_attack = dic_regla['attack_name'] ,typeof_attack = dic_regla['typeofattack'], typeof_value=dic_regla['typeofvalue'], link=link)
            send_message(message = (f"Nuevo ataque DDoS contra el recurso '{ip}' con id {id_event} de tipo {event_info['attack_name']}. Consulte nuestra <https://remedios.redimadrid.es/|*web*> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información sobre el ataque visite el siguiente link: {link}."), peer=peer.peer_tag,superuser=False)          
            if not created:
                geni_attack.save()        
            route_dic = {'name':dic_regla['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla['ip_dest'],'ipsrc':dic_regla['ip_src'],'protocol':dic_regla['protocol'],'protocol_pk':protocol.pk,'tcpflag':dic_regla['tcp_flag'],'port':dic_regla['port']}
            create_route(dic_regla['id_attack'],route_dic, peer.peer_tag, protocol)
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
        
        ongoing(id_event,peer)
    elif event_info['status'] == 'Recovered':
        recovered(id_event,event_info,peer)




def ongoing(id_event,peer):
    import time
    from flowspec.models import MatchProtocol
    from golem.models import GolemAttack
    from flowspec.tasks import create_route


    time.sleep(210)
    event_data, info = petition_geni(id_event)
    if info['status'] == 'Ongoing':
        traffic_characteristics = event_data['response']['result']['data'][0]['traffic_characteristics']
        dic_regla2 = assemble_dic(traffic_characteristics,info)
        link1 = get_link(id_event)
        attack = GolemAttack.objects.get(id_name=id_event)
        attack.status, attack.max_value, attack.threshold_value,attack.link = dic_regla2['status'], dic_regla2['max_value'], dic_regla2['th_value'], link1
        attack.save()
        protocol = traffic_characteristics[4]['data'][0][0]
        match_protocol = check_protocol(protocol)
        route_info = {'name':dic_regla2['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla2['ip_dest'],'ipsrc':dic_regla2['ip_src'],'protocol_pk':match_protocol.pk,'tcpflag':dic_regla2['tcp_flag'],'port':dic_regla2['port']}
        try:
            create_route(id_event,route_info,peer.peer_tag, match_protocol.protocol)
        except Exception as e:
            logger.info(f"t2 There was an exception when creating a new proposed route. Error: {e}")
        send_message(f"El ataque DDoS con id {dic_regla2['id_attack']} de tipo {info['attack_name']} a la institución {dic_regla2['institution_name']} persiste y hemos actualizado los datos del ataque. Consulte nuestra <https://remedios.redimadrid.es/|web> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información sobre el ataque visite el siguiente link: {link1}.", peer=peer.peer_tag,superuser=False)
    elif info['status'] == 'Recovered' or info['status'] == 'Burst':
        recovered(id_event,info, peer)
    
    not_recovered = True 
    while not_recovered:
        time.sleep(300)
        attack_data, attack_info = petition_geni(id_event)
        if attack_info['status'] == 'Ongoing':
        # wait 4 min , rule proposition and send email to user , repeat process every 5 min until status equals 'recovered'
            traffic_data = attack_data['response']['result']['data'][0]['traffic_characteristics']
            protocol = traffic_data[4]['data'][0][0]
            match_protocol = check_protocol(protocol)
            dic_regla3 = assemble_dic(traffic_data,attack_info)
            link2 = get_link(id_event)                                
            attack = GolemAttack.objects.get(id_name=id_event)
            attack.status = dic_regla3['status']
            attack.max_value = dic_regla3['max_value']
            attack.threshold_value = dic_regla3['th_value']
            attack.link = link2
            attack.save()
            route_info1 = {'name':dic_regla3['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla3['ip_dest'],'ipsrc':dic_regla3['ip_src'],'port':dic_regla3['port'],'protocol_pk':match_protocol.pk,'tcpflag':dic_regla3['tcp_flag']}
            try:
                create_route(id_event,route_info1,peer.peer_tag, match_protocol.protocol)
            except Exception as e:
                logger.info(f"Ha habido un error proponiendo la nueva regla para el ataque {dic_regla3['id_attack']}. Error: {e}")
            send_message(message=(f"El ataque DDoS con id {dic_regla3['id_attack']} de tipo {attack_info['attack_name']} a la institución {dic_regla3['institution_name']} persiste y hemos actualizado los datos del ataque. Consulte nuestra <https://remedios.redimadrid.es/|web> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información siga el siguiente link: {link2}."),peer=peer.peer_tag,superuser=False)
            not_recovered = True
        elif attack_info['status'] == 'Recovered' or attack_info['status'] == 'Burst':
            # send message to slack saying the attack has finished
            recovered(id_event,attack_info, peer)
            not_recovered = False
            break
            
    


def recovered(id_event, info, peer):
    from golem.models import GolemAttack
    from datetime import datetime
    from django.utils import timezone

    try:
        attack = GolemAttack.objects.get(id_name=id_event)
        if not attack.finished:
            peer = find_peer(info['institution_name'])    
            attack.status = info['status']
            attack.max_value = info['max_value']
            attack.threshold_value = info['threshold_value']
            attack.ends_at = timezone.now()
            attack.finished = True
            attack.save()                          
            send_message(message=(f"El ataque DDoS con id {id_event} a la institución {info['institution_name']} ha terminado. Más información en <https://remedios.redimadrid.es/|REMeDDoS> o REM-GOLEM."),peer=peer.peer_tag,superuser=False)
        else:
            #means the attack has already finished and the user has been notified 
            pass  
    except ObjectDoesNotExist:
        #was not tracked 
        pass


def create_route(golem_id,route_dic,peer,protocolo):
    from flowspec.helpers import get_route,find_routes
    from golem.models import GolemAttack
    from peers.models import Peer
    

    #ip origen, ip destino, protocolo, puerto (que mas trafico tenga), la tcp flag q mas trafico que tenga, 
    #el tcp-flag si el protocolo es udp debe ser descartado porque siempre va a ser 0
    peers = Peer.objects.get(peer_tag=peer)
    golem_routes = []
    
   # protocolo = route_dic['protocol'].protocol
    try:
        routes = find_routes(applier=None, peer=peer)
        route = get_route(applier=None,peer=peer)
    except MultipleObjectsReturned:
        logger.info('Route has already being commited to the router')
        return None
    for r in routes:
        name = r.name
        fd = name.find('_')
        if golem_id == name[:fd] :
            golem_routes.append(r)
        # busqueda de todas las reglas, ver ya se ha propuesto alguna regla para el ataque sino generar la primera regla 
    if len(golem_routes)==0:
        route.name = route_dic['name']+'_1'
        route.peer = peers
        route.status = 'PROPOSED'
        route.is_proposed = True
        if protocolo == 'tcp':
            tcpflag = golem_translate_tcpflag(route_dic['tcpflag'])
            route.source = route_dic['ipsrc']                    
            route.destination = route_dic['ipdest']
            route.port = route_dic['port']
            route.tcpflag = tcpflag
            
            try: 
                route.save()
            except Exception as e:
                logger.info(f"There was an exception when creating a new proposed route. Error: {e}")

        else: 
            route.source = route_dic['ipsrc']
            route.destination = route_dic['ipdest']
            route.port = route_dic['port']
            try: 
                route.save()
            except Exception as e:
                logger.info(f"There was an exception when creating a new proposed route. Error: {e}")
        route.protocol.add(route_dic['protocol_pk'])
        g = GolemAttack.objects.get(id_name=golem_id)
        g.set_route(route)
        try: 
            g.save()
        except Exception as e:
            logger.info(f"There was an exception when creating a new proposed route. Error: {e}")
        return route
    else:
        sorted_routes = [route.name for route in golem_routes]
        last_element = sorted_routes[-1]
        n = last_element[-1]
        num = (int(n)+1)
        dicname = route_dic['name']
        name = str(f"{dicname}_{num}")
        route.name = name
        route.peer = peers
        route.status = 'PROPOSED'
        route.is_proposed = True
        if protocolo == 'tcp':
            tcpflag = golem_translate_tcpflag(route_dic['tcpflag'])
            route.source  = route_dic['ipsrc']
            route.destination = route_dic['ipdest']
            route.port = route_dic['port']
            route.tcpflag = tcpflag
            try: 
                route.save()
            except Exception as e:
                logger.info(f"There was an exception when creating a new proposed route. Error: {e}")
        else:
            route.source = route_dic['ipsrc']
            route.destination = route_dic['ipdest']
            route.port = route_dic['port']
            try: 
                route.save()
            except Exception as e:
                logger.info(f"There was an exception when creating a new proposed route. Error: {e}")
        route.protocol.add(route_dic['protocol_pk'])
        g = GolemAttack.objects.get(id_name=golem_id)
        g.set_route(route)
        try: 
            route.save()
        except Exception as e:
            logger.info(f"There was an exception when creating a new proposed route. Error: {e}")
        return route
    







