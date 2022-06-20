from urllib3.exceptions import InsecureRequestWarning
from django.core.exceptions import MultipleObjectsReturned
from flowspec.helpers import *
from flowspy import settings
import requests



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
        print(response.status_code)           
    return (response.json(),event_data)





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
            try:
                geni_attack = GolemAttack.objects.get(id_name=dic_regla['id_attack'])
                geni_attack.peer=peer; geni_attack.ip_src = dic_regla['ip_src']; geni_attack.port=dic_regla['port']; geni_attack.tcpflag=dic_regla['tcp_flag']; geni_attack.status = dic_regla['status']; geni_attack.max_value=dic_regla['max_value'];geni_attack.threshold_value=dic_regla['th_value']; geni_attack.typeof_attack=dic_regla['typeofattack'];geni_attack.typeof_value=dic_regla['typeofvalue'];geni_attack.link=link
                geni_attack.save()
                        
            except GolemAttack.DoesNotExist:
                geni_attack = GolemAttack(id_name=dic_regla['id_attack'], peer=peer, ip_src = dic_regla['ip_src'], port=dic_regla['port'], tcpflag=dic_regla['tcp_flag'], status = dic_regla['status'], max_value=dic_regla['max_value'],threshold_value=dic_regla['th_value'], typeof_attack=dic_regla['typeofattack'],typeof_value=dic_regla['typeofvalue'],link=link)
                geni_attack.save()
                send_message(message = (f"Nuevo ataque DDoS contra el recurso '{ip}' con id {id_event} de tipo {event_info['attack_name']}. Consulte nuestra <https://remedios.redimadrid.es/|*web*> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información sobre el ataque visite el siguiente link: {link}."), peer=peer.peer_tag,superuser=False)  
                    
                route_dic = {'name':dic_regla['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla['ip_dest'],'ipsrc':dic_regla['ip_src'],'protocol':protocol.pk,'tcpflag':dic_regla['tcp_flag'],'port':dic_regla['port']}
                try:
                    create_route(dic_regla['id_attack'],route_dic, peer.peer_tag)
                except Exception as e:
                    logger.info('There was an error: ')
                    pass
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
    else:
        pass




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
        route_info = {'name':dic_regla2['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla2['ip_dest'],'ipsrc':dic_regla2['ip_src'],'protocol':match_protocol.pk,'tcpflag':dic_regla2['tcp_flag'],'port':dic_regla2['port']}
        try:
            create_route(id_event,route_info,peer.peer_tag)
        except Exception as e:
                logger.info('There was an error: ')
                pass
        send_message(f"El ataque DDoS con id {dic_regla2['id_attack']} de tipo {info['attack_name']} a la institución {dic_regla2['institution_name']} persiste y hemos actualizado los datos del ataque. Consulte nuestra <https://remedios.redimadrid.es/|web> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información sobre el ataque visite el siguiente link: {link1}.", peer=peer.peer_tag,superuser=False)
        not_recovered = True 
        while not_recovered:
            time.sleep(300)
            print('after 300')
            attack_data, attack_info = petition_geni(id_event)
            if attack_info['status'] == 'Ongoing':
            # wait 4 min , rule proposition and send email to user , repeat process every 5 min until status equals 'recovered'
                traffic_data = attack_data['response']['result']['data'][0]['traffic_characteristics']
                dic_regla3 = assemble_dic(traffic_data,attack_info)
                link2 = get_link(id_event)                                
                attack = GolemAttack.objects.get(id_name=id_event)
                attack.status = dic_regla3['status']
                attack.max_value = dic_regla3['max_value']
                attack.threshold_value = dic_regla3['th_value']
                attack.link = link2
                attack.save()
                route_info1 = {'name':dic_regla3['id_attack']+'_'+peer.peer_tag,'ipdest':dic_regla3['ip_dest'],'ipsrc':dic_regla3['ip_src'],'port':dic_regla3['port'],'protocol':match_protocol.pk,'tcpflag':dic_regla3['tcp_flag']}
                try:
                    create_route(id_event,route_info1,peer.peer_tag)
                except Exception as e:
                    logger.info('There was an error: ')
                send_message(message=(f"El ataque DDoS con id {dic_regla3['id_attack']} de tipo {attack_info['attack_name']} a la institución {dic_regla3['institution_name']} persiste y hemos actualizado los datos del ataque. Consulte nuestra <https://remedios.redimadrid.es/|web> donde se podrán ver las reglas propuestas para mitigar el ataque. Para más información siga el siguiente link: {link2}."),peer=peer.peer_tag,superuser=False)
                not_recovered = True
            elif attack_info['status'] == 'Recovered' or attack_info['status'] == 'Burst':
                # send message to slack saying the attack has finished
                recovered(id_event,attack_info, peer)
                not_recovered = False
                break
            
    elif info['status'] == 'Recovered' or info['status'] =='Burst':
        recovered(id_event,info, peer)




def recovered(id_event, info, peer):
    from golem.models import GolemAttack
    try:
        attack = GolemAttack.objects.get(id_name=id_event)
        peer = find_peer(info['institution_name'])    
        attack.status = info['status']
        attack.max_value = info['max_value']
        attack.threshold_value = info['threshold_value']
        attack.save()                          
        send_message(message=(f"El ataque DDoS con id {id_event} a la institución {info['institution_name']} ha terminado. Más información en <https://remedios.redimadrid.es/|REMeDDoS> o REM-GOLEM."),peer=peer.peer_tag,superuser=False)
    except ObjectDoesNotExist:
        #was not tracked 
        pass

    
    


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
                    try: 
                        route.save()
                    except Exception as e:
                        pass
                else: 
                    route.source,route.destination,route.port = route_dic['ipsrc'],route_dic['ipdest'],route_dic['port']
                    try: 
                        route.save()
                    except Exception as e:
                        pass
                route.protocol.add(route_dic['protocol'])
                g = GolemAttack.objects.get(id_name=golem_id)
                g.set_route(route)
                try: 
                    g.save()
                except Exception as e:
                    pass
                return route
            except Exception as e:
                logger.info('An exception happened: ',e)
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
                try: 
                    route.save()
                except Exception as e:
                    pass
            else:
                route.source,route.destination,route.port = route_dic['ipsrc'],route_dic['ipdest'],route_dic['port']
                try: 
                    route.save()
                except Exception as e:
                    pass
            route.protocol.add(route_dic['protocol'])
            g = GolemAttack.objects.get(id_name=golem_id)
            g.set_route(route)
            try: 
                route.save()
            except Exception as e:
                pass
            return route
    except MultipleObjectsReturned:
        logger.info('Route has already being commited to the router')
        return None



""" @shared_task
def check_golem_events():
    from golem.models import GolemAttack
    from golem.helpers import petition_geni

    golem_events = GolemAttack.objects.all()
    for golem in golem_events:
        if golem.status == 'Ongoing' :
            event_ticket, attack_info = petition_geni(id_event=golem.id_name)
            open_event(attack_info,golem.id_name)
        else:
            pass
 """


