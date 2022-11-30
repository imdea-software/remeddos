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
import slack
from flowspec.helpers import *
from django.http import HttpResponse
from flowspec.models import *
from golem.helpers import *


LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
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

        backup_applier = PR.Backup_Applier(route_object=route)
        b_commit, b_response = backup_applier.apply()

        print('this is commit: ', commit, ' b_commit: ', b_commit)            
        if commit and b_commit:            
            status = "ACTIVE"
            route.status = status
            route.response = response
            route.save()
            message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
        else:
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}, {response}")
            send_message(message,peer,superuser=False)
            if not commit:
                message = (f"Ha habido un error cuando se intentaba configurar la regla en el primer router. Regla activa en el back up router. Porfavor contacte con su administrador.")
                send_message(message,peer,superuser=False)
            elif not b_commit:
                message = (f"Ha habido un error cuando se intentaba configurar la regla en backup router. Regla activa en el router principal. Porfavor contacte con su administrador.")
                send_message(message,peer,superuser=False)
    except TimeLimitExceeded as error:
        route.status = "ERROR"
        route.response = "Task timeout"
        try: 
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba configurar la regla en el primer router. Regla activa en el back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba configurar la ruta en el back up router. Porfavor contacte con su administrador.")
            logger.info(f"Error (TimeLimitExceeded): {error}")
            send_message(message,peer,superuser=False)
    except SoftTimeLimitExceeded as error:
        route.status = "ERROR"
        route.response = "Task timeout"
        try: 
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba configurar la regla en el primer router. Regla activa en el back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba configurar la ruta en el back up router. Porfavor contacte con su administrador.")
            logger.info(f"Error (SoftTimeLimitExceeded): {error}")
            send_message(message,peer,superuser=False)
    except Exception as error:
        route.status = "ERROR"
        route.response = "Error"
        try: 
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba configurar la regla en el primer router. Regla activa en el back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba configurar la ruta en el back up router. Porfavor contacte con su administrador.")
            logger.info(f"Error (Error): {error}")
            send_message(message,peer,superuser=False)
    except TransactionManagementError as error: 
        route.status = "ERROR"
        route.response = "Transaction Management Error"
        try: 
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier_username_nice}] Rule add: {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba configurar la regla en el primer router. Regla activa en el back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba configurar la ruta en el back up router. Porfavor contacte con su administrador.")
            logger.info(f"Error (TransactionManagementError): {error}")
            send_message(message,peer,superuser=False)

@shared_task(ignore_result=True)
def edit(route, callback=None):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR

    peer = get_peer_with_name(route.name)
    try:        

        applier = PR.Applier(route_object=route)
        commit, response = applier.apply(operation="replace")   
        
        backup_applier = PR.Backup_Applier(route_object=route)
        b_commit, b_response = backup_applier.apply(operation="replace")
        
        print('(edit) this is commit: ', commit, ' b_commit: ', b_commit)            
        if commit and b_commit:
            status = "ACTIVE"
            route.status = status
            route.response = response
            route.save()
            message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
        else:
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.b_response}, {response}")
            send_message(message,peer,superuser=False)
            if not b_commit:
                
                message = (f"Ha habido un error cuando se intentaba editar la regla en el primer router. Error: {response}. Regla activa y actualizada en el back up router. Porfavor contacte con su administrador.")
                send_message(message,peer,superuser=False)
            elif not commit:
                message = (f"Ha habido un error cuando se intentaba editar la regla en el backup router. Error: {response}. Regla activa y actualizada en el router principal. Porfavor contacte con su administrador.")
                send_message(message,peer,superuser=False)
        
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        try: 
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba editar la regla en el primer router. Regla activa y actualizada en el segundo back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"There was an error when trying to edit the route on to the second router {e}")
            send_message(message,peer,superuser=False)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        try: 
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba editar la regla en el primer router. Regla activa y actualizada en el segundo back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"There was an error when trying to edit the route on to the second router {e}")
            send_message(message,peer,superuser=False)
    except Exception:
        route.status = "ERROR"
        route.response = "Error"
        try: 
            status = "OUTOFSYNC" if (commit or b_commit) else "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier}] Rule edit:  {route.name} - Result: {route.response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba editar la regla en el primer router. Regla activa y actualizada en el back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"There was an error when trying to edit the route on to the second router {e}")
            send_message(message,peer,superuser=False)


@shared_task(ignore_result=True)
def delete(route, **kwargs):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR

    peer = get_peer_with_name(route.name)
    try:
        backup_applier = PR.Backup_Applier(route_object=route)
        b_commit, b_response = backup_applier.apply(operation="delete")
    except:
        message = (f"Ha habido un error cuando se intentaba eliminar la regla en el segundo back up router. Porfavor contacte con su administrador.")
        send_message(message,peer,superuser=False)
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply(operation="delete")
        
        if commit:
            status = "INACTIVE"
            if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                status = 'EXPIRED'
                reason_text = " Reason: %s " % status
        else:
            status = "ERROR"
            if b_commit:
                status = "OUTOFSYNC"
                if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                    status = 'EXPIRED'
                else: 
                    status = 'ERROR'
                route.status = status
                route.response = b_response
                route.save()
                message = (f"Suspending rule:  {route.name}")
                send_message(message,peer,superuser=False)
                message = (f"Ha habido un error cuando se intentaba eliminar la regla en el primer router. Regla suspendida en el back up router. Porfavor contacte con su administrador.")
                send_message(message,peer,superuser=False)
    except TimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        try: 
            if b_commit:            
                status = "OUTOFSYNC"
                if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                    status = 'EXPIRED'
            else:
                status = "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {b_response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el primer router. Regla suspendida en el back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el segundo router. Porfavor contacte con su administrador. Error: {e}")
            send_message(message,peer,superuser=False)
    except SoftTimeLimitExceeded:
        route.status = "ERROR"
        route.response = "Task timeout"
        try: 
            if b_commit:            
                status = "OUTOFSYNC"
                if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                    status = 'EXPIRED'
            else:
                status = "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el primer router. Regla suspendida en el back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el back up router. Porfavor contacte con su administrador. Error: {e}")
            send_message(message,peer,superuser=False)
    except Exception as e:
        route.status = "ERROR"
        route.response = "Error"
        try: 
            if b_commit:            
                status = "OUTOFSYNC"
                if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                    status = 'EXPIRED'
            else:
                status = "ERROR"
            route.status = status
            route.response = b_response
            route.save()
            message = (f"[{route.applier}] Suspending rule:  {route.name} - Result: {response}")
            send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el primer router. Regla suspendida en el back up router. Porfavor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el back up router. Porfavor contacte con su administrador. Error: {e}")
            send_message(message,peer,superuser=False)


# May not work in the first place... proxy is not aware of Route models
@shared_task(serializer='json')
def batch_delete(routes, **kwargs):
    from utils import proxy as PR
    import datetime

    peer = get_peer_with_name(route.name)
    if routes:
        for route in routes:
            route.status = 'PENDING'
            route.save()
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
                
@shared_task(ignore_result=True)
def notify_expired():
    import datetime
    from django.contrib.sites.models import Site
    from django.core.mail import send_mail
    from django.template.loader import render_to_string

    today = datetime.date.today()
    peers = Peer.objects.all()
    
    for peer in peers:
        routes = find_routes(applier=None, peer=peer.peer_tag)    
        for route in routes:
            if route.expires != None:
                expiration_days = (route.expires - today).days
                if route.status == 'ACTIVE' :
                    if expiration_days < settings.EXPIRATION_NOTIFY_DAYS or expiration_days > 0:
                        
                        try:
                            fqdn = Site.objects.get_current().domain
                            admin_url = "https://%s%s" % \
                            (fqdn, "/edit/%s" % route.name)
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
                                send_mail(settings.EMAIL_SUBJECT_PREFIX + "Rule %s expires %s%s" %(route.name,expiration_days_text, days_num),mail_body, settings.SERVER_EMAIL,[route.applier.email])
                            if route.has_expired and expiration_days < 0:
                                route.status == 'DEACTIVATED'
                                route.save()
                                logger.info(f"Deactivating route: {route.name}..")
                                route.commit_delete()

                        except Exception as e:
                            logger.info("Exception: %s"%e)
            else:
                message = ("Route: %s, won't expire." % route.name)
                logger.info(message)
                pass

@shared_task
def expired_val_codes():
    from flowspec.models import Validation
    valid_codes = Validation.objects.all()
    for code in valid_codes:
        code.is_outdated()


@shared_task
def routes_sync():
    today = datetime.date.today()
    
    try:
        first_router = get_routes_router()
        backup_router = get_routes_backuprouter()
    except Exception as e:
        logger.info(f"There was an error when trying to retrieve the routes from the routers. Error: {e}")

    routes_db = find_all_routes()

    routenames_db = []
    fw_routes = []
    backup_fw_routes = []

    for x in routes_db:
        for route in x:
            if route.status == 'ACTIVE' or route.status == 'OUTOFSYNC':
                routenames_db.append(route.name)

    for children in first_router:
        for child in children:
            if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                fw_routes.append(child.text)
    
    for children in backup_router:
        for child in children:
            if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                backup_fw_routes.append(child.text)
    """ routes from both routers """
    fw_routes.sort()
    backup_fw_routes.sort()     
    """ routes from db """            
    routenames_db.sort()
    """ find every active route in db , first router and backup router """
    found_routers = set(fw_routes + list(set(backup_fw_routes) - set(fw_routes)))
    
    found_diff = found_routers.difference(routenames_db)
    found_diff1 = set(routenames_db).difference(found_routers)
    found_diff.update(found_diff1)
    
    found_routes = list(found_diff)
    if found_routes:
        print(found_routes)
        for routename in found_routes:
            peer_tag = get_peer_with_name(routename)
            try:
                if peer_tag:
                    route = get_specific_route(applier=None,peer=peer_tag,route_slug=routename)
                    if route is not None:
                        if route.status != 'ACTIVE' and not (route.is_synced() and route.is_synced_backup):
                            try:
                                route.commit_add()
                            except Exception as e:    
                                logger.info('We tried to commit a route outofsync but it didnt work, please review if there is any conexion problem. Route: ', route.name)
                        if route.status == 'ACTIVE' and (not route.has_expired) and route.is_synced() and route.is_synced_backup():
                            pass
                        if route.status == 'ACTIVE' and ((not route.is_synced()) or (not route.is_synced_backup)) and (not route.has_expired()):
                            route.commit_add() 
                            logger.info("The following route has been commited to the router due to an out of sync problem. ", routename)
                        if route.is_synced() and route.is_synced_backup() and (not route.has_expired()):
                            route.status = 'ACTIVE'
                            route.save()
                        if route.has_expired() and ((route.is_synced()) or (route.is_synced_backup)):
                            route.status = 'EXPIRED'
                            route.save()
                            route.commit_delete()
                            logger.info("The following route has been deleted from the router due to an out of sync problem. ", routename)
                        if (not route.has_expired()) and (route.status == 'OUTOFSYNC'):
                            route.commit_add()
                            logger.info('status: %s route out of sync: %s, saving route.' %(route.status, route.name))
                        if route.has_expired() and route.status == 'ACTIVE':
                            route.status == 'EXPIRED'
                            route.save()
                            route.commit_delete()
                        if route.expires:
                            expiration_days = (route.expires - today).days
                            if route.has_expired() and expiration_days < 0:
                                route.status == 'EXPIRED'
                                route.save()
                                logger.info(f"Deactivating route: {route.name}..")
                                route.commit_delete()
                        if not route.applier:
                            route.comments = 'Esta regla ha sido guardada por REMeDDoS de manera automática, porfavor revise esta regla.'
                            route.save()
                            
                    else:
                     # there's a route in a router that is not synced with the db
                        route = find_match_route_config_router(routename)
                        # now the route has already been save into the db, now we commit again the route if it's not commited already
                        if (not route.is_synced()) or (not route.is_synced_backup):
                            try:
                                route.commit_add()
                            except Exception as e:
                                route.status = 'OUTOFSYNC'
                                route.save()
                                logger.info('Ha habido un error al intentar configurar las reglas:',e)
                        elif (route.is_synced() and route.is_synced_backup):
                            route.status ='ACTIVE'
                            route.comments = 'Esta regla ha sido guardada por REMeDDoS de manera automática, porfavor revise esta regla.'
                            route.save()
                            print('routes have been synced: ', route.name)
            except Exception as e:
                logger.info(f"There following route does not belong to any peer: {routename}")
    else:
        pass
        logger.info('There are no routes out of sync.') 


    

@shared_task
def create_db_backup():
    from django.core.management import call_command
    import datetime

    now = datetime.datetime.now()
    current_time = now.strftime("%H:%M")
    current_date = now.strftime("%d-%B-%Y")
    
    try:
        call_command('dumpdata', format='json',output=f'_backup/REMeDDoS/remeddos_backup_{current_date}_{current_time}.json')
        message = 'Se ha generado una copia de seguridad de toda la base de datos. Copia de seguridad creada con éxito.'
        send_message(message)
    except Exception as e:
        message = ('Ha ocurrido un error intentando crear la copia de seguridad. %s'%e)
        send_message(message)
    
    


@shared_task
def daily_backup():
    import datetime
    from django.core.management import call_command
    from peers.models import Peer

    peers = Peer.objects.all()
    now = datetime.datetime.now()
    current_time = now.strftime("%H:%M")
    current_date = now.strftime("%d-%B-%Y")
    send_message('Testing backup 1', peer=None, superuser=True)
    try:
        for peer in peers:
            if not peer.peer_tag == 'Punch':
                call_command('dumpdata', f'flowspec.Route_{peer.peer_tag}', format='json',output=f'_backup/{peer.peer_tag}/{peer.peer_tag}_{current_date}-{current_time}.json')
            else:
                pass
        logger.info(f'Copia de seguridad de toda la BBDD creada con éxito.')
    except Exception as e:
        send_message(f"Testing backup error: {e}", peer=None, superuser=True)
        message = ('Ha ocurrido un error intentando crear la copia de seguridad. from %s'%e)
        send_message(message,peer=peer.peer_tag,superuser=False)


def restore_complete_db():
    from django.core.management import call_command
    
    CHOICES_FILES = []
    for f in os.listdir(settings.BACK_UP_DIR+'/REMeDDoS/'):
        CHOICES_FILES.append(f)
    filename = CHOICES_FILES[-1]
    fixture_path = (settings.BACK_UP_DIR+'/REMeDDoS/'+filename)
    call_command(f"loaddata",fixture_path)
    




@shared_task
def expired_backups():
    from django.core.management import call_command
    from peers.models import Peer
    from flowspy.settings import BACK_UP_DIR
    import os
    import datetime
    
    peers = Peer.objects.all()
    fixture = ''
    today = datetime.datetime.now()
    for peer in peers:
        if not peer.peer_tag == 'Punch':
            backup_dir = (f"{BACK_UP_DIR}/{peer.peer_tag}/")
            for f in os.listdir(backup_dir):
                fixture = (backup_dir+f)
                fd = f.find('_')
                p1 = f[fd+1:]
                fd2 = p1.find('.')        
                date = p1[:fd2]            
                date_obj = datetime.datetime.strptime(date, '%d-%B-%Y-%H:%M')
                expired_date = date_obj + datetime.timedelta(days=30)
                if today > expired_date:
                    os.remove(fixture)
                    logger.info(f"Removing back up file... {fixture}")
                else:
                    pass                    
        else:
            pass

@shared_task 
def restore_backups():
    from django.core.management import call_command
    from peers.models import Peer
    from flowspy.settings import BACK_UP_DIR
    import os
    import datetime

    peers = Peer.objects.all()
    backup_files = []
    fixture = ''

    for peer in peers: 
        backup_dir = (BACK_UP_DIR+{peer.peer_tag}+'/')
        for f in os.listdir(backup_dir):
            backup_files.append(f)
        for files in backup_files:
            fixture = (backup_dir+files)
            call_command(f"loaddata",fixture)
            logger.info('BBDD restaurada')



@shared_task
def delete_expired_events():
    # task for deleting attacks and routes that are a week old and not relevant since the info will be saved in the rem-golem app
    from golem.models import GolemAttack
    from django.utils import timezone
    import datetime

    today = timezone.now() 
    golem_events = GolemAttack.objects.all()
    for event in golem_events:
        expired_date = event.received_at  + datetime.timedelta(days=5)
        if today > expired_date:
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
            if (route.status == 'OUTOFSYNC' or route.status == 'EXPIRED' or route.status == 'PROPOSED') and route.is_proposed == True:
                expired_date = route.filed + datetime.timedelta(days=5)
                if today > expired_date:
                    logger.info(f"Route: {route.name} is about to expired")
                    route.delete()



@shared_task
def check_open_events():
    from golem.models import GolemAttack
    from golem.helpers import ongoing
    import datetime

    limit = datetime.timedelta(minutes=30)
    events = GolemAttack.objects.filter(status='Ongoing')
    for event in events:
        expire = event.received_at + limit
        if expire > event.received_at:
            ongoing(event.id_name, event.peer)