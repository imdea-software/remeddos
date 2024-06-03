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
def add_sync(route, callback=None, **kwargs):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR

    peer = get_peer_with_name(route.name)

    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply()
        backup_applier = PR.Backup_Applier(route_object=route)
        b_commit, b_response = backup_applier.apply()

        isroutePR=kwargs.get('addPR')
        isroutePRB=kwargs.get('addPRB')
        #print("------funcion add_sync de taskpy")
    
        if (commit and b_commit) or ((not isroutePR or not isroutePRB) and (commit or b_commit)):
            #print("entra primer if de add_sync")
            status = 'ACTIVE'
            route.status = status
            reason_text = " Reason: %s " % status
            route.save()
            message = (f" Se ha añadido la siguiente ruta en los routers correctamente: {route.name}")
            send_message(message,peer,superuser=False)
        elif ((not isroutePR and not isroutePRB) and (not commit and not b_commit)):
            #print("entra en el segundo add_sync")
            route.status ='ERROR'
            route.response = response
            route.save()
            message = (f"Ha habido un error cuando se intentaba añadir la siguiente regla  en los routers: {route.name}. Por favor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        elif (not isroutePR and not commit) or (not isroutePRB and not b_commit):
            #print("entra en el else de add_sync")
            route.status ='OUTOFSYNC'
            route.response = response
            route.save()
            message = (f"Ha habido un error de sincronización cuando se intentaba añadir la siguiente regla  en algún router: {route.name}. Por favor contacte con su administrador.")
            send_message(message,peer,superuser=False)
    except (TimeLimitExceeded, SoftTimeLimitExceeded, Exception):
        route.status = 'ERROR'
        route.response = response
        route.save()
        message = (f"Ha habido un error cuando se intentaba añadir la regla en los routers. Por favor contacte con su administrador.")
        send_message(message,peer,superuser=False)


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
        

        # conditions to see if the route has been commited in both routers or there has been an error. 
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
            #send_message(message,peer,superuser=False)
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
def del_sync(route, **kwargs):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply(operation="delete")
        backup_applier = PR.Backup_Applier(route_object=route)
        b_commit, b_response = backup_applier.apply(operation="delete")

        isroutePR=kwargs.get('deletePR')
        isroutePRB=kwargs.get('deletePRB')

        if(commit and b_commit):
            status = 'INACTIVE'
            route.status = status
            reason_text = " Reason: %s " % status
            route.save()
            message = (f"Se ha eliminado la siguiente regla: {route.name}")
            send_message(message,peer,superuser=False)

        if((isroutePR and isroutePRB) and (commit and b_commit)) or ((isroutePR or isroutePRB) and (commit or b_commit)):
            status = 'DEACTIVATED'
            route.status = status
            reason_text = " Reason: %s " % status
            route.save()
            message = (f"El estado de la siguiente regla ha pasado a Deactivated: {route.name}")
            send_message(message,peer,superuser=False)
        elif((isroutePR and isroutePRB) and (not commit and not b_commit)):
            route.status ='ERROR'
            route.response = response
            route.save()
            message = (f"Ha habido un error cuando se intentaba eliminar la siguiente regla en los routers: {route.name}. Por favor contacte con su administrador.")
            send_message(message,peer,superuser=False)
        elif(isroutePR and not commit) or (isroutePRB and not b_commit):
            route.status = 'OUTOFSYNC'
            route.response=response
            route.save()
            message = (f"Ha habido un error de sincronización entre los routers con la siguiente regla: {route.name}. Por favor contacte con su administrador.")
            send_message(message,peer,superuser=False)

    except (TimeLimitExceeded, SoftTimeLimitExceeded, Exception):
        route.status = 'ERROR'
        route.response = response
        route.save()
        message = (f"Ha habido un error cuando se intentaba eliminar la regla de los routers. Por favor contacte con su administrador.")
        send_message(message,peer,superuser=False)


@shared_task(ignore_result=True)
def delete(route, **kwargs):
    from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
    from utils import proxy as PR
   # print("***********ENTRA EN DEF DELETE() DE TASKS.PY*******")
    peer = get_peer_with_name(route.name)
    try:
        backup_applier = PR.Backup_Applier(route_object=route)
        b_commit, b_response = backup_applier.apply(operation="delete")
        print("BCOMMIT")
        print(b_commit)
        print("B_RESPONSE")
        print(b_response)
    except:
        message = (f"Ha habido un error cuando se intentaba eliminar la regla en el segundo back up router. Porfavor contacte con su administrador.")
        #send_message(message,peer,superuser=False)
    try:
        applier = PR.Applier(route_object=route)
        commit, response = applier.apply(operation="delete")
        print("DELETE PRINCIPAL")
        print(commit)
        print("Response princiapl")
        print(response)
        if commit:
            status = "INACTIVE"
            print("Cambia estado inactive")
            if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                print("Cambia estado a Expired")
                status = 'EXPIRED'
                reason_text = " Reason: %s " % status
                message = (f"La siguiente regla ha sido eliminada {route.name}.")
                #send_message(message,peer,superuser=False)
        else:
            print("Cambia estado a ERROR")
            status = "ERROR"
            if b_commit:
                print("Cambia estado a Outofsync")
                status = "OUTOFSYNC"
                if "reason" in kwargs and kwargs['reason'] == 'EXPIRED':
                    print("Cambia estado a expired")
                    status = 'EXPIRED'
                else: 
                    print("Si no es expired")
                    status = 'ERROR'
                route.status = status
                route.response = b_response
                route.save()
                message = (f"Suspending rule:  {route.name}")
            
                #send_message(message,peer,superuser=False)
                message = (f"Ha habido un error cuando se intentaba eliminar la regla en el primer router. Regla suspendida en el back up router. Porfavor contacte con su administrador.")
                #send_message(message,peer,superuser=False)
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
            #send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el primer router. Regla suspendida en el back up router. Porfavor contacte con su administrador.")
            #send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el segundo router. Porfavor contacte con su administrador. Error: {e}")
            #send_message(message,peer,superuser=False)
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
            #send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el primer router. Regla suspendida en el back up router. Porfavor contacte con su administrador.")
            #send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el back up router. Porfavor contacte con su administrador. Error: {e}")
            #send_message(message,peer,superuser=False)
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
            #send_message(message,peer,superuser=False)
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el primer router. Regla suspendida en el back up router. Porfavor contacte con su administrador.")
            #send_message(message,peer,superuser=False)
        except Exception as e:
            message = (f"Ha habido un error cuando se intentaba eliminar la regla en el back up router. Porfavor contacte con su administrador. Error: {e}")
            #send_message(message,peer,superuser=False)


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

#deletes used verification tokens
@shared_task
def expired_val_codes():
    from flowspec.models import Validation
    valid_codes = Validation.objects.all()
    for code in valid_codes:
        code.is_outdated()



@shared_task
def routes_sync():
    import datetime
    print("*************************EMPIEZA LA TAREA ROUTE SYNC***************")
    #today = datetime.date.today()
    
    try:
        first_router = get_routes_router()
        print("RUTAS DEL R1")
        print(first_router)
        backup_router = get_routes_backuprouter()
        print("RUTAS DEL R2")
        print(backup_router)
    except Exception as e:
        logger.info(f"There was an error when trying to retrieve the routes from the routers. Error: {e}")

    # Obtiene todas las reglas de la Base de datos
    routes_db = find_all_routes() 
    #print("Routes DB. SE HAN OBTENIDO CON EL SCRIPT")
    #print(routes_db)

    
    routenames_db = []
    routenames_Rfirst=[]
    routenames_Rbackup=[]

    #fw_routes = []
    #backup_fw_routes = []

    #Se obtienen los nombres de las rutas de la base de datos y se añaden a una lista
    for rules in routes_db:
        for rule in rules:
            if(rule.name):
                routenames_db.append(rule.name)

    #print("ROUTE DB NAMES")
    #print(routenames_db)

    #Se obtiene el nombre de rutas del router principal
    for rules in first_router:
        for rule in rules:
            if rule.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                routenames_Rfirst.append(rule.text)

    #Se obtiene el nombre de las rutas en el router de backup
    for rules in backup_router:
        for rule in rules:
            if rule.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                routenames_Rbackup.append(rule.text)

    #print("NOMBRE RUtas del primer Firewall")
    #print( routenames_Rfirst)

    #print("NOMBRE Rutas del fw backup")
    #print(routenames_Rbackup)

    ######Flujo primero: Se obtienen las reglas que se han añadido a los routers manualmente pero que no están en la DB.Se avisaría al administrador para que elimine las reglas
    routes_delete_Rfirst=list(set(routenames_Rfirst)-set(routenames_db))
    if(routes_delete_Rfirst):
        for route in routes_delete_Rfirst:
            message = (f"La siguiente regla se encuentra en el router principal pero no en la DB: {route}. Por favor, contacte con su administrador")
            send_message(message,peer,superuser=False)

    routes_delete_Rbackup=list(set(routenames_Rbackup)-set(routenames_db))
    if(routes_delete_Rbackup):
        for route in routes_delete_Rbackup:
            message = (f"La siguiente regla se encuentra en el router backup pero no en la DB: {route}. Por favor, contacte con su administrador")
            send_message(message,peer,superuser=False)

    #############Flujo segundo: obtengo las reglas de la DB, compruebo ciertos estados. La existencia de esas reglas en los routers y se elimina o borran de los routers según caso.
    #print("****AHORA EMPIEZA EL FLUJO REVISANDO LA BASE DE DATOS****")
    for nameroute in routenames_db:
        #print("---------------------------------------Organizacion es:---------------------")
        #print("NOMBRE DE RUTA A REVISAR:")
        #print(nameroute)
        peer_tag = get_peer_with_name(nameroute)
        #print(peer_tag)
        try:
            if peer_tag:
                route=get_specific_route(applier=None,peer=peer_tag,route_slug=nameroute)
                if route is not None:
                    #print("Fecha EXPIRA")
                    #print(route.expires)
                    #print("ESTADO REGLA")
                    #print(route.status)
                    if route.status == 'INACTIVE' and (not route.has_expired()):
                        #print("El estado es inactivo pero no ha caducado.Se modifica la fecha")
                        route.expires=(datetime.date.today() - datetime.timedelta(days=1))
                        route.save()
                        #print("AHora modificada es ")
                        #print(route.expires)
                    if route.has_expired() and route.status!='DEACTIVATED':
                        #print("la ruta ha expirado o el estado es desactivado")
                        if nameroute in set(routenames_Rfirst) or nameroute in set(routenames_Rbackup):
                            #print("La ruta ha expirado pero sigue existiendo en uno de los dos routers, hay que eliminarla")
                            route.commit_delete(deletePR=nameroute in set(routenames_Rfirst),deletePRB=nameroute in set(routenames_Rbackup))
                        else:
                            route.status='DEACTIVATED'
                            route.save()
                    elif(not route.has_expired() and (route.status=='ACTIVE' or route.status=='ERROR' or route.status=='OUTOFSYNC')):
                            #print("La regla no ha expirado y es error o activa")
                            if (not nameroute in set(routenames_Rfirst)) or (not nameroute in set(routenames_Rbackup)):
                                #print("La regla no está añadida en algun router.Tengo que añadirla")
                                route.commit_add(addPR=nameroute in set(routenames_Rfirst),addPRB=nameroute in set(routenames_Rbackup))
                            elif(route.status!='ACTIVE'):
                                #print("Entra en Active")
                                route.status ='ACTIVE'
                                route.save()
        except Exception as e:
	        logger.info(f"There following route does not belong to any peer: {routename}")


# daily backup for the whole DB

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
    
    
# Daily back up for each Route table

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


# Restores the whole DB backup, this method is not on the celery.py file 
def restore_complete_db():
    from django.core.management import call_command
    
    CHOICES_FILES = []
    for f in os.listdir(settings.BACK_UP_DIR+'/REMeDDoS/'):
        CHOICES_FILES.append(f)
    filename = CHOICES_FILES[-1]
    fixture_path = (settings.BACK_UP_DIR+'/REMeDDoS/'+filename)
    call_command(f"loaddata",fixture_path)
    



# Delete expired backups , days a save file is stored = 30
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
# Restores the whole DB backup, this method is not on the celery.py file 
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



# task for deleting attacks that are a week old and not relevant since the info will be saved in the rem-golem app
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
            event.delete()


# task for deleting proposed routes that are a week old and not relevant since the info will be saved in the rem-golem app
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
