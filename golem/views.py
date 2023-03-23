from asyncio import tasks
from django.shortcuts import render
from django.http import HttpResponse
from django.views.generic import View 
from braces.views import CsrfExemptMixin
from django.contrib.auth.decorators import login_required
from allauth.account.decorators import verified_email_required
from django.views.decorators.cache import never_cache
from django.contrib import messages
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from flowspec.decorators import *

from flowspec.validators import (
    clean_source,
    clean_destination,
    clean_expires,
    clean_route_form
)
import multiprocessing
from multiprocessing import Process

from golem.tasks import golem


from .models import *


from peers.models import *
from .helpers import *
import json
import threading
from flowspec.forms import *
import logging


LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Create your views here.
class ProcessWebHookView(CsrfExemptMixin, View):
    def post(self, request, *args, **kwargs):
        message = json.loads(request.body)
        id_event = message['event']['id']
        anomaly_ticket, anomaly_info = petition_geni(id_event)

        try:
            last_updated = message['event']['datetime']['update_time']
        except Exception as e:
            #if not found it means the field is not has not been sent yet
            pass
        print('New webhook event, ', id_event, anomaly_info['status'])   
        if not anomaly_info['status'] == 'Recovered':   
            try:
                with multiprocessing.Pool(processes=50) as pool:
                    pool.apply_async(golem, args=(anomaly_info,id_event,last_updated))
                    pool.close()
                    pool.join()
                
            except Exception as e:
                logger.info('Error while trying to analyze the golem event. Error: ', e)
                pass
        elif anomaly_info['status'] == 'Recovered' :
            dic_regla = assemble_dic(anomaly_ticket['response']['result']['data'][0]['traffic_characteristics'],anomaly_info)
            peer = find_peer(dic_regla['institution_name'])
            recovered(id_event,anomaly_info,peer)

        return HttpResponse()

@login_required
@verify_profile
@verified_email_required
@never_cache
def display(request):
    username = request.user.username
    if request.user.is_superuser:
        golem_attacks = GolemAttack.objects.all().order_by('-received_at')
        return render(request,'golem/display.html',{'attacks':golem_attacks})

    else:
        peer_name = get_peers(username)
        peer = Peer.objects.get(peer_name=peer_name)
        golem_attacks = GolemAttack.objects.filter(peer=peer.pk).all()[::-1]
        return render(request,'golem/display.html',{'attacks':golem_attacks})


@login_required
@verify_profile
@verified_email_required
@never_cache
def display_routes(request,golem_name):

    all_routes = find_all_routes()
    golem_routes = []

    for x in all_routes:
        for route in x:
            if route.name.startswith(golem_name):
                golem_routes.append(route)

    actions = ThenAction.objects.all()
    golem = GolemAttack.objects.get(id_name=golem_name)

    if golem.link:
        return render(request,'golem/user_routes.html',{'routes':golem_routes,'golem_name':golem_name,'link':golem.link,'actions':actions})
    else:
        return render(request,'golem/user_routes.html',{'routes':golem_routes,'golem_name':golem_name,'actions':actions})


@login_required
@verify_profile
@verified_email_required
@never_cache
def display_proposed_routes(request):
    try:
        user = request.user
        routes = find_routes(user.username)
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(request,'error.html',{'error': error})
    all_routes = []
    for r in routes:
        if r.is_proposed :
            all_routes.append(r)    
    return render(request,'pending_routes.html',{'routes':all_routes})


@login_required
@verify_profile   
@verified_email_required
@never_cache
def display_golem_updates(request,golem_id):
    golem_attack = GolemAttack.objects.get(id_name=golem_id)
    updates = golem_attack.check_golem_updates()
    return render(request,'golem/updates.html',{'golem':golem_attack,'updates':updates})



@login_required
@verify_profile
@verified_email_required
@never_cache
@verify_staff_account
def delete_golem(request):
    username = request.user.username
    golem_id = request.POST['golem_id']
    try:
        golem = GolemAttack.objects.get(id_name=golem_id)
        golem.delete()
    except Exception as e:
        logger.info(f"There was an error when trying to delete a golem event. Error: {e} ")
    if request.user.is_superuser:
        golem_attacks = GolemAttack.objects.all().order_by('-received_at')
        return render(request,'golem/display.html',{'attacks':golem_attacks})
    else:
        peer_name = get_peers(username)
        peer = Peer.objects.get(peer_name=peer_name)
        golem_attacks = GolemAttack.objects.filter(peer=peer.pk).all()[::-1]
        return render(request,'golem/display.html',{'attacks':golem_attacks})


##================= commit pending routes to router

@login_required
@verify_profile
@verified_email_required
@verify_staff_account
def verify_commit_route(request, route_slug):
    if 'token' in request.COOKIES:
        url = reverse('commit', kwargs={'route_slug': route_slug})
        return HttpResponseRedirect(url)
    else: 
        if request.is_ajax and request.method == "GET":
            if not 'token' in request.COOKIES:
                num = get_code()
                """ user = request.user """
                peer = get_peer_tag(request.user.username)
                msg = "El usuario {user} ha solicitado un codigo de seguridad para configurar una regla propuesta en el router. Código: '{code}'.".format(user=request.user,code=num)
                code = Validation(value=num,user=request.user)
                code.save()
                if request.user.is_superuser:
                    send_message(msg,peer=None, superuser=True)
                else:
                    send_message(msg,peer,superuser=False)
                form = ValidationForm(request.GET)
                route = get_specific_route(applier=request.user.username,peer=None,route_slug=route_slug)
                message = f"CUIDADO. Seguro que quiere aplicar la siguiente regla {route_slug}?"
                response = render(request,'values/add_value.html', {'form': form, 'message':message,'status':'commit', 'route':route}) 
                return response      
        if request.method=='POST':
            form = ValidationForm(request.POST)
            if form.is_valid():
                code = form.cleaned_data.get('value')
                value = Validation.objects.latest('id')
                try:
                    if str(value) == str(code):
                        url = reverse('commit', kwargs={'route_slug': route_slug})
                        response = HttpResponseRedirect(url) 
                        try:
                            num = Validation.objects.latest('created_date')
                            response.set_cookie('token',value=num,max_age=900) 
                        except Exception as e:
                            logger.info('There was an exception when trying to assign the token, ',e)
                        return response
                    else:
                        form = ValidationForm(request.GET)
                        message = "El código introducido es erróneo por favor introduzca el último código enviado."
                        return render(request,'values/add_value.html', {'form': form, 'message':message})
                    
                except Exception as e:
                    form = ValidationForm(request.GET)
                    message = "El código introducido es erróneo por favor introduzca el último código enviado."
                    return render(request,'values/add_value.html', {'form': form, 'message':message})
            else:
                form = ValidationForm(request.GET)
                message = "El código introducido es erróneo por favor introduzca el último código enviado."
                return render(request,'values/add_value.html', {'form': form, 'message':message})




@login_required
@verify_profile
@never_cache
@verify_staff_account
def commit_to_router(request,route_slug):
    import datetime

    applier_peer_networks = []
    tomorrow = (datetime.date.today() + datetime.timedelta(days=1))

    fd = route_slug.find('_')
    peer_tag = route_slug[fd+1:-2]
    route = get_specific_route(applier=None,peer=peer_tag,route_slug=route_slug)
    route.expires = tomorrow
    event_name = get_event_name(route_slug)
    if request.user.is_superuser:
        route.applier = request.user
        route.save()
        route.commit_add()
        return HttpResponseRedirect(reverse("golem-routes",kwargs={'golem_name': event_name}))
    if not request.user.is_superuser: 
        user_peers = request.user.profile.peers.all()
        for peer in user_peers:
            applier_peer_networks.extend(peer.networks.all())
    if not applier_peer_networks:
        messages.add_message(request,messages.WARNING,('Insufficient rights on administrative networks. Cannot add rule. Contact your administrator'))
        return HttpResponseRedirect(reverse("group-routes"))
    
    if not request.user.is_superuser:
        source = clean_source(request.user,route.source)
        destination = clean_destination(request.user, route.destination)
        route.source = source
        route.destination = destination
        route.applier = request.user
        route.expires = clean_expires(route.expires)
        try:
            route.save()
            route.commit_add()
            return HttpResponseRedirect(reverse("golem-routes", kwargs={'golem_name': event_name}))
        except Exception as e:
            logger.info(f"Ha habido un error cuando se intentaba hacer commit de una regla. Error: {e}")
            messages.add_message(request,messages.WARNING,('Ha ocurrido un error a la hora de intentar configurar la regla en el router. Contacte con su administrador.'))
            return HttpResponseRedirect(reverse("golem-routes", kwargs={'golem_name': event_name}))


        

        

        
        



