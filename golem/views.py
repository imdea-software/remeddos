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

from flowspec.validators import (
    clean_source,
    clean_destination,
    clean_expires,
    clean_route_form
)

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
                task = Process(target=golem, args=(anomaly_info,id_event,last_updated))
                task.start()
            except Exception as e:
                logger.info('Error while trying to analyze the golem event. Error: ',e)
        elif anomaly_info['status'] == 'Recovered' :
            dic_regla = assemble_dic(anomaly_ticket['response']['result']['data'][0]['traffic_characteristics'],anomaly_info)
            peer = find_peer(dic_regla['institution_name'])
            recovered(id_event,anomaly_info,peer)

        return HttpResponse()

@verified_email_required
@login_required
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

@verified_email_required
@login_required
@never_cache
def display_routes(request,golem_name):
    peers = Peer.objects.all()
    actions = ThenAction.objects.all()
    golem = GolemAttack.objects.get(id_name=golem_name)
    p = ''
    dic = {'Punch': golem.route.order_by('filed'),'CV':golem.route_cv.order_by('filed'),'CIB':golem.route_cib.order_by('filed'),'CSIC':golem.route_csic.order_by('filed'),'CEU':golem.route_ceu.order_by('filed'),'CUNEF':golem.route_cunef.order_by('filed'),'IMDEA_NET':golem.route_imdeanet.order_by('filed'),
    'IMDEA':golem.route_imdea.order_by('filed'),'UAM':golem.route_uam.all(),'UC3M':golem.route_uc3m.order_by('filed'),'UCM':golem.route_ucm.order_by('filed'),'UAH':golem.route_uah.order_by('filed'),'UEM':golem.route_uem.order_by('filed'),'UNED':golem.route_uned.order_by('filed'),'UPM':golem.route_upm.order_by('filed'),
    'URJC':golem.route_urjc.order_by('filed')}
    for peer in peers:
        if peer.peer_tag == golem.peer.peer_tag:
            p = peer.peer_tag
            reglas = dic.get(p,'Institución invalida')
    return render(request,'golem/user_routes.html',{'routes':reglas,'golem_name':golem_name,'link':golem.link,'actions':actions})
    
@verified_email_required
@login_required
@never_cache
def display_golem_updates(request,golem_id):
    golem_attack = GolemAttack.objects.get(id_name=golem_id)
    updates = golem_attack.check_golem_updates()
    return render(request,'golem/updates.html',{'golem':golem_attack,'updates':updates})


@verified_email_required
@login_required
@never_cache
def delete_golem(request,golem_id):
    username = request.user.username
    try:
        golem = GolemAttack.objects.get(id_name=golem_id)
        golem.delete()
    except Exception as e:
        print (e)
    if request.user.is_superuser:
        golem_attacks = GolemAttack.objects.all().order_by('-received_at')
        return render(request,'golem/display.html',{'attacks':golem_attacks})
    else:
        peer_name = get_peers(username)
        peer = Peer.objects.get(peer_name=peer_name)
        golem_attacks = GolemAttack.objects.filter(peer=peer.pk).all()[::-1]
        return render(request,'golem/display.html',{'attacks':golem_attacks})


##================= commit pending routes to router
@verified_email_required
@login_required
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
                            print('There was an exception when trying to assign the token, ',e)
                        return response
                    else:
                        form = ValidationForm(request.GET)
                        message = "El código introducido es erróneo porfavor introduzca el último código enviado."
                        return render(request,'values/add_value.html', {'form': form, 'message':message})
                    
                except Exception as e:
                    form = ValidationForm(request.GET)
                    message = "El código introducido es erróneo porfavor introduzca el último código enviado."
                    return render(request,'values/add_value.html', {'form': form, 'message':message})
            else:
                form = ValidationForm(request.GET)
                message = "El código introducido es erróneo porfavor introduzca el último código enviado."
                return render(request,'values/add_value.html', {'form': form, 'message':message})





@login_required
@never_cache
def commit_to_router(request,route_slug):
    applier_peer_networks = []
    fd = route_slug.find('_')
    peer_tag = route_slug[fd+1:-2]
    route = get_specific_route(applier=None,peer=peer_tag,route_slug=route_slug)
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
        source = IPNetwork('%s/%s' % (IPNetwork(route.source).network.compressed, IPNetwork(route.source).prefixlen)).compressed
        destination = IPNetwork('%s/%s' % (IPNetwork(route.destination).network.compressed, IPNetwork(route.destination).prefixlen)).compressed
        route.source = clean_source(request.user, source)
        route.destination = clean_destination(request.user, destination) 

        peer = Peer.objects.get(pk__in=user_peers)
        network = peer.networks.filter(network__icontains=route.destination)
        print('fml ', route.destination, ' network: ', network )
        if not network.exists():
            print('this is netwooork: ', network, peer)
            messages.add_message(request,messages.WARNING,('Estás intentando aplicacar una regla con direcciones que no pertenecen a tu espacio administrativo. Contacte con su administrador.'))
            return HttpResponseRedirect(reverse("golem-routes", kwargs={'golem_name': event_name})) 
        
        route.applier = request.user
        route.expires = clean_expires(route.expires)
        
        try:
            route.requesters_address = request.META['HTTP_X_FORWARDED_FOR']
        except:
            # in case the header is not provided
            route.requesters_address = 'unknown'
        try:
            print('weak')
            route.save()
            route.commit_add()
            return HttpResponseRedirect(reverse("golem-routes", kwargs={'golem_name': event_name}))
        except Exception as e:
            messages.add_message(request,messages.WARNING,('Estás intentando aplicacar una regla con direcciones que no pertenecen a tu espacio administrativo. Contacte con su administrador. Excepción: ',e))
            return HttpResponseRedirect(reverse("golem-routes", kwargs={'golem_name': event_name}))


        

        

        
        



