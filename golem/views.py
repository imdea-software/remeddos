from asyncio import tasks
from django.shortcuts import render
from django.http import HttpResponse
from django.views.generic import View 
from braces.views import CsrfExemptMixin
from django.contrib.auth.decorators import login_required
from allauth.account.decorators import verified_email_required
from django.views.decorators.cache import never_cache
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse

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
        print('New webhook event, ', id_event)
        try:
            #post.apply_async((anomaly_info, id_event))
            task = Process(target=golem, args=(anomaly_info,id_event))
            task.start()
            
        except Exception as e:
            logger.info('Error while trying to analyze the golem event. Error: ',e)
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
    if request.is_ajax and request.method == "GET":
        if not 'token' in request.COOKIES:
            num = get_code()
            user = request.user
            peer = get_peer_tag(user.username)
            msg = "El usuario {user} ha solicitado un codigo de seguridad para configurar una regla propuesta en el router. Código: '{code}'.".format(user=user,code=num)
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
    fd = route_slug.find('_')
    peer_tag = route_slug[fd+1:-2]
    route = get_specific_route(applier=None,peer=peer_tag,route_slug=route_slug)
    route.applier = request.user
    route.save()
    route.commit_add()
    return HttpResponseRedirect(reverse("group-routes"))


