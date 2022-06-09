from django.shortcuts import render
from django.http import HttpResponse
from django.views.generic import View 
from braces.views import CsrfExemptMixin
from django.contrib.auth.decorators import login_required
from allauth.account.decorators import verified_email_required
from django.views.decorators.cache import never_cache
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse


from .models import *

from flowspec.tasks import post 
from peers.models import *
from .helpers import *
import json
import threading
from flowspec.forms import *

# Create your views here.
class ProcessWebHookView(CsrfExemptMixin, View):
    def post(self, request, *args, **kwargs):
        message = json.loads(request.body)
        id_event = message['event']['id']
        anomaly_ticket, anomaly_info = petition_geni(id_event)
        print('New webhook event, ', id_event)
        try:
            post.apply_async((anomaly_info, id_event))
        except Exception as e:
            print('WTF: ',e)
        print('after post')
        #post(anomaly_info, id_event) 
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
    dic = {'Punch': golem.route.all(),'CV':golem.route_cv.all(),'CIB':golem.route_cib.all(),'CSIC':golem.route_csic.all(),'CEU':golem.route_ceu.all(),'CUNEF':golem.route_cunef.all(),'IMDEA_NET':golem.route_imdeanet.all(),
    'IMDEA':golem.route_imdea.all(),'UAM':golem.route_uam.all(),'UC3M':golem.route_uc3m.all(),'UCM':golem.route_ucm.all(),'UAH':golem.route_uah.all(),'UEM':golem.route_uem.all(),'UNED':golem.route_uned.all(),'UPM':golem.route_upm.all(),
    'URJC':golem.route_urjc.all()}
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
def verify_commit_route(request):
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
            response = JsonResponse({"valid":True}, status = 200)
            try:
                response.set_cookie('token',value=num,max_age=900) 
            except Exception as e:
                print('There was an exception when trying to assign the token, ',e)
            return response      
    if request.method=='POST':
        form = ValidationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('value')
            value = Validation.objects.latest('id')
            try:
                if str(value) == str(code):
                    url = reverse('commit')
                    response = HttpResponseRedirect(url) 
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
    return HttpResponseRedirect(reverse("attack-list"))


