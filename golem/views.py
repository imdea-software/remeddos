from django.shortcuts import render
from django.http import HttpResponse
from django.views.generic import View 
from braces.views import CsrfExemptMixin
from django.contrib.auth.decorators import login_required
from allauth.account.decorators import verified_email_required
from django.views.decorators.cache import never_cache

from .models import *

from flowspec.tasks import *
from peers.models import *
from .helpers import *
import json

# Create your views here.
class ProcessWebHookView(CsrfExemptMixin, View):
    def post(self, request, *args, **kwargs):
        message = json.loads(request.body)
        id_event = message['event']['id']
        anomaly_ticket, anomaly_info = petition_geni(id_event)
        #post.apply_async(args=[anomaly_ticket, anomaly_info, id_event], kwargs={'kwarg1':'anomaly_ticket','kwarg2':'anomaly_info','kwarg3':'id_event'})
        post(anomaly_info, id_event) 
        return HttpResponse()

@verified_email_required
@login_required
@never_cache
def display(request):
    username = request.user.username
    protocolo = []
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
    golem = GolemAttack.objects.get(id_name=golem_name)
    p = ''
    routes = []
    dic = {'Punch': golem.route,'CV':golem.route_cv,'CIB':golem.route_cib,'CSIC':golem.route_csic,'CEU':golem.route_ceu,'CUNEF':golem.route_cunef,'IMDEA_NET':golem.route_imdeanet,
    'IMDEA':golem.route_imdea,'UAM':golem.route_uam,'UC3M':golem.route_uc3m,'UCM':golem.route_ucm,'UAH':golem.route_uah,'UEM':golem.route_uem,'UNED':golem.route_uned,'UPM':golem.route_upm,
    'URJC':golem.route_urjc}
    for peer in peers:
        if peer.peer_tag == golem.peer.peer_tag:
            p = peer.peer_tag
    routes.append(dic.get(p,'Institución invalida'))
    return render(request,'golem/user_routes.html',{'routes':routes,'golem_name':golem_name})
    
@verified_email_required
@login_required
@never_cache
def display_golem_updates(request,golem_id):
    golem_attack = GolemAttack.objects.get(id_name=golem_id)
    updates = golem_attack.check_golem_updates()
    return render(request,'golem/updates.html',{'golem':golem_attack,'updates':updates})