from django.shortcuts import render
from django.http import HttpResponse
from django.views.generic import View 
from braces.views import CsrfExemptMixin

from .models import *

from flowspec.tasks import *
from .helpers import *
import json

# Create your views here.
class ProcessWebHookView(CsrfExemptMixin, View):
    def post(self, request, *args, **kwargs):
        message = json.loads(request.body)
        id_event = message['event']['id']
        anomaly_ticket, anomaly_info = petition_geni(id_event)
        #post.apply_async(args=[anomaly_ticket, anomaly_info, id_event], kwargs={'kwarg1':'anomaly_ticket','kwarg2':'anomaly_info','kwarg3':'id_event'})
        post(request,anomaly_ticket, anomaly_info, id_event) 
        return HttpResponse()

def display(request):
    golem_attacks = GolemAttack.objects.all()
    return render(request,'golem/display.html',{'attacks':golem_attacks})

def confirmation_commit(request):
        # method that will commit the route to the router once the client approves it
        pass