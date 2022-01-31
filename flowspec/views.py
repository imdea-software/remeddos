# -*- coding: utf-8 -*- vim:fileencoding=utf-8:
# vim: tabstop=4:shiftwidth=4:softtabstop=4:expandtab

# Copyright (C) 2010-2014 GRNET S.A.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import json
from django import forms
from django.contrib.auth.decorators import login_required
from allauth.account.decorators import verified_email_required
from django.contrib.auth import logout
from django.contrib.sites.models import Site
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.template.context import RequestContext
from django.template.loader import render_to_string
from django.utils.translation import ugettext as _
from django.urls import reverse
from django.contrib import messages
from accounts.models import *
from ipaddr import *
from django.db.models import Q
from django.contrib.auth import authenticate, login
from django.core.exceptions import ObjectDoesNotExist
from django.core.management import call_command
from django.views.decorators.csrf import csrf_exempt

from django.views.decorators.http import require_POST
from django.views.generic import View 
from braces.views import CsrfExemptMixin

from django.forms.models import model_to_dict


from flowspec.forms import *
from flowspec.models import *
from peers.models import *

#from registration.models import RegistrationProfile 

from copy import deepcopy

from django.views.decorators.cache import never_cache
from django.conf import settings
from django.template.defaultfilters import slugify
from django.core.exceptions import PermissionDenied
from flowspec.helpers import *
from django.utils.crypto import get_random_string
import datetime
import os
import shutil
from utils import proxy as PR
from utils.proxy import Retriever
from xml.etree import ElementTree as ET

from pathlib import Path
from dotenv import load_dotenv

from pybix import GraphImageAPI
from pyzabbix import ZabbixAPI


LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')
# FORMAT = '%(asctime)s %(levelname)s: %(message)s'
# logging.basicConfig(format=FORMAT)
#formatter = logging.Formatter('%(asctime)s %(levelname)s %(user)s: %(message)s')
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME)
handler.setFormatter(formatter)
logger.addHandler(handler)

def get_code():
   n = get_random_string(length=6)
   return n

@login_required
def user_routes(request):
    user_routes = Route.objects.filter(applier=request.user)
    return render(
        request,
        'user_routes.html',
        {
            'routes': user_routes
        },
    )


def welcome(request):
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse('dashboard'))
    else:
        return render(request,'index.html')
        
        
def service_desc(request):
    return render(request,'service_description.html')


@verified_email_required
@login_required
@never_cache
def dashboard(request):
    all_group_routes = []
    message = ''
    try:
        peers = request.user.profile.peers.prefetch_related('user_profile')
        route_name = Route.objects.filter(applier=request.user).values_list('name',flat=True)
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(
            request,
            'error.html',
            {
                'error': error
            }
        )
    if peers:
        if request.user.is_superuser:
            all_group_routes = Route.objects.all().order_by('-last_updated')[:10]
            # add method for revising which rules are expired and which not for deleting the ones that are 
            for group_route in all_group_routes:
                group_route.has_expired()
        else:
            all_group_routes = Route.objects.filter(applier=request.user)
            # checking if any route is expired, if they are, the rules are deleted
            for group_route in all_group_routes:
                group_route.has_expired()
        if all_group_routes is None:
            message = 'You have not added any rules yet'
    else:
        message = 'You are not associated with a peer.'
        return render(request,'dashboard.html',{'messages': message})

    return render(request,'dashboard.html',{'routes': all_group_routes.prefetch_related('applier', 'applier','protocol','dscp',),'messages': message,'file' : '','route_slug':route_name},)


@login_required
@never_cache
def group_routes(request):
    try:
        request.user.profile.peers.all()
        routes = Route.objects.filter(applier=request.user).values_list('name',flat=True)
       
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(
            request,
            'error.html',
            {
                'error': error
            }
        )
    context = {
        'route_slug' : routes,
        'file'  : ''
    }
    return render(request,'user_routes.html',context)

@verified_email_required
@login_required
@never_cache
def group_routes_ajax(request):
    all_group_routes = []
    try:
        peers = request.user.profile.peers.prefetch_related('networks')
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(
            request,
            'error.html',
            {'error': error}
        )
    if request.user.is_superuser:
        all_group_routes = Route.objects.all()
    else:
        all_group_routes = Route.objects.filter(applier=request.user)
    jresp = {}
    routes = build_routes_json(all_group_routes, request.user.is_superuser)
    jresp['aaData'] = routes
    return JsonResponse(jresp)


@login_required
@never_cache
def overview_routes_ajax(request):
    all_group_routes = []
    try:
        peers = request.user.profile.peers.prefetch_related('user_profile')
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(request,'error.html', {'error': error})
    query = Q()
    for peer in peers:
        query |= Q(applier='use_profile' in peer.user_profile.all())
    all_group_routes = Route.objects.filter(query)
    if request.user.is_superuser or request.user.has_perm('accounts.overview'):
        all_group_routes = Route.objects.all()
    jresp = {}
    routes = build_routes_json(all_group_routes, request.user.is_superuser)
    jresp['aaData'] = routes
    return HttpResponse(json.dumps(jresp), content_type='application/json')


def build_routes_json(groutes, is_superuser):
    routes = []
    for r in groutes.prefetch_related(
            'applier',
            #'fragmenttype',
            'protocol',
            'dscp',
    ):
        rd = {}
        rd['id'] = r.pk
        rd['port'] = r.port
        rd['sourceport'] = r.sourceport
        rd['destinationport'] = r.destinationport
        # name with link to rule details
        rd['name'] = r.name
        rd['details'] = '<a href="%s">%s</a>' % (r.get_absolute_url(), r.name)
        if not r.comments:
            rd['comments'] = 'Not Any'
        else:
            rd['comments'] = r.comments
        rd['match'] = r.get_match()
        rd['then'] = r.get_then()
        rd['status'] = r.status
        # in case there is no applier (this should not occur)
        try:
            #rd['applier'] = r.applier.username
            userinfo = r.applier_username_nice
            #if is_superuser:
            #  applier_username = r.applier.username
            #  if applier_username != userinfo:
            #    userinfo += " ("+applier_username+")"
            rd['applier'] = userinfo
        except:
            rd['applier'] = 'unknown'
            rd['peer'] = ''
        else:
            peers = r.applier.profile.peers.prefetch_related('networks')
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(r.destination) in net:
                        username = peer.peer_name
                        break
            try:
                rd['peer'] = username
            except UserProfile.DoesNotExist:
                rd['peer'] = ''

        rd['expires'] = "%s" % r.expires
        rd['response'] = "%s" % r.response
        routes.append(rd)
    return routes

@verified_email_required
@login_required
def verify_add_user(request):
    if request.is_ajax and request.method == "GET":
        num = get_code()
        user = request.user
        msg = "El usuario {user} ha solicitado un codigo de seguridad para añadir una nueva regla. Código: '{code}'.".format(user=user,code=num)
        code = Validation(value=num,user=request.user)
        code.save()
        send_message(msg)
        return JsonResponse({"valid":True}, status = 200)     
    if request.method=='POST':
        form = ValidationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('value')
            value = Validation.objects.latest('id')
            try:
                if str(value) == str(code):
                    url = reverse('add')
                    return HttpResponseRedirect(url)
                else:
                    form = ValidationForm(request.GET)
                    message = "El código introducido es erróneo porfavor introduzca el último código enviado."
                    return render(request,'values/add_value.html', {'form': form, 'message':message})
            
            except Exception as e:
                form = ValidationForm(request.GET)
                message = "El código introducido es erróneo porfavor introduzca el último código enviado."
                return render(request,'values/add_value.html', {'form': form, 'message':message})
            


@verified_email_required
@login_required
@never_cache
def add_route(request):
    applier_peer_networks = []
    applier = request.user.pk
    if request.user.is_superuser:       
        applier_peer_networks = PeerRange.objects.all()
        user_peers = request.user.profile.peers.all()
    else:
        user_peers = request.user.profile.peers.all()
        for peer in user_peers:
            applier_peer_networks.extend(peer.networks.all())
    if not applier_peer_networks:
        messages.add_message(request,messages.WARNING,('Insufficient rights on administrative networks. Cannot add rule. Contact your administrator'))
        return HttpResponseRedirect(reverse("group-routes"))
    if request.method == "GET":
        user = request.user
        form = RouteForm(initial={'applier': applier})
        form.fields['destinationport'].required=False
        form.fields['sourceport'].required=False
        form.fields['port'].required=False
        form.fields['expires'].required=False
        peer = Peer.objects.get(pk__in=user_peers)
        #form.fields['source'] = forms.ModelChoiceField(queryset=peer.networks.all(), required=True)
        #form.fields['destination'] = forms.ModelMultipleChoiceField(queryset=peer.networks.all(), required=True)
        if not request.user.is_superuser:
            form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
            form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
        return render(request,'apply.html',{'form': form,'applier': applier,'maxexpires': settings.MAX_RULE_EXPIRE_DAYS,'peers':peer.networks.all()})
    else:
        request_data = request.POST.copy()
        if request.user.is_superuser:
            request_data['issuperuser'] = request.user.username
        else:
            request_data['applier'] = applier
            try:
                del requset_data['issuperuser']
            except:
                pass
        form = RouteForm(request_data)
        if form.is_valid():
            route = form.save(commit=False)
            if not request.user.is_superuser:
                route.applier = request.user
            #route.status= "PENDING"
            route.response = "Applying"
            route.source = IPNetwork('%s/%s' % (IPNetwork(route.source).network.compressed, IPNetwork(route.source).prefixlen)).compressed
            route.destination = IPNetwork('%s/%s' % (IPNetwork(route.destination).network.compressed, IPNetwork(route.destination).prefixlen)).compressed
            try:
                route.requesters_address = request.META['HTTP_X_FORWARDED_FOR']
            except:
                # in case the header is not provided
                route.requesters_address = 'unknown'
            route.save()
            form.save_m2m()
                # We have to make the commit after saving the form
                # in order to have all the m2m relations.
            route.commit_add()
            return HttpResponseRedirect(reverse("group-routes"))
        else:
            if not request.user.is_superuser:
                form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
                form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
            return render(request,'apply.html',{'form': form,'applier': applier,'maxexpires': settings.MAX_RULE_EXPIRE_DAYS})

@verified_email_required
@login_required             
def verify_edit_user(request,route_slug):
    if request.method =='GET':
        num = get_code()
        user= request.user
        route = Route.objects.get(name=route_slug)
        msg = "El usuario {user} ha solicitado el siguiente código para editar la regla: {route_slug}. Código:  '{code}'.".format(user=user,code=num,route_slug=route_slug)
        code = Validation(value=num,user=request.user)
        code.save()
        send_message(msg)
        form = ValidationForm(request.GET)
        message = ""
        return render(request,'values/add_value.html', {'form': form, 'message':message,'status':'edit', 'route':route})
        
    if request.method=='POST':
        form = ValidationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('value')
            value = Validation.objects.latest('id')
            try:
                if str(value) == str(code):
                    url = reverse('edit', kwargs={'route_slug': route_slug})
                    return HttpResponseRedirect(url)
                else:
                    form = ValidationForm(request.GET)
                    message = "El código introducido es erróneo porfavor introduzca el último código enviado."
                    return render(request,'values/add_value.html', {'form': form, 'message':message})

            except Exception as e:
                form = ValidationForm(request.GET)
                message = "Ha sucedido un error, porfavor introduzca el último código enviado.", e
                return render(request,'values/add_value.html', {'form': form, 'message':message})

@verified_email_required
@login_required
@never_cache
def edit_route(request, route_slug):
    applier = request.user.pk
    route_edit = get_object_or_404(Route, name=route_slug)
    applier_peer_networks = []
    if request.user.is_superuser:
        applier_peer_networks = PeerRange.objects.all()
    else:
        user_peers = request.user.profile.peers.all()
        for peer in user_peers:
            applier_peer_networks.extend(peer.networks.all())
    if not applier_peer_networks:
        messages.add_message(
            request,
            messages.WARNING,
            ('Insufficient rights on administrative networks. Cannot add rule. Contact your administrator')
        )
        return HttpResponseRedirect(reverse("group-routes"))    
    if route_edit.status== 'PENDING':
        messages.add_message(
            request,
            messages.WARNING,
            ('Cannot edit a pending rule: %s.') % (route_slug)
        )
        return HttpResponseRedirect(reverse("group-routes"))
    route_original = deepcopy(route_edit)
    if request.POST:
        request_data = request.POST.copy()
        if request.user.is_superuser:
            request_data['issuperuser'] = request.user.username
        else:
            request_data['applier'] = applier
            try:
                del request_data['issuperuser']
            except:
                pass
        form = RouteForm(
            request_data,
            instance=route_edit
        )
        
        critical_changed_values = ['source', 'destination', 'sourceport', 'destinationport', 'port', 'protocol', 'then', 'packetlenght','tcpflags']
        if form.is_valid():
            changed_data = form.changed_data
            route = form.save(commit=False)
            route.name = route_original.name
            route.status= route_original.status
            route.response = route_original.response
            if not request.user.is_superuser:
                route.applier = request.user
            if bool(set(changed_data) and set(critical_changed_values)) or (not route_original.status== 'ACTIVE'):
                #route.status= "PENDING"
                route.response = "Applying"
                route.source = IPNetwork('%s/%s' % (IPNetwork(route.source).network.compressed, IPNetwork(route.source).prefixlen)).compressed
                route.destination = IPNetwork('%s/%s' % (IPNetwork(route.destination).network.compressed, IPNetwork(route.destination).prefixlen)).compressed
                try:
                    route.requesters_address = request.META['HTTP_X_FORWARDED_FOR']
                except:
                    # in case the header is not provided
                    route.requesters_address = 'unknown'

            route.save()
            if bool(set(changed_data) and set(critical_changed_values)) or (not route_original.status== 'ACTIVE'):
                form.save_m2m()
                route.commit_edit()
            return HttpResponseRedirect(reverse("group-routes"))
        else:  
            if not request.user.is_superuser:
                form.fields['destinationport'].required=False
                form.fields['sourceport'].required=False
                form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
                form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
            return render(request,
                'apply.html',
                {
                    'form': form,
                    'edit': True,
                    'applier': applier,
                    'routename':route_edit.name, 
                    'maxexpires': settings.MAX_RULE_EXPIRE_DAYS
                }
            )
    else:
        if (not route_original.status== 'ACTIVE'):
            route_edit.expires = datetime.date.today() + datetime.timedelta(days=settings.EXPIRATION_DAYS_OFFSET-1)
        dictionary = model_to_dict(route_edit, fields=[], exclude=[])
        
        routef = Route.objects.get(id=route_edit.pk)       
        form = RouteForm(instance=routef)
        form.fields['name'].required=False
        form.fields['destinationport'].required=False
        form.fields['sourceport'].required=False
        if not request.user.is_superuser:
            form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
            form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
        return render(request,
            'apply.html',
            {
                'form': form,
                'edit': True,
                'applier': applier,
                'routename':route_edit.name,
                'maxexpires': settings.MAX_RULE_EXPIRE_DAYS
            }
        )


@verified_email_required
@login_required
def verify_delete_user(request, route_slug):
    if request.method =='GET':
        num = get_code()
        user = request.user
        msg = "El usuario: {user} ha solicitado un código para poder eliminar una regla. Código: '{code}'.".format(user=user,code=num)
        code = Validation(value=num,user=request.user)
        code.save()
        send_message(msg)
        form = ValidationForm(request.GET)
        route = Route.objects.get(name=route_slug)
        message = f"CUIDADO. Seguro que quiere eliminar la siguiente regla {route_slug}?"
        return render(request,'values/add_value.html', {'form': form, 'message':message,'status':'delete', 'route':route})
            
    if request.method=='POST':
        form = ValidationForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data.get('value')
            value = Validation.objects.latest('id')
            try:
                if str(value) == str(code):
                    url = reverse('delete', kwargs={'route_slug': route_slug})
                    return HttpResponseRedirect(url)
                else:
                    form = ValidationForm(request.GET)
                    message = "The code introduced does not match the one that has been sent, please try again."
                    return render(request,'values/add_value.html', {'form': form, 'message':message}) 
            except Exception as e:
                form = ValidationForm(request.GET)
                message = "The code used is not valid. Please introduce it again."
                return render(request,'values/add_value.html', {'form': form, 'message':message})


@verified_email_required
@login_required
@never_cache
def delete_route(request, route_slug):
    route = get_object_or_404(Route, name=route_slug)
    peers = route.applier.profile.peers.all()
    username = None
    for peer in peers:
        if username:
            break
        for network in peer.networks.all():
            net = IPNetwork(network)
            if IPNetwork(route.destination) in net:
                username = peer
                break
    applier_peer = username
    peers = request.user.profile.peers.all()
    username = None
    for peer in peers:
        if username:
            break
        for network in peer.networks.all():
            net = IPNetwork(network)
            if IPNetwork(route.destination) in net:
                username = peer
                break
    requester_peer = username
    if applier_peer == requester_peer or request.user.is_superuser:
        route.status= "INACTIVE"
        route.status="INACTIVE"
        route.expires = datetime.date.today()
        if not request.user.is_superuser:
            route.applier = request.user
        route.response = "Deactivating"
        try:
            route.requesters_address = request.META['HTTP_X_FORWARDED_FOR']
        except:
            # in case the header is not provided
            route.requesters_address = 'unknown'
        route.save()
        route.commit_delete()
    return HttpResponseRedirect(reverse("group-routes"))

@login_required
@never_cache
def user_profile(request):
    user = request.user
    try:
        peers = request.user.profile.peers.all()
        if user.is_superuser:
            peers = Peer.objects.all()
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % user.username
        return render(request,'error.html',{'error': error})
    return render(request,'profile.html',{'user': user,'peers': peers})

@login_required
@never_cache
def add_rate_limit(request):
    if request.method == "GET":
        form = ThenPlainForm()
        return render( request,'add_rate_limit.html',{'form': form})
    else:
        form = ThenPlainForm(request.POST)
        if form.is_valid():
            then = form.save(commit=False)
            then.action_value = "%sk" % then.action_value
            then.save()
            response_data = {}
            response_data['pk'] = "%s" % then.pk
            response_data['value'] = "%s:%s" % (then.action, then.action_value)
            return HttpResponse(
                json.dumps(response_data),mimetype='application/json')
        else:
            return render(request,'add_rate_limit.html',{'form': form})


@login_required
@never_cache
def add_port(request):
    if request.method == "GET":
        form = PortRangeForm()
        return render(request,'add_port.html',{'form': form})
    else:
        form = PortRangeForm(request.POST)
        if form.is_valid():
            port = form.save()
            response_data = {}
            response_data['value'] = "%s" % port.pk
            response_data['text'] = "%s" % port.port
            return HttpResponse(json.dumps(response_data),mimetype='application/json')
        else:
            return render(request,'add_port.html',{'form': form})

@never_cache
def selectinst(request):
    if request.method == 'POST':
        request_data = request.POST.copy()
        user = request_data['user']
        try:
            UserProfile.objects.get(user=user)
            error = _("Violation warning: User account is already associated with an institution.The event has been logged and our administrators will be notified about it")
            return render(request,'error.html',{'error': error,'inactive': True})
        except UserProfile.DoesNotExist:
            pass

        form = UserProfileForm(request_data)
        if form.is_valid():
            userprofile = form.save()
            user_activation_notify(userprofile.user)
            error = _("User account <strong>%s</strong> is pending activation. Administrators have been notified and will activate this account within the next days. <br>If this account has remained inactive for a long time contact your technical coordinator or GEANT Helpdesk") %userprofile.user.username
            return render(request,'error.html',{'error': error,'inactive': True})
        else:
            return render(request,'registration/select_institution.html',{'form': form})


@never_cache
def overview(request):
    user = request.user
    if user.is_authenticated:
        if user.has_perm('accounts.overview'):
            users = User.objects.all()
            return render(request,'overview/index.html',{'users': users},)
        else:
            violation = True
            return render(request,'overview/index.html',{'violation': violation})
    else:
        return HttpResponseRedirect(reverse("altlogin"))

@never_cache
def load_jscript(request,file):
    long_polling_timeout = int(settings.POLL_SESSION_UPDATE) * 1000 + 10000
    return render(request,'%s.js' % file, {'timeout': long_polling_timeout})

def lookupShibAttr(attrmap, requestMeta):
    for attr in attrmap:
        if (attr in requestMeta.keys()):
            if len(requestMeta[attr]) > 0:
                return requestMeta[attr]
    return ''


# show the details of specific route
@login_required
@never_cache
def routedetails(request, route_slug):
    route = get_object_or_404(Route, name=route_slug)
    now = datetime.datetime.now()
    return render(request, 'flowspy/route_details.html', {'route': route,'mytime': now,'tz' : settings.TIME_ZONE,'is_superuser' : request.user.is_superuser,'route_comments_len' : len(str(route.comments))})

@login_required
def routestats(request, route_slug):
    route = get_object_or_404(Route, name=route_slug)
    import junos
    import time
    res = {}
    try:
        with open(settings.SNMP_TEMP_FILE, "r") as f:
            res = json.load(f)
        f.close()
        routename = create_junos_name(route)
        route_id = str(route.id)
        if not res:
            raise Exception("No data stored in the existing file.")
        if settings.STATISTICS_PER_RULE==False:
            if routename in res:
              return HttpResponse(json.dumps({"name": routename, "data": res[routename]}), mimetype="application/json")
            else:
              return HttpResponse(json.dumps({"error": "Route '{}' was not found in statistics.".format(routename)}), mimetype="application/json", status=404)
        else:
            if route_id in res['_per_rule']:
              return HttpResponse(json.dumps({"name": routename, "data": res['_per_rule'][route_id]}), mimetype="application/json")
            else:
              return HttpResponse(json.dumps({"error": "Route '{}' was not found in statistics.".format(route_id)}), mimetype="application/json", status=404)

    except Exception as e:
        logger.error('routestats failed: %s' % e)
        return HttpResponse(json.dumps({"error": "No data available. %s" % e}), mimetype="application/json", status=404)

def setup(request):
    if settings.ENABLE_SETUP_VIEW and User.objects.count() == 0:
        if request.method == "POST":
            form = SetupForm(request.POST)
            if form.is_valid():
                u = User.objects.create_user(username="admin", email="email@example.com", password=form.cleaned_data["password"])
                u.is_superuser = True
                u.is_staff = True
                u.save()
                pr = PeerRange(network = form.cleaned_data["test_peer_addr"])
                pr.save()
                p = Peer(peer_name = "testpeer", peer_tag = "testpeer")
                p.save()
                p.networks.add(pr)
                ua = UserProfile()
                ua.user = u
                ua.save()
                ua.peers.add(p)

                with open("flowspy/settings_local.py", "a") as f:
                    f.write("NETCONF_DEVICE = \"%s\"\n" % form.cleaned_data["netconf_device"])
                    f.write("NETCONF_USER = \"%s\"\n"   % form.cleaned_data["netconf_user"])
                    f.write("NETCONF_PASS = \"%s\"\n"   % form.cleaned_data["netconf_pass"])
                    f.write("NETCONF_PORT = %s\n"       % form.cleaned_data["netconf_port"])

                logger.error('TODO REMOVE: password: %s' % form.cleaned_data["password"])
                return HttpResponseRedirect(reverse("welcome"))
        else:
            form = SetupForm()
            return render(request, 'flowspy/setup.html', {'form': form})
    else:
        raise PermissionDenied

def managing_files(string_items,routename):
    i = 0
    files = []
    graph = ''
    src = './'
    dest = settings.MEDIA_ROOT
    # locate the file dir & move files
    for f_name in os.listdir('./'):
        if f_name.endswith('.png'):
            files.append(f_name)
    for f in files:
        src = './' + f
        shutil.move(src,dest)
    # rename files with the id for each graph   
    for f in files:
        src = settings.MEDIA_ROOT + f
        os.rename(src,settings.MEDIA_ROOT+routename+'.png')
        i+=1
    graph = (routename+'.png')
    return graph


def fetch_graphs(source, destination, item_id,routename):
    # by default pybix downloads the img into the output path so
    # checks if there's a graph associated with that id first if not 
    # it will collect the img & will change the image's name and direction to make it more accessible
    dest = settings.MEDIA_ROOT
    route = get_object_or_404(Route, name=routename)
    string_items = '_'.join([str(item) for item in item_id])
    graphs = string_items+'.png'
    graph = GraphImageAPI(url=settings.ZABBIX_SOURCE,user=settings.ZABBIX_USER,password=settings.ZABBIX_PWD)
    try:
        prev_fwg = get_object_or_404(Graph, route=route)
        prev_fwg.delete() 
        fwg = Graph(graph_img=graph.get_by_item_ids(item_id),route=route)
        fwg.save()
    except:
        fwg = Graph(graph_img=graph.get_by_item_ids(item_id),route=route)
        fwg.graph_img=graphs
        fwg.save()
    graph = managing_files(string_items,routename)
    return graph


def graphs(timefrom,timetill, routename):
    zapi = ZabbixAPI(ZABBIX_SOURCE)
    zapi.login(ZABBIX_USER,ZABBIX_PWD)
    route = get_object_or_404(Route, name=routename)
    query = get_query(route.name, route.destination, route.source)

    #in order to access history log we need to send the dates as timestamp
    from_date_obj = datetime.datetime.strptime(timefrom,"%Y/%m/%d %H:%M")
    till_date_obj = datetime.datetime.strptime(timetill,"%Y/%m/%d %H:%M")

    ts_from = int(from_date_obj.timestamp())
    ts_till = int(till_date_obj.timestamp())
    #query for getting the itemid and the hostid
    item = zapi.do_request(method='item.get', params={"output": "extend","search": {"key_":query}})
    item_id = [i['itemid'] for i in item['result']]
    hostid = [i['hostid'] for i in item['result']]
    #if query fails it might be because parameters are not int parsed
    item_history = zapi.history.get(hostids=hostid,itemids=item_id,time_from=ts_from,time_till=ts_till)
    
    beats_date = []; beats_hour = []; clock_value = []; beat_value = []; beats_fulltime = []; beats_values = []

    for x in item_history:
        clock_value.append(x['clock'])
        beat_value.append(x['value'])
    
    for x in clock_value:
        y = datetime.datetime.fromtimestamp(int(x))
        beats_date.append(y.strftime("%m/%d/%Y"))
        beats_hour.append(y.strftime("%H:%M:%S"))
        beats_fulltime.append(y.strftime("%Y/%m/%d %H:%M:%S"))
    
    beats_values = dict(zip(beats_hour,beat_value))
    return beats_date, beats_hour, beat_value, beats_values, beats_fulltime

def ajax_graphs(request):
    if request.method == "POST":
        print('yess')
        from_time = request.POST.get('from')
        till_time = request.POST.get('till')
        routename = request.POST.get('routename')
        if from_time and till_time:
            beats_date, beats_hour, beats_value, beats_values, bfulltime = graphs(from_time, till_time, routename)
            data = {
                'beats_date':beats_date,
                'beats_hour': beats_hour,
                'beats_value' : beats_value,
            }
            """ bv = json.dumps(beats_values) """
            print(type(bfulltime))
            return JsonResponse({'status':'succesful','time':bfulltime,'beats':beats_value},status=200)
        else:
            print('trace2, the bad one')
            return JsonResponse({'message':'Porfavor introduce los parámetros necesarios para ver el gráfico'}, status=400)


@verified_email_required
@login_required
@never_cache
def display_graphs(request,route_slug):
    route = get_object_or_404(Route, name=route_slug) 
    return render(request,'graphs.html',{'route':route})
    
def get_routes_router():
    retriever = Retriever()
    router_config = retriever.fetch_config_str()    
    tree = ET.fromstring(router_config)
    data = [d for d in tree]
    config = [c for c in data]
    for config_nodes in config:
        options = config_nodes
    for option_nodes in options:
        flow = option_nodes 
    for flow_nodes in flow:
        routes = flow_nodes   
    return routes
    
def sync_router(request):
    # find what peer organisation does the user belong to
    peer = get_peers(request.user)
    # first initialize all the needed vars    
    applier = User.objects.get(username=request.user); routes = get_routes_router() ; fw_rules = []; message = ''
    # for getting the route parameters is needed to run through the xml 
    for children in routes:
        then = '' ; then_action = '' ; protocol = [] ; destination = [] ; source = '' ; src_port =  '' ; dest_port = '' ; tcpflags = '' ; icmpcode = ''; icmptype = ''; packetlength = ''; prot = '';  name_fw = ''
        for child in children:
            if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                name_fw = child.text
                if (peer in name_fw):
                    name_peer = child.text
                    fw_rules.append(child.text)                              
            # if the user peer organisation is found on the router the program will collect all the vars info    
            if (peer in name_fw):  
                for child in children:
                    if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}then':
                        for thenaction in child:                    
                            th = thenaction.tag ; start = th.find('}') ; then = th[start+1::]
                            then_action = thenaction.text
                    if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}match':
                        for c in child:
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}protocol': protocol = c.text
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}destination-port':dest_port = c.text
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}source-port':src_port = c.text
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}destination':destination = c.text
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}tcp-flags': tcpflags = c.text 
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}icmp-code': icmpcode = c.text 
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}icmp-type': icmptype = c.text 
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}packet-length' and c.text != '': packetlength = c.text
                            if c.tag == '{http://xml.juniper.net/xnm/1.1/xnm}source': source = c.text                       
            if (peer in name_fw):
                try:
                    route = Route(name=name_fw,applier=applier,source=source,sourceport=src_port,destination=destination,destinationport=dest_port,icmpcode=icmpcode,icmptype=icmptype,packetlength=packetlength,tcpflag=tcpflags,status="ACTIVE")  
                        # check if the route is already in our DB
                    if not Route.objects.filter(name=route.name).exists():
                        route.save()
                        if isinstance(protocol,(list)):
                            for p in protocol:
                                prot, created = MatchProtocol.objects.get_or_create(protocol=p)
                                route.protocol.add(prot.pk)
                        else:
                            prot, created = MatchProtocol.objects.get_or_create(protocol=protocol)
                            route.protocol.add(prot)
                        th_act, created = ThenAction.objects.get_or_create(action=then,action_value=then_action)
                        route.then.add(th_act.pk)
                        message ='All the routes have been properly syncronised with the database'                    
                    else:
                        message = 'Routes have already been syncronised.'
                        pass
                except Exception as e:                    
                    message = (f'There was an error when trying to sync all routes from the router. {e}')
    return render(request,'routes_synced.html',{'message':message})

@login_required
@never_cache
def routes_sync(request):
    routes = Route.objects.all(); route = get_routes_router()
    peer = get_peers(request.user); names = []
    for children in route:
        for child in children:
            if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                if child.text.endswith('_%s'%peer):
                    names.append(child.text)                   
            else:
                pass  
    routenames = [x.name for x in routes]
    message = ''
    diff = (set(routenames).difference(names))
    notsynced_routes = list(diff)
    if notsynced_routes:
        for route in notsynced_routes:
            route = Route.objects.get(name=route)
            if (route.has_expired()==False) and (route.status== 'ACTIVE' or route.status== 'OUTOFSYNC'):
                route.save()
                message = ('Estado: %s, regla de firewall no sincronizada: %s, guardando regla de firewall.' %(route.status, route.name))
                send_message(message)
            else:
                if (route.has_expired()==True) or (route.status== 'EXPIRED' and route.status!= 'ADMININACTIVE' and route.status!= 'INACTIVE'):
                    route.check_sync() 
                    message = ('Estado: %s, regla de firewall  %s, comprobando regla.' %(route.status, route.name))
                    send_message(message)
        message = 'Reglas sincronizadas.'
        send_message(message)
    else:
        message = 'No hay reglas sin sincronizar.'
        send_message(message)
    return render(request,'routes_synced.html',{'message':message})

@login_required
@never_cache
def backup(request):
    now = datetime.datetime.now()
    current_time = now.strftime("%H:%M")
    current_date = now.strftime("%d-%B-%Y") 
    try:
        call_command('dbbackup', output_filename=(f"redifod-{current_date}-{current_time}.psql"))
        message = 'Copia de seguridad creada con éxito.'
        send_message(message)
        return render(request,'routes_synced.html',{'message':message}) 
    except Exception as e:
        message = ('Ha ocurrido un error intentando crear la copia de seguridad. %s'%e)
        send_message(message)
        return render(request,'routes_synced.html',{'message':message})

@verified_email_required
@login_required
def restore_backup(request):
    if request.method=='GET':
        CHOICES_FILES = []
        for f in os.listdir(settings.BACK_UP_DIR):
            CHOICES_FILES.append(f)
        return render(request,'backup_menu.html',{'files':CHOICES_FILES})    
    if request.method=='POST':
        filename = request.POST.get("value", "")
        try:
            call_command(f"dbrestore", interactive=False, input_filename=filename)
            message = 'La copia de seguridad ha sido restaurada con éxito, recomendamos en caso de caida también sincronizar su router con la base de datos.'
            send_message(message)
            return render(request,'routes_synced.html',{'message':message}) 
        except Exception as e:
            message = ('Ha ocurrido un error y no se ha podido restaurar la base de datos. Error:  ',e)
            send_message(message)
            return render(request,'routes_synced.html',{'message':message})



def restore_last_backup():
    CHOICES_FILES = []
    for f in os.listdir(settings.BACK_UP_DIR):
        CHOICES_FILES.append(f)
    try:
        call_command(f"dbrestore", interactive=False, input_filename=CHOICES_FILES[0])
        message = 'La copia de seguridad ha sido restaurada con éxito.'
        send_message(message)
    except Exception as e:
        message = ('Ha ocurrido un error y no se ha podido restaurar la base de datos. Error: ',e)
        send_message(message)


##================= Webhook GENI

class ProcessWebHookView(CsrfExemptMixin, View):
    def post(self, request, *args, **kwargs):
        message = json.loads(request.body)
        id_event = message['event']['id']
        anomaly_ticket, anomaly_info = petition_geni(id_event)
        print('entra en el process view')
        #post.apply_async(args=[anomaly_ticket, anomaly_info, id_event], kwargs={'kwarg1':'anomaly_ticket','kwarg2':'anomaly_info','kwarg3':'id_event'})
        post(request,anomaly_ticket, anomaly_info, id_event) 
        return HttpResponse()
        


