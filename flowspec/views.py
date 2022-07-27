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
from tkinter import N
from django import forms
from django.contrib.auth.decorators import login_required
from allauth.account.decorators import verified_email_required
from django.contrib.auth import logout
from django.contrib.sites.models import Site
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
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
from flowspec.tasks import *
from flowspec.helpers import *

#from registration.models import RegistrationProfile 

from copy import deepcopy

from django.views.decorators.cache import never_cache
from django.conf import settings
from django.template.defaultfilters import slugify
from django.core.exceptions import PermissionDenied
from flowspec.helpers import *
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

@login_required
def user_routes(request):
    #user_routes = Route.objects.filter(applier=request.user)
    user = request.user
    routes = find_routes(user.username)
    user_routes = []
    for route in routes:
        if route.applier != None:
            user_routes.append(route)
    return render(request,'user_routes.html',{'routes': user_routes})


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
    user = request.user
    all_group_routes = []
    message = ''
    try:
        peers = request.user.profile.peers.prefetch_related('user_profile')
        route_name = Route.objects.filter(applier=request.user).values_list('name',flat=True)
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(request,'error.html',{'error': error})
    if peers:
        if request.user.is_superuser:
            all_group_routes = find_all_routes()
            if all_group_routes != None:
                all_routes = []
                for groute in all_group_routes:
                    for group_route in groute:
                        if group_route.status=='ACTIVE': 
                            group_route.has_expired()
                            all_routes.append(group_route)
                return render(request,'dashboard.html',{'routes': all_routes,'messages': message,'file' : '','route_slug':route_name},)
            else:
                message = 'You have not added any rules yet'
                return render(request,'dashboard.html',{'routes': all_group_routes.prefetch_related('applier', 'applier','protocol','dscp'),'messages': message,'file' : '','route_slug':route_name})

        else:
            all_group_routes = find_routes(user.username)
            routes = []
            if all_group_routes != None:
                #for groute in all_group_routes:
                for group_route in all_group_routes:
                    if group_route.status=='ACTIVE':
                        group_route.has_expired()
                        routes.append(group_route)
                return render(request,'dashboard.html',{'routes': routes,'messages': message,'file' : '','route_slug':route_name})
            else:
                message = 'You have not added any rules yet'
                return render(request,'dashboard.html',{'routes': all_group_routes.prefetch_related('applier', 'applier','protocol','dscp'),'messages': message,'file' : '','route_slug':route_name})
    else:
        message = 'You are not associated with a peer.'
        return render(request,'dashboard.html',{'messages': message})
    


@login_required
@never_cache
def group_routes(request):
    user = request.user
    if user.is_superuser:
        try:
            routes = find_all_routes()
        except UserProfile.DoesNotExist:
            error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
            return render(request,'error.html',{'error': error})
        context = {'route_slug' : routes,'file'  : ''}
        return render(request,'user_routes.html',context)
    else:
        try:
            routes = find_routes(user.username)
        except UserProfile.DoesNotExist:
            error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
            return render(request,'error.html',{'error': error})
        context = {'route_slug' : routes,'file'  : ''}
        return render(request,'user_routes.html',context)


@verified_email_required
@login_required
@never_cache
def group_routes_ajax(request):
    all_group_routes = []
    applier = request.user
    user = User.objects.get(username=applier)
    try:
        if request.user.is_superuser:
            all_group_routes = find_all_routes()
        else:
            all_group_routes = find_routes(user.username)
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(request,'error.html',{'error': error})
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
    group_routes = []
    if is_superuser:
        for routes in groutes:
            for r in routes.prefetch_related('applier','protocol','dscp'):
                if (r.applier == None and r.status=='ACTIVE') or (r.applier == None and r.status=='ERROR') or r.applier!=None:
                    rd = {}
                    rd['id'] = r.pk
                    rd['filed'] = r.filed
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
                    try:
                        userinfo = r.applier_username_nice
                        rd['applier'] = userinfo
                    except:
                        rd['applier'] = 'unknown'
                        rd['peer'] = ''
                    else:
                        try:
                            if not r.applier == None:
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
                            else:
                                logger.info(f"The route {r} does not have an applier.")    
                        except Exception as e:
                            logger.info('There has been an exception when building the routes json: ', e)

                    rd['expires'] = "%s" % r.expires
                    rd['response'] = "%s" % r.response
                    group_routes.append(rd)
    else: 
        for r in groutes.prefetch_related('applier','protocol','dscp'):
                if (r.applier == None and r.status=='ACTIVE') or (r.applier == None and r.status=='ERROR') or r.applier!=None: 
                    rd = {}
                    rd['id'] = r.pk
                    rd['port'] = r.port
                    rd['filed'] = r.filed
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
                    try:
                        userinfo = r.applier_username_nice
                        rd['applier'] = userinfo
                    except:
                        rd['applier'] = 'unknown'
                        rd['peer'] = ''
                    else:
                        try:
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
                        except Exception as e:
                            logger.info('There has been an exception when building the routes json: ', e)
                    rd['expires'] = "%s" % r.expires
                    rd['response'] = "%s" % r.response
                    group_routes.append(rd)
    return group_routes

@verified_email_required
@login_required
def verify_add_user(request):
    if 'token' in request.COOKIES != None:
        url = reverse('add')
        response = HttpResponseRedirect(url)
        return response 
    else:
        if request.is_ajax and request.method == "GET":
            if not 'token' in request.COOKIES:
                num = get_code()
                user = request.user
                peer = get_peers(request.user.username)
                msg = "El usuario {user} ha solicitado un codigo de seguridad para añadir una nueva regla. Código: '{code}'.".format(user=user,code=num)
                code = Validation(value=num,user=request.user)
                code.save()
                if request.user.is_superuser:
                    send_message(msg,peer,superuser=True)
                else:
                    send_message(msg,peer,superuser=False)
                response = JsonResponse({"valid":True}, status = 200)
                try:
                    response.set_cookie('token',value=num,max_age=900) 
                except Exception as e:
                    logger.info('There was an exception when trying to assign the token, ',e)
                return response      
        if request.method=='POST':
            form = ValidationForm(request.POST)
            if form.is_valid():
                code = form.cleaned_data.get('value')
                value = Validation.objects.latest('id')
                try:
                    if str(value) == str(code):
                        url = reverse('add')
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


@verified_email_required
@login_required
@never_cache
def add_route(request):
    applier_peer_networks = []
    applier = request.user.pk
    user = request.user.username
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
        form = find_get_form(user)
        form.applier = applier
        form.fields['destinationport'].required=False
        form.fields['sourceport'].required=False
        form.fields['port'].required=False
        form.fields['expires'].required=False
        if request.user.is_superuser:
            peer = Peer.objects.filter(pk__in=user_peers)
            network = []
            for p in peer:
                network.append(p.networks.all())
        else:
            peer = Peer.objects.get(pk__in=user_peers)
            network = peer.networks.all()

        if not request.user.is_superuser:
            form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
            form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
        return render(request,'apply.html',{'form': form,'applier': applier,'maxexpires': settings.MAX_RULE_EXPIRE_DAYS,'peers':network})
    else:
        request_data = request.POST.copy()
        if request.user.is_superuser:
            request_data['issuperuser'] = request.user.username
        else:
            request_data['applier'] = applier
            try:
                del request_data['issuperuser']
            except:
                pass
        form = find_post_form(user, request_data)
       # form = RouteForm(request_data)
        if form.is_valid():
            route = form.save(commit=False)
            if not request.user.is_superuser:
                route.applier = request.user
            #route.status= "PENDING"
            if not request.user.is_superuser:
                peer = Peer.objects.get(pk__in=user_peers)
                route.peer = peer
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
    if 'token' in request.COOKIES != None:
        url = reverse('edit', kwargs={'route_slug':route_slug})
        response = HttpResponseRedirect(url)
        return response     
    if (request.method =='GET') and (not 'token' in request.COOKIES): 
        num = get_code()
        user= request.user.username
        peer = get_peers(user)
        route = get_specific_route(applier=user,peer=None, route_slug=route_slug)
        msg = "El usuario {user} ha solicitado el siguiente código para editar la regla: {route_slug}. Código:  '{code}'.".format(user=user,code=num,route_slug=route_slug)
        code = Validation(value=num,user=request.user)
        code.save()
        if request.user.is_superuser:
            send_message(msg,peer,superuser=True)
        else:
            send_message(msg,peer,superuser=False)
        form = ValidationForm(request.GET)
        message = ""
        response = render(request,'values/add_value.html', {'form': form, 'message':message,'status':'edit', 'route':route})
        try:
            response.set_cookie('token',value=num,max_age=900) 
        except Exception as e:
            logger.info('There was an exception when trying to assign the token, ',e)
        return response
            
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
    username = request.user.username
    route_edit = get_specific_route(applier=request.user.username, peer=None, route_slug=route_slug)
    applier_peer_networks = []
    if request.user.is_superuser:
        applier_peer_networks = PeerRange.objects.all()
    else:
        user_peers = request.user.profile.peers.all()
        for peer in user_peers:
            applier_peer_networks.extend(peer.networks.all())
    if not applier_peer_networks:
        messages.add_message(request,messages.WARNING,('Insufficient rights on administrative networks. Cannot add rule. Contact your administrator') )
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
        form = find_edit_post_route(username, request_data, route_edit)
        critical_changed_values = ['source', 'destination', 'sourceport', 'destinationport', 'port', 'protocol', 'then', 'packetlenght','tcpflags']
        try:
            if form.is_valid():            
                changed_data = form.changed_data
                route = form.save(commit=False)
                route.name = route_original.name
                route.status= route_original.status
                route.response = route_original.response
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
        except Exception as e:
            logger.info('There has been an exception when trying to add a route: ', e)
            return HttpResponseRedirect(reverse("group-routes"))
        else:
            routename = route_edit.name  
            if not request.user.is_superuser:
                form.fields['destinationport'].required=False
                form.fields['sourceport'].required=False
                form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
                form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)
            return render(request,'apply.html',{'form': form,'edit': True,'applier': applier,'routename':routename, 'maxexpires': settings.MAX_RULE_EXPIRE_DAYS})
    else:
        routename = route_edit.name
        if (not route_original.status== 'ACTIVE'):
            route_edit.expires = datetime.date.today() + datetime.timedelta(days=settings.EXPIRATION_DAYS_OFFSET-1)
        #dictionary = model_to_dict(route_edit, fields=[], exclude=[])
        form  = get_instance_form(username, route_edit)
        form.fields['name'].required=False
        form.fields['destinationport'].required=False
        form.fields['sourceport'].required=False
        if not request.user.is_superuser:
            form.fields['then'] = forms.ModelMultipleChoiceField(queryset=ThenAction.objects.filter(action__in=settings.UI_USER_THEN_ACTIONS).order_by('action'), required=True)
            form.fields['protocol'] = forms.ModelMultipleChoiceField(queryset=MatchProtocol.objects.filter(protocol__in=settings.UI_USER_PROTOCOLS).order_by('protocol'), required=False)      
        return render(request,'apply.html', {'form': form,'edit': True,'applier': applier,'routename':routename,'maxexpires': settings.MAX_RULE_EXPIRE_DAYS})


@verified_email_required
@login_required
@never_cache
def verify_delete_user(request, route_slug):
    print('dis method? ')
    if not 'token' in request.COOKIES != None:
        if request.method =='GET':
            num = get_code()
            user = request.user
            username = request.user.username
            peer = get_peers(username)
            msg = "El usuario: {user} ha solicitado un código para poder eliminar una regla. Código: '{code}'.".format(user=user,code=num)
            code = Validation(value=num,user=request.user)
            code.save()
            if request.user.is_superuser:
                send_message(msg,peer,superuser=True)
            else:
                send_message(msg,peer,superuser=False)
            form = ValidationForm(request.GET)
            route = get_specific_route(applier=username,peer=None,route_slug=route_slug)
            message = f"CUIDADO. Seguro que quiere eliminar la siguiente regla {route_slug}?"
            response = render(request,'values/add_value.html', {'form': form, 'message':message,'status':'delete', 'route':route}) 
            try:
                response.set_cookie('token',value=num,max_age=900) 
            except Exception as e:
                logger.info('There was an exception when trying to assign the token, ',e)
            return response
                
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
    else:
        url = reverse('delete', kwargs={'route_slug': route_slug})
        response = HttpResponseRedirect(url)
        return response 


@verified_email_required
@login_required
@never_cache
def delete_route(request, route_slug):
    print('or dis method? ')
    uname = request.user.username
    route = get_object_or_404(get_edit_route(uname, rname=route_slug), name=route_slug)

    peers = get_peer_with_name(route_slug)
    peer = Peer.objects.get(peer_tag=peers)
    username = None
    for network in peer.networks.all():
        net = IPNetwork(network)
        if IPNetwork(route.destination) in net:
            username = peer
            break
    applier_peer = username
    username = None
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
def exterminate_route(request,route_slug):
    from flowspec.helpers import get_peer_with_name

    peertag = get_peer_with_name(route_slug)
    try:
        route = get_specific_route(applier=None,peer=peertag,route_slug=route_slug)
        print('this is rooute: ', route)
        route.delete()
        return HttpResponseRedirect(reverse("group-routes"))
    except Exception as e:
        logger.info(f"There was an exception when trying to exterminate a route from the DB. Exception: {e}")
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


@verified_email_required
@login_required
@never_cache
def routes_update(request, route_slug):
#    route = Route.objects.get(name=route_slug)
    route = get_specific_route(applier=request.user.username,peer=None,route_slug=route_slug)
    updates = route.check_history_changes()
    return render(request,'route_updates.html',{'route':route,'updates':updates})


# show the details of specific route
@login_required
@never_cache
def routedetails(request, route_slug):
    """ uname = request.user.username
    route = get_specific_route(applier=uname,peer=None,route_slug=route_slug)
    now = datetime.datetime.now()
    return render(request, 'flowspy/route_details.html', {'route': route,'mytime': now,'tz' : settings.TIME_ZONE,'is_superuser' : request.user.is_superuser,'route_comments_len' : len(str(route.comments))}) """
    uname = request.user.username
    
    try:
        route = get_object_or_404(get_edit_route(uname, rname=route_slug), name=route_slug)
        return render(request,'graphs.html',{'route':route})
    except Exception as e:
        logger.info('There was an exception when trying to display the graph. Error: ', e)
        return HttpResponseRedirect(reverse('dashboard'))

@login_required
def routestats(request, route_slug):
    uname = request.user.username
    route = get_object_or_404(get_edit_route(uname, rname=route_slug), name=route_slug)
    #route = get_object_or_404(Route, name=route_slug)
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


@verified_email_required
@login_required
@never_cache
def ajax_graphs(request):
    username = request.user.username
    if request.method == 'GET':
        routename = request.GET.get('routename')
        beats_date, beats_hour, beats_value, beats_values, bfulltime = get_default_graph(routename, username)
        data = {
                'beats_date':beats_date,
                'beats_hour': beats_hour,
                'beats' : beats_value,
                'time' : bfulltime,
            }
        return JsonResponse(data,status=200)
    if request.method == "POST":
        from_time = request.POST.get('from')
        till_time = request.POST.get('till')
        routename = request.POST.get('routename')
        if from_time and till_time:
            beats_date, beats_hour, beats_value, beats_values, bfulltime = graphs(from_time, till_time, routename, username)
            data = {
                'beats_date':beats_date,
                'beats_hour': beats_hour,
                'beats' : beats_value,
                'time' : bfulltime,
            }
            return JsonResponse(data,status=200)
        else:
            beats_date, beats_hour, beats_value, beats_values, bfulltime = get_default_graph(routename, username)
            data = {
                'beats_date':beats_date,
                'beats_hour': beats_hour,
                'beats' : beats_value,
                'time' : bfulltime,
            }
            return JsonResponse(data,status=200)



@verified_email_required
@login_required
@never_cache
def display_graphs(request,route_slug):
    uname = request.user.username
    route = get_object_or_404(get_edit_route(uname, rname=route_slug), name=route_slug)
    return render(request,'graphs.html',{'route':route})
    """ try:
        route = get_object_or_404(get_edit_route(uname, rname=route_slug), name=route_slug)
        return render(request,'graphs.html',{'route':route})
    except Exception as e:
        logger.info('There was an exception when trying to display the graph. Error: ', e)
        return HttpResponseRedirect(reverse('dashboard')) """
    
    

""" PENDING ROUTES """
@verified_email_required
@login_required
@never_cache
def pending_routes(request):
    try:
        user = request.user
        routes = find_routes(user.username)
    except UserProfile.DoesNotExist:
        error = "User <strong>%s</strong> does not belong to any peer or organization. It is not possible to create new firewall rules.<br>Please contact Helpdesk to resolve this issue" % request.user.username
        return render(request,'error.html',{'error': error})
    all_routes = []
    for r in routes:
        if r.applier == None:
            all_routes.append(r)    
    return render(request,'pending_routes.html',{'routes':all_routes})




#synchronize routes from the router to the database 
def sync_router(request):
    # find what peer organisation does the user belong to
    peers = Peer.objects.all()
    # first initialize all the needed vars    
    applier = User.objects.get(pk=request.user.pk)
    routes = get_routes_router()
    fw_rules = []
    message = ''
    # for getting the route parameters is needed to run through the xml 
    for children in routes:
        then = '' ; then_action = '' ; protocol = [] ; destination = [] ; source = '' ; src_port =  '' ; dest_port = '' ; tcpflags = '' ; icmpcode = ''; icmptype = ''; packetlength = ''; prot = '';  name_fw = ''
        for child in children:
            if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                name_fw = child.text
                peer = get_peer_with_name(name_fw)
                if peers.filter(peer_name__icontains = peer):
                    #name_peer = child.text
                    fw_rules.append(child.text)                              
            # if the user peer organisation is found on the router the program will collect all the vars info
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
                try:
                    #route = get_route(username)
                    route = get_specific_route(applier=None, peer=None, route_slug = name_fw)
                    route.name = name_fw
                    route.applier = applier
                    route.source = source
                    route.sourceport = src_port
                    route.destination = destination
                    route.destinationport = dest_port
                    route.icmpcode = icmpcode
                    route.icmptype = icmptype
                    route.packetlength = packetlength
                    route.tcpflag = tcpflags
                    route.status = 'ACTIVE'
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
                    print('Todas las reglas ya han sido sincronizadas con la base de datos.') 
                        # check if the route is already in our DB
                except Exception as e:                    
                    #message = 'Routes have already been syncronised.'
                    logger.info(f'Regla: {name_fw} ya ha está sincronizada con la base de datos.')
            else:
                # means that the route does not belong to the user's peer
                pass 
    return render(request,'routes_synced.html',{'message':message})

@verified_email_required
@login_required
@never_cache 
#synchronize routes from the database to the router
def routes_sync(request):
    routes = find_all_routes()
    router = get_routes_router()
    router_routes = []
    peers = Peer.objects.all()
    for children in router:
        for child in children:
            if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
                #if child.text.endswith('_%s'%peer):
                router_routes.append(child.text)  
    routes_db = []
    for x in routes:
        for route in x:
            if route.status == 'ACTIVE':
                routes_db.append(route.name)
    message = ''
    if router_routes:
        diff = (set(routes_db).difference(router_routes))
        notsynced_routes = list(diff)
        if notsynced_routes:
            for notsynced_route in notsynced_routes:
                route = get_specific_route(applier=None, peer=None,route_slug=notsynced_route)
                try:
                    if (route.has_expired()==False) and (route.status=='ACTIVE'):
                        add(route)
                        message = ('Estado: %s, regla de firewall no sincronizada: %s, guardando regla de firewall.' %(route.status, route.name))
                        send_message(message,peer=None,superuser=True)
                    else:
                        if (route.has_expired()==True) or (route.status== 'EXPIRED' and route.status!= 'ADMININACTIVE' and route.status!= 'INACTIVE'): 
                            logger.info('Estado: %s, regla de firewall  %s, comprobando regla.' %(route.status, route.name))
                            route.check_sync()
                except Exception as e:
                    logger.info(f"Ha ocurrido una excepción cuando se intentaban sincronizar las reglas: ", e)
            message = 'Reglas sincronizadas.'
            send_message(message,peer=None,superuser=True)
        else:
            print('there are not syncroutes: ',diff, notsynced_routes)
    else:
        if router_routes == [] and routes_db:
            for route_db in routes_db:
                route = get_specific_route(applier=None, peer=None,route_slug=route_db)
                add(route)
                message = ('Estado: %s, regla de firewall no sincronizada: %s, guardando regla de firewall.' %(route.status, route.name))
                send_message(message,peer=None,superuser=True)
    return HttpResponseRedirect(reverse('group-routes'))

@verified_email_required
@login_required
@never_cache 
def backup(request):
    daily_backup()
    message = 'Copia de seguridad creada con éxito.'
    send_message(message,peer=None,superuser=True)
    return render(request,'routes_synced.html',{'message':message})

@verified_email_required
@login_required
def restore_backup(request):
    user = request.user
    
    if request.user.is_superuser:
        backup_dir = (settings.BACK_UP_DIR+'REM_REMEDIOS'+'/')
        if request.method=='GET':
            CHOICES_FILES = []
            for f in os.listdir(backup_dir):
                CHOICES_FILES.append(f)
            return render(request,'backup_menu.html',{'files':CHOICES_FILES})    
        if request.method=='POST':
            filename = request.POST.get("value", "")
            fixture_path = (backup_dir+filename)
            try:
                call_command(f"loaddata",fixture_path)
                message = 'La copia de seguridad ha sido restaurada con éxito, recomendamos en caso de caida también sincronizar su router con la base de datos.'
                send_message(message,peer_tag,superuser=True)
                return render(request,'routes_synced.html',{'message':message}) 
            except Exception as e:
                return render(request,'routes_synced.html')
    else:
        peer_tag = get_peer_tag(user.username)
        backup_dir = (settings.BACK_UP_DIR+peer_tag+'/')
        if request.method=='GET':
            CHOICES_FILES = []
            for f in os.listdir(backup_dir):
                CHOICES_FILES.append(f)
            return render(request,'backup_menu.html',{'files':CHOICES_FILES})    
        if request.method=='POST':
            filename = request.POST.get("value", "")
            fixture_path = (backup_dir+filename)
            try:
                call_command(f"loaddata",fixture_path)
                message = 'La copia de seguridad ha sido restaurada con éxito, recomendamos en caso de caida también sincronizar su router con la base de datos.'
                send_message(message,peer_tag,superuser=True)
                return render(request,'routes_synced.html',{'message':message}) 
            except Exception as e:
                return render(request,'routes_synced.html')



@verified_email_required
@login_required
@never_cache 
def create_db_backup(request):
    now = datetime.datetime.now()
    user = request.user
    current_time = now.strftime("%H:%M")
    current_date = now.strftime("%d-%B-%Y")
    if user.is_superuser: 
        try:
            call_command('dumpdata', format='json',output=f'_backup/FOD/FOD_backup_{current_date}_{current_time}.json')
            #call_command('dbbackup', output_filename=(f"redifod-{current_date}-{current_time}.psql"))
            message = 'Copia de seguridad creada con éxito.'
            send_message(message)
            return render(request,'routes_synced.html',{'message':message}) 
        except Exception as e:
            message = ('Ha ocurrido un error intentando crear la copia de seguridad. %s'%e)
            send_message(message)
            return render(request,'routes_synced.html',{'message':message})
    else:
        return render(request,'routes_synced.html',{'message':'Esta opción solo puede ser usada por un superusuario, disculpe las molestias.'})


@verified_email_required
@login_required
@never_cache 
def restore_complete_db(request):
    user = request.user
    if user.is_superuser:
        CHOICES_FILES = []
        if request.method=='GET':
            for f in os.listdir(settings.BACK_UP_DIR+'/FOD/'):
                CHOICES_FILES.append(f)
            return render(request,'backup_menu.html',{'files':CHOICES_FILES[-1]})    
    if request.method=='POST':
        filename = request.POST.get("value", "")
        fixture_path = (settings.BACK_UP_DIR+'/FOD/'+filename)
        try:
            call_command(f"loaddata",fixture_path)
            message = 'La copia de seguridad ha sido restaurada con éxito.'
            send_message(message,peer=None,superuser=None)
            return render(request,'routes_synced.html',{'message':message}) 
        except Exception as e:
            message = ('Ha ocurrido un error y no se ha podido restaurar la base de datos. Error:  ',e)
            send_message(message,peer=None,superuser=None)
            return render(request,'routes_synced.html')
    else:
        return render(request,'routes_synced.html',{'message':'Esta opción solo puede ser usada por un superusuario, disculpe las molestias.'})



"""  
            celery -A flowspy worker -l INFO --logfile=/var/log/fod/celery_jobs.log --concurrency=10 -n worker1@%h 
            celery -A flowspy worker --loglevel=INFO --logfile=/var/log/fod/celery_jobs.log  --concurrency=10 -n worker2@%h 
            celery -A flowspy worker --loglevel=INFO --logfile=/var/log/fod/celery_jobs.log  --concurrency=10 -n worker3@%h" """


