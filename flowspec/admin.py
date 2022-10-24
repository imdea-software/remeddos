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

from django.contrib import admin
from flowspec.models import MatchPort, MatchDscp, MatchProtocol, FragmentType, ThenAction, Route
from accounts.models import UserProfile
from utils import proxy as PR
from flowspec.tasks import *
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from peers.models import *
from flowspec.forms import *
from longerusername.forms import UserCreationForm, UserChangeForm

import json
import jsonpickle
from json import JSONEncoder



class RouteAdmin(admin.ModelAdmin):
    form = RouteForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]

""" class RouteIMDEAAdmin(admin.ModelAdmin):
    form = Route_IMDEAForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]

class RouteCVAdmin(admin.ModelAdmin):
    form = Route_CVForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteCIBAdmin(admin.ModelAdmin):
    form = Route_CIBForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteCSICAdmin(admin.ModelAdmin):
    form = Route_CSICForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteCEUAdmin(admin.ModelAdmin):
    form = Route_CEUForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class Route_CEUAdmin(admin.ModelAdmin):
    form = Route_CEUForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]

class RouteCUNEFAdmin(admin.ModelAdmin):
    form = Route_CUNEFForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]

class RouteIMDEANETAdmin(admin.ModelAdmin):
    form = Route_IMDEANETForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]

class RouteUAMAdmin(admin.ModelAdmin):
    form = Route_UAMForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteUAHAdmin(admin.ModelAdmin):
    form = Route_UAHForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteUC3MAdmin(admin.ModelAdmin):
    form = Route_UC3MForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteUCMAdmin(admin.ModelAdmin):
    form = Route_UCMForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteUEMAdmin(admin.ModelAdmin):
    form = Route_UEMForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]

class RouteUNEDAdmin(admin.ModelAdmin):
    form = Route_UNEDForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteUPMAdmin(admin.ModelAdmin):
    form = Route_UPMForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
class RouteURJCAdmin(admin.ModelAdmin):
    form = Route_URJCForm
    actions = ['deactivate','delete']
    search_fields = ['destination', 'name', 'applier__username']

    def deactivate(self, request, queryset):
        #the following line is commented because so far no succesful rule has been created
        #therefore there are no rules with status = ACTIVE 
        queryset = queryset.filter(status='ACTIVE')
        response = batch_delete(queryset, reason="ADMININACTIVE")
        self.message_user(request, "Added request %s to job que. Check in a while for result" % response)
    deactivate.short_description = "Remove selected routes from network"

    def delete(self, request, queryset):
        queryset.delete()
    delete.short_description = "Exterminate selected routes from network"
    
    def save_model(self, request, obj, form, change):
        obj.status = "PENDING"
        obj.save()
        if change:
            obj.commit_edit()
        else:
            obj.commit_add()

    def has_delete_permission(self, request, obj=None):
        return False

    list_display = ('name', 'status', 'applier_username', 'applier_peers', 'get_match', 'get_then', 'response', "expires", "comments",'filed')

    fieldsets = [
        (None, {'fields': ['name', 'applier']}),
        ("Match", {'fields': ['source', 'sourceport', 'destination', 'destinationport', 'port']}),
        ('Advanced Match Statements', {'fields': ['dscp','icmpcode', 'icmptype', 'packetlength', 'protocol', 'tcpflag'], 'classes': ['collapse']}),
        ("Then", {'fields': ['then']}),
        ("Expires", {'fields': ['expires']}),
        (None, {'fields': ['comments', ]}),

    ]
 """
class UserProfileInline(admin.StackedInline):
    model = UserProfile


class UserProfileAdmin(UserAdmin):
    search_fields = ['username']
    add_form = UserCreationForm
    form = UserChangeForm
    actions = ['deactivate', 'activate']
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active', 'is_superuser', 'get_userprofile_peers')
    inlines = [UserProfileInline]

    def deactivate(self, request, queryset):
        queryset = queryset.update(is_active=False)
    deactivate.short_description = "Deactivate Selected Users"

    

    def activate(self, request, queryset):
        queryset = queryset.update(is_active=True)
    activate.short_description = "Activate Selected Users"

    def get_userprofile_peers(self, instance):
        # instance is User instance
        peers = instance.profile.peers.all()
        return ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]

    get_userprofile_peers.short_description = "User Peer(s)"
#    fields = ('name', 'applier', 'expires')
 
    #def formfield_for_dbfield(self, db_field, **kwargs):
    #    if db_field.name == 'password':
    #        kwargs['widget'] = PasswordInput
    #    return db_field.formfield(**kwargs)

class GeniEventsAdmin(admin.ModelAdmin):
    actions = ['deactivate','delete']
    search_fields = ['event', 'recieved_at']


class WebhookMessageAdmin(admin.ModelAdmin):
    actions = ['deactivate','delete']
    search_fields = ['message', 'recieved_at']
    

admin.site.unregister(User)
admin.site.register(MatchPort)
admin.site.register(MatchProtocol)
admin.site.register(MatchDscp)
admin.site.register(ThenAction)
# admin.site.register(Route, RouteAdmin)

admin.site.register(User, UserProfileAdmin)
admin.site.disable_action('delete_selected')


admin.site.register(Route_IMDEA)
admin.site.register(Route_Punch)
""" admin.site.register(Route_CV,RouteCVAdmin)
admin.site.register(Route_CIB, RouteCIBAdmin)
admin.site.register(Route_CSIC,RouteCSICAdmin)
admin.site.register(Route_CEU,RouteCEUAdmin)
admin.site.register(Route_CUNEF,RouteCUNEFAdmin)
admin.site.register(Route_IMDEANET,RouteIMDEANETAdmin)
admin.site.register(Route_UAM, RouteUAMAdmin)
admin.site.register(Route_UAH,RouteUAHAdmin)
admin.site.register(Route_UC3M,RouteUC3MAdmin)
admin.site.register(Route_UCM,RouteUCMAdmin)
admin.site.register(Route_UEM,RouteUEMAdmin)
admin.site.register(Route_UNED,RouteUNEDAdmin)
admin.site.register(Route_UPM,RouteUPMAdmin)
admin.site.register(Route_URJC,RouteURJCAdmin) """
