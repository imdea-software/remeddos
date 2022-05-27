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


from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.sites.models import Site
from django.utils.translation import ugettext_lazy as _
from django.shortcuts import render
from django.template.loader import render_to_string
from django.urls import reverse
import json
from django.core import serializers

from flowspec.helpers import *
from utils import proxy as PR
from ipaddr import *
import datetime
import logging
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.exceptions import ObjectDoesNotExist
from simple_history.models import HistoricalRecords

from flowspec.junos import create_junos_name


from utils.randomizer import id_generator as id_gen

import flowspec.tasks
from flowspec.tasks import *

import json
from json import JSONEncoder

from django.contrib.postgres.fields import HStoreField
from django.db.models.signals import post_save, post_delete


FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


FRAGMENT_CODES = (
    ("dont-fragment", "Don't fragment"),
    ("first-fragment", "First fragment"),
    ("is-fragment", "Is fragment"),
    ("last-fragment", "Last fragment"),
    ("not-a-fragment", "Not a fragment")
)

THEN_CHOICES = (
    ("accept", "Accept"),
    ("discard", "Discard"),
    ("community", "Community"),
    ("next-term", "Next term"),
    ("routing-instance", "Routing Instance"),
    ("rate-limit", "Rate limit"),
    ("sample", "Sample")
)

MATCH_PROTOCOL = (
    ("ah", "ah"),
    ("egp", "egp"),
    ("esp", "esp"),
    ("gre", "gre"),
    ("icmp", "icmp"),
    ("icmp6", "icmp6"),
    ("igmp", "igmp"),
    ("ipip", "ipip"),
    ("ospf", "ospf"),
    ("pim", "pim"),
    ("rsvp", "rsvp"),
    ("sctp", "sctp"),
    ("tcp", "tcp"),
    ("udp", "udp"),
)

ROUTE_STATES = (
        ("ACTIVE", "ACTIVE"),
        ("ERROR", "ERROR"),
        ("EXPIRED", "EXPIRED"),
        ("PENDING", "PENDING"),
        ("OUTOFSYNC", "OUTOFSYNC"),
        ("INACTIVE", "INACTIVE"),
        ("ADMININACTIVE", "ADMININACTIVE"),
    ) 

TCP_CHOICES =(
    ("ack","ACK"),
    ("rst","RST"),
    ("fin","FIN"),
    ("push","PUSH"),
    ("urgent","URGENT"),
    ("syn","SYN"),
)


def days_offset(): return datetime.date.today() + datetime.timedelta(days = settings.EXPIRATION_DAYS_OFFSET-1)

class MatchPort(models.Model):
    port = models.CharField(max_length=24, unique=True, blank=True, null=True)
    def __str__(self):
        return self.port
    class Meta:
        db_table = u'match_port'

class MatchDscp(models.Model):
    dscp = models.CharField(max_length=24)
    def __str__(self):
        return self.dscp
    class Meta:
        db_table = u'match_dscp'

class MatchProtocol(models.Model):
    protocol = models.CharField(max_length=24, unique=True)
    def __str__(self):
        return self.protocol
    class Meta:
        db_table = u'match_protocol'

class FragmentType(models.Model):
    fragmenttype = models.CharField(max_length=20, choices=FRAGMENT_CODES, verbose_name="Fragment Type")

    def __str__(self):
        return "%s" %(self.fragmenttype)


class ThenAction(models.Model):
    action = models.CharField(max_length=60, choices=THEN_CHOICES, verbose_name="Action")
    action_value = models.CharField(max_length=255, blank=True, null=True, verbose_name="Action Value")

    def __str__(self):
        ret = "%s"%(self.action) if self.action_value==None else "%s:%s" %(self.action, self.action_value)
        return ret

    class Meta:
        db_table = u'then_action'
        ordering = ['action', 'action_value']
        unique_together = ("action", "action_value")

class Validation(models.Model):
    value = models.CharField(max_length=10, blank=False, null=False)
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    created_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.value
    
    def is_outdated(self):
        today = datetime.date.today()
        if today > self.created_date:
            logger.info(f'Deleting verification code {self}')
            self.delete()
         

#================================= Route Casa Velázquez
class Route_CV(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_cv'
        verbose_name = "Rule CV"
        verbose_name_plural = "Rules CV"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_CV, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_CV, self).save(*args, **kwargs)

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_CV.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        if not settings.DISABLE_EMAIL_NOTIFICATION:
            fqdn = Site.objects.get_current().domain
            admin_url = 'https://%s%s' % (
                fqdn,
                reverse('edit-route', kwargs={'route_slug': self.name})
            )
            mail_body = render_to_string(
                'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
            try:
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
            except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
                
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        if not settings.DISABLE_EMAIL_NOTIFICATION:
            fqdn=Site.objects.get_current().domain
            admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
            mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
            try: 
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
            except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        if not settings.DISABLE_EMAIL_NOTIFICATION:
            fqdn = Site.objects.get_current().domain
            admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
            )
            mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
            try:
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
            except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#======================= ROUTES IMDEA
class Route_IMDEA(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_imdea'
        verbose_name = "Rule IMDEA"
        verbose_name_plural = "Rules IMDEA"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_IMDEA, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_IMDEA, self).save(*args, **kwargs) 

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_IMDEA.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})

#============================================
#==================================== Route CIB
class Route_CIB(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"),unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_cib'
        verbose_name = "Rule CIB"
        verbose_name_plural = "Rules CIB"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_CIB, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_CIB, self).save(*args, **kwargs) 

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_CIB.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)

    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route CSIC
class Route_CSIC(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"),unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_csic'
        verbose_name = "Rule CSIC"
        verbose_name_plural = "Rules CSIC"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_CSIC, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_CSIC, self).save(*args, **kwargs)

    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_CSIC.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)

    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#============================================================================
#==================================== Route CSIC
class Route_CEU(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"),unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_ceu'
        verbose_name = "Rule CEU"
        verbose_name_plural = "Rules CEU"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_CEU, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_CEU, self).save(*args, **kwargs)

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_CEU.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        if not settings.DISABLE_EMAIL_NOTIFICATION:
            fqdn = Site.objects.get_current().domain
            admin_url = 'https://%s%s' % (
                fqdn,
                reverse('edit-route', kwargs={'route_slug': self.name})
            )
            mail_body = render_to_string(
                'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
            try:
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
            except Exception as e:
                print('There was an error when trying to send the email confirmation.')

                
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route CUNEF
class Route_CUNEF(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_cunef'
        verbose_name = "Rule CUNEF"
        verbose_name_plural = "Rules CUNEF"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_CUNEF, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_CUNEF, self).save(*args, **kwargs)

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_CUNEF.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route IMDEA NETWORKS
class Route_IMDEANET(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_imdeanet'
        verbose_name = "Rule IMDEANET"
        verbose_name_plural = "Rules IMDEANET"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_IMDEANET, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_IMDEANET, self).save(*args, **kwargs)

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_IMDEANET.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route
class Route(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route'
        verbose_name = "Rule"
        verbose_name_plural = "Rules"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route, self).save(*args, **kwargs) 

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route UAM 
class Route_UAM(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"),unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_uam'
        verbose_name = "Rule UAM"
        verbose_name_plural = "Rules UAM"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_UAM, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_UAM, self).save(*args, **kwargs) 

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_UAM.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route UAH
class Route_UAH(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"),unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_uah'
        verbose_name = "Rule UAH"
        verbose_name_plural = "Rules UAH"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_UAH, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_UAH, self).save(*args, **kwargs) 

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_UAH.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route UC3M
class Route_UC3M(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"),unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_uc3m'
        verbose_name = "Rule UC3M"
        verbose_name_plural = "Rules UC3M"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_UC3M, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_UC3M, self).save(*args, **kwargs)

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_UC3M.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route UCM
class Route_UCM(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"),unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None


    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    if change.old:
                        history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
                    else:
                        pass
        return history_records

   
    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_ucm'
        verbose_name = "Rule UCM"
        verbose_name_plural = "Rules UCM"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_UCM, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_UCM, self).save(*args, **kwargs) 

    def back_up_route(self):
        from datetime import datetime
        from django.core.management import call_command
        now = datetime.now()
        name = self.name ; fd = name.find('_')
        peer_tag = name[fd+1::]
        current_time = now.strftime("%H:%M")
        current_date = now.strftime("%d-%B-%Y")
        try:
            call_command('dumpdata', f'flowspec.Route_{peer_tag}', format='json',output=f'_backup/{peer_tag}/{peer_tag}_backup_{current_date}_{current_time}.json')
        #call_command('dbbackup', output_filename=(f"redifod-{current_date}-{current_time}.psql"))
            message = 'Copia de seguridad creada con éxito.'
            send_message(message) 
        except Exception as e:
            message = ('Ha ocurrido un error intentando crear la copia de seguridad. %s'%e)
            send_message(message)

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_UCM.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route UEM
class Route_UEM(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

  
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    if change.old:
                        history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
                    else:
                        pass
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_uem'
        verbose_name = "Rule UEM"
        verbose_name_plural = "Rules UEM"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_UEM, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_UEM, self).save(*args, **kwargs)

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_UEM.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route UNED
class Route_UNED(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

   
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    if change.old:
                        history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
                    else:
                        pass
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_uned'
        verbose_name = "Rule UNED"
        verbose_name_plural = "Rules UNED"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_UNED, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_UNED, self).save(*args, **kwargs) 

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_UNED.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route UPM
class Route_UPM(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_upm'
        verbose_name = "Rule UPM"
        verbose_name_plural = "Rules UPM"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_UPM, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_UPM, self).save(*args, **kwargs) 

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_UPM.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status= "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================
#==================================== Route URJC
class Route_URJC(models.Model):    
    name = models.SlugField(max_length=128, verbose_name=_("Name"), unique=True)
    applier = models.ForeignKey(User, blank=True, null=True,on_delete=models.CASCADE)
    peer = models.ForeignKey(Peer, blank=True, null=True,on_delete=models.CASCADE)
    source = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Source Address"),blank=True, null=True)
    sourceport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Source Port"))
    destination = models.CharField(max_length=32, help_text=_("Usar la notación CIDR"), verbose_name=_("Destination Address"),blank=True, null=True)
    destinationport = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Destination Port"))
    port = models.CharField(max_length=65535, blank=True, null=True, verbose_name=_("Port"))
    dscp = models.ManyToManyField(MatchDscp, blank=True, verbose_name="DSCP")
    icmpcode = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Code")
    icmptype = models.CharField(max_length=32, blank=True, null=True, verbose_name="ICMP-Type")
    packetlength = models.CharField(max_length=65535, blank=True, null=True, verbose_name="Packet Length")
    protocol = models.ManyToManyField(MatchProtocol, blank=True, verbose_name=_("Protocol"))
    tcpflag = models.CharField(max_length=50, choices=TCP_CHOICES, blank=True, null=True, verbose_name="TCP flag")
    #tcpflag = models.ManyToManyField(TCPFlags, verbose_name=_("TCP Flag"))
    then = models.ManyToManyField(ThenAction, verbose_name=_("Then"))
    filed = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)
    expires = models.DateField(default=days_offset, verbose_name=_("Expires"), blank=True, null=True)
    response = models.CharField(max_length=512, blank=True, null=True, verbose_name=_("Response"))
    comments = models.TextField(null=True, blank=True, verbose_name=_("Comments"))
    requesters_address = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=20, choices=ROUTE_STATES, blank=True, null=True, verbose_name=_("Status"), default="PENDING")
    history = HistoricalRecords(use_base_model_db=True)
    

    @property
    def applier_username(self):
        if self.applier:
            return self.applier.username
        else:
            return None
       
    @property
    def applier_username_nice(self):
        if self.applier:
            if self.applier.first_name or self.applier.last_name:
                fn = self.applier.first_name if self.applier.first_name else ""
                ln = self.applier.last_name if self.applier.last_name else ""
                ret = "{0} {1}".format(fn, ln).strip()
            elif self.applier.email:
                ret = self.applier.email
            else:
                ret = self.applier.username
            return ret
        else:
            return None

    
    def check_history_changes(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def __str__(self):
        return "%s, %s, %s, %s, %s, %s"%(self.name,self.expires, self.applier, self.status,self.source,self.destination)

    class Meta:
        db_table = u'route_urjc'
        verbose_name = "Rule URJC"
        verbose_name_plural = "Rules URJC"

    def save(self, *args, **kwargs):
        peer_suff = ''
        if self.applier == None:
            fd = self.name.find('_')
            peer_suff = self.name[fd+1:]
            pass
        else:
            peer_suff = get_peer_tag(self.applier.username)
        if not self.pk and self.name.endswith('_%s'%(peer_suff)):
            super(Route_URJC, self).save(*args, **kwargs)
        elif not self.pk:
            name = self.name
            self.name = "%s_%s" % (self.name, peer_suff) 
        super(Route_URJC, self).save(*args, **kwargs) 

                  

    def clean(self, *args, **kwargs):
        from django.core.exceptions import ValidationError
        if self.destination:
            try:
                address = IPNetwork(self.destination)
                self.destination = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Destination Field'))
        if self.source:
            try:
                address = IPNetwork(self.source)
                self.source = address.exploded
            except Exception:
                raise ValidationError(_('Invalid network address format at Source Field'))
    
    def commit_add(self, *args, **kwargs):
        if self.applier:
            peers = self.applier.profile.peers.all()
            username = None
            for peer in peers:
                if username:
                    break
                for network in peer.networks.all():
                    net = IPNetwork(network)
                    if IPNetwork(self.destination) in net:
                        username = peer
                        break
        else:
            peers = self.peer
            username = None
            for network in peers.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peers
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        route =  Route_URJC.objects.get(name = self.name)
        routename = route
        response = add(routename)
        logger.info('Got add job id: %s' % response)
        try: 
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (
                    fqdn,
                    reverse('edit-route', kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string(
                    'rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'creation','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(settings.EMAIL_SUBJECT_PREFIX + 'Rule %s creation request submitted by %s' % (self.name, self.applier_username_nice),mail_body,settings.SERVER_EMAIL, user_mail,get_peer_techc_mails(self.applier, username))
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def commit_edit(self, *args, **kwargs):
        peers = self.applier.profile.peers.all()
        username = None
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = edit(self)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn=Site.objects.get_current().domain
                admin_url='https://%s%s' % (fqdn, reverse('edit-route',kwargs={'route_slug':self.name}))
                mail_body=render_to_string('rule_action.txt',{'route':self,'address':self.requesters_address,'action':'edit','url':admin_url,'peer':username})
                user_mail='%s' % self.applier.email
                user_mail=user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s edit request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL, user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
        logger.info('Got edit job id: %s' % response)
            
    def commit_delete(self, *args, **kwargs):
        username = None
        reason_text = ''
        reason = ''
        if "reason" in kwargs:
            reason = kwargs['reason']
            reason_text = 'Reason: %s.' % reason
        peers = self.applier.profile.peers.all()
        for peer in peers:
            if username:
                break
            for network in peer.networks.all():
                net = IPNetwork(network)
                if IPNetwork(self.destination) in net:
                    username = peer
                    break
        if username:
            peer = username.peer_tag
        else:
            peer = None
        response = delete(self, reason=reason)
        logger.info('Got delete job id: %s' % response)
        try:
            if not settings.DISABLE_EMAIL_NOTIFICATION:
                fqdn = Site.objects.get_current().domain
                admin_url = 'https://%s%s' % (fqdn,reverse('edit-route',kwargs={'route_slug': self.name})
                )
                mail_body = render_to_string('rule_action.txt',{'route': self,'address': self.requesters_address,'action': 'removal','url': admin_url,'peer': username})
                user_mail = '%s' % self.applier.email
                user_mail = user_mail.split(';')
                send_new_mail(
                    settings.EMAIL_SUBJECT_PREFIX + 'Rule %s removal request submitted by %s' % (self.name, self.applier_username_nice),
                    mail_body,
                    settings.SERVER_EMAIL,
                    user_mail,
                    get_peer_techc_mails(self.applier, username)
                )
        except Exception as e:
                print('There was an exception when trying to notify the user via e-mail, ',e)
    def has_expired(self):
        today = datetime.date.today()
        if self.expires == None:
            return False
        elif today > self.expires:
            return True
        
        return False

    def check_sync(self):
        if self.status == 'INACTIVE' or 'ADMINACTIVE':
            self.save()
        if not self.is_synced():
            self.status = "OUTOFSYNC"
            self.save()

    def is_synced(self):
        found = False
        get_device = PR.Retriever()
        device = get_device.fetch_device()
        try:
            routes = device.routing_options[0].routes
        except Exception as e:
            self.status= "EXPIRED"
            self.save()
            logger.error('No routing options on device. Exception: %s' % e)
            return True
        for route in routes:
            if route.name == self.name:
                found = True
                logger.info('Found a matching rule name')
                devicematch = route.match
                try:
                    assert(self.destination)
                    assert(devicematch['destination'][0])
                    if self.destination == devicematch['destination'][0]:
                        found = found and True
                        logger.info('Found a matching destination')
                    else:
                        found = False
                        logger.info('Destination fields do not match')
                except:
                    pass
                try:
                    assert(self.source)
                    assert(devicematch['source'][0])
                    if self.source == devicematch['source'][0]:
                        found = found and True
                        logger.info('Found a matching source')
                    else:
                        found = False
                        logger.info('Source fields do not match')
                except:
                    pass

                try:
                    assert(self.fragmenttype.all())
                    assert(devicematch['fragment'])
                    devitems = devicematch['fragment']
                    dbitems = ["%s"%i for i in self.fragmenttype.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching fragment type')
                    else:
                        found = False
                        logger.info('Fragment type fields do not match')
                except:
                    pass

                try:
                    assert(self.port.all())
                    assert(devicematch['port'])
                    devitems = devicematch['port']
                    dbitems = ["%s"%i for i in self.port.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching port type')
                    else:
                        found = False
                        logger.info('Port type fields do not match')
                except:
                    pass

                try:
                    assert(self.protocol.all())
                    assert(devicematch['protocol'])
                    devitems = devicematch['protocol']
                    dbitems = ["%s"%i for i in self.protocol.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching protocol type')
                    else:
                        found = False
                        logger.info('Protocol type fields do not match')
                except:
                    pass

                try:
                    assert(self.destinationport.all())
                    assert(devicematch['destination-port'])
                    devitems = devicematch['destination-port']
                    dbitems = ["%s"%i for i in self.destinationport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching destination port type')
                    else:
                        found = False
                        logger.info('Destination port type fields do not match')
                except:
                    pass

                try:
                    assert(self.sourceport.all())
                    assert(devicematch['source-port'])
                    devitems = devicematch['source-port']
                    dbitems = ["%s"%i for i in self.sourceport.all()]
                    intersect = list(set(devitems).intersection(set(dbitems)))
                    if ((len(intersect) == len(dbitems)) and (len(intersect) == len(devitems))):
                        found = found and True
                        logger.info('Found a matching source port type')
                    else:
                        found = False
                        logger.info('Source port type fields do not match')
                except:
                    pass
                try:
                    assert(self.icmpcode)
                    assert(devicematch['icmp-code'][0])
                    if self.icmpcode == devicematch['icmp-code'][0]:
                        found = found and True
                        logger.info('Found a matching icmp code')
                    else:
                        found = False
                        logger.info('Icmp code fields do not match')
                except:
                    pass
                try:
                    assert(self.icmptype)
                    assert(devicematch['icmp-type'][0])
                    if self.icmptype == devicematch['icmp-type'][0]:
                        found = found and True
                        logger.info('Found a matching icmp type')
                    else:
                        found = False
                        logger.info('Icmp type fields do not match')
                except:
                    pass
                if found and self.status!= "ACTIVE":
                    logger.error('Rule is applied on device but appears as offline')
                    self.status= "ACTIVE"
                    self.save()
                    found = True
            if self.status== "ADMININACTIVE" or self.status== "INACTIVE" or self.status== "EXPIRED":
                found = True
        return found

    def get_then(self):
        ret = ''
        then_statements = self.then.all()
        for statement in then_statements:
            if statement.action_value:
                ret = "%s %s %s" %(ret, statement.action, statement.action_value)
            else:
                ret = "%s %s" %(ret, statement.action)
        return ret

    get_then.short_description = 'Then statement'
    get_then.allow_tags = True
#

    def get_match(self):
        ret = '<dl class="dl-horizontal">'
        if self.destination:
            ret = '%s <dt>Dst Addr</dt><dd>%s</dd>' %(ret, self.destination)
        #if self.fragmenttype.all():
          #  ret = ret + "<dt>Fragment Types</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.fragmenttype.all()]))
#            for fragment in self.fragmenttype.all():
#                    ret = ret + "Fragment Types:<strong>%s</dd>" %(fragment)
        if self.icmpcode:
            ret = "%s <dt>ICMP code</dt><dd>%s</dd>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <dt>ICMP Type</dt><dd>%s</dd>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <dt>Packet Length</dt><dd>%s</dd>" %(ret, self.packetlength)
        if self.source:
            ret = "%s <dt>Src Addr</dt><dd>%s</dd>" %(ret, self.source)
        if self.tcpflag:
            ret = "%s <dt>TCP flag</dt><dd>%s</dd>" %(ret, self.tcpflag)
        if self.port:
            ret = ret + "<dt>Ports</dt><dd>%s</dd>" %(self.port)
#            for port in self.port.all():
#                    ret = ret + "Port:<strong>%s</dd>" %(port)
        if self.protocol.all():
            ret = ret + "<dt>Protocols</dt><dd>%s</dd>" %(', '.join(["%s"%i for i in self.protocol.all()]))
#            for protocol in self.protocol.all():
#                    ret = ret + "Protocol:<strong>%s</dd>" %(protocol)
        if self.destinationport:
            ret = ret + "<dt>DstPorts</dt><dd>%s</dd>" %(self.destinationport)
#            for port in self.destinationport.all():
#                    ret = ret + "Dst Port:<strong>%s</dd>" %(port)
        if self.sourceport:
            ret = ret + "<dt>SrcPorts</dt><dd>%s</dd>" %(self.sourceport)
#            for port in self.sourceport.all():
#                    ret = ret +"Src Port:<strong>%s</dd>" %(port)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret = ret + "%s <dt>Port</dt><dd>%s</dd>" %(ret, dscp)
        ret = ret + "</dl>"
        return ret

    get_match.short_description = 'Match statement'
    get_match.allow_tags = True


    def get_table(self):
        then = self.get_then()
        ret = '<tr>'
        ret1 = '<tr>'
        ret2 = '<tr>'
        if self.destination:
            ret = '%s <td><small><b>Dst Addr:</b> %s</small></td>' %(ret, self.destination)
        if self.icmpcode:
            ret = "%s <td><small><b>ICMP code: </b>%s</small></td>" %(ret, self.icmpcode)
        if self.icmptype:
            ret = "%s <td><small><b>ICMP Type: </b>%s</small></td>" %(ret, self.icmptype)
        if self.packetlength:
            ret = "%s <td><small><b>Packet Length: </b>%s</small></td>" %(ret, self.packetlength)
        if self.source:
            ret1 = "%s <td><small><b>Src Addr: </b>%s</small></td>" %(ret1, self.source)
        if self.tcpflag:
            ret1 = "%s <td><small><b>TCP flags: </b>%s</small></td>" %(ret1, self.tcpflag)
        if self.port:
            ret1 = ret1 + "<td><small><b>Ports: </b>%s</small></td>" %(self.port)
        if self.protocol.all():
            ret1 = ret1 + "<td><small><b>Protocols: </b>%s</small></td>" %(', '.join(["%s"%i for i in self.protocol.all()]))
        if self.destinationport:
            ret2 = ret2 + "<td><small><b>DstPorts:  </b>%s</small></td>" %(self.destinationport)
        if self.sourceport:
            ret2 = ret2 + "<td><small><b>SrcPorts: </b>%s</small></td>" %(self.sourceport)
        if self.then:
            ret2 = ret2 + "<td><small><b>Then: </b>%s</small></td>" %(then)
        if self.dscp:
            for dscp in self.dscp.all():
                    ret2 = ret + "%s <td><small><b>Port: </b>%s</small></td>" %(ret2, dscp)
        ret = ret + "</tr>"
        ret1 = ret1 + "</tr>"
        ret2 = ret2 + "</tr>"
        data = ret + ret1 + ret2
        return data

        
    @property
    def applier_peers(self):
        try:
            peers = self.applier.get_profile().peers.all()
            applier_peers = ''.join(('%s, ' % (peer.peer_name)) for peer in peers)[:-2]
        except:
            applier_peers = None
        return applier_peers

    @property
    def days_to_expire(self):
        if self.status not in ['EXPIRED', 'ADMININACTIVE', 'ERROR', 'INACTIVE']:
            expiration_days = (self.expires - datetime.date.today()).days
            if expiration_days < settings.EXPIRATION_NOTIFY_DAYS:
                return "%s" %expiration_days
            else:
                return False
        else:
            return False

    @property
    def junos_name(self):
        return create_junos_name(self)

    def get_absolute_url(self):
        return reverse('route-details', kwargs={'route_slug': self.name})
#=================================================================================