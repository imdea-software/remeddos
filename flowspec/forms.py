
from django import forms
from django.forms import ModelForm
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _
from django.utils.translation import ugettext_lazy
from django.template.defaultfilters import filesizeformat
from flowspec.models import *
from peers.models import *
from accounts.models import *
from ipaddr import *
from flowspec.validators import (
    clean_source,
    clean_destination,
    clean_expires,
    clean_route_form
)
from django.urls import reverse
from django.contrib.auth.models import User
from django.conf import settings
import datetime
import re
from django.core.mail import send_mail
from utils.portrange import parse_portrange
from flowspy.settings import *
import os 




class PortRangeForm(forms.CharField):
    class Meta:
        model = MatchPort
        fields = ('port')

    def clean(self, value):
        """Validation of Port Range value.

Supported format is the list of ports or port ranges separated by ','.
A port range is a tuple of ports separated by '-'.

Example: 80,1000-1100,8088
This method validates input:
* input must not be empty
* all ports must be integer 0 >= p >= 65535
* value is matched with regular expression: "^[0-9]+([-,][0-9]+)*$"
* ports in a port range A-B must ordered: A < B
"""
        if value:
            regexp = re.compile(r"^[0-9]+([-,][0-9]+)*$")
            r = re.match(regexp, value)
            if r:
                res = []
                pranges = value.split(",")
                for prange in pranges:
                    ports = prange.split("-")
                    prev = -1
                    for port in ports:
                        p = int(port)
                        if p < 0 or p > 65535:
                            raise forms.ValidationError(_('Port should be < 65535 and >= 0'))
                        if p <= prev:
                            raise forms.ValidationError(_('First port must be < the second port in a port range (e.g. A < B for A-B).'))
                        prev = p

                ports = parse_portrange(value)
                if len(ports) > settings.PORTRANGE_LIMIT:
                    # We do not allow more than PORTRANGE_LIMIT ports
                    raise forms.ValidationError(_('Maximal number of ports is {0}.').format(settings.PORTRANGE_LIMIT))
            else:
                raise forms.ValidationError(_('Malformed port range format, example: 80,1000-1100,6000-6010'))
        return value


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = '__all__'


class RouteForm(forms.ModelForm):
    sourceport = PortRangeForm()
    destinationport = PortRangeForm()
    port = PortRangeForm()
    class Meta:
        model = Route
        fields = '__all__'
    

    def clean_applier(self):
        applier = self.cleaned_data['applier']
        if applier:
            return self.cleaned_data["applier"]
        else:
            raise forms.ValidationError('This field is required.')

    def clean_source(self):
        # run validator which is used by rest framework too
        source = self.cleaned_data['source']
        res = clean_source(
            User.objects.get(pk=self.data['applier']),
            source
        )
        if res != source:
            raise forms.ValidationError(res)
        else:
            return res

    def clean_destination(self):
        destination = self.cleaned_data.get('destination')
        res = clean_destination(
            User.objects.get(pk=self.data['applier']),
            destination
        )
        if destination != res:
            raise forms.ValidationError(res)
        else:
            return res

    def clean_expires(self):
        date = self.cleaned_data['expires']
        res = clean_expires(date)
        if date != res:
            raise forms.ValidationError(res)
        return res

    def clean(self):
        if self.errors:
            raise forms.ValidationError(_('Errors in form. Please review and fix them: %s' % ", ".join(self.errors)))
        error = clean_route_form(self.cleaned_data)
        if error:
            raise forms.ValidationError(error)

        # check if same rule exists with other name
        user = self.cleaned_data['applier']
        if user.is_superuser:
            peers = Peer.objects.all()
        else:
            # have changed user.userprofile.peers.all() for:
            peers = user.profile.peers.all()
        existing_routes = Route.objects.all()
        existing_routes = existing_routes.filter(applier=user.profile.peers in peers)
        name = self.cleaned_data.get('name', None)
        protocols = self.cleaned_data.get('protocol', None)
        source = self.cleaned_data.get('source', None)
        sourceports = self.cleaned_data.get('sourceport', None)
        port = self.cleaned_data.get('port', None)
        destination = self.cleaned_data.get('destination', None)
        destinationports = self.cleaned_data.get('destinationport', None)
        icmptype = self.cleaned_data.get('icmptype', None)
        icmpcode = self.cleaned_data.get('icmpcode', None)
        packetlength = self.cleaned_data.get('packetlength', None)
        tcpflag = self.cleaned_data.get('tcpflag', None)
        user = self.cleaned_data.get('applier', None)

        if source:
            source = IPNetwork(source).compressed
            existing_routes = existing_routes.filter(source=source)
        else:
            existing_routes = existing_routes.filter(source=None)
        if protocols:
            route_pk_list=get_matchingprotocol_route_pks(protocols, existing_routes)
            if route_pk_list:
                existing_routes = existing_routes.filter(pk__in=route_pk_list)
            else:
                existing_routes = existing_routes.filter(protocol=None)
            if "icmp" in [str(i) for i in protocols] and (destinationports or sourceports or port):
                raise forms.ValidationError(_('It is not allowed to specify ICMP protocol and source/destination ports at the same time.'))
        else:
            existing_routes = existing_routes.filter(protocol=None)
        if sourceports:
            route_pk_list=get_matchingport_route_pks(sourceports, existing_routes)
            if route_pk_list:
                existing_routes = existing_routes.filter(pk__in=route_pk_list)
        else:
            existing_routes = existing_routes.filter(sourceport=None)
        if destinationports:
            route_pk_list=get_matchingport_route_pks(destinationports, existing_routes)
            if route_pk_list:
                existing_routes = existing_routes.filter(pk__in=route_pk_list)
        else:
            existing_routes = existing_routes.filter(destinationport=None)
        if port:
            route_pk_list=get_matchingport_route_pks(port, existing_routes)
            if route_pk_list:
                existing_routes = existing_routes.filter(pk__in=route_pk_list)
        else:
            existing_routes = existing_routes.filter(port=None)
        if icmpcode:
            if int(icmpcode) not in range(0,255):
                raise forms.ValidationError(_('The ICMP code {} introduced does not match any registered code.').format(icmpcode))
        
        if icmptype:
            if int(icmptype) not in range(0,255):
                raise forms.ValidationError(_('The ICMP type {} introduced does not match any registered type.').format(icmptype))
        if packetlength:
            regxp = re.compile(r"^[0-9]+([-,][0-9]+)*$")
            r = re.match(regxp, packetlength)
            if r:
                res = []
                plength = packetlength.split(",")
                for packet in plength:
                    p = int(packet)
                    if p < 0 or p > 65535:
                        raise forms.ValidationError(_('Packet length should be < 65535 and >= 0'))
            else:
                raise forms.ValidationError(_('Malformed packet'))        

        for route in existing_routes:
            if name != route.name:
                existing_url = reverse('edit-route', args=[route.name])
                if IPNetwork(destination) in IPNetwork(route.destination) or IPNetwork(route.destination) in IPNetwork(destination):
                    raise forms.ValidationError('Found an exact %s rule, %s with destination prefix %s<br>To avoid overlapping try editing rule <a href=\'%s\'>%s</a>' % (route.status, route.name, route.destination, existing_url, route.name))
        return self.cleaned_data


class ThenPlainForm(forms.ModelForm):
#    action = forms.CharField(initial='rate-limit')
    class Meta:
        model = ThenAction
        fields = '__all__'

    def clean_action_value(self):
        action_value = self.cleaned_data['action_value']
        if action_value:
            try:
                assert(int(action_value))
                if int(action_value) < 50:
                    raise forms.ValidationError(_('Rate-limiting cannot be < 50kbps'))
                return "%s" %self.cleaned_data["action_value"]
            except:
                raise forms.ValidationError(_('Rate-limiting should be an integer < 50'))
        else:
            raise forms.ValidationError(_('Cannot be empty'))

    def clean_action(self):
        action = self.cleaned_data['action']
        if action != 'rate-limit':
            raise forms.ValidationError(_('Cannot select something other than rate-limit'))
        else:
            return self.cleaned_data["action"]


class PortPlainForm(forms.ModelForm):
#    action = forms.CharField(initial='rate-limit')
    class Meta:
        model = MatchPort
        fields = '__all__'

    def clean_port(self):
        port = self.cleaned_data['port']
        if port:
            try:
                if int(port) > 65535 or int(port) < 0:
                    raise forms.ValidationError(_('Port should be < 65535 and >= 0'))
                return "%s" %self.cleaned_data["port"]
            except forms.ValidationError:
                raise forms.ValidationError(_('Port should be < 65535 and >= 0'))
            except:
                raise forms.ValidationError(_('Port should be an integer'))
        else:
            raise forms.ValidationError(_('Cannot be empty'))


def value_list_to_list(valuelist):
    vl = []
    for val in valuelist:
        vl.append(val[0])
    return vl


def get_matchingport_route_pks(portlist, routes):
    route_pk_list = []
    ports_value_list = parse_portrange(portlist)
    if not ports_value_list:
        return None

    for route in routes:
        rsp = parse_portrange(route.destinationport)
        if rsp and rsp == ports_value_list:
            route_pk_list.append(route.pk)
    return route_pk_list


def get_matchingprotocol_route_pks(protocolist, routes):
    route_pk_list = []
    protocols_value_list = value_list_to_list(protocolist.values_list('protocol').order_by('protocol'))
    for route in routes:
        rsp = value_list_to_list(route.protocol.all().values_list('protocol').order_by('protocol'))
        if rsp and rsp == protocols_value_list:
            route_pk_list.append(route.pk)
    return route_pk_list

class SetupForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput(), label="Password")
    netconf_device = forms.CharField(label="Router host (NETCONF)")
    netconf_port = forms.IntegerField(label="Router port (NETCONF)", min_value=0, max_value=65535)
    netconf_user = forms.CharField(label="Router user (NETCONF)")
    netconf_pass = forms.CharField(widget=forms.PasswordInput(), label="Router password (NETCONF)")
    test_peer_addr = forms.CharField(label="Test peer IP subnet")

class ValidationForm(forms.ModelForm):
    class Meta:
        model = Validation

        fields=["value"]
    
    def clean(self):
        super(ValidationForm, self).clean()
        value=self.cleaned_data.get('value')
        return self.cleaned_data
        