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

from . import jncdevice as np
from ncclient import manager
from ncclient.transport.errors import AuthenticationError, SSHError
import lxml
import xml.etree.ElementTree as ET
from django.conf import settings
import logging
from django.core.cache import cache
import os
from io import StringIO
from celery.exceptions import TimeLimitExceeded, SoftTimeLimitExceeded
import re as re_
from utils.jncdevice import Device
            


from utils.portrange import parse_portrange

cwd = os.getcwd()
Tag_pattern_ = re_.compile(r'({.*})?(.*)')

LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')

# FORMAT = '%(asctime)s %(levelname)s: %(message)s'
# logging.basicConfig(format=FORMAT)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME)
handler.setFormatter(formatter)
logger.addHandler(handler)


def fod_unknown_host_cb(host, fingerprint):
    return True


class Retriever(object):
    def __init__(self, device=settings.NETCONF_DEVICE, username=settings.NETCONF_USER, password=settings.NETCONF_PASS, filter=settings.ROUTES_FILTER, port=settings.NETCONF_PORT, route_name=None, xml=None):
        self.device = device
        self.username = username
        self.password = password
        self.port = port
        self.filter = filter
        self.xml = xml
        if route_name:
            self.filter = settings.ROUTE_FILTER%route_name

    def fetch_xml(self):
        with manager.connect(host=self.device, port=self.port, username=self.username, password=self.password, hostkey_verify=False) as m:
            xmlconfig = m.get_config(source='running', filter=('subtree',self.filter)).data_xml
            import lxml.etree as ET
            parser = ET.XMLParser(recover=True)
            tree = ET.ElementTree(ET.fromstring(bytes(xmlconfig, encoding='utf-8'), parser=parser))
        return tree
    
    def fetch_config_str(self):
        with manager.connect(host=self.device, port=self.port, username=self.username, password=self.password, hostkey_verify=False) as m:
            xmlconfig = m.get_config(source='running', filter=('subtree',self.filter)).data_xml
        return xmlconfig

    def proccess_xml(self):
        if self.xml:
            xmlconfig = self.xml
        else:
            xmlconfig = self.fetch_xml()
        parser = np.Parser()
        parser.confile = xmlconfig
        device = self.fetch_xml()
        return device

    def fetch_device(self):
        device = cache.get("device")
        logger.info("[CACHE] hit! got device")
        if device:
            return device
        else:
            device = self.fetch_xml()
            rootNode = device.getroot()
            rootNodeTag = Tag_pattern_.match(rootNode.tag).groups()[-1]
            if rootNodeTag == 'rpc-reply':
                rootNode = rootNode.xpath("//*[local-name()='configuration']")[0]
            if rootNodeTag == 'data':
                rootNode = rootNode.xpath("//*[local-name()='configuration']")[0]
            rootObj = Device()
            rootObj.build(rootNode)
            if rootObj.routing_options:
                cache.set("device", device, 3600)
                logger.info("[CACHE] miss, setting device")
                return rootObj
            else:
                return False

class Applier(object):
    def __init__(self, route_objects=[], route_object=None, device=settings.NETCONF_DEVICE, username=settings.NETCONF_USER, password=settings.NETCONF_PASS, port=settings.NETCONF_PORT):
        self.route_object = route_object
        self.route_objects = route_objects
        self.device = device
        self.username = username
        self.password = password
        self.port = port

    def to_xml(self, operation=None):
        logger.info("Operation: %s"%operation)
        if self.route_object:
            try:
                settings.PORTRANGE_LIMIT
            except:
                settings.PORTRANGE_LIMIT = 100
            logger.info("Generating XML config")
            route_obj = self.route_object
            device = np.Device()
            flow = np.Flow()
            route = np.Route()
            flow.routes.append(route)
            device.routing_options.append(flow)
            route.name = route_obj.name
            if operation == "delete":
                logger.info("Requesting a delete operation")
                route.operation = operation
                device = device.export(netconf_config=True)
                return ET.tostring(device)
            if route_obj.source:
                route.match['source'].append(route_obj.source)
            if route_obj.destination:
                route.match['destination'].append(route_obj.destination)
            try:
                if route_obj.protocol:
                    for protocol in route_obj.protocol.all():
                        route.match['protocol'].append(protocol.protocol)
            except:
                pass
            try:
                ports = []
                if route_obj.port:
                    portrange = str(route_obj.port)
                    for port in portrange.split(","):
                        route.match['port'].append(port)
            except:
                pass
            try:
                ports = []
                if route_obj.destinationport:
                    portrange = str(route_obj.destinationport)
                    for port in portrange.split(","):
                        route.match['destination-port'].append(port)
            except:
                pass
            try:
                if route_obj.sourceport:
                    portrange = str(route_obj.sourceport)
                    for port in portrange.split(","):
                        route.match['source-port'].append(port)
            except:
                pass
            if route_obj.icmpcode:
                route.match['icmp-code'].append(route_obj.icmpcode)
            if route_obj.icmptype:
                route.match['icmp-type'].append(route_obj.icmptype)
            if route_obj.tcpflag:
                route.match['tcp-flags'].append(route_obj.tcpflag)
            if route_obj.packetlength:
                route.match['packet-length'].append(route_obj.packetlength)
            try:
                if route_obj.dscp:
                    for dscp in route_obj.dscp.all():
                        route.match['dscp'].append(dscp.dscp)
            except:
                pass

            try:
                if route_obj.fragmenttype:
                    for frag in route_obj.fragmenttype.all():
                        route.match['fragment'].append(frag.fragmenttype)
            except:
                pass
            for thenaction in route_obj.then.all():
                if thenaction.action_value:
                    route.then[thenaction.action] = thenaction.action_value
                else:
                    route.then[thenaction.action] = True
            if operation == "replace":
                logger.info("Requesting a replace operation")
                route.operation = operation
            device = device.export(netconf_config=True)
            result = ET.tostring(device)
            logger.info("result="+str(result))
            return result
        else:
            return False

    def delete_routes(self):
        if self.route_objects:
            logger.info("Generating XML config")
            device = np.Device()
            flow = np.Flow()
            for route_object in self.route_objects:
                route_obj = route_object
                route = np.Route()
                flow.routes.append(route)
                route.name = route_obj.name
                route.operation = 'delete'
            device.routing_options.append(flow)
            device = device.export(netconf_config=True)
            device = ET.tostring(device)
            return device
        else:
            return False

    def get_existing_config_xml(self):
        retriever0 = Retriever(xml=None)
        config_xml_running = retriever0.fetch_xml()
        logger.info("proxy::get_existing_config(): config_xml_running="+str(config_xml_running))
        return config_xml_running

    def get_existing_config(self):
        retriever0 = Retriever(xml=None)
        config_parsed = retriever0.proccess_xml()
        logger.info("proxy::get_existing_config(): config_parsed="+str(config_parsed))
        return config_parsed

    def get_existing_routes(self):
        config_parsed = self.get_existing_config()
        import lxml.etree as ET
        parser = ET.XMLParser(recover=True)
        data = ET.ElementTree(ET.tostring(config_parsed))
        if data.routing_options and data.routing_options.__len__()>0:
          flow = config_parsed.routing_options[0]
          logger.info("proxy::get_existing_routes(): config_parsed.flow="+str(flow))
          routes_existing = flow.routes
          logger.info("proxy::get_existing_routes(): config_parsed.flow.routes="+str(routes_existing))
          return routes_existing
        else:
          logger.info("proxy::get_existing_routes(): no routing_options or is empty")
          return []

    def get_existing_route_names(self):
      routes_existing = self.get_existing_routes()
      route_ids_existing = [route.name for route in routes_existing]
      logger.info("proxy::get_existing_route_names(): config_parsed.flow.routes.ids="+str(route_ids_existing))
      return route_ids_existing


    def apply(self, configuration = None, operation=None):
        reason = None
        if not configuration:
            configuration = self.to_xml(operation=operation)
        edit_is_successful = False
        commit_confirmed_is_successful = False
        commit_is_successful = False
        try:
          if configuration:
            with manager.connect(host=self.device, port=self.port, username=self.username, password=self.password, hostkey_verify=False) as m:
                assert(":candidate" in m.server_capabilities)              
                with m.locked(target='candidate'):
                    m.discard_changes()
                    try:
                        edit_response = m.edit_config(target='candidate', config=configuration.decode('utf-8'), test_option='test-then-set').ok                       
                        edit_is_successful, reason = is_successful(edit_response)
                        logger.info("Successfully edited @ %s" % self.device)
                        if not edit_is_successful:
                            raise Exception()
                    except SoftTimeLimitExceeded:
                        cause="Task timeout"
                        logger.error(cause)
                        return False, cause
                    except TimeLimitExceeded:
                        cause="Task timeout"
                        logger.error(cause)
                        return False, cause
                    except Exception as e:
                        cause = "Caught edit exception: %s %s" % (e, reason)
                        cause = cause.replace('\n', '')
                        logger.error(cause)
                        m.discard_changes()
                        return False, cause
                    if edit_is_successful:
                        try:
                            if ":confirmed-commit" in m.server_capabilities:
                                commit_confirmed_response = m.commit(confirmed=True, timeout=settings.COMMIT_CONFIRMED_TIMEOUT).ok
                                commit_confirmed_is_successful, reason = is_successful(commit_confirmed_response)
                                if not commit_confirmed_is_successful:
                                    raise Exception()
                                else:
                                    logger.info("Successfully confirmed committed @ %s" % self.device)
                                    if not settings.COMMIT:
                                        return True, "Successfully confirmed committed"
                            else:
                                commit_response = m.commit(confirmed=False, timeout=settings.COMMIT_CONFIRMED_TIMEOUT)
                                if commit_response.ok:
                                    logger.info("Successfully committed @ %s" % self.device)
                                    return True, "Successfully committed"
                                else:
                                    return False, "Failed to commit changes %s" % commit_response.errors

                        except SoftTimeLimitExceeded:
                            cause="Task timeout"
                            logger.error(cause)
                            return False, cause
                        except TimeLimitExceeded:
                            cause="Task timeout"
                            logger.error(cause)
                            return False, cause
                        except Exception as e:
                            cause="Caught commit confirmed exception: %s %s" %(e,reason)
                            cause=cause.replace('\n', '')
                            logger.error(cause)
                            return False, cause
                        if settings.COMMIT:
                            if edit_is_successful and commit_confirmed_is_successful:
                                try:
                                    commit_response = m.commit(confirmed=False).ok
                                    commit_is_successful, reason = is_successful(commit_response)
                                    logger.info("Successfully committed @ %s" % self.device)
                                    newconfig = m.get_config(source='running', filter=('subtree',settings.ROUTES_FILTER)).data_xml
                                    retrieve = Retriever(xml=newconfig)
                                    logger.info("[CACHE] caching device configuration")
                                    ###next function is the one causing problems: 
                                    #cache.set("device", retrieve.proccess_xml(), 3600)
                                    cache.set("device", retrieve, 3600)

                                    if not commit_is_successful:
                                        raise Exception()
                                    else:
                                        logger.info("Successfully cached device configuration")
                                        return True, "Successfully committed"
                                except SoftTimeLimitExceeded:
                                    cause="Task timeout"
                                    logger.error(cause)
                                    return False, cause
                                except TimeLimitExceeded:
                                    cause="Task timeout"
                                    logger.error(cause)
                                    return False, cause
                                except Exception as e:
                                    cause="Caught commit exception: %s %s" %(e,reason)
                                    cause=cause.replace('\n', '')
                                    logger.error(cause)
                                    return False, cause
          else:
            return False, "No configuration was supplied"
        except Exception as e:
                            cause="NETCONF connection exception: %s %s" %(e,reason)
                            cause=cause.replace('\n', '')
                            logger.error(cause)
                            cause_user="NETCONF connection failed"
                            return False, cause_user

class Backup_Retriever(object):
    def __init__(self, device=settings.NETCONF_DEVICE_B, username=settings.NETCONF_USER_B, password=settings.NETCONF_PASS_B, filter=settings.ROUTES_FILTER, port=settings.NETCONF_PORT_B, route_name=None, xml=None):
        self.device = device
        self.username = username
        self.password = password
        self.port = port
        self.filter = filter
        self.xml = xml
        if route_name:
            self.filter = settings.ROUTE_FILTER%route_name

    def fetch_xml(self):
        with manager.connect(host=self.device, port=self.port, username=self.username, password=self.password, hostkey_verify=False) as m:
            xmlconfig = m.get_config(source='running', filter=('subtree',self.filter)).data_xml
            import lxml.etree as ET
            parser = ET.XMLParser(recover=True)
            tree = ET.ElementTree(ET.fromstring(bytes(xmlconfig, encoding='utf-8'), parser=parser))
        return tree
    
    def fetch_config_str(self):
        with manager.connect(host=self.device, port=self.port, username=self.username, password=self.password, hostkey_verify=False) as m:
            xmlconfig = m.get_config(source='running', filter=('subtree',self.filter)).data_xml
        return xmlconfig

    def proccess_xml(self):
        if self.xml:
            xmlconfig = self.xml
        else:
            xmlconfig = self.fetch_xml()
        parser = np.Parser()
        parser.confile = xmlconfig
        device = self.fetch_xml()
        return device

    def fetch_device(self):
        device = cache.get("device")
        logger.info("[CACHE] hit! got device")
        if device:
            return device
        else:
            device = self.fetch_xml()
            rootNode = device.getroot()
            rootNodeTag = Tag_pattern_.match(rootNode.tag).groups()[-1]
            if rootNodeTag == 'rpc-reply':
                rootNode = rootNode.xpath("//*[local-name()='configuration']")[0]
            if rootNodeTag == 'data':
                rootNode = rootNode.xpath("//*[local-name()='configuration']")[0]
            rootObj = Device()
            rootObj.build(rootNode)
            if rootObj.routing_options:
                cache.set("device", device, 3600)
                logger.info("[CACHE] miss, setting device")
                return rootObj
            else:
                return False

class Backup_Applier(object):
    def __init__(self, route_objects=[], route_object=None, device=settings.NETCONF_DEVICE_B, username=settings.NETCONF_USER_B, password=settings.NETCONF_PASS_B, port=settings.NETCONF_PORT_B):
        self.route_object = route_object
        self.route_objects = route_objects
        self.device = device
        self.username = username
        self.password = password
        self.port = port

    def to_xml(self, operation=None):
        logger.info("Operation: %s"%operation)
        if self.route_object:
            try:
                settings.PORTRANGE_LIMIT
            except:
                settings.PORTRANGE_LIMIT = 100
            logger.info("Generating XML config")
            route_obj = self.route_object
            device = np.Device()
            flow = np.Flow()
            route = np.Route()
            flow.routes.append(route)
            device.routing_options.append(flow)
            route.name = route_obj.name
            if operation == "delete":
                logger.info("Requesting a delete operation")
                route.operation = operation
                device = device.export(netconf_config=True)
                return ET.tostring(device)
            if route_obj.source:
                route.match['source'].append(route_obj.source)
            if route_obj.destination:
                route.match['destination'].append(route_obj.destination)
            try:
                if route_obj.protocol:
                    for protocol in route_obj.protocol.all():
                        route.match['protocol'].append(protocol.protocol)
            except:
                pass
            try:
                ports = []
                if route_obj.port:
                    portrange = str(route_obj.port)
                    for port in portrange.split(","):
                        route.match['port'].append(port)
            except:
                pass
            try:
                ports = []
                if route_obj.destinationport:
                    portrange = str(route_obj.destinationport)
                    for port in portrange.split(","):
                        route.match['destination-port'].append(port)
            except:
                pass
            try:
                if route_obj.sourceport:
                    portrange = str(route_obj.sourceport)
                    for port in portrange.split(","):
                        route.match['source-port'].append(port)
            except:
                pass
            if route_obj.icmpcode:
                route.match['icmp-code'].append(route_obj.icmpcode)
            if route_obj.icmptype:
                route.match['icmp-type'].append(route_obj.icmptype)
            if route_obj.tcpflag:
                route.match['tcp-flags'].append(route_obj.tcpflag)
            if route_obj.packetlength:
                route.match['packet-length'].append(route_obj.packetlength)
            try:
                if route_obj.dscp:
                    for dscp in route_obj.dscp.all():
                        route.match['dscp'].append(dscp.dscp)
            except:
                pass

            try:
                if route_obj.fragmenttype:
                    for frag in route_obj.fragmenttype.all():
                        route.match['fragment'].append(frag.fragmenttype)
            except:
                pass
            for thenaction in route_obj.then.all():
                if thenaction.action_value:
                    route.then[thenaction.action] = thenaction.action_value
                else:
                    route.then[thenaction.action] = True
            if operation == "replace":
                logger.info("Requesting a replace operation")
                route.operation = operation
            device = device.export(netconf_config=True)
            result = ET.tostring(device)
            logger.info("result="+str(result))
            return result
        else:
            return False

    def delete_routes(self):
        if self.route_objects:
            logger.info("Generating XML config")
            device = np.Device()
            flow = np.Flow()
            for route_object in self.route_objects:
                route_obj = route_object
                route = np.Route()
                flow.routes.append(route)
                route.name = route_obj.name
                route.operation = 'delete'
            device.routing_options.append(flow)
            device = device.export(netconf_config=True)
            device = ET.tostring(device)
            return device
        else:
            return False

    def get_existing_config_xml(self):
        retriever0 = Retriever(xml=None)
        config_xml_running = retriever0.fetch_xml()
        logger.info("proxy::get_existing_config(): config_xml_running="+str(config_xml_running))
        return config_xml_running

    def get_existing_config(self):
        retriever0 = Retriever(xml=None)
        config_parsed = retriever0.proccess_xml()
        logger.info("proxy::get_existing_config(): config_parsed="+str(config_parsed))
        return config_parsed

    def get_existing_routes(self):
        config_parsed = self.get_existing_config()
        import lxml.etree as ET
        parser = ET.XMLParser(recover=True)
        data = ET.ElementTree(ET.tostring(config_parsed))
        if data.routing_options and data.routing_options.__len__()>0:
          flow = config_parsed.routing_options[0]
          logger.info("proxy::get_existing_routes(): config_parsed.flow="+str(flow))
          routes_existing = flow.routes
          logger.info("proxy::get_existing_routes(): config_parsed.flow.routes="+str(routes_existing))
          return routes_existing
        else:
          logger.info("proxy::get_existing_routes(): no routing_options or is empty")
          return []

    def get_existing_route_names(self):
      routes_existing = self.get_existing_routes()
      route_ids_existing = [route.name for route in routes_existing]
      logger.info("proxy::get_existing_route_names(): config_parsed.flow.routes.ids="+str(route_ids_existing))
      return route_ids_existing


    def apply(self, configuration = None, operation=None):
        reason = None
        if not configuration:
            configuration = self.to_xml(operation=operation)
        edit_is_successful = False
        commit_confirmed_is_successful = False
        commit_is_successful = False
        try:
          if configuration:
            with manager.connect(host=self.device, port=self.port, username=self.username, password=self.password, hostkey_verify=False) as m:
                assert(":candidate" in m.server_capabilities)              
                with m.locked(target='candidate'):
                    m.discard_changes()
                    try:
                        edit_response = m.edit_config(target='candidate', config=configuration.decode('utf-8'), test_option='test-then-set').ok                       
                        edit_is_successful, reason = is_successful(edit_response)
                        logger.info("Successfully edited @ %s" % self.device)
                        if not edit_is_successful:
                            raise Exception()
                    except SoftTimeLimitExceeded:
                        cause="Task timeout"
                        logger.error(cause)
                        return False, cause
                    except TimeLimitExceeded:
                        cause="Task timeout"
                        logger.error(cause)
                        return False, cause
                    except Exception as e:
                        cause = "Caught edit exception: %s %s" % (e, reason)
                        cause = cause.replace('\n', '')
                        logger.error(cause)
                        m.discard_changes()
                        return False, cause
                    if edit_is_successful:
                        try:
                            if ":confirmed-commit" in m.server_capabilities:
                                commit_confirmed_response = m.commit(confirmed=True, timeout=settings.COMMIT_CONFIRMED_TIMEOUT).ok
                                commit_confirmed_is_successful, reason = is_successful(commit_confirmed_response)
                                if not commit_confirmed_is_successful:
                                    raise Exception()
                                else:
                                    logger.info("Successfully confirmed committed @ %s" % self.device)
                                    if not settings.COMMIT:
                                        return True, "Successfully confirmed committed"
                            else:
                                commit_response = m.commit(confirmed=False, timeout=settings.COMMIT_CONFIRMED_TIMEOUT)
                                if commit_response.ok:
                                    logger.info("Successfully committed @ %s" % self.device)
                                    return True, "Successfully committed"
                                else:
                                    return False, "Failed to commit changes %s" % commit_response.errors

                        except SoftTimeLimitExceeded:
                            cause="Task timeout"
                            logger.error(cause)
                            return False, cause
                        except TimeLimitExceeded:
                            cause="Task timeout"
                            logger.error(cause)
                            return False, cause
                        except Exception as e:
                            cause="Caught commit confirmed exception: %s %s" %(e,reason)
                            cause=cause.replace('\n', '')
                            logger.error(cause)
                            return False, cause
                        if settings.COMMIT:
                            if edit_is_successful and commit_confirmed_is_successful:
                                try:
                                    commit_response = m.commit(confirmed=False).ok
                                    commit_is_successful, reason = is_successful(commit_response)
                                    logger.info("Successfully committed @ %s" % self.device)
                                    newconfig = m.get_config(source='running', filter=('subtree',settings.ROUTES_FILTER)).data_xml
                                    retrieve = Retriever(xml=newconfig)
                                    logger.info("[CACHE] caching device configuration")
                                    ###next function is the one causing problems: 
                                    #cache.set("device", retrieve.proccess_xml(), 3600)
                                    cache.set("device", retrieve, 3600)

                                    if not commit_is_successful:
                                        raise Exception()
                                    else:
                                        logger.info("Successfully cached device configuration")
                                        return True, "Successfully committed"
                                except SoftTimeLimitExceeded:
                                    cause="Task timeout"
                                    logger.error(cause)
                                    return False, cause
                                except TimeLimitExceeded:
                                    cause="Task timeout"
                                    logger.error(cause)
                                    return False, cause
                                except Exception as e:
                                    cause="Caught commit exception: %s %s" %(e,reason)
                                    cause=cause.replace('\n', '')
                                    logger.error(cause)
                                    return False, cause
          else:
            return False, "No configuration was supplied"
        except Exception as e:
                            cause="NETCONF connection exception: %s %s" %(e,reason)
                            cause=cause.replace('\n', '')
                            logger.error(cause)
                            cause_user="NETCONF connection failed"
                            return False, cause_user



def is_successful(response):
    if response == True:
        return True, None
    else:
        reason_return = 'Edit_configuration error'
    return False, reason_return

def parsexml_(*args, **kwargs):
    if 'parser' not in kwargs:
        kwargs['parser'] = ET.ETCompatXMLParser()
    doc = ET.parse(*args, **kwargs)
    return doc