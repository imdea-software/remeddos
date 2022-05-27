from django.core.mail import send_mail
from django.conf import settings
from accounts.models import *
from flowspy.settings import * 
from utils.proxy import *
from flowspy import settings
from django.shortcuts import get_object_or_404
import os
import logging
import slack
from pyzabbix import ZabbixAPI
import datetime
from datetime import timedelta
from django.core.exceptions import ObjectDoesNotExist


FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


def get_code():
  from django.utils.crypto import get_random_string
  n = get_random_string(length=6)
  return n

def iter_for_delta_changes(iterable):
  from itertools import tee
  a,b = tee(iterable)
  next(b,None)
  return zip(a,b)

def send_new_mail(subject, message, from_email, recipient_list, bcc_list):
  try:
    logger.info("helpers::send_new_mail(): send mail: from_email="+str(from_email)+", recipient_list="+str(recipient_list)+", bcc_list="+str(bcc_list)) 
    #i have removed the bbc_list just for now
    return send_mail(subject, message, from_email, recipient_list)
  except Exception as e:
    #os.write(3, "send_new_mail() failed: exc="+str(e)+"\n") 
    logger.error("helpers::send_new_mail() failed: exc="+str(e)) 


def send_message(message, peer=None):
  print('inside send_message, this is peer: ', peer)
  slack_channels = {'CEU':'C03GQM0MN0K','CIB':'C03GA4HK8FR','CSIC':'C03HEF23RAL','CUNEF':'C03H3B3G3G9','CV':'C03GQMFQ519','IMDEA':'C03H3B7GBND','IMDEA_NET':'C03GJ3M124E',
  'Punch':'C03H3B7GBND','UAH':'C03H3B9BTGR','UAM':'C03GQML0JP5','UC3M':'C03GQN6P9MG','UCM':'C03GJ3RENLE','UEM':'C03H3BE7EBB',
  'UNED':'C03GA56STTR','UPM':'C03GJ3W32KY', 'URJC':'C03GJ3X931C'}
  if not peer:
    client = slack.WebClient(token=settings.SLACK_TOKEN)
    client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
  else:
    print('peer: ', peer, ' channel: ', slack_channels[peer], ' text: ', message)
    channel = slack_channels[peer]
    client = slack.WebClient(token=settings.REM_SLACK_TOKEN)
    client.chat_postMessage(channel=channel, text=message) 


def get_peer_with_name(name):
  fd = name.find('_')
  peer_name = '' 
  if not name[fd::][-1].isnumeric():
    peer_name = name[fd+1::]
  else:
    n = name[fd+1::]
    fd1 = n.find('_')
    peer_name = n[:fd1]
  return peer_name



def get_link(id_golem):
  import paramiko
  from flowspy import settings
  
  try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    path = "/home/remedios/.ssh/id_rsa"
    k = paramiko.RSAKey.from_private_key_file(path)
    ssh.connect(hostname="logs.redimadrid.es", port=22, pkey=k, username="alicia.cardenosa")
    try:
        stdin, stdout, stderr = ssh.exec_command(f'grep {id_golem} /var/log/remote/193.145.15.26/`date +%Y-%m-%d`.log')
        res,err = stdout.read(),stderr.read()
        result = res if res else err
        decode_result = result.decode()
        fs = decode_result.find('<')
        fe = decode_result.find('>') 
        fc = decode_result.find('=')
        html_link = decode_result[fs:fe+1]
        link = decode_result[fc+1:fe]
        return link
    except Exception as e:
        print('There was an error when trying to read the configuration file: ',e)
  except Exception as e:
      print('There was an error when trying to connect via ssh: ',e)
    


def get_peer_techc_mails(user, peer):
  logger.info("helpers::get_peer_techc_mails(): user="+str(user)+", peer="+str(peer))
  mail = []
  additional_mail = []
  techmails_list = []
  user_mail = '%s' % user.email
  user_mail = user_mail.split(';')
  techmails = []
  if peer:
    techmails = peer.techc_emails.all()
  if techmails:
    for techmail in techmails:
      techmails_list.append(techmail.email)
    if settings.NOTIFY_ADMIN_MAILS:
      additional_mail = settings.NOTIFY_ADMIN_MAILS
    mail.extend(additional_mail)
    mail.extend(techmails_list)
    logger.info("helpers::get_peer_techc_mails(): additional_mail="+str(additional_mail))
    logger.info("helpers::get_peer_techc_mails(): techmails_list="+str(techmails_list))
    return mail


def get_peers(username):
  user = User.objects.get(username=username)
  up = UserProfile.objects.get(user=user)
  peers = up.peers.all()
  peername = ''
  for peer in peers:
    peername = peer.peer_name
  return peername

def get_peer_tag(username):
  user = User.objects.get(username=username)
  up = UserProfile.objects.get(user=user)
  peers = up.peers.all()
  for peer in peers:
    peer_tag = peer.peer_tag
  return peer_tag

def get_back_up_files():
  files = []
  for f in os.listdir(settings.BACK_UP_DIR):
    files.append(f)
  return files

def translate_protocol(prot):
  operations = {'ah':51,'egp':8,'gre':47,'icmp':1,'igmp':2,'ospf':89, 'pim':103, 'rsvp':46,'sctp':132,'tcp':6,'udp':17}
  protocol = operations.get(prot,"Invalid argument") 
  return protocol 

def get_protocol(p):
  from flowspec.models import MatchProtocol
  protocol = ''
  if isinstance(p,(list)):
    for prot in p:
      try:
        fs = prot.find('(')
        protocol, created = MatchProtocol.objects.get_or_create(protocol=prot[:fs].lower())
      except Exception as e:
        protocol, created = MatchProtocol.objects.get_or_create(protocol=p)
  else:
    try:
      fs = p.find('(')
      protocol,created = MatchProtocol.objects.get_or_create(protocol=p[:fs].lower())
    except Exception as e:
      protocol,created = MatchProtocol.objects.get_or_create(protocol=p)
  return protocol

def translate_tcpflags(tf):
  tcpflag_dict = {'ack':'10','rst':'04','fin':'01','push':'08','urgent':'20','syn':'02'}
  tcpflags = tcpflag_dict.get(tf,"Invalid argument")
  return tcpflags

def golem_translate_tcpflag(tf):
  tcpdict = {'-----F':'1', '----S-':'2', '----SF':'3', '---R--':'4', '---R-F':'5', '---RS-':'6', '---RSF':'7', '--P---':'8', '--P--F':'9', '--P-S-':'10', '--P-SF':'11', '--PR--':'12', '--PR-F':'13', '--PRS-':'14', '--PRSF':'15',
  '-A----':'16', '-A---F':'17', '-A--S-':'18', '-A--SF':'19', '-A-R--':'20', '-A-R-F':'21', '-A-RS-':'22', '-A-RSF':'23', '-AP---':'24', '-AP--F':'25', '-AP-S-':'26', '-AP-SF':'27', '-APR--':'28', '-APR-F':'29', '-APRS-':'30',
  '-APRSF':'31'}
  tcpflags = tcpdict.get(tf,"Invalid Argument")
  return tcpflags

def check_protocol(protocol):
  from flowspec.models import MatchProtocol
  if isinstance(protocol,(list)):
    for p in protocol:
      fs = p.find('(')
      prot, created = MatchProtocol.objects.get_or_create(protocol=p[:fs].lower())
      return prot
  else:
    match_protocol = get_protocol(protocol)
    return match_protocol

def assemble_dic(traffic_event,event_info):
  try:
    ip_dest = traffic_event[1]['data'][0][0]; 
    ip_src = traffic_event[0]['data'][0][0] 
    source_port = traffic_event[2]['data'][0][0]; fd = source_port.find(':') ; src_port = source_port[fd+1::] 
    destination_port = traffic_event[3]['data'][0][0]; fn = destination_port.find(':'); dest_port = destination_port[fn+1::]
    p = traffic_event[4]['data'][0][0]; tcp_flag = traffic_event[5]['data'][0][0]
    spt = traffic_event[2]['data'][0][1]; sport = traffic_event[2]['data'][0][0] ; fs = sport.find(':'); srcport = sport[fs+1:]
    dpt = traffic_event[3]['data'][0][1]; dport = traffic_event[3]['data'][0][0] ; fd = dport.find(':'); destport = dport[fd+1:]
    ft = tcp_flag.find('(')
    tcpflag = tcp_flag[:ft]
    if spt > dpt : 
      dic = {'id_attack':event_info['id'],'status':event_info['status'],'typeofattack':event_info['typeof_attack'],'max_value':event_info['max_value'],'th_value':event_info['threshold_value'],
      'attack_name':event_info['attack_name'],'institution_name':event_info['institution_name'],'typeofvalue':event_info['typeof_value'],
      'ip_dest':ip_dest,'ip_src':ip_src,'source_port':src_port,'dest_port':dest_port,'tcp_flag':tcpflag,'port':srcport}
    else:
      dic = {'id_attack':event_info['id'],'status':event_info['status'],'typeofattack':event_info['typeof_attack'],'max_value':event_info['max_value'],'th_value':event_info['threshold_value'],
      'attack_name':event_info['attack_name'],'institution_name':event_info['institution_name'],'typeofvalue':event_info['typeof_value'],
      'ip_dest':ip_dest,'ip_src':ip_src,'source_port':src_port,'dest_port':dest_port,'tcp_flag':tcpflag,'port':destport}
  except Exception as e:
    print('There was an exception when trying to assemble the dictionary for a proposed route.')
  
  return dic


def get_query(routename, dest, src, username):
  from flowspec.models import Route
  route = get_specific_route(applier=username,peer=None,route_slug=routename)
  #route = Route.objects.get(name=routename)
  source = '0/0' if src == '0.0.0.0/0' else src[:-3]
  destination = '0/0' if dest == '0.0.0.0/0' else dest[:-3]
  query = (f'jnxFWCounterByteCount["{source},{destination}"]')
  if route.protocol.values('protocol'):
      prot = route.protocol.values('protocol')        
      value = [k for k in prot]
      p = translate_protocol(value[0]['protocol'])
      protocol = f',proto={p}'
  else:
      protocol = ''
  destport = f',dstport={route.destinationport}' if route.destinationport else ''
  sourceport = f',srcport={route.sourceport}' if route.sourceport else ''
  icmpcode = f',icmp-code={route.icmpcode}' if route.icmpcode else ''
  icmptype = f',icmp-type={route.icmptype}' if route.icmptype else ''
  tcp_flags = route.tcpflag if route.tcpflag else ''
  if route.tcpflag:
    tcp_flags = f',tcp-flag:{translate_tcpflags(route.tcpflag)}'
  p_length =  f',len={route.packetlength}' if route.packetlength else ''
  query = (f'jnxFWCounterByteCount["{destination},{source}{protocol}{destport}{sourceport}{icmpcode}{icmptype}{tcp_flags}{p_length}"]')
  return query

def get_graph_name(routename,dest,src):
  q = get_query(routename,dest,src)
  q1 = q.strip('jnxFWCounterByteCount[')
  q2 = q1.strip(']')
  q3 = q2.strip('"')
  graph_name = (f'FWCounter {q3}') 
  return graph_name

def get_ip_address(ip):
  # 62.204.192.200
  # 193.146.228.27
  import subprocess
  process = subprocess.Popen(["nslookup", ip], stdout=subprocess.PIPE)
  output = str(process.communicate()[0]).split("'")
  try:
    helper = output[1].split("\\t"); h = helper[1].split("\\n")
    address = h[0].split("=")
    return address[1]
  except Exception as e:
    print('There was an error when trying to parse the ip. Error: ',e)
    return ip

#===================================================== Routes helpers
def find_route_pk(applier, pk):
  from flowspec.models import Route, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  route = {
    'Punch': Route.objects.get(id=pk),
    'IMDEA': Route_IMDEA.objects.get(id=pk),
    'CV': Route_CV.objects.get(id=pk),
    'CIB' : Route_CIB.objects.get(id=pk),
    'CSIC' : Route_CSIC.objects.get(id=pk),
    'CEU' : Route_CEU.objects.get(id=pk),
    'CUNEF' : Route_CUNEF.objects.get(id=pk),
    'IMDEA_NET': Route_IMDEANET.objects.get(id=pk),
    'UAM' : Route_UAM.objects.get(id=pk),
    'UC3M' : Route_UC3M.objects.get(id=pk),
    'UCM' : Route_UCM.objects.get(id=pk),
    'UAH' : Route_UAH.objects.get(id=pk),
    'UEM' : Route_UEM.objects.get(id=pk),
    'UNED' : Route_UNED.objects.get(id=pk),
    'UPM' : Route_UPM.objects.get(id=pk),
    'URJC' : Route_URJC.objects.get(id=pk),
  }
  peer_tag = get_peer_tag(applier)
  user_route = route[peer_tag]
  return user_route

def find_routes(applier=None, peer=None):
  from flowspec.models import Route, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  routes = {
    'Punch': Route.objects.all(),
    'IMDEA': Route_IMDEA.objects.all(),
    'CV': Route_CV.objects.all(),
    'CIB' : Route_CIB.objects.all(),
    'CSIC' : Route_CSIC.objects.all(),
    'CEU' : Route_CEU.objects.all(),
    'CUNEF' : Route_CUNEF.objects.all(),
    'IMDEA_NET': Route_IMDEANET.objects.all(),
    'UAM' : Route_UAM.objects.all(),
    'UC3M' : Route_UC3M.objects.all(),
    'UCM' : Route_UCM.objects.all(),
    'UAH' : Route_UAH.objects.all(),
    'UEM' : Route_UEM.objects.all(),
    'UNED' : Route_UNED.objects.all(),
    'UPM' : Route_UPM.objects.all(),
    'URJC' : Route_URJC.objects.all(),
  }
  if not peer: 
    peer_tag = get_peer_tag(applier)
    user_routes = routes[peer_tag]
    return user_routes
  else:
    user_routes = routes[peer]
    return user_routes

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

def get_route(applier,peer):
  from flowspec.models import Route, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  routes = {
    'Punch': Route(),
    'IMDEA': Route_IMDEA(),
    'CV': Route_CV(),
    'CIB' : Route_CIB(),
    'CSIC' : Route_CSIC(),
    'CEU' : Route_CEU(),
    'CUNEF' : Route_CUNEF(),
    'IMDEA_NET': Route_IMDEANET(),
    'UAM' : Route_UAM(),
    'UC3M' : Route_UC3M(),
    'UCM' : Route_UCM(),
    'UAH' : Route_UAH(),
    'UEM' : Route_UEM(),
    'UNED' : Route_UNED(),
    'UPM' : Route_UPM(),
    'URJC' : Route_URJC(),
  }
  if peer==None:
    peer_tag = get_peer_tag(applier)
    user_routes = routes[peer_tag]
    return user_routes
  elif applier==None:
    user_routes = routes[peer]
    return user_routes

def get_edit_route(applier):
  from flowspec.models import Route, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  routes = {
    'Punch': Route,
    'IMDEA': Route_IMDEA,
    'CV': Route_CV,
    'CIB' : Route_CIB,
    'CSIC' : Route_CSIC,
    'CEU' : Route_CEU,
    'CUNEF' : Route_CUNEF,
    'IMDEA_NET': Route_IMDEANET,
    'UAM' : Route_UAM,
    'UC3M' : Route_UC3M,
    'UCM' : Route_UCM,
    'UAH' : Route_UAH,
    'UEM' : Route_UEM,
    'UNED' : Route_UNED,
    'UPM' : Route_UPM,
    'URJC' : Route_URJC,
  }
  peer_tag = get_peer_tag(applier)
  user_routes = routes[peer_tag]
  return user_routes


def find_all_routes():
  from peers.models import Peer
  from flowspec.models import Route, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  peers = Peer.objects.all()
  routes = []
  for peer in peers:
    routes.append(find_routes(applier=None,peer=peer.peer_tag))
  return routes

def find_edit_post_route(applier, data, route_edit):
  from flowspec.forms import RouteForm, Route_IMDEAForm, Route_CVForm, Route_CIBForm, Route_CSICForm, Route_CEUForm, Route_CUNEFForm, Route_IMDEANETForm, Route_UAMForm, Route_UC3MForm, Route_UCMForm, Route_UAHForm, Route_UEMForm, Route_UNEDForm, Route_UPMForm, Route_URJCForm
  route_forms = {
    'Punch': RouteForm(data, instance=route_edit),
    'IMDEA': Route_IMDEAForm(data, instance=route_edit),
    'CV': Route_CVForm(data, instance=route_edit),
    'CIB' : Route_CIBForm(data, instance=route_edit),
    'CSIC' : Route_CSICForm(data, instance=route_edit),
    'CEU' : Route_CEUForm(data, instance=route_edit),
    'CUNEF' : Route_CUNEFForm(data, instance=route_edit),
    'IMDEA_NET': Route_IMDEANETForm(data, instance=route_edit),
    'UAM' : Route_UAMForm(data, instance=route_edit),
    'UC3M' : Route_UC3MForm(data, instance=route_edit),
    'UCM' : Route_UCMForm(data, instance=route_edit),
    'UAH' : Route_UAHForm(data, instance=route_edit),
    'UEM' : Route_UEMForm(data, instance=route_edit),
    'UNED' : Route_UNEDForm(data, instance=route_edit),
    'UPM' : Route_UPMForm(data, instance=route_edit),
    'URJC' : Route_URJCForm(data, instance=route_edit),
  }
  peer_tag = get_peer_tag(applier)
  form_class = route_forms[peer_tag]
  return form_class

def find_get_form(applier):
  from flowspec.forms import RouteForm, Route_IMDEAForm, Route_CVForm, Route_CIBForm, Route_CSICForm, Route_CEUForm, Route_CUNEFForm, Route_IMDEANETForm, Route_UAMForm, Route_UC3MForm, Route_UCMForm, Route_UAHForm, Route_UEMForm, Route_UNEDForm, Route_UPMForm, Route_URJCForm
  route_forms = {
    'Punch': RouteForm(),
    'IMDEA': Route_IMDEAForm(),
    'CV': Route_CVForm(),
    'CIB' : Route_CIBForm(),
    'CSIC' : Route_CSICForm(),
    'CEU' : Route_CEUForm(),
    'CUNEF' : Route_CUNEFForm(),
    'IMDEA_NET': Route_IMDEANETForm(),
    'UAM' : Route_UAMForm(),
    'UC3M' : Route_UC3MForm(),
    'UCM' : Route_UCMForm(),
    'UAH' : Route_UAHForm(),
    'UEM' : Route_UEMForm(),
    'UNED' : Route_UNEDForm(),
    'UPM' : Route_UPMForm(),
    'URJC' : Route_URJCForm(),
  }
  peer_tag = get_peer_tag(applier)
  form_class = route_forms[peer_tag]
  return form_class

def find_post_form(applier, data):
  from flowspec.forms import RouteForm, Route_IMDEAForm, Route_CVForm, Route_CIBForm, Route_CSICForm, Route_CEUForm, Route_CUNEFForm, Route_IMDEANETForm, Route_UAMForm, Route_UC3MForm, Route_UCMForm, Route_UAHForm, Route_UEMForm, Route_UNEDForm, Route_UPMForm, Route_URJCForm
  route_forms = {
    'Punch': RouteForm(data),
    'IMDEA': Route_IMDEAForm(data),
    'CV': Route_CVForm(data),
    'CIB' : Route_CIBForm(data),
    'CSIC' : Route_CSICForm(data),
    'CEU' : Route_CEUForm(data),
    'CUNEF' : Route_CUNEFForm(data),
    'IMDEA_NET': Route_IMDEANETForm(data),
    'UAM' : Route_UAMForm(data),
    'UC3M' : Route_UC3MForm(data),
    'UCM' : Route_UCMForm(data),
    'UAH' : Route_UAHForm(data),
    'UEM' : Route_UEMForm(data),
    'UNED' : Route_UNEDForm(data),
    'UPM' : Route_UPMForm(data),
    'URJC' : Route_URJCForm(data),
  }
  peer_tag = get_peer_tag(applier)
  form_class = route_forms[peer_tag]
  return form_class

def get_instance_form(applier, route):
  from flowspec.forms import RouteForm, Route_IMDEAForm, Route_CVForm, Route_CIBForm, Route_CSICForm, Route_CEUForm, Route_CUNEFForm, Route_IMDEANETForm, Route_UAMForm, Route_UC3MForm, Route_UCMForm, Route_UAHForm, Route_UEMForm, Route_UNEDForm, Route_UPMForm, Route_URJCForm
  peer_tag = get_peer_tag(applier)
  route_form = {
    'Punch' : RouteForm(instance = route),
    'IMDEA' : Route_IMDEAForm(instance = route),
    'CV': Route_CVForm(instance=route),
    'CIB' : Route_CIBForm(instance=route),
    'CSIC' : Route_CSICForm(instance=route),
    'CEU' : Route_CEUForm(instance=route),
    'CUNEF' : Route_CUNEFForm(instance=route),
    'IMDEA_NET': Route_IMDEANETForm(instance=route),
    'UAM' : Route_UAMForm(instance=route),
    'UC3M' : Route_UC3MForm(instance=route),
    'UCM' : Route_UCMForm(instance=route),
    'UAH' : Route_UAHForm(instance=route),
    'UEM' : Route_UEMForm(instance=route),
    'UNED' : Route_UNEDForm(instance=route),
    'UPM' : Route_UPMForm(instance=route),
    'URJC' : Route_URJCForm(instance=route),
  }
  route = route_form[peer_tag]
  return route

def get_specific_route(applier,peer, route_slug):
  from peers.models import Peer
  from flowspec.models import Route, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  peers = Peer.objects.all()
  if not applier == None:
    peer_tag = get_peer_tag(applier)
  if not peer == None:
    peer_tag = peer
  if peer == None and applier == None:
    fd = route_slug.find('_')
    peer_tag = route_slug[fd+1:-2]
  for r in peers:
    if peer_tag == 'IMDEA': 
      try:
        route = Route_IMDEA.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
          print('There has been an error')
    elif peer_tag == 'CV':
      try:
        route = Route_CV.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'CIB':
      try:
        route = Route_CIB.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'CSIC':
      try:
        route = Route_CSIC.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'CEU':
      try:
        route = Route_CEU.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'CUNEF':
      try:
        route = Route_CUNEF.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'IMDEA_NET':
      try:
        route = Route_IMDEANET.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'UAM':
      try:
        route = Route_UAM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'UC3M':
      try:
        route = Route_UC3M.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'UCM':
      try:
        route = Route_UCM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'UAH':
      try:
        route = Route_UAH.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'UEM':
      try:
        route = Route_UEM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'UNED':
      try:
        route = Route_UNED.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'UPM':
      try:
        route = Route_UPM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'URJC':
      try:
        route = Route_URJC.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')
    elif peer_tag == 'Punch':
      try:
        route = Route.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        print('There has been an error')

  

def get_specific_route_pk(username, pk):
  from peers.models import Peer
  from flowspec.models import Route, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  peers = Peer.objects.all()
  peer_tag = get_peer_tag(username)
  check = True
  while check:
    for r in peers:
      if peer_tag == 'IMDEA': 
        try:
          route = Route_IMDEA.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'CV':
        try:
          route = Route_CV.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'CIB':
        try:
          route = Route_CIB.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'CSIC':
        try:
          route = Route_CSIC.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'CEU':
        try:
          route = Route_CEU.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'CUNEF':
        try:
          route = Route_CUNEF.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'IMDEA_NET':
        try:
          route = Route_IMDEANET.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'UAM':
        try:
          route = Route_UAM.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'UC3M':
        try:
          route = Route_UC3M.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'UCM':
        try:
          route = Route_UCM.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'UAH':
        try:
          route = Route_UAH.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'UEM':
        try:
          route = Route_UEM.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'UNED':
        try:
          route = Route_UNED.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'UPM':
        try:
          route = Route_UPM.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'URJC':
        try:
          route = Route_URJC.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'Punch':
        try:
          route = Route.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
#============================================ 

def find_peer(peer_name):
  from peers.models import Peer
  find = peer_name.find('_')
  pn = peer_name[find+1::]
  print('pn: ',pn,' peer_name: ',peer_name)
  peers = ['CV', 'CIB', 'CSIC', 'CEU', 'CUNEF', 'IMDEA_NET', 'IMDEA', 'UAM', 'UC3M', 'UCM', 'UAH', 'UEM', 'UNED', 'UPM', 'URJC']
  for peer in peers:
    if peer_name == 'punch.software.imdea.org':
      return Peer.objects.get(peer_name='Punch')
    elif peer_name == 'CASA VELAZQUEZ':
      return Peer.objects.get(peer_tag='CV')
    elif peer_name == 'IMDEA NETWORKS':
      return Peer.objects.get(peer_name='IMDEA NETWORKS')
    elif peer_name == 'REDIMADRID':
      return Peer.objects.get(peer_name='REM_IMDEA')
    elif peer_name == 'CEU(2)' or peer_name == 'CEU':
      return Peer.objects.get(peer_name='CEU')
    elif peer_name == 'UEM':
      return Peer.objects.get(peer_tag='UEM')
    elif peer_name == 'URJC':
      return Peer.objects.get(peer_tag='URJC')
    elif peer_name == 'UNED':
      return Peer.objects.get(peer_tag='UNED')
    elif peer_name == 'UAH':
      return Peer.objects.get(peer_tag='UAH')
    elif peer_name == 'CSIC':
      return Peer.objects.get(peer_tag='CSIC')
    elif peer_name == 'CIB':
      return Peer.objects.get(peer_tag='CIB')
    elif peer_name == 'CUNEF':
      return Peer.objects.get(peer_tag='CUNEF')
    elif peer_name == 'UC3M':
      return Peer.objects.get(peer_tag='UC3M')
    elif peer_name == 'CSIC':
      return Peer.objects.get(peer_tag='CSIC')
    elif peer_name == 'UCM':
      return Peer.objects.get(peer_tag='UCM')
    elif peer_name == 'UAM':
      return Peer.objects.get(peer_tag='UAM')
    elif peer_name == 'UPM':
      return Peer.objects.get(peer_tag='UPM')
    elif peer == pn:
      return Peer.objects.get(peer_name=peer) 
    elif peer in pn or pn in peer:
      return Peer.objects.get(peer_tag=peer)
    else:
      print(f'The following institution is not connected to REM-E-DDOS {peer_name}')
      return False 

       

def graphs(timefrom,timetill, routename, username):
  from flowspec.models import Route
  zapi = ZabbixAPI(ZABBIX_SOURCE)
  zapi.login(ZABBIX_USER,ZABBIX_PWD)
  route = get_object_or_404(get_edit_route(username), name=routename)
  query = get_query(route.name, route.destination, route.source, username)
  #in order to access history log we need to send the dates as timestamp
  if not timefrom=='' and not timetill=='':
    from_date_obj = datetime.datetime.strptime(timefrom,"%Y/%m/%d %H:%M")
    till_date_obj = datetime.datetime.strptime(timetill,"%Y/%m/%d %H:%M")

    ts_from = int(from_date_obj.timestamp())
    ts_till = int(till_date_obj.timestamp())
    #query for getting the itemid and the hostid
    item = zapi.do_request(method='item.get', params={"output": "extend","search": {"key_":query}})
    item_id = [i['itemid'] for i in item['result']]
    hostid = [i['hostid'] for i in item['result']]
    print('host ',from_date_obj,till_date_obj)
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
  else:
    beats_date, beats_hour, beat_value, beats_values, beats_fulltime = get_default_graph(routename)
    return beats_date, beats_hour, beat_value, beats_values, beats_fulltime


def get_default_graph(routename, username):
  from flowspec.models import Route
  zapi = ZabbixAPI(ZABBIX_SOURCE)
  zapi.login(ZABBIX_USER,ZABBIX_PWD)
  route = get_object_or_404(get_edit_route(username), name=routename)
  query = get_query(route.name, route.destination, route.source, username)

  item = zapi.do_request(method='item.get', params={"output": "extend","search": {"key_":query}})
  item_id = [i['itemid'] for i in item['result']]
  hostid = [i['hostid'] for i in item['result']]

  now = datetime.datetime.now() 
  yesterday = datetime.datetime.now() - timedelta(1)
  ts_from = int(yesterday.timestamp())
  ts_till = int(now.timestamp())
    
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


#============== back up code

def create_db_backup():
  from django.core.management import call_command
  now = datetime.datetime.now()
  current_time = now.strftime("%H:%M")
  current_date = now.strftime("%d-%B-%Y")
  call_command('dumpdata', format='json',output=f'_backup/FOD/FOD_backup_{current_date}_{current_time}.json')
    #call_command('dbbackup', output_filename=(f"redifod-{current_date}-{current_time}.psql"))
  message = 'Copia de seguridad creada con éxito.'
  print(message)
    
def restore_db_backup():
  from django.core.management import call_command
  now = datetime.datetime.now()
  call_command('dumpdata', output_filename=("_backup/FOD/FOD_backup_08-March-2022_16:39.json"))
  message = 'Succesfull restore.'
  print(message)