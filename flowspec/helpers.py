from django.core.mail import send_mail
from django.conf import settings
from accounts.models import *
from flowspy.settings import *
from peers.models import PeerNotify 
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
from peers.models import *
import bisect


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

def send_new_mail(subject, message, recipient_list, bcc_list):
  from_email='remeddos@software.imdea.org'
  try:
    logger.info("helpers::send_new_mail(): send mail: from_email="+str(from_email)+", recipient_list="+str(recipient_list)+", bcc_list="+str(bcc_list)) 
    #i have removed the bbc_list just for now
    return send_mail(subject, message, from_email, recipient_list)
  except Exception as e:
    #os.write(3, "send_new_mail() failed: exc="+str(e)+"\n") 
    logger.error("helpers::send_new_mail() failed: exc="+str(e)) 


def send_message(message, peer=None, superuser=False):
  slack_channels = {'CEU':'C03GQM0MN0K','CIB':'C03GA4HK8FR','CSIC':'C03HEF23RAL','CUNEF':'C03H3B3G3G9','CV':'C03GQMFQ519','IMDEA':'C03H3B7GBND','IMDEANET':'C03GJ3M124E',
  'Punch':'C03H3B7GBND','UAH':'C03H3B9BTGR','UAM':'C03GQML0JP5','UC3M':'C03GQN6P9MG','UCM':'C03GJ3RENLE','UEM':'C03H3BE7EBB',
  'UNED':'C03GA56STTR','UPM':'C03GJ3W32KY', 'URJC':'C03GJ3X931C','REM':'C03H3B7GBND', 'RediMadrid':'C03H3B7GBND'}
  # if there is no peer, the message will be sent to the default testing slack channel, the one used for redimadrid staff
  if not peer or superuser:
    client = slack.WebClient(token=settings.SLACK_TOKEN)
    client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)
  else:
    channel = slack_channels[peer]
    client = slack.WebClient(token=settings.REM_SLACK_TOKEN)
    client.chat_postMessage(channel=channel, text=message) 


#  find peer tag based on a routename 
def get_peer_with_name(routename):
  peers = Peer.objects.all()
  fd = routename.find('_')
  peer_name = '' 
  if routename[fd::][-1].isnumeric():
    helper = routename[fd+1::]
    fd1 = helper.find('_')
    peer_name = helper[:fd1]
  else:
    n = routename[fd+1::]
    fd1 = n.find('_')
    peer_name = n[fd1+1::]
  if any(peer_name in i.peer_tag for i in peers):
    return peer_name
  else:
    return False

# get peer object
def get_peers(username):
  user = User.objects.get(username=username)
  up = UserProfile.objects.get(user=user)
  peers = up.peers.all()
  peername = ''
  for peer in peers:
    peername = peer.peer_name
  return peername

#  find peer tag based on a username
def get_peer_tag(username):
  user = User.objects.get(username=username)
  up = UserProfile.objects.get(user=user)
  peers = up.peers.all()
  for peer in peers:
    peer_tag = peer.peer_tag
  return peer_tag


  # method for finding golem pop up  
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
        stdin, stdout, stderr = ssh.exec_command(f'grep {id_golem} /var/log/remote/{settings.DIR_GOLEM}/`date +%Y-%m-%d`.log')
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
      link = False
      logger.info('There was an error when trying to read the configuration file: ',e)
      return link
  except Exception as e:
    link = False
    logger.info('There was an error when trying to connect via ssh.')
    return link
    


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


# retrieve files from backup dir
def get_back_up_files():
  files = []
  for f in os.listdir(settings.BACK_UP_DIR):
    files.append(f)
  return files

#============== back up code

def create_db_backup():
  from django.core.management import call_command
  now = datetime.datetime.now()
  current_time = now.strftime("%H:%M")
  current_date = now.strftime("%d-%B-%Y")
  call_command('dumpdata', format='json',output=f'_backup/FOD/FOD_backup_{current_date}_{current_time}.json')
    #call_command('dbbackup', output_filename=(f"redifod-{current_date}-{current_time}.psql"))
  message = 'Copia de seguridad creada con éxito.'
  logger.info(message)
    
def restore_db_backup():
  from django.core.management import call_command
  now = datetime.datetime.now()
  call_command('dumpdata', output_filename=("_backup/FOD/FOD_backup_08-March-2022_16:39.json"))
  message = 'Succesfull restore.'
  logger.info(message)



## methods for parsing or checking data exist in db for when collecting info from either zabbix or rem_golem


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
  tcpflags = tcpflag_dict.get(tf,False)
  return tcpflags

def golem_translate_tcpflag(tf):
  tcpf = {'-----F':'fin', '----S-':'syn', '----SF':'syn fin', '---R--':'rst', '---R-F':'rst fin', '---RS-':'rst syn', '---RSF':'rst syn fin', '--P---':'push', '--P--F':'push fin', '--P-S-':'push syn', '--P-SF':'push syn fin', '--PR--':'push rst', '--PR-F':'push rst fin', '--PRS-':'push rst syn', '--PRSF':'push rst syn fin',
  '-A----':'ack', '-A---F':'ack fin', '-A--S-':'ack syn', '-A--SF':'19', 'ack syn fin':'ack rst', '-A-R-F':'ack rst fin', '-A-RS-':'ack rst syn', '-A-RSF':'ack rst syn fin', '-AP---':'ack push', '-AP--F':'ack push fin', '-AP-S-':'ack push syn', '-AP-SF':'ack push syn fin', '-APR--':'ack push rst', '-APR-F':'ack push rst fin', '-APRS-':'ack push rst syn',
  '-APRSF':'ack push rst syn fin'}
  tcpflags = tcpf.get(tf,False)
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


def get_ip_address(ip):
  import subprocess
  process = subprocess.Popen(["nslookup", ip], stdout=subprocess.PIPE)
  output = str(process.communicate()[0]).split("'")
  try:
    helper = output[1].split("\\t")
    h = helper[1].split("\\n")
    address = h[0].split("=")
    return address[1]
  except Exception as e:
    logger.info(f"There was an error when trying to parse the ip. Error: {e}")
    return ip


""" Graph's, Zabbix helpers """
  # first we find the route we need for the zabbix query, then we check which parameters we need in order to get the full query
  # and then we assemble it

def parse_destport_zbx(destinationport):
  if not ',' in destinationport:
    destport = f',dstport={destinationport}'
    return destport 
  else:
    destportlist = destinationport.split(',')
    top = len(destportlist)
    i = 0
    destport = ',dstport'
    for port in destportlist:
      i+=1
      if i == top:
        destport = destport + "=%s"%(port)
      else:
        destport = destport + "=%s,"%(port)
    return destport

def parse_srcport_zbx(sourceport):
  if not ',' in sourceport:
    sourceport = f',srcport={sourceport}'
    return sourceport
  else:
    sourceportlist = sourceport.split(',')
    top = len(sourceportlist)
    i = 0
    sourceport = ',srcport'
    for port in sourceportlist:
      i+=1
      if i == top:
        sourceport = sourceport + "=%s"%(port)
      else:
        sourceport = sourceport + "=%s,"%(port)
    return sourceport

def parse_ports_zbx(ports):
  if '-' in ports:
    ports = ports.split('-')
    port = ''
  if ports[0] < ports[1]:
    port = f',port>={ports[0]}&<={ports[1]}'
    return port
  else:
    port = f',port>={ports[1]}&<={ports[0]}' 
    return port
  

def parse_packetlen(packetlength):
  if not ',' in packetlength and not '-' in packetlength:
    plength = f',len={packetlength}'
    return plength
  else:
    if ',' in packetlength:
      plengthlist = packetlength.split(',')
      top = len(plengthlist)
      i = 0
      plength = ',len'
      for pl in plengthlist:
        i+=1
        if i == top:
          plength = plength + "=%s"%(pl)
        else:
          plength = plength + "=%s,"%(pl)
      return plength
    if '-' in packetlength:
      plengthlist = packetlength.split('-')
      top = len(plengthlist)
      i = 0
      plength = ',len'
      for pl in plengthlist:
        i+=1
        if i == top:
          plength = plength + "=%s"%(pl)
        else:
          plength = plength + "=%s,"%(pl)
      return plength

def get_query(routename, dest, src, username):
  route = get_specific_route(applier=username,peer=None,route_slug=routename)
  hd = dest.find('/') ; barra_dest = int(dest[1+hd:]) ; destination = '' 
  hs = src.find('/') ; barra_src = int(src[1+hs:]) ; source = ''

  if src == '0.0.0.0/0':
    source = '0/0'

  if hs == -1 and hd == -1:
    source = src
    destination = dest
  
  if src.endswith('/32'):
    source = src[:-3]
  elif isinstance(barra_src,int) and barra_src >= 25 and barra_src < 32:
    source = src
  elif isinstance(barra_src,int) and barra_src >= 17 and barra_src < 24:
    if src[:-3].endswith('.0'):
      source = src.replace('.0','')
  elif isinstance(barra_src,int) and barra_src == 16:
    if src[:-3].endswith('.0.0'):
      source = src.replace('.0','')

  if dest.endswith('/32'):
    destination = dest[:-3]
  if isinstance(barra_dest,int) and barra_dest >= 25 and barra_dest < 32:
    destination = dest
  if isinstance(barra_dest,int) and barra_dest >= 17 and barra_dest < 24:
    if dest[:-3].endswith('.0'):
      destination = dest.replace('.0','')
  if int(barra_dest) == 16:
    if dest[:-3].endswith('.0.0'):
      destination = dest.replace('.0','')

  # incluir solo /32, sino quitar las reglas
  query = (f'jnxFWCounterByteCount["{source},{destination}"]')
  if route.protocol.values('protocol'):
      prot = route.protocol.values('protocol')        
      value = [k for k in prot]
      p = translate_protocol(value[0]['protocol'])
      protocol = f',proto={p}'
  else:
      protocol = ''

  if route.port:
    port = parse_ports_zbx(route.port)
    destport = ''
    sourceport = ''
  else:
    port = ''
    destport = parse_destport_zbx(route.destinationport) if route.destinationport else ''
    sourceport = parse_srcport_zbx(route.sourceport) if route.sourceport else ''
    

  icmpcode = f',icmp-code={route.icmpcode}' if route.icmpcode else ''
  icmptype = f',icmp-type={route.icmptype}' if route.icmptype else ''
  tcp_flags = ',tcp-flag'
  
  # Query's example for zabbix: 1.1.1.1,2.2.2.2,proto=6,=1,=17,dstport=67,=93,=45,srcport=45,=56,=92,tcp-flag:10,:01,:08,len=1234,=1345,=1567
  if route.tcpflag.all():
    for count, flag in enumerate(route.tcpflag.all()):
      if not (count+1 == len(route.tcpflag.all())):
        tcp_flags = tcp_flags + ":%s,"%(translate_tcpflags(flag.flag))
      else:
        tcp_flags = tcp_flags + ":%s"%(translate_tcpflags(flag.flag))

  p_length = parse_packetlen(route.packetlength) if route.packetlength else ''
  
  if route.tcpflag.all():
    query = (f'jnxFWCounterByteCount["{destination},{source}{protocol}{destport}{sourceport}{port}{icmpcode}{icmptype}{tcp_flags}{p_length}"]')
  else:
    query = (f'jnxFWCounterByteCount["{destination},{source}{protocol}{destport}{sourceport}{port}{icmpcode}{icmptype}{p_length}"]')
  return query

def get_graph_name(routename,dest,src):
  q = get_query(routename,dest,src)
  q1 = q.strip('jnxFWCounterByteCount[')
  q2 = q1.strip(']')
  q3 = q2.strip('"')
  graph_name = (f'FWCounter {q3}') 
  return graph_name

def graphs(timefrom,timetill, routename, username):
  zapi = ZabbixAPI(ZABBIX_SOURCE)
  zapi.login(ZABBIX_USER,ZABBIX_PWD)
  route = get_object_or_404(get_edit_route(username, routename), name=routename)
  query = get_query(route.name, route.destination, route.source, username)
  #in order to access history log we need to send the dates as timestamp
  
  if not timefrom == '' and not timetill =='':
    tm_from = timefrom.replace('T',' ')
    tm_till = timetill.replace('T',' ')
    from_date_obj = datetime.datetime.strptime(tm_from,"%Y-%m-%d %H:%M")
    till_date_obj = datetime.datetime.strptime(tm_till,"%Y-%m-%d %H:%M")
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
      beats_date.append(y.strftime("%d-%m"))
      beats_fulltime.append(y.strftime("%d-%m %H:%M"))
      beats_hour.append(y.strftime("%H:%M"))
    
    beats_values = dict(zip(beats_hour,beat_value))

    return beats_date, beats_hour, beat_value, beats_values, beats_fulltime
  else:
    beats_date, beats_hour, beat_value, beats_values, beats_fulltime = get_default_graph(routename)
    return beats_date, beats_hour, beat_value, beats_values, beats_fulltime, clock_value


def get_default_graph(routename, username):
  zapi = ZabbixAPI(ZABBIX_SOURCE)
  zapi.login(ZABBIX_USER,ZABBIX_PWD)
  route = get_object_or_404(get_edit_route(username, routename), name=routename)
  query = get_query(route.name, route.destination, route.source, username)

  item = zapi.do_request(method='item.get', params={"output": "extend","search": {"key_":query}})
  item_id = [i['itemid'] for i in item['result']]
  hostid = [i['hostid'] for i in item['result']]

  now = datetime.datetime.now() 
  yesterday = datetime.datetime.now() - timedelta(1)
  ts_from = int(yesterday.timestamp())
  ts_till = int(now.timestamp())
    
  item_history = zapi.history.get(hostids=hostid,itemids=item_id,time_from=ts_from,time_till=ts_till)
  
  beats_date = []
  beats_hour = [] 
  clock_value = []
  beat_value = []
  beats_fulltime = []
  beats_values = []
  i = 0 
  
  for x in item_history:
    y = datetime.datetime.fromtimestamp(int(x['clock']))
    """ y = x['clock'] """
    if i == 60:
      """ bisect.insort(clock_value,y.isoformat(sep='T', timespec='auto')) """ 
      """beats_fulltime.append(y.strftime("%H:%M %d-%B"))"""
      bisect.insort(clock_value,y.strftime("%d-%b %H:%M"))
      beat_value.append(x['value'])
      i = 0
    if i!= 60 and x['value'] !=  '0' :

      """ bisect.insort(clock_value,y.isoformat(sep='T', timespec='auto')) """
      bisect.insort(clock_value,y.strftime("%d-%b %H:%M "))
      beat_value.append(x['value'])
    
    i+=1  
  beats_values = list(zip(beats_hour,beat_value))
  # 2018-12-30T20:59
  beats_fulltime.sort()
  bvalues = list(beats_values)
  return beats_date, beats_hour, beat_value, list(bvalues), clock_value



""" Route helpers """

def find_route_pk(applier, pk):
  from flowspec.models import Route_Punch,Route_REM, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  route = {
  'Punch': Route_Punch.objects.get(id=pk),'REM':Route_REM.objects.get(id=pk) , 'IMDEA': Route_IMDEA.objects.get(id=pk), 'CV': Route_CV.objects.get(id=pk), 'CIB' : Route_CIB.objects.get(id=pk),'CSIC' : Route_CSIC.objects.get(id=pk),
  'CEU' : Route_CEU.objects.get(id=pk),'CUNEF' : Route_CUNEF.objects.get(id=pk),'IMDEANET': Route_IMDEANET.objects.get(id=pk), 'UAM' : Route_UAM.objects.get(id=pk),'UC3M' : Route_UC3M.objects.get(id=pk),
    'UCM' : Route_UCM.objects.get(id=pk),'UAH' : Route_UAH.objects.get(id=pk),'UEM' : Route_UEM.objects.get(id=pk),'UNED' : Route_UNED.objects.get(id=pk),'UPM' : Route_UPM.objects.get(id=pk),'URJC' : Route_URJC.objects.get(id=pk),
  }
  peer_tag = get_peer_tag(applier)
  user_route = route[peer_tag]
  return user_route

def find_routes(applier=None, peer=None):
  from flowspec.models import Route_Punch,Route_REM, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  routes = {
    'Punch': Route_Punch.objects.all(),
    'REM' : Route_REM.objects.all(),
    'IMDEA': Route_IMDEA.objects.all(),
    'CV': Route_CV.objects.all(),
    'CIB' : Route_CIB.objects.all(),
    'CSIC' : Route_CSIC.objects.all(),
    'CEU' : Route_CEU.objects.all(),
    'CUNEF' : Route_CUNEF.objects.all(),
    'IMDEANET': Route_IMDEANET.objects.all(),
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

def get_routes_backuprouter():
    retriever = Backup_Retriever()
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
  from flowspec.models import Route_Punch,Route_REM, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  routes = {
    'Punch': Route_Punch(),
    'REM' : Route_REM(),
    'IMDEA': Route_IMDEA(),
    'CV': Route_CV(),
    'CIB' : Route_CIB(),
    'CSIC' : Route_CSIC(),
    'CEU' : Route_CEU(),
    'CUNEF' : Route_CUNEF(),
    'IMDEANET': Route_IMDEANET(),
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

def get_edit_route(applier,rname):
  from flowspec.models import Route_Punch,Route_REM, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  routes = {
    'Punch': Route_Punch,
    'REM' : Route_REM,
    'IMDEA': Route_IMDEA,
    'CV': Route_CV,
    'CIB' : Route_CIB,
    'CSIC' : Route_CSIC,
    'CEU' : Route_CEU,
    'CUNEF' : Route_CUNEF,
    'IMDEANET': Route_IMDEANET,
    'UAM' : Route_UAM,
    'UC3M' : Route_UC3M,
    'UCM' : Route_UCM,
    'UAH' : Route_UAH,
    'UEM' : Route_UEM,
    'UNED' : Route_UNED,
    'UPM' : Route_UPM,
    'URJC' : Route_URJC,
  } 
  peer_tag = get_peer_with_name(rname)
  user_routes = routes[peer_tag]
  return user_routes


def find_all_routes():
  from peers.models import Peer

  peers = Peer.objects.all()
  routes = []
  try:
    for peer in peers:
      routes.append(find_routes(applier=None,peer=peer.peer_tag))
  except Exception as e:
    pass
  return routes

def find_edit_post_route(applier, data, route_edit):
  from flowspec.forms import Route_PunchForm,Route_REMForm, Route_IMDEAForm, Route_CVForm, Route_CIBForm, Route_CSICForm, Route_CEUForm, Route_CUNEFForm, Route_IMDEANETForm, Route_UAMForm, Route_UC3MForm, Route_UCMForm, Route_UAHForm, Route_UEMForm, Route_UNEDForm, Route_UPMForm, Route_URJCForm
  route_forms = {
    'Punch': Route_PunchForm(data, instance=route_edit),
    'REM' : Route_REMForm(data, instance=route_edit),
    'IMDEA': Route_IMDEAForm(data, instance=route_edit),
    'CV': Route_CVForm(data, instance=route_edit),
    'CIB' : Route_CIBForm(data, instance=route_edit),
    'CSIC' : Route_CSICForm(data, instance=route_edit),
    'CEU' : Route_CEUForm(data, instance=route_edit),
    'CUNEF' : Route_CUNEFForm(data, instance=route_edit),
    'IMDEANET': Route_IMDEANETForm(data, instance=route_edit),
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
  from flowspec.forms import Route_PunchForm,Route_REMForm, Route_IMDEAForm, Route_CVForm, Route_CIBForm, Route_CSICForm, Route_CEUForm, Route_CUNEFForm, Route_IMDEANETForm, Route_UAMForm, Route_UC3MForm, Route_UCMForm, Route_UAHForm, Route_UEMForm, Route_UNEDForm, Route_UPMForm, Route_URJCForm
  route_forms = {
    'Punch': Route_PunchForm(),
    'REM': Route_REMForm(),
    'IMDEA': Route_IMDEAForm(),
    'CV': Route_CVForm(),
    'CIB' : Route_CIBForm(),
    'CSIC' : Route_CSICForm(),
    'CEU' : Route_CEUForm(),
    'CUNEF' : Route_CUNEFForm(),
    'IMDEANET': Route_IMDEANETForm(),
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
  from flowspec.forms import Route_PunchForm, Route_REMForm, Route_IMDEAForm, Route_CVForm, Route_CIBForm, Route_CSICForm, Route_CEUForm, Route_CUNEFForm, Route_IMDEANETForm, Route_UAMForm, Route_UC3MForm, Route_UCMForm, Route_UAHForm, Route_UEMForm, Route_UNEDForm, Route_UPMForm, Route_URJCForm
  route_forms = {
    'Punch': Route_PunchForm(data),
    'REM': Route_REMForm(data),
    'IMDEA': Route_IMDEAForm(data),
    'CV': Route_CVForm(data),
    'CIB' : Route_CIBForm(data),
    'CSIC' : Route_CSICForm(data),
    'CEU' : Route_CEUForm(data),
    'CUNEF' : Route_CUNEFForm(data),
    'IMDEANET': Route_IMDEANETForm(data),
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
  from flowspec.forms import Route_PunchForm, Route_REMForm, Route_IMDEAForm, Route_CVForm, Route_CIBForm, Route_CSICForm, Route_CEUForm, Route_CUNEFForm, Route_IMDEANETForm, Route_UAMForm, Route_UC3MForm, Route_UCMForm, Route_UAHForm, Route_UEMForm, Route_UNEDForm, Route_UPMForm, Route_URJCForm
  peer_tag = get_peer_tag(applier)
  route_form = {
    'Punch' : Route_PunchForm(instance = route),
    'REM' : Route_REMForm(instance = route),
    'IMDEA' : Route_IMDEAForm(instance = route),
    'CV': Route_CVForm(instance=route),
    'CIB' : Route_CIBForm(instance=route),
    'CSIC' : Route_CSICForm(instance=route),
    'CEU' : Route_CEUForm(instance=route),
    'CUNEF' : Route_CUNEFForm(instance=route),
    'IMDEANET': Route_IMDEANETForm(instance=route),
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
  from flowspec.models import Route_Punch,Route_REM, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
  peers = Peer.objects.all()
  peer_tag = get_peer_with_name(route_slug)
  for r in peers:
    if peer_tag == 'IMDEA': 
      try:
        route = Route_IMDEA.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
          logger.info('There has been an error when trying to find the route')
          return None
    if peer_tag == 'CV':
      try:
        route = Route_CV.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'CIB':
      try:
        route = Route_CIB.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'CSIC':
      try:
        route = Route_CSIC.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'CEU':
      try:
        route = Route_CEU.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'CUNEF':
      try:
        route = Route_CUNEF.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'IMDEANET':
      try:
        route = Route_IMDEANET.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'UAM':
      try:
        route = Route_UAM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'UC3M':
      try:
        route = Route_UC3M.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'UCM':
      try:
        route = Route_UCM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'UAH':
      try:
        route = Route_UAH.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'UEM':
      try:
        route = Route_UEM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'UNED':
      try:
        route = Route_UNED.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'UPM':
      try:
        route = Route_UPM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'URJC':
      try:
        route = Route_URJC.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')
        return None
    if peer_tag == 'REM':
      try:
        route = Route_REM.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route')  
        return None  
    if peer_tag == 'Punch':
      try:
        route = Route_Punch.objects.get(name=route_slug)
        return route
      except ObjectDoesNotExist:
        logger.info('There has been an error when trying to find the route. Object does not exist.')
        return None

  

def get_specific_route_pk(username, pk):
  from peers.models import Peer
  from flowspec.models import Route_Punch,Route_REM, Route_CV, Route_IMDEA, Route_CIB, Route_CSIC, Route_CEU, Route_CUNEF, Route_IMDEANET,Route_UAM, Route_UC3M, Route_UCM, Route_UAH ,Route_UEM, Route_UNED, Route_UPM, Route_URJC
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
      elif peer_tag == 'IMDEANET':
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
          route = Route_Punch.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
      elif peer_tag == 'REM':
        try:
          route = Route_REM.objects.get(id=pk)
          check = False
          return route
        except ObjectDoesNotExist:
          check = True
#============================================ 

def find_peer(peer_name):
  from peers.models import Peer
  find = peer_name.find('_')
  pn = peer_name[find+1::]
  peers = Peer.objects.all()
  for peer in peers:
    if peer_name == 'punch.software.imdea.org' or peer_name == 'punch2.software.imdea.org' or peer_name == 'punch2.software.imdea.org(2)':
      return Peer.objects.get(peer_name='Punch')
    elif peer_name == 'CASA VELAZQUEZ' or peer_name == 'CASA VELAZQUEZ(2)' :
      return Peer.objects.get(peer_tag='CV')
    elif peer_name == 'IMDEA_NETWORK' or peer_name == 'IMDEA_NETWORK(2)':
      return Peer.objects.get(peer_name='IMDEA Networks')
    elif peer_name == 'REDIMADRID' or peer_name == 'REDIMADRID(2)':
      return Peer.objects.get(peer_name='RediMadrid')
    elif peer_name == 'CEU(2)' or peer_name == 'CEU':
      return Peer.objects.get(peer_name='CEU')
    elif peer_name == 'UEM' or peer_name == 'UEM(2)':
      return Peer.objects.get(peer_tag='UEM')
    elif peer_name == 'URJC' or peer_name == 'URJC(2)':
      return Peer.objects.get(peer_tag='URJC')
    elif peer_name == 'UNED' or peer_name == 'UNED(2)':
      return Peer.objects.get(peer_tag='UNED')
    elif peer_name == 'UAH' or peer_name == 'UAH(2)':
      return Peer.objects.get(peer_tag='UAH')
    elif peer_name == 'CSIC' or peer_name == 'CSIC(2)':
      return Peer.objects.get(peer_tag='CSIC')
    elif peer_name == 'CIB' or peer_name == 'CIB(2)':
      return Peer.objects.get(peer_tag='CIB')
    elif peer_name == 'CUNEF' or peer_name == 'CUNEF(2)':
      return Peer.objects.get(peer_tag='CUNEF')
    elif peer_name == 'UC3M' or peer_name == 'UC3M(2)' or peer_name=='NAT_UC3M' or peer_name=='NAT_UC3M(2)':
      return Peer.objects.get(peer_tag='UC3M')
    elif peer_name == 'CSIC' or peer_name == 'CSIC(2)':
      return Peer.objects.get(peer_tag='CSIC')
    elif peer_name == 'UCM' or peer_name == 'UCM(2)':
      return Peer.objects.get(peer_tag='UCM')
    elif peer_name == 'UAM' or peer_name == 'UAM(2)':
      return Peer.objects.get(peer_tag='UAM')
    elif peer_name == 'UPM' or peer_name == 'UPM(2)':
      return Peer.objects.get(peer_tag='UPM')
    elif peer == pn:
      return Peer.objects.get(peer_name=peer) 
    else:
      logger.info(f'The following institution is not connected to REM-E-DDOS {peer_name}')
      return False 

""" finds route missing in db and saves it  """

def find_match_route_config_router(routename):
  from flowspec.models import MatchProtocol, TcpFlag, ThenAction
  import datetime


  tomorrow = (datetime.date.today() + datetime.timedelta(days=1))

  first_retriever = get_routes_router()
  second_retriever = get_routes_backuprouter()
  
  peer_tag = get_peer_with_name(routename)
  route = get_route(applier=None,peer=peer_tag)
  
  check = False
  
  protocol = []
  tcpflags = []
  destports = []
  sourceports = []
  packetlength = []
  destination = ''
  src = ''
  icmpcode = ''
  icmptype = ''
  then = []
  then_value = []

  for children in first_retriever:
    for child in children:
      if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
        if child.text == routename:
          check = True
          route.name = routename
        else:
          check = False
      if check:
        for tag in child:
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}protocol':
            protocol.append(tag.text)
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}destination-port':
            destports.append(tag.text)
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}source-port':
            sourceports.append(tag.text)
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}tcp-flags':
            tcpflags.append(tag.text)
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}packet-length':
            packetlength.append(tag.text)
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}destination':
            destination = tag.text
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}source':
            src = tag.text
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}icmp-code':
            icmpcode = tag.text
          if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}icmp-type':
            icmptype = tag.text
      if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}then' and check:
        for c in child:
          f = c.tag.find('}')
          text = c.tag[f+1:]
          then.append(text)
          if c.tag != '{http://xml.juniper.net/xnm/1.1/xnm}discard' or c.tag != '{http://xml.juniper.net/xnm/1.1/xnm}accept':
            then_value.append(c.text)
  
  if route.name:
    if packetlength: route.packetlength = packetlength
    if icmpcode: route.icmpcode = icmpcode
    if icmptype: route.icmptype = icmptype
    if src: route.source = src
    if destination: route.destination = destination
    route.expires = tomorrow
    if sourceports: route.sourceport = sourceports[0]
    if destports: route.destinationport = destports[0]
    
    try:
      route.save()
    except Exception as e:
      logger.info(f"There was an error when saving {routename} into the DB. It might be a duplicate. Error: ", e)
      return None 
    
    if then:
      if then_value[0] is not None:
        then_action, created = ThenAction.objects.get_or_create(action=then[0],action_value=then_value[0])
        route.then.add(then_action)
      else:
        then_action, created = ThenAction.objects.get_or_create(action=then[0])
        route.then.add(then_action)
    for p in protocol:
      prot = MatchProtocol.objects.get(protocol=p)
      route.protocol.add(prot)
    for flag in tcpflags:
      tcpflag = TcpFlag.objects.get(flag=flag)
      route.tcpflag.add(tcpflag)
      route.save()
    return route
  else:     
    for children in second_retriever:
      for child in children:
        if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}name':
          if child.text == routename:
            check = True
            route.name = routename
          else:
            check = False
        if check:
          for tag in child:
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}protocol':
              protocol.append(tag.text)
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}destination-port':
              destports.append(tag.text)
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}source-port':
              sourceports.append(tag.text)
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}tcp-flags':
              tcpflags.append(tag.text)
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}packet-length':
              packetlength.append(tag.text)
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}destination':
              destination = tag.text
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}source':
              src = tag.text
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}icmp-code':
              icmpcode = tag.text
            if tag.tag == '{http://xml.juniper.net/xnm/1.1/xnm}icmp-type':
              icmptype = tag.text
        if child.tag == '{http://xml.juniper.net/xnm/1.1/xnm}then' and check:
          for c in child:
            f = c.tag.find('}')
            text = c.tag[f+1:]
            then.append(text)
            if c.tag != '{http://xml.juniper.net/xnm/1.1/xnm}discard' or c.tag != '{http://xml.juniper.net/xnm/1.1/xnm}accept':
              then_value.append(c.text)
            
  if route.name:
    if packetlength: route.packetlength = packetlength[0]
    if icmpcode: route.icmpcode = icmpcode
    if icmptype: route.icmptype = icmptype
    if src: route.source = src
    if destination: route.destination = destination
    route.expires = tomorrow
    if sourceports: route.sourceport = sourceports[0]
    if destports: route.destinationport = destports[0]
    logger.info(f"The following route is about to be saved and commited : {route}")
    try:
      route.save()
    except Exception as e:
      logger.info(f"There was an error when saving {routename} into the DB. It might be a duplicate.")
      return None

  if then:
    if then_value[0] is not None :
      then_action, created = ThenAction.objects.get_or_create(action=then[0],action_value=then_value[0])
      route.then.add(then_action)
    else:
      then_action, created = ThenAction.objects.get_or_create(action=then[0])
      route.then.add(then_action)

  for p in protocol:
    prot = MatchProtocol.objects.get(protocol=p)
    route.protocol.add(prot)

  for flag in tcpflags:
    tcpflag = TcpFlag.objects.get(flag=flag)
    route.tcpflag.add(tcpflag)
  send_message(f"Acabamos de encontrar una regla que no estaba sincronizada, la hemos activado durante un día más. Porfavor revise todas sus reglas activas. Regla: {route.name}",peer=peer_tag,superuser=False)
  route.save()
  
  return route