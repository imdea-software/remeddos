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
from flowspec.models import *

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
 
#====TG Settings:
""" API_KEY = settings.API_KEY_T
bot = telebot.TeleBot(API_KEY)  """

def send_new_mail(subject, message, from_email, recipient_list, bcc_list):
  try:
    logger.info("helpers::send_new_mail(): send mail: from_email="+str(from_email)+", recipient_list="+str(recipient_list)+", bcc_list="+str(bcc_list)) 
    #i have removed the bbc_list just for now
    return send_mail(subject, message, from_email, recipient_list)
  except Exception as e:
    #os.write(3, "send_new_mail() failed: exc="+str(e)+"\n") 
    logger.error("helpers::send_new_mail() failed: exc="+str(e)) 


def send_message(message):
  client = slack.WebClient(token=settings.SLACK_TOKEN)
  client.chat_postMessage(channel=settings.SLACK_CHANNEL, text=message)

""" @bot.message_handler(commands=['Greet'])
def greet(message):
  bot.reply_to(message,'Hello there! How is it going?')
  bot.polling() """

""" def send_message_tg(message):
  print(message)
  telegram_send.send(messages=[message]) """
""" def send_message_tg(message):
  import requests
  id_chat ='@redimadrid_bot'
  token = settings.API_KEY_T
  url = (f'https://api.telegram.org/bot{token}/sendMessage')

  params = {'chat_id':id,'text':message}
  requests.post(url,params=params)
  #bot.send_message(message.chat_id, msg) """

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

def get_back_up_files():
  files = []
  for f in os.listdir(settings.BACK_UP_DIR):
    files.append(f)
  return files

def translate_protocol(prot):
  operations = {'ah':51,'egp':8,'gre':47,'icmp':1,'igmp':2,'ospf':89, 'pim':103, 'rsvp':46,'sctp':132,'tcp':6,'udp':17}
  protocol = operations.get(prot,"Invalid argument") 
  return protocol 

def translate_tcpflags(tf):
  tcpflag_dict = {'ack':'10','rst':'04','fin':'01','push':'08','urgent':'20','syn':'02'}
  tcpflags = tcpflag_dict.get(tf,"Invalid argument")
  return tcpflags


def get_query(routename, dest, src):
  from flowspec.models import Route
  route = Route.objects.get(name=routename)
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


def petition_geni(id_event):
    import requests
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    session = requests.Session()
    session.verify = False
    data = {'request': '{"display_data":"yes"}'}
    response = ''
    try:
        # this is the petition that needs to go through:  curl --user Alicia:ali54* --insecure --data 'request={"display_data":"yes"}' https://193.145.15.26/api/anomalyevent/application/A376135
        response = requests.get(f'https://193.145.15.26/api/anomalyevent/application/{id_event}', data=data, verify=False, auth=('Alicia', 'ali54*'))
        json_event = response.json()
        event_data = {
           'id':json_event['response']['result']['data'][0]['event']['id'],'status':json_event['response']['result']['data'][0]['event']['status'],'severity':json_event['response']['result']['data'][0]['event']['severity']['type'],
            'threshold_value':json_event['response']['result']['data'][0]['event']['severity']['threshold_value'],'max_value':json_event['response']['result']['data'][0]['event']['severity']['max_value'],
            'institution_name': json_event['response']['result']['data'][0]['event']['resource']['name'][0], 'attack_name' : json_event['response']['result']['data'][0]['event']['attack']['name'],
            'initial_date' : json_event['response']['result']['data'][0]['event']['datetime']['start_time'], 'attack_duration' : json_event['response']['result']['data'][0]['event']['datetime']['duration'], 'ip_attacked' : json_event['response']['result']['data'][0]['event']['resource']['ip']
            }
    except requests.exceptions.ConnectionError:
        print(response.status_code)           
    return (response.json(),event_data)
  

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
  


def graphs(timefrom,timetill, routename):
  from flowspec.models import Route
  zapi = ZabbixAPI(ZABBIX_SOURCE)
  zapi.login(ZABBIX_USER,ZABBIX_PWD)
  route = get_object_or_404(Route, name=routename)
  query = get_query(route.name, route.destination, route.source)
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


def get_default_graph(routename):
  from flowspec.models import Route
  zapi = ZabbixAPI(ZABBIX_SOURCE)
  zapi.login(ZABBIX_USER,ZABBIX_PWD)
  route = get_object_or_404(Route, name=routename)
  query = get_query(route.name, route.destination, route.source)

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
