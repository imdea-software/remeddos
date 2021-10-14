from django.core.mail import send_mail
from django.conf import settings
from accounts.models import *
from flowspy.settings import * 
from utils.proxy import *
from flowspy import settings
from django.shortcuts import get_object_or_404
import os
import logging

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
 
def send_new_mail(subject, message, from_email, recipient_list, bcc_list):
  try:
    logger.info("helpers::send_new_mail(): send mail: from_email="+str(from_email)+", recipient_list="+str(recipient_list)+", bcc_list="+str(bcc_list)) 
    #i have removed the bbc_list just for now
    return send_mail(subject, message, from_email, recipient_list)
  except Exception as e:
    #os.write(3, "send_new_mail() failed: exc="+str(e)+"\n") 
    logger.error("helpers::send_new_mail() failed: exc="+str(e)) 

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
  tcp_flags = f',tcp-flag:0{route.tcpflag}' if route.tcpflag else ''          
  p_length =  f',len={route.packetlength}' if route.packetlength else ''
  query = (f'jnxFWCounterByteCount["{destination},{source}{protocol}{destport}{sourceport}{icmpcode}{icmptype}{tcp_flags}{p_length}"]')
  return query