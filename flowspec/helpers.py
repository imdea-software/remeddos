from django.core.mail import send_mail
from django.conf import settings
from accounts.models import * 
from flowspy.settings import * 

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