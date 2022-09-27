from flowspy.celery import app
#from __future__ import absolute_import, unicode_literals
from socket import IP_TOS
from tabnanny import check

from celery import shared_task
import logging
from golem.helpers import *
from golem.models import *




LOG_FILENAME = os.path.join(settings.LOG_FILE_LOCATION, 'celery_jobs.log')

FORMAT = '%(asctime)s %(levelname)s: %(message)s'
logging.basicConfig(format=FORMAT)
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
handler = logging.FileHandler(LOG_FILENAME)
handler.setFormatter(formatter)
logger.addHandler(handler)


@shared_task
def golem(anomaly_info, id_event,last_updated=None):

    if not anomaly_info['institution_name'] == 'Non-Home':
        if anomaly_info['status'] == 'Open':
            open_event(id_event)

        if anomaly_info['status'] == 'Recovered':
            event = GolemAttack.objects.get(id_name=id_event)
            event.status = anomaly_info['status']
            try:
                event.ends_at = last_updated
            except Exception as e:
                pass
            event.save()
   
    else:
        if anomaly_info['institution_name'] == 'Non-Home':
            check_golem_conexion(anomaly_info)
        #event doesn't belong to peer
        pass

