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
        # start the process util the attack has finished
        if anomaly_info['status'] == 'Open':
            open_event(id_event)
        # let the user know the event has finished and update the DB
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
            # check up in case it's the false positive we make every morning to check remeddos keeps working
            check_golem_conexion(anomaly_info)
        #event doesn't belong to peer
        pass


@shared_task
def check_ongoing_golem_events():
    from golem.models import GolemAttack
    from golem.helpers import petition_geni

    golem_events = GolemAttack.objects.all()
    for golem in golem_events:
        if not golem.finished:
            open_event(golem.id_name)
        else:
            pass