from django.db import models
from flowspec.models import *
from peers.models import *
from django.utils import timezone
from datetime import datetime
from simple_history.models import HistoricalRecords
from flowspec.helpers import * 


# Create your models here

# if a route is in the database but not in the router it means that the route has been proposed but not yet accepted
# so first we create a new rule and commit it to the db but not sync w the router till the client accepts it 
# through django-simple-history we will keep track of the changes and propose to change the route to a previous version

class GolemAttack(models.Model):
    id_name = models.CharField(max_length=50,unique=True)
    peer = models.ForeignKey(Peer,blank=True,on_delete=models.CASCADE,null=True)
    #fk to route (we we'll create here a new proposition of route where it is just commited to the db)
    ip_src = models.GenericIPAddressField(default='0.0.0.0')
    ip_dest = models.GenericIPAddressField(default='0.0.0.0')
    src_port = models.CharField(max_length=65535, blank=True, null=True)
    dest_port = models.CharField(max_length=65535, blank=True, null=True)
    port = models.CharField(max_length=65535, blank=True, null=True)
    protocol = models.ManyToManyField(MatchProtocol, blank=True)
    tcpflag = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=50)
    max_value = models.FloatField(max_length=500, blank=True, null=True)
    threshold_value  = models.FloatField(max_length=500, blank=True, null=True)
    typeof_value = models.CharField(max_length=200, blank=True, null=True)
    history = HistoricalRecords(use_base_model_db=True)
    received_at = models.DateTimeField(auto_now_add=True)
    ends_at = models.DateTimeField(null=True, blank=True, default=None)
    nameof_attack = models.CharField(max_length=200, blank=True, null=True)
    typeof_attack = models.CharField(max_length=200, blank=True, null=True)
    link = models.CharField(max_length=300, blank=True, null=True)
    finished = models.BooleanField(default=False)
    # route models
    route = models.ManyToManyField(Route_Punch,blank=True, related_name='route_ceu')
    route_rem = models.ManyToManyField(Route_REM,blank=True, related_name='route_rem')
    route_cv = models.ManyToManyField(Route_CV,blank=True, related_name='route_cv')
    route_cib = models.ManyToManyField(Route_CIB,blank=True, related_name='route_cib')
    route_csic = models.ManyToManyField(Route_CSIC,blank=True,related_name='route_csic')
    route_ceu = models.ManyToManyField(Route_CEU,blank=True, related_name='route_ceu')
    route_cunef = models.ManyToManyField(Route_CUNEF,blank=True, related_name='route_cunef')
    route_imdeanet = models.ManyToManyField(Route_IMDEANET,blank=True, related_name='route_imdeanet')
    route_imdea = models.ManyToManyField(Route_IMDEA,blank=True, related_name='route_imdea')
    route_uam = models.ManyToManyField(Route_UAM,blank=True, related_name='route_uam')
    route_uc3m = models.ManyToManyField(Route_UC3M,blank=True, related_name='route_uc3m')
    route_ucm = models.ManyToManyField(Route_UCM,blank=True, related_name='route_ucm')
    route_uah = models.ManyToManyField(Route_UAH,blank=True, related_name='route_uah')
    route_uem = models.ManyToManyField(Route_UEM,blank=True, related_name='route_uem')
    route_uned = models.ManyToManyField(Route_UNED,blank=True, related_name='route_uned')
    route_upm = models.ManyToManyField(Route_UPM,blank=True, related_name='route_upm')
    route_urjc = models.ManyToManyField(Route_URJC,blank=True, related_name='route_urjc')

    def __str__(self):
        return (f'{self.id_name}, {self.peer}, {self.route}, {self.status}')

    def history_translation(self):
        if self.history:
            history_records = []
            iter = self.history.all()
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                if delta != None:
                    for change in delta.changes:
                        record = f'{change.field} ha cambiado de {change.old} a {change.new}.'
                        history_records.append(record)
                        return history_records
                else:
                    history_records = 'El ataque no ha sufrido cambios registrados.'
                    return history_records
    
    def get_event_duration(self):
        if not self.ends_at == None:
            try:
                duration = self.ends_at - self.received_at 
                return (duration // 1000000 * 1000000)
            except Exception as e:
                pass
        else: 
            pass
        

    def check_golem_updates(self):
        if self.history:
            iter = self.history.all().order_by('history_date').iterator()
            history_records = []
            for record_pair in iter_for_delta_changes(iter):
                old_record, new_record = record_pair
                delta = new_record.diff_against(old_record)
                for change in delta.changes:
                    history_records.append(f'{change.field} ha cambiado de: {change.old} a: {change.new}.')
        return history_records

    def set_route(self,route):
        peers = Peer.objects.all()
        for peer in peers:
            self.route.add(route) if self.peer.peer_tag == 'Punch' else None
            self.route_cv.add(route) if self.peer.peer_tag == 'CV' else None
            self.route_cib.add(route) if self.peer.peer_tag == 'CIB' else None
            self.route_csic.add(route) if self.peer.peer_tag == 'CSIC' else None
            self.route_ceu.add(route) if self.peer.peer_tag == 'CEU' else None
            self.route_cunef.add(route) if self.peer.peer_tag == 'CUNEF' else None
            self.route_imdeanet.add(route) if self.peer.peer_tag == 'IMDEA_NET' else None
            self.route_imdea.add(route) if self.peer.peer_tag == 'IMDEA' else None
            self.route_uam.add(route) if self.peer.peer_tag == 'UAM' else None
            self.route_uc3m.add(route) if self.peer.peer_tag == 'UC3M' else None
            self.route_ucm.add(route) if self.peer.peer_tag == 'UCM' else None
            self.route_uah.add(route) if self.peer.peer_tag == 'UAH' else None
            self.route_uem.add(route) if self.peer.peer_tag == 'UEM' else None
            self.route_uned.add(route) if self.peer.peer_tag == 'UNED' else None
            self.route_upm.add(route) if self.peer.peer_tag == 'UPM' else None
            self.route_urjc.add(route) if self.peer.peer_tag == 'URJC' else None

