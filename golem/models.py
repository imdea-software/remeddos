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
    id_name = models.CharField(max_length=50)
    peer = models.ForeignKey(Peer,blank=True,on_delete=models.CASCADE,null=True)
    #fk to route (we we'll create here a new proposition of route where it is just commited to the db)
    ip_src = models.GenericIPAddressField(default='0.0.0.0')
    ip_dest = models.GenericIPAddressField(default='0.0.0.0')
    src_port = models.CharField(max_length=65535, blank=True, null=True)
    dest_port = models.CharField(max_length=65535, blank=True, null=True)
    protocol = models.ManyToManyField(MatchProtocol, blank=True)
    tcpflag = models.CharField(max_length=100, blank=True, null=True)
    status = models.CharField(max_length=50)
    max_value = models.FloatField(max_length=500, blank=True, null=True)
    threshold_value  = models.FloatField(max_length=500, blank=True, null=True)
    typeof_value = models.CharField(max_length=200, blank=True, null=True)
    history = HistoricalRecords(use_base_model_db=True)
    received_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    typeof_attack = models.CharField(max_length=200, blank=True, null=True)
    # route models
    route = models.ForeignKey(to=Route,blank=True,on_delete=models.CASCADE,null=True)
    route_cv = models.ForeignKey(Route_CV,blank=True,on_delete=models.CASCADE,null=True)
    route_cib = models.ForeignKey(Route_CIB,blank=True,on_delete=models.CASCADE,null=True)
    route_csic = models.ForeignKey(Route_CSIC,blank=True,on_delete=models.CASCADE,null=True)
    route_ceu = models.ForeignKey(Route_CEU,blank=True,on_delete=models.CASCADE,null=True)
    route_cunef = models.ForeignKey(Route_CUNEF,blank=True,on_delete=models.CASCADE,null=True)
    route_imdeanet = models.ForeignKey(Route_IMDEANET,blank=True,on_delete=models.CASCADE,null=True)
    route_imdea = models.ForeignKey(Route_IMDEA,blank=True,on_delete=models.CASCADE,null=True)
    route_uam = models.ForeignKey(Route_UAM,blank=True,on_delete=models.CASCADE,null=True)
    route_uc3m = models.ForeignKey(Route_UC3M,blank=True,on_delete=models.CASCADE,null=True)
    route_ucm = models.ForeignKey(Route_UCM,blank=True,on_delete=models.CASCADE,null=True)
    route_uah = models.ForeignKey(Route_UAH,blank=True,on_delete=models.CASCADE,null=True)
    route_uem = models.ForeignKey(Route_UEM,blank=True,on_delete=models.CASCADE,null=True)
    route_uned = models.ForeignKey(Route_UNED,blank=True,on_delete=models.CASCADE,null=True)
    route_upm = models.ForeignKey(Route_UPM,blank=True,on_delete=models.CASCADE,null=True)
    route_urjc = models.ForeignKey(Route_URJC,blank=True,on_delete=models.CASCADE,null=True)

# test for saving 
#  Nuevo ataque a la institución 'UAH' de tipo '['Host TCP Traffic']' contra el recurso '193.146.58.180'.
#  La regla para poder mitigar este ataque que te proponemos desde RediMadrid es [ ... ]. Más información sobre
#  el ataque : Id: A377936, Status: Ongoing, Max Value: 264235306.66667, Threshold value: 203800000.

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
            self.route = route if self.peer.peer_tag == 'Punch' else None
            self.route_cv = route if self.peer.peer_tag == 'CV' else None
            self.route_cib = route if self.peer.peer_tag == 'CIB' else None
            self.route_csic = route if self.peer.peer_tag == 'CSIC' else None
            self.route_ceu = route if self.peer.peer_tag == 'CEU' else None
            self.route_cunef = route if self.peer.peer_tag == 'CUNEF' else None
            self.route_imdeanet = route if self.peer.peer_tag == 'IMDEA_NET' else None
            self.route_imdea = route if self.peer.peer_tag == 'IMDEA' else None
            self.route_uam = route if self.peer.peer_tag == 'UAM' else None
            self.route_uc3m = route if self.peer.peer_tag == 'UC3M' else None
            self.route_ucm = route if self.peer.peer_tag == 'UCM' else None
            self.route_uah = route if self.peer.peer_tag == 'UAH' else None
            self.route_uem = route if self.peer.peer_tag == 'UEM' else None
            self.route_uned = route if self.peer.peer_tag == 'UNED' else None
            self.route_upm = route if self.peer.peer_tag == 'UPM' else None
            self.route_urjc = route if self.peer.peer_tag == 'URJC' else None


    def commit_add():
        # method that will commit the route to the router once the client approves it
        pass

# from golem.models import * ; golem = GolemAttack.objects.get(pk=56) ; g = golem.history_translation()