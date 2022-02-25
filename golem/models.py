from django.db import models
from flowspec.models import *
from peers.models import *
from django.utils import timezone
from datetime import datetime
from simple_history.models import HistoricalRecords


# Create your models here

# if a route is in the database but not in the router it means that the route has been proposed but not yet accepted
# so first we create a new rule and commit it to the db but not sync w the router till the client accepts it 
# through django-simple-history we will keep track of the changes and propose to change the route to a previous version

class GolemAttack(models.Model):
    id_name = models.CharField(max_length=50)
    peer = models.ForeignKey(Peer,max_length=50,blank=True,null=True,on_delete=models.CASCADE)
    #fk to route (we we'll create here a new proposition of route where it is just commited to the db)
    route = models.ForeignKey(Route,max_length=50,blank=True,null=True,on_delete=models.CASCADE)
    source = models.GenericIPAddressField(default='0.0.0.0')
    status = models.CharField(max_length=50)
    max_value = models.FloatField()
    threshold_value  = models.FloatField()
    history = HistoricalRecords(use_base_model_db=True)
    received_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)

# test for saving 
#  Nuevo ataque a la institución 'UAH' de tipo '['Host TCP Traffic']' contra el recurso '193.146.58.180'.
#  La regla para poder mitigar este ataque que te proponemos desde RediMadrid es [ ... ]. Más información sobre
#  el ataque : Id: A377936, Status: Ongoing, Max Value: 264235306.66667, Threshold value: 203800000.

    def __str__(self):
        return (f'{self.id_name}, {self.peer}, {self.route}, {self.source}, {self.status}  ')

    def commit_add():
        # method that will commit the route to the router once the client approves it
        pass

