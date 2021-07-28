# encoding: utf-8
from django.conf import settings
from django.db import migrations, models
from django.db import models
from longerusername import MAX_USERNAME_LENGTH

class Migration(migrations.Migration):

    def forwards(self, orm):
        # Changing field 'User.username'
        db.alter_column('auth_user', 'username', models.CharField(max_length=MAX_USERNAME_LENGTH()))


    def backwards(self, orm):

        # Changing field 'User.username'
        db.alter_column('auth_user', 'username', models.CharField(max_length=35))


    models = {
        
    }

    complete_apps = ['django_monkeypatches']
