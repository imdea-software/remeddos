# Generated by Django 3.2 on 2022-11-07 11:33

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import simple_history.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('flowspec', '0001_initial'),
        ('peers', '0002_auto_20210603_1642'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='HistoricalGolemAttack',
            fields=[
                ('id', models.IntegerField(auto_created=True, blank=True, db_index=True, verbose_name='ID')),
                ('id_name', models.CharField(db_index=True, max_length=50)),
                ('ip_src', models.GenericIPAddressField(default='0.0.0.0')),
                ('ip_dest', models.GenericIPAddressField(default='0.0.0.0')),
                ('src_port', models.CharField(blank=True, max_length=65535, null=True)),
                ('dest_port', models.CharField(blank=True, max_length=65535, null=True)),
                ('port', models.CharField(blank=True, max_length=65535, null=True)),
                ('tcpflag', models.CharField(blank=True, max_length=100, null=True)),
                ('status', models.CharField(max_length=50)),
                ('max_value', models.FloatField(blank=True, max_length=500, null=True)),
                ('threshold_value', models.FloatField(blank=True, max_length=500, null=True)),
                ('typeof_value', models.CharField(blank=True, max_length=200, null=True)),
                ('received_at', models.DateTimeField(blank=True, editable=False)),
                ('ends_at', models.DateTimeField(blank=True, default=None, null=True)),
                ('nameof_attack', models.CharField(blank=True, max_length=200, null=True)),
                ('typeof_attack', models.CharField(blank=True, max_length=200, null=True)),
                ('link', models.CharField(blank=True, max_length=300, null=True)),
                ('finished', models.BooleanField(default=False)),
                ('history_id', models.AutoField(primary_key=True, serialize=False)),
                ('history_date', models.DateTimeField()),
                ('history_change_reason', models.CharField(max_length=100, null=True)),
                ('history_type', models.CharField(choices=[('+', 'Created'), ('~', 'Changed'), ('-', 'Deleted')], max_length=1)),
                ('history_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('peer', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', to='peers.peer')),
            ],
            options={
                'verbose_name': 'historical golem attack',
                'ordering': ('-history_date', '-history_id'),
                'get_latest_by': 'history_date',
            },
            bases=(simple_history.models.HistoricalChanges, models.Model),
        ),
        migrations.CreateModel(
            name='GolemAttack',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('id_name', models.CharField(max_length=50, unique=True)),
                ('ip_src', models.GenericIPAddressField(default='0.0.0.0')),
                ('ip_dest', models.GenericIPAddressField(default='0.0.0.0')),
                ('src_port', models.CharField(blank=True, max_length=65535, null=True)),
                ('dest_port', models.CharField(blank=True, max_length=65535, null=True)),
                ('port', models.CharField(blank=True, max_length=65535, null=True)),
                ('tcpflag', models.CharField(blank=True, max_length=100, null=True)),
                ('status', models.CharField(max_length=50)),
                ('max_value', models.FloatField(blank=True, max_length=500, null=True)),
                ('threshold_value', models.FloatField(blank=True, max_length=500, null=True)),
                ('typeof_value', models.CharField(blank=True, max_length=200, null=True)),
                ('received_at', models.DateTimeField(auto_now_add=True)),
                ('ends_at', models.DateTimeField(blank=True, default=None, null=True)),
                ('nameof_attack', models.CharField(blank=True, max_length=200, null=True)),
                ('typeof_attack', models.CharField(blank=True, max_length=200, null=True)),
                ('link', models.CharField(blank=True, max_length=300, null=True)),
                ('finished', models.BooleanField(default=False)),
                ('peer', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='peers.peer')),
                ('protocol', models.ManyToManyField(blank=True, to='flowspec.MatchProtocol')),
                ('route', models.ManyToManyField(blank=True, related_name='route_ceu', to='flowspec.Route_Punch')),
                ('route_ceu', models.ManyToManyField(blank=True, related_name='route_ceu', to='flowspec.Route_CEU')),
                ('route_cib', models.ManyToManyField(blank=True, related_name='route_cib', to='flowspec.Route_CIB')),
                ('route_csic', models.ManyToManyField(blank=True, related_name='route_csic', to='flowspec.Route_CSIC')),
                ('route_cunef', models.ManyToManyField(blank=True, related_name='route_cunef', to='flowspec.Route_CUNEF')),
                ('route_cv', models.ManyToManyField(blank=True, related_name='route_cv', to='flowspec.Route_CV')),
                ('route_imdea', models.ManyToManyField(blank=True, related_name='route_imdea', to='flowspec.Route_IMDEA')),
                ('route_imdeanet', models.ManyToManyField(blank=True, related_name='route_imdeanet', to='flowspec.Route_IMDEANET')),
                ('route_rem', models.ManyToManyField(blank=True, related_name='route_rem', to='flowspec.Route_REM')),
                ('route_uah', models.ManyToManyField(blank=True, related_name='route_uah', to='flowspec.Route_UAH')),
                ('route_uam', models.ManyToManyField(blank=True, related_name='route_uam', to='flowspec.Route_UAM')),
                ('route_uc3m', models.ManyToManyField(blank=True, related_name='route_uc3m', to='flowspec.Route_UC3M')),
                ('route_ucm', models.ManyToManyField(blank=True, related_name='route_ucm', to='flowspec.Route_UCM')),
                ('route_uem', models.ManyToManyField(blank=True, related_name='route_uem', to='flowspec.Route_UEM')),
                ('route_uned', models.ManyToManyField(blank=True, related_name='route_uned', to='flowspec.Route_UNED')),
                ('route_upm', models.ManyToManyField(blank=True, related_name='route_upm', to='flowspec.Route_UPM')),
                ('route_urjc', models.ManyToManyField(blank=True, related_name='route_urjc', to='flowspec.Route_URJC')),
            ],
        ),
    ]
