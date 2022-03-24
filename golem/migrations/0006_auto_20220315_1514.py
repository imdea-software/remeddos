# Generated by Django 3.1 on 2022-03-15 15:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('peers', '0002_auto_20210603_1642'),
        ('flowspec', '0016_auto_20220307_1155'),
        ('golem', '0005_auto_20220307_1155'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='historicalgolemattack',
            name='peer',
        ),
        migrations.RemoveField(
            model_name='historicalgolemattack',
            name='route',
        ),
        migrations.RemoveField(
            model_name='golemattack',
            name='peer',
        ),
        migrations.AddField(
            model_name='golemattack',
            name='peer',
            field=models.ManyToManyField(blank=True, max_length=50, to='peers.Peer'),
        ),
        migrations.RemoveField(
            model_name='golemattack',
            name='route',
        ),
        migrations.AddField(
            model_name='golemattack',
            name='route',
            field=models.ManyToManyField(blank=True, max_length=50, to='flowspec.Route'),
        ),
    ]
