# Generated by Django 3.2 on 2022-10-10 14:26

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('flowspec', '0002_route_punch'),
        ('golem', '0002_auto_20221010_1539'),
    ]

    operations = [
        migrations.AddField(
            model_name='golemattack',
            name='route',
            field=models.ManyToManyField(blank=True, related_name='route_ceu', to='flowspec.Route_Punch'),
        ),
    ]
