# Generated by Django 3.1 on 2022-03-07 11:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('golem', '0004_auto_20220303_1157'),
    ]

    operations = [
        migrations.AlterField(
            model_name='golemattack',
            name='tcpflag',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='historicalgolemattack',
            name='tcpflag',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]