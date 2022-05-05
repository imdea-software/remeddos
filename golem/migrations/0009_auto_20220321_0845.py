# Generated by Django 3.1 on 2022-03-21 08:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('golem', '0008_auto_20220316_1511'),
    ]

    operations = [
        migrations.AddField(
            model_name='golemattack',
            name='typeof_attack',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='golemattack',
            name='typeof_value',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='historicalgolemattack',
            name='typeof_attack',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AddField(
            model_name='historicalgolemattack',
            name='typeof_value',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
        migrations.AlterField(
            model_name='golemattack',
            name='max_value',
            field=models.FloatField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='golemattack',
            name='threshold_value',
            field=models.FloatField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='historicalgolemattack',
            name='max_value',
            field=models.FloatField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='historicalgolemattack',
            name='threshold_value',
            field=models.FloatField(blank=True, max_length=500, null=True),
        ),
    ]