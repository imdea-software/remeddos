# Generated by Django 3.1 on 2022-02-24 11:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('golem', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='golemattack',
            name='max_value',
            field=models.FloatField(),
        ),
        migrations.AlterField(
            model_name='golemattack',
            name='source',
            field=models.GenericIPAddressField(default='0.0.0.0'),
        ),
        migrations.AlterField(
            model_name='golemattack',
            name='threshold_value',
            field=models.FloatField(),
        ),
        migrations.AlterField(
            model_name='historicalgolemattack',
            name='max_value',
            field=models.FloatField(),
        ),
        migrations.AlterField(
            model_name='historicalgolemattack',
            name='source',
            field=models.GenericIPAddressField(default='0.0.0.0'),
        ),
        migrations.AlterField(
            model_name='historicalgolemattack',
            name='threshold_value',
            field=models.FloatField(),
        ),
    ]