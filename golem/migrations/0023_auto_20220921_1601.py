# Generated by Django 3.1 on 2022-09-21 14:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('golem', '0022_auto_20220916_1439'),
    ]

    operations = [
        migrations.AlterField(
            model_name='golemattack',
            name='ends_at',
            field=models.DateField(auto_now=True, null=True),
        ),
        migrations.AlterField(
            model_name='historicalgolemattack',
            name='ends_at',
            field=models.DateField(blank=True, editable=False, null=True),
        ),
    ]
