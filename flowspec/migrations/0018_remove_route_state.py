# Generated by Django 3.1 on 2021-09-23 15:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('flowspec', '0017_auto_20210921_1443'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='route',
            name='state',
        ),
    ]