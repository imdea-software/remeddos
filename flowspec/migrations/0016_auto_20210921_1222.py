# Generated by Django 3.1 on 2021-09-21 11:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('flowspec', '0015_auto_20210921_1000'),
    ]

    operations = [
        migrations.AlterField(
            model_name='route',
            name='state',
            field=models.CharField(max_length=20, verbose_name='Status'),
        ),
    ]
