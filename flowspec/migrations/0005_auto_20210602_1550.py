# Generated by Django 2.2 on 2021-06-02 12:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('flowspec', '0004_auto_20210601_1609'),
    ]

    operations = [
        migrations.AlterField(
            model_name='matchport',
            name='port',
            field=models.CharField(blank=True, max_length=24, null=True, unique=True),
        ),
    ]
