# Generated by Django 3.1 on 2021-12-13 16:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('flowspec', '0006_auto_20211201_1616'),
    ]

    operations = [
        migrations.CreateModel(
            name='TCPFlags',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('flag', models.CharField(blank=True, choices=[('ack', 'ACK'), ('rst', 'RST'), ('fin', 'FIN'), ('push', 'PUSH'), ('urgent', 'URGENT'), ('syn', 'SYN')], max_length=50, null=True)),
            ],
        ),
        migrations.RemoveField(
            model_name='route',
            name='tcpflag',
        ),
        migrations.AddField(
            model_name='route',
            name='tcpflag',
            field=models.ManyToManyField(to='flowspec.TCPFlags', verbose_name='TCP Flag'),
        ),
    ]
