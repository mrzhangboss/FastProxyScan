# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2017-11-30 00:14
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='HostInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('host', models.CharField(max_length=256, unique=True)),
                ('port_sum', models.IntegerField(default=0)),
                ('mode', models.IntegerField(choices=[(0, 'IP'), (1, 'HOST'), (2, 'IP+*')], default=0)),
                ('speed', models.IntegerField(default=0)),
                ('is_deleted', models.BooleanField(default=False)),
                ('insert_at', models.DateTimeField(auto_now_add=True)),
                ('update_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='IPInfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.CharField(max_length=16, unique=True)),
                ('port_sum', models.IntegerField(default=0)),
                ('speed', models.IntegerField(default=0)),
                ('is_deleted', models.BooleanField(default=False)),
                ('country', models.CharField(blank=True, max_length=128, null=True)),
                ('province', models.CharField(blank=True, max_length=128, null=True)),
                ('city', models.CharField(blank=True, max_length=128, null=True)),
                ('district', models.CharField(blank=True, max_length=128, null=True)),
                ('operator', models.CharField(blank=True, max_length=128, null=True)),
                ('insert_at', models.DateTimeField(auto_now_add=True)),
                ('update_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='Proxy',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('port', models.IntegerField()),
                ('state', models.IntegerField(choices=[(0, 'default'), (1, 'open'), (2, 'closed'), (3, 'filtered'), (4, 'unfiltered'), (5, 'open|filtered'), (6, 'closed|filtered')], default=0)),
                ('is_checked', models.BooleanField(default=False)),
                ('is_proxy', models.BooleanField(default=False)),
                ('checked_state', models.IntegerField(choices=[(0, 'Default'), (1, 'TransparentProxy'), (2, 'AnonymousProxy'), (3, 'HighAnonymousProxy'), (4, 'NeedAuthProxy'), (5, 'MitmProxy')], default=0)),
                ('protocol', models.IntegerField(choices=[(0, 'default'), (1, 'http'), (2, 'https'), (3, 'http+https'), (4, 'socks')], default=0)),
                ('speed', models.IntegerField(default=0)),
                ('insert_at', models.DateTimeField(auto_now_add=True)),
                ('update_at', models.DateTimeField(auto_now=True)),
                ('ip', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='proxies', to='database.IPInfo')),
            ],
        ),
    ]
