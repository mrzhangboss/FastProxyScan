# -*- coding: utf-8 -*-
# Generated by Django 1.10.8 on 2017-11-22 03:18
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('database', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='proxy',
            name='checked_state',
            field=models.IntegerField(choices=[(0, 'Default'), (1, 'TransparentProxy'), (2, 'AnonymousProxy'), (3, 'HighAnonymousProxy'), (4, 'NeedAuthProxy'), (5, 'MitmProxy')], default=0),
        ),
    ]
