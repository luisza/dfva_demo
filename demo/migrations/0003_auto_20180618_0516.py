# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-06-18 05:16
from __future__ import unicode_literals

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('demo', '0002_auto_20180618_0506'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='institution',
            name='bccr_bussiness',
        ),
        migrations.RemoveField(
            model_name='institution',
            name='bccr_entity',
        ),
        migrations.RemoveField(
            model_name='institution',
            name='public_key',
        ),
    ]
