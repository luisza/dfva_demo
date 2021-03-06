# -*- coding: utf-8 -*-
# Generated by Django 1.11.13 on 2018-06-18 05:06
from __future__ import unicode_literals

import demo.models
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('demo', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Institution',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=250)),
                ('code', models.UUIDField()),
                ('active', models.BooleanField(default=True)),
                ('bccr_bussiness', models.IntegerField(default=1)),
                ('bccr_entity', models.IntegerField(default=1)),
                ('private_key', models.TextField()),
                ('public_key', models.TextField()),
                ('server_public_key', models.TextField()),
            ],
            options={
                'ordering': ('pk',),
                'permissions': (('view_institution', 'Can see available tasks'),),
            },
            bases=(models.Model, demo.models.PEMpresentation),
        ),
        migrations.AlterField(
            model_name='authenticatedatarequest',
            name='institution',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='demo.Institution'),
        ),
        migrations.AlterField(
            model_name='notificationurl',
            name='institution',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='demo.Institution'),
        ),
    ]
