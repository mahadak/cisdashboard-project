# Generated by Django 3.1.7 on 2021-05-28 10:14

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0008_servicesreport_priority'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='servicesreport',
            name='priority',
        ),
    ]
