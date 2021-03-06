# Generated by Django 3.1.7 on 2021-05-24 11:53

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('dashboard', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='useraws',
            old_name='aws_access_key',
            new_name='roleArn',
        ),
        migrations.RemoveField(
            model_name='useraws',
            name='aws_secret_key',
        ),
        migrations.AddField(
            model_name='useraws',
            name='uuid',
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AlterField(
            model_name='useraws',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
