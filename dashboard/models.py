from django.utils.timezone import now
from django.db import models
from django.contrib.auth import get_user_model
User = get_user_model()
import uuid

# Create your models here.

class UserAWS(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    account_number = models.CharField(max_length=20, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    roleArn = models.CharField(max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return self.user.name


class ScanReports(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    account = models.ForeignKey(UserAWS, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

class ServicesReport(models.Model):
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    service = models.CharField(max_length=100)\
        
    report = models.JSONField()
    test_status = models.CharField(max_length=100)
    scan = models.ForeignKey(ScanReports, on_delete=models.CASCADE)