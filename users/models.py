from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser
from django.contrib.auth import get_user_model
from django.db.models import Q
# Create your models here.

class User(AbstractUser):

    name = models.CharField(max_length=100)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    email = models.CharField(max_length=200, unique=True)
    is_admin = models.BooleanField(default=False)

    def __str__(self):
        return self.name