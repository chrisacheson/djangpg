from django.db import models
from django.contrib.auth.models import User

class PublicKey(models.Model):
    fingerprint = models.CharField(max_length=40, unique=True)
    email = models.EmailField()
    username = models.CharField(max_length=64)
    user = models.ForeignKey(User, blank=True, null=True)
