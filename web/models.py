from django.db import models


# Create your models here.
class AuthUser(models.Model):
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(blank=True, null=True)
    is_superuser = models.IntegerField()
    username = models.CharField(unique=True, max_length=150)
    first_name = models.CharField(max_length=30)
    last_name = models.CharField(max_length=150)
    email = models.CharField(max_length=254)
    is_staff = models.IntegerField()
    is_active = models.IntegerField()
    date_joined = models.DateTimeField()


class UploadedFile(models.Model):
    filename = models.CharField(max_length=128)
    encryption_key = models.CharField(max_length=256)
    created_at = models.DateTimeField()
    username = models.CharField(max_length=128)
