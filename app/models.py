import uuid

from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models


class ValidManager(models.Manager):
    def get_queryset(self):
        return super(ValidManager, self).get_queryset().filter(is_deleted=False)


class BaseModel(models.Model):
    created = models.DateTimeField(auto_now_add=True, null=True)
    updated = models.DateTimeField(auto_now=True, null=True)
    isDeleted = models.BooleanField(default=False)
    createdBy = models.ForeignKey('app.User', on_delete=models.CASCADE, null=True, blank=True,
                                   related_name='+')

    objects = models.Manager()
    valid_objects = ValidManager()

    class Meta():
        abstract = True


class CustomUserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email, phone, password, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, phone=phone, **extra_fields)
        user.set_password(password)
        print('print here')
        user.save(using=self._db)
        return user

    def create_user(self, email, phone=None, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, phone, password, **extra_fields)

    def create_superuser(self, email, phone, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self._create_user(email, phone, password, **extra_fields)


class User(AbstractUser):
    userId = models.UUIDField(primary_key=True, default=uuid.uuid4,
                          help_text="Unique ID for this particular user across the table")
    email = models.EmailField(
        verbose_name="email address",
        max_length=255,
        unique=True,
    )
    firstName = models.CharField(max_length=100)
    lastName = models.CharField(max_length=100)
    phone = models.CharField(max_length=70, null=True, blank=True)
    username = models.CharField(max_length=70, null=True, blank=True)
    created = models.DateTimeField(auto_now_add=True, null=True)
    updated = models.DateTimeField(auto_now=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["phone_number"]

    class Meta:
        ordering = ('-pk',)

    def __str__(self):
        return self.full_name()

    def full_name(self):
        return self.get_full_name().replace(',', "'")


class Organisation(BaseModel):
    orgId = models.UUIDField(primary_key=True, default=uuid.uuid4,
                              help_text="Unique ID for this particular organisation across the table")
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    member = models.ManyToManyField('app.User', related_name='organisations')

    def __str__(self):
        return self.name


