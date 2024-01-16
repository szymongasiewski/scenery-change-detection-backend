from django.db import models
from django.utils.translation import gettext_lazy
from django.contrib.auth import models as auth_models
from .managers import UserManager


# class UserManager(auth_models.BaseUserManager):
#
#     def create_user(self, email: str, password: str, is_staff=False, is_superuser=False) -> 'User':
#         if not email:
#             raise ValueError('User must have email')
#
#         user = self.model(email=self.normalize_email(email))
#         user.set_password(password)
#         user.is_active = True
#         user.is_staff = is_staff
#         user.is_superuser = is_superuser
#         user.save()
#
#         return user
#
#     def create_superuser(self, email: str, password: str) -> 'User':
#         user = self.create_user(email=email, password=password, is_staff=True, is_superuser=True)
#         user.save()
#
#         return user


# class User(auth_models.AbstractUser):
#     email = models.EmailField(max_length=255, unique=True)
#     password = models.CharField(max_length=255)
#     username = None
#     first_name = None
#     last_name = None
#
#     objects = UserManager()
#
#     USERNAME_FIELD = 'email'
#     REQUIRED_FIELDS = []

class User(auth_models.AbstractBaseUser, auth_models.PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True, verbose_name=gettext_lazy("Email Address"))
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True, null=True, blank=True)
    # is_verified = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        pass


class Image(models.Model):
    image = models.ImageField(upload_to='images/')
