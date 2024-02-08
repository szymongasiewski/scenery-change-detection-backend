from django.db import models
from django.utils.translation import gettext_lazy
from django.contrib.auth import models as auth_models
from .managers import UserManager
from rest_framework_simplejwt.tokens import RefreshToken


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
        refresh = RefreshToken.for_user(self)
        access = refresh.access_token
        access['email'] = self.email

        return {
            'refresh': str(refresh),
            'access': str(access)
        }


class Image(models.Model):
    image = models.ImageField(upload_to='images/')
