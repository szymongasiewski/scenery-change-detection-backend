from django.db import models
from django.utils.translation import gettext_lazy
from django.contrib.auth import models as auth_models
from rest_framework_simplejwt.tokens import RefreshToken
from .managers import UserManager


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


def user_directory_path_input_images(instance, filename):
    return 'user_{0}/input_images/{1}'.format(instance.user.id, filename)


def user_directory_path_output_images(instance, filename):
    return 'user_{0}/output_images/{1}'.format(instance.user.id, filename)


class OutputImage(models.Model):
    image = models.ImageField(upload_to=user_directory_path_output_images)
    date_created = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, related_name='output_images', on_delete=models.CASCADE)


class InputImage(models.Model):
    image = models.ImageField(upload_to=user_directory_path_input_images)
    output_image = models.ForeignKey(OutputImage, related_name='input_images', on_delete=models.CASCADE)
    date_created = models.DateTimeField(auto_now_add=True)
    user = models.ForeignKey(User, related_name='input_images', on_delete=models.CASCADE)
