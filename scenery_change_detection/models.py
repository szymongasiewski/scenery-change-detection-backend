from django.db import models
from django.utils.translation import gettext_lazy
from django.contrib.auth import models as auth_models
from django.core.validators import FileExtensionValidator
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken
from .managers import UserManager
import secrets


class User(auth_models.AbstractBaseUser, auth_models.PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True, verbose_name=gettext_lazy("Email Address"))
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True, null=True, blank=True)

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


class ImageRequest(models.Model):
    ALGORITHM_CHOICES = [
        ('pca_kmeans', 'PCA k-Means'),
        ('img_diff', 'Image Difference'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(
        max_length=20,
        choices=[
            ('PENDING', gettext_lazy('Pending')),
            ('PROCESSING', gettext_lazy('Processing')),
            ('COMPLETED', gettext_lazy('Completed')),
            ('FAILED', gettext_lazy('Failed'))
        ],
        default='PENDING'
    )
    algorithm = models.CharField(max_length=20, choices=ALGORITHM_CHOICES, default='pca_kmeans')
    parameters = models.JSONField(default=dict)


def user_directory_path_input_images(instance, filename):
    return 'user_{0}/request_{1}/input_images/{2}'.format(instance.image_request.user.id,
                                                          instance.image_request.id, filename)


def user_directory_path_output_images(instance, filename):
    return 'user_{0}/request_{1}/output_images/{2}'.format(instance.image_request.user.id,
                                                           instance.image_request.id, filename)


class InputImage(models.Model):
    image = models.ImageField(
        upload_to=user_directory_path_input_images,
        validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])]
    )
    image_request = models.ForeignKey(ImageRequest, on_delete=models.CASCADE, related_name='input_images', null=False)


class OutputImage(models.Model):
    image = models.ImageField(
        upload_to=user_directory_path_output_images,
        validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])]
    )
    image_request = models.ForeignKey(ImageRequest, on_delete=models.CASCADE, related_name='output_image', null=False)


class ProcessingLog(models.Model):
    image_request = models.ForeignKey(ImageRequest, on_delete=models.CASCADE)
    log_message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)


def generate_otp():
    return secrets.token_hex(3)

class OneTimePassword(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, default=generate_otp)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.otp
    
    def is_valid(self, otp):
        return otp == self.otp and self.expires_at >= timezone.now()
    
    class Meta:
        ordering = ['created_at']