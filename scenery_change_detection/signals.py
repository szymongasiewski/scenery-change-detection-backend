from django.db.models.signals import pre_delete, post_save
from django.dispatch import receiver
from django.core.files.storage import default_storage
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from os.path import join
from .models import User, InputImage, OutputImage, ImageRequest, OneTimePassword


@receiver(pre_delete, sender=User)
def delete_user_images(sender, instance, **kwargs):
    image_requests = ImageRequest.objects.filter(user=instance)
    for request in image_requests:
        input_images = InputImage.objects.filter(image_request=request)
        for img in input_images:
            #absolute_path = join(settings.MEDIA_ROOT, img.image.name)
            if default_storage.exists(img.image.name):
                default_storage.delete(img.image.name)

        output_image = OutputImage.objects.filter(image_request=request).first()
        if output_image is not None:
            #absolute_path = join(settings.MEDIA_ROOT, output_image.image.name)
            if default_storage.exists(output_image.image.name):
                default_storage.delete(output_image.image.name)


@receiver(post_save, sender=User)
def create_one_time_password(sender, instance, created, **kwargs):
    if created:
        if instance.is_superuser:
            return
        else:
            OneTimePassword.objects.create(user=instance, expires_at=timezone.now() + timezone.timedelta(minutes=5))


        otp = OneTimePassword.objects.filter(user=instance).last()
        subject = 'Your One Time Password'
        message = f'Your OTP is {otp.otp} \n\n This OTP will expire in 5 minutes.\n{settings.CORS_ALLOWED_ORIGINS[0]}/verify-email/{instance.id}'
        sender = settings.EMAIL_HOST_USER
        receiver = [instance.email, ]

        send_mail(subject, message, sender, receiver, fail_silently=False)