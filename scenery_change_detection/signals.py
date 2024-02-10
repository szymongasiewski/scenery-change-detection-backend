from django.db.models.signals import post_delete, pre_delete
from django.dispatch import receiver
from django.core.files.storage import default_storage
from django.conf import settings
from os.path import join
from .models import User, InputImage, OutputImage


@receiver(pre_delete, sender=User)
def delete_user_images(sender, instance, **kwargs):
    input_images = InputImage.objects.filter(user=instance)
    for img in input_images:
        absolute_path = join(settings.MEDIA_ROOT, img.image.name)
        if default_storage.exists(absolute_path):
            default_storage.delete(absolute_path)

    output_images = OutputImage.objects.filter(user=instance)
    for img in output_images:
        absolute_path = join(settings.MEDIA_ROOT, img.image.name)
        if default_storage.exists(absolute_path):
            default_storage.delete(absolute_path)
