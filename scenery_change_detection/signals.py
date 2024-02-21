from django.db.models.signals import pre_delete
from django.dispatch import receiver
from django.core.files.storage import default_storage
from django.conf import settings
from os.path import join
from .models import User, InputImage, OutputImage, ImageRequest


@receiver(pre_delete, sender=User)
def delete_user_images(sender, instance, **kwargs):
    image_requests = ImageRequest.objects.filter(user=instance)
    for request in image_requests:
        input_images = InputImage.objects.filter(image_request=request)
        for img in input_images:
            absolute_path = join(settings.MEDIA_ROOT, img.image.name)
            if default_storage.exists(absolute_path):
                default_storage.delete(absolute_path)

        output_image = OutputImage.objects.filter(image_request=request).first()
        if output_image is not None:
            absolute_path = join(settings.MEDIA_ROOT, output_image.image.name)
            if default_storage.exists(absolute_path):
                default_storage.delete(absolute_path)
