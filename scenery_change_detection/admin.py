from django.contrib import admin
from django.utils.html import format_html, format_html_join
from django.urls import reverse
from . import models


class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'email')
    search_fields = ('id', 'email')
    list_filter = ('is_staff', 'is_active', 'is_superuser')
    list_per_page = 50


class ImageRequestAdmin(admin.ModelAdmin):
    list_display = ('id', 'created_at', 'updated_at', 'user_id', 'user_link')
    readonly_fields = ('user', 'created_at', 'updated_at',)

    def user_link(self, obj):
        url = reverse('admin:scenery_change_detection_user_change', args=[obj.user.id])
        return format_html('<a href="{}">{}<a/>', url, obj.user.email)
    user_link.short_description = 'User'


def get_image_request_link(obj):
    url = reverse('admin:scenery_change_detection_imagerequest_change', args=[obj.image_request.id])
    return format_html('<a href="{}">{}<a/>', url, obj.image_request.id)


class ImageAdmin(admin.ModelAdmin):
    list_display = ('id', 'image_request_id', 'image_request_link', 'image')
    readonly_fields = ('image', 'image_request',)

    def image_request_link(self, obj):
        return get_image_request_link(obj)
    image_request_link.short_description = 'Image Request ID'


class InputImageAdmin(ImageAdmin):
    list_display = ImageAdmin.list_display + ('output_image_reference',)
    readonly_fields = ImageAdmin.readonly_fields + ('output_image_reference',)

    def output_image_reference(self, obj):
        output_image = obj.image_request.output_image
        url = reverse('admin:scenery_change_detection_outputimage_change', args=[output_image.id])
        return format_html('<a href="{}">{}<a/>', url, output_image.id)

    output_image_reference.short_description = 'Output Image ID'


class OutputImageAdmin(ImageAdmin):
    list_display = ImageAdmin.list_display + ('input_images_links',)
    readonly_fields = ImageAdmin.readonly_fields + ('input_images_links',)

    def input_images_links(self, obj):
        links = []
        for input_image in obj.image_request.input_images.all():
            url = reverse('admin:scenery_change_detection_inputimage_change', args=[input_image.id])
            links.append(format_html('<a href="{}">{}</a>', url, input_image.id))
        return format_html_join(', ', '{}', ((link,) for link in links))

    input_images_links.short_description = 'Input Images Links'


class ProcessingLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'image_request_id', 'image_request_link')
    readonly_fields = ('image_request',)

    def image_request_link(self, obj):
        return get_image_request_link(obj)

    image_request_link.short_description = 'Image Request ID'


admin.site.register(models.User, UserAdmin)
admin.site.register(models.ImageRequest, ImageRequestAdmin)
admin.site.register(models.InputImage, InputImageAdmin)
admin.site.register(models.OutputImage, OutputImageAdmin)
admin.site.register(models.ProcessingLog, ProcessingLogAdmin)
admin.site.register(models.OneTimePassword)
