from django.contrib import admin
from django.http import HttpRequest
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
    readonly_fields = ('user', 'created_at', 'updated_at', 'parameters', 'algorithm', 'status')

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request):
        return False

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

    def has_change_permission(self, request, obj=None):
        return False

    def has_add_permission(self, request):
        return False

    def image_request_link(self, obj):
        return get_image_request_link(obj)
    image_request_link.short_description = 'Image Request ID'


class InputImageAdmin(ImageAdmin):
    list_display = ImageAdmin.list_display + ('output_images_links',)
    readonly_fields = ImageAdmin.readonly_fields + ('output_images_links',)

    def output_images_links(self, obj):
        links = []
        for output_image in obj.image_request.output_images.all():
            url = reverse('admin:scenery_change_detection_outputimage_change', args=[output_image.id])
            links.append(format_html('<a href="{}">{}</a>', url, output_image.id))
        return format_html_join(', ', '{}', ((link,) for link in links))
    
    output_images_links.short_description = 'Output Images Links'


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

    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False

    def image_request_link(self, obj):
        return get_image_request_link(obj)

    image_request_link.short_description = 'Image Request ID'

class OneTimePasswordAdmin(admin.ModelAdmin):
    list_display = ('otp',)

    def has_change_permission(self, request, obj=None):
        return False
    
    def has_add_permission(self, request):
        return False


admin.site.register(models.User, UserAdmin)
admin.site.register(models.ImageRequest, ImageRequestAdmin)
admin.site.register(models.InputImage, InputImageAdmin)
admin.site.register(models.OutputImage, OutputImageAdmin)
admin.site.register(models.ProcessingLog, ProcessingLogAdmin)
admin.site.register(models.OneTimePassword, OneTimePasswordAdmin)