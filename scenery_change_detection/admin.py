from django.contrib import admin
from . import models


admin.site.register(models.User)

# class UserAdmin(admin.ModelAdmin):
#     list_display = (
#         'id',
#         'email',
#     )
#
#
# admin.site.register(models.User, UserAdmin)
