from django.apps import AppConfig


class SceneryChangeDetectionConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scenery_change_detection'

    def ready(self):
        import scenery_change_detection.signals