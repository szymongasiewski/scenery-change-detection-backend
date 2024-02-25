from django.contrib.auth import models
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.utils.translation import gettext_lazy


class UserManager(models.BaseUserManager):
    @staticmethod
    def email_validator(email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(gettext_lazy("enter valid email address"))

    def create_user(self, email, password, **kwargs):
        if email:
            email = self.normalize_email(email)
            self.email_validator(email)
        else:
            raise ValueError(gettext_lazy("email address is required"))

        user = self.model(email=email, **kwargs)
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, email, password, **kwargs):
        kwargs.setdefault("is_staff", True)
        kwargs.setdefault("is_superuser", True)

        if kwargs.get("is_staff") is not True:
            raise ValueError(gettext_lazy("is staff must be true for admin user"))

        if kwargs.get("is_superuser") is not True:
            raise ValueError(gettext_lazy("is superuser must be true for admin user"))

        user = self.create_user(email, password, **kwargs)
        user.save()

        return user

