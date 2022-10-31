from django.contrib.auth.models import BaseUserManager
from django.utils.translation import gettext_lazy as _



class UserManager(BaseUserManager):
    use_in_migrations: bool = True

    """
        Custom user model manager where phone is the unique identifiers
        for authentication instead of usernames.

    """
    def _create_user(self, phone:str, password=None, **extra_fields):
        """
            Create and save a user with the given phone and password.
        """
        if not phone:
            raise ValueError(_('The phone must be set'))
        user = self.model(phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, phone, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(phone, password, **extra_fields)

    def create_superuser(self, phone, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))

        return self._create_user(phone, password, **extra_fields)
