from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.utils.translation import gettext_lazy as _
from .managers import UserManager
from django.core.validators import RegexValidator


# Create your models here.


class User(AbstractBaseUser):
    _USER_ERROR_MESSAGE = _("Bunday raqamli foydalanuvchi mavjud")

    phone_regex = RegexValidator(regex=r'^998[0-9]{2}[0-9]{7}$', message=_("Faqat O'zbekiston raqamlari kiriting"))
    phone = models.CharField(_('phone number'), validators=[phone_regex], max_length=13, unique=True, help_text=_('Phone number must be entered in the format: 9989XXXXXXXX'))
    name = models.CharField(_('name'), max_length=50, blank=True, null=True)
    first_login = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    # is_verified = models.BooleanField(default=False)


    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.phone
    

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')

    def get_full_name(self):
        if self.name:
            return self.name
        return self.phone

    def get_short_name(self):
        return self.phone

    # @property
    # def is_admin(self):
    #     return self.is_superuser

    # @property
    # def is_staff(self):
    #     return self.is_staff
    
    # @property
    # def is_active(self):
    #     return self.is_active
    

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    def get_username(self):
        return self.phone

    def get_phone(self):
        return self.phone

class PhoneOTP(models.Model):
    phone = models.CharField(max_length=13, unique=True)
    otp = models.CharField(max_length=9)
    count = models.IntegerField(default=0)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.otp + ' sent to ' + self.phone

    class Meta:
        verbose_name = _('Phone OTP')
        verbose_name_plural = _('Phone OTPS')

    def get_phone(self):
        return self.phone

    def get_otp(self):
        return self.otp

class SMSToken(models.Model):
    name = models.CharField(max_length=50, blank=True, null=True)
    token = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        return self.token

    class Meta:
        verbose_name = _('SMS Token')
        verbose_name_plural = _('SMS Tokens')

    def get_token(self):
        return self.token

class SMSLog(models.Model):
    phone = models.CharField(max_length=13)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.phone + ' ' + self.message

    class Meta:
        verbose_name = _('SMS log')
        verbose_name_plural = _('SMS logs')

    def get_phone(self):
        return self.phone

    def get_message(self):
        return self.message
