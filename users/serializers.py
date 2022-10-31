from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken, AuthenticationFailed
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'phone', 'name', 'password', 'is_staff', 'is_active', 'is_superuser', )
        extra_kwargs = {
            'password': {'write_only': True},
            'is_staff': {'read_only': True},
            'is_active': {'read_only': True},
            'is_superuser': {'read_only': True},
        }

class ValidateSendOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()

    def validate_phone(self, phone):
        if not phone:
            raise serializers.ValidationError('Phone number is required')
        return phone
    

class ValidateOTPSerializer(serializers.Serializer):
    phone = serializers.CharField()
    otp = serializers.CharField()

    def validate(self, attrs):
        phone = attrs.get('phone')
        otp = attrs.get('otp')
        if not phone:
            raise serializers.ValidationError('Phone number is required')
        if not otp:
            raise serializers.ValidationError('OTP is required')
        return attrs


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['name'] = user.name
        token['phone'] = user.phone
        token['is_staff'] = user.is_staff
        token['is_active'] = user.is_active
        token['is_superuser'] = user.is_superuser
        return token


class CreateUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User 
        fields = ['phone', 'password', 'name']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        print("User: ", user, user.password)

        return user 

class LoginSerializer(serializers.Serializer):
    phone = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        phone = data.get('phone')
        password = data.get('password')

        if phone and password:
            user = authenticate(request=self.context.get('request'), phone=phone, password=password)
            if not user:
                msg = 'Unable to log in with provided credentials.'
                raise AuthenticationFailed(msg, code='authorization')
            
        else:
            msg = 'Must include "phone" and "password".'
            raise AuthenticationFailed(msg, code='authorization')

        data['user'] = user
        return data

"""class LoginSerializer(serializers.Serializer):
    phone = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        phone = attrs.get('phone')
        password = attrs.get('password')
        if phone and password:
            if User.objects.filter(phone=phone).exists():
                user = authenticate(**attrs)
                if user and user.is_active:
                    return user 
                print("User.. user auth", user)
            else:
                msg = {
                    'register': False,
                    'detail': 'Phone number not found',
                }
                raise serializers.ValidationError(msg)

            if not user:
                msg = {
                    'register': False,
                    'detail': 'Unable to login with provided credentials', 
                }
                raise serializers.ValidationError(msg, code='authorization')
        else:
            msg = {
                'status': False,
                'detail': 'Phone number or password not found in request'
            }
            raise serializers.ValidationError(msg, code='authorization')
        return False"""

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is invalid or expired'),
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')

            