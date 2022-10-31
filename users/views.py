from django.shortcuts import render

# Create your views here.
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework import permissions
from rest_framework.views import APIView

from .serializers import (
    UserSerializer, 
    ValidateSendOTPSerializer, 
    ValidateOTPSerializer, 
    CreateUserSerializer, 
    LoginSerializer,
    MyTokenObtainPairSerializer,
    LogoutSerializer,
)
from .models import PhoneOTP, User
from .utils import send_sms

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken, AuthenticationFailed
from django.contrib.auth import get_user_model
from drf_yasg.utils import swagger_auto_schema

User = get_user_model()

# class UserView(generics.RetrieveAPIView):
#     permission_classes = (permissions.IsAuthenticated,  )
#     serializer_class = UserSerializer

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

     
class ValidateOTPView(APIView):
    permission_classes = (AllowAny, )
    serializer_class = ValidateOTPSerializer
    http_method_names = ['post']

    @swagger_auto_schema(request_body=ValidateOTPSerializer)
    def post(self, request, *args, **kwargs):
        serializer = ValidateOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.data.get('phone')
        otp = serializer.data.get('otp')
        phoneotp = PhoneOTP.objects.filter(phone=phone)
        if phoneotp.exists():
            phoneotp = phoneotp.first()
            if phoneotp.otp == otp:
                phoneotp.is_verified = True
                phoneotp.save()
                return Response({'message': 'OTP verified successfully. Now you can register/login phone'}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': 'Invalid phone number'}, status=status.HTTP_400_BAD_REQUEST)


class SendOTPView(APIView):
    permission_classes = (AllowAny, )
    serializer_class = ValidateSendOTPSerializer
    http_method_names = ['post']

    @swagger_auto_schema(request_body=ValidateSendOTPSerializer)
    def post(self, request, *args, **kwargs):
        serializer = ValidateSendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.data.get('phone')
        try:
            key = send_sms(phone)
            print("Key: ", key)
            if PhoneOTP.objects.filter(phone=phone).exists():
                phoneotp = PhoneOTP.objects.filter(phone=phone)
                phoneotp = phoneotp.first()
                if phoneotp:
                    phoneotp.otp = key
                    phoneotp.save()

            phoneotp = PhoneOTP.objects.create(phone=phone, otp=key)
            phoneotp.save()
            return Response({'message': 'OTP sent successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response({'message': 'Error sending OTP'}, status=status.HTTP_400_BAD_REQUEST)

class RegisterView(generics.CreateAPIView):
    permission_classes = (AllowAny, )
    serializer_class = CreateUserSerializer
    http_method_names = ['post']

    @swagger_auto_schema(request_body=CreateUserSerializer)
    def post(self, request, *args, **kwargs):
        serializer = CreateUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        token = get_tokens_for_user(user)
        return Response({'message': 'User created successfully', 'token': token}, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = (AllowAny, )
    serializer_class = LoginSerializer
    http_method_names = ['post']

    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        phone = serializer.data.get('phone')
        password = serializer.data.get('password')
        user = User.objects.get(phone=phone)
        if user.check_password(password):
            token = get_tokens_for_user(user)
            return Response({'message': 'User logged in successfully', 'token': token}, status=status.HTTP_200_OK)
            # return Response({'message': 'User logged in successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

# Path: users\serializers.py
# Compare this snippet from users\models.py:
#

class UsersView(generics.ListAPIView):
    permission_classes = (permissions.IsAuthenticated,  )
    serializer_class = UserSerializer
    queryset = User.objects.all()   
    http_method_names = ['get']

class UserView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = (permissions.IsAuthenticated,  )
    serializer_class = UserSerializer
    http_method_names = ['get', 'put', 'patch', 'delete']


    def get_object(self):
        return self.request.user

class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated, )
    serializer_class = LogoutSerializer
    http_method_names = ['post']

    @swagger_auto_schema(request_body=LogoutSerializer)
    def post(self, request, *args, **kwargs):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message': 'User logged out successfully'}, status=status.HTTP_200_OK)



class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


