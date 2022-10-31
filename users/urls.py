from rest_framework import routers
from django.urls import path, include
from .views import (
    UserView,
    ValidateOTPView,
    SendOTPView,
    RegisterView,
    LoginView,
    LogoutView,
    UsersView
)

# router = routers.DefaultRouter()
# router.register(r'users', UsersView.as_view(), basename='users')
# router.register(r'user', UserView.as_view(), basename='user')
# router.register(r'validate-otp', ValidateOTPView.as_view(), basename='validate-otp')
# router.register(r'send-otp', SendOTPView.as_view(), basename='send-otp')
# router.register(r'register', RegisterView.as_view(), basename='register')
# router.register(r'login', LoginView.as_view(), basename='login')
# router.register(r'logout', LogoutView.as_view(), basename='logout')

urlpatterns = [
    path('users/', UsersView.as_view(), name='users'),
    path('user/', UserView.as_view(), name='user'),
    path('validate-otp/', ValidateOTPView.as_view(), name='validate-otp'),
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('users/register/', RegisterView.as_view(), name='register'),
    path('users/login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),

] 

# urlpatterns += router.urls