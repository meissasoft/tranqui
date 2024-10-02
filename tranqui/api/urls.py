from django.urls import path
from .views import *


urlpatterns = [
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/profile-update/', ProfileUpdateView.as_view(), name='profile_update'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/send-confirmation-code/', VerifyOTPView.as_view(), name='send_confirmation_code'),
    path('auth/validate-reset-code/', ValidateResetCodeView.as_view(), name='validate_reset_code'),
    path('auth/reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('auth/google-sign-in/', GoogleSignInView.as_view(), name='google-sign-in'),
    path('docs/websocket/', WebSocketDocView.as_view(), name='websocket-doc'),
]


