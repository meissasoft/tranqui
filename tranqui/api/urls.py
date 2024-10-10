from django.urls import path
from .views import *


urlpatterns = [
    path('auth/register/', RegisterUserView.as_view(), name='register'),
    path('auth/profile-update/', ProfileUpdateView.as_view(), name='profile_update'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/verify-OTP/', VerifyOTPView.as_view(), name='send_confirmation_code'),
    path('auth/verify-reset-code/', VerifyResetCodeView.as_view(), name='validate_reset_code'),
    path('auth/reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('auth/google-sign-in/', GoogleSignInView.as_view(), name='google-sign-in'),
    path('chats/', GetAllChatsView.as_view(), name='get_all_chats'),
    path('chats/session/<str:session_id>/', GetChatsBySessionIDView.as_view(), name='get_chats_by_session_id'),
]


