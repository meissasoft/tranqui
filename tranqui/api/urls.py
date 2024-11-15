from django.urls import path
from .views import *

urlpatterns = [
    # Auth URLS
    path('auth/register/', RegisterUserView.as_view(), name='register_user'),
    path('auth/profile/', ProfileUpdateView.as_view(), name='update_profile'),
    path('auth/login/', LoginView.as_view(), name='user_login'),
    path('auth/otp/verify/', VerifyOTPView.as_view(), name='verify_otp'),
    # path('auth/otp/resend/', ResendOTPView.as_view(), name='resend_otp'),
    path('auth/password/reset/verify-code/', VerifyResetCodeView.as_view(), name='verify_reset_code'),
    path('auth/password/reset/', ResetPasswordView.as_view(), name='reset_password'),
    path('auth/google-signin/', GoogleSignInView.as_view(), name='google_signin'),
    # Chats URLs
    path('chats/', GetAllChatsView.as_view(), name='list_chats'),
    path('chats/create/', CreateChatView.as_view(), name='create_chat'),
    # LiveKit Token
    path('livekit/token/', GetLiveKitToken.as_view(), name='get_livekit_token'),
]