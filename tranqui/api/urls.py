from django.urls import path
from .views import *

urlpatterns = [
    # Auth URLs
    path('auth/register/', UserRegistrationView.as_view(), name='register_user'),
    path('auth/login/', UserLoginView.as_view(), name='user_login'),
    path('auth/profile/', UserProfileUpdateView.as_view(), name='update_profile'),
    path('auth/otp/verify/', OTPVerificationView.as_view(), name='verify_otp'),
    # path('auth/otp/resend/', OTPRetryView.as_view(), name='resend_otp'),
    path('auth/password/reset/', PasswordResetRequestView.as_view(), name='reset_password'),
    path('auth/password/reset/verify-code/', PasswordResetVerificationView.as_view(), name='verify_reset_code'),
    path('auth/google-signin/', GoogleOAuthSignInView.as_view(), name='google_signin'),

    # Chat URLs
    path('chats/', UserChatsListView.as_view(), name='list_chats'),
    path('chats/create/', ChatCreationView.as_view(), name='create_chat'),

    # LiveKit Token
    path('livekit/token/', GenerateLiveKitTokenView.as_view(), name='get_livekit_token'),
]