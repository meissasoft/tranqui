from django.urls import path
from .views import *

urlpatterns = [
    # Auth URLs
    path("auth/register/", UserRegistrationView.as_view(), name="register_user"),
    path("auth/login/", UserLoginView.as_view(), name="user_login"),
    # path('auth/profile/update', UserProfileUpdateView.as_view(), name='update_profile'),
    path("auth/otp/verify/", OTPVerificationView.as_view(), name="verify_otp"),
    path(
        "auth/password/reset/request",
        PasswordResetRequestView.as_view(),
        name="reset_password",
    ),
    path(
        "auth/password/reset/verify/",
        PasswordResetVerificationView.as_view(),
        name="verify_reset_code",
    ),
    path("auth/social/google/", GoogleAuthView.as_view(), name="google_oauth_signin"),
    path(
        "auth/social/facebook/",
        FacebookAuthView.as_view(),
        name="facebook_oauth_signin",
    ),
    # Chat URLs
    path("chats/create/", ChatCreateView.as_view(), name="create_chat"),
    path("chat/list/", ChatListView.as_view(), name="chat_list"),
    # Conversation URLs
    path(
        "conversation/history/",
        ConversationHistoryView.as_view(),
        name="conversation_history",
    ),
    path(
        "current_user_conversation_history/",
        CurrentUserConversationHistoryView.as_view(),
        name="conversation_history",
    ),
    path("conversation/", ConversationListView.as_view(), name="conversation_list"),
    path(
        "conversation/create/",
        ConversationCreateView.as_view(),
        name="conversation_create",
    ),
    path(
        "conversation/<int:conversation_id>/",
        ConversationDetailView.as_view(),
        name="conversation_detail",
    ),
    # LiveKit Token
    path(
        "livekit/token/", GenerateLiveKitTokenView.as_view(), name="get_livekit_token"
    ),
]
