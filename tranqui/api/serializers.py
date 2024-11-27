from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from .utils import get_google_user_info
from .models import User, Chat, Conversation


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name']

    def create(self, validated_data):
        """Create a new user with a hashed password."""
        username = f"{validated_data['email']}"
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user


# Serializer for handling user login
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email']
        extra_kwargs = {
            'email': {'read_only': True},
        }


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)


class PasswordChangeConfirmationSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, required=False)
    new_password = serializers.CharField(min_length=6, write_only=True, required=False)


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)


class GoogleSignInSerializer(serializers.Serializer):
    # token = serializers.CharField()

    def validate_token(self, value):
        """Validate the Google token by making a request to Google's API."""
        user_info = get_google_user_info(value)
        if not user_info.get('email'):
            raise ValidationError("Unable to retrieve email from Google account.")
        if not user_info.get('email_verified'):
            raise ValidationError("Google email is not verified.")
        return value


class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chat
        fields = '__all__'


class ConversationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Conversation
        fields = '__all__'


class FacebookSignInSerializer(serializers.Serializer):
    token = serializers.CharField()
