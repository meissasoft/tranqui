from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from .utils import get_google_user_info, get_facebook_user_info
from .models import User, OTP, Chat, Conversation


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

    def create_or_update_google_user(self, user_info):
        """Create a new user if they don't exist, otherwise update the existing user."""
        email = user_info['email']
        first_name = user_info['given_name']
        last_name = user_info['family_name']
        username = user_info.get('given_name', '') + user_info.get('family_name', '')
        username = username.strip() or email.split('@')[0]

        user, created = User.objects.get_or_create(
            email=email,
            first_name=first_name,
            last_name=last_name,
            is_verified=True,
            defaults={
                'username': email,
            }
        )
        print(created)
        if created:
            user.set_password(User.objects.generate_random_password())

            user.save()
        return user


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

    def create_or_update_user(self):
        # Extract user info from the validated token
        user_info = get_facebook_user_info(self.validated_data['token'])
        email = user_info.get("email")
        name = user_info.get("name")

        # Find or create the user in the database
        user, created = User.objects.get_or_create(email=email, defaults={"name": name})
        if not created:
            # Update user info if necessary
            user.name = name
            user.save()
        return user
