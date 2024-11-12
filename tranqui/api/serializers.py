from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from .utils import get_google_user_info
from .models import User, OTP, Chat


# Serializer for registering a new user
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def validate_username(self, value):
        """Ensure the username is unique."""
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists.")
        return value

    def validate_email(self, value):
        """Ensure the email is unique."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email already exists.")
        return value

    def create(self, validated_data):
        """Create a new user with a hashed password."""
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user


# Serializer for handling user login
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """Validate user credentials."""
        email = attrs.get('email')
        password = attrs.get('password')
        try:
            user = User.objects.filter(email=email).first()
            if user is None:
                raise serializers.ValidationError("Invalid email or password.")
            if not user.check_password(password):
                raise serializers.ValidationError("Invalid email or password.")
            if not user.is_active:
                raise serializers.ValidationError("User account is inactive.")
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        except Exception as e:
            raise serializers.ValidationError(f"An unexpected error occurred: {str(e)}")
        attrs['user'] = user
        return attrs


# Serializer for updating user profile
class ProfileUpdateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {
            'email': {'read_only': True},
            'password': {'write_only': True, 'required': False},
            'username': {'required': False}
        }

    def validate(self, attrs):
        """Ensure that the user exists in the system based on the provided email."""
        email = attrs.get('email')
        if not email:
            raise serializers.ValidationError("Email must be provided to update other fields.")
        try:
            user = User.objects.get(email=email)
            attrs['user'] = user
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")

        return attrs

    def update(self, instance, validated_data):
        """Update user profile data."""
        instance.username = validated_data.get('username', instance.username)
        if 'password' in validated_data:
            instance.set_password(validated_data['password'])
        instance.save()
        return instance


# Serializer for resetting the password
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        """Ensure that the email exists in the system."""
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email does not exist.")
        return value


# Serializer for verifying OTP sent to the user
class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate_email(self, value):
        """Ensure the provided email exists in the system."""
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email does not exist.")
        return value

    def validate_otp(self, value):
        """Check if the OTP is valid and corresponds to the email."""
        email = self.initial_data.get('email')
        otp_record = OTP.objects.filter(email=email).first()

        if not otp_record or not otp_record.is_valid() or otp_record.otp != value:
            raise serializers.ValidationError("Invalid or expired OTP.")

        user = User.objects.get(email=email)
        user.is_verified = True
        user.save()
        return value


# Serializer for validating the OTP code and resetting the password
class VerifyResetCodeSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(min_length=8, write_only=True)

    def validate_otp(self, value):
        """Check if the OTP exists and is valid."""
        otp_record = OTP.objects.filter(otp=value).first()

        if not otp_record or not otp_record.is_valid():
            raise serializers.ValidationError("Invalid or expired OTP.")
        return value


# Serializer for Google sign-in using Google OAuth token
class GoogleSignInSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        """Validate the Google token by making a request to Google's API."""
        user_info = get_google_user_info(value)

        if not user_info.get('email'):
            raise ValidationError("Unable to retrieve email from Google account.")
        if not user_info.get('email_verified'):
            raise ValidationError("Google email is not verified.")

        self.user_info = user_info
        return value

    def create_or_update_user(self):
        """Create a new user if they don't exist, otherwise update the existing user."""
        email = self.user_info['email']
        username = self.user_info.get('given_name', '') + self.user_info.get('family_name', '')
        username = username.strip() or email.split('@')[0]

        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': username,
                'password': User.objects.make_random_password()
            }
        )
        return user


# Serializer for chat requests
class ChatRequestSerializer(serializers.Serializer):
    prompt = serializers.CharField()

    def validate_prompt(self, value):
        """Validate that the prompt is not empty."""
        if not value.strip():
            raise serializers.ValidationError("Prompt cannot be empty.")
        return value


# Serializer for the chat model
class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chat
        fields = ['id', 'user', 'prompt', 'response']
