from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from .utils import get_google_user_info
from .models import User, OTP


# Serializer for registering a new user
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']

    def create(self, validated_data):
        """
            Create a new user with the validated data.
            The password is hashed before saving.
        """
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user


# Serializer for handling user login
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """
        Validate the email and password provided by the user.
        Check if the user exists and the account is active.
        """
        email = attrs.get('email')
        password = attrs.get('password')
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("User does not exist.")

        user = User.objects.get(email=email)
        if not user.is_active:
            raise serializers.ValidationError("User account is inactive.")

        return attrs


# Serializer for updating user profile
class ProfileUpdateSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """
        Ensure that the user exists in the system before updating the profile.
        """
        try:
            user = User.objects.get(email=attrs['email'])
        except User.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        attrs['user'] = user
        return attrs


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    new_password = serializers.CharField(min_length=8)

    def validate_email(self, value):
        """
        Ensure that the email exists in the system.
        """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email does not exist.")
        return value

    def validate_new_password(self, value):
        """
        Ensure that the new password is at least 8 characters long.
        """
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        return value


# Serializer for verifying OTP sent to the user
class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate_email(self, value):
        """
        Ensure the provided email exists in the system.
        """
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email does not exist.")
        return value

    def validate_otp(self, value):
        """
        Check if the OTP is valid and corresponds to the email.
        Ensure the OTP hasn't expired and matches the one stored in the database.
        """
        email = self.initial_data.get('email')
        try:
            otp_record = OTP.objects.get(email=email)
            if not otp_record.is_valid():
                raise serializers.ValidationError("OTP has expired.")
            if otp_record.otp != value:
                raise serializers.ValidationError("Invalid OTP.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("No OTP found for this email.")
        user = User.objects.get(email=email)
        user.is_verified = True
        user.save()
        return value


# Serializer for validating the OTP code and resetting the password
class ValidateResetCodeSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6)
    password = serializers.CharField(min_length=8)  # Adjust length as necessary

    def validate_otp(self, value):
        """
        Check if the OTP exists and is valid, ensuring it hasn't expired.
        """
        try:
            otp_record = OTP.objects.get(otp=value)
            if not otp_record.is_valid():
                raise serializers.ValidationError("OTP has expired.")
        except OTP.DoesNotExist:
            raise serializers.ValidationError("Invalid OTP.")
        return value


# Serializer for Google sign-in using Google OAuth token
class GoogleSignInSerializer(serializers.Serializer):
    token = serializers.CharField()

    def validate_token(self, value):
        """
        Validate the Google token by making a request to Google's API.
        Retrieve user information and ensure the email is verified.
        """
        try:
            user_info = get_google_user_info(value)
        except Exception as e:
            raise ValidationError(f"Error verifying token: {str(e)}")

        if not user_info.get('email'):
            raise ValidationError("Unable to retrieve email from Google account.")
        if not user_info.get('email_verified'):
            raise ValidationError("Google email is not verified.")
        self.user_info = user_info
        return value

    def create_or_update_user(self):
        """
        Create a new user if they don't exist, otherwise update the existing user.
        This ensures that the user can log in with Google credentials.
        """
        email = self.user_info['email']
        first_name = self.user_info.get('given_name', '')
        last_name = self.user_info.get('family_name', '')
        user_name = f"{first_name}{last_name}".strip()
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                'username': user_name,
                'email': email.split('@')[0],
                'password': User.objects.make_random_password()
            }
        )
        return user


class ChatRequestSerializer(serializers.Serializer):
    prompt = serializers.CharField(required=True)


class ChatResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    success = serializers.BooleanField(default=True)  # Indicates if the operation was successful
    error = serializers.CharField(allow_blank=True, required=False)
