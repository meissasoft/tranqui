from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from .utils import get_google_user_info, get_facebook_user_info
from .models import User, OTP, Chat, Conversation


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name']

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
        username = f"{validated_data['first_name']} {validated_data['last_name']}"
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
    token = serializers.CharField()

    def validate_token(self, value):
        # Validate the Google token and retrieve user info
        user_info = get_google_user_info(value)
        if not user_info:
            raise ValidationError("Invalid Google token.")
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
