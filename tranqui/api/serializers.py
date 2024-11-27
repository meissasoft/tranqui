from rest_framework import serializers
from .models import User, Chat, Conversation


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User
        fields = ['email', 'password', 'first_name', 'last_name']

    def create(self, validated_data):
        username = f"{validated_data['email']}"
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user


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
    otp = serializers.CharField(max_length=6)
    email = serializers.EmailField()


class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chat
        fields = '__all__'


class ConversationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Conversation
        fields = '__all__'


class SocialAuthTokenSerializer(serializers.Serializer):
    token = serializers.CharField()


class GoogleSignInSerializer(SocialAuthTokenSerializer):
    pass


class FacebookSignInSerializer(SocialAuthTokenSerializer):
    pass
