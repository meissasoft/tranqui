import string
import random
import uuid

from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        If no password is provided, generates a random password.
        """
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        if password is None:
            password = self.generate_random_password()
        user.set_password(password)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates and saves a superuser with the given email and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)

    def generate_random_password(self, length=12):
        """
        Generates a random password consisting of uppercase, lowercase letters, digits, and punctuation.
        :param length: Length of the password to be generated.
        :return: Randomly generated password.
        """
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password


class User(AbstractUser):
    is_verified = models.BooleanField(
        default=False,
        help_text='Indicates if the user has verified their email with a OTP.'
    )
    objects = UserManager()

    def __str__(self):
        return self.email


class OTP(models.Model):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        """Check if the OTP is valid based on the time limit (1 hour)."""
        return (timezone.now() - self.created_at).seconds <= 3600  # Valid for 1 hour


class Conversation(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "api_conversation"

    def __str__(self):
        return self.name


class Chat(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    prompt = models.TextField()
    response = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name="chats")

    class Meta:
        db_table = "api_chat"

    def __str__(self):
        return f"Chat - User {self.user}"
