import logging
import smtplib
import string
from email.mime.text import MIMEText
from typing import Dict, Any
import facebook
import requests
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from dotenv import load_dotenv
import random
from rest_framework import status
from .models import User, OTP

load_dotenv()
logger = logging.getLogger(__name__)

EMAIL_SENDER = settings.EMAIL_SENDER
EMAIL_PASSWORD = settings.EMAIL_PASSWORD


def get_jwt_token(user: User) -> Dict[str, str]:
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


def send_verification_email(email: str, otp_code: str) -> None:
    subject = "Your OTP Code"
    body = f"Your OTP code is {otp_code}."
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_SENDER
    msg['To'] = email
    try:
        with smtplib.SMTP_SSL(host='smtp.gmail.com', port=465) as server:
            server.login(user=EMAIL_SENDER, password=EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, email, msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        logger.error(msg=f"Error in sending OTP: {e}")


def generate_otp() -> str:
    """Generates a 6-digit OTP."""
    return str(random.randint(a=100000, b=999999))


def send_otp(email: str) -> None:
    try:
        otp_code = generate_otp()
        send_verification_email(email=email, otp_code=otp_code)
        OTP.objects.update_or_create(email=email, defaults={'otp': otp_code})
    except Exception as e:
        logger.error(f"Error sending OTP to {email}: {str(e)}")
        raise e


def generate_random_code() -> str:
    random_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return f"{random_code}"


def create_or_get_user(
        first_name: str, last_name: str, email: str, is_verified: bool, username: str = None
) -> User:
    if username is None:
        username = email
    user, created = User.objects.get_or_create(
        email=email,
        first_name=first_name,
        last_name=last_name,
        is_verified=is_verified,
        defaults={
            'username': email,
        }
    )
    if created:
        user.set_password(User.objects.generate_random_password())
        user.save()
    return user


def handle_facebook_auth(token: str) -> Dict[str, any]:
    try:
        graph = facebook.GraphAPI(access_token=token)
        profile = graph.request(path='/me?fields=id,name,email,first_name,last_name')

        if 'email' not in profile:
            error_message = f"Email permission not granted or missing for user: {profile.get('name')}"
            logger.error(error_message)
            return {
                "error": True,
                "message": error_message,
                "status": status.HTTP_400_BAD_REQUEST
            }
        user = create_or_get_user(
            email=profile.get('email'),
            username=profile.get('name'),
            first_name=profile.get('first_name'),
            last_name=profile.get('last_name'),
            is_verified=True
        )
        token = get_jwt_token(user)
        return {
            "error": False,
            "message": "Login successful",
            "user_id": user.id,
            "token": token.get("access"),
            "status": status.HTTP_200_OK
        }

    except facebook.GraphAPIError as e:
        logger.error(f"Facebook API error: {e}")
        return {
            "error": True,
            "message": f"Facebook API error: {str(e)}",
            "status": status.HTTP_400_BAD_REQUEST
        }
    except Exception as e:
        logger.error(f"Unexpected error during Facebook sign-in: {e}")
        return {
            "error": True,
            "message": "An unexpected error occurred. Please try again later.",
            "status": status.HTTP_500_INTERNAL_SERVER_ERROR
        }


def handle_google_auth(token: str) -> Dict[str, any]:
    try:
        google_url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token}"
        response = requests.get(google_url)

        if response.status_code != 200:
            logger.error(f"Google API returned error: {response.json()}")
            return {
                "error": True,
                "message": "Failed to retrieve user info from Google.",
                "status": status.HTTP_400_BAD_REQUEST
            }
        user_info = response.json()
        if User.objects.filter(email=user_info["email"]).first():
            logger.error(f"User with email : {user_info['email']} already exists")
            return {
                "error": False,
                "message": "User with this email already exists",
                "status": status.HTTP_200_OK
            }
        user = create_or_get_user(
            email=user_info["email"],
            first_name=user_info["given_name"],
            last_name=user_info["family_name"],
            is_verified=True
        )
        token = get_jwt_token(user)
        return {
            "error": False,
            "message": "Login successful",
            "user_id": user.id,
            "token": token.get("access"),
            "status": status.HTTP_200_OK
        }

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error during Google sign-in: {e}")
        return {
            "error": True,
            "message": f"Request error: {str(e)}",
            "status": status.HTTP_400_BAD_REQUEST
        }
    except Exception as e:
        logger.error(f"Unexpected error during Google sign-in: {e}")
        return {
            "error": True,
            "message": "An unexpected error occurred. Please try again later.",
            "status": status.HTTP_400_BAD_REQUEST
        }
