import logging
import smtplib
import string
from email.mime.text import MIMEText
import requests
from django.conf import settings
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from dotenv import load_dotenv
import random
from django.db import transaction
from rest_framework.response import Response
from rest_framework import status
from .models import OTP, User

load_dotenv()

logger = logging.getLogger(__name__)

EMAIL_SENDER = settings.EMAIL_SENDER
EMAIL_PASSWORD = settings.EMAIL_PASSWORD


def get_jwt_token(user):
    """
    Generates JWT tokens for the given user.

    Args:
        user: The user instance for which the tokens are generated.

    Returns:
        dict: A dictionary containing 'refresh' and 'access' tokens.
    """
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


def send_verification_email(email, otp_code):
    """
    Sends a verification email containing the OTP code to the specified email address.

    Args:
        email (str): The recipient's email address.
        otp_code (str): The OTP code to be sent in the email.

    Raises:
        SMTPAuthenticationError: If authentication fails during the email sending process.
    """
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


def get_google_user_info(token: str):
    """
    Retrieves user information from Google using the provided OAuth token.

    Args:
        token (str): The OAuth token received from Google.

    Returns:
        dict: A dictionary containing user information retrieved from Google.

    Raises:
        HTTPError: If the request to the Google API fails.
    """
    userinfo_endpoint = "https://www.googleapis.com/oauth2/v3/userinfo"
    response = requests.get(
        userinfo_endpoint, headers={"Authorization": f"Bearer {token}"}
    )
    response.raise_for_status()
    return response.json()


def generate_otp():
    """Generates a 6-digit OTP."""
    return str(random.randint(a=100000, b=999999))


def generate_random_code() -> str:
    random_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return f"{random_code}"


def get_facebook_user_info(token):
    url = f"https://graph.facebook.com/me?fields=id,name,email&access_token={token}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        logger.error(f"Failed to fetch Facebook user info: {response.text}")
        return None


@transaction.atomic
def register_user(serializer, email):
    user = serializer.save()
    user.username = f"{user.first_name} {user.last_name} {user.email}"
    user.save()
    otp_code = generate_otp()
    send_verification_email(email, otp_code)
    OTP.objects.create(email=email, otp=otp_code)
    return Response({"message": f"OTP sent to {email}"}, status=status.HTTP_201_CREATED)


def handle_existing_unverified_user(email):
    otp_code = generate_otp()
    send_verification_email(email, otp_code)
    otp_entry, _ = OTP.objects.get_or_create(email=email)
    otp_entry.otp = otp_code
    otp_entry.save(update_fields=['otp'])
    return Response(
        {"message": f"This email is already registered but never verified. New OTP sent to {email}."},
        status=status.HTTP_200_OK
    )

def get_user_by_email(email):
    """
    Retrieve the user by their email.
    """
    return User.objects.get(email=email)

def check_user_password(password, hashed_password):
    """
    Check if the given password matches the hashed password.
    """
    return check_password(password, hashed_password)

def generate_jwt_token(user):
    """
    Generate and return JWT token for the authenticated user.
    """
    return get_jwt_token(user)

def handle_invalid_credentials():
    """
    Handle invalid credentials response.
    """
    return {"message": "Invalid email or password."}, status.HTTP_400_BAD_REQUEST

def handle_inactive_account(email):
    """
    Handle login attempt for inactive accounts.
    """
    return {"message": "This account is inactive."}, status.HTTP_403_FORBIDDEN

def handle_successful_login(user, token):
    """
    Return successful login response.
    """
    return {
        "message": "Login successful!",
        "first_name": user.first_name,
        "last_name": user.last_name,
        "user_id": user.id,
        "token": token.get('access')
    }, status.HTTP_200_OK

def handle_user_not_found(email):
    """
    Handle case where user is not found.
    """
    return {"message": "User does not exist."}, status.HTTP_404_NOT_FOUND

def handle_unexpected_error(email, exception):
    """
    Handle unexpected errors during login.
    """
    return {"message": "An error occurred while trying to log in."}, status.HTTP_500_INTERNAL_SERVER_ERROR